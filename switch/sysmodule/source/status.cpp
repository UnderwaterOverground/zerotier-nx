// See status.hpp.
#include <stratosphere.hpp>

#include <atomic>
#include <cstring>

#include "log.hpp"
#include "memory.hpp"
#include "runtime.hpp"
#include "status.hpp"

namespace ams::status {

    namespace {

        constexpr const char PausedPath[] = "sdmc:/config/zerotier-nx/paused";
        // Ultrahand shows a toast for each .notify file here (and only if it
        // is installed: we never create the directory).
        constexpr const char NotifyDir[] = "sdmc:/config/ultrahand/notifications";
        constexpr const char ConnectedNotifyPath[] = "sdmc:/config/ultrahand/notifications/zerotier-nx-connected.notify";
        constexpr const char UpdateNotifyPath[] = "sdmc:/config/ultrahand/notifications/zerotier-nx-update.notify";
        constexpr const char MemoryNotifyPath[] = "sdmc:/config/ultrahand/notifications/zerotier-nx-memory.notify";
        constexpr const char ConfigNotifyPath[] = "sdmc:/config/ultrahand/notifications/zerotier-nx-config.notify";
        // Config problems show at boot, often before anyone looks at the
        // screen, and say what to do: long enough to read and act on.
        constexpr u32 ConfigToastMs = 20000;
        // The overlay's "Connection notice" switch: present = off.
        constexpr const char NoNoticePath[] = "sdmc:/config/zerotier-nx/no-connect-notice";

        constinit os::SdkMutex g_mutex;
        constinit ::ztnx::Runtime *g_runtime = nullptr;
        constinit ZtnxCtlStatus g_status = {};
        constinit char g_last_error[192] = {};
        constinit char g_conf_name[ZTNX_CTL_CONF_NAME_MAX] = {};
        constinit ZtnxPeerInfo g_peers[ZTNX_CTL_MAX_PEERS] = {};
        constinit size_t g_peer_count = 0;  // in g_peers
        constinit size_t g_peer_total = 0;  // configured, including any that didn't fit
        constinit bool g_handshaken = false;  // a handshake since the conf was applied
        constinit std::atomic<bool> g_paused = false;
        constinit bool g_connect_notice = true;   // config.ini connect_notice
        constinit bool g_announced_connected = false;  // once per boot
        constinit std::atomic<u64> g_engine_ran_ns = 0;
        // What the engine loop is doing outside the engine itself (nullptr:
        // the engine), and whether its current stall has been logged.
        constinit std::atomic<const char *> g_engine_step = nullptr;
        constinit std::atomic<bool> g_stall_logged = false;

        u64 NowNs() { return armTicksToNs(armGetSystemTick()); }

        bool Exists(const char *path, fs::DirectoryEntryType want) {
            fs::DirectoryEntryType t;
            return R_SUCCEEDED(fs::GetEntryType(std::addressof(t), path)) && t == want;
        }

        void WriteFile(const char *path, const char *data, size_t len) {
            static_cast<void>(fs::DeleteFile(path));
            if (R_FAILED(fs::CreateFile(path, static_cast<s64>(len)))) return;
            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Write))) return;
            static_cast<void>(fs::WriteFile(f, 0, data, len, fs::WriteOption::Flush));
            fs::CloseFile(f);
        }

        // A short toast, if Ultrahand is installed. `text` is JSON string
        // content already.
        void Toast(const char *path, const char *title, const char *text, u32 duration_ms) {
            if (!Exists(NotifyDir, fs::DirectoryEntryType_Directory)) return;
            static char json[400];
            const int n = util::SNPrintf(json, sizeof json,
                                         "{\n"
                                         "    \"title\": \"%s\",\n"
                                         "    \"text\": \"%s\",\n"
                                         "    \"font_size\": 18,\n"
                                         "    \"duration\": %u,\n"
                                         "    \"priority\": 10\n"
                                         "}\n",
                                         title, text, static_cast<unsigned>(duration_ms));
            WriteFile(path, json, static_cast<size_t>(n));
        }

        // First connection since boot: a short toast with our address. Not on
        // later reconnects (every wake would show it). g_mutex held.
        void AnnounceConnected() {
            if (g_announced_connected || g_status.state != ZTNX_CTL_CONNECTED) return;
            g_announced_connected = true;
            if (!g_connect_notice || Exists(NoNoticePath, fs::DirectoryEntryType_File)) return;
            char text[48];
            util::SNPrintf(text, sizeof text, "Connected. IP: %u.%u.%u.%u", g_status.ipv4[0], g_status.ipv4[1], g_status.ipv4[2], g_status.ipv4[3]);
            Toast(ConnectedNotifyPath, "ZeroTier", text, 5000);
        }

        // Errors go into JSON and the overlay: keep them to plain printable
        // ASCII without quotes or backslashes.
        void CopySafe(char *dst, size_t cap, const char *src) {
            size_t n = 0;
            for (; *src && n + 1 < cap; src++) {
                const char c = *src;
                if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') dst[n++] = c;
            }
            dst[n] = 0;
        }

        // The state while the tunnel is meant to be running (g_mutex held).
        u32 RunningState() {
            return g_handshaken ? ZTNX_CTL_CONNECTED : ZTNX_CTL_CONNECTING;
        }

    }

    void Initialize(::ztnx::Runtime &rt, u32 flags, bool connect_notice) {
        std::scoped_lock lk(g_mutex);
        g_runtime = std::addressof(rt);
        g_connect_notice = connect_notice;
        g_status.version = ZTNX_CTL_VERSION;
        g_status.flags |= flags;
        if (Exists(PausedPath, fs::DirectoryEntryType_File)) {
            g_paused = true;
            g_status.state = ZTNX_CTL_PAUSED;
            rt.StartSuspended(::ztnx::Runtime::kPaused);
            Log("status: paused (delete %s or use the overlay to resume)", PausedPath);
        } else if (g_status.state == ZTNX_CTL_STARTING && !(g_status.flags & ZTNX_CTL_FLAG_CONF_ERROR)) {
            g_status.state = RunningState();
        }
    }

    void SetConf(const char *name, u32 peers) {
        std::scoped_lock lk(g_mutex);
        util::SNPrintf(g_conf_name, sizeof g_conf_name, "%s", name);
        g_status.peers = peers;
        g_status.peers_up = 0;
        g_status.flags &= ~static_cast<u32>(ZTNX_CTL_FLAG_CONF_ERROR | ZTNX_CTL_FLAG_CONF_MISSING);
        g_last_error[0] = 0;
        g_handshaken = false;
        g_peer_count = g_peer_total = 0;
        if (g_runtime && !g_paused && g_status.state != ZTNX_CTL_STOPPING) g_status.state = ZTNX_CTL_CONNECTING;
    }

    void SetConfError(const char *name, const char *error) {
        {
            std::scoped_lock lk(g_mutex);
            g_status.flags |= ZTNX_CTL_FLAG_CONF_ERROR;
            g_status.flags &= ~static_cast<u32>(ZTNX_CTL_FLAG_CONF_MISSING);
            char msg[192];
            util::SNPrintf(msg, sizeof msg, "%s: %s", name, error);
            CopySafe(g_last_error, sizeof g_last_error, msg);
            // What was running before (if anything) keeps running.
        }
        char text[220];
        util::SNPrintf(text, sizeof text, "%s", g_last_error);
        Toast(ConfigNotifyPath, "ZeroTier: config error", text, ConfigToastMs);
    }

    void SetConfMissing(const char *message) {
        {
            std::scoped_lock lk(g_mutex);
            g_status.flags |= ZTNX_CTL_FLAG_CONF_ERROR | ZTNX_CTL_FLAG_CONF_MISSING;
            CopySafe(g_last_error, sizeof g_last_error, message);
        }
        char text[220];
        util::SNPrintf(text, sizeof text, "%s", g_last_error);
        Toast(ConfigNotifyPath, "ZeroTier: no config", text, ConfigToastMs);
    }

    void OnEvent(const ZtnxEvent &ev) {
        std::scoped_lock lk(g_mutex);
        switch (ev.kind) {
            case ZTNX_EVENT_ADDRESSES: {
                u32 a = 0, b = 0, c = 0, d = 0;
                const char *p = ev.text;
                auto num = [&p](u32 *out) {
                    if (*p < '0' || *p > '9') return false;
                    for (*out = 0; *p >= '0' && *p <= '9'; p++) *out = *out * 10 + static_cast<u32>(*p - '0');
                    return true;
                };
                if (num(&a) && *p++ == '.' && num(&b) && *p++ == '.' && num(&c) && *p++ == '.' && num(&d)) {
                    g_status.ipv4[0] = a, g_status.ipv4[1] = b, g_status.ipv4[2] = c, g_status.ipv4[3] = d;
                } else {
                    std::memset(g_status.ipv4, 0, sizeof g_status.ipv4);
                }
                break;
            }
            case ZTNX_EVENT_PEERS:
                g_status.peers = ev.value;
                break;
            case ZTNX_EVENT_ERROR:
                CopySafe(g_last_error, sizeof g_last_error, ev.text);
                break;
            default:
                break;
        }
    }

    void SetPeers(const ZtnxPeerInfo *peers, size_t n) {
        std::scoped_lock lk(g_mutex);
        g_peer_total = n;
        g_peer_count = std::min(n, static_cast<size_t>(ZTNX_CTL_MAX_PEERS));
        u32 up = 0;
        for (size_t i = 0; i < g_peer_count; i++) {
            g_peers[i] = peers[i];
            g_peers[i].name[sizeof g_peers[i].name - 1] = 0;
            if (peers[i].flags & ZTNX_PEER_SESSION) up++;
        }
        g_status.peers_up = up;
        if (up > 0 && !g_handshaken) {
            g_handshaken = true;
            if (!g_paused && g_status.state != ZTNX_CTL_STOPPING) {
                g_status.state = ZTNX_CTL_CONNECTED;
                AnnounceConnected();
            }
        }
    }

    void AnnounceUpdate(const char *latest) {
        char text[96];
        util::SNPrintf(text, sizeof text, "zerotier-nx %s is out (you have %s).", latest, ztnx_version());
        Toast(UpdateNotifyPath, "ZeroTier: update available", text, 10000);
    }

    void AnnounceLowMemory(u32 free_kb) {
        char text[128];
        util::SNPrintf(text, sizeof text, "Only %u KB was free after boot. If the Switch crashes (2001-0132), turn off a sysmodule.",
                       static_cast<unsigned>(free_kb));
        Toast(MemoryNotifyPath, "ZeroTier: low system memory", text, 10000);
    }

    ZtnxCtlStatus Get() {
        ZtnxCtlStatus s;
        {
            std::scoped_lock lk(g_mutex);
            s = g_status;
        }
        s.memory_kb = static_cast<u32>(memory::Own() / 1024);
        u64 free_bytes = 0, total = 0;
        if (memory::SystemPool(&free_bytes, &total)) s.system_free_kb = static_cast<u32>(free_bytes / 1024);
        const u64 now = NowNs();
        const u64 ran = g_engine_ran_ns;
        const u64 idle_s = ran && now > ran ? (now - ran) / 1'000'000'000ull : 0;
        // Suspended (the console dozing or asleep, or paused) isn't stuck:
        // the loop is meant to be idle. Resuming counts as a round.
        const bool suspended = g_runtime && g_runtime->IsSuspended();
        if (idle_s >= 3 && !suspended && s.state != ZTNX_CTL_PAUSED && s.state != ZTNX_CTL_STOPPING) s.engine_stalled_s = static_cast<u32>(idle_s);
        // A stuck loop can't log where it is: say it from here (the overlay
        // asks twice a second while it's open).
        if (s.engine_stalled_s >= 10 && !g_stall_logged.exchange(true)) {
            const char *step = g_engine_step;
            const char *driver = ztnx_driver_step();
            Log("engine loop stuck for %u s, in: %s (driver's last step: %s)", s.engine_stalled_s, step ? step : "the engine",
                driver ? driver : "none");
        }
        return s;
    }

    void EngineRan(u64 now_ns) {
        g_engine_ran_ns = now_ns;
        if (g_stall_logged.load(std::memory_order_relaxed)) {
            g_stall_logged = false;
            Log("engine loop running again");
        }
    }

    void EngineStep(const char *what) {
        g_engine_step = what;
    }

    void SetOffline(bool offline) {
        std::scoped_lock lk(g_mutex);
        if (offline) g_status.flags |= ZTNX_CTL_FLAG_OFFLINE;
        else g_status.flags &= ~static_cast<u32>(ZTNX_CTL_FLAG_OFFLINE);
    }

    size_t GetLastError(char *out, size_t cap) {
        std::scoped_lock lk(g_mutex);
        return static_cast<size_t>(util::SNPrintf(out, cap, "%s", g_last_error));
    }

    size_t GetConfName(char *out, size_t cap) {
        std::scoped_lock lk(g_mutex);
        return static_cast<size_t>(util::SNPrintf(out, cap, "%s", g_conf_name));
    }

    size_t GetPeers(ZtnxPeerInfo *out, size_t max) {
        std::scoped_lock lk(g_mutex);
        std::memcpy(out, g_peers, std::min(g_peer_count, max) * sizeof *out);
        return g_peer_total;
    }

    bool IsPaused() {
        return g_paused;
    }

    bool IsConnected() {
        std::scoped_lock lk(g_mutex);
        return g_status.state == ZTNX_CTL_CONNECTED;
    }

    bool IsStopping() {
        std::scoped_lock lk(g_mutex);
        return g_status.state == ZTNX_CTL_STOPPING;
    }

    void SetStopping() {
        std::scoped_lock lk(g_mutex);
        g_status.state = ZTNX_CTL_STOPPING;
    }

    void SetPaused(bool paused) {
        ::ztnx::Runtime *rt;
        {
            std::scoped_lock lk(g_mutex);
            if (g_paused == paused || !g_runtime || g_status.state == ZTNX_CTL_STOPPING) return;
            g_paused = paused;
            rt = g_runtime;
            if (paused) {
                g_status.state = ZTNX_CTL_PAUSED;
                WriteFile(PausedPath, "1", 1);
            } else {
                g_status.state = RunningState();
                static_cast<void>(fs::DeleteFile(PausedPath));
                // The loop didn't run while paused: that isn't a stall.
                g_engine_ran_ns = NowNs();
            }
        }
        // Without waiting for the engine loop: ztnx:ctl must always answer,
        // even while the loop is busy or stuck. Homebrew's tunnel sockets
        // fail at once anyway (bsd_mitm checks IsPaused), and the loop
        // closes or reopens the engine's own within a second.
        rt->RequestSuspended(::ztnx::Runtime::kPaused, paused);
        Log("status: ZeroTier %s", paused ? "paused" : "resumed");
    }

}
