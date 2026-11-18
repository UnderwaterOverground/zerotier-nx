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
        // The version from the start: ztnx:ctl answers before Initialize.
        constinit ZtnxCtlStatus g_status = {.version = ZTNX_CTL_VERSION};
        constinit std::atomic<u64> g_requested_nwid = 0;
        constinit char g_last_error[192] = {};
        constinit char g_net_name[ZTNX_CTL_NAME_MAX] = {};
        constinit ZtnxCtlPeer g_peers[ZTNX_CTL_MAX_PEERS] = {};
        constinit size_t g_peer_count = 0;  // in g_peers
        constinit size_t g_peer_total = 0;  // known, including any that didn't fit
        constinit bool g_net_ok = false;    // on the network, with an address
        // What the last toast about joining was for (a net_status, or -1), so
        // each change is announced once.
        constinit int g_announced_net = -1;
        constinit bool g_announced_truncated = false;
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
            return g_net_ok ? ZTNX_CTL_CONNECTED : ZTNX_CTL_CONNECTING;
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

    void SetNode(u64 node, u64 nwid) {
        std::scoped_lock lk(g_mutex);
        g_status.node = node;
        g_status.nwid = nwid;
    }

    void SetConfigError(const char *message) {
        {
            std::scoped_lock lk(g_mutex);
            g_status.flags |= ZTNX_CTL_FLAG_CONF_ERROR;
            CopySafe(g_last_error, sizeof g_last_error, message);
        }
        char text[220];
        util::SNPrintf(text, sizeof text, "%s", g_last_error);
        Toast(ConfigNotifyPath, "ZeroTier: setup needed", text, ConfigToastMs);
    }

    void SetMakingIdentity(bool making) {
        std::scoped_lock lk(g_mutex);
        if (making) g_status.flags |= ZTNX_CTL_FLAG_MAKING_ID;
        else g_status.flags &= ~static_cast<u32>(ZTNX_CTL_FLAG_MAKING_ID);
    }

    void RequestNetwork(u64 nwid) {
        if (nwid != 0) g_requested_nwid = nwid;
    }

    u64 TakeNetworkRequest() {
        return g_requested_nwid.exchange(0);
    }

    void ChangeNetwork(u64 nwid) {
        std::scoped_lock lk(g_mutex);
        g_status.nwid = nwid;
        g_status.flags &= ~static_cast<u32>(ZTNX_CTL_FLAG_CONF_ERROR);
        g_status.net_status = ZTNX_CTL_NET_REQUESTING;
        g_status.truncated = 0;
        std::memset(g_status.ipv4, 0, sizeof g_status.ipv4);
        g_net_ok = false;
        g_net_name[0] = 0;
        g_last_error[0] = 0;
        g_announced_net = -1;
        g_announced_truncated = false;
        if (g_runtime && !g_paused && g_status.state != ZTNX_CTL_STOPPING) g_status.state = RunningState();
    }

    void SetNetwork(const ZtnxNetConfig &c) {
        char title[48] = {}, text[200] = {};
        u32 toast_ms = 0;
        {
            std::scoped_lock lk(g_mutex);
            g_status.net_status = c.status;
            g_status.truncated = c.truncated;
            g_net_ok = c.status == ZTNX_NET_OK && c.n_addrs > 0;
            if (g_net_ok) std::memcpy(g_status.ipv4, c.addrs[0].ip, 4);
            else std::memset(g_status.ipv4, 0, sizeof g_status.ipv4);
            CopySafe(g_net_name, sizeof g_net_name, c.name);
            if (!g_paused && g_status.state != ZTNX_CTL_STOPPING && g_runtime) g_status.state = RunningState();
            if (g_net_ok) {
                g_last_error[0] = 0;
                AnnounceConnected();
            }
            // Say once what stands in the way, with what to do about it.
            const int status = static_cast<int>(c.status);
            if (!g_net_ok && status != g_announced_net) {
                switch (c.status) {
                    case ZTNX_NET_ACCESS_DENIED:
                        util::SNPrintf(g_last_error, sizeof g_last_error, "Authorize %010llx in the network's controller (my.zerotier.com or your own).",
                                       static_cast<unsigned long long>(g_status.node));
                        util::SNPrintf(title, sizeof title, "ZeroTier: not authorized yet");
                        break;
                    case ZTNX_NET_NOT_FOUND:
                        util::SNPrintf(g_last_error, sizeof g_last_error, "There is no network %016llx. Check its ID: select Network in the ZeroTier overlay.",
                                       static_cast<unsigned long long>(g_status.nwid));
                        util::SNPrintf(title, sizeof title, "ZeroTier: network not found");
                        break;
                    case ZTNX_NET_AUTH_REQUIRED:
                        util::SNPrintf(g_last_error, sizeof g_last_error, "This network asks for single sign-on, which the Switch can't do.");
                        util::SNPrintf(title, sizeof title, "ZeroTier: can't join");
                        break;
                    case ZTNX_NET_CLIENT_TOO_OLD:
                        util::SNPrintf(g_last_error, sizeof g_last_error, "The network's controller says this ZeroTier is too old for it.");
                        util::SNPrintf(title, sizeof title, "ZeroTier: can't join");
                        break;
                    default:
                        break;
                }
                if (title[0]) {
                    g_announced_net = status;
                    util::SNPrintf(text, sizeof text, "%s", g_last_error);
                    toast_ms = ConfigToastMs;
                }
            }
            if (c.truncated && !g_announced_truncated && !title[0]) {
                g_announced_truncated = true;
                util::SNPrintf(title, sizeof title, "ZeroTier: network too large");
                if (c.truncated & ZTNX_TRUNCATED_RULES) {
                    // ZeroTier's rules end by accepting what the earlier ones
                    // let through: cut short, they let nothing through.
                    util::SNPrintf(text, sizeof text, "This network has more traffic rules than the Switch has room for, so its traffic is blocked. It needs fewer rules.");
                } else {
                    util::SNPrintf(text, sizeof text, "This network has more routes, addresses or tags than the Switch has room for. Some traffic may not work.");
                }
                if (!g_last_error[0]) util::SNPrintf(g_last_error, sizeof g_last_error, "%s", text);
                toast_ms = ConfigToastMs;
            }
        }
        if (toast_ms) Toast(ConfigNotifyPath, title, text, toast_ms);
    }

    void OnEngineEvent(u32 event) {
        std::scoped_lock lk(g_mutex);
        if (event == ZTNX_EVENT_ONLINE) g_status.flags &= ~static_cast<u32>(ZTNX_CTL_FLAG_NO_ROOTS);
        else if (event == ZTNX_EVENT_OFFLINE) g_status.flags |= ZTNX_CTL_FLAG_NO_ROOTS;
    }

    namespace {

        // The name config.ini gives an address ("ip name\n" lines), into
        // out; empty if none.
        void NameOf(const char *names, const u8 ip[4], char *out, size_t cap) {
            out[0] = 0;
            char want[16];
            const int want_len = util::SNPrintf(want, sizeof want, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
            for (const char *line = names; line && *line;) {
                const char *end = std::strchr(line, '\n');
                const size_t len = end ? static_cast<size_t>(end - line) : std::strlen(line);
                if (len > static_cast<size_t>(want_len) + 1 && std::memcmp(line, want, want_len) == 0 && line[want_len] == ' ') {
                    const size_t name_len = std::min(len - want_len - 1, cap - 1);
                    std::memcpy(out, line + want_len + 1, name_len);
                    out[name_len] = 0;
                    return;
                }
                line = end ? end + 1 : nullptr;
            }
        }

    }

    void SetPeers(const ZtnxPeerInfo *peers, size_t n, size_t total, const ZtnxNeighbor *neighbors, size_t n_neighbors, const char *names) {
        std::scoped_lock lk(g_mutex);
        g_peer_total = total;
        g_peer_count = std::min(n, static_cast<size_t>(ZTNX_CTL_MAX_PEERS));
        u32 leaves = 0, direct = 0;
        for (size_t i = 0; i < g_peer_count; i++) {
            const ZtnxPeerInfo &p = peers[i];
            ZtnxCtlPeer &o = g_peers[i];
            std::memset(std::addressof(o), 0, sizeof o);
            o.address = p.address;
            o.latency_ms = p.latency_ms;
            o.last_rx_ms = p.last_rx_ms;
            std::memcpy(o.path_ip, p.path_ip, 4);
            o.path_port = p.path_port;
            o.role = p.role;
            o.direct = p.direct;
            std::memcpy(o.version, p.version, 3);
            if (p.role == ZTNX_PEER_LEAF) {
                leaves++;
                if (p.direct) direct++;
            }
            // Its address on the network, if it has talked to us (ARP), and
            // the name config.ini gives that address.
            const u64 mac = g_status.nwid ? ztnx_engine_peer_mac(p.address, g_status.nwid) : 0;
            for (size_t k = 0; mac && k < n_neighbors; k++) {
                if (neighbors[k].mac != mac) continue;
                std::memcpy(o.ipv4, neighbors[k].ip, 4);
                NameOf(names, o.ipv4, o.name, sizeof o.name);
                break;
            }
        }
        g_status.peers = leaves;
        g_status.peers_up = direct;
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

    size_t GetNetworkName(char *out, size_t cap) {
        std::scoped_lock lk(g_mutex);
        return static_cast<size_t>(util::SNPrintf(out, cap, "%s", g_net_name));
    }

    size_t GetPeers(ZtnxCtlPeer *out, size_t max) {
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
