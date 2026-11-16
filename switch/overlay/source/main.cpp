// ZeroTier overlay: status, devices, pause and stop/start for the
// zerotier-nx sysmodule, through its ztnx:ctl service (native/ctl/ztnx_ctl.h).
#define TESLA_INIT_IMPL
#include <tesla.hpp>

#include <dirent.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>

#include "ztnx_ctl.h"
// The newest firmware the sysmodule's Atmosphère libraries know (built from
// the same tree): on a newer major version they abort before zerotier-nx can
// log anything (patches/atmosphere-firmware-major-only.patch).
#include "vapours/ams/ams_target_firmware.h"

namespace {

    // ---- ztnx:ctl client -------------------------------------------------

    // Atmosphère's sm makes a request for a service nobody has registered
    // wait until someone does (for boot ordering), so the overlay would hang
    // when zerotier-nx isn't running: ask whether it exists first.
    bool ServiceExists(const char *name) {
        u8 has = 0;
        const SmServiceName sn = smEncodeName(name);
        Result rc = 0;
        tsl::hlp::doWithSmSession([&] { rc = tipcDispatchInOut(smGetServiceSessionTipc(), 65100, sn, has); });  // see ctl::Main
        return R_SUCCEEDED(rc) && (has & 1);
    }

    // Every ztnx:ctl request runs on this thread, so a sysmodule that doesn't
    // answer (busy, or stuck) can't freeze the overlay: the panel keeps its
    // last answer and says the sysmodule isn't responding. The UI thread
    // only reads the snapshot and posts requests.
    namespace ctl {

        struct Snapshot {
            bool valid = false;  // the thread has looked at least once
            bool have = false;   // a session is open
            bool status_ok = false;
            ZtnxCtlStatus status = {};
            char last_error[192] = {};
            char net_name[ZTNX_CTL_NAME_MAX] = {};
            ZtnxCtlPeer peers[ZTNX_CTL_MAX_PEERS] = {};
            u32 peer_count = 0;  // all of them, which can be more than fit in peers
        };

        Thread g_thread;
        bool g_started = false;
        UEvent g_wake;
        Mutex g_mutex;  // guards g_snap; never held during a request
        Snapshot g_snap;
        std::atomic<bool> g_quit{false};
        std::atomic<bool> g_wanted{true};          // false: close the session, don't reopen
        std::atomic<int> g_set_paused{-1};         // a SetPaused to send (0 or 1)
        std::atomic<bool> g_pause_pending{false};  // until a status after it is in
        std::atomic<bool> g_stop{false};           // a Stop to send
        std::atomic<bool> g_stop_done{false};
        Result g_stop_rc = 0;
        u32 g_stop_code = 0;
        std::atomic<u64> g_call_since{0};  // system tick the current request began, 0: none

        Service g_session;  // the thread's own
        bool g_open = false;

        template <class F>
        auto Call(F &&f) {
            g_call_since = armGetSystemTick();
            auto r = f();
            g_call_since = 0;
            return r;
        }

        size_t GetString(u32 cmd, char *buf, size_t cap) {
            u32 len = 0;
            const Result rc = Call([&] {
                return serviceDispatchOut(&g_session, cmd, len, .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out}, .buffers = {{buf, cap}});
            });
            if (R_FAILED(rc)) {
                buf[0] = 0;
                return 0;
            }
            buf[cap - 1] = 0;
            return len;
        }

        void Close() {
            if (g_open) serviceClose(&g_session);
            g_open = false;
        }

        void Refresh() {
            static Snapshot s;  // keeps the thread's stack small
            s = Snapshot{};
            if (g_open) {
                s.status_ok = R_SUCCEEDED(Call([] { return serviceDispatchOut(&g_session, 0, s.status); }));
                if (!s.status_ok) Close();  // the process went away
            }
            if (s.status_ok) GetString(2, s.last_error, sizeof s.last_error);
            if (s.status_ok) GetString(5, s.net_name, sizeof s.net_name);
            if (s.status_ok) {
                u32 n = 0;
                const Result rc = Call([&] {
                    return serviceDispatchOut(&g_session, 4, n, .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
                                              .buffers = {{s.peers, sizeof s.peers}});
                });
                s.peer_count = R_SUCCEEDED(rc) ? n : 0;
            }
            s.have = g_open;
            s.valid = true;
            mutexLock(&g_mutex);
            g_snap = s;
            mutexUnlock(&g_mutex);
        }

        void Main(void *) {
            while (!g_quit) {
                if (!g_wanted) {
                    Close();
                } else if (!g_open) {
                    // Only once the service exists (see ServiceExists). Tesla
                    // keeps no sm session open after start-up, so open one
                    // around each use (libnx counts them, across threads too).
                    g_open = Call([] {
                        bool ok = false;
                        tsl::hlp::doWithSmSession([&] { ok = ServiceExists(ZTNX_CTL_SERVICE) && R_SUCCEEDED(smGetService(&g_session, ZTNX_CTL_SERVICE)); });
                        return ok;
                    });
                }
                if (g_open && g_stop) {
                    struct {
                        u32 code, detail;
                    } out = {};
                    g_stop_rc = Call([&] { return serviceDispatchOut(&g_session, 3, out); });
                    g_stop_code = out.code;
                    g_stop = false;
                    g_stop_done = true;
                }
                const int paused = g_set_paused.exchange(-1);
                if (g_open && paused >= 0) {
                    const u8 v = static_cast<u8>(paused);
                    Call([&] { return serviceDispatchIn(&g_session, 1, v); });
                }
                Refresh();
                if (paused >= 0) g_pause_pending = false;
                // About twice a second, or at once when asked.
                waitSingle(waiterForUEvent(&g_wake), 500'000'000ull);
            }
            Close();
        }

        void Wake() { ueventSignal(&g_wake); }

        void Start() {
            ueventCreate(&g_wake, true);
            mutexInit(&g_mutex);
            g_started = R_SUCCEEDED(threadCreate(&g_thread, Main, nullptr, nullptr, 0x4000, 0x2C, -2)) && R_SUCCEEDED(threadStart(&g_thread));
            // A moment for the first answer, so the panel opens with it.
            for (int i = 0; i < 30 && g_started; i++) {
                mutexLock(&g_mutex);
                const bool valid = g_snap.valid;
                mutexUnlock(&g_mutex);
                if (valid) break;
                svcSleepThread(10'000'000);
            }
        }

        void Finish() {
            if (!g_started) return;
            g_quit = true;
            Wake();
            // A request the sysmodule never answers would block forever:
            // then leave the thread to the process's exit.
            if (R_SUCCEEDED(waitSingleHandle(g_thread.handle, 1'000'000'000ull))) threadClose(&g_thread);
        }

        Snapshot Get() {
            mutexLock(&g_mutex);
            const Snapshot s = g_snap;
            mutexUnlock(&g_mutex);
            return s;
        }

        // How long the current request has waited for an answer.
        u64 BusySeconds() {
            const u64 since = g_call_since;
            return since ? armTicksToNs(armGetSystemTick() - since) / 1'000'000'000ull : 0;
        }

    }

    bool g_have_ctl = false;
    bool g_valid = false;  // ctl::Snapshot::valid
    ZtnxCtlStatus g_status = {};
    bool g_status_ok = false;

    // ---- stop and start ------------------------------------------------------

    // Stop asks the sysmodule to end itself (ztnx:ctl Stop): it refuses
    // whenever exiting could disturb the console or an app. Start launches it
    // through pm. Neither touches its boot flag.
    constexpr u64 SysmoduleProgramId = 0x4200000000005A54;
    constexpr const char DisabledPath[] = "sdmc:/config/zerotier-nx/disabled";
    // Our system tick, so the sysmodule's crash guard knows this start isn't
    // a boot.
    constexpr const char StartRequestedPath[] = "sdmc:/config/zerotier-nx/start_requested";

    bool SysmoduleRunning() {
        u64 pid = 0;
        return R_SUCCEEDED(pmdmntGetProcessId(&pid, SysmoduleProgramId)) && pid != 0;
    }

    enum class Phase {
        Idle,
        Stopping,  // the Stop request is under way (on the ctl thread)
        Exiting,   // accepted; waiting for the process and its service to go
        Starting,  // running, but its service isn't there yet
    };
    Phase g_phase = Phase::Idle;
    u64 g_phase_since = 0;  // system tick
    bool g_we_started = false;
    char g_msg[2][64] = {};  // the outcome of the last stop or start
    bool g_msg_problem = false;  // drawn in red

    void SetPhase(Phase p) {
        g_phase = p;
        g_phase_since = armGetSystemTick();
    }

    u64 PhaseSeconds() { return armTicksToNs(armGetSystemTick() - g_phase_since) / 1'000'000'000ull; }

    // A stop or start that didn't happen (shown in red).
    void Say(const char *first, const char *second = "") {
        std::memset(g_msg, 0, sizeof g_msg);  // see DrawMessage
        std::snprintf(g_msg[0], sizeof g_msg[0], "%s", first);
        std::snprintf(g_msg[1], sizeof g_msg[1], "%s", second);
        g_msg_problem = true;
    }

    // Progress or success.
    void Note(const char *first, const char *second = "") {
        Say(first, second);
        g_msg_problem = false;
    }

    // Stop can take a few seconds (it waits for the engine and the system);
    // the ctl thread sends it while the overlay keeps drawing.
    void BeginStop() {
        if (!g_have_ctl || g_phase != Phase::Idle) return;
        ctl::g_stop_done = false;
        ctl::g_stop = true;
        ctl::Wake();
        Note("");
        SetPhase(Phase::Stopping);
    }

    void FinishStop() {
        SetPhase(Phase::Idle);
        // A failed request most likely means it exited before replying.
        if (R_FAILED(ctl::g_stop_rc) || ctl::g_stop_code == ZTNX_CTL_STOP_OK) {
            ctl::g_wanted = false;
            ctl::Wake();
            g_have_ctl = g_status_ok = false;
            SetPhase(Phase::Exiting);
            return;
        }
        switch (ctl::g_stop_code) {
            case ZTNX_CTL_STOP_HOMEBREW:
                Say("Close homebrew apps first: they have", "connections through zerotier-nx.");
                break;
            case ZTNX_CTL_STOP_BUSY:
                Say("Busy (sleep, wake or setting up).", "Try again in a moment.");
                break;
            default:
                Say("Couldn't stop cleanly. It stays idle", "until the console restarts.");
                break;
        }
    }

    bool FileExists(const char *path) {
        bool found = false;
        tsl::hlp::doWithSDCardHandle([&] {
            if (FILE *f = std::fopen(path, "r")) {
                found = true;
                std::fclose(f);
            }
        });
        return found;
    }

    void StartSysmodule() {
        if (g_phase != Phase::Idle) return;
        if (SysmoduleRunning()) {
            SetPhase(Phase::Starting);
            return;
        }
        if (FileExists(DisabledPath)) {
            Say("config/zerotier-nx/disabled keeps it off.", "Delete that file to start it.");
            return;
        }
        tsl::hlp::doWithSDCardHandle([] {
            if (FILE *f = std::fopen(StartRequestedPath, "w")) {
                char tick[24];  // snprintf, not fprintf: that would add 17 KB
                std::snprintf(tick, sizeof tick, "%llu\n", static_cast<unsigned long long>(armGetSystemTick()));
                std::fputs(tick, f);
                std::fclose(f);
            }
        });
        Result rc = 0;
        tsl::hlp::doWithSmSession([&rc] { rc = pmshellInitialize(); });  // see ctl::Main
        if (R_SUCCEEDED(rc)) {
            const NcmProgramLocation loc = {.program_id = SysmoduleProgramId, .storageID = NcmStorageId_None};
            u64 pid = 0;
            rc = pmshellLaunchProgram(0, &loc, &pid);
            pmshellExit();
        }
        if (R_FAILED(rc)) {
            tsl::hlp::doWithSDCardHandle([] { std::remove(StartRequestedPath); });
            if (SysmoduleRunning()) {  // started by someone else meanwhile
                SetPhase(Phase::Starting);
                return;
            }
            char line[64];
            std::snprintf(line, sizeof line, "Couldn't start it (error 0x%x).", rc);
            Say(line, "Restarting the console starts it.");
            return;
        }
        Note("");
        g_we_started = true;
        SetPhase(Phase::Starting);
    }

    // ---- state shared with the drawers -------------------------------------

    // Why the sysmodule isn't running, read from the SD card when the overlay
    // opens (the crash guard's file, the kill switch, or a missing boot flag).
    constexpr const char CrashedPath[] = "sdmc:/config/zerotier-nx/crashed";
    constexpr const char Boot2Path[] = "sdmc:/atmosphere/contents/4200000000005A54/flags/boot2.flag";
    char g_crashed[160] = {};   // first line of the crash guard's reason
    char g_not_started[200] = {};  // why it declined to start (too little memory)
    bool g_no_boot_flag = false;
    bool g_disabled = false;
    char g_fw_too_new[16] = {};  // the console's firmware, if this build can't run on it
    char g_fw_max[16] = {};      // what it runs on, e.g. "23.x"

    // Same test as our patched libstratosphere's (hos_version_api.cpp): a
    // newer minor or micro version is fine, a newer major one aborts the
    // sysmodule.
    void CheckFirmware() {
        constexpr u32 MaxMajor = (ATMOSPHERE_TARGET_FIRMWARE_MAX >> 24) & 0xFF;
        g_fw_too_new[0] = 0;
        std::snprintf(g_fw_max, sizeof g_fw_max, "%u.x", MaxMajor);
        SetSysFirmwareVersion fw = {};
        if (R_FAILED(setsysGetFirmwareVersion(&fw))) return;  // Tesla opened setsys
        if (fw.major > MaxMajor)
            std::snprintf(g_fw_too_new, sizeof g_fw_too_new, "%u.%u.%u", fw.major, fw.minor, fw.micro);
    }

    void ReadWhyNotRunning() {
        CheckFirmware();
        tsl::hlp::doWithSDCardHandle([] {
            g_crashed[0] = 0;
            if (FILE *f = std::fopen(CrashedPath, "r")) {
                if (!std::fgets(g_crashed, sizeof g_crashed, f) || !g_crashed[0]) std::snprintf(g_crashed, sizeof g_crashed, "repeated failures");
                g_crashed[std::strcspn(g_crashed, "\r\n")] = 0;
                std::fclose(f);
            }
            g_not_started[0] = 0;
            if (FILE *f = std::fopen("sdmc:/config/zerotier-nx/not_started", "r")) {
                if (std::fgets(g_not_started, sizeof g_not_started, f)) g_not_started[std::strcspn(g_not_started, "\r\n")] = 0;
                std::fclose(f);
            }
            FILE *b = std::fopen(Boot2Path, "r");
            g_no_boot_flag = b == nullptr;
            if (b) std::fclose(b);
            FILE *d = std::fopen(DisabledPath, "r");
            g_disabled = d != nullptr;
            if (d) std::fclose(d);
        });
    }

    // Clears the crash guard and starts zerotier-nx again.
    void TurnBackOn() {
        tsl::hlp::doWithSDCardHandle([] {
            for (const char *p : {CrashedPath, "sdmc:/config/zerotier-nx/starting", "sdmc:/config/zerotier-nx/sleep_failures",
                                  "sdmc:/config/zerotier-nx/sleeping"}) {
                std::remove(p);
            }
        });
        g_crashed[0] = 0;
        StartSysmodule();
    }

    // Moves the stop/start phases along (twice a second).
    void Poll() {
        switch (g_phase) {
            case Phase::Stopping:
                if (ctl::g_stop_done) FinishStop();
                break;
            case Phase::Exiting:
                // Gone from pm and from sm: a new instance can register again.
                if (!SysmoduleRunning() && !ServiceExists(ZTNX_CTL_SERVICE)) {
                    ctl::g_wanted = true;
                    SetPhase(Phase::Idle);
                    ReadWhyNotRunning();
                    Note("Stopped. It starts again at the next boot.");
                } else if (PhaseSeconds() >= 10) {
                    Note("Still stopping...");
                }
                break;
            case Phase::Starting:
                if (!SysmoduleRunning()) {
                    SetPhase(Phase::Idle);
                    ReadWhyNotRunning();
                    if (g_we_started && g_fw_too_new[0]) {
                        char line[64];
                        std::snprintf(line, sizeof line, "It can't run on firmware %s.", g_fw_too_new);
                        Say(line, "Update zerotier-nx.");
                    } else if (g_we_started) {
                        Say("It stopped right away. See", "config/zerotier-nx/sysmodule.log.");
                    }
                    g_we_started = false;
                } else if (g_have_ctl) {  // the ctl thread opens the session
                    SetPhase(Phase::Idle);
                    g_we_started = false;
                }
                break;
            case Phase::Idle:
                // Running without its service: starting up (it waits for the
                // network first), or a stale session to an old instance.
                if (!g_have_ctl && SysmoduleRunning()) SetPhase(Phase::Starting);
                break;
        }
    }

    char g_last_error[192] = {};
    char g_net_name[ZTNX_CTL_NAME_MAX] = {};
    ZtnxCtlPeer g_peers[ZTNX_CTL_MAX_PEERS] = {};
    u32 g_peer_count = 0;  // all of them; the first (up to ZTNX_CTL_MAX_PEERS) are in g_peers
    u32 g_peers_shown = 0;  // how many are in g_peers
    u8 g_order[ZTNX_CTL_MAX_PEERS] = {};  // g_peers indices in the order listed

    void CtlSetPaused(bool paused) {
        if (!g_have_ctl || g_phase != Phase::Idle) return;
        ctl::g_pause_pending = true;
        ctl::g_set_paused = paused;
        ctl::Wake();
    }

    // Takes the ctl thread's latest answers.
    void Refresh() {
        const ctl::Snapshot s = ctl::Get();
        g_valid = s.valid;
        g_have_ctl = s.have && g_phase != Phase::Exiting;
        g_status_ok = s.status_ok && g_have_ctl;
        g_status = s.status;
        std::memcpy(g_peers, s.peers, sizeof g_peers);
        g_peer_count = s.peer_count;
        g_peers_shown = std::min<u32>(g_peer_count, ZTNX_CTL_MAX_PEERS);
        for (u32 i = 0; i < g_peers_shown; i++) g_order[i] = static_cast<u8>(i);
        // In a fixed order, so rows stay put: named devices by name, the
        // others by address, ZeroTier's own servers last.
        std::sort(g_order, g_order + g_peers_shown, [](u8 a, u8 b) {
            const ZtnxCtlPeer &x = g_peers[a], &y = g_peers[b];
            const int kx = x.role == ZTNX_CTL_PEER_PLANET ? 2 : x.name[0] ? 0 : 1;
            const int ky = y.role == ZTNX_CTL_PEER_PLANET ? 2 : y.name[0] ? 0 : 1;
            if (kx != ky) return kx < ky;
            if (const int c = std::strcmp(x.name, y.name); c != 0) return c < 0;
            return x.address < y.address;
        });
        std::snprintf(g_last_error, sizeof g_last_error, "%s", s.last_error);
        std::snprintf(g_net_name, sizeof g_net_name, "%s", s.net_name);
    }

    // "12 s ago", "4 min ago", "2 h ago".
    void Ago(u32 secs, char *out, size_t cap) {
        if (secs < 60) std::snprintf(out, cap, "%u s ago", secs);
        else if (secs < 3600) std::snprintf(out, cap, "%u min ago", secs / 60);
        else if (secs < 86400) std::snprintf(out, cap, "%u h ago", secs / 3600);
        else std::snprintf(out, cap, "%u d ago", secs / 86400);
    }

    // ---- drawing ------------------------------------------------------------

    // Tesla's CustomDrawer, kept inside its list: Tesla's sets the clip to
    // the drawer's own bounds, replacing the list's, so a drawer partly
    // scrolled out of the list drew over the header or the footer.
    class Drawer : public tsl::elm::Element {
        public:
            using Func = void (*)(tsl::gfx::Renderer *, s32 x, s32 y, s32 w, s32 h);
            explicit Drawer(Func f) : m_func(f) {}

            void draw(tsl::gfx::Renderer *r) override {
                s32 top = getTopBound(), bottom = getBottomBound();
                if (Element *list = getParent()) {
                    top = std::max(top, list->getTopBound());
                    bottom = std::min(bottom, list->getBottomBound());
                }
                if (bottom <= top) return;
                r->enableScissoring(getX(), top, getWidth(), bottom - top);
                m_func(r, ELEMENT_BOUNDS(this));
                r->disableScissoring();
            }

            void layout(u16, u16, u16, u16) override {}

        private:
            Func m_func;
    };

    constexpr tsl::Color White{0xF, 0xF, 0xF, 0xF};
    constexpr tsl::Color Black{0x0, 0x0, 0x0, 0xF};
    constexpr tsl::Color Grey{0xA, 0xA, 0xA, 0xF};
    constexpr tsl::Color Green{0x4, 0xE, 0x6, 0xF};
    constexpr tsl::Color Yellow{0xF, 0xC, 0x3, 0xF};
    constexpr tsl::Color Blue{0x5, 0xA, 0xF, 0xF};
    constexpr tsl::Color Red{0xF, 0x5, 0x5, 0xF};

    // Draws text over two lines at most (broken at a space, about `cols`
    // characters each; the rest is cut with "...").
    void DrawTwoLines(tsl::gfx::Renderer *r, const char *text, s32 x, s32 y, u32 size, tsl::Color c, size_t cols) {
        char first[96], second[96] = "";
        size_t cut = std::strlen(text);
        if (cut > cols) {
            cut = cols;
            while (cut > 0 && text[cut] != ' ') cut--;
            if (cut == 0) cut = cols;
        }
        std::snprintf(first, sizeof first, "%.*s", static_cast<int>(cut), text);
        const char *rest = text + cut + (text[cut] == ' ');
        if (*rest) {
            if (std::strlen(rest) > cols) std::snprintf(second, sizeof second, "%.*s...", static_cast<int>(cols - 3), rest);
            else std::snprintf(second, sizeof second, "%s", rest);
        }
        if (first[0]) r->drawString(first, false, x, y, size, r->a(c));  // see DrawMessage
        if (second[0]) r->drawString(second, false, x, y + size + 3, size, r->a(c));
    }

    s32 TextWidth(tsl::gfx::Renderer *r, const char *text, u32 size) {
        return static_cast<s32>(r->drawString(text, false, 0, 0, size, tsl::style::color::ColorTransparent).first);
    }

    // `text` into `out`, cut short with "..." to fit `w` pixels.
    void Fit(tsl::gfx::Renderer *r, const char *text, u32 size, s32 w, char *out, size_t cap) {
        std::snprintf(out, cap, "%s", text);
        for (size_t n = std::strlen(out); n > 0 && TextWidth(r, out, size) > w; n--) {
            std::snprintf(out, cap, "%.*s...", static_cast<int>(n - 1), text);
        }
    }

    // What a device is called: its configured name, else its ZeroTier
    // address.
    void PeerLabel(const ZtnxCtlPeer &p, char *out, size_t cap) {
        if (p.name[0]) std::snprintf(out, cap, "%s", p.name);
        else if (p.role == ZTNX_CTL_PEER_PLANET) std::snprintf(out, cap, "ZeroTier server %010llx", static_cast<unsigned long long>(p.address));
        else std::snprintf(out, cap, "%010llx", static_cast<unsigned long long>(p.address));
    }

    // How a device is reached, in a few words.
    void PeerState(const ZtnxCtlPeer &p, char *out, size_t cap) {
        if (!p.direct) std::snprintf(out, cap, "Relayed");
        else if (p.latency_ms >= 0) std::snprintf(out, cap, "Direct, %d ms", static_cast<int>(p.latency_ms));
        else std::snprintf(out, cap, "Direct");
    }

    // Green: a direct path; yellow: through ZeroTier's relays (slower).
    tsl::Color StateColor(const ZtnxCtlPeer &p) {
        return p.direct ? Green : Yellow;
    }

    // No internet connection (not while paused or stopping: then it's moot).
    bool Offline() {
        return (g_status.flags & ZTNX_CTL_FLAG_OFFLINE) && g_status.state != ZTNX_CTL_PAUSED && g_status.state != ZTNX_CTL_STOPPING;
    }

    // Its engine loop hasn't run for a while (short pauses are normal: a
    // DNS lookup or an SD card write can take a few seconds).
    bool Stalled() { return g_status.engine_stalled_s >= 10; }

    void DrawStatus(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        const char *state = "Not running";
        tsl::Color color = Red;
        if (g_phase == Phase::Stopping || g_phase == Phase::Exiting) {
            r->drawString("Stopping...", false, x + 20, y + 40, 30, r->a(Grey));
            return;
        }
        // The sysmodule hasn't answered a request: it's busy or stuck.
        if (const u64 busy = ctl::BusySeconds(); busy >= 2) {
            char since[64];
            std::snprintf(since, sizeof since, "No reply from zerotier-nx for %llu seconds.", static_cast<unsigned long long>(busy));
            r->drawString("Not responding", false, x + 20, y + 40, 30, r->a(Red));
            r->drawString(since, false, x + 20, y + 75, 17, r->a(Grey));
            r->drawString("Restart the console if this continues.", false, x + 20, y + 100, 17, r->a(Grey));
            return;
        }
        if (!g_valid) {
            r->drawString("Checking...", false, x + 20, y + 40, 30, r->a(Grey));
            return;
        }
        if (g_phase == Phase::Starting) {
            r->drawString("Starting...", false, x + 20, y + 40, 30, r->a(Blue));
            r->drawString("The sysmodule is running and waits for", false, x + 20, y + 75, 17, r->a(Grey));
            r->drawString("the network before it can be reached.", false, x + 20, y + 100, 17, r->a(Grey));
            return;
        }
        if (g_status_ok) {
            switch (g_status.state) {
                case ZTNX_CTL_STARTING:    state = "Starting...";   color = Blue;   break;
                case ZTNX_CTL_CONNECTING:
                    switch (g_status.net_status) {
                        case ZTNX_CTL_NET_ACCESS_DENIED:  state = "Not authorized";  color = Yellow; break;
                        case ZTNX_CTL_NET_NOT_FOUND:      state = "No such network"; color = Red;    break;
                        case ZTNX_CTL_NET_AUTH_REQUIRED:  state = "Sign-in needed";  color = Red;    break;
                        case ZTNX_CTL_NET_CLIENT_TOO_OLD: state = "Not supported";   color = Red;    break;
                        default:                          state = "Connecting...";   color = Blue;   break;
                    }
                    break;
                case ZTNX_CTL_CONNECTED:   state = "Connected";     color = Green;  break;
                case ZTNX_CTL_PAUSED:      state = "Paused";        color = Grey;   break;
                case ZTNX_CTL_STOPPING:    state = "Stopping...";   color = Grey;   break;
            }
            if ((g_status.flags & ZTNX_CTL_FLAG_CONF_ERROR) && g_status.state != ZTNX_CTL_PAUSED && g_status.state != ZTNX_CTL_STOPPING) {
                state = "No network set";
                color = Red;
            }
            if (Offline()) {
                state = "Offline";
                color = Grey;
            } else if (Stalled()) {
                state = "Not responding";
                color = Red;
            }
        }
        r->drawString(state, false, x + 20, y + 40, 30, r->a(color));
        char line[128], extra[64];
        if (!g_status_ok) {
            if (g_fw_too_new[0]) {
                // Checked first: nothing else can apply, it never got to run.
                std::snprintf(line, sizeof line, "This version runs on firmware up to %s,", g_fw_max);
                r->drawString(line, false, x + 20, y + 75, 17, r->a(Grey));
                std::snprintf(line, sizeof line, "not %s. Update zerotier-nx.", g_fw_too_new);
                r->drawString(line, false, x + 20, y + 100, 17, r->a(Grey));
            } else if (g_crashed[0]) {
                // "zerotier-nx stopped itself: <why>." -> show the reason.
                const char *why = std::strstr(g_crashed, ": ");
                why = why ? why + 2 : g_crashed;
                r->drawString("It turned itself off after failures:", false, x + 20, y + 75, 17, r->a(Grey));
                DrawTwoLines(r, why, x + 20, y + 98, 15, Grey, 40);
            } else if (g_not_started[0]) {
                // "Too little system memory: other sysmodules leave N KB free ..."
                r->drawString("It didn't start: too little system memory.", false, x + 20, y + 75, 17, r->a(Grey));
                r->drawString("Other sysmodules use the rest; turn one off.", false, x + 20, y + 100, 17, r->a(Grey));
            } else if (g_disabled) {
                r->drawString("config/zerotier-nx/disabled keeps it off.", false, x + 20, y + 75, 17, r->a(Grey));
                r->drawString("Delete that file to start it.", false, x + 20, y + 100, 17, r->a(Grey));
            } else if (g_no_boot_flag) {
                r->drawString("The zerotier-nx sysmodule isn't running,", false, x + 20, y + 75, 17, r->a(Grey));
                r->drawString("and its boot setting in Sysmodules is off.", false, x + 20, y + 100, 17, r->a(Grey));
            } else {
                r->drawString("The zerotier-nx sysmodule isn't running.", false, x + 20, y + 75, 17, r->a(Grey));
                r->drawString("It starts at boot, or with Start below.", false, x + 20, y + 100, 17, r->a(Grey));
            }
            return;
        }
        if (Offline()) {
            r->drawString("No internet connection.", false, x + 20, y + 75, 17, r->a(Grey));
            r->drawString("It reconnects once the Switch is back online.", false, x + 20, y + 102, 17, r->a(Grey));
            return;
        }
        if ((g_status.flags & ZTNX_CTL_FLAG_CONF_ERROR) && g_status.state != ZTNX_CTL_PAUSED) {
            DrawTwoLines(r, g_last_error[0] ? g_last_error : "Add network=<its 16-digit ID> to config/zerotier-nx/config.ini and restart.", x + 20, y + 75, 15, Grey, 46);
            return;
        }
        if (Stalled()) {
            // It answers, but its engine loop hasn't run: it can't connect.
            std::snprintf(line, sizeof line, "It has made no progress for %u seconds.", g_status.engine_stalled_s);
            r->drawString(line, false, x + 20, y + 75, 17, r->a(Grey));
            r->drawString("Restart the console if this continues.", false, x + 20, y + 102, 17, r->a(Grey));
            return;
        }
        const unsigned long long node = g_status.node, nwid = g_status.nwid;
        if (g_status.state == ZTNX_CTL_CONNECTING) {
            // Joining: where it stands, and what the user can do about it.
            const char *second = "", *third = "";
            switch (g_status.net_status) {
                case ZTNX_CTL_NET_ACCESS_DENIED:
                    std::snprintf(line, sizeof line, "Authorize %010llx", node);
                    r->drawString(line, false, x + 20, y + 77, 20, r->a(White));
                    r->drawString("in the network's member list (for most", false, x + 20, y + 102, 15, r->a(Grey));
                    r->drawString("networks: my.zerotier.com).", false, x + 20, y + 122, 15, r->a(Grey));
                    return;
                case ZTNX_CTL_NET_NOT_FOUND:
                    std::snprintf(line, sizeof line, "Network %016llx doesn't exist.", nwid);
                    second = "Check network= in config.ini.";
                    break;
                case ZTNX_CTL_NET_AUTH_REQUIRED:
                    std::snprintf(line, sizeof line, "This network asks for single sign-on,");
                    second = "which zerotier-nx can't do.";
                    break;
                case ZTNX_CTL_NET_CLIENT_TOO_OLD:
                    std::snprintf(line, sizeof line, "This network needs a newer ZeroTier");
                    second = "than zerotier-nx has.";
                    break;
                default:
                    if (g_status.flags & ZTNX_CTL_FLAG_NO_ROOTS) {
                        std::snprintf(line, sizeof line, "ZeroTier's servers don't answer.");
                        second = "Some networks block it (UDP).";
                    } else {
                        std::snprintf(line, sizeof line, "Asking the network's controller...");
                        std::snprintf(extra, sizeof extra, "This Switch: %010llx", node);
                        second = extra;
                    }
                    break;
            }
            r->drawString(line, false, x + 20, y + 75, 17, r->a(Grey));
            if (second[0]) r->drawString(second, false, x + 20, y + 100, 17, r->a(Grey));
            if (third[0]) r->drawString(third, false, x + 20, y + 125, 17, r->a(Grey));
            return;
        }
        // Our address only while it's usable (it stays known while paused).
        s32 ly = y + 75;
        const u8 *ip = g_status.ipv4;
        if (g_status.state == ZTNX_CTL_CONNECTED) {
            if (ip[0]) {
                std::snprintf(line, sizeof line, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
                r->drawString(line, false, x + 20, ly, 20, r->a(White));
                ly += 27;
            }
            if (g_status.peers == 0) std::snprintf(line, sizeof line, "No other device seen yet.");
            else std::snprintf(line, sizeof line, "%u device%s, %u reached directly", g_status.peers, g_status.peers == 1 ? "" : "s", g_status.peers_up);
            r->drawString(line, false, x + 20, ly, 17, r->a(Grey));
            ly += 25;
            // Rules, routes or addresses beyond what this build holds.
            if (g_status.truncated & 0x01) r->drawString("Too many traffic rules: traffic is blocked.", false, x + 20, ly, 15, r->a(Yellow));
            else if (g_status.truncated) r->drawString("Some of the network's settings didn't fit.", false, x + 20, ly, 15, r->a(Yellow));
            return;
        }
        if (g_last_error[0] && g_status.state != ZTNX_CTL_PAUSED) DrawTwoLines(r, g_last_error, x + 20, ly, 15, Grey, 46);
    }

    // What's active, and the memory line.
    void DrawInfo(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        s32 ty = y + 30;
        auto line = [&](const char *text, tsl::Color c) {
            r->drawString(text, false, x + 20, ty, 17, r->a(c));
            ty += 28;
        };
        if (!g_status_ok) return;
        if (g_status.flags & ZTNX_CTL_FLAG_MITM) line("Homebrew apps reach the network.", White);
        if (g_status.flags & ZTNX_CTL_FLAG_HOSTS) line("Names from config.ini resolve (Moonlight).", White);
        if (g_status.state == ZTNX_CTL_PAUSED) line("Paused: the network is unreachable.", Grey);
        if (g_status.memory_kb) {
            char mem[96];
            std::snprintf(mem, sizeof mem, "Memory: %u.%u MB. System free: %u.%u MB.", g_status.memory_kb / 1024,
                          g_status.memory_kb % 1024 * 10 / 1024, g_status.system_free_kb / 1024, g_status.system_free_kb % 1024 * 10 / 1024);
            // Little left for other modules: say so (it can crash the console).
            line(mem, g_status.system_free_kb < ZTNX_CTL_LOW_SYSTEM_FREE_KB ? Red : Grey);
        }
    }

    // The outcome of the last stop or start.
    void DrawMessage(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        const tsl::Color c = g_msg_problem ? Red : White;
        // Never an empty string: Tesla's drawString reads one character past
        // its end before checking, so "" would draw whatever follows it.
        if (g_msg[0][0]) r->drawString(g_msg[0], false, x + 20, y + 22, 15, r->a(c));
        if (g_msg[1][0]) r->drawString(g_msg[1], false, x + 20, y + 42, 15, r->a(c));
    }

    void DrawTip(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        r->drawString("Stop ends zerotier-nx until the next boot.", false, x + 20, y + 25, 15, r->a(Grey));
        r->drawString("To keep it off, turn off its boot setting", false, x + 20, y + 47, 15, r->a(Grey));
        r->drawString("in Sysmodules.", false, x + 20, y + 69, 15, r->a(Grey));
    }

    // ---- settings -------------------------------------------------------------

    // Switches the sysmodule reads as marker files: present = off.
    constexpr const char NoNoticePath[] = "sdmc:/config/zerotier-nx/no-connect-notice";
    constexpr const char NoUpdateCheckPath[] = "sdmc:/config/zerotier-nx/no-update-check";

    bool MarkerExists(const char *path) {
        bool exists = false;
        tsl::hlp::doWithSDCardHandle([&] {
            if (FILE *f = std::fopen(path, "r")) {
                exists = true;
                std::fclose(f);
            }
        });
        return exists;
    }

    void SetMarker(const char *path, bool present) {
        tsl::hlp::doWithSDCardHandle([&] {
            if (present) {
                if (FILE *f = std::fopen(path, "w")) std::fclose(f);
            } else {
                std::remove(path);
            }
        });
    }

    // ---- GUI ----------------------------------------------------------------

    // The Devices page: every device ZeroTier is in contact with, a row
    // each: what it's called, and how it's reached at the right.
    // One element that scrolls itself: Tesla's lists scroll by moving focus
    // between items, and items can't safely come and go while one has it,
    // but devices come and go all the time.
    // The device whose details page is open.
    u64 g_detail_address = 0;
    char g_detail_label[48] = {};

    void DrawPeer(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        const ZtnxCtlPeer *p = nullptr;
        for (u32 i = 0; i < g_peers_shown; i++)
            if (g_peers[i].address == g_detail_address) p = &g_peers[i];
        if (!p) {
            r->drawString("No longer in contact with it.", false, x + 20, y + 30, 17, r->a(Grey));
            return;
        }
        s32 ty = y + 30;
        auto line = [&](const char *label, const char *value, tsl::Color c) {
            r->drawString(label, false, x + 20, ty, 17, r->a(Grey));
            r->drawString(value, false, x + 20 + 130, ty, 17, r->a(c));
            ty += 30;
        };
        char v[64];
        PeerState(*p, v, sizeof v);
        line("Reached", v, StateColor(*p));
        std::snprintf(v, sizeof v, "%010llx", static_cast<unsigned long long>(p->address));
        line("ZeroTier ID", v, White);
        if (p->ipv4[0] || p->ipv4[1] || p->ipv4[2] || p->ipv4[3]) {
            std::snprintf(v, sizeof v, "%u.%u.%u.%u", p->ipv4[0], p->ipv4[1], p->ipv4[2], p->ipv4[3]);
            line("Address", v, White);
        }
        if (p->direct) std::snprintf(v, sizeof v, "%u.%u.%u.%u:%u", p->path_ip[0], p->path_ip[1], p->path_ip[2], p->path_ip[3], p->path_port);
        else std::snprintf(v, sizeof v, "ZeroTier's relays");
        line("Through", v, White);
        if (p->direct) {
            Ago(p->last_rx_ms / 1000, v, sizeof v);
            line("Last packet", v, White);
        }
        if (p->version[0] || p->version[1] || p->version[2]) {
            std::snprintf(v, sizeof v, "%u.%u.%u", p->version[0], p->version[1], p->version[2]);
            line("Version", v, White);
        }
        line("Kind", p->role == ZTNX_CTL_PEER_PLANET ? "ZeroTier server" : p->role == ZTNX_CTL_PEER_MOON ? "Moon (own server)" : "Device", White);
    }

    class PeerGui : public tsl::Gui {
        public:
            tsl::elm::Element *createUI() override {
                auto *frame = new tsl::elm::OverlayFrame("ZeroTier", g_detail_label);
                auto *list = new tsl::elm::List();
                list->addItem(new Drawer(DrawPeer), 240);
                frame->setContent(list);
                return frame;
            }

            void update() override {
                if (++m_frames % 30 != 0) return;
                Poll();
                Refresh();
            }

        private:
            u32 m_frames = 0;
    };

    // The network joined, and this Switch on it.
    void DrawNetwork(tsl::gfx::Renderer *r, s32 x, s32 y, s32 w, s32 h) {
        if (!g_status_ok) {
            r->drawString("Not running.", false, x + 20, y + 30, 17, r->a(Grey));
            return;
        }
        s32 ty = y + 30;
        auto line = [&](const char *label, const char *value, tsl::Color c) {
            r->drawString(label, false, x + 20, ty, 17, r->a(Grey));
            if (value[0]) r->drawString(value, false, x + 20 + 130, ty, 17, r->a(c));  // see DrawMessage
            ty += 30;
        };
        char v[ZTNX_CTL_NAME_MAX + 4];
        if (g_net_name[0]) {
            Fit(r, g_net_name, 17, w - 170, v, sizeof v);
            line("Name", v, White);
        }
        if (g_status.nwid) {
            std::snprintf(v, sizeof v, "%016llx", static_cast<unsigned long long>(g_status.nwid));
            line("Network ID", v, White);
        } else {
            line("Network ID", "none in config.ini", Red);
        }
        std::snprintf(v, sizeof v, "%010llx", static_cast<unsigned long long>(g_status.node));
        line("This Switch", v, White);
        const u8 *ip = g_status.ipv4;
        if (ip[0]) {
            std::snprintf(v, sizeof v, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
            line("Address", v, White);
        }
        const char *status = "";
        tsl::Color color = Grey;
        if (g_status.nwid) switch (g_status.net_status) {
            case ZTNX_CTL_NET_REQUESTING:     status = "asking its controller"; break;
            case ZTNX_CTL_NET_OK:             status = "joined"; color = Green; break;
            case ZTNX_CTL_NET_ACCESS_DENIED:  status = "not authorized yet"; color = Yellow; break;
            case ZTNX_CTL_NET_NOT_FOUND:      status = "no such network"; color = Red; break;
            case ZTNX_CTL_NET_AUTH_REQUIRED:  status = "wants single sign-on"; color = Red; break;
            case ZTNX_CTL_NET_CLIENT_TOO_OLD: status = "needs a newer ZeroTier"; color = Red; break;
            default:                          status = "down"; break;
        }
        if (status[0]) line("Status", status, color);
        if (g_status.truncated & 0x01) {  // ZTNX_TRUNCATED_RULES
            r->drawString("It has more traffic rules than", false, x + 20, ty + 8, 15, r->a(Yellow));
            r->drawString("zerotier-nx holds, so its traffic is", false, x + 20, ty + 28, 15, r->a(Yellow));
            r->drawString("blocked. It needs fewer rules.", false, x + 20, ty + 48, 15, r->a(Yellow));
        } else if (g_status.truncated) {
            r->drawString("Some of its settings didn't fit:", false, x + 20, ty + 8, 15, r->a(Yellow));
            r->drawString("routes, addresses or tags beyond what", false, x + 20, ty + 28, 15, r->a(Yellow));
            r->drawString("zerotier-nx holds. See sysmodule.log.", false, x + 20, ty + 48, 15, r->a(Yellow));
        }
    }

    class NetworkGui : public tsl::Gui {
        public:
            tsl::elm::Element *createUI() override {
                auto *frame = new tsl::elm::OverlayFrame("ZeroTier", "Network");
                auto *list = new tsl::elm::List();
                list->addItem(new Drawer(DrawNetwork), 250);
                list->addItem(new Drawer([](tsl::gfx::Renderer *r, s32 x, s32 y, s32, s32) {
                    r->drawString("The network is set with network= in", false, x + 20, y + 25, 15, r->a(Grey));
                    r->drawString("config/zerotier-nx/config.ini.", false, x + 20, y + 47, 15, r->a(Grey));
                }), 70);
                frame->setContent(list);
                return frame;
            }

            void update() override {
                if (++m_frames % 30 != 0) return;
                Poll();
                Refresh();
            }

        private:
            u32 m_frames = 0;
    };

    class PeerTable : public tsl::elm::Element {
        public:
            void draw(tsl::gfx::Renderer *r) override {
                const s32 x = getX(), y = getY(), w = getWidth(), h = getHeight();
                if (!g_status_ok) {
                    r->drawString("Not running.", false, x + 20, y + 30, 17, r->a(Grey));
                    return;
                }
                char line[160];
                if (g_peer_count > g_peers_shown) {
                    std::snprintf(line, sizeof line, "In contact with %u; the first %u are listed.", g_peer_count, g_peers_shown);
                } else {
                    std::snprintf(line, sizeof line, "Devices in contact. Press A for details.");
                }
                r->drawString(line, false, x + 20, y + 25, 15, r->a(Grey));
                r->drawString("Green: direct. Yellow: relayed (slower).", false, x + 20, y + 47, 15, r->a(Grey));
                const u32 n = g_peers_shown;
                if (n == 0) {
                    r->drawString("Nothing in contact yet.", false, x + 20, y + 95, 17, r->a(White));
                    return;
                }
                Follow(n);
                const s32 top = y + RowsTop, visible = Visible(h);
                for (u32 row = m_top; row < n && row < m_top + static_cast<u32>(visible); row++) {
                    const ZtnxCtlPeer &p = g_peers[g_order[row]];
                    char label[48];
                    PeerLabel(p, label, sizeof label);
                    const s32 ry = top + static_cast<s32>(row - m_top) * RowHeight;
                    if (row == m_sel) {
                        r->drawRect(x + 6, ry, w - 12, RowHeight, r->a(Selected));  // a 2-pixel border
                        r->drawRect(x + 8, ry + 2, w - 16, RowHeight - 4, r->a(Black));
                    }
                    // The path at the right, the name at the left: each has
                    // what it needs, and when both are long, half the row.
                    const s32 left = x + 20, right = x + w - 20, gap = 14;
                    const s32 half = (right - left - gap) / 2, name_w = TextWidth(r, label, 17);
                    char full[48], path[48];
                    PeerState(p, full, sizeof full);
                    const s32 full_w = TextWidth(r, full, 17);
                    const s32 path_w = std::min(full_w, std::max(half, right - left - gap - name_w));
                    Fit(r, full, 17, path_w, path, sizeof path);
                    const s32 room = right - path_w - gap - left;
                    const bool long_name = name_w > room, long_path = full_w > path_w;
                    if (row == m_sel) Turns(long_name, long_path);
                    if (row == m_sel && long_path && m_turn == PathTurn) {
                        Marquee(r, full, right - path_w, ry, path_w, StateColor(p));
                    } else {
                        r->drawString(path, false, right - TextWidth(r, path, 17), ry + 22, 17, r->a(StateColor(p)));
                    }
                    if (row == m_sel && long_name && m_turn == NameTurn) {
                        Marquee(r, label, left, ry, room, White);
                    } else {
                        char name[sizeof label + 4];
                        Fit(r, label, 17, room, name, sizeof name);
                        if (name[0] && std::strcmp(name, "...") != 0) r->drawString(name, false, x + 20, ry + 22, 17, r->a(White));  // see DrawMessage
                    }
                }
                // Where the rows on screen are in the whole list.
                if (n > static_cast<u32>(visible)) {
                    const s32 track = visible * RowHeight;
                    const s32 bar = std::max<s32>(track * visible / static_cast<s32>(n), 20);
                    const s32 at = (track - bar) * static_cast<s32>(m_top) / static_cast<s32>(n - visible);
                    r->drawRect(x + w + 10, top + at, 5, bar, r->a(tsl::style::color::ColorHandle));
                }
            }

            void layout(u16, u16, u16, u16) override {}

            tsl::elm::Element *requestFocus(tsl::elm::Element *, tsl::FocusDirection) override { return this; }

            // Not Tesla's focus look (a black box and a border round the
            // whole element): the selected row shows instead.
            void drawFocusBackground(tsl::gfx::Renderer *) override {}
            void drawHighlight(tsl::gfx::Renderer *) override {}

            // Up and down move the selection (repeating while held, as in
            // Tesla's lists); B goes back.
            bool handleInput(u64 down_keys, u64 held, const HidTouchState &, HidAnalogStickState, HidAnalogStickState) override {
                if ((down_keys & HidNpadButton_A) && g_peers_shown > 0) {
                    g_detail_address = g_peers[g_order[m_sel]].address;
                    PeerLabel(g_peers[g_order[m_sel]], g_detail_label, sizeof g_detail_label);
                    tsl::changeTo<PeerGui>();
                    return true;
                }
                const bool up = held & HidNpadButton_AnyUp, down = held & HidNpadButton_AnyDown;
                if (up == down) {
                    m_repeat = 0;
                    return false;
                }
                if (m_repeat == 0 || (m_repeat > 20 && m_repeat % 4 == 0)) Select(static_cast<s32>(m_sel) + (up ? -1 : 1));
                m_repeat++;
                return true;
            }

        private:
            static constexpr s32 RowsTop = 66, RowHeight = 30;
            static constexpr tsl::Color Selected{0x0, 0xC, 0xF, 0xF};

            static s32 Visible(s32 h) { return std::max<s32>((h - RowsTop) / RowHeight, 1); }

            void Select(s32 row) {
                const s32 n = static_cast<s32>(g_peers_shown);
                if (n == 0) return;
                m_sel = static_cast<u32>(std::clamp(row, 0, n - 1));
                m_sel_address = g_peers[g_order[m_sel]].address;
                m_scroll = 0;
                m_wait = 0;
                m_turn = NameTurn;
            }

            // Keeps the selection on the same device as others come and go, and
            // in view.
            void Follow(u32 n) {
                u32 found = n;
                for (u32 i = 0; i < n && m_sel_address; i++) {
                    if (g_peers[g_order[i]].address == m_sel_address) found = i;
                }
                if (found < n) m_sel = found;
                else Select(static_cast<s32>(std::min(m_sel, n - 1)));
                const u32 visible = static_cast<u32>(Visible(getHeight()));
                if (m_sel < m_top) m_top = m_sel;
                if (m_sel >= m_top + visible) m_top = m_sel - visible + 1;
                m_top = std::min(m_top, n > visible ? n - visible : 0);
            }

            // The selected row's name and path take turns to scroll when
            // both are too long, so only one moves at a time.
            void Turns(bool long_name, bool long_path) {
                const u32 turn = !long_name && long_path ? PathTurn : !long_path && long_name ? NameTurn : m_turn;
                if (turn == m_turn) return;
                m_turn = turn;
                m_scroll = m_wait = 0;
            }

            // Text too long for its place, scrolling by (like Tesla's list
            // items): still for a second and a half, then a pixel a frame;
            // then it's the other's turn.
            void Marquee(tsl::gfx::Renderer *r, const char *text, s32 x, s32 ry, s32 w, tsl::Color c) {
                const s32 loop = TextWidth(r, text, 17) + 40;
                if (m_wait < 90) {
                    m_wait++;
                } else if (++m_scroll >= loop) {
                    m_scroll = m_wait = 0;
                    m_turn = m_turn == NameTurn ? PathTurn : NameTurn;
                }
                r->enableScissoring(x, ry, w, RowHeight);
                r->drawString(text, false, x - m_scroll, ry + 22, 17, r->a(c));
                r->drawString(text, false, x - m_scroll + loop, ry + 22, 17, r->a(c));
                r->disableScissoring();
            }

            static constexpr u32 NameTurn = 0, PathTurn = 1;

            u32 m_sel = 0, m_top = 0;
            u64 m_sel_address = 0;
            s32 m_scroll = 0, m_wait = 0;
            u32 m_turn = NameTurn;
            u32 m_repeat = 0;
    };

    class PeersGui : public tsl::Gui {
        public:
            tsl::elm::Element *createUI() override {
                auto *frame = new tsl::elm::OverlayFrame("ZeroTier", "Devices");
                frame->setContent(new PeerTable());
                return frame;
            }

            void update() override {
                if (++m_frames % 30 != 0) return;
                Poll();
                Refresh();
            }

        private:
            u32 m_frames = 0;
    };

    class MainGui : public tsl::Gui {
        public:
            tsl::elm::Element *createUI() override {
                Refresh();
                auto *frame = new tsl::elm::OverlayFrame("ZeroTier", "zerotier-nx " APP_VERSION);
                auto *list = new tsl::elm::List();
                list->addItem(new Drawer(DrawStatus), 135);
                if (!g_status_ok) ReadWhyNotRunning();

                m_toggle = new tsl::elm::ToggleListItem("ZeroTier", !(g_status_ok && g_status.state == ZTNX_CTL_PAUSED));
                m_toggle->setStateChangedListener([](bool on) {
                    CtlSetPaused(!on);
                    Refresh();
                });
                list->addItem(m_toggle);

                // Every device in contact, and how it's reached.
                m_peers = new tsl::elm::ListItem("Devices", PeersValue());
                m_peers->setClickListener([](u64 keys) {
                    if (!(keys & HidNpadButton_A)) return false;
                    tsl::changeTo<PeersGui>();
                    return true;
                });
                list->addItem(m_peers);

                // The network joined; A shows its details and this Switch's ID.
                m_net = new tsl::elm::ListItem("Network", NetValue());
                m_net->setClickListener([](u64 keys) {
                    if (!(keys & HidNpadButton_A)) return false;
                    tsl::changeTo<NetworkGui>();
                    return true;
                });
                list->addItem(m_net);

                // Stop or start the sysmodule itself (not its boot setting).
                m_power = new tsl::elm::ListItem(PowerLabel());
                m_power->setClickListener([](u64 keys) {
                    if (!(keys & HidNpadButton_A)) return false;
                    switch (PowerAction()) {
                        case Action::Stop:       BeginStop(); break;
                        case Action::Start:      StartSysmodule(); break;
                        case Action::TurnBackOn: TurnBackOn(); break;
                        case Action::None:       break;
                    }
                    return true;
                });
                list->addItem(m_power);
                list->addItem(new Drawer(DrawMessage), 50);

                // The sysmodule's "Connected. IP: ..." toast at boot; off is
                // a marker file it checks when it connects.
                auto *notice = new tsl::elm::ToggleListItem("Connection notice", !MarkerExists(NoNoticePath));
                notice->setStateChangedListener([](bool on) { SetMarker(NoNoticePath, !on); });
                list->addItem(notice);

                // The sysmodule's check for a newer release on GitHub, once
                // per boot soon after connecting (a toast if there is one).
                auto *updates = new tsl::elm::ToggleListItem("Check for updates", !MarkerExists(NoUpdateCheckPath));
                updates->setStateChangedListener([](bool on) { SetMarker(NoUpdateCheckPath, !on); });
                list->addItem(updates);

                list->addItem(new Drawer(DrawInfo), 140);
                list->addItem(new Drawer(DrawTip), 85);
                frame->setContent(list);
                return frame;
            }

            void update() override {
                // Poll about twice a second.
                if (++m_frames % 30 != 0) return;
                Poll();
                Refresh();
                const bool on = !(g_status_ok && g_status.state == ZTNX_CTL_PAUSED);
                if (m_toggle && !ctl::g_pause_pending && m_toggle->getState() != on) m_toggle->setState(on);
                if (m_peers) {
                    const std::string value = PeersValue();
                    if (value != m_peers_value) {
                        m_peers->setValue(value);
                        m_peers_value = value;
                    }
                }
                if (m_net) {
                    const std::string value = NetValue();
                    if (value != m_net_value) {
                        m_net->setValue(value);
                        m_net_value = value;
                    }
                }
                if (m_power) {
                    const char *label = PowerLabel();
                    if (label != m_power_label) {
                        m_power->setText(label);
                        m_power_label = label;
                    }
                }
            }

        private:
            enum class Action { None, Stop, Start, TurnBackOn };

            static std::string PeersValue() {
                if (!g_status_ok || g_status.state == ZTNX_CTL_STARTING) return "";
                if (g_status.peers == 0) return "None";
                return std::to_string(g_status.peers_up) + " of " + std::to_string(g_status.peers) + " direct";
            }

            // The network's name once its controller has said it, else its ID.
            static std::string NetValue() {
                if (!g_status_ok || !g_status.nwid) return "";
                if (g_net_name[0]) return g_net_name;
                char id[20];
                std::snprintf(id, sizeof id, "%016llx", static_cast<unsigned long long>(g_status.nwid));
                return id;
            }

            static Action PowerAction() {
                if (g_phase != Phase::Idle) return Action::None;
                if (g_have_ctl && g_status_ok) return g_status.state == ZTNX_CTL_STOPPING ? Action::None : Action::Stop;
                if (SysmoduleRunning()) return Action::None;
                return g_crashed[0] ? Action::TurnBackOn : Action::Start;
            }

            static const char *PowerLabel() {
                switch (g_phase) {
                    case Phase::Stopping:
                    case Phase::Exiting:  return "Stopping...";
                    case Phase::Starting: return "Starting...";
                    case Phase::Idle:     break;
                }
                if (g_have_ctl && g_status_ok) return g_status.state == ZTNX_CTL_STOPPING ? "Restart the console to finish" : "Stop zerotier-nx";
                return g_crashed[0] ? "Turn back on" : "Start zerotier-nx";
            }

            tsl::elm::ToggleListItem *m_toggle = nullptr;
            tsl::elm::ListItem *m_peers = nullptr;
            std::string m_peers_value;
            tsl::elm::ListItem *m_net = nullptr;
            std::string m_net_value;
            tsl::elm::ListItem *m_power = nullptr;
            const char *m_power_label = nullptr;
            u32 m_frames = 0;
    };

    // Ultrahand shows notifications ("Connected", updates) only while its
    // own menu is the loaded overlay, and a hidden Tesla overlay stays loaded.
    // With Ultrahand installed, hiding exits instead, back to a hidden menu.
    bool g_exit_on_hide = false;

    class ZeroTierOverlay : public tsl::Overlay {
        public:
            void initServices() override {
                ctl::Start();
                tsl::hlp::doWithSDCardHandle([] {
                    if (DIR *d = opendir("sdmc:/config/ultrahand/notifications")) {
                        g_exit_on_hide = true;
                        closedir(d);
                    }
                });
            }

            // From the combo, HOME or a touch outside us (Tesla's input thread).
            void onHide() override {
                if (!g_exit_on_hide) return;
                // Without --skipCombo the menu starts hidden, as at boot.
                envSetNextLoad("sdmc:/switch/.overlays/ovlmenu.ovl", "ovlmenu.ovl");
                close();
            }

            void exitServices() override {
                ctl::Finish();
            }

            std::unique_ptr<tsl::Gui> loadInitialGui() override {
                return initially<MainGui>();
            }
    };

}

int main(int argc, char **argv) {
    return tsl::loop<ZeroTierOverlay>(argc, argv);
}
