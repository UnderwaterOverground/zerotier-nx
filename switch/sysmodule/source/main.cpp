// zerotier-nx sysmodule: runs the WireGuard engine from boot (boot2), so the
// console is on its tunnel without any app open.
//
// It also MITMs bsd:u for homebrew (bsd_mitm.cpp), so their sockets reach
// tunnel addresses through the engine (mitm=off in config.ini disables that).
//
// Files (SD card):
//   config/zerotier-nx/<name>.conf  wg-quick style tunnel configuration(s)
//   config/zerotier-nx/config.ini   conf=<name>.conf (default: the only one,
//                                    else wg0.conf), log_udp=<ip>:<port>,
//                                    mitm=homebrew|homebrew,sys-ftpd|off,
//                                    mitm_titles=<program IDs>, hosts=on|off,
//                                    aliases=on|off (stand-in peer addresses),
//                                    overlay_budget_kb=<128..384>,
//                                    connect_notice=on|off, update_check=on|off,
//                                    tunnel_lan=on (tests: LAN through the tunnel)
//   config/zerotier-nx/disabled     kill switch: if present, exit at boot
//   config/zerotier-nx/no-update-check  the overlay's update check switch (off)
//   config/zerotier-nx/crashed      written after 3 boots in a row that ended
//                                    within 3 minutes, or 2 sleeps that never woke;
//                                    keeps it off (delete to retry)
//   config/zerotier-nx/start_requested  written by the overlay just before it
//                                    starts us (its system tick): not a boot start
//   config/zerotier-nx/sysmodule.log (+ .1 from the previous boot)
#include <stratosphere.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <strings.h>

extern "C" {
#include <switch/services/bsd.h>
#include "ztnx.h"
#include "ztnx_app.h"
#include "ztnx_dns.h"
#include "ztnx_driver.h"
#include "ztnx_engine.h"
#include "ztnx_update.h"
}

#include <memory>
#include <string>

#include "bsd_mitm.hpp"
#include "ctl.hpp"
#include "hosts.hpp"
#include "log.hpp"
#include "runtime.hpp"
#include "vsock.hpp"
#include "stack_watch.hpp"
#include "heap_size.h"
#include "memory.hpp"
#include "status.hpp"

namespace ams {

    namespace {

        constexpr const char ConfigDir[] = "sdmc:/config/zerotier-nx";
        constexpr const char ConfigPath[] = "sdmc:/config/zerotier-nx/config.ini";
        // A .conf is a few hundred bytes; 32 peers with names fit easily.
        constexpr size_t ConfMaxSize = 8_KB;
        constexpr const char DefaultConf[] = "wg0.conf";
        constexpr const char DisabledPath[] = "sdmc:/config/zerotier-nx/disabled";
        // Why we didn't start this time (too little system memory), for the
        // overlay; removed once we do start.
        constexpr const char NotStartedPath[] = "sdmc:/config/zerotier-nx/not_started";
        // System memory left for everything launched after us: Nintendo
        // starts some modules on demand, and they fail without it.
        constexpr u64 MinSystemFree = 1_MB;
        // How long after our start to watch the system's free memory (boot
        // and the HOME menu starting), for the log and a low-memory warning.
        constexpr u64 BootLowWindowNs = 120'000'000'000ull;
        constexpr const char CrashedPath[] = "sdmc:/config/zerotier-nx/crashed";
        constexpr const char StartingPath[] = "sdmc:/config/zerotier-nx/starting";
        constexpr const char SleepingPath[] = "sdmc:/config/zerotier-nx/sleeping";
        constexpr const char SleepFailuresPath[] = "sdmc:/config/zerotier-nx/sleep_failures";
        constexpr const char StartRequestedPath[] = "sdmc:/config/zerotier-nx/start_requested";
        // How old the overlay's start request may be (pm launches at once).
        constexpr u64 StartRequestFreshNs = 30'000'000'000ull;
        // A boot that doesn't last HealthyAfterNs counts against us (the
        // console itself can go down: a failed sleep made omm abort and
        // reboot it every ~2.5 minutes). Only boot-time starts count; a
        // sysmodule that dies isn't restarted, so loops span reboots.
        constexpr int MaxUnhealthyStarts = 3;
        constexpr u64 HealthyAfterNs = 180'000'000'000ull;
        constexpr u64 BootStartWithinNs = 120'000'000'000ull;
        constexpr int MaxSleepFailures = 2;
        constexpr const char LogPath[] = "sdmc:/config/zerotier-nx/sysmodule.log";
        constexpr const char OldLogPath[] = "sdmc:/config/zerotier-nx/sysmodule.log.1";
        constexpr s64 LogMaxSize = 512_KB;

        // Heap for ZeroTier's core, the Rust stack, the driver and our own
        // allocations, sized at build time so the whole sysmodule takes
        // exactly 4 MB (heap_size.h).
        constexpr size_t MallocBufferSize = ZTNX_HEAP_SIZE;
        static_assert(MallocBufferSize % os::MemoryPageSize == 0);
        alignas(os::MemoryPageSize) constinit u8 g_malloc_buffer[MallocBufferSize];

        // The engine's own sockets: the update check (TCP); WireGuard, DNS,
        // the runtime's wake pair and the log (UDP). The
        // transfer memory is the buffer pool for all of them: each socket's
        // buffers are taken from it, and one that doesn't fit fails with
        // ENOBUFS. UDP sockets start with a small receive buffer, as only
        // WireGuard's needs to be big, and it grows its own
        // (ztnx_driver.c): at 48 KB each, the small sockets took so much
        // that once WireGuard had grown, a new DNS socket didn't fit. The
        // pool keeps the size it had with 48 KB (sb_efficiency sockets'
        // worth), so WireGuard gets what the small sockets no longer take.
        constexpr u32 UdpRxPoolShare = 0xC000;
        consteval size_t BsdTransferMemorySize(const ::SocketInitConfig &c) {
            const u32 sum = c.tcp_tx_buf_max_size + c.tcp_rx_buf_max_size + c.udp_tx_buf_size + UdpRxPoolShare;
            return static_cast<size_t>(c.sb_efficiency) * util::AlignUp(sum, os::MemoryPageSize);
        }

        constexpr const ::SocketInitConfig SocketConfig = {
            .tcp_tx_buf_size = 0x4000,
            .tcp_rx_buf_size = 0x4000,
            .tcp_tx_buf_max_size = 0x8000,
            .tcp_rx_buf_max_size = 0x8000,
            .udp_tx_buf_size = 0x2000,
            .udp_rx_buf_size = 0x2000,
            .sb_efficiency = 3,
            // Each counts against the socket service's session limit, which
            // every process shares: two cover the engine's long poll plus
            // log writes from other threads.
            .num_bsd_sessions = 2,
            .bsd_service_type = BsdServiceType_System,
        };

        alignas(os::MemoryPageSize) constinit u8 g_bsd_tmem[BsdTransferMemorySize(SocketConfig)];

        constexpr const ::BsdInitConfig BsdConfig = {
            .version = 1,
            .tmem_buffer = g_bsd_tmem,
            .tmem_buffer_size = sizeof(g_bsd_tmem),
            .tcp_tx_buf_size = SocketConfig.tcp_tx_buf_size,
            .tcp_rx_buf_size = SocketConfig.tcp_rx_buf_size,
            .tcp_tx_buf_max_size = SocketConfig.tcp_tx_buf_max_size,
            .tcp_rx_buf_max_size = SocketConfig.tcp_rx_buf_max_size,
            .udp_tx_buf_size = SocketConfig.udp_tx_buf_size,
            .udp_rx_buf_size = SocketConfig.udp_rx_buf_size,
            .sb_efficiency = SocketConfig.sb_efficiency,
        };

        // ---- files -------------------------------------------------------

        bool FileExists(const char *path) {
            fs::DirectoryEntryType type;
            return R_SUCCEEDED(fs::GetEntryType(std::addressof(type), path)) && type == fs::DirectoryEntryType_File;
        }

        // Reads a whole (small) file into buf, NUL-terminated. Returns length or -1.
        s64 ReadWholeFile(const char *path, char *buf, size_t cap) {
            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Read))) return -1;
            ON_SCOPE_EXIT { fs::CloseFile(f); };
            s64 size = 0;
            if (R_FAILED(fs::GetFileSize(std::addressof(size), f)) || size < 0 || static_cast<size_t>(size) >= cap) return -1;
            size_t got = 0;
            if (R_FAILED(fs::ReadFile(std::addressof(got), f, 0, buf, static_cast<size_t>(size)))) return -1;
            buf[got] = 0;
            return static_cast<s64>(got);
        }

        bool WriteWholeFile(const char *path, const void *data, size_t len) {
            static_cast<void>(fs::DeleteFile(path));
            if (R_FAILED(fs::CreateFile(path, static_cast<s64>(len)))) return false;
            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Write))) return false;
            ON_SCOPE_EXIT { fs::CloseFile(f); };
            return R_SUCCEEDED(fs::WriteFile(f, 0, data, len, fs::WriteOption::Flush));
        }

        // ---- logging -----------------------------------------------------

        constinit os::SdkMutex g_log_mutex;
        constinit fs::FileHandle g_log_file;
        constinit bool g_log_open = false;
        constinit s64 g_log_offset = 0;
        constinit int g_log_udp_fd = -1;
        // While the console sleeps, logging must not touch the socket service
        // (it may be asleep and block the caller): file only.
        constinit std::atomic<bool> g_log_udp_paused = false;
        // log_udp pointing at a tunnel address: lines queue here and the
        // engine loop sends them through the tunnel (works away from the LAN).
        constinit bool g_log_tunnel = false;
        constinit char g_tunnel_log[4_KB] = {};
        constinit size_t g_tunnel_log_len = 0;
        // After a wake the tunnel needs a moment to re-handshake; lines sent
        // before then are lost, so hold them until this tick.
        constinit u64 g_tunnel_log_hold_until_ns = 0;
        // The engine loop's last round, to log stalls (0: not since resuming;
        // it doesn't run while suspended).
        constinit u64 g_last_round_ns = 0;

        // Runs a housekeeping step of the engine loop, logging it if it held
        // the loop up (homebrew's tunnel sockets wait meanwhile).
        template <class F>
        void Timed(const char *what, F &&f) {
            const u64 t0 = armTicksToNs(armGetSystemTick());
            status::EngineStep(what);
            f();
            status::EngineStep(nullptr);
            const u64 ms = (armTicksToNs(armGetSystemTick()) - t0) / 1'000'000;
            if (ms >= 500) Log("slow: %s took %llu ms", what, static_cast<unsigned long long>(ms));
        }

        // Appends a line, dropping the oldest whole lines to make room.
        void QueueTunnelLog(const char *line, size_t n) {
            if (n > sizeof g_tunnel_log) return;
            while (g_tunnel_log_len + n > sizeof g_tunnel_log) {
                const char *nl = static_cast<const char *>(std::memchr(g_tunnel_log, '\n', g_tunnel_log_len));
                const size_t drop = nl ? static_cast<size_t>(nl - g_tunnel_log) + 1 : g_tunnel_log_len;
                std::memmove(g_tunnel_log, g_tunnel_log + drop, g_tunnel_log_len - drop);
                g_tunnel_log_len -= drop;
            }
            std::memcpy(g_tunnel_log + g_tunnel_log_len, line, n);
            g_tunnel_log_len += n;
        }
        constinit sockaddr_in g_log_udp_addr = {};
        // Lines logged before the UDP log socket exists, replayed once it does.
        // Once the engine loop runs, the buffer holds its thread's lines
        // instead (g_log_defer_thread).
        constinit char g_early_log[4_KB] = {};
        constinit size_t g_early_log_len = 0;
        constinit bool g_early_log_done = false;
        // The engine thread, while the engine loop runs: its lines wait in
        // g_early_log until the loop has released the runtime lock (an SD
        // write takes 5-9 ms, and homebrew's tunnel sockets wait on that
        // lock). Other threads write theirs directly, after any waiting.
        constinit os::ThreadType *g_log_defer_thread = nullptr;

        // Sends lines to the log socket, a datagram each (g_log_mutex held).
        void SendLogLines(const char *lines, size_t n) {
            for (size_t off = 0; off < n;) {
                const char *nl = static_cast<const char *>(std::memchr(lines + off, '\n', n - off));
                const size_t len = nl ? static_cast<size_t>(nl - (lines + off)) + 1 : n - off;
                ::sendto(g_log_udp_fd, lines + off, len, 0, reinterpret_cast<sockaddr *>(std::addressof(g_log_udp_addr)), sizeof g_log_udp_addr);
                off += len;
            }
        }

        // Writes lines to the log file and the log socket or tunnel queue
        // (g_log_mutex held).
        void EmitLog(const char *lines, size_t n) {
            if (g_log_open && g_log_offset + static_cast<s64>(n) <= LogMaxSize) {
                // Logging must never take the sysmodule down: ignore failures.
                if (R_SUCCEEDED(fs::WriteFile(g_log_file, g_log_offset, lines, n, fs::WriteOption::Flush))) g_log_offset += n;
            }
            if (g_log_tunnel) {
                QueueTunnelLog(lines, n);
            } else if (g_log_udp_fd >= 0 && g_early_log_done && !g_log_udp_paused) {
                SendLogLines(lines, n);
            } else if (!g_early_log_done && g_early_log_len + n <= sizeof g_early_log) {
                std::memcpy(g_early_log + g_early_log_len, lines, n);
                g_early_log_len += n;
            }
        }

        // Writes the engine thread's waiting lines (g_log_mutex held).
        void EmitDeferredLog() {
            if (!g_early_log_done || g_early_log_len == 0) return;
            const size_t n = g_early_log_len;
            g_early_log_len = 0;
            EmitLog(g_early_log, n);
        }

    }  // namespace

    void Log(const char *fmt, ...) {
            char line[600];
            const u64 ms = armTicksToNs(armGetSystemTick()) / 1'000'000;
            int n = util::SNPrintf(line, sizeof line, "[%5llu.%03llu] ", static_cast<unsigned long long>(ms / 1000),
                                  static_cast<unsigned long long>(ms % 1000));
            va_list ap;
            va_start(ap, fmt);
            n += util::VSNPrintf(line + n, sizeof line - n - 1, fmt, ap);
            va_end(ap);
            if (n > static_cast<int>(sizeof line) - 2) n = sizeof line - 2;
            line[n++] = '\n';
            line[n] = 0;

            std::scoped_lock lk(g_log_mutex);
            // The engine thread's lines wait for the loop to write them, except
            // while asleep (the loop doesn't run then).
            if (g_log_defer_thread == os::GetCurrentThread() && !g_log_udp_paused && g_early_log_len + n <= sizeof g_early_log) {
                std::memcpy(g_early_log + g_early_log_len, line, n);
                g_early_log_len += n;
                return;
            }
            EmitDeferredLog();
            EmitLog(line, n);
    }

    namespace {

        void OpenLog() {
            static_cast<void>(fs::DeleteFile(OldLogPath));
            static_cast<void>(fs::RenameFile(LogPath, OldLogPath));
            if (R_FAILED(fs::CreateFile(LogPath, 0))) return;
            g_log_open = R_SUCCEEDED(fs::OpenFile(std::addressof(g_log_file), LogPath, fs::OpenMode_Write | fs::OpenMode_AllowAppend));
        }

        // ---- config ------------------------------------------------------

        struct Config {
            char conf[ZTNX_CTL_CONF_NAME_MAX] = {};  // the .conf to use (file name in ConfigDir)
            char log_udp[64] = {};
            char mitm[32] = "homebrew";  // "homebrew,sys-ftpd" or "off"
            char mitm_titles[384] = {};  // forwarders' program IDs, served like homebrew
            char hosts[8] = "on";        // peer names in Atmosphere's hosts file, or "off"
            char aliases[8] = "on";      // private peer addresses named as 100.127.x.y stand-ins, or "off"
            char overlay_budget_kb[8] = {};  // tunnel socket buffers; default 320
            char connect_notice[8] = "on";   // toast with our address when first connected
            char update_check[8] = "on";     // ask GitHub for a newer release at boot
            char tunnel_lan[8] = {};         // "on": LAN addresses go through the tunnel too (tests)
        };

        void LoadConfig(Config &c) {
            static char buf[2_KB];  // config.ini is a few hundred bytes
            if (ReadWholeFile(ConfigPath, buf, sizeof buf) < 0) return;
            char *save = nullptr;
            for (char *line = strtok_r(buf, "\r\n", &save); line; line = strtok_r(nullptr, "\r\n", &save)) {
                if (line[0] == '#') continue;
                char *eq = std::strchr(line, '=');
                if (!eq) continue;
                *eq = 0;
                const char *v = eq + 1;
                auto set = [&](const char *key, char *dst, size_t cap) {
                    if (!std::strcmp(line, key)) util::SNPrintf(dst, cap, "%s", v);
                };
                set("conf", c.conf, sizeof c.conf);
                set("log_udp", c.log_udp, sizeof c.log_udp);
                set("mitm", c.mitm, sizeof c.mitm);
                set("mitm_titles", c.mitm_titles, sizeof c.mitm_titles);
                set("hosts", c.hosts, sizeof c.hosts);
                set("aliases", c.aliases, sizeof c.aliases);
                set("overlay_budget_kb", c.overlay_budget_kb, sizeof c.overlay_budget_kb);
                set("connect_notice", c.connect_notice, sizeof c.connect_notice);
                set("update_check", c.update_check, sizeof c.update_check);
                set("tunnel_lan", c.tunnel_lan, sizeof c.tunnel_lan);
            }
        }

        // Rewrites (or adds) `key=value` in config.ini, keeping the rest.
        void SetConfigValue(const char *key, const char *value) {
            static char buf[2_KB], out[2_KB];
            const s64 n = ReadWholeFile(ConfigPath, buf, sizeof buf);
            if (n < 0) buf[0] = 0;
            size_t o = 0;
            bool done = false;
            const size_t klen = std::strlen(key);
            for (const char *line = buf; *line;) {
                const char *eol = std::strchr(line, '\n');
                const size_t len = eol ? static_cast<size_t>(eol - line) + 1 : std::strlen(line);
                if (std::strncmp(line, key, klen) == 0 && line[klen] == '=') {
                    if (!done) o += util::SNPrintf(out + o, sizeof out - o, "%s=%s\n", key, value);
                    done = true;
                } else if (o + len < sizeof out) {
                    std::memcpy(out + o, line, len);
                    o += len;
                }
                line += len;
            }
            if (o && out[o - 1] != '\n' && o < sizeof out - 1) out[o++] = '\n';
            if (!done) o += util::SNPrintf(out + o, sizeof out - o, "%s=%s\n", key, value);
            if (!WriteWholeFile(ConfigPath, out, o)) Log("cannot write %s", ConfigPath);
        }

        // A .conf file name: just a name (no directories), ending in .conf.
        bool ValidConfName(const char *name) {
            const size_t n = std::strlen(name);
            if (n < 6 || n >= ZTNX_CTL_CONF_NAME_MAX || std::strchr(name, '/') || std::strchr(name, '\\') || std::strstr(name, "..")) return false;
            return std::strcmp(name + n - 5, ".conf") == 0;
        }

        // A config saved as wg0.conf.txt (Windows hides extensions) becomes
        // wg0.conf, unless that exists already.
        void RenameTxtConfs() {
            constexpr int Max = 4;
            char names[Max][ZTNX_CTL_CONF_NAME_MAX + 4] = {};
            int found = 0;
            fs::DirectoryHandle dir;
            if (R_FAILED(fs::OpenDirectory(std::addressof(dir), ConfigDir, fs::OpenDirectoryMode_File))) return;
            {
                ON_SCOPE_EXIT { fs::CloseDirectory(dir); };
                static fs::DirectoryEntry entry;
                s64 got = 0;
                while (found < Max && R_SUCCEEDED(fs::ReadDirectory(std::addressof(got), std::addressof(entry), dir, 1)) && got == 1) {
                    const size_t n = std::strlen(entry.name);
                    if (n > 9 && n < sizeof names[0] && strcasecmp(entry.name + n - 9, ".conf.txt") == 0)
                        util::SNPrintf(names[found++], sizeof names[0], "%s", entry.name);
                }
            }
            for (int i = 0; i < found; i++) {
                char from[96], to[96];
                util::SNPrintf(from, sizeof from, "%s/%s", ConfigDir, names[i]);
                const size_t n = std::strlen(names[i]);
                util::SNPrintf(to, sizeof to, "%s/%.*s.conf", ConfigDir, static_cast<int>(n - 9), names[i]);
                if (!ValidConfName(std::strrchr(to, '/') + 1)) continue;
                if (R_SUCCEEDED(fs::RenameFile(from, to))) Log("config: renamed %s to %s", names[i], std::strrchr(to, '/') + 1);
                else Log("config: cannot rename %s (is there a .conf with that name already?)", names[i]);
            }
        }

        // Which .conf to use: config.ini's, else the only one there is, else
        // wg0.conf.
        void SelectConf(const Config &cfg, char *out, size_t cap) {
            if (cfg.conf[0]) {
                util::SNPrintf(out, cap, "%s%s", cfg.conf, std::strstr(cfg.conf, ".conf") ? "" : ".conf");
                return;
            }
            util::SNPrintf(out, cap, "%s", DefaultConf);
            fs::DirectoryHandle dir;
            if (R_FAILED(fs::OpenDirectory(std::addressof(dir), ConfigDir, fs::OpenDirectoryMode_File))) return;
            ON_SCOPE_EXIT { fs::CloseDirectory(dir); };
            static fs::DirectoryEntry entry;  // ~0x310 bytes: not on the stack
            char only[ZTNX_CTL_CONF_NAME_MAX] = {};
            int found = 0;
            s64 got = 0;
            while (R_SUCCEEDED(fs::ReadDirectory(std::addressof(got), std::addressof(entry), dir, 1)) && got == 1) {
                if (!ValidConfName(entry.name)) continue;
                if (++found == 1) util::SNPrintf(only, sizeof only, "%s", entry.name);
            }
            if (found == 1) util::SNPrintf(out, cap, "%s", only);
        }

        // What to do when `name` isn't in the config folder, from what is:
        // nothing, a .conf saved as .conf.txt (Windows hides extensions), or
        // other .conf files to pick from.
        void DescribeMissingConf(const char *name, char *out, size_t cap) {
            int confs = 0;
            char txt[ZTNX_CTL_CONF_NAME_MAX + 4] = {};
            fs::DirectoryHandle dir;
            if (R_SUCCEEDED(fs::OpenDirectory(std::addressof(dir), ConfigDir, fs::OpenDirectoryMode_File))) {
                ON_SCOPE_EXIT { fs::CloseDirectory(dir); };
                static fs::DirectoryEntry entry;
                s64 got = 0;
                while (R_SUCCEEDED(fs::ReadDirectory(std::addressof(got), std::addressof(entry), dir, 1)) && got == 1) {
                    const size_t n = std::strlen(entry.name);
                    if (ValidConfName(entry.name)) confs++;
                    else if (!txt[0] && n > 9 && n < sizeof txt && strcasecmp(entry.name + n - 9, ".conf.txt") == 0)
                        util::SNPrintf(txt, sizeof txt, "%s", entry.name);
                }
            }
            if (confs > 0) {
                util::SNPrintf(out, cap, "%s isn't in config/zerotier-nx. Pick one of the .conf files there under Config.", name);
            } else if (txt[0]) {
                util::SNPrintf(out, cap, "Rename %s to %.*s, then restart the Switch.", txt, static_cast<int>(std::strlen(txt) - 4), txt);
            } else {
                util::SNPrintf(out, cap, "No .conf in config/zerotier-nx. Copy your WireGuard config there and restart.");
            }
        }

        // ---- network -----------------------------------------------------

        bool NetworkUp() {
            NifmInternetConnectionStatus status;
            return R_SUCCEEDED(nifmGetInternetConnectionStatus(nullptr, nullptr, &status)) &&
                   status == NifmInternetConnectionStatus_Connected;
        }

        // DNS through the servers nifm reports (the system resolver can't be
        // used from a sysmodule), falling back to public resolvers. It blocks
        // the engine loop, so: nothing at all while offline (every reconnect
        // attempt would wait out each server), and about 3 s at most.
        int ResolveViaDns(const char *host, u32 *out) {
            struct Done {
                ~Done() { status::EngineStep(nullptr); }
            } done;
            status::EngineStep("DNS lookup (network status)");
            if (!NetworkUp()) {
                errno = ENETUNREACH;
                return -1;
            }
            u32 ip = 0, mask = 0, gw = 0, dns1 = 0, dns2 = 0;
            u32 servers[4] = {};
            int n = 0;
            status::EngineStep("DNS lookup (network settings)");
            const bool have_config = R_SUCCEEDED(nifmGetCurrentIpConfigInfo(&ip, &mask, &gw, &dns1, &dns2));
            status::EngineStep("DNS lookup");
            if (have_config) {
                if (dns1) servers[n++] = dns1;
                if (dns2) servers[n++] = dns2;
            }
            servers[n++] = inet_addr("1.1.1.1");
            servers[n++] = inet_addr("8.8.8.8");
            const u64 deadline = armTicksToNs(armGetSystemTick()) + 3'000'000'000ull;
            for (int i = 0; i < n; i++) {
                const u64 now = armTicksToNs(armGetSystemTick());
                if (now >= deadline) break;
                const int timeout_ms = static_cast<int>(std::min<u64>(1500, (deadline - now) / 1'000'000));
                if (ztnx_dns_query_a(servers[i], host, out, timeout_ms) == 0) return 0;
                Log("dns: %s via %s failed: errno %d", host, inet_ntoa(in_addr{servers[i]}), errno);
            }
            return -1;
        }

        u32 CurrentIp() {
            u32 ip = 0;
            return R_SUCCEEDED(nifmGetCurrentIpAddress(&ip)) ? ip : 0;
        }

        // Tells the MITM our LAN (its addresses are reached directly).
        void SetLocalNet(u32 ip) {
            u32 cur = 0, mask = 0, gw = 0, dns1 = 0, dns2 = 0;
            unsigned len = 32;
            if (ip && R_SUCCEEDED(nifmGetCurrentIpConfigInfo(&cur, &mask, &gw, &dns1, &dns2)) && cur == ip) {
                len = static_cast<unsigned>(__builtin_popcount(mask));
            }
            ::ztnx::VSock::SetLocalNet(ntohl(ip), len);
        }

        // The network clock if synced, else the user clock.
        u64 ConsoleUnixTime() {
            u64 t = 0;
            if (R_SUCCEEDED(timeGetCurrentTime(TimeType_NetworkSystemClock, &t)) && t > static_cast<u64>(ZTNX_BUILD_UNIX)) return t;
            if (R_SUCCEEDED(timeGetCurrentTime(TimeType_UserSystemClock, &t))) return t;
            return 0;
        }

        // ---- update check --------------------------------------------------

        // Once per boot, soon after connecting (once the "Connected" toast
        // is gone), or a minute after starting if it doesn't connect: a newer
        // release on GitHub gets a toast. Failures are only logged. Off with
        // update_check=off or the overlay's switch.
        constexpr const char NoUpdateCheckPath[] = "sdmc:/config/zerotier-nx/no-update-check";
        constexpr u64 UpdateCheckAfterConnectNs = 10'000'000'000ull;
        constexpr u64 UpdateCheckLatestNs = 60'000'000'000ull;
        constexpr u32 UpdateCheckTimeoutMs = 30'000;

        constinit bool g_update_check = false;  // still to do this boot
        constinit u64 g_update_check_at_ns = 0;  // 0: counted from the next tick
        constinit ZtnxUpdate *g_update = nullptr;

        // Engine loop, runtime lock held. Only the start blocks (DNS lookup).
        void StepUpdateCheck(u64 now) {
            if (!g_update_check) return;
            if (!g_update) {
                if (g_update_check_at_ns == 0) g_update_check_at_ns = now + UpdateCheckLatestNs;
                if (status::IsConnected()) g_update_check_at_ns = std::min(g_update_check_at_ns, now + UpdateCheckAfterConnectNs);
                if (now < g_update_check_at_ns) return;
                if (!NetworkUp()) {
                    g_update_check_at_ns = now + 5'000'000'000ull;
                    return;
                }
                // Read now, so the overlay's switch applies to this boot too.
                if (FileExists(NoUpdateCheckPath)) {
                    g_update_check = false;
                    return;
                }
                g_update = ztnx_update_start(ZTNX_UPDATE_REPO, ztnx_version(), ztnx_driver_now_ns(), UpdateCheckTimeoutMs);
                if (!g_update) {
                    Log("update check: out of memory");
                    g_update_check = false;
                    return;
                }
            }
            const int r = ztnx_update_step(g_update, ztnx_driver_now_ns());
            if (r == ZTNX_UPDATE_PENDING) return;
            if (r == ZTNX_UPDATE_NEWER) {
                Log("update check: %s is available (this is %s)", ztnx_update_latest(g_update), ztnx_version());
                status::AnnounceUpdate(ztnx_update_latest(g_update));
            } else if (r == ZTNX_UPDATE_CURRENT) {
                Log("update check: up to date (latest release %s)", ztnx_update_latest(g_update));
            } else {
                Log("update check failed: %s", ztnx_update_error(g_update));
            }
            ztnx_update_free(g_update);
            g_update = nullptr;
            g_update_check = false;
        }

        // Sleep or pause (engine thread): the socket must close now. Checks
        // again a while after resuming.
        void SuspendUpdateCheck() {
            if (g_update) {
                ztnx_update_free(g_update);
                g_update = nullptr;
                Log("update check: interrupted; trying again after resuming");
            }
            g_update_check_at_ns = 0;
        }

        // Free system memory through boot; too little left gets a warning
        // in the log and a toast.
        void WatchBootMemory(u64 now_ns) {
            u64 low = 0;
            if (!memory::SampleBootLow(now_ns, BootLowWindowNs, &low) || low >= ZTNX_CTL_LOW_SYSTEM_FREE_KB * 1024ull) return;
            Log("WARN memory: under %u KB free: modules started later can fail (2001-0132)", ZTNX_CTL_LOW_SYSTEM_FREE_KB);
            status::AnnounceLowMemory(static_cast<u32>(low / 1024));
        }

        const char *EventName(u32 kind) {
            switch (kind) {
                case ZTNX_EVENT_ADDRESSES: return "addresses";
                case ZTNX_EVENT_PEERS: return "peers";
                case ZTNX_EVENT_ERROR: return "error";
                case ZTNX_EVENT_RESOLVE: return "resolve";
                case ZTNX_EVENT_HANDSHAKE: return "handshake";
                case ZTNX_EVENT_PEER_LOST: return "peer-lost";
                default: return "log";
            }
        }

        void SetUpUdpLog(const char *target) {
            char host[48];
            const char *colon = std::strchr(target, ':');
            const int port = colon ? std::atoi(colon + 1) : 0;
            if (!colon || port <= 0 || port > 65535 || static_cast<size_t>(colon - target) >= sizeof host) return;
            std::memcpy(host, target, colon - target);
            host[colon - target] = 0;
            g_log_udp_addr.sin_family = AF_INET;
            g_log_udp_addr.sin_port = htons(static_cast<u16>(port));
            g_log_udp_addr.sin_addr.s_addr = inet_addr(host);
        }

        // Once the tunnel's routes are known: a tunnel address gets its lines
        // through the engine, anything else a real socket.
        void StartUdpLog() {
            if (g_log_udp_addr.sin_family != AF_INET) return;
            const bool tunnel = ::ztnx::VSock::IsTunnel(reinterpret_cast<const sockaddr *>(std::addressof(g_log_udp_addr)));
            std::scoped_lock lk(g_log_mutex);
            if (tunnel == g_log_tunnel && (tunnel || g_log_udp_fd >= 0)) return;
            g_log_tunnel = tunnel;
            if (tunnel) {
                if (g_log_udp_fd >= 0) ::close(g_log_udp_fd);
                g_log_udp_fd = -1;
                if (!g_early_log_done) {
                    QueueTunnelLog(g_early_log, g_early_log_len);
                    g_early_log_len = 0;
                    g_early_log_done = true;
                }
                return;
            }
            const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) return;
            // Send-only: keep its share of the socket buffer pool small.
            const int rcv = 0x1000, snd = 0x2000;
            ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv);
            ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof snd);
            g_log_udp_fd = fd;
        }

        // Sends queued log lines through the tunnel (engine loop, runtime lock
        // held). Waits while we're not on the tunnel; lines from boot are
        // kept (the oldest dropped if the queue fills).
        void FlushTunnelLog(ZtnxEngine *engine) {
            static int32_t udp = 0;
            static char out[sizeof g_tunnel_log];
            if (!g_log_tunnel) return;
            const ZtnxCtlStatus st = status::Get();
            if (st.state != ZTNX_CTL_CONNECTED) return;
            if (armTicksToNs(armGetSystemTick()) < g_tunnel_log_hold_until_ns) return;
            size_t len;
            {
                std::scoped_lock lk(g_log_mutex);
                if (g_tunnel_log_len == 0) return;
                len = g_tunnel_log_len;
                std::memcpy(out, g_tunnel_log, len);
                g_tunnel_log_len = 0;
            }
            if (udp <= 0) udp = ztnx_net_udp_bind(engine, 0);
            if (udp <= 0) return;
            ZtnxAddr dst = {};
            dst.family = 4;
            std::memcpy(dst.ip, &g_log_udp_addr.sin_addr.s_addr, 4);
            dst.port = ntohs(g_log_udp_addr.sin_port);
            for (size_t off = 0; off < len;) {
                const char *nl = static_cast<const char *>(std::memchr(out + off, '\n', len - off));
                const size_t n = (nl ? static_cast<size_t>(nl - (out + off)) : len - off) + (nl ? 1 : 0);
                ztnx_net_udp_sendto(engine, udp, reinterpret_cast<const u8 *>(out + off), n, &dst);
                off += n;
            }
        }

        void CloseUdpLogSocket() {
            std::scoped_lock lk(g_log_mutex);
            if (g_log_udp_fd >= 0) ::close(g_log_udp_fd);
            g_log_udp_fd = -1;
        }

        // Sends the lines logged so far over UDP, once the network is up (at
        // boot the log socket exists before Wi-Fi does); later lines go out
        // directly.
        void FlushEarlyLog() {
            std::scoped_lock lk(g_log_mutex);
            if (g_early_log_done) return;  // includes the tunnel case (queued instead)
            if (g_log_udp_fd < 0) {
                g_early_log_len = 0;
                g_early_log_done = true;
                return;
            }
            SendLogLines(g_early_log, g_early_log_len);
            g_early_log_len = 0;
            g_early_log_done = true;
        }

    }

    namespace {

        // ---- the tunnel's configuration ------------------------------------

        constinit os::SdkMutex g_conf_mutex;
        constinit char g_conf_name[ZTNX_CTL_CONF_NAME_MAX] = {};
        constinit bool g_hosts_on = true;
        constinit bool g_aliases_on = true;
        constinit std::atomic<bool> g_hosts_due = false;  // Collect() ran; Write() pending

        // Loads config/zerotier-nx/<name> into the engine (directly at boot,
        // through the runtime once it runs), tells the MITM and the hosts
        // file, and records the outcome for the overlay. Returns ZTNX_CTL_CONF_*.
        u32 ApplyConf(const char *name, ZtnxEngine *engine, ::ztnx::Runtime *rt) {
            std::scoped_lock lk(g_conf_mutex);
            if (!ValidConfName(name)) return ZTNX_CTL_CONF_NOT_FOUND;
            char path[128];
            util::SNPrintf(path, sizeof path, "%s/%s", ConfigDir, name);
            auto text = std::make_unique<char[]>(ConfMaxSize);
            const s64 len = ReadWholeFile(path, text.get(), ConfMaxSize);
            if (len < 0) {
                char what[160];
                DescribeMissingConf(name, what, sizeof what);
                Log("config: %s: not found (or over %zu KB). %s", path, ConfMaxSize / 1024, what);
                // From the overlay's Config page the file was there a moment
                // ago, and the running config stays: only a boot has none.
                if (!rt) status::SetConfMissing(what);
                return ZTNX_CTL_CONF_NOT_FOUND;
            }
            ZtnxConfig wc = {};
            wc.conf = text.get();
            wc.conf_len = static_cast<size_t>(len);
            static char err[160];
            static ZtnxPrefix routes[::ztnx::VSock::MaxRoutes];  // 64 * 24 bytes: static, not stack
            size_t n_routes = 0;
            u32 peers = 0;
            auto load = [&](ZtnxEngine *e) {
                if (!ztnx_engine_reload(e, &wc, ztnx_driver_now_ns(), err, sizeof err)) return false;
                n_routes = ztnx_engine_routes(e, routes, ::ztnx::VSock::MaxRoutes);
                static ZtnxPeerInfo info[ZTNX_CTL_MAX_PEERS];
                peers = static_cast<u32>(ztnx_engine_peers(e, info, ZTNX_CTL_MAX_PEERS));
                if (g_hosts_on) g_hosts_due = hosts::Collect(e, g_aliases_on) || g_hosts_due.load();
                return true;
            };
            const bool ok = rt ? rt->With(load) : load(engine);
            if (!ok) {
                Log("config: %s: %s", name, err);
                status::SetConfError(name, err);
                return ZTNX_CTL_CONF_INVALID;
            }
            ::ztnx::VSock::SetRoutes(routes, std::min(n_routes, ::ztnx::VSock::MaxRoutes));
            util::SNPrintf(g_conf_name, sizeof g_conf_name, "%s", name);
            status::SetConf(name, peers);
            ZtnxPrefix addr[1];
            const bool have_addr = ztnx_engine_addresses(engine, addr, 1) > 0 && addr[0].family == 4;
            u32 addr_be = 0;
            if (have_addr) std::memcpy(&addr_be, addr[0].ip, 4);
            Log("config: %s: %u peer(s), address %s, tunnel routes %zu%s", name, peers, have_addr ? inet_ntoa(in_addr{addr_be}) : "(none)",
                n_routes, n_routes > ::ztnx::VSock::MaxRoutes ? " (only the first 64 are used)" : "");
            StartUdpLog();
            return ZTNX_CTL_CONF_OK;
        }

        // Host names in Endpoint= lines: the engine asks (ZTNX_EVENT_RESOLVE,
        // with the runtime lock held, where a lookup must not block), the
        // loop looks them up between rounds without the lock, and answers
        // on its next round.
        struct Resolve {
            u32 peer;
            u16 port;
            char host[96];
        };
        constinit os::SdkMutex g_resolve_mutex;
        constinit Resolve g_resolve_asked[8] = {};
        constinit int g_resolve_asked_n = 0;
        constinit Resolve g_resolve_done[8] = {};
        constinit u32 g_resolve_done_ip[8] = {};
        constinit int g_resolve_done_n = 0;
        constinit u64 g_resolve_last_ns[ZTNX_CTL_MAX_PEERS] = {};

        void QueueResolve(const ZtnxEvent &ev) {
            std::scoped_lock lk(g_resolve_mutex);
            for (int i = 0; i < g_resolve_asked_n; i++)
                if (g_resolve_asked[i].peer == ev.value) return;
            if (g_resolve_asked_n == static_cast<int>(util::size(g_resolve_asked))) return;
            Resolve &r = g_resolve_asked[g_resolve_asked_n++];
            r.peer = ev.value;
            r.port = ev.port;
            util::SNPrintf(r.host, sizeof r.host, "%s", ev.text);
        }

        // Without the runtime lock: one lookup per round (up to 3 s), at most
        // every 10 s per peer.
        void ResolveOne() {
            Resolve r;
            {
                std::scoped_lock lk(g_resolve_mutex);
                if (g_resolve_asked_n == 0) return;
                r = g_resolve_asked[0];
                std::memmove(g_resolve_asked, g_resolve_asked + 1, sizeof(Resolve) * (g_resolve_asked_n - 1));
                g_resolve_asked_n--;
            }
            const u64 now = armTicksToNs(armGetSystemTick());
            if (r.peer < ZTNX_CTL_MAX_PEERS && g_resolve_last_ns[r.peer] && now - g_resolve_last_ns[r.peer] < 10'000'000'000ull) return;
            if (r.peer < ZTNX_CTL_MAX_PEERS) g_resolve_last_ns[r.peer] = now;
            u32 ip = 0;
            bool ok = false;
            Timed("endpoint lookup", [&] { ok = ResolveViaDns(r.host, &ip) == 0; });
            if (!ok) {
                Log("endpoint: %s: lookup failed (errno %d)", r.host, errno);
                return;
            }
            std::scoped_lock lk(g_resolve_mutex);
            if (g_resolve_done_n == static_cast<int>(util::size(g_resolve_done))) return;
            g_resolve_done_ip[g_resolve_done_n] = ip;
            g_resolve_done[g_resolve_done_n++] = r;
        }

        // With the runtime lock: hand the answers to the engine.
        void ApplyResolved(ZtnxEngine *engine) {
            std::scoped_lock lk(g_resolve_mutex);
            for (int i = 0; i < g_resolve_done_n; i++) {
                const Resolve &r = g_resolve_done[i];
                ZtnxAddr a = {};
                a.family = 4;
                std::memcpy(a.ip, &g_resolve_done_ip[i], 4);
                a.port = r.port;
                Log("endpoint: peer %u = %s -> %s:%u", r.peer, r.host, inet_ntoa(in_addr{g_resolve_done_ip[i]}), r.port);
                ztnx_engine_set_peer_endpoint(engine, r.peer, &a, ztnx_driver_now_ns());
            }
            g_resolve_done_n = 0;
        }

        // ---- sleep / wake ----------------------------------------------------

        // With our sockets open and in use across sleep, the transition
        // failed and omm aborted (2165-0001). So we take part in power-state
        // changes (psc) and close every socket we own on the way down.
        constexpr auto ZtnxPmModuleId = static_cast<psc::PmModuleId>(0x7747);
        constexpr psc::PmModuleId PmDependencies[] = {psc::PmModuleId_Nifm, psc::PmModuleId_Fs};

        psc::PmModule g_pm_module;
        constinit ::ztnx::Runtime *g_power_runtime = nullptr;
        alignas(os::ThreadStackAlignment) constinit u8 g_power_thread_stack[0x2000];  // measured: ~1 KB
        constinit os::ThreadType g_power_thread;
        constinit bool g_power_running = false;  // registered with psc, thread started

        // A stop from the overlay (StopForOverlay) asks the power thread to
        // leave psc, which it does only between transitions. Asked -> Taken
        // (the thread is deciding; can't be withdrawn) -> Done or Refused;
        // the asker may withdraw Asked -> Idle.
        enum PowerStop : int { PowerStop_Idle, PowerStop_Asked, PowerStop_Taken, PowerStop_Done, PowerStop_Refused };
        constinit std::atomic<int> g_power_stop = PowerStop_Idle;
        constinit os::EventType g_power_stop_event = {};

        // Every step is acknowledged without waiting on the network: by the
        // time "sleep ready" arrives the socket service may already be asleep,
        // and a blocked call there would hang the whole transition. So the
        // sockets close on the first step down (FullAwake -> MinimumAwake),
        // while everything is still awake, and reopen after FullAwake is
        // acknowledged, on the engine thread.
        void PowerThread(void *) {
            psc::PmState last = psc::PmState_FullAwake;
            bool suspended = false;
            // Time between being asked and acknowledging, over a wake's steps
            // (the system waits on every module, so this is our share).
            u64 wake_held_ns = 0;
            bool waking = false;
            auto handle_request = [&] {
                const u64 asked = armTicksToNs(armGetSystemTick());
                psc::PmState state;
                psc::PmFlagSet flags;
                if (R_FAILED(g_pm_module.GetRequest(std::addressof(state), std::addressof(flags)))) return;
                if (!suspended && last == psc::PmState_FullAwake && state != psc::PmState_FullAwake) {
                    // Every socket must be closed before we acknowledge: with
                    // ours open, the transition fails and omm aborts (2165-0001;
                    // also seen when this ran asynchronously). The engine thread
                    // does the closing; this thread never touches the socket
                    // service (it may already be asleep if the system went
                    // straight to "sleep ready") and waits a bounded time.
                    g_log_udp_paused = true;
                    Log("power: leaving full awake (state %d); closing sockets", static_cast<int>(state));
                    // A reboot or power-off (ShutdownReady) never wakes, so it
                    // must not count as a failed sleep.
                    if (state != psc::PmState_ShutdownReady) WriteWholeFile(SleepingPath, "1", 1);  // removed on wake; see PassesCrashGuard
                    g_power_runtime->RequestSuspend(::ztnx::Runtime::kSleep);
                    const u64 deadline = armTicksToNs(armGetSystemTick()) + 2'500'000'000ull;
                    while (!g_power_runtime->IsSuspended() && armTicksToNs(armGetSystemTick()) < deadline) {
                        os::SleepThread(TimeSpan::FromMilliSeconds(10));
                    }
                    if (!g_power_runtime->IsSuspended()) Log("power: sockets not closed in time; continuing");
                    suspended = true;
                }
                if (state == psc::PmState_ShutdownReady) {
                    // A clean power-off or reboot: this boot ended normally, so
                    // it mustn't count towards the crash guard (people reboot
                    // a lot while setting things up).
                    static_cast<void>(fs::DeleteFile(StartingPath));
                    if (suspended) static_cast<void>(fs::DeleteFile(SleepingPath));
                }
                if (const Result rc = g_pm_module.Acknowledge(state, ResultSuccess()); R_FAILED(rc)) Log("power: acknowledge failed: 0x%x", rc.GetValue());
                // Wake steps: from "essential services awake" up to full awake
                // (a light sleep goes straight back to full awake).
                if (state == psc::PmState_EssentialServicesAwake) waking = true;
                if (suspended && (waking || state == psc::PmState_FullAwake)) wake_held_ns += armTicksToNs(armGetSystemTick()) - asked;
                if (suspended && state == psc::PmState_FullAwake) {
                    g_log_udp_paused = false;
                    g_power_runtime->Resume(::ztnx::Runtime::kSleep);
                    suspended = false;
                    static_cast<void>(fs::DeleteFile(SleepingPath));
                    static_cast<void>(fs::DeleteFile(SleepFailuresPath));
                    Log("power: awake; reconnecting (we held the wake for %llu us)", static_cast<unsigned long long>(wake_held_ns / 1000));
                    wake_held_ns = 0;
                    waking = false;
                }
                last = state;
            };
            for (;;) {
                os::WaitAny(g_pm_module.GetEventPointer()->GetBase(), std::addressof(g_power_stop_event));
                if (g_pm_module.GetEventPointer()->TryWait()) handle_request();
                if (!os::TryWaitEvent(std::addressof(g_power_stop_event))) continue;
                int expected = PowerStop_Asked;
                if (!g_power_stop.compare_exchange_strong(expected, PowerStop_Taken)) continue;  // withdrawn
                // Only fully awake with no request waiting; one that just
                // arrived is handled first, and the stop refused.
                if (g_pm_module.GetEventPointer()->TryWait()) {
                    handle_request();
                } else if (!suspended && last == psc::PmState_FullAwake) {
                    if (const Result rc = g_pm_module.Finalize(); R_SUCCEEDED(rc)) {
                        Log("power: left psc (stopping)");
                        g_power_stop = PowerStop_Done;
                        return;
                    } else {
                        Log("power: leaving psc failed: 0x%x", rc.GetValue());
                    }
                }
                g_power_stop = PowerStop_Refused;
            }
        }

        // Without psc, sleep with our sockets open makes omm abort (the
        // console restarts): false means don't run at all.
        bool StartPowerHandling(::ztnx::Runtime &rt) {
            g_power_runtime = std::addressof(rt);
            if (R_FAILED(::pscmInitialize())) {
                Log("power: psc unavailable; not starting (sleep would fail)");
                return false;
            }
            if (const Result rc = g_pm_module.Initialize(ZtnxPmModuleId, PmDependencies, util::size(PmDependencies), os::EventClearMode_AutoClear); R_FAILED(rc)) {
                Log("power: psc module registration failed: 0x%x; not starting (sleep would fail)", rc.GetValue());
                return false;
            }
            os::InitializeEvent(std::addressof(g_power_stop_event), false, os::EventClearMode_AutoClear);
            stack_watch::Paint(g_power_thread_stack, sizeof g_power_thread_stack);
            if (R_FAILED(os::CreateThread(std::addressof(g_power_thread), PowerThread, nullptr, g_power_thread_stack, sizeof g_power_thread_stack,
                                          os::GetThreadCurrentPriority(os::GetCurrentThread())))) {
                Log("power: cannot create thread; not starting");
                static_cast<void>(g_pm_module.Finalize());
                return false;
            }
            os::SetThreadNamePointer(std::addressof(g_power_thread), "ztnx.Power");
            stack_watch::Add("power", std::addressof(g_power_thread));
            os::StartThread(std::addressof(g_power_thread));
            g_power_running = true;
            return true;
        }

        // Leaves psc for a stop, if no power transition is under way. Once
        // this returns true the system no longer waits for us at sleep, so
        // our sockets must already be closed.
        bool StopPowerHandling() {
            if (!g_power_running) return true;
            g_power_stop = PowerStop_Asked;
            os::SignalEvent(std::addressof(g_power_stop_event));
            const u64 deadline = armTicksToNs(armGetSystemTick()) + 3'000'000'000ull;
            for (;;) {
                const int st = g_power_stop.load();
                if (st == PowerStop_Done || st == PowerStop_Refused) break;
                if (st == PowerStop_Asked && armTicksToNs(armGetSystemTick()) > deadline) {
                    int expected = PowerStop_Asked;
                    if (g_power_stop.compare_exchange_strong(expected, PowerStop_Idle)) return false;
                }
                // Taken: the thread is deciding (bounded by one request).
                os::SleepThread(TimeSpan::FromMilliSeconds(10));
            }
            const bool done = g_power_stop.load() == PowerStop_Done;
            if (done) {
                g_power_running = false;
            } else {
                g_power_stop = PowerStop_Idle;
            }
            return done;
        }

    }

    namespace init {

        // Only what logging needs; everything else is initialized in Main()
        // where failures are logged and end the process cleanly, never in a
        // fatal error screen.
        void InitializeSystemModule() {
            R_ABORT_UNLESS(sm::Initialize());
            fs::InitializeForSystem();
            fs::SetEnabledAutoAbort(false);
        }

        void FinalizeSystemModule() {}

        void Startup() {
            init::InitializeAllocator(g_malloc_buffer, sizeof(g_malloc_buffer));
        }

    }

    void NORETURN Exit(int rc) {
        AMS_UNUSED(rc);
        ::svcExitProcess();
        __builtin_unreachable();
    }

    // The overlay's Start writes its system tick to StartRequestedPath just
    // before launching us. A fresh one means this isn't a boot-time start
    // (the tick restarts at boot, so a leftover from an earlier boot is
    // never fresh). Always consumed.
    bool StartedFromOverlay() {
        char buf[32] = {};
        const bool have = ReadWholeFile(StartRequestedPath, buf, sizeof buf) > 0;
        static_cast<void>(fs::DeleteFile(StartRequestedPath));
        if (!have) return false;
        const u64 asked = std::strtoull(buf, nullptr, 10);
        const u64 now = armGetSystemTick();
        if (asked == 0 || asked > now || armTicksToNs(now - asked) > StartRequestFreshNs) return false;
        Log("started from the overlay");
        return true;
    }

    // Crash-loop guard: stays off (and writes `crashed`) after repeated
    // boots that died early, or repeated sleeps that never woke up.
    bool PassesCrashGuard() {
        auto give_up = [](const char *why) {
            Log("%s: disabling (see %s)", why, CrashedPath);
            char msg[256];
            const int n = util::SNPrintf(msg, sizeof msg,
                                        "zerotier-nx stopped itself: %s.\n"
                                        "See sysmodule.log / sysmodule.log.1. Delete this file to try again.\n", why);
            WriteWholeFile(CrashedPath, msg, n);
            static_cast<void>(fs::DeleteFile(StartingPath));
            static_cast<void>(fs::DeleteFile(SleepFailuresPath));
            return false;
        };
        if (FileExists(CrashedPath)) {
            Log("%s exists (earlier runs failed): staying off; delete it to retry", CrashedPath);
            return false;
        }

        char buf[16] = {};
        if (FileExists(SleepingPath)) {
            // The console went to sleep with us running and never woke us.
            static_cast<void>(fs::DeleteFile(SleepingPath));
            const int failures = (ReadWholeFile(SleepFailuresPath, buf, sizeof buf) > 0 ? std::atoi(buf) : 0) + 1;
            if (failures >= MaxSleepFailures) return give_up("the console didn't wake from sleep twice in a row");
            Log("warning: the last sleep never woke up (%d of %d before disabling)", failures, MaxSleepFailures);
            WriteWholeFile(SleepFailuresPath, buf, util::SNPrintf(buf, sizeof buf, "%d", failures));
        }

        if (StartedFromOverlay()) return true;
        if (armTicksToNs(armGetSystemTick()) > BootStartWithinNs) return true;  // started by hand
        const int count = ReadWholeFile(StartingPath, buf, sizeof buf) > 0 ? std::atoi(buf) : 0;
        if (count >= MaxUnhealthyStarts) return give_up("3 boots in a row crashed within 3 minutes");
        WriteWholeFile(StartingPath, buf, util::SNPrintf(buf, sizeof buf, "%d", count + 1));
        return true;
    }

    namespace {

        constinit ::ztnx::Runtime *g_runtime = nullptr;
        constinit std::atomic<bool> g_stopping = false;  // committed: exit once the engine loop ends
        constinit bool g_stop_failed = false;  // committed but can't exit: idle until restart

        // ztnx:ctl Stop, on the ctl thread. Exiting is safe only with no
        // client session through our MITM, the MITM uninstalled from sm
        // (sm aborts on queries to a dead owner), our psc module gone (the
        // system would wait on it at sleep) and our sockets closed before
        // that. Each check that can refuse runs while it can still be undone.
        u32 StopForOverlay(u32 *detail) {
            *detail = 0;
            if (g_stopping) return ZTNX_CTL_STOP_OK;
            if (g_stop_failed) return ZTNX_CTL_STOP_FAILED;
            if (!g_runtime) return ZTNX_CTL_STOP_BUSY;
            Log("stop: requested from the overlay");

            // 1. No homebrew sessions; new ones bypass us from now on.
            switch (bsd_mitm::PrepareStop(detail)) {
                case bsd_mitm::StopCheck::Ok:
                    break;
                case bsd_mitm::StopCheck::Homebrew:
                    Log("stop: refused, homebrew has %u session(s) through us", *detail);
                    return ZTNX_CTL_STOP_HOMEBREW;
                case bsd_mitm::StopCheck::Busy:
                    return ZTNX_CTL_STOP_BUSY;
            }
            // 2. Close the engine's sockets (and the UDP log's).
            if (!g_runtime->Suspend(::ztnx::Runtime::kStopping, std::chrono::milliseconds(3000))) {
                Log("stop: refused, the engine didn't close its sockets in time");
                g_runtime->Resume(::ztnx::Runtime::kStopping);
                bsd_mitm::CancelStop();
                return ZTNX_CTL_STOP_BUSY;
            }
            // 3. Leave psc, unless a sleep or wake is under way.
            if (!StopPowerHandling()) {
                Log("stop: refused, a power state change is under way");
                g_runtime->Resume(::ztnx::Runtime::kStopping);
                bsd_mitm::CancelStop();
                return ZTNX_CTL_STOP_BUSY;
            }

            // Committed. On failure from here on the process stays, idle:
            // engine suspended, out of psc, new sessions not MITM'd.
            status::SetStopping();
            // A deliberate stop isn't a failed boot for the crash guard.
            static_cast<void>(fs::DeleteFile(StartingPath));
            if (!bsd_mitm::UninstallForStop()) {
                Log("stop: couldn't detach from the system cleanly; staying idle until the console restarts");
                g_stop_failed = true;
                return ZTNX_CTL_STOP_FAILED;
            }
            Log("stop: exiting (it starts again at boot, or from the overlay)");
            g_stopping = true;
            g_runtime->Stop();  // the main thread exits once the loop returns
            return ZTNX_CTL_STOP_OK;
        }

        // After StopForOverlay: nothing of ours is registered anywhere, and
        // our threads are idle. End the process without running global
        // destructors under those threads.
        void NORETURN ExitAfterStop() {
            os::SleepThread(TimeSpan::FromMilliSeconds(250));  // let the ctl reply go out
            {
                std::scoped_lock lk(g_log_mutex);
                if (g_log_open) fs::CloseFile(g_log_file);
                g_log_open = false;
            }
            ::svcExitProcess();
            __builtin_unreachable();
        }

        constinit ZtnxEngine *g_engine = nullptr;

        // ztnx:ctl SetConf, on the ctl thread: switch to another .conf and
        // make it the default for the next boot.
        u32 SetConfForOverlay(const char *name) {
            if (g_stopping || g_stop_failed || !g_runtime || !g_engine || status::IsStopping()) return ZTNX_CTL_CONF_BUSY;
            Log("config: switching to %s (from the overlay)", name);
            const u32 rc = ApplyConf(name, g_engine, g_runtime);
            if (rc == ZTNX_CTL_CONF_OK) SetConfigValue("conf", name);
            return rc;
        }

    }

    void Main() {
        stack_watch::AddCurrent("main");
        // Without the SD card there is nothing to log to or configure from.
        if (R_FAILED(fs::MountSdCard("sdmc"))) return;
        static_cast<void>(fs::CreateDirectory("sdmc:/config"));
        static_cast<void>(fs::CreateDirectory(ConfigDir));
        OpenLog();
        Log("zerotier-nx sysmodule %s starting", ztnx_version());
        if (FileExists(DisabledPath)) {
            Log("%s exists: staying disabled", DisabledPath);
            return;
        }
        // Our memory was taken when we were launched; if that left the
        // system short, give it back now (exiting), before anything needs it.
        // Not a failure for the crash guard. Only useful for a start from the
        // overlay: at boot most other sysmodules start after us (about 14 MB
        // later on a typical setup), so plenty is still free here.
        u64 sys_free = 0, sys_total = 0;
        const bool pool_known = memory::SystemPool(&sys_free, &sys_total);
        Log("memory: %lu KB (fixed); system memory free: %lu KB of %lu KB", static_cast<unsigned long>(memory::Own() / 1024),
            static_cast<unsigned long>(sys_free / 1024), static_cast<unsigned long>(sys_total / 1024));
        if (pool_known && sys_free < MinSystemFree) {
            char why[200];
            const int n = util::SNPrintf(why, sizeof why,
                                         "Too little system memory: other sysmodules leave %lu KB free with zerotier-nx running, "
                                         "and it keeps %lu KB free for the system.\n",
                                         static_cast<unsigned long>(sys_free / 1024), static_cast<unsigned long>(MinSystemFree / 1024));
            Log("%.*s; not starting", n - 1, why);
            WriteWholeFile(NotStartedPath, why, static_cast<size_t>(n));
            return;
        }
        static_cast<void>(fs::DeleteFile(NotStartedPath));
        if (!PassesCrashGuard()) return;

        // Services, initialized here so a failure is a logged, clean exit.
        if (Result rc = nifmInitialize(NifmServiceType_Admin); R_FAILED(rc)) {
            Log("nifmInitialize failed: 0x%x", rc.GetValue());
            return;
        }
        if (Result rc = timeInitialize(); R_FAILED(rc)) Log("timeInitialize failed: 0x%x (clock from server)", rc.GetValue());
        if (Result rc = bsdInitialize(&BsdConfig, SocketConfig.num_bsd_sessions, SocketConfig.bsd_service_type); R_FAILED(rc)) {
            Log("bsdInitialize failed: 0x%x", rc.GetValue());
            return;
        }
        if (Result rc = socketInitialize(&SocketConfig); R_FAILED(rc)) {
            Log("socketInitialize failed: 0x%x", rc.GetValue());
            return;
        }

        Config cfg;
        LoadConfig(cfg);
        if (cfg.log_udp[0]) SetUpUdpLog(cfg.log_udp);  // opened once the tunnel's routes are known
        ztnx_set_log_callback([](u32 level, const char *msg) { Log("%s%s", level <= 2 ? "WARN " : "", msg); }, 3);
        ztnx_set_resolver(ResolveViaDns);

        // The ZeroTier identity's keys come from this generator, so seed it
        // with all 256 bits of the kernel's entropy: GenerateRandomBytes is a
        // TinyMT seeded from half of them.
        u8 seed[32];
        os::GenerateRandomBytes(seed, sizeof seed);
        for (int i = 0; i < 4; i++) {
            u64 entropy = 0;
            if (R_SUCCEEDED(svc::GetInfo(&entropy, svc::InfoType_RandomEntropy, svc::InvalidHandle, i))) {
                for (int b = 0; b < 8; b++) seed[i * 8 + b] ^= static_cast<u8>(entropy >> (8 * b));
            }
        }
        ztnx_seed_rng(seed);
        if (const u32 st = ztnx_selftest(); st != ZTNX_SELFTEST_OK) {
            Log("crypto selftest FAILED (%u); not starting", st);
            return;
        }
        // ZeroTier's core throws and catches C++ exceptions, which Atmosphère's
        // default link turns into aborts. Make sure this build's link didn't.
        if (const u32 st = ztnx_engine_selftest(); st != 0) {
            Log("C++ exceptions selftest FAILED (0x%x); not starting", st);
            return;
        }
        Log("C++ exceptions: ok");

        // Boot2 runs before Wi-Fi is up (about 25 s before, typically).
        // nifm only signals events for network requests of our own, which
        // would change how it manages the connection, so poll instead: one
        // cheap IPC per 100 ms, so we start soon after Wi-Fi does.
        if (!NetworkUp()) {
            Log("waiting for the network");
            while (!NetworkUp()) {
                WatchBootMemory(armTicksToNs(armGetSystemTick()));
                os::SleepThread(TimeSpan::FromMilliSeconds(100));
            }
        }
        u32 ip = CurrentIp();
        Log("network up, local address %s", inet_ntoa(in_addr{ip}));
        SetLocalNet(ip);

        // Consoles often have wrong clocks (dead RTC, Nintendo's NTP blocked):
        // TLS needs a plausible date, and so does WireGuard (handshake
        // timestamps must never go backwards, or peers ignore us).
        bool corrected = false;
        const u64 console_time = ConsoleUnixTime();
        u64 unix_time = ztnx_sane_unix_time(console_time, ZTNX_UPDATE_HOST, &corrected);
        if (corrected) Log("console clock implausible (%llu); using %s's time (%llu)",
                           static_cast<unsigned long long>(console_time), ZTNX_UPDATE_HOST, static_cast<unsigned long long>(unix_time));
        if (unix_time == 0) unix_time = console_time;

        ZtnxEngine *engine = ztnx_engine_new(ztnx_driver_now_ns(), unix_time);
        g_engine = engine;
        g_hosts_on = std::strcmp(cfg.hosts, "off") != 0;
        g_aliases_on = std::strcmp(cfg.aliases, "off") != 0;
        if (std::strcmp(cfg.tunnel_lan, "on") == 0) {
            Log("tunnel_lan=on: LAN addresses go through the tunnel too (testing)");
            ::ztnx::VSock::SetTunnelLan(true);
        }
        char conf_name[ZTNX_CTL_CONF_NAME_MAX];
        RenameTxtConfs();
        SelectConf(cfg, conf_name, sizeof conf_name);
        // A broken or missing .conf isn't fatal: the overlay shows why and
        // offers the others.
        ApplyConf(conf_name, engine, nullptr);
        StartUdpLog();
        FlushEarlyLog();
        // Events arrive with the runtime lock held.
        ZtnxDriver *driver = ztnx_driver_new(engine, [](void *, const ZtnxEvent *ev) {
            if (ev->kind == ZTNX_EVENT_RESOLVE) QueueResolve(*ev);
            else Log("%s: %s (%u)", EventName(ev->kind), ev->text, ev->value);
            status::OnEvent(*ev);
        }, engine);
        ztnx_driver_resolve_inline(driver, 0);  // lookups happen off the lock (ResolveOne)
        if (cfg.overlay_budget_kb[0]) {
            // Bounded by the sysmodule's heap (heap_size.h): the engine and
            // the MITM need about 300 KB of it besides the overlay buffers.
            const unsigned long kb = std::clamp(std::strtoul(cfg.overlay_budget_kb, nullptr, 10), 128ul, 384ul);
            ztnx_net_set_budget(engine, kb * 1024);
            Log("overlay buffer budget: %lu KB", kb);
        }
        const u16 listen_port = ztnx_engine_listen_port(engine);
        if (ztnx_driver_open_udp(driver, listen_port) != 0 && ztnx_driver_open_udp(driver, 0) != 0) {
            Log("no UDP socket (errno %d); not starting", errno);
            return;
        }
        Log("udp: port %u%s", ztnx_driver_udp_port(driver), listen_port && ztnx_driver_udp_port(driver) != listen_port ? " (ListenPort was taken)" : "");
        std::string error;
        auto rt = ::ztnx::Runtime::Adopt(engine, driver, &error);
        if (!rt) {
            Log("runtime: %s (errno %d)", error.c_str(), errno);
            return;
        }
        Log("engine started");

        // Homebrew sockets to tunnel addresses go through the engine.
        // The log socket goes down and up with the engine's own (sleep).
        // Coming back counts as having been offline (see the loop below).
        g_update_check = std::strcmp(cfg.update_check, "off") != 0;
        // Slow steps of the engine loop run after its tick, without the
        // runtime lock (see Runtime::Run): the network check (nifm calls,
        // 3-7 ms), the hosts file (most of a second) and log lines written
        // to the SD card.
        bool network_check_due = false, network_checked = false;
        u32 network_ip = 0;
        rt->SetSuspendHooks([] {
            {
                std::scoped_lock lk(g_log_mutex);
                EmitDeferredLog();  // the loop won't run to write them
            }
            CloseUdpLogSocket();
            SuspendUpdateCheck();
        }, [&ip, &network_checked] {
            network_checked = false;  // from before the sleep
            g_tunnel_log_hold_until_ns = armTicksToNs(armGetSystemTick()) + 10'000'000'000ull;
            StartUdpLog();
            ip = 0;
            g_last_round_ns = 0;
            status::EngineRan(armTicksToNs(armGetSystemTick()));
        });
        if (!StartPowerHandling(*rt)) return;
        g_runtime = rt.get();
        // mitm=homebrew (default), off, or homebrew,sys-ftpd. Homebrew
        // includes forwarders (non-01 IDs); mitm_titles adds others.
        const bool mitm = bsd_mitm::Start(*rt, std::strcmp(cfg.mitm, "off") == 0 ? bsd_mitm::Scope::Off : bsd_mitm::Scope::Homebrew,
                                          std::strstr(cfg.mitm, "sys-ftpd") != nullptr, cfg.mitm_titles);

        // Status for the overlay (and the user's pause switch, applied before
        // the engine loop's first round), then its control service.
        status::Initialize(*rt, (mitm ? ZTNX_CTL_FLAG_MITM : 0) | (g_hosts_on ? ZTNX_CTL_FLAG_HOSTS : 0),
                           std::strcmp(cfg.connect_notice, "off") != 0);
        ctl::Start(StopForOverlay, SetConfForOverlay);

        // Engine loop on this thread; housekeeping between rounds. Re-detect
        // our address after Wi-Fi changes (roaming, sleep/wake): every 5 s,
        // or 250 ms while offline (a wake usually finds Wi-Fi still down).
        // Back online (or on a new address), every peer is contacted again at
        // once and host names are resolved afresh.
        u64 last_check = armTicksToNs(armGetSystemTick());
        u64 last_heap_log = 0;
        const u64 started = armTicksToNs(armGetSystemTick());
        bool healthy = false;
        size_t heap_all_peak = 0;
        int batched = 0;  // the driver's batched receive state, as last logged
        {
            std::scoped_lock lk(g_log_mutex);
            g_log_defer_thread = os::GetCurrentThread();
        }
        // The engine loop runs on core 2 when it can (see bsd_mitm::EngineCores).
        os::SetThreadCoreMask(os::GetCurrentThread(), bsd_mitm::PreferredCore, bsd_mitm::EngineCores);
        rt->Run([&](ZtnxDriver *d) {
            const u64 now = armTicksToNs(armGetSystemTick());
            WatchBootMemory(now);
            // A round takes at most about a second (the poll timeout).
            if (g_last_round_ns && now - g_last_round_ns > 3'000'000'000ull) {
                Log("engine loop stalled: %llu ms since the last round", static_cast<unsigned long long>((now - g_last_round_ns) / 1'000'000));
            }
            g_last_round_ns = now;
            status::EngineRan(now);
            static ZtnxPeerInfo peers[ZTNX_CTL_MAX_PEERS];  // 2.5 KB: static, not stack
            status::SetPeers(peers, ztnx_engine_peers(engine, peers, ZTNX_CTL_MAX_PEERS));
            ApplyResolved(engine);
            // Whole-heap use (Rust, C++, C), sampled every round; the Rust
            // peak below is exact.
            const size_t heap_free = init::GetAllocator()->GetTotalFreeSize();
            heap_all_peak = std::max(heap_all_peak, MallocBufferSize - std::min(heap_free, MallocBufferSize));
            if (!healthy && now - started > HealthyAfterNs) {
                healthy = true;
                static_cast<void>(fs::DeleteFile(StartingPath));
                Log("running stably; crash guard reset");
            }
            if (now - last_heap_log > 60'000'000'000ull) {
                last_heap_log = now;
                size_t cur = 0, peak = 0;
                ztnx_heap_stats(&cur, &peak);
                Log("heap: rust %zu KB (peak %zu), all %zu KB (peak %zu, largest free %zu) of %zu KB; overlay buffers %zu KB", cur / 1024,
                    peak / 1024, (MallocBufferSize - std::min(heap_free, MallocBufferSize)) / 1024, heap_all_peak / 1024,
                    init::GetAllocator()->GetAllocatableSize() / 1024, MallocBufferSize / 1024, ztnx_net_buffer_usage(engine) / 1024);
                char classes[200];
                ztnx_heap_classes(classes, sizeof classes);
                Log("heap by size (KB/allocs): %s", classes);
                stack_watch::Log();
            }
            int bsd_errno = 0;
            if (const int b = ztnx_driver_batched_receive(d, &bsd_errno); b != batched) {
                batched = b;
                if (b > 0) {
                    Log("udp: batched receive");
                } else {
                    Log("udp: one datagram per call (batched receive errno %d)", bsd_errno);
                }
            }
            FlushTunnelLog(engine);
            Timed("update check", [&] { StepUpdateCheck(now); });
            if (now - last_check > (ip ? 5'000'000'000ull : 250'000'000ull)) {
                last_check = now;
                network_check_due = true;
            }
            if (network_checked) {
                network_checked = false;
                const u32 cur = network_ip;
                status::SetOffline(cur == 0);
                if (cur != ip) {
                    Log("local address changed: %s", cur ? inet_ntoa(in_addr{cur}) : "(offline)");
                    ip = cur;
                    SetLocalNet(cur);
                    if (cur) ztnx_engine_network_up(engine, ztnx_driver_now_ns());
                }
            }
        }, [&] {
            if (network_check_due) {
                network_check_due = false;
                Timed("network check", [&] { network_ip = NetworkUp() ? CurrentIp() : 0; });
                network_checked = true;
            }
            if (g_hosts_due.exchange(false)) Timed("hosts file update", [] { hosts::Write(); });
            ResolveOne();
            std::scoped_lock lk(g_log_mutex);
            EmitDeferredLog();
        });
        {
            std::scoped_lock lk(g_log_mutex);
            g_log_defer_thread = nullptr;
            EmitDeferredLog();
        }
        // Only a stop from the overlay ends the loop.
        if (g_stopping) ExitAfterStop();
        Log("engine loop ended unexpectedly; exiting");
        bsd_mitm::UninstallForExit();
        ::svcExitProcess();
    }

}

namespace ams {

    // A crash in this process (libstratosphere's CrashHandler builds `ctx`
    // and calls this; the default reboots into the fatal screen). Log where
    // it happened, as offsets into our binary for addr2line, then end only
    // this process: zerotier-nx stops but the console keeps running.
    // Runs on the one-page exception stack, maybe with the log mutex held,
    // so it formats into a static buffer and writes without locking.
    void ExceptionHandler(FatalErrorContext *ctx) {
        static char line[640];
        const u64 base = ctx->module_base;
        auto off = [base](u64 a) { return a >= base ? a - base : a; };
        // x0/x1: an abort's failing Result is usually among them.
        int n = util::SNPrintf(line, sizeof line, "CRASH desc 0x%x: pc +0x%lx lr +0x%lx far 0x%lx sp 0x%lx base 0x%lx x0 0x%lx x1 0x%lx; trace",
                               ctx->error_desc, off(ctx->pc), off(ctx->lr), ctx->far, ctx->sp, base, ctx->gprs[0], ctx->gprs[1]);
        for (u64 i = 0; i < ctx->stack_trace_size && i < 12 && n < static_cast<int>(sizeof line) - 24; i++) {
            n += util::SNPrintf(line + n, sizeof line - n, " +0x%lx", off(ctx->stack_trace[i]));
        }
        if (n > static_cast<int>(sizeof line) - 2) n = sizeof line - 2;
        line[n++] = '\n';
        if (g_log_open) {
            // Lines the engine thread logged since the loop last wrote them.
            if (g_early_log_done && g_early_log_len) {
                static_cast<void>(fs::WriteFile(g_log_file, g_log_offset, g_early_log, g_early_log_len, fs::WriteOption::Flush));
                g_log_offset += g_early_log_len;
            }
            static_cast<void>(fs::WriteFile(g_log_file, g_log_offset, line, n, fs::WriteOption::Flush));
            g_log_offset += n;
        }
        if (g_log_udp_fd >= 0) {
            ::sendto(g_log_udp_fd, line, n, 0, reinterpret_cast<sockaddr *>(std::addressof(g_log_udp_addr)), sizeof g_log_udp_addr);
        }
        bsd_mitm::UninstallForExit();
        svcExitProcess();
        __builtin_unreachable();
    }

}

extern "C" [[noreturn]] void ztnx_platform_panic(const uint8_t *msg, size_t len) {
    ams::g_log_defer_thread = nullptr;  // written now, with any lines still waiting
    ams::Log("PANIC in ztnx core: %.*s", static_cast<int>(len), reinterpret_cast<const char *>(msg));
    AMS_ABORT("ztnx core panic");
}

// operator new and delete are in operator_new.cpp (on malloc, which is
// backed by g_malloc_buffer).

// The shared C helpers' snprintf, routed to libstratosphere's formatter
// (the sysmodule build defines snprintf=ztnx_snprintf): newlib's would add
// its float formatting and stdio to the binary.
extern "C" int ztnx_snprintf(char *dst, size_t size, const char *fmt, ...) {
    std::va_list vl;
    va_start(vl, fmt);
    const int n = ams::util::VSNPrintf(dst, size, fmt, vl);
    va_end(vl);
    return n;
}

// Used by the shared app helpers (ztnx_app.c).
extern "C" void ztnx_platform_random(uint8_t *buf, size_t len) { ams::os::GenerateRandomBytes(buf, len); }

// ZeroTier's random source: the core's CSPRNG, seeded in Main before any
// ZeroTier code runs.
extern "C" void ztnx_secure_random(void *buf, unsigned int len) {
    AMS_ABORT_UNLESS(ztnx_random_bytes(static_cast<uint8_t *>(buf), len));
}
