// zerotier-nx sysmodule: runs ZeroTier's core from boot (boot2), so the
// console is on its ZeroTier network without any app open.
//
// It also MITMs bsd:u for homebrew (bsd_mitm.cpp), so their sockets reach
// the network's addresses (mitm=off in config.ini disables that).
//
// Files (SD card):
//   config/zerotier-nx/config.ini   network=<16 hex digits>, port=<udp port>,
//                                    host = <name> <address> (any number),
//                                    log_udp=<ip>:<port>,
//                                    mitm=homebrew|homebrew,sys-ftpd|off,
//                                    mitm_titles=<program IDs>, hosts=on|off,
//                                    aliases=on|off (stand-in addresses),
//                                    overlay_budget_kb=<128..384>,
//                                    connect_notice=on|off, update_check=on|off,
//                                    tunnel_lan=on (tests: LAN through the tunnel)
//   config/zerotier-nx/identity.secret, identity.public  this Switch's
//                                    ZeroTier identity (made on first boot when
//                                    memory allows, or with zerotier-idtool)
//   config/zerotier-nx/planet, networks.d/  what ZeroTier itself stores
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
#include "zt_link.hpp"
#include "stack_watch.hpp"
#include "heap_size.h"
#include "memory.hpp"
#include "status.hpp"

namespace ams {

    namespace {

        constexpr const char ConfigDir[] = "sdmc:/config/zerotier-nx";
        constexpr const char ConfigPath[] = "sdmc:/config/zerotier-nx/config.ini";
        // ZeroTier's state: this console's identity (its node ID and keys)
        // and the network's last configuration.
        constexpr const char IdentitySecretPath[] = "sdmc:/config/zerotier-nx/identity.secret";
        constexpr const char IdentityPublicPath[] = "sdmc:/config/zerotier-nx/identity.public";
        constexpr const char NetworksDir[] = "sdmc:/config/zerotier-nx/networks.d";
        // Making an identity borrows 2 MB from the system once. Not while the
        // console is still starting up: this long after power-on at the
        // earliest, and only with this much free.
        constexpr u64 IdentityAfterBootNs = 120'000'000'000ull;
        constexpr u64 IdentityMinFree = 3_MB;
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
        // exactly tools/footprint.sh's target (heap_size.h).
        constexpr size_t MallocBufferSize = ZTNX_HEAP_SIZE;
        static_assert(MallocBufferSize % os::MemoryPageSize == 0);
        alignas(os::MemoryPageSize) constinit u8 g_malloc_buffer[MallocBufferSize];

        // The engine's own sockets: the update check (TCP, a 1 KB answer
        // through the system's TLS); ZeroTier's, DNS, the runtime's wake pair
        // and the log (UDP). The transfer memory is the buffer pool for all
        // of them: each socket's buffers are taken from it, and one that
        // doesn't fit fails with ENOBUFS. Only ZeroTier's socket is big (it
        // grows its receive buffer to 160 KB, ztnx_driver.c); the rest ask
        // for 4-8 KB each. The pool is what those need together (about 230
        // KB with the update check running) and some to spare: libnx's own
        // formula, with this much in place of one UDP receive buffer.
        constexpr u32 UdpRxPoolShare = 0x10000;
        consteval size_t BsdTransferMemorySize(const ::SocketInitConfig &c) {
            const u32 sum = c.tcp_tx_buf_max_size + c.tcp_rx_buf_max_size + c.udp_tx_buf_size + UdpRxPoolShare;
            return static_cast<size_t>(c.sb_efficiency) * util::AlignUp(sum, os::MemoryPageSize);
        }

        constexpr const ::SocketInitConfig SocketConfig = {
            .tcp_tx_buf_size = 0x2000,
            .tcp_rx_buf_size = 0x2000,
            .tcp_tx_buf_max_size = 0x2000,
            .tcp_rx_buf_max_size = 0x4000,
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
        // The socket service dropped the log socket (the network went away
        // without a sleep); the engine loop's network check opens another.
        constinit std::atomic<bool> g_log_udp_lost = false;
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
                if (::sendto(g_log_udp_fd, lines + off, len, 0, reinterpret_cast<sockaddr *>(std::addressof(g_log_udp_addr)), sizeof g_log_udp_addr) < 0 &&
                    (errno == EPIPE || errno == EBADF || errno == ENOTSOCK || errno == ENOTCONN)) {
                    ::close(g_log_udp_fd);
                    g_log_udp_fd = -1;
                    g_log_udp_lost = true;
                    return;
                }
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
            char network[20] = {};  // the network to join: its 16 hex digit ID
            char port[8] = {};      // ZeroTier's UDP port; default 9993
            char log_udp[64] = {};
            char mitm[32] = "homebrew";  // "homebrew,sys-ftpd" or "off"
            char mitm_titles[384] = {};  // forwarders' program IDs, served like homebrew
            char hosts[8] = "on";        // host= names in Atmosphere's hosts file, or "off"
            char aliases[8] = "on";      // private addresses named as 100.127.x.y stand-ins, or "off"
            char overlay_budget_kb[8] = {};  // tunnel socket buffers; default 320
            char connect_notice[8] = "on";   // toast with our address when first connected
            char update_check[8] = "on";     // ask GitHub for a newer release at boot
            char tunnel_lan[8] = {};         // "on": LAN addresses go through the tunnel too (tests)
        };

        // Names for addresses on the network, from config.ini's
        // "host = name a.b.c.d" lines, as "a.b.c.d name\n" lines (the form
        // hosts::Collect takes). ZeroTier itself has no device names.
        constinit char g_host_lines[2_KB] = {};

        void AddHost(const char *value) {
            // "name a.b.c.d" (no sscanf here: the sysmodule has no stdio).
            char name[64] = {}, ip[20] = {};
            const size_t name_len = std::strcspn(value, " \t");
            const char *rest = value + name_len;
            while (*rest == ' ' || *rest == '\t') rest++;
            const size_t ip_len = std::strcspn(rest, " \t");
            if (name_len == 0 || name_len >= sizeof name || ip_len == 0 || ip_len >= sizeof ip) {
                Log("config: host = %s: expected a name and an IPv4 address", value);
                return;
            }
            std::memcpy(name, value, name_len);
            std::memcpy(ip, rest, ip_len);
            if (inet_addr(ip) == INADDR_NONE) {
                Log("config: host = %s: %s is not an IPv4 address", value, ip);
                return;
            }
            const size_t used = std::strlen(g_host_lines);
            const int n = util::SNPrintf(g_host_lines + used, sizeof g_host_lines - used, "%s %s\n", ip, name);
            if (n < 0 || used + static_cast<size_t>(n) >= sizeof g_host_lines) {
                g_host_lines[used] = 0;
                Log("config: too many host= lines; %s left out", name);
            }
        }

        void LoadConfig(Config &c) {
            static char buf[4_KB];  // config.ini is a few hundred bytes
            if (ReadWholeFile(ConfigPath, buf, sizeof buf) < 0) return;
            char *save = nullptr;
            for (char *line = strtok_r(buf, "\r\n", &save); line; line = strtok_r(nullptr, "\r\n", &save)) {
                while (*line == ' ' || *line == '\t') line++;
                if (line[0] == '#') continue;
                char *eq = std::strchr(line, '=');
                if (!eq) continue;
                // "key=value" or "key = value".
                char *key_end = eq;
                while (key_end > line && (key_end[-1] == ' ' || key_end[-1] == '\t')) key_end--;
                *key_end = 0;
                char *v = eq + 1;
                while (*v == ' ' || *v == '\t') v++;
                for (char *end = v + std::strlen(v); end > v && (end[-1] == ' ' || end[-1] == '\t'); end--) end[-1] = 0;
                auto set = [&](const char *key, char *dst, size_t cap) {
                    if (!std::strcmp(line, key)) util::SNPrintf(dst, cap, "%s", v);
                };
                if (!std::strcmp(line, "host")) AddHost(v);
                set("network", c.network, sizeof c.network);
                set("port", c.port, sizeof c.port);
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

        // Engine loop's tick. Only the start blocks (DNS lookup).
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

        // Once the network's routes are known: an address on it gets its
        // lines through the stack, anything else a real socket.
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

        // Sends queued log lines through the network (engine loop's tick).
        // Waits while we're not on it; lines from boot are kept (the oldest
        // dropped if the queue fills).
        void FlushTunnelLog(::ztnx::Runtime &rt) {
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
            ZtnxAddr dst = {};
            dst.family = 4;
            std::memcpy(dst.ip, &g_log_udp_addr.sin_addr.s_addr, 4);
            dst.port = ntohs(g_log_udp_addr.sin_port);
            rt.With([&](ZtnxStack *stack) {
                if (udp <= 0) udp = ztnx_net_udp_bind(stack, 0);
                if (udp <= 0) return;
                for (size_t off = 0; off < len;) {
                    const char *nl = static_cast<const char *>(std::memchr(out + off, '\n', len - off));
                    const size_t n = (nl ? static_cast<size_t>(nl - (out + off)) : len - off) + (nl ? 1 : 0);
                    ztnx_net_udp_sendto(stack, udp, reinterpret_cast<const u8 *>(out + off), n, &dst);
                    off += n;
                }
            });
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

        // ---- ZeroTier's state on the SD card --------------------------------

        bool StatePath(int type, u64 id, char *out, size_t cap) {
            switch (type) {
                case ZTNX_STATE_IDENTITY_SECRET:
                    util::SNPrintf(out, cap, "%s", IdentitySecretPath);
                    return true;
                case ZTNX_STATE_IDENTITY_PUBLIC:
                    util::SNPrintf(out, cap, "%s", IdentityPublicPath);
                    return true;
                case ZTNX_STATE_PLANET:
                    util::SNPrintf(out, cap, "%s/planet", ConfigDir);
                    return true;
                case ZTNX_STATE_NETWORK_CONFIG:
                    util::SNPrintf(out, cap, "%s/%016llx.conf", NetworksDir, static_cast<unsigned long long>(id));
                    return true;
                default:
                    return false;
            }
        }

        // Engine thread, without the runtime lock (see ZtLinkConfig).
        int StateGet(void *, int type, u64 id, void *buf, unsigned int cap) {
            char path[96];
            if (!StatePath(type, id, path, sizeof path)) return -1;
            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), path, fs::OpenMode_Read))) return -1;
            ON_SCOPE_EXIT { fs::CloseFile(f); };
            s64 size = 0;
            if (R_FAILED(fs::GetFileSize(std::addressof(size), f)) || size < 0 || static_cast<u64>(size) > cap) return -1;
            size_t got = 0;
            if (R_FAILED(fs::ReadFile(std::addressof(got), f, 0, buf, static_cast<size_t>(size)))) return -1;
            return static_cast<int>(got);
        }

        void StatePut(void *, int type, u64 id, const void *data, int len) {
            char path[96];
            if (!StatePath(type, id, path, sizeof path)) return;
            status::EngineStep("writing ZeroTier's state");
            if (len < 0) {
                static_cast<void>(fs::DeleteFile(path));
            } else {
                if (type == ZTNX_STATE_NETWORK_CONFIG) static_cast<void>(fs::CreateDirectory(NetworksDir));
                if (!WriteWholeFile(path, data, static_cast<size_t>(len))) Log("state: cannot write %s", path);
            }
            status::EngineStep(nullptr);
        }

        // ---- the identity ----------------------------------------------------

        // The address of the identity on the card, or 0 if there is none (or
        // what is there isn't one with its private key).
        u64 LoadIdentity() {
            static char text[ZTNX_IDENTITY_TEXT_MAX];
            const s64 n = ReadWholeFile(IdentitySecretPath, text, sizeof text);
            if (n <= 0) return 0;
            text[std::strcspn(text, "\r\n \t")] = 0;
            return ztnx_engine_identity_address(text);
        }

        // Makes this console's identity and stores it. The work needs 2 MB of
        // scratch memory, which the sysmodule's own heap doesn't have: it is
        // borrowed from the system for the few seconds this takes and given
        // back. Returns the new address, or 0.
        u64 CreateIdentity() {
            if (const Result rc = os::SetMemoryHeapSize(ZTNX_IDENTITY_SCRATCH); R_FAILED(rc)) {
                Log("identity: the system wouldn't lend 2 MB (0x%x)", rc.GetValue());
                return 0;
            }
            ON_SCOPE_EXIT { static_cast<void>(os::SetMemoryHeapSize(0)); };
            uintptr_t block = 0;
            if (const Result rc = os::AllocateMemoryBlock(std::addressof(block), ZTNX_IDENTITY_SCRATCH); R_FAILED(rc)) {
                Log("identity: cannot use the borrowed memory (0x%x)", rc.GetValue());
                return 0;
            }
            static char secret[ZTNX_IDENTITY_TEXT_MAX], pub[ZTNX_IDENTITY_TEXT_MAX];
            const u64 t0 = armTicksToNs(armGetSystemTick());
            const u64 addr = ztnx_engine_generate_identity(reinterpret_cast<void *>(block), secret, pub);
            const u64 took_ms = (armTicksToNs(armGetSystemTick()) - t0) / 1'000'000;
            os::FreeMemoryBlock(block, ZTNX_IDENTITY_SCRATCH);
            if (!addr) {
                Log("identity: generation failed");
                return 0;
            }
            if (!WriteWholeFile(IdentitySecretPath, secret, std::strlen(secret))) {
                Log("identity: cannot write %s", IdentitySecretPath);
                return 0;
            }
            static_cast<void>(WriteWholeFile(IdentityPublicPath, pub, std::strlen(pub)));
            Log("identity: created %010llx in %llu ms", static_cast<unsigned long long>(addr), static_cast<unsigned long long>(took_ms));
            return addr;
        }

        // Sends the lines logged so far over UDP through a socket that is
        // closed again at once. Until the identity exists nothing of ours
        // handles sleep (StartPowerHandling comes later), and the console
        // can't sleep with a socket of ours open: omm aborts.
        void SendEarlyLogBriefly() {
            std::scoped_lock lk(g_log_mutex);
            if (g_log_udp_addr.sin_family != AF_INET || g_early_log_done || g_early_log_len == 0 || g_log_udp_fd >= 0) return;
            const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) return;
            g_log_udp_fd = fd;
            SendLogLines(g_early_log, g_early_log_len);
            g_log_udp_fd = -1;
            ::close(fd);
            g_early_log_len = 0;
        }

        // Returns this console's ZeroTier address: the identity on the card,
        // or a new one, made once the console has finished starting up and
        // has the memory to spare. Until then it waits here (also for an
        // identity.secret made on a PC to appear).
        u64 EnsureIdentity() {
            if (const u64 addr = LoadIdentity()) return addr;
            // The overlay says so meanwhile, instead of a bare "Starting".
            status::SetMakingIdentity(true);
            ON_SCOPE_EXIT { status::SetMakingIdentity(false); };
            const u64 entered = armTicksToNs(armGetSystemTick());
            bool healthy = false;
            Log("identity: none yet; one is made %llu s after power-on, when %llu MB of system memory is free",
                static_cast<unsigned long long>(IdentityAfterBootNs / 1'000'000'000ull), static_cast<unsigned long long>(IdentityMinFree / 1_MB));
            u64 next_try = 0;
            bool told = false;
            for (u32 round = 0;; round++) {
                const u64 now = armTicksToNs(armGetSystemTick());  // counts from power-on
                WatchBootMemory(now);
                // The wait can be long and nothing else has started: show it
                // in the log as it happens.
                SendEarlyLogBriefly();
                if (!healthy && now - entered > HealthyAfterNs) {
                    // Waiting isn't crashing: reboots during a long wait
                    // mustn't trip the crash guard.
                    healthy = true;
                    static_cast<void>(fs::DeleteFile(StartingPath));
                }
                if (round % 5 == 4) {
                    if (const u64 addr = LoadIdentity()) return addr;
                }
                u64 free_bytes = 0, total = 0;
                if (now >= IdentityAfterBootNs && now >= next_try && memory::SystemPool(&free_bytes, &total)) {
                    if (free_bytes >= IdentityMinFree) {
                        Log("identity: making one (system memory free: %lu KB)", static_cast<unsigned long>(free_bytes / 1024));
                        if (const u64 addr = CreateIdentity()) return addr;
                        next_try = now + 30'000'000'000ull;
                    } else if (!told && now >= IdentityAfterBootNs + 60'000'000'000ull) {
                        told = true;
                        Log("identity: only %lu KB of system memory is free; waiting for %lu KB", static_cast<unsigned long>(free_bytes / 1024),
                            static_cast<unsigned long>(IdentityMinFree / 1024));
                        status::IdentityShortOfMemory();
                    }
                }
                os::SleepThread(TimeSpan::FromSeconds(1));
            }
        }

        // ---- the network -------------------------------------------------------

        constinit bool g_hosts_on = true;
        constinit bool g_aliases_on = true;
        constinit std::atomic<bool> g_hosts_due = false;  // Collect() ran; Write() pending

        // GameStream hosts reached by address (hosts::LearnGameStreamHost),
        // as "a.b.c.d a.b.c.d\n" lines: each named as itself, so the hosts
        // file resolves the address to its stand-in. Engine thread only;
        // forgotten when the network changes (and at reboot: Moonlight asks
        // the PC for its state again first).
        constexpr size_t MaxLearnedHosts = 8;
        constinit char g_learned_lines[MaxLearnedHosts * 34] = {};
        constinit size_t g_learned_count = 0;
        // The network's configuration as last reported, to rebuild the
        // hosts block with when a host is learned.
        constinit ZtnxNetConfig g_last_net = {};

        void CollectHosts() {
            if (!g_hosts_on || g_last_net.status != ZTNX_NET_OK || !g_last_net.n_addrs) return;
            g_hosts_due = hosts::Collect(g_host_lines, g_learned_lines, g_last_net, g_aliases_on) || g_hosts_due.load();
        }

        void ForgetLearnedHosts() {
            g_learned_lines[0] = 0;
            g_learned_count = 0;
            g_last_net = {};
        }

        // Whether "a.b.c.d " starts a line of `lines`.
        bool HasLineFor(const char *lines, const char *ip) {
            const size_t n = std::strlen(ip);
            for (const char *p = lines; *p;) {
                if (std::strncmp(p, ip, n) == 0 && p[n] == ' ') return true;
                const char *eol = std::strchr(p, '\n');
                if (!eol) break;
                p = eol + 1;
            }
            return false;
        }

        void TakeLearnedHosts() {
            u32 ips[8];
            const size_t n = hosts::TakeLearned(ips, util::size(ips));
            if (n == 0 || !g_hosts_on || !g_aliases_on) return;
            bool added = false;
            for (size_t i = 0; i < n; i++) {
                char ip[16];
                util::SNPrintf(ip, sizeof ip, "%u.%u.%u.%u", ips[i] >> 24, (ips[i] >> 16) & 0xff, (ips[i] >> 8) & 0xff, ips[i] & 0xff);
                // Named in config.ini already, or learned already.
                if (HasLineFor(g_host_lines, ip) || HasLineFor(g_learned_lines, ip)) continue;
                if (g_learned_count == MaxLearnedHosts) {
                    Log("hosts: %s is a GameStream host, but %zu are named already", ip, MaxLearnedHosts);
                    continue;
                }
                const size_t used = std::strlen(g_learned_lines);
                util::SNPrintf(g_learned_lines + used, sizeof g_learned_lines - used, "%s %s\n", ip, ip);
                g_learned_count++;
                added = true;
                Log("hosts: %s is a GameStream host reached by its address; naming it after its stand-in", ip);
            }
            if (added) CollectHosts();
        }

        const char *NetStatusName(u32 status) {
            switch (status) {
                case ZTNX_NET_REQUESTING: return "asking the controller";
                case ZTNX_NET_OK: return "up";
                case ZTNX_NET_ACCESS_DENIED: return "not authorized";
                case ZTNX_NET_NOT_FOUND: return "not found";
                case ZTNX_NET_PORT_ERROR: return "port error";
                case ZTNX_NET_CLIENT_TOO_OLD: return "client too old";
                case ZTNX_NET_AUTH_REQUIRED: return "single sign-on required";
                case ZTNX_NET_DOWN: return "down";
                default: return "?";
            }
        }

        // ZeroTier reported the network's status or configuration (engine
        // thread, no lock held; the stack and the socket layer's routes have
        // been updated already).
        void OnNetwork(const ZtnxNetConfig &c) {
            char ip[24] = "none";
            if (c.n_addrs) util::SNPrintf(ip, sizeof ip, "%u.%u.%u.%u/%u", c.addrs[0].ip[0], c.addrs[0].ip[1], c.addrs[0].ip[2], c.addrs[0].ip[3], c.addrs[0].prefix);
            Log("network %016llx: %s; address %s, mtu %u, %u route(s)%s%s", static_cast<unsigned long long>(c.nwid), NetStatusName(c.status), ip, c.mtu, c.n_routes,
                c.truncated ? "; its configuration didn't all fit" : "", c.status == ZTNX_NET_OK && !c.broadcast ? "; broadcast is off (ARP won't work)" : "");
            status::SetNetwork(c);
            g_last_net = c;
            CollectHosts();
            StartUdpLog();
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
        // The overlay's service, from the start: on a first boot it can say
        // why nothing has happened yet (the identity waits ~2 minutes) and
        // take the network to join while the rest waits. Stop answers "busy"
        // until the engine runs.
        ctl::Start(StopForOverlay);

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
        // TLS (the update check) needs a plausible date, and ZeroTier's own
        // clock starts from it.
        bool corrected = false;
        const u64 console_time = ConsoleUnixTime();
        u64 unix_time = ztnx_sane_unix_time(console_time, ZTNX_UPDATE_HOST, &corrected);
        if (corrected) Log("console clock implausible (%llu); using %s's time (%llu)",
                           static_cast<unsigned long long>(console_time), ZTNX_UPDATE_HOST, static_cast<unsigned long long>(unix_time));
        if (unix_time == 0) unix_time = console_time;

        ztnx_set_unix_time(unix_time);
        g_hosts_on = std::strcmp(cfg.hosts, "off") != 0;
        g_aliases_on = std::strcmp(cfg.aliases, "off") != 0;
        if (std::strcmp(cfg.tunnel_lan, "on") == 0) {
            Log("tunnel_lan=on: LAN addresses go through the network too (testing)");
            ::ztnx::VSock::SetTunnelLan(true);
        }
        // Without a network to join there is nothing to do but say so: the
        // rest still starts, so the overlay can show it.
        char *nwid_end = nullptr;
        u64 nwid = std::strtoull(cfg.network, &nwid_end, 16);
        if (std::strlen(cfg.network) != 16 || *nwid_end || nwid == 0) {
            nwid = 0;
            Log("config: no network= (16 hex digits) in %s; nothing to join until one is entered in the overlay", ConfigPath);
            status::SetConfigError("Open ZeroTier in Ultrahand (L + D-pad Down + R3), select Network and enter your network's ID.");
        }
        // The overlay shows the network meanwhile (the first boot's wait).
        status::SetNode(0, nwid);
        // First boot: this waits until the console has settled, then makes
        // the identity (see EnsureIdentity).
        const u64 node = EnsureIdentity();
        StartUdpLog();
        FlushEarlyLog();

        ZtnxDriver *driver = ztnx_driver_new();
        ZtnxStack *stack = ztnx_stack_new(ztnx_driver_now_ns());
        if (!driver || !stack) {
            Log("out of memory; not starting");
            return;
        }
        if (cfg.overlay_budget_kb[0]) {
            // Bounded by the sysmodule's heap (heap_size.h), most of which
            // ZeroTier's core needs.
            const unsigned long kb = std::clamp(std::strtoul(cfg.overlay_budget_kb, nullptr, 10), 128ul, 384ul);
            ztnx_net_set_budget(stack, kb * 1024);
            Log("overlay buffer budget: %lu KB", kb);
        }
        // ZeroTier's usual port is 9993, but so is that of a computer running
        // ZeroTier on the same LAN, and some routers then hand the answers
        // of a server both talk to to only one of the two (seen: the console
        // heard nothing at all). So ours comes from the node's address, as
        // ZeroTier's own second port does: stable, and nobody else's.
        const u16 want_port = cfg.port[0] ? static_cast<u16>(std::strtoul(cfg.port, nullptr, 10)) : static_cast<u16>(20000 + node % 45500);
        if (ztnx_driver_open_udp(driver, want_port) != 0 && ztnx_driver_open_udp(driver, 0) != 0) {
            Log("no UDP socket (errno %d); not starting", errno);
            return;
        }
        if (ztnx_driver_udp_port(driver) == want_port) {
            Log("udp: port %u", want_port);
        } else {
            Log("udp: port %u (%u was taken)", ztnx_driver_udp_port(driver), want_port);
        }

        std::string error;
        ::ztnx::ZtLinkConfig link_cfg;
        link_cfg.state_get = StateGet;
        link_cfg.state_put = StatePut;
        link_cfg.on_config = OnNetwork;
        link_cfg.on_event = [](u32 event) {
            Log("zerotier: %s", event == ZTNX_EVENT_ONLINE ? "online (a root server answered)"
                                : event == ZTNX_EVENT_OFFLINE ? "offline (no root server answers; is UDP blocked?)"
                                                              : "another device is using this identity; delete identity.secret to make a new one");
            status::OnEngineEvent(event);
        };
        link_cfg.wall_ms = static_cast<int64_t>(unix_time) * 1000;
        int zt_rc = 0;
        auto link = ::ztnx::ZtLink::Create(driver, std::move(link_cfg), &error, &zt_rc);
        if (!link) {
            Log("zerotier: %s (code %d); not starting", error.c_str(), zt_rc);
            return;
        }
        auto rt = ::ztnx::Runtime::Create(stack, driver, link->Ops(), &error);
        if (!rt) {
            Log("runtime: %s (errno %d)", error.c_str(), errno);
            return;
        }
        link->Attach(rt.get());
        link->SetLocalIp(ip);
        status::SetNode(link->Address(), nwid);
        Log("zerotier: node %010llx%s", static_cast<unsigned long long>(link->Address()), link->Address() != node ? " (not the identity just read?)" : "");
        // Entered in the overlay while the identity was being made.
        if (const u64 asked = status::TakeNetworkRequest(); asked && asked != nwid) {
            Log("network %016llx: entered in the overlay", static_cast<unsigned long long>(asked));
            nwid = asked;
            status::ChangeNetwork(nwid);
        }
        if (nwid) {
            Log("joining network %016llx", static_cast<unsigned long long>(nwid));
            link->Join(nwid);
        }
        Log("engine started");

        // Homebrew sockets to addresses on the network go through the stack.
        // The log socket goes down and up with the engine's own (sleep).
        // Coming back counts as having been offline (see the loop below).
        g_update_check = std::strcmp(cfg.update_check, "off") != 0;
        rt->SetSuspendHooks([] {
            {
                std::scoped_lock lk(g_log_mutex);
                EmitDeferredLog();  // the loop won't run to write them
            }
            CloseUdpLogSocket();
            SuspendUpdateCheck();
        }, [&ip] {
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

        // Engine loop on this thread; housekeeping between rounds, without
        // the runtime lock (homebrew's sockets don't wait for it). Re-detect
        // our address after Wi-Fi changes (roaming, sleep/wake): every 5 s,
        // or 250 ms while offline (a wake usually finds Wi-Fi still down).
        // Back online (or on a new address) ZeroTier is told at once.
        u64 last_check = armTicksToNs(armGetSystemTick());
        u64 last_heap_log = 0, last_peers = 0;
        const u64 started = armTicksToNs(armGetSystemTick());
        bool healthy = false;
        size_t heap_all_peak = 0;
        int batched = 0;  // the driver's batched receive state, as last logged
        // The driver's socket reopens and the loop's wake pairs remade, as
        // last logged, and when: while offline it can be every second, so a
        // line every 10 s at most.
        unsigned int reopens = 0;
        uint64_t wake_remakes = 0;
        u64 last_reopen_log = 0, last_wake_log = 0;
        {
            std::scoped_lock lk(g_log_mutex);
            g_log_defer_thread = os::GetCurrentThread();
        }
        // The engine loop runs on core 2 when it can (see bsd_mitm::EngineCores).
        os::SetThreadCoreMask(os::GetCurrentThread(), bsd_mitm::PreferredCore, bsd_mitm::EngineCores);
        rt->Run([&] {
            const u64 now = armTicksToNs(armGetSystemTick());
            WatchBootMemory(now);
            // A round takes at most about a second (the poll timeout).
            if (g_last_round_ns && now - g_last_round_ns > 3'000'000'000ull) {
                Log("engine loop stalled: %llu ms since the last round", static_cast<unsigned long long>((now - g_last_round_ns) / 1'000'000));
            }
            g_last_round_ns = now;
            status::EngineRan(now);
            // The peer list costs ZeroTier an allocation of about 2 KB a
            // peer each time: not every round.
            if (now - last_peers > 5'000'000'000ull) {
                last_peers = now;
                static ZtnxPeerInfo peers[ZTNX_CTL_MAX_PEERS];  // static, not stack
                const size_t total = link->Peers(peers, ZTNX_CTL_MAX_PEERS);
                static ZtnxNeighbor neighbors[32];
                const size_t n_neighbors = rt->Read([&](ZtnxStack *st) { return ztnx_l2_neighbors(st, neighbors, util::size(neighbors)); });
                status::SetPeers(peers, std::min<size_t>(total, ZTNX_CTL_MAX_PEERS), total, neighbors, n_neighbors, g_host_lines);
            }
            // Whole-heap use (ZeroTier, Rust, C++, C), sampled every tick;
            // the Rust peak below is exact.
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
                ZtnxStackStats net = {};
                const size_t buffers = rt->Read([&](ZtnxStack *st) {
                    ztnx_stack_stats(st, &net);
                    return ztnx_net_buffer_usage(st);
                });
                Log("heap: rust %zu KB (peak %zu), all %zu KB (peak %zu, largest free %zu) of %zu KB; overlay buffers %zu KB", cur / 1024,
                    peak / 1024, (MallocBufferSize - std::min(heap_free, MallocBufferSize)) / 1024, heap_all_peak / 1024,
                    init::GetAllocator()->GetAllocatableSize() / 1024, MallocBufferSize / 1024, buffers / 1024);
                char classes[200];
                ztnx_heap_classes(classes, sizeof classes);
                Log("heap by size (KB/allocs): %s", classes);
                const auto zt = link->GetStats();
                const auto loop = rt->GetStats();
                unsigned int ttl_failures = 0;
                const int send_errno = ztnx_driver_send_error(driver, &ttl_failures);
                Log("zerotier: datagrams in %llu out %llu (failed %llu: %u hop limits, last errno %d), frames in %llu out %llu; arp broadcasts %u (held back %u), "
                    "unresolved %u, unroutable %u, app queue full %u; loop rounds %llu, wake-ups %llu",
                    static_cast<unsigned long long>(zt.wire_in), static_cast<unsigned long long>(zt.wire_out),
                    static_cast<unsigned long long>(zt.wire_out_failed), ttl_failures, send_errno, static_cast<unsigned long long>(zt.frames_in),
                    static_cast<unsigned long long>(zt.frames_out), net.arp_broadcasts, net.arp_limited, net.unresolved, net.unroutable,
                    net.udp_dropped, static_cast<unsigned long long>(loop.rounds), static_cast<unsigned long long>(loop.wakes));
                {
                    // Where the engine thread's time went since the last of
                    // these lines: near 100% busy means it, not the network,
                    // limits what gets through.
                    static auto prev_loop = loop;
                    static u64 prev_loop_at = 0;
                    if (prev_loop_at != 0 && now > prev_loop_at) {
                        const u64 wall = now - prev_loop_at;
                        const auto pct = [wall](u64 to, u64 from) { return static_cast<unsigned>(std::min<u64>((to - from) * 100 / wall, 100)); };
                        Log("loop: busy %u%% (reading the socket %u%%, zerotier %u%%, waiting for the lock %u%%)", 100 - pct(loop.poll_ns, prev_loop.poll_ns),
                            pct(loop.recv_ns, prev_loop.recv_ns), pct(loop.engine_ns, prev_loop.engine_ns), pct(loop.lock_ns, prev_loop.lock_ns));
                    }
                    prev_loop = loop;
                    prev_loop_at = now;
                }
                stack_watch::Log();
            }
            int bsd_errno = 0;
            if (const int b = ztnx_driver_batched_receive(driver, &bsd_errno); b != batched) {
                batched = b;
                if (b > 0) {
                    Log("udp: batched receive");
                } else {
                    Log("udp: one datagram per call (batched receive errno %d)", bsd_errno);
                }
            }
            if (const unsigned int r = ztnx_driver_reopens(driver); r != reopens && now - last_reopen_log >= 10'000'000'000ull) {
                reopens = r;
                last_reopen_log = now;
                Log("udp: socket reopened (%u so far; last failed send errno %d)", r, ztnx_driver_send_error(driver, nullptr));
            }
            if (const uint64_t w = rt->GetStats().wake_remakes; w != wake_remakes && now - last_wake_log >= 10'000'000'000ull) {
                wake_remakes = w;
                last_wake_log = now;
                Log("loop: wake sockets remade (%llu so far)", static_cast<unsigned long long>(w));
            }
            FlushTunnelLog(*rt);
            Timed("update check", [&] { StepUpdateCheck(now); });
            if (now - last_check > (ip ? 5'000'000'000ull : 250'000'000ull)) {
                last_check = now;
                u32 cur = 0;
                Timed("network check", [&] { cur = NetworkUp() ? CurrentIp() : 0; });
                status::SetOffline(cur == 0);
                if (cur && g_log_udp_lost.exchange(false)) StartUdpLog();
                if (cur != ip) {
                    Log("local address changed: %s", cur ? inet_ntoa(in_addr{cur}) : "(offline)");
                    ip = cur;
                    SetLocalNet(cur);
                    link->SetLocalIp(cur);
                    if (cur) link->NetworkChanged(cur);
                }
            }
            // A network entered in the overlay (which has saved it in
            // config.ini): joining it leaves the current one.
            if (const u64 asked = status::TakeNetworkRequest(); asked && asked != nwid) {
                Log("network %016llx: entered in the overlay; joining it%s", static_cast<unsigned long long>(asked), nwid ? " instead" : "");
                nwid = asked;
                ForgetLearnedHosts();
                status::ChangeNetwork(nwid);
                link->Join(nwid);
            }
            TakeLearnedHosts();
            if (g_hosts_due.exchange(false)) Timed("hosts file update", [] { hosts::Write(); });
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
