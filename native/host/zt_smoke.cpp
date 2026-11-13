// zt-smoke: the smallest program that puts the pieces together on a host.
// One thread, no runtime: ZeroTier's core through its glue (native/zt), the
// Rust stack (ztnx.h), one UDP socket and a state directory. It joins a
// network, answers pings, and can run a UDP echo against a peer and a TCP
// echo server for one, so the path from a socket call to ZeroTier's wire
// format and back is tested before any threading is involved.
//
//   zt-smoke --state DIR --join NWID [--port N] [--gen-identity]
//            [--udp-echo IP:PORT] [--udp-echo-size BYTES]
//            [--tcp-echo-server PORT] [--for SECONDS] [--report SECONDS]
//
// --report prints "heap: N KB in use, M peers" that often (glibc only: what
// malloc has handed out), to see what a network's size costs.
//
// Exit status 0 if everything asked for happened within --for seconds
// (default 60): the network came up with an address, and the UDP echo, if
// asked for, was answered.
#include <arpa/inet.h>
#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#ifdef __GLIBC__
#include <malloc.h>
#endif

#include "ztnx.h"
#include "ztnx_engine.h"

namespace {

// Room for the largest frame or datagram ZeroTier handles (its MTU limit is
// 10000).
constexpr size_t ZTNX_SMOKE_FRAME_MAX = 10240;

struct Options {
    std::string state = "/state";
    uint64_t nwid = 0;
    uint16_t port = 9993;
    bool gen_identity = false;
    ZtnxAddr udp_echo = {};
    size_t udp_echo_size = 14;
    uint16_t tcp_echo_server = 0;
    int seconds = 60;
    int report = 0;  // seconds between "heap:" lines; 0 for none
};

struct App {
    Options opt;
    int udp = -1;
    ZtnxEngine *engine = nullptr;
    ZtnxStack *stack = nullptr;
    int64_t epoch_base_ms = 0;
    ZtnxNetConfig config = {};
    bool up = false;
};

uint64_t mono_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// ZeroTier's clock: wall time at start plus monotonic time since.
int64_t zt_now(const App &app) { return app.epoch_base_ms + (int64_t)(mono_ns() / 1000000ull); }

void say(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
}

std::string state_path(const App &app, int type, uint64_t id) {
    char name[64];
    switch (type) {
        case ZTNX_STATE_IDENTITY_PUBLIC: return app.opt.state + "/identity.public";
        case ZTNX_STATE_IDENTITY_SECRET: return app.opt.state + "/identity.secret";
        case ZTNX_STATE_PLANET: return app.opt.state + "/planet";
        case ZTNX_STATE_NETWORK_CONFIG:
            snprintf(name, sizeof name, "/networks.d/%016" PRIx64 ".conf", id);
            return app.opt.state + name;
        default: return "";
    }
}

int state_get(void *ctx, int type, uint64_t id, void *buf, unsigned int cap) {
    const std::string path = state_path(*static_cast<App *>(ctx), type, id);
    FILE *f = path.empty() ? nullptr : fopen(path.c_str(), "rb");
    if (!f) return -1;
    const size_t n = fread(buf, 1, cap, f);
    const bool whole = feof(f) || fgetc(f) == EOF;
    fclose(f);
    return whole ? (int)n : -1;
}

void state_put(void *ctx, int type, uint64_t id, const void *data, int len) {
    const App &app = *static_cast<App *>(ctx);
    const std::string path = state_path(app, type, id);
    if (path.empty()) return;
    if (len < 0) {
        unlink(path.c_str());
        return;
    }
    mkdir((app.opt.state + "/networks.d").c_str(), 0700);
    if (FILE *f = fopen(path.c_str(), "wb")) {
        fwrite(data, 1, (size_t)len, f);
        fclose(f);
        if (type == ZTNX_STATE_IDENTITY_SECRET) chmod(path.c_str(), 0600);
    }
}

int wire_send(void *ctx, uint32_t ip_be, uint16_t port, const void *data, unsigned int len, unsigned int ttl) {
    const App &app = *static_cast<App *>(ctx);
    // A packet with a TTL is a hole-punching probe meant to die on the way.
    // They are skipped here; see the notes on whether they are worth it.
    if (ttl) return -1;
    struct sockaddr_in to = {};
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = ip_be;
    to.sin_port = htons(port);
    return sendto(app.udp, data, len, 0, (struct sockaddr *)&to, sizeof to) == (ssize_t)len ? 0 : -1;
}

bool ensure_identity(App &app) {
    char secret[ZTNX_IDENTITY_TEXT_MAX] = {};
    const int n = state_get(&app, ZTNX_STATE_IDENTITY_SECRET, 0, secret, sizeof secret - 1);
    if (n > 0 && ztnx_engine_identity_address(secret)) return true;
    if (!app.opt.gen_identity) {
        say("no identity in %s (use --gen-identity)", app.opt.state.c_str());
        return false;
    }
    void *scratch = malloc(ZTNX_IDENTITY_SCRATCH);
    char pub[ZTNX_IDENTITY_TEXT_MAX] = {};
    const uint64_t t0 = mono_ns();
    const uint64_t addr = scratch ? ztnx_engine_generate_identity(scratch, secret, pub) : 0;
    free(scratch);
    if (!addr) {
        say("identity generation failed");
        return false;
    }
    mkdir(app.opt.state.c_str(), 0700);
    state_put(&app, ZTNX_STATE_IDENTITY_SECRET, 0, secret, (int)strlen(secret));
    state_put(&app, ZTNX_STATE_IDENTITY_PUBLIC, 0, pub, (int)strlen(pub));
    say("identity: generated %010" PRIx64 " in %" PRIu64 " ms", addr, (mono_ns() - t0) / 1000000ull);
    return true;
}

const char *status_name(uint32_t s) {
    switch (s) {
        case ZTNX_NET_REQUESTING: return "REQUESTING_CONFIGURATION";
        case ZTNX_NET_OK: return "OK";
        case ZTNX_NET_ACCESS_DENIED: return "ACCESS_DENIED";
        case ZTNX_NET_NOT_FOUND: return "NOT_FOUND";
        case ZTNX_NET_PORT_ERROR: return "PORT_ERROR";
        case ZTNX_NET_CLIENT_TOO_OLD: return "CLIENT_TOO_OLD";
        case ZTNX_NET_AUTH_REQUIRED: return "AUTHENTICATION_REQUIRED";
        case ZTNX_NET_DOWN: return "DOWN";
        default: return "?";
    }
}

// Applies what ZeroTier reported since the last call. Never from inside a
// ZeroTier callback: the multicast subscriptions call back into the node.
void apply_config(App &app) {
    ZtnxNetConfig c;
    while (ztnx_engine_take_config(app.engine, &c)) {
        app.config = c;
        char ip[32] = "-";
        if (c.n_addrs) snprintf(ip, sizeof ip, "%u.%u.%u.%u/%u", c.addrs[0].ip[0], c.addrs[0].ip[1], c.addrs[0].ip[2], c.addrs[0].ip[3], c.addrs[0].prefix);
        say("network: %s ip=%s mtu=%u routes=%u rev=%u truncated=0x%x name=%s", status_name(c.status), ip, c.mtu, c.n_routes, c.revision, c.truncated, c.name);
        app.up = c.status == ZTNX_NET_OK && c.n_addrs > 0;
        if (app.up) {
            ztnx_l2_configure(app.stack, c.nwid, c.mac, c.mtu, c.addrs, c.n_addrs, c.routes, c.n_routes);
            uint32_t ips[ZTNX_MAX_ADDRS];
            for (unsigned i = 0; i < c.n_addrs; i++) memcpy(&ips[i], c.addrs[i].ip, 4);
            ztnx_engine_multicast_sync(app.engine, ips, c.n_addrs);
        } else {
            ztnx_l2_down(app.stack);
        }
    }
    while (const uint32_t ev = ztnx_engine_take_event(app.engine)) {
        say("event: %s", ev == ZTNX_EVENT_ONLINE ? "ONLINE" : ev == ZTNX_EVENT_OFFLINE ? "OFFLINE" : "IDENTITY_COLLISION");
    }
}

// Moves frames both ways between ZeroTier and the stack, until neither has
// more for the other.
void exchange(App &app) {
    static uint8_t out[16][ZTNX_SMOKE_FRAME_MAX];
    for (int round = 0; round < 64; round++) {
        const ZtnxFrame *frames;
        const size_t n = ztnx_engine_frames(app.engine, &frames);
        ztnx_stack_begin(app.stack, mono_ns());
        for (size_t i = 0; i < n; i++) {
            ztnx_l2_frame_in(app.stack, frames[i].src_mac, frames[i].dst_mac, frames[i].ethertype, frames[i].data, frames[i].len);
        }
        ztnx_engine_frames_done(app.engine);
        ztnx_stack_end(app.stack);
        size_t len[16];
        uint64_t mac[16];
        uint32_t type[16];
        int taken = 0;
        while (taken < 16 && (len[taken] = ztnx_l2_next_out(app.stack, out[taken], sizeof out[taken], &mac[taken], &type[taken])) > 0) taken++;
        for (int i = 0; i < taken; i++) ztnx_engine_frame_out(app.engine, mac[i], type[i], out[i], (unsigned)len[i], zt_now(app));
        apply_config(app);
        const ZtnxFrame *more;
        if (!taken && !ztnx_stack_out_pending(app.stack) && !ztnx_engine_frames(app.engine, &more)) return;
    }
}

bool parse_addr(const char *s, ZtnxAddr *out) {
    char host[64];
    unsigned port = 0;
    if (sscanf(s, "%63[^:]:%u", host, &port) != 2 || port == 0 || port > 65535) return false;
    struct in_addr a;
    if (inet_pton(AF_INET, host, &a) != 1) return false;
    *out = ZtnxAddr{};
    out->family = 4;
    memcpy(out->ip, &a, 4);
    out->port = (uint16_t)port;
    return true;
}

}  // namespace

int main(int argc, char **argv) {
    App app;
    setvbuf(stdout, nullptr, _IOLBF, 0);
    for (int i = 1; i < argc; i++) {
        const std::string a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : nullptr;
        if (a == "--gen-identity") {
            app.opt.gen_identity = true;
        } else if (!v) {
            fprintf(stderr, "missing value for %s\n", a.c_str());
            return 2;
        } else if (a == "--state") {
            app.opt.state = v, i++;
        } else if (a == "--join") {
            app.opt.nwid = strtoull(v, nullptr, 16), i++;
        } else if (a == "--port") {
            app.opt.port = (uint16_t)atoi(v), i++;
        } else if (a == "--udp-echo") {
            if (!parse_addr(v, &app.opt.udp_echo)) return 2;
            i++;
        } else if (a == "--udp-echo-size") {
            app.opt.udp_echo_size = (size_t)atoi(v), i++;
        } else if (a == "--tcp-echo-server") {
            app.opt.tcp_echo_server = (uint16_t)atoi(v), i++;
        } else if (a == "--for") {
            app.opt.seconds = atoi(v), i++;
        } else if (a == "--report") {
            app.opt.report = atoi(v), i++;
        } else {
            fprintf(stderr, "unknown option %s\n", a.c_str());
            return 2;
        }
    }
    if (!app.opt.nwid) {
        fprintf(stderr, "usage: zt-smoke --state DIR --join NWID [--port N] [--gen-identity] [--udp-echo IP:PORT] [--udp-echo-size BYTES] [--tcp-echo-server PORT] [--for SECONDS]\n");
        return 2;
    }
    if (const uint32_t failed = ztnx_engine_selftest()) {
        say("C++ exceptions selftest FAILED (0x%x)", failed);
        return 1;
    }

    uint8_t seed[32];
    if (FILE *f = fopen("/dev/urandom", "rb")) {
        if (fread(seed, 1, sizeof seed, f) != sizeof seed) return 1;
        fclose(f);
    }
    ztnx_seed_rng(seed);
    app.epoch_base_ms = (int64_t)time(nullptr) * 1000 - (int64_t)(mono_ns() / 1000000ull);

    if (!ensure_identity(app)) return 1;

    app.udp = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in bind_to = {};
    bind_to.sin_family = AF_INET;
    bind_to.sin_port = htons(app.opt.port);
    if (app.udp < 0 || bind(app.udp, (struct sockaddr *)&bind_to, sizeof bind_to) != 0) {
        say("cannot bind UDP port %u: %s", app.opt.port, strerror(errno));
        return 1;
    }
    fcntl(app.udp, F_SETFL, fcntl(app.udp, F_GETFL) | O_NONBLOCK);

    app.stack = ztnx_stack_new(mono_ns());
    const ZtnxEngineHooks hooks = {&app, wire_send, state_get, state_put};
    int rc = 0;
    app.engine = ztnx_engine_new(&hooks, zt_now(app), &rc);
    if (!app.engine) {
        say("ztnx_engine_new failed (%d)", rc);
        return 1;
    }
    say("node: %010" PRIx64, ztnx_engine_address(app.engine));
    ztnx_engine_network_up(app.engine, 0, app.opt.port, zt_now(app));
    if ((rc = ztnx_engine_join(app.engine, app.opt.nwid)) != 0) {
        say("join failed (%d)", rc);
        return 1;
    }
    apply_config(app);

    int32_t echo_sock = 0, listener = 0;
    std::vector<int32_t> clients;
    bool echo_ok = app.opt.udp_echo.family == 0;
    uint64_t echo_sent_at = 0, last_echo_try = 0;
    bool announced_up = false;
    std::vector<uint8_t> echo_payload(app.opt.udp_echo_size);
    for (size_t i = 0; i < echo_payload.size(); i++) echo_payload[i] = (uint8_t)(i * 31 + 7);
    const uint64_t t0 = mono_ns();
    const uint64_t give_up = t0 + (uint64_t)app.opt.seconds * 1000000000ull;

    uint64_t next_report = t0;
    while (mono_ns() < give_up) {
        const int64_t now_ms = zt_now(app);
        if (now_ms >= ztnx_engine_deadline_ms(app.engine)) ztnx_engine_background(app.engine, now_ms);
        exchange(app);
        if (app.opt.report > 0 && mono_ns() >= next_report) {
            next_report += (uint64_t)app.opt.report * 1000000000ull;
            size_t in_use = 0;
#ifdef __GLIBC__
            const struct mallinfo2 m = mallinfo2();
            in_use = m.uordblks + m.hblkhd;
#endif
            // Read before counting peers: the count itself allocates.
            ZtnxPeerInfo one;
            const size_t n_peers = ztnx_engine_peers(app.engine, &one, 1, now_ms);
            say("heap: %zu KB in use, %zu peers", in_use / 1024, n_peers);
        }

        if (app.up && !announced_up) {
            announced_up = true;
            say("up: after %" PRIu64 " ms", (mono_ns() - t0) / 1000000ull);
        }
        if (app.up) {
            ztnx_stack_begin(app.stack, mono_ns());
            if (!echo_ok && !echo_sock) echo_sock = ztnx_net_udp_bind(app.stack, 0);
            if (app.opt.tcp_echo_server && !listener) {
                listener = ztnx_net_tcp_listen(app.stack, app.opt.tcp_echo_server, 4);
                say("tcp echo server: port %u (%d)", app.opt.tcp_echo_server, listener);
            }
            if (!echo_ok && echo_sock > 0 && mono_ns() - last_echo_try >= 500000000ull) {
                last_echo_try = echo_sent_at = mono_ns();
                ztnx_net_udp_sendto(app.stack, echo_sock, echo_payload.data(), echo_payload.size(), &app.opt.udp_echo);
            }
            static uint8_t buf[16384];  // --udp-echo-size can be a jumbo network's datagram
            ZtnxAddr from;
            const int32_t got = (!echo_ok && echo_sock > 0) ? ztnx_net_udp_recvfrom(app.stack, echo_sock, buf, sizeof buf, &from) : 0;
            if (got > 0 && ((size_t)got != echo_payload.size() || memcmp(buf, echo_payload.data(), (size_t)got) != 0)) {
                say("udp echo: a reply of %d bytes that is not what was sent", got);
            } else if (got > 0) {
                echo_ok = true;
                say("udp echo: ok, %d bytes (%" PRIu64 " ms after sending, %" PRIu64 " ms after start)", got, (mono_ns() - echo_sent_at) / 1000000ull, (mono_ns() - t0) / 1000000ull);
            }
            if (listener > 0) {
                ZtnxAddr peer;
                const int32_t c = ztnx_net_tcp_accept(app.stack, listener, &peer);
                if (c > 0) {
                    clients.push_back(c);
                    say("tcp echo server: connection from %u.%u.%u.%u", peer.ip[0], peer.ip[1], peer.ip[2], peer.ip[3]);
                }
            }
            for (size_t i = 0; i < clients.size();) {
                const int32_t n = ztnx_net_recv(app.stack, clients[i], buf, sizeof buf);
                if (n > 0) {
                    int32_t off = 0;
                    while (off < n) {
                        const int32_t w = ztnx_net_send(app.stack, clients[i], buf + off, (size_t)(n - off));
                        if (w <= 0) break;
                        off += w;
                    }
                } else if (n == 0 || (n != ZTNX_EAGAIN && n < 0)) {
                    ztnx_net_close(app.stack, clients[i]);
                    clients.erase(clients.begin() + (long)i);
                    continue;
                }
                i++;
            }
            ztnx_stack_end(app.stack);
            exchange(app);
        }
        // With nothing else asked for, the echo is the last thing to wait for.
        if (app.up && echo_ok && !app.opt.tcp_echo_server && app.opt.udp_echo.family) break;

        // Sleep until a datagram arrives or the next timer, 20 ms at most
        // while sockets are being served.
        int64_t wait_ms = ztnx_engine_deadline_ms(app.engine) - zt_now(app);
        const uint64_t stack_at = ztnx_stack_next_deadline(app.stack);
        if (stack_at != UINT64_MAX) {
            const int64_t until = (int64_t)((stack_at > mono_ns() ? stack_at - mono_ns() : 0) / 1000000ull);
            if (until < wait_ms) wait_ms = until;
        }
        if (wait_ms > 20) wait_ms = 20;
        if (wait_ms < 0) wait_ms = 0;
        struct pollfd pfd = {app.udp, POLLIN, 0};
        poll(&pfd, 1, (int)wait_ms);
        for (int i = 0; i < 64; i++) {
            uint8_t pkt[ZTNX_SMOKE_FRAME_MAX];
            struct sockaddr_in from;
            socklen_t fromlen = sizeof from;
            const ssize_t n = recvfrom(app.udp, pkt, sizeof pkt, 0, (struct sockaddr *)&from, &fromlen);
            if (n <= 0) break;
            ztnx_engine_wire_in(app.engine, from.sin_addr.s_addr, ntohs(from.sin_port), pkt, (unsigned)n, zt_now(app));
            if (ztnx_engine_frames_high(app.engine)) exchange(app);
        }
    }

    ZtnxStackStats st;
    ztnx_stack_stats(app.stack, &st);
    say("stats: arp broadcasts %u, limited %u, unresolved %u, unroutable %u", st.arp_broadcasts, st.arp_limited, st.unresolved, st.unroutable);
    ZtnxPeerInfo peers[32];
    const size_t n = ztnx_engine_peers(app.engine, peers, 32, zt_now(app));
    for (size_t i = 0; i < n && i < 32; i++) {
        say("peer: %010" PRIx64 " %s %s %u.%u.%u.%u:%u latency %d ms v%u.%u.%u", peers[i].address,
            peers[i].role == ZTNX_PEER_PLANET ? "PLANET" : peers[i].role == ZTNX_PEER_MOON ? "MOON" : "LEAF", peers[i].direct ? "DIRECT" : "RELAY",
            peers[i].path_ip[0], peers[i].path_ip[1], peers[i].path_ip[2], peers[i].path_ip[3], peers[i].path_port, peers[i].latency_ms,
            peers[i].version[0], peers[i].version[1], peers[i].version[2]);
    }
    const bool ok = app.up && echo_ok;
    say("result: %s", ok ? "ok" : !app.up ? "network never came up" : "no echo reply");
    ztnx_engine_free(app.engine);
    ztnx_stack_free(app.stack);
    close(app.udp);
    return ok ? 0 : 1;
}
