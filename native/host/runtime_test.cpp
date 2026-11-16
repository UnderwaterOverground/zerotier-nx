// Tests for the runtime (make runtime-test): who runs engine code and with
// what held, wake-ups, timers, pause and suspend, the command mailbox.
//
// No ZeroTier here. The engine is a fake: a second stack, the "peer", that
// the fake hands our frames to and takes replies from, with echo servers on
// it. So the stack under test talks real ARP, UDP and TCP to something,
// through the same loop that carries frames to and from ZeroTier.
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include "runtime.hpp"

using ztnx::EngineFrame;
using ztnx::EngineOps;
using ztnx::Runtime;
using namespace std::chrono_literals;

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
            std::abort();                                                        \
        }                                                                        \
    } while (0)

namespace {

constexpr uint64_t kNwid = 0x8056c2e21c000001ull;
constexpr uint64_t kOurMac = 0x32000000000aull;
constexpr uint64_t kPeerMac = 0x32000000000bull;
constexpr uint64_t kBroadcast = 0xffffffffffffull;
const uint8_t kOurIp[4] = {10, 20, 30, 2};
const uint8_t kPeerIp[4] = {10, 20, 30, 7};
const uint8_t kDeadIp[4] = {10, 20, 30, 99};  // on-link, nobody there

ZtnxAddr Addr(const uint8_t ip[4], uint16_t port) {
    ZtnxAddr a{};
    a.family = 4;
    memcpy(a.ip, ip, 4);
    a.port = port;
    return a;
}

void Configure(ZtnxStack *s, uint64_t mac, const uint8_t ip[4]) {
    ZtnxV4Net net{};
    memcpy(net.ip, ip, 4);
    net.prefix = 24;
    ztnx_stack_begin(s, ztnx_driver_now_ns());
    CHECK(ztnx_l2_configure(s, kNwid, mac, 2800, &net, 1, nullptr, 0));
    ztnx_stack_end(s);
}

// The engine: a peer stack with a UDP and a TCP echo server on port 7.
struct FakeEngine {
    ZtnxStack *peer = ztnx_stack_new(ztnx_driver_now_ns());
    int32_t udp = 0, listener = 0;
    std::vector<int32_t> clients;

    // Frames for the stack under test, in one buffer (the pointers handed
    // out stay valid until frames_done).
    std::vector<uint8_t> arena = std::vector<uint8_t>(256 * 1024);
    size_t arena_used = 0;
    std::vector<EngineFrame> inbox;

    // What the tests look at (written on the engine thread).
    std::atomic<uint64_t> frames_out{0}, arp_broadcasts{0}, ipv4_out{0};
    std::atomic<int64_t> last_arp_broadcast_ms{0};
    std::atomic<uint32_t> network_ups{0};
    std::mutex mu;
    std::vector<uint32_t> commands;
    // While set, frame_out blocks: the engine thread is "busy".
    std::mutex hold_mu;
    std::condition_variable hold_cv;
    bool hold = false;
    std::atomic<bool> holding{false};
    // A violation of the rules, seen on the engine thread.
    std::atomic<int> violations{0};

    FakeEngine() {
        Configure(peer, kPeerMac, kPeerIp);
        ztnx_stack_begin(peer, ztnx_driver_now_ns());
        udp = ztnx_net_udp_bind(peer, 7);
        listener = ztnx_net_tcp_listen(peer, 7, 4);
        ztnx_stack_end(peer);
        CHECK(udp > 0 && listener > 0);
    }
    ~FakeEngine() { ztnx_stack_free(peer); }

    // Every entry: on the engine thread, without the runtime lock.
    void Enter() {
        if (!Runtime::OnEngineThread() || Runtime::HoldsLock()) violations++;
    }

    // Runs the peer: its servers, then its stack, then moves what it wants
    // to send into the inbox.
    void PumpPeer() {
        ztnx_stack_begin(peer, ztnx_driver_now_ns());
        uint8_t buf[4096];
        ZtnxAddr from;
        for (int i = 0; i < 64; i++) {
            const int32_t n = ztnx_net_udp_recvfrom(peer, udp, buf, sizeof buf, &from);
            if (n <= 0) break;
            ztnx_net_udp_sendto(peer, udp, buf, static_cast<size_t>(n), &from);
        }
        for (;;) {
            const int32_t c = ztnx_net_tcp_accept(peer, listener, nullptr);
            if (c <= 0) break;
            clients.push_back(c);
        }
        for (size_t i = 0; i < clients.size();) {
            bool closed = false;
            for (;;) {
                const int32_t n = ztnx_net_recv(peer, clients[i], buf, sizeof buf);
                if (n > 0) {
                    // The echo may not fit the send buffer in one go; these
                    // tests send less than a window at a time.
                    CHECK(ztnx_net_send(peer, clients[i], buf, static_cast<size_t>(n)) == n);
                    continue;
                }
                closed = n == 0 || n != ZTNX_EAGAIN;
                break;
            }
            if (closed) {
                ztnx_net_close(peer, clients[i]);
                clients.erase(clients.begin() + static_cast<long>(i));
            } else {
                i++;
            }
        }
        ztnx_stack_end(peer);
        for (;;) {
            if (arena.size() - arena_used < 10240) break;
            uint64_t mac = 0;
            uint32_t type = 0;
            const size_t len = ztnx_l2_next_out(peer, arena.data() + arena_used, arena.size() - arena_used, &mac, &type);
            if (len == 0) break;
            if (mac == kOurMac || mac == kBroadcast) {
                inbox.push_back({kPeerMac, mac, type, static_cast<uint32_t>(len), arena.data() + arena_used});
                arena_used += len;
            }
        }
    }

    static FakeEngine *Self(void *ctx) { return static_cast<FakeEngine *>(ctx); }

    EngineOps Ops() {
        EngineOps ops;
        ops.ctx = this;
        ops.wire_in = [](void *ctx, uint32_t, uint16_t, const uint8_t *, size_t) { Self(ctx)->Enter(); };
        ops.frames = [](void *ctx, const EngineFrame **out) -> size_t {
            auto *e = Self(ctx);
            *out = e->inbox.data();
            return e->inbox.size();
        };
        ops.frames_done = [](void *ctx) {
            auto *e = Self(ctx);
            e->inbox.clear();
            e->arena_used = 0;
        };
        ops.frames_high = [](void *ctx) -> bool { return Self(ctx)->arena_used > Self(ctx)->arena.size() / 2; };
        ops.frame_out = [](void *ctx, uint64_t dst_mac, uint32_t ethertype, const uint8_t *data, size_t len) {
            auto *e = Self(ctx);
            e->Enter();
            {
                std::unique_lock<std::mutex> lock(e->hold_mu);
                e->holding = e->hold;
                e->hold_cv.wait(lock, [&] { return !e->hold; });
                e->holding = false;
            }
            e->frames_out++;
            if (ethertype == ZTNX_ETHERTYPE_ARP && dst_mac == kBroadcast) {
                e->arp_broadcasts++;
                e->last_arp_broadcast_ms = static_cast<int64_t>(ztnx_driver_now_ns() / 1000000);
            }
            if (ethertype == ZTNX_ETHERTYPE_IPV4) e->ipv4_out++;
            if (dst_mac == kPeerMac || dst_mac == kBroadcast) {
                ztnx_stack_begin(e->peer, ztnx_driver_now_ns());
                ztnx_l2_frame_in(e->peer, kOurMac, dst_mac, ethertype, data, len);
                ztnx_stack_end(e->peer);
                e->PumpPeer();
            }
        };
        ops.background = [](void *ctx) -> int {
            auto *e = Self(ctx);
            e->Enter();
            e->PumpPeer();
            if (!e->inbox.empty()) return 0;
            const uint64_t at = ztnx_stack_next_deadline(e->peer);
            const uint64_t now = ztnx_driver_now_ns();
            if (at == UINT64_MAX) return 1000;
            return at <= now ? 0 : static_cast<int>((at - now) / 1000000) + 1;
        };
        ops.after = [](void *ctx) { Self(ctx)->Enter(); };
        ops.command = [](void *ctx, uint32_t command, uint64_t) {
            auto *e = Self(ctx);
            e->Enter();
            std::lock_guard<std::mutex> lock(e->mu);
            e->commands.push_back(command);
        };
        ops.network_up = [](void *ctx) {
            Self(ctx)->Enter();
            Self(ctx)->network_ups++;
        };
        return ops;
    }

    void Hold(bool on) {
        {
            std::lock_guard<std::mutex> lock(hold_mu);
            hold = on;
        }
        hold_cv.notify_all();
    }
};

bool WaitSuspended(Runtime &rt, bool want) {
    for (int i = 0; i < 30; i++) {
        if (rt.IsSuspended() == want) return true;
        std::this_thread::sleep_for(100ms);
    }
    return false;
}

template <class F>
bool Eventually(F &&f, std::chrono::milliseconds within = 3000ms) {
    const auto until = std::chrono::steady_clock::now() + within;
    while (std::chrono::steady_clock::now() < until) {
        if (f()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return f();
}

// A UDP datagram to the peer's echo and back. Returns the round trip in
// milliseconds, or -1 if no reply came within `within`.
int UdpEcho(Runtime &rt, int32_t sock, const std::vector<uint8_t> &payload, std::chrono::milliseconds within = 3000ms) {
    const ZtnxAddr peer = Addr(kPeerIp, 7);
    const auto t0 = std::chrono::steady_clock::now();
    CHECK(rt.With([&](ZtnxStack *s) { return ztnx_net_udp_sendto(s, sock, payload.data(), payload.size(), &peer); }) == static_cast<int32_t>(payload.size()));
    const auto deadline = t0 + within;
    if (!rt.WaitFor([&](ZtnxStack *s) { return (ztnx_net_readiness(s, sock) & ZTNX_READABLE) != 0; }, &deadline)) return -1;
    std::vector<uint8_t> buf(payload.size() + 16);
    const int32_t n = rt.Read([&](ZtnxStack *s) { return ztnx_net_udp_recvfrom(s, sock, buf.data(), buf.size(), nullptr); });
    CHECK(n == static_cast<int32_t>(payload.size()) && memcmp(buf.data(), payload.data(), payload.size()) == 0);
    return static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count());
}

// The runtime's wake pair: the loopback socket another loopback socket is
// connected to. Returns its receiving end, or -1.
int FindWakeRx() {
    for (int fd = 3; fd < 256; fd++) {
        sockaddr_in peer{};
        socklen_t len = sizeof peer;
        if (getpeername(fd, reinterpret_cast<sockaddr *>(&peer), &len) != 0 || peer.sin_family != AF_INET ||
            peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
            continue;
        for (int rx = 3; rx < 256; rx++) {
            sockaddr_in local{};
            len = sizeof local;
            if (rx != fd && getsockname(rx, reinterpret_cast<sockaddr *>(&local), &len) == 0 && local.sin_family == AF_INET &&
                local.sin_addr.s_addr == peer.sin_addr.s_addr && local.sin_port == peer.sin_port)
                return rx;
        }
    }
    return -1;
}

}  // namespace

int main() {
    uint8_t seed[32] = {};
    if (FILE *f = std::fopen("/dev/urandom", "rb")) {
        CHECK(std::fread(seed, 1, sizeof seed, f) == sizeof seed);
        std::fclose(f);
    }
    ztnx_seed_rng(seed);

    // ---- A socket the socket service dropped is reopened --------------------
    // (Horizon drops sockets when the network goes away without a sleep, e.g.
    // Airplane Mode: sends fail with EPIPE and poll() returns at once.)
    {
        ZtnxDriver *d = ztnx_driver_new();
        CHECK(ztnx_driver_open_udp(d, 0) == 0);
        const uint16_t port = ztnx_driver_udp_port(d);
        const int sink = socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in sin = {};
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t slen = sizeof sin;
        CHECK(sink >= 0 && bind(sink, reinterpret_cast<sockaddr *>(&sin), sizeof sin) == 0 &&
              getsockname(sink, reinterpret_cast<sockaddr *>(&sin), &slen) == 0);
        const auto drop = [&] {
            pollfd fds[ZTNX_DRIVER_MAX_FDS] = {};
            CHECK(ztnx_driver_pollfds(d, fds, ZTNX_DRIVER_MAX_FDS) == 1);
            close(fds[0].fd);
        };
        const auto delivered = [&] {
            const char msg[] = "after reopen";
            CHECK(ztnx_driver_send(d, sin.sin_addr.s_addr, ntohs(sin.sin_port), msg, sizeof msg, 0) == 0);
            pollfd p = {sink, POLLIN, 0};
            char buf[64];
            return poll(&p, 1, 1000) == 1 && recv(sink, buf, sizeof buf, 0) == static_cast<ssize_t>(sizeof msg);
        };
        CHECK(!ztnx_driver_broken(d));
        // Found by a send.
        drop();
        CHECK(ztnx_driver_send(d, sin.sin_addr.s_addr, ntohs(sin.sin_port), "x", 1, 0) == -1);
        CHECK(ztnx_driver_broken(d));
        CHECK(ztnx_driver_reopen(d) == 0);
        CHECK(!ztnx_driver_broken(d) && ztnx_driver_udp_port(d) == port && ztnx_driver_reopens(d) == 1);
        CHECK(delivered());
        // Found by poll() (the closed descriptor is reported invalid).
        drop();
        pollfd fds[ZTNX_DRIVER_MAX_FDS + 1] = {};
        const int n = ztnx_driver_pollfds(d, fds, ZTNX_DRIVER_MAX_FDS);
        CHECK(ztnx_driver_poll(d, fds, n, 100) >= 1);
        CHECK(ztnx_driver_recv(d, fds) == 0);
        CHECK(ztnx_driver_broken(d));
        CHECK(ztnx_driver_reopen(d) == 0 && ztnx_driver_udp_port(d) == port && ztnx_driver_reopens(d) == 2);
        CHECK(delivered());
        // An explicit suspend is not a broken socket.
        ztnx_driver_suspend(d);
        CHECK(!ztnx_driver_broken(d));
        close(sink);
        ztnx_driver_free(d);
        std::puts("ok: a dropped socket is found (send, poll) and reopened on the same port");
    }

    ZtnxStack *stack = ztnx_stack_new(ztnx_driver_now_ns());
    Configure(stack, kOurMac, kOurIp);
    ZtnxDriver *driver = ztnx_driver_new();
    CHECK(ztnx_driver_open_udp(driver, 0) == 0);
    FakeEngine engine;
    std::string error;
    auto rt = Runtime::Create(stack, driver, engine.Ops(), &error);
    CHECK(rt);
    std::atomic<int> ticks{0};
    std::atomic<int> tick_violations{0};
    // The same stack size as the sysmodule's engine thread.
    CHECK(rt->StartThread(0x28000, [&] {
        ticks++;
        if (!Runtime::OnEngineThread() || Runtime::HoldsLock()) tick_violations++;
    }));
    CHECK(Eventually([&] { return engine.network_ups.load() == 1; }));

    // ---- UDP and TCP through the loop, from another thread ----------------
    const int32_t udp = rt->With([](ZtnxStack *s) { return ztnx_net_udp_bind(s, 0); });
    CHECK(udp > 0);
    std::vector<uint8_t> small(64, 0x5a), big(2000);
    for (size_t i = 0; i < big.size(); i++) big[i] = static_cast<uint8_t>(i * 7);
    CHECK(UdpEcho(*rt, udp, small) >= 0);
    CHECK(engine.arp_broadcasts.load() == 1);  // one request found the peer
    CHECK(UdpEcho(*rt, udp, big) >= 0);        // larger than TCP's packets, still one datagram here
    CHECK(engine.arp_broadcasts.load() == 1);

    {
        const ZtnxAddr peer = Addr(kPeerIp, 7);
        const int32_t tcp = rt->With([&](ZtnxStack *s) { return ztnx_net_tcp_connect(s, &peer); });
        CHECK(tcp > 0);
        auto deadline = std::chrono::steady_clock::now() + 5s;
        CHECK(rt->WaitFor([&](ZtnxStack *s) { return (ztnx_net_readiness(s, tcp) & ZTNX_WRITABLE) != 0; }, &deadline));
        std::vector<uint8_t> data(60000), got;
        for (size_t i = 0; i < data.size(); i++) data[i] = static_cast<uint8_t>(i % 253);
        size_t sent = 0;
        deadline = std::chrono::steady_clock::now() + 10s;
        while (got.size() < data.size() && std::chrono::steady_clock::now() < deadline) {
            if (sent < data.size()) {
                // A little at a time: the fake's echo server expects each
                // read to fit its send buffer.
                const size_t chunk = std::min<size_t>(2000, data.size() - sent);
                const int32_t n = rt->With([&](ZtnxStack *s) { return ztnx_net_send(s, tcp, data.data() + sent, chunk); });
                if (n > 0) sent += static_cast<size_t>(n);
            }
            uint8_t buf[8192];
            const int32_t n = rt->With([&](ZtnxStack *s) { return ztnx_net_recv(s, tcp, buf, sizeof buf); });
            if (n > 0) {
                got.insert(got.end(), buf, buf + n);
            } else {
                const auto slice = std::chrono::steady_clock::now() + 20ms;
                rt->WaitFor([&](ZtnxStack *s) { return (ztnx_net_readiness(s, tcp) & ZTNX_READABLE) != 0; }, &slice);
            }
        }
        CHECK(got == data);
        rt->With([&](ZtnxStack *s) { ztnx_net_close(s, tcp); });
    }
    std::puts("ok: UDP and TCP echo through the loop");

    // ---- wake-ups ---------------------------------------------------------
    // Reads never wake the engine.
    std::this_thread::sleep_for(100ms);
    uint64_t wakes = rt->GetStats().wakes;
    for (int i = 0; i < 100; i++) rt->Read([&](ZtnxStack *s) { return ztnx_net_readiness(s, udp); });
    CHECK(rt->GetStats().wakes == wakes);
    // A burst of sends while the engine is busy sending costs one wake-up at
    // most, not one each.
    engine.Hold(true);
    const ZtnxAddr peer = Addr(kPeerIp, 7);
    rt->With([&](ZtnxStack *s) { ztnx_net_udp_sendto(s, udp, small.data(), small.size(), &peer); });
    CHECK(Eventually([&] { return engine.holding.load(); }));
    wakes = rt->GetStats().wakes;
    for (int i = 0; i < 100; i++) rt->With([&](ZtnxStack *s) { ztnx_net_udp_sendto(s, udp, small.data(), small.size(), &peer); });
    const uint64_t burst_wakes = rt->GetStats().wakes - wakes;
    CHECK(burst_wakes <= 1);
    // The mailbox takes four commands; a fifth has to wait.
    for (uint32_t c = 1; c <= 4; c++) CHECK(rt->Post(c, 0));
    CHECK(!rt->Post(5, 0));
    engine.Hold(false);
    CHECK(Eventually([&] {
        std::lock_guard<std::mutex> lock(engine.mu);
        return engine.commands == std::vector<uint32_t>({1, 2, 3, 4});
    }));
    // Everything sent in the burst that fit the queue comes back.
    CHECK(Eventually([&] { return engine.ipv4_out.load() >= 60; }));
    std::this_thread::sleep_for(100ms);
    uint8_t drain[256];
    while (rt->Read([&](ZtnxStack *s) { return ztnx_net_udp_recvfrom(s, udp, drain, sizeof drain, nullptr); }) > 0) {
    }
    std::printf("ok: 100 reads woke the engine 0 times, 100 sends while it was busy %d time(s)\n", static_cast<int>(burst_wakes));

    // ---- the stack's timers wake an idle loop -----------------------------
    // A connection to an address nobody answers ARP for: the second request
    // goes out about a second after the first, with nothing else happening.
    {
        const uint64_t before = engine.arp_broadcasts.load();
        const ZtnxAddr dead = Addr(kDeadIp, 80);
        const int64_t t0 = static_cast<int64_t>(ztnx_driver_now_ns() / 1000000);
        const int32_t tcp = rt->With([&](ZtnxStack *s) { return ztnx_net_tcp_connect(s, &dead); });
        CHECK(tcp > 0);
        CHECK(Eventually([&] { return engine.arp_broadcasts.load() == before + 1; }, 500ms));
        CHECK(Eventually([&] { return engine.arp_broadcasts.load() == before + 2; }, 2000ms));
        const int64_t second = engine.last_arp_broadcast_ms.load() - t0;
        CHECK(second >= 900 && second <= 1500);
        rt->With([&](ZtnxStack *s) { ztnx_net_close(s, tcp); });
        std::printf("ok: the ARP retry went out %d ms after the first\n", static_cast<int>(second));
    }

    // ---- the system drops the wake pair (Airplane Mode on the console) -----
    // poll() then reports it invalid at once, every round: the loop must not
    // spin on it, and must make a new pair.
    {
        const int rx = FindWakeRx();
        CHECK(rx >= 0);
        std::this_thread::sleep_for(100ms);
        const auto before = rt->GetStats();
        close(rx);  // the loop's next poll() finds it invalid
        CHECK(Eventually([&] { return rt->GetStats().wake_remakes == before.wake_remakes + 1; }, 3000ms));
        const auto after = rt->GetStats();
        // An idle loop: a few rounds a second, not hundreds of thousands.
        CHECK(after.rounds - before.rounds < 200);
        CHECK(FindWakeRx() >= 0);
        // Wake-ups work again: an echo comes back long before the loop's
        // one-second poll would have ended.
        std::this_thread::sleep_for(200ms);
        const int ms = UdpEcho(*rt, udp, small);
        CHECK(ms >= 0 && ms < 300);
        std::printf("ok: a dropped wake pair is remade (%d rounds meanwhile), wake-ups work (echo in %d ms)\n",
                    static_cast<int>(after.rounds - before.rounds), ms);
    }

    // ---- pause: nothing is sent, and resuming doesn't flood ----------------
    CHECK(rt->Suspend(Runtime::kPaused, 2500ms));
    CHECK(rt->IsSuspended());
    {
        const uint64_t before = engine.frames_out.load();
        for (int i = 0; i < 500; i++) rt->With([&](ZtnxStack *s) { ztnx_net_udp_sendto(s, udp, small.data(), small.size(), &peer); });
        ZtnxStackStats st;
        rt->Read([&](ZtnxStack *s) { ztnx_stack_stats(s, &st); });
        CHECK(st.out_queued > 0 && st.out_queued <= 256);  // bounded, however much was sent
        std::this_thread::sleep_for(200ms);
        CHECK(engine.frames_out.load() == before);
        rt->Resume(Runtime::kPaused);
        CHECK(WaitSuspended(*rt, false));
        CHECK(Eventually([&] { return engine.network_ups.load() == 2; }));
        std::this_thread::sleep_for(200ms);
        // What queued while paused was dropped, not sent late.
        CHECK(engine.frames_out.load() == before);
        CHECK(UdpEcho(*rt, udp, small) >= 0);
        // Resuming re-checks the neighbour by asking it directly, not by a
        // broadcast.
        CHECK(engine.arp_broadcasts.load() <= 4);
    }
    std::puts("ok: paused sends nothing, resume drops what queued");

    // ---- suspend under traffic, and a reader that spins --------------------
    {
        std::atomic<bool> stop{false};
        std::thread sender([&] {
            while (!stop) rt->With([&](ZtnxStack *s) { ztnx_net_udp_sendto(s, udp, small.data(), small.size(), &peer); });
        });
        std::thread spinner([&] {
            while (!stop) rt->Read([&](ZtnxStack *s) { return ztnx_net_readiness(s, udp); });
        });
        std::this_thread::sleep_for(200ms);
        // The loop still gets its turns: frames keep flowing both ways.
        const uint64_t out0 = engine.ipv4_out.load();
        std::this_thread::sleep_for(500ms);
        CHECK(engine.ipv4_out.load() > out0 + 50);
        const auto t0 = std::chrono::steady_clock::now();
        CHECK(rt->Suspend(Runtime::kSleep, 2500ms));
        const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
        CHECK(ztnx_driver_udp_port(driver) == 0);  // the socket is closed
        stop = true;
        sender.join();
        spinner.join();
        rt->Resume(Runtime::kSleep);
        CHECK(WaitSuspended(*rt, false));
        CHECK(ztnx_driver_udp_port(driver) != 0);  // reopened
        std::printf("ok: suspended under traffic in %d ms\n", static_cast<int>(took));
    }

    // ---- RequestSuspended: the non-blocking pause --------------------------
    rt->RequestSuspended(Runtime::kPaused, true);
    CHECK(WaitSuspended(*rt, true));
    rt->RequestSuspended(Runtime::kPaused, false);
    CHECK(WaitSuspended(*rt, false));
    // The latest request wins, however quickly they follow each other.
    rt->RequestSuspended(Runtime::kPaused, true);
    rt->RequestSuspended(Runtime::kPaused, false);
    std::this_thread::sleep_for(1500ms);
    CHECK(!rt->IsSuspended());
    rt->RequestSuspended(Runtime::kPaused, false);
    rt->RequestSuspended(Runtime::kPaused, true);
    CHECK(WaitSuspended(*rt, true));
    // Reasons stack: resuming the pause during a sleep stays suspended until
    // the wake.
    rt->RequestSuspend(Runtime::kSleep);
    rt->RequestSuspended(Runtime::kPaused, false);
    std::this_thread::sleep_for(1500ms);
    CHECK(rt->IsSuspended());
    rt->Resume(Runtime::kSleep);
    CHECK(WaitSuspended(*rt, false));
    CHECK(ztnx_driver_udp_port(driver) != 0);
    std::puts("ok: RequestSuspended");

    // ---- Stop releases whoever is waiting ----------------------------------
    {
        std::atomic<int> result{-1};
        std::thread waiter([&] { result = rt->WaitFor([](ZtnxStack *) { return false; }, nullptr) ? 1 : 0; });
        std::this_thread::sleep_for(100ms);
        rt->Stop();
        waiter.join();
        CHECK(result == 0);
    }
    CHECK(ticks.load() > 10);
    CHECK(tick_violations.load() == 0);
    CHECK(engine.violations.load() == 0);
    rt.reset();
    ztnx_driver_free(driver);
    ztnx_stack_free(stack);
    std::puts("runtime tests passed");
    return 0;
}
