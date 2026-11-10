// ztnx-c: the sysmodule's moving parts on a host, without the socket MITM:
// ZeroTier's core on the engine thread, the stack behind the runtime's lock,
// and this (main) thread using sockets through the runtime, as a bsd:u
// thread does on the console.
//
//   ztnx-c --state DIR --join NWID [--port N] [--gen-identity] [--log]
//          [--echo-test IP] [--sleep-test] [--for SECONDS]
//   ztnx-c --update-check VERSION   (GitHub release check, as at boot)
//
// --echo-test: TCP and UDP echo against port 7 of a device on the network.
// --sleep-test: after the echo, what the console does around sleep (close
// every socket within 2.5 s, idle, reopen), then the echo again.
// Exit status 0 if the network came up and every test asked for passed.
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <unistd.h>

#include "session.hpp"
#include "ztnx_app.h"
#include "ztnx_update.h"

using namespace std::chrono_literals;

extern "C" void ztnx_platform_random(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, len, f) != len) abort();
    fclose(f);
}

namespace {

const char *Arg(int argc, char **argv, const char *name) {
    for (int i = 1; i + 1 < argc; i++)
        if (!strcmp(argv[i], name)) return argv[i + 1];
    return nullptr;
}

bool Has(int argc, char **argv, const char *name) {
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], name)) return true;
    return false;
}

int UpdateCheck(const char *current) {
    uint8_t seed[32];
    ztnx_platform_random(seed, sizeof seed);
    ztnx_seed_rng(seed);
    ztnx_set_unix_time(static_cast<uint64_t>(time(nullptr)));
    ZtnxUpdate *u = ztnx_update_start(ZTNX_UPDATE_REPO, current, ztnx_driver_now_ns(), 30000);
    if (!u) return 1;
    int r;
    while ((r = ztnx_update_step(u, ztnx_driver_now_ns())) == ZTNX_UPDATE_PENDING) usleep(50000);
    if (r == ZTNX_UPDATE_FAILED) printf("update check failed: %s\n", ztnx_update_error(u));
    else printf("latest %s: %s\n", ztnx_update_latest(u), r == ZTNX_UPDATE_NEWER ? "newer" : "not newer");
    ztnx_update_free(u);
    return r == ZTNX_UPDATE_FAILED;
}

// The echo against `target`, driven the way an application thread would.
bool Echo(ztnx::Runtime &rt, const ZtnxAddr &target, const char *label) {
    ZtnxEcho echo;
    ztnx_echo_init(&echo, &target);
    const uint64_t t0 = ztnx_driver_now_ns();
    int result = 0;
    while (!(result = rt.With([&](ZtnxStack *s) { return ztnx_echo_step(&echo, s, ztnx_driver_now_ns()); }))) {
        const auto slice = ztnx::Runtime::Clock::now() + 20ms;
        rt.WaitFor([](ZtnxStack *) { return false; }, &slice);
    }
    printf("%s: %s (%" PRIu64 " ms)\n", label, result > 0 ? "ok" : "FAILED", (ztnx_driver_now_ns() - t0) / 1000000);
    return result > 0;
}

}  // namespace

int main(int argc, char **argv) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (const char *version = Arg(argc, argv, "--update-check")) return UpdateCheck(version);
    const char *state = Arg(argc, argv, "--state");
    const char *join = Arg(argc, argv, "--join");
    if (!state || !join) {
        fprintf(stderr, "usage: %s --state DIR --join NWID [--port N] [--gen-identity] [--log] [--echo-test IP] [--sleep-test] [--for SECONDS]\n       %s --update-check VERSION\n", argv[0], argv[0]);
        return 2;
    }
    ztnx::HostOptions opt;
    opt.state = state;
    opt.nwid = strtoull(join, nullptr, 16);
    if (const char *port = Arg(argc, argv, "--port")) opt.port = static_cast<uint16_t>(atoi(port));
    opt.gen_identity = Has(argc, argv, "--gen-identity");
    opt.log = Has(argc, argv, "--log");
    const int seconds = Arg(argc, argv, "--for") ? atoi(Arg(argc, argv, "--for")) : 60;

    std::string error;
    auto session = ztnx::HostSession::Start(opt, &error);
    if (!session) {
        fprintf(stderr, "ztnx-c: %s\n", error.c_str());
        return 1;
    }
    printf("node: %010" PRIx64 "\n", session->link().Address());
    if (!session->WaitUp(std::chrono::seconds(seconds))) {
        const ZtnxNetConfig c = session->Config();
        printf("network: not up after %d s (status %u)\n", seconds, c.status);
        return 1;
    }
    const ZtnxNetConfig c = session->Config();
    printf("network: OK ip=%u.%u.%u.%u/%u\n", c.addrs[0].ip[0], c.addrs[0].ip[1], c.addrs[0].ip[2], c.addrs[0].ip[3], c.addrs[0].prefix);

    bool ok = true;
    ZtnxAddr target;
    const char *echo_ip = Arg(argc, argv, "--echo-test");
    if (echo_ip) {
        if (ztnx_parse_ipv4(echo_ip, 7, &target) != 0) {
            fprintf(stderr, "bad address %s\n", echo_ip);
            return 2;
        }
        ok = Echo(session->runtime(), target, "echo") && ok;
    }
    if (Has(argc, argv, "--sleep-test")) {
        // What the console does around sleep: every socket closed before the
        // first acknowledgement (2.5 s at most), nothing until the wake.
        const uint64_t t0 = ztnx_driver_now_ns();
        const bool suspended = session->runtime().Suspend(ztnx::Runtime::kSleep, 2500ms);
        printf("suspend: %s (%" PRIu64 " ms), socket %s\n", suspended ? "ok" : "TIMED OUT", (ztnx_driver_now_ns() - t0) / 1000000,
               ztnx_driver_udp_port(session->driver()) == 0 ? "closed" : "STILL OPEN");
        ok = ok && suspended && ztnx_driver_udp_port(session->driver()) == 0;
        std::this_thread::sleep_for(5s);
        session->runtime().Resume(ztnx::Runtime::kSleep);
        if (echo_ip) ok = Echo(session->runtime(), target, "echo after resume") && ok;
    }
    if (!echo_ip && !Has(argc, argv, "--sleep-test")) {
        // Nothing to test: stay up (answering pings) for the time given.
        std::this_thread::sleep_for(std::chrono::seconds(seconds));
    }
    const auto link = session->link().GetStats();
    const auto rt = session->runtime().GetStats();
    printf("stats: datagrams in %" PRIu64 " out %" PRIu64 " (failed %" PRIu64 "), frames in %" PRIu64 " out %" PRIu64 ", loop rounds %" PRIu64 ", wake-ups %" PRIu64 "\n",
           link.wire_in, link.wire_out, link.wire_out_failed, link.frames_in, link.frames_out, rt.rounds, rt.wakes);
    printf("result: %s\n", ok ? "ok" : "FAILED");
    return ok ? 0 : 1;
}
