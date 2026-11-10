// Tests for the runtime's non-blocking pause, RequestSuspended (make runtime-test).
#include <cassert>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <thread>

#include "runtime.hpp"

extern "C" void ztnx_platform_random(uint8_t *buf, size_t len);

using ztnx::Runtime;

static bool WaitSuspended(Runtime &rt, bool want) {
    for (int i = 0; i < 30; i++) {
        if (rt.IsSuspended() == want) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

int main() {
    uint8_t seed[32];
    ztnx_platform_random(seed, 32);
    ztnx_seed_rng(seed);
    // A peer nobody answers at: the engine just keeps trying to handshake.
    static const char kConf[] =
        "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.7.0.2/32\n"
        "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.7.0.1/32\n"
        "Endpoint = 127.0.0.1:9\nPersistentKeepalive = 1\n";
    ZtnxEngine *engine = ztnx_engine_new(ztnx_driver_now_ns(), static_cast<uint64_t>(time(nullptr)));
    ZtnxConfig cfg{kConf, sizeof kConf - 1};
    char err[128];
    assert(ztnx_engine_reload(engine, &cfg, ztnx_driver_now_ns(), err, sizeof err));
    ZtnxDriver *driver = ztnx_driver_new(engine, nullptr, nullptr);
    assert(ztnx_driver_open_udp(driver, 0) == 0);
    std::string error;
    auto rt = Runtime::Adopt(engine, driver, &error);
    assert(rt);
    std::thread loop([&] { rt->Run([](ZtnxDriver *) {}); });

    rt->RequestSuspended(Runtime::kPaused, true);
    assert(WaitSuspended(*rt, true));
    rt->RequestSuspended(Runtime::kPaused, false);
    assert(WaitSuspended(*rt, false));

    // The latest request wins, however quickly they follow each other.
    rt->RequestSuspended(Runtime::kPaused, true);
    rt->RequestSuspended(Runtime::kPaused, false);
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    assert(!rt->IsSuspended());
    rt->RequestSuspended(Runtime::kPaused, false);
    rt->RequestSuspended(Runtime::kPaused, true);
    assert(WaitSuspended(*rt, true));

    // Reasons stack: resuming the pause during a sleep stays suspended
    // until the wake.
    rt->RequestSuspend(Runtime::kSleep);
    rt->RequestSuspended(Runtime::kPaused, false);
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    assert(rt->IsSuspended());
    rt->Resume(Runtime::kSleep);
    assert(WaitSuspended(*rt, false));
    assert(ztnx_driver_udp_port(driver) != 0);  // reopened on resume

    rt->Stop();
    loop.join();
    rt.reset();
    ztnx_driver_free(driver);
    ztnx_engine_free(engine);
    std::puts("runtime tests passed");
    return 0;
}
