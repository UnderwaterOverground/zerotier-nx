// What the host tools share: a ZeroTier node on a state directory, joined to
// one network, running on the runtime's engine thread.
#pragma once

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>

#include "runtime.hpp"
#include "zt_link.hpp"

namespace ztnx {

struct HostOptions {
    std::string state;          // identity.secret, networks.d/... live here
    uint64_t nwid = 0;
    uint16_t port = 0;          // 0: 9993, else any
    bool gen_identity = false;  // make an identity if the state has none
    bool log = false;           // print status changes to stderr
    // The sysmodule's engine thread has this much stack; the same here, so
    // code that needs more fails on the development machine too.
    size_t engine_stack = 0x1C000;
};

class HostSession {
public:
    static std::unique_ptr<HostSession> Start(const HostOptions &opt, std::string *error);
    ~HostSession();

    Runtime &runtime() { return *rt_; }
    ZtLink &link() { return *link_; }
    ZtnxStack *stack() { return stack_; }
    ZtnxDriver *driver() { return driver_; }

    // Waits until the network is up with an address. False on timeout.
    bool WaitUp(std::chrono::milliseconds timeout);
    // The network's status and configuration as last reported.
    ZtnxNetConfig Config();

private:
    HostSession() = default;
    HostOptions opt_;
    ZtnxStack *stack_ = nullptr;
    ZtnxDriver *driver_ = nullptr;
    std::unique_ptr<ZtLink> link_;
    std::unique_ptr<Runtime> rt_;
    std::mutex mu_;
    std::condition_variable cv_;
    ZtnxNetConfig config_{};
};

}  // namespace ztnx
