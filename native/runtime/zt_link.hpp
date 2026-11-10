// ZeroTier as the runtime's engine: owns the node (native/zt's glue), feeds
// it from the driver's socket, and applies what it reports (the network's
// configuration, events) to the stack, the socket layer's routes and the
// embedder.
//
// Everything here runs on the engine thread except the constructor, Join,
// Leave, NetworkChanged and the getters, which any thread may call.
#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>

#include "runtime.hpp"
#include "ztnx_engine.h"

namespace ztnx {

struct ZtLinkConfig {
    // State objects (see ZtnxEngineHooks): the identity must be there
    // already. Called on the engine thread, without the runtime lock.
    void *state_ctx = nullptr;
    int (*state_get)(void *ctx, int type, uint64_t id, void *buf, unsigned int cap) = nullptr;
    void (*state_put)(void *ctx, int type, uint64_t id, const void *data, int len) = nullptr;
    // Called on the engine thread, without the lock, when the network's
    // configuration or status changed (after it was applied) and for each
    // event (ZTNX_EVENT_*).
    std::function<void(const ZtnxNetConfig &)> on_config;
    std::function<void(uint32_t)> on_event;
    // Wall-clock time now, in milliseconds since the Unix epoch, where the C
    // library's clock can't be trusted (the console); 0 to use time().
    int64_t wall_ms = 0;
};

class ZtLink {
public:
    // Creates the node. On failure returns null with *error set; *rc gets
    // ZeroTier's result code (ZTNX_ENGINE_*).
    static std::unique_ptr<ZtLink> Create(ZtnxDriver *driver, ZtLinkConfig cfg, std::string *error, int *rc = nullptr);
    ~ZtLink();

    // The table to give Runtime::Create, then the runtime it made.
    EngineOps Ops();
    void Attach(Runtime *rt) { rt_ = rt; }

    // Our ZeroTier address (the node ID).
    uint64_t Address() const { return address_; }

    // Asks the engine thread to join `nwid` (leaving any other) / to leave.
    bool Join(uint64_t nwid) { return rt_->Post(kJoin, nwid); }
    bool Leave() { return rt_->Post(kLeave, 0); }
    // The console's own address changed (network byte order; 0 if none):
    // the engine tells ZeroTier and re-runs its timers at once.
    bool NetworkChanged(uint32_t local_ip_be) {
        local_ip_be_.store(local_ip_be);
        return rt_->Post(kNetworkUp, 0);
    }
    void SetLocalIp(uint32_t local_ip_be) { local_ip_be_.store(local_ip_be); }

    // Engine thread only (e.g. from the runtime's on_tick): the peers.
    size_t Peers(ZtnxPeerInfo *out, size_t max);

    // Counters for the log.
    struct Stats {
        uint64_t wire_in, wire_out, wire_out_failed, frames_in, frames_out;
    };
    Stats GetStats() const { return {wire_in_.load(), wire_out_.load(), wire_out_failed_.load(), frames_in_.load(), frames_out_.load()}; }

private:
    enum : uint32_t { kJoin = 1, kLeave = 2, kNetworkUp = 3 };
    ZtLink() = default;
    int64_t Now() const;
    void After();
    void Apply(const ZtnxNetConfig &c);

    ZtnxEngine *engine_ = nullptr;
    ZtnxDriver *driver_ = nullptr;
    Runtime *rt_ = nullptr;
    ZtLinkConfig cfg_;
    uint64_t address_ = 0;
    int64_t epoch_base_ms_ = 0;
    std::atomic<uint32_t> local_ip_be_{0};
    std::atomic<uint64_t> wire_in_{0}, wire_out_{0}, wire_out_failed_{0}, frames_in_{0}, frames_out_{0};
};

}  // namespace ztnx
