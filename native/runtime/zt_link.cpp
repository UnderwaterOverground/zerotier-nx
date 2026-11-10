#include "zt_link.hpp"

#include <cstring>
#include <ctime>
#include <new>

#include "vsock.hpp"

namespace ztnx {

// The runtime's view of a frame is the glue's.
static_assert(sizeof(EngineFrame) == sizeof(ZtnxFrame) && offsetof(EngineFrame, data) == offsetof(ZtnxFrame, data) &&
                  offsetof(EngineFrame, len) == offsetof(ZtnxFrame, len) && offsetof(EngineFrame, ethertype) == offsetof(ZtnxFrame, ethertype),
              "EngineFrame must match ZtnxFrame");

// ZeroTier's clock: wall time when we started plus monotonic time since. It
// has to look like wall time (the core compares it with timestamps that
// start at zero) and must never step backwards.
int64_t ZtLink::Now() const { return epoch_base_ms_ + static_cast<int64_t>(ztnx_driver_now_ns() / 1000000); }

std::unique_ptr<ZtLink> ZtLink::Create(ZtnxDriver *driver, ZtLinkConfig cfg, std::string *error, int *rc) {
    std::unique_ptr<ZtLink> link(new (std::nothrow) ZtLink());
    if (!link) {
        *error = "out of memory";
        return nullptr;
    }
    link->driver_ = driver;
    link->cfg_ = std::move(cfg);
    int64_t wall_ms = link->cfg_.wall_ms ? link->cfg_.wall_ms : static_cast<int64_t>(time(nullptr)) * 1000;
    // A clock that was never set would give ZeroTier times near zero.
    if (wall_ms < 1600000000000LL) wall_ms = 1600000000000LL;
    link->epoch_base_ms_ = wall_ms - static_cast<int64_t>(ztnx_driver_now_ns() / 1000000);

    ZtnxEngineHooks hooks{};
    hooks.ctx = link.get();
    hooks.wire_send = [](void *ctx, uint32_t ip_be, uint16_t port, const void *data, unsigned int len, unsigned int ttl) -> int {
        auto *self = static_cast<ZtLink *>(ctx);
        const int sent = ztnx_driver_send(self->driver_, ip_be, port, data, len, ttl);
        (sent == 0 ? self->wire_out_ : self->wire_out_failed_).fetch_add(1, std::memory_order_relaxed);
        return sent;
    };
    hooks.state_get = [](void *ctx, int type, uint64_t id, void *buf, unsigned int cap) -> int {
        auto *self = static_cast<ZtLink *>(ctx);
        return self->cfg_.state_get ? self->cfg_.state_get(self->cfg_.state_ctx, type, id, buf, cap) : -1;
    };
    hooks.state_put = [](void *ctx, int type, uint64_t id, const void *data, int len) {
        auto *self = static_cast<ZtLink *>(ctx);
        if (self->cfg_.state_put) self->cfg_.state_put(self->cfg_.state_ctx, type, id, data, len);
    };
    int code = 0;
    link->engine_ = ztnx_engine_new(&hooks, link->Now(), &code);
    if (rc) *rc = code;
    if (!link->engine_) {
        *error = code == ZTNX_ENGINE_OUT_OF_MEMORY ? "out of memory" : code == ZTNX_ENGINE_INTERNAL ? "no valid identity" : "ZeroTier failed to start";
        return nullptr;
    }
    link->address_ = ztnx_engine_address(link->engine_);
    return link;
}

ZtLink::~ZtLink() { ztnx_engine_free(engine_); }

size_t ZtLink::Peers(ZtnxPeerInfo *out, size_t max) { return ztnx_engine_peers(engine_, out, max, Now()); }

// The routes the socket layer sends through the network: our subnets and
// the managed routes, except a default route (the console's own traffic
// stays on its own connection).
void ZtLink::Apply(const ZtnxNetConfig &c) {
    const bool up = c.status == ZTNX_NET_OK && c.n_addrs > 0;
    if (!up) {
        VSock::SetRoutes(nullptr, 0);
        rt_->With([](ZtnxStack *s) { ztnx_l2_down(s); });
        ztnx_engine_multicast_sync(engine_, nullptr, 0);
        return;
    }
    rt_->With([&](ZtnxStack *s) { ztnx_l2_configure(s, c.nwid, c.mac, c.mtu, c.addrs, c.n_addrs, c.routes, c.n_routes); });
    ZtnxPrefix routes[VSock::MaxRoutes];
    size_t n = 0;
    auto add = [&](const uint8_t ip[4], uint8_t len) {
        if (n >= VSock::MaxRoutes || len == 0) return;
        ZtnxPrefix &p = routes[n++];
        memset(&p, 0, sizeof p);
        p.family = 4;
        p.len = len;
        memcpy(p.ip, ip, 4);
    };
    for (unsigned i = 0; i < c.n_addrs; i++) add(c.addrs[i].ip, c.addrs[i].prefix);
    for (unsigned i = 0; i < c.n_routes; i++) add(c.routes[i].target, c.routes[i].prefix);
    VSock::SetRoutes(routes, n);
    // ARP requests for our addresses only reach us through these groups.
    uint32_t ips[ZTNX_MAX_ADDRS];
    for (unsigned i = 0; i < c.n_addrs; i++) memcpy(&ips[i], c.addrs[i].ip, 4);
    ztnx_engine_multicast_sync(engine_, ips, c.n_addrs);
}

void ZtLink::After() {
    ZtnxNetConfig c;
    while (ztnx_engine_take_config(engine_, &c)) {
        Apply(c);
        if (cfg_.on_config) cfg_.on_config(c);
    }
    while (const uint32_t event = ztnx_engine_take_event(engine_)) {
        if (cfg_.on_event) cfg_.on_event(event);
    }
}

EngineOps ZtLink::Ops() {
    EngineOps ops;
    ops.ctx = this;
    ops.wire_in = [](void *ctx, uint32_t ip_be, uint16_t port, const uint8_t *data, size_t len) {
        auto *self = static_cast<ZtLink *>(ctx);
        self->wire_in_.fetch_add(1, std::memory_order_relaxed);
        ztnx_engine_wire_in(self->engine_, ip_be, port, data, static_cast<unsigned int>(len), self->Now());
    };
    ops.frames = [](void *ctx, const EngineFrame **out) -> size_t {
        auto *self = static_cast<ZtLink *>(ctx);
        const ZtnxFrame *frames = nullptr;
        const size_t n = ztnx_engine_frames(self->engine_, &frames);
        *out = reinterpret_cast<const EngineFrame *>(frames);
        self->frames_in_.fetch_add(n, std::memory_order_relaxed);
        return n;
    };
    ops.frames_done = [](void *ctx) { ztnx_engine_frames_done(static_cast<ZtLink *>(ctx)->engine_); };
    ops.frames_high = [](void *ctx) -> bool { return ztnx_engine_frames_high(static_cast<ZtLink *>(ctx)->engine_); };
    ops.frame_out = [](void *ctx, uint64_t dst_mac, uint32_t ethertype, const uint8_t *data, size_t len) {
        auto *self = static_cast<ZtLink *>(ctx);
        self->frames_out_.fetch_add(1, std::memory_order_relaxed);
        ztnx_engine_frame_out(self->engine_, dst_mac, ethertype, data, static_cast<unsigned int>(len), self->Now());
    };
    ops.background = [](void *ctx) -> int {
        auto *self = static_cast<ZtLink *>(ctx);
        int64_t now = self->Now();
        if (now >= ztnx_engine_deadline_ms(self->engine_)) {
            ztnx_engine_background(self->engine_, now);
            now = self->Now();
        }
        const int64_t wait = ztnx_engine_deadline_ms(self->engine_) - now;
        return wait < 0 ? 0 : wait > 1000 ? 1000 : static_cast<int>(wait);
    };
    ops.after = [](void *ctx) { static_cast<ZtLink *>(ctx)->After(); };
    ops.command = [](void *ctx, uint32_t command, uint64_t arg) {
        auto *self = static_cast<ZtLink *>(ctx);
        switch (command) {
            case kJoin:
                ztnx_engine_join(self->engine_, arg);
                break;
            case kLeave:
                ztnx_engine_leave(self->engine_);
                break;
            case kNetworkUp:
                ztnx_engine_network_up(self->engine_, self->local_ip_be_.load(), ztnx_driver_udp_port(self->driver_), self->Now());
                break;
        }
    };
    ops.network_up = [](void *ctx) {
        auto *self = static_cast<ZtLink *>(ctx);
        ztnx_engine_network_up(self->engine_, self->local_ip_be_.load(), ztnx_driver_udp_port(self->driver_), self->Now());
    };
    return ops;
}

}  // namespace ztnx
