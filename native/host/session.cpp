#include "session.hpp"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

namespace ztnx {

namespace {

std::string StatePath(const std::string &dir, int type, uint64_t id) {
    char name[64];
    switch (type) {
        case ZTNX_STATE_IDENTITY_PUBLIC: return dir + "/identity.public";
        case ZTNX_STATE_IDENTITY_SECRET: return dir + "/identity.secret";
        case ZTNX_STATE_PLANET: return dir + "/planet";
        case ZTNX_STATE_NETWORK_CONFIG:
            snprintf(name, sizeof name, "/networks.d/%016" PRIx64 ".conf", id);
            return dir + name;
        default: return "";
    }
}

int StateGet(void *ctx, int type, uint64_t id, void *buf, unsigned int cap) {
    const std::string path = StatePath(*static_cast<const std::string *>(ctx), type, id);
    FILE *f = path.empty() ? nullptr : fopen(path.c_str(), "rb");
    if (!f) return -1;
    const size_t n = fread(buf, 1, cap, f);
    const bool whole = feof(f) || fgetc(f) == EOF;
    fclose(f);
    return whole ? static_cast<int>(n) : -1;
}

void StatePut(void *ctx, int type, uint64_t id, const void *data, int len) {
    const std::string &dir = *static_cast<const std::string *>(ctx);
    const std::string path = StatePath(dir, type, id);
    if (path.empty()) return;
    if (len < 0) {
        unlink(path.c_str());
        return;
    }
    mkdir(dir.c_str(), 0700);
    mkdir((dir + "/networks.d").c_str(), 0700);
    if (FILE *f = fopen(path.c_str(), "wb")) {
        fwrite(data, 1, static_cast<size_t>(len), f);
        fclose(f);
        if (type == ZTNX_STATE_IDENTITY_SECRET) chmod(path.c_str(), 0600);
    }
}

bool EnsureIdentity(const HostOptions &opt, std::string *error) {
    std::string dir = opt.state;
    char secret[ZTNX_IDENTITY_TEXT_MAX] = {};
    const int n = StateGet(&dir, ZTNX_STATE_IDENTITY_SECRET, 0, secret, sizeof secret - 1);
    if (n > 0 && ztnx_engine_identity_address(secret)) return true;
    if (!opt.gen_identity) {
        *error = "no identity in " + opt.state;
        return false;
    }
    void *scratch = malloc(ZTNX_IDENTITY_SCRATCH);
    char pub[ZTNX_IDENTITY_TEXT_MAX] = {};
    const uint64_t addr = scratch ? ztnx_engine_generate_identity(scratch, secret, pub) : 0;
    free(scratch);
    if (!addr) {
        *error = "identity generation failed";
        return false;
    }
    StatePut(&dir, ZTNX_STATE_IDENTITY_SECRET, 0, secret, static_cast<int>(strlen(secret)));
    StatePut(&dir, ZTNX_STATE_IDENTITY_PUBLIC, 0, pub, static_cast<int>(strlen(pub)));
    return true;
}

const char *StatusName(uint32_t s) {
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

}  // namespace

std::unique_ptr<HostSession> HostSession::Start(const HostOptions &opt, std::string *error) {
    if (const uint32_t failed = ztnx_engine_selftest()) {
        *error = "C++ exceptions selftest failed (" + std::to_string(failed) + ")";
        return nullptr;
    }
    uint8_t seed[32] = {};
    if (FILE *f = fopen("/dev/urandom", "rb")) {
        const size_t got = fread(seed, 1, sizeof seed, f);
        fclose(f);
        if (got != sizeof seed) {
            *error = "cannot read /dev/urandom";
            return nullptr;
        }
    }
    ztnx_seed_rng(seed);
    if (!EnsureIdentity(opt, error)) return nullptr;

    std::unique_ptr<HostSession> s(new HostSession());
    s->opt_ = opt;
    s->driver_ = ztnx_driver_new();
    if (!s->driver_ || (ztnx_driver_open_udp(s->driver_, opt.port ? opt.port : 9993) != 0 && ztnx_driver_open_udp(s->driver_, 0) != 0)) {
        *error = "cannot open a UDP socket";
        return nullptr;
    }
    s->stack_ = ztnx_stack_new(ztnx_driver_now_ns());

    HostSession *self = s.get();
    ZtLinkConfig cfg;
    cfg.state_ctx = &s->opt_.state;
    cfg.state_get = StateGet;
    cfg.state_put = StatePut;
    cfg.on_config = [self](const ZtnxNetConfig &c) {
        if (self->opt_.log) {
            char ip[32] = "-";
            if (c.n_addrs) snprintf(ip, sizeof ip, "%u.%u.%u.%u/%u", c.addrs[0].ip[0], c.addrs[0].ip[1], c.addrs[0].ip[2], c.addrs[0].ip[3], c.addrs[0].prefix);
            fprintf(stderr, "[ztnx] network: %s ip=%s mtu=%u routes=%u truncated=0x%x\n", StatusName(c.status), ip, c.mtu, c.n_routes, c.truncated);
        }
        {
            std::lock_guard<std::mutex> lock(self->mu_);
            self->config_ = c;
        }
        self->cv_.notify_all();
    };
    cfg.on_event = [self](uint32_t event) {
        if (self->opt_.log) fprintf(stderr, "[ztnx] event: %s\n", event == ZTNX_EVENT_ONLINE ? "ONLINE" : event == ZTNX_EVENT_OFFLINE ? "OFFLINE" : "IDENTITY_COLLISION");
    };
    s->link_ = ZtLink::Create(s->driver_, std::move(cfg), error);
    if (!s->link_) return nullptr;
    s->rt_ = Runtime::Create(s->stack_, s->driver_, s->link_->Ops(), error);
    if (!s->rt_) return nullptr;
    s->link_->Attach(s->rt_.get());
    if (opt.log) fprintf(stderr, "[ztnx] node %010" PRIx64 ", UDP port %u\n", s->link_->Address(), ztnx_driver_udp_port(s->driver_));
    if (!s->rt_->StartThread(opt.engine_stack)) {
        *error = "cannot start the engine thread";
        return nullptr;
    }
    if (opt.nwid && !s->link_->Join(opt.nwid)) {
        *error = "cannot post the join";
        return nullptr;
    }
    return s;
}

HostSession::~HostSession() {
    // The loop first (it uses everything else), then the node, which leaves
    // the network and writes its state as it goes.
    rt_.reset();
    link_.reset();
    if (driver_) ztnx_driver_free(driver_);
    if (stack_) ztnx_stack_free(stack_);
}

bool HostSession::WaitUp(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mu_);
    return cv_.wait_for(lock, timeout, [&] { return config_.status == ZTNX_NET_OK && config_.n_addrs > 0; });
}

ZtnxNetConfig HostSession::Config() {
    std::lock_guard<std::mutex> lock(mu_);
    return config_;
}

}  // namespace ztnx
