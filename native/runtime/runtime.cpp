#include "runtime.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <new>

namespace ztnx {

thread_local int Runtime::internal_depth_ = 0;
thread_local int Runtime::lock_depth_ = 0;
thread_local bool Runtime::on_engine_thread_ = false;

namespace {

// A loopback UDP pair used to interrupt the engine thread's poll().
bool MakeWakePair(int *rx, int *tx) {
    *rx = socket(AF_INET, SOCK_DGRAM, 0);
    *tx = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof a;
    if (*rx < 0 || *tx < 0 || bind(*rx, reinterpret_cast<sockaddr *>(&a), sizeof a) != 0 ||
        getsockname(*rx, reinterpret_cast<sockaddr *>(&a), &len) != 0 ||
        connect(*tx, reinterpret_cast<sockaddr *>(&a), sizeof a) != 0) {
        if (*rx >= 0) close(*rx);
        if (*tx >= 0) close(*tx);
        *rx = *tx = -1;
        return false;
    }
    fcntl(*rx, F_SETFL, fcntl(*rx, F_GETFL, 0) | O_NONBLOCK);
    fcntl(*tx, F_SETFL, fcntl(*tx, F_GETFL, 0) | O_NONBLOCK);
#ifdef __SWITCH__
    // One byte at a time goes through: on the console every socket's
    // buffers come out of one small pool, so take the least.
    for (const int fd : {*rx, *tx}) {
        const int size = 0x1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof size);
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof size);
    }
#endif
    return true;
}

constexpr uint64_t kTickEveryNs = 50'000'000;
constexpr int kMaxWaitMs = 1000;

}  // namespace

std::unique_ptr<Runtime> Runtime::Create(ZtnxStack *stack, ZtnxDriver *driver, const EngineOps &ops, std::string *error) {
    InternalScope internal;
    std::unique_ptr<Runtime> rt(new (std::nothrow) Runtime());
    if (!rt) {
        *error = "out of memory";
        return nullptr;
    }
    rt->stack_ = stack;
    rt->driver_ = driver;
    rt->ops_ = ops;
    rt->out_buf_.reset(new (std::nothrow) uint8_t[kOutBytes]);
    if (!rt->out_buf_) {
        *error = "out of memory";
        return nullptr;
    }
    if (!MakeWakePair(&rt->wake_rx_, &rt->wake_tx_)) {
        *error = "cannot create wake sockets";
        return nullptr;
    }
    return rt;
}

void Runtime::Run(const std::function<void()> &on_tick) { Loop(&on_tick); }

bool Runtime::StartThread(size_t stack_size, std::function<void()> on_tick) {
    thread_tick_ = std::move(on_tick);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, stack_size);
    const int rc = pthread_create(
        &thread_, &attr,
        [](void *self) -> void * {
            auto *rt = static_cast<Runtime *>(self);
            rt->Loop(&rt->thread_tick_);
            return nullptr;
        },
        this);
    pthread_attr_destroy(&attr);
    thread_started_ = rc == 0;
    return thread_started_;
}

void Runtime::Stop() {
    std::lock_guard<std::mutex> lock(mu_);
    InternalScope internal;
    stop_ = true;
    Wake();
    cv_.notify_all();
}

Runtime::~Runtime() {
    Stop();
    if (thread_started_) pthread_join(thread_, nullptr);
    InternalScope internal;
    if (wake_rx_ >= 0) close(wake_rx_);
    if (wake_tx_ >= 0) close(wake_tx_);
}

// With the lock held (the wake pair is closed and reopened under it).
void Runtime::Wake() {
    if (wake_tx_ < 0) return;
    char b = 0;
    send(wake_tx_, &b, 1, 0);
    wakes_.fetch_add(1, std::memory_order_relaxed);
}

// With the lock held, after a caller's work on the stack.
void Runtime::AfterCall() {
    const uint32_t flags = ztnx_stack_end(stack_);
    if (suspended_) return;  // nothing is sent until Resume(), which drops what queued up
    if (on_engine_thread_) {
        engine_dirty_ = true;  // the loop looks before it next sleeps
        return;
    }
    // Wake the loop only if it is (about to be) asleep and this call gave it
    // something to do before its poll() would end anyway: frames to send, or
    // a timer of the stack's that is now due earlier. Most calls (a datagram
    // read, a readiness check, more data for a busy connection) don't.
    if (!polling_.load(std::memory_order_acquire)) return;
    if ((flags & ZTNX_OUT_PENDING) || ztnx_stack_next_deadline(stack_) < poll_until_ns_) {
        if (polling_.exchange(false)) Wake();
    }
}

bool Runtime::Post(uint32_t command, uint64_t arg) {
    std::lock_guard<std::mutex> lock(mu_);
    InternalScope internal;
    if (n_commands_ >= kMaxCommands) return false;
    commands_[n_commands_++] = {command, arg};
    if (polling_.exchange(false)) Wake();
    return true;
}

bool Runtime::Suspend(SuspendReason why, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mu_);
    InternalScope internal;
    suspend_reasons_ |= why;
    Wake();
    return cv_.wait_for(lock, timeout, [&] { return suspended_ || stop_; });
}

void Runtime::Resume(SuspendReason why) {
    std::lock_guard<std::mutex> lock(mu_);
    async_suspend_.fetch_and(~static_cast<uint32_t>(why));
    suspend_reasons_ &= ~static_cast<uint32_t>(why);
    cv_.notify_all();
}

void Runtime::RequestSuspended(SuspendReason why, bool suspended) {
    uint32_t cur = async_wanted_.load();
    uint32_t next;
    do {
        next = (cur | (static_cast<uint32_t>(why) << 16)) & ~static_cast<uint32_t>(why);
        if (suspended) next |= why;
    } while (!async_wanted_.compare_exchange_weak(cur, next));
    // No Wake(): the wake pair is the loop's, and it may be closing it.
    cv_.notify_all();
}

// With the lock held.
void Runtime::ApplyRequests() {
    const uint32_t w = async_wanted_.exchange(0);
    const uint32_t asked = w >> 16;
    suspend_reasons_ = (suspend_reasons_ & ~asked) | (w & asked);
}

void Runtime::WaitForLoop() {
    std::unique_lock<std::mutex> gate(gate_mu_);
    gate_cv_.wait(gate, [&] { return !loop_wants_lock_.load(std::memory_order_acquire); });
}

bool Runtime::WaitFor(const std::function<bool(ZtnxStack *)> &ready, const Clock::time_point *deadline) {
    std::unique_lock<std::mutex> lock(mu_);
    LockScope held;
    for (;;) {
        if (ready(stack_)) return true;
        if (stop_) return false;
        if (deadline) {
            if (cv_.wait_until(lock, *deadline) == std::cv_status::timeout) return ready(stack_);
        } else {
            cv_.wait(lock);
        }
    }
}

// Takes the lock for the loop, ahead of callers queueing for it (see With).
void Runtime::LockForLoop(std::unique_lock<std::mutex> &lock) {
    {
        std::lock_guard<std::mutex> gate(gate_mu_);
        loop_wants_lock_.store(true, std::memory_order_release);
    }
    lock.lock();
    {
        std::lock_guard<std::mutex> gate(gate_mu_);
        loop_wants_lock_.store(false, std::memory_order_release);
    }
    gate_cv_.notify_all();
}

// With the lock held: if a suspend is wanted, closes the sockets and waits
// here until it no longer is. Returns false if the loop should end.
bool Runtime::HandleSuspend(std::unique_lock<std::mutex> &lock) {
    suspend_reasons_ |= async_suspend_.exchange(0);
    ApplyRequests();
    if (suspend_reasons_ == 0) return !stop_;
    ztnx_driver_suspend(driver_);
    close(wake_rx_);
    close(wake_tx_);
    wake_rx_ = wake_tx_ = -1;
    if (on_suspend_) on_suspend_();
    suspended_ = true;
    suspended_flag_ = true;
    cv_.notify_all();
    // RequestSuspended notifies without the lock, so a wake-up can be
    // missed: look again every second.
    while (!stop_) {
        ApplyRequests();
        if (suspend_reasons_ == 0) break;
        cv_.wait_for(lock, std::chrono::seconds(1));
    }
    if (stop_) return false;  // stopping: keep everything closed
    // Without a wake pair the loop still runs, just with up to a second of
    // latency for new overlay sockets.
    if (on_resume_) on_resume_();
    MakeWakePair(&wake_rx_, &wake_tx_);
    ztnx_driver_resume(driver_);
    // What queued up meanwhile is stale, and so is what the stack believes
    // about its neighbours.
    ztnx_stack_begin(stack_, ztnx_driver_now_ns());
    ztnx_stack_link_reset(stack_);
    ztnx_stack_end(stack_);
    resumed_ = true;
    suspended_ = false;
    suspended_flag_ = false;
    cv_.notify_all();
    return true;
}

int Runtime::Exchange(std::unique_lock<std::mutex> &lock, int engine_wait_ms, int *wait_ms) {
    (void)lock;
    const uint64_t now = ztnx_driver_now_ns();
    ztnx_stack_begin(stack_, now);
    const EngineFrame *frames = nullptr;
    const size_t n = ops_.frames(ops_.ctx, &frames);
    for (size_t i = 0; i < n; i++) {
        ztnx_l2_frame_in(stack_, frames[i].src_mac, frames[i].dst_mac, frames[i].ethertype, frames[i].data, frames[i].len);
    }
    ops_.frames_done(ops_.ctx);
    const uint32_t flags = ztnx_stack_end(stack_);

    int taken = 0;
    size_t used = 0;
    while (taken < kOutFrames) {
        OutFrame &f = out_[taken];
        uint64_t mac = 0;
        uint32_t type = 0;
        const size_t len = ztnx_l2_next_out(stack_, out_buf_.get() + used, kOutBytes - used, &mac, &type);
        if (len == 0) break;
        f = {mac, type, static_cast<uint32_t>(len), static_cast<uint32_t>(used)};
        used += len;
        taken++;
    }
    const bool more = ztnx_stack_out_pending(stack_);

    int wait = std::min(engine_wait_ms, kMaxWaitMs);
    const uint64_t stack_at = ztnx_stack_next_deadline(stack_);
    if (stack_at != UINT64_MAX) {
        const uint64_t ms = stack_at > now ? (stack_at - now) / 1000000 + 1 : 0;
        if (ms < static_cast<uint64_t>(wait)) wait = static_cast<int>(ms);
    }
    if (more || engine_dirty_ || n_commands_ > 0 || resumed_ || stop_ || suspend_reasons_ != 0 || async_suspend_.load() != 0) wait = 0;
    engine_dirty_ = false;
    *wait_ms = wait;
    // From here callers must wake the loop for anything they leave it (the
    // frames taken above are sent before it sleeps, without the lock).
    poll_until_ns_ = now + static_cast<uint64_t>(wait) * 1000000;
    polling_.store(wait > 0, std::memory_order_release);
    if ((flags & ZTNX_CHANGED) || n > 0) cv_.notify_all();
    return taken;
}

void Runtime::Loop(const std::function<void()> *on_tick) {
    InternalScope internal;  // this thread only ever does the runtime's own work
    on_engine_thread_ = true;
    pollfd fds[ZTNX_DRIVER_MAX_FDS + 1];
    uint64_t last_tick = 0;
    int engine_wait_ms = 0;
    std::unique_lock<std::mutex> lock(mu_);
    lock_depth_++;
    while (HandleSuspend(lock)) {
        rounds_.fetch_add(1, std::memory_order_relaxed);
        // ---- with the lock: carry frames between the engine and the stack,
        // ---- and decide how long to sleep.
        Command commands[kMaxCommands];
        const int n_commands = n_commands_;
        std::copy(commands_, commands_ + n_commands, commands);
        const bool resumed = resumed_;
        int wait = 0;
        const int n_out = Exchange(lock, engine_wait_ms, &wait);
        n_commands_ = 0;
        resumed_ = false;
        lock_depth_--;
        lock.unlock();

        // ---- without it: everything that touches the engine or a socket.
        for (int i = 0; i < n_out; i++) {
            ops_.frame_out(ops_.ctx, out_[i].dst_mac, out_[i].ethertype, out_buf_.get() + out_[i].offset, out_[i].len);
        }
        if (ops_.command) {
            for (int i = 0; i < n_commands; i++) ops_.command(ops_.ctx, commands[i].command, commands[i].arg);
        }
        if (resumed && ops_.network_up) ops_.network_up(ops_.ctx);
        // Any of that may have left frames with the engine (ZeroTier's
        // arrive by datagram, but an engine may answer on the spot).
        {
            const EngineFrame *frames = nullptr;
            if (ops_.frames(ops_.ctx, &frames) > 0) wait = 0;
        }

        const int n = ztnx_driver_pollfds(driver_, fds, ZTNX_DRIVER_MAX_FDS);
        // The wake pair is only replaced by this thread (HandleSuspend).
        fds[n].fd = wake_rx_;
        fds[n].events = POLLIN;
        fds[n].revents = 0;
        const int nfds = n + (wake_rx_ >= 0 ? 1 : 0);
        const int rc = ztnx_driver_poll(driver_, fds, nfds, wait);
        polling_.store(false, std::memory_order_release);
        if (rc > 0 && wake_rx_ >= 0 && (fds[n].revents & POLLIN)) {
            char buf[64];
            for (int i = 0; i < 8 && recv(wake_rx_, buf, sizeof buf, 0) > 0; i++) {
            }
        }
        if (rc > 0) {
            const int got = ztnx_driver_recv(driver_, fds);
            for (int i = 0; i < got; i++) {
                const uint8_t *data;
                size_t len;
                uint32_t ip;
                uint16_t port;
                ztnx_driver_staged(driver_, i, &data, &len, &ip, &port);
                ops_.wire_in(ops_.ctx, ip, port, data, len);
                if (ops_.frames_high && ops_.frames_high(ops_.ctx)) {
                    // The engine's buffer is filling: hand its frames to the
                    // stack now. What the stack wants to send in return
                    // waits for the round's own exchange.
                    LockForLoop(lock);
                    lock_depth_++;
                    ztnx_stack_begin(stack_, ztnx_driver_now_ns());
                    const EngineFrame *frames = nullptr;
                    const size_t m = ops_.frames(ops_.ctx, &frames);
                    for (size_t k = 0; k < m; k++) {
                        ztnx_l2_frame_in(stack_, frames[k].src_mac, frames[k].dst_mac, frames[k].ethertype, frames[k].data, frames[k].len);
                    }
                    ops_.frames_done(ops_.ctx);
                    ztnx_stack_end(stack_);
                    engine_dirty_ = true;
                    cv_.notify_all();
                    lock_depth_--;
                    lock.unlock();
                }
            }
        }
        const uint64_t now = ztnx_driver_now_ns();
        if (on_tick && *on_tick && now - last_tick >= kTickEveryNs) {
            last_tick = now;
            (*on_tick)();
        }
        engine_wait_ms = ops_.background ? ops_.background(ops_.ctx) : kMaxWaitMs;
        if (ops_.after) ops_.after(ops_.ctx);

        LockForLoop(lock);
        lock_depth_++;
    }
    lock_depth_--;
    on_engine_thread_ = false;
}

}  // namespace ztnx
