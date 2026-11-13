// Runs the engine on its own thread and lets other threads use the stack.
//
// Two things live here. The stack (ztnx.h: the TCP/IP stack and its Ethernet
// layer) is not thread-safe and is guarded by one mutex; any thread may use
// it through With/Read/WaitFor. The engine (ZeroTier's core, or a fake in
// tests) is used by the engine thread alone, through EngineOps, and never
// with that mutex held: its call paths need more stack than other threads
// have, and it may be slow (it writes state to the SD card).
//
// So a socket call from another thread only changes the stack and, if that
// left frames to send or a nearer timer, wakes the engine thread, which
// carries frames between the stack and the engine once per round.
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include <pthread.h>

#include "ztnx.h"
#include "ztnx_driver.h"

namespace ztnx {

// A frame the engine received from the network (as ZtnxFrame in
// ztnx_engine.h).
struct EngineFrame {
    uint64_t src_mac;
    uint64_t dst_mac;
    uint32_t ethertype;
    uint32_t len;
    const uint8_t *data;
};

// What the loop needs from the engine. Every function is called on the
// engine thread with the runtime lock not held.
struct EngineOps {
    void *ctx = nullptr;
    // A datagram arrived on the UDP socket.
    void (*wire_in)(void *ctx, uint32_t ip_be, uint16_t port, const uint8_t *data, size_t len) = nullptr;
    // Frames received since frames_done, oldest first; valid until then.
    size_t (*frames)(void *ctx, const EngineFrame **out) = nullptr;
    void (*frames_done)(void *ctx) = nullptr;
    // True when the engine wants its frames taken before more datagrams.
    bool (*frames_high)(void *ctx) = nullptr;
    // Sends a frame into the network.
    void (*frame_out)(void *ctx, uint64_t dst_mac, uint32_t ethertype, const uint8_t *data, size_t len) = nullptr;
    // Runs the engine's timers if they are due. Returns milliseconds until
    // they next are.
    int (*background)(void *ctx) = nullptr;
    // After a batch of the calls above: act on what the engine reported
    // meanwhile (a new network configuration, events). May use With().
    void (*after)(void *ctx) = nullptr;
    // A command from Post().
    void (*command)(void *ctx, uint32_t command, uint64_t arg) = nullptr;
    // The network underneath is (back) up: at start and after each resume.
    void (*network_up)(void *ctx) = nullptr;
};

class Runtime {
public:
    using Clock = std::chrono::steady_clock;

    // Wraps a stack and a driver the caller set up (and keeps owning) and
    // the engine behind `ops`.
    static std::unique_ptr<Runtime> Create(ZtnxStack *stack, ZtnxDriver *driver, const EngineOps &ops, std::string *error);

    // The engine loop; returns after Stop(). on_tick runs on this thread
    // without the lock, at least once a second and at most every 50 ms.
    void Run(const std::function<void()> &on_tick = nullptr);
    // Runs the loop on a new thread with `stack_size` bytes of stack (the
    // engine needs far more than a thread's default on the Switch; hosts use
    // the same size so an overflow shows up there too). The destructor stops
    // and joins it.
    bool StartThread(size_t stack_size, std::function<void()> on_tick = nullptr);
    void Stop();

    // Suspend() has the loop close every socket the driver and the runtime
    // own and idle without network I/O until Resume(). Independent reasons
    // (sleep, a user pause, ...) stack: I/O resumes once none is left.
    // Suspend returns once the sockets are closed (false: timed out).
    // Stop() while suspended ends the loop without reopening anything.
    enum SuspendReason : uint32_t { kSleep = 1, kPaused = 2, kStopping = 4 };
    bool Suspend(SuspendReason why, std::chrono::milliseconds timeout);
    void Resume(SuspendReason why);
    // Before Run(): start suspended (no waiting; the loop honours it first).
    void StartSuspended(SuspendReason why) { suspend_reasons_ |= why; }
    // Suspend without taking the lock or touching the network (no wake-up
    // datagram): the loop picks it up within its poll interval (<= 1 s), and
    // IsSuspended() turns true once every socket is closed. For callers that
    // must not stall on the socket service, e.g. a sleep notification.
    void RequestSuspend(SuspendReason why) { async_suspend_.fetch_or(why); }
    // Suspends or resumes for `why` without waiting on the engine: the loop
    // applies the latest request within its poll interval (<= 1 s), also
    // while suspended. For a control service that must always answer.
    void RequestSuspended(SuspendReason why, bool suspended);
    bool IsSuspended() const { return suspended_flag_.load(); }
    // Run on the engine thread right after suspending / before resuming,
    // e.g. to close and reopen sockets the embedder owns.
    void SetSuspendHooks(std::function<void()> on_suspend, std::function<void()> on_resume) {
        on_suspend_ = std::move(on_suspend);
        on_resume_ = std::move(on_resume);
    }

    // Hands a command to the engine thread (EngineOps::command), for callers
    // that must not run engine code themselves. False if too many are
    // waiting already.
    bool Post(uint32_t command, uint64_t arg);

    ~Runtime();
    Runtime(const Runtime &) = delete;
    Runtime &operator=(const Runtime &) = delete;

    // Runs f(stack) with exclusive access, between ztnx_stack_begin and
    // ztnx_stack_end, and wakes the engine thread if that left it work.
    template <class F>
    auto With(F &&f) -> decltype(f(static_cast<ZtnxStack *>(nullptr))) {
        // The loop first: a caller making call after call would otherwise
        // take the lock back before the loop thread runs, and frames in both
        // directions would wait. Callers block rather than spin: spinning
        // threads can starve the socket service the loop is waiting on.
        if (!on_engine_thread_ && loop_wants_lock_.load(std::memory_order_acquire)) WaitForLoop();
        std::unique_lock<std::mutex> lock(mu_);
        LockScope held;
        ztnx_stack_begin(stack_, ztnx_driver_now_ns());
        if constexpr (std::is_void_v<decltype(f(stack_))>) {
            f(stack_);
            AfterCall();
        } else {
            auto r = f(stack_);
            AfterCall();
            return r;
        }
    }

    // Like With, for calls that only read the stack's state (readiness,
    // taking a queued datagram): nothing to send afterwards, so the stack is
    // not run and nobody is woken.
    template <class F>
    auto Read(F &&f) -> decltype(f(static_cast<ZtnxStack *>(nullptr))) {
        if (!on_engine_thread_ && loop_wants_lock_.load(std::memory_order_acquire)) WaitForLoop();
        std::unique_lock<std::mutex> lock(mu_);
        LockScope held;
        return f(stack_);
    }

    // Blocks until ready(stack) returns true or the deadline passes
    // (nullptr = no deadline). Returns ready()'s final value.
    bool WaitFor(const std::function<bool(ZtnxStack *)> &ready, const Clock::time_point *deadline);

    // Wakes all waiters (e.g. a socket was closed under them).
    void NotifyAll() { cv_.notify_all(); }

    // True while the current thread is executing the runtime's own code (its
    // sockets, the engine's files). Interposition layers must pass such
    // calls straight through.
    static bool InInternal() { return internal_depth_ > 0; }
    // For assertions: this thread is the engine thread / holds the lock.
    static bool OnEngineThread() { return on_engine_thread_; }
    static bool HoldsLock() { return lock_depth_ > 0; }

    struct Stats {
        uint64_t rounds;  // loop rounds
        uint64_t wakes;   // wake-up datagrams sent to the engine thread
        // Where the engine thread's time went, in nanoseconds since start.
        // What is left of the wall clock is the rounds' other work (the
        // exchange with the stack, sending, the tick).
        uint64_t poll_ns;    // asleep in poll(): idle
        uint64_t recv_ns;    // reading datagrams from the socket
        uint64_t engine_ns;  // the engine taking them (decrypting, reassembling)
        uint64_t lock_ns;    // waiting for the lock at the end of a round
    };
    Stats GetStats() const { return {rounds_.load(), wakes_.load(), poll_ns_.load(), recv_ns_.load(), engine_ns_.load(), lock_ns_.load()}; }

private:
    Runtime() = default;
    void Loop(const std::function<void()> *on_tick);
    void AfterCall();
    void Wake();
    // The loop's locked part of a round. Returns how many frames it put in
    // the out buffer; *wait_ms gets how long the loop may sleep.
    int Exchange(std::unique_lock<std::mutex> &lock, int engine_wait_ms, int *wait_ms);
    bool HandleSuspend(std::unique_lock<std::mutex> &lock);
    void LockForLoop(std::unique_lock<std::mutex> &lock);

    struct InternalScope {
        InternalScope() { internal_depth_++; }
        ~InternalScope() { internal_depth_--; }
    };
    struct LockScope {
        InternalScope internal;
        LockScope() { lock_depth_++; }
        ~LockScope() { lock_depth_--; }
    };
    static thread_local int internal_depth_;
    static thread_local int lock_depth_;
    static thread_local bool on_engine_thread_;

    std::mutex mu_;
    std::condition_variable cv_;
    ZtnxStack *stack_ = nullptr;
    ZtnxDriver *driver_ = nullptr;
    EngineOps ops_;
    pthread_t thread_{};
    bool thread_started_ = false;
    std::function<void()> thread_tick_;
    bool stop_ = false;
    uint32_t suspend_reasons_ = 0;
    std::atomic<uint32_t> async_suspend_{0};
    // RequestSuspended: the reasons asked about (high 16 bits) and whether
    // each is wanted (low 16 bits); the latest request per reason wins.
    std::atomic<uint32_t> async_wanted_{0};
    void ApplyRequests();
    std::atomic<bool> suspended_flag_{false};
    std::function<void()> on_suspend_, on_resume_;
    bool suspended_ = false;
    bool resumed_ = true;  // tell the engine the network is up (also at start)
    int wake_rx_ = -1, wake_tx_ = -1;
    // True from when the loop decides to sleep in poll() until it is back.
    // A caller that leaves work for the engine while it is true sends one
    // wake-up and clears it, so a burst of calls costs one datagram.
    std::atomic<bool> polling_{false};
    // Until when that poll() waits at most (ztnx_driver_now_ns).
    uint64_t poll_until_ns_ = 0;
    // A With() on the engine thread itself left work: don't sleep yet.
    bool engine_dirty_ = false;
    // Set (under gate_mu_) while the loop waits for the lock; callers wait
    // on gate_cv_ until it has it.
    std::atomic<bool> loop_wants_lock_{false};
    std::mutex gate_mu_;
    std::condition_variable gate_cv_;
    void WaitForLoop();

    static constexpr int kMaxCommands = 4;
    struct Command {
        uint32_t command;
        uint64_t arg;
    };
    Command commands_[kMaxCommands];
    int n_commands_ = 0;

    // Frames taken from the stack under the lock, sent after releasing it.
    static constexpr int kOutFrames = 16;
    static constexpr size_t kOutBytes = 24 * 1024;
    struct OutFrame {
        uint64_t dst_mac;
        uint32_t ethertype;
        uint32_t len;
        uint32_t offset;
    };
    OutFrame out_[kOutFrames];
    std::unique_ptr<uint8_t[]> out_buf_;

    std::atomic<uint64_t> rounds_{0}, wakes_{0};
    std::atomic<uint64_t> poll_ns_{0}, recv_ns_{0}, engine_ns_{0}, lock_ns_{0};
};

}  // namespace ztnx
