// Runs unmodified programs through the ztnx socket virtualization layer, the
// same code the Switch bsd:u MITM uses, so it can be tested and debugged on
// the development machine.
//
//   macOS: DYLD_INSERT_LIBRARIES=target/libztnx_interpose.dylib prog ...
//          (not for SIP-protected binaries such as /usr/bin/curl)
//   Linux: LD_PRELOAD=target/linux/libztnx_interpose.so prog ...
//
// Configuration (environment): ZTNX_STATE (the state directory) and
// ZTNX_NWID (the network to join, hex) activate it. Optional: ZTNX_PORT,
// ZTNX_GEN_IDENTITY=1 (make an identity if the state has none),
// ZTNX_WAIT_READY=1 (hold the first socket call until the network is up
// with an address), ZTNX_LOG=1 (print status changes to stderr),
// ZTNX_LOG_LEVEL, ZTNX_ENGINE_STACK (bytes; default the sysmodule's),
// ZTNX_HEAP_LOG=<ms>, ZTNX_TRACE=1.
#include <pthread.h>
#include <thread>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string.h>

#include <atomic>
#include <type_traits>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "runtime.hpp"
#include "session.hpp"
#include "vsock.hpp"

extern "C" void ztnx_platform_random(uint8_t *buf, size_t len) {
#ifdef __APPLE__
    arc4random_buf(buf, len);
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, len, f) != len) abort();
    fclose(f);
#endif
}

namespace {

// ---- access to the real functions ----------------------------------------

#ifdef __APPLE__
// Inside the interposing image, plain calls reach the originals.
#define REAL(name) ::name
#else
template <class T>
T Resolve(const char *name) {
    return reinterpret_cast<T>(dlsym(RTLD_NEXT, name));
}
#define REAL(name) (Resolve<decltype(&::name)>(#name))
#endif

class LibcBackend final : public ztnx::Backend {
public:
    ztnx::Result Socket(int d, int t, int p) override { return R(REAL(socket)(d, t, p)); }
    ztnx::Result Close(int fd) override { return R(REAL(close)(fd)); }
    ztnx::Result Connect(int fd, const sockaddr *a, socklen_t l) override { return R(REAL(connect)(fd, a, l)); }
    ztnx::Result Bind(int fd, const sockaddr *a, socklen_t l) override { return R(REAL(bind)(fd, a, l)); }
    ztnx::Result Listen(int fd, int b) override { return R(REAL(listen)(fd, b)); }
    ztnx::Result Accept(int fd, sockaddr *a, socklen_t *l) override { return R(REAL(accept)(fd, a, l)); }
    ztnx::Result Send(int fd, const void *b, size_t n, int f) override { return R(REAL(send)(fd, b, n, f)); }
    ztnx::Result SendTo(int fd, const void *b, size_t n, int f, const sockaddr *a, socklen_t l) override {
        return R(REAL(sendto)(fd, b, n, f, a, l));
    }
    ztnx::Result Recv(int fd, void *b, size_t n, int f) override { return R(REAL(recv)(fd, b, n, f)); }
    ztnx::Result RecvFrom(int fd, void *b, size_t n, int f, sockaddr *a, socklen_t *l) override {
        return R(REAL(recvfrom)(fd, b, n, f, a, l));
    }
    ztnx::Result Poll(pollfd *fds, nfds_t n, int t) override { return R(REAL(poll)(fds, n, t)); }
    ztnx::Result Shutdown(int fd, int h) override { return R(REAL(shutdown)(fd, h)); }
    ztnx::Result GetSockName(int fd, sockaddr *a, socklen_t *l) override { return R(REAL(getsockname)(fd, a, l)); }
    ztnx::Result GetPeerName(int fd, sockaddr *a, socklen_t *l) override { return R(REAL(getpeername)(fd, a, l)); }
    ztnx::Result GetSockOpt(int fd, int lv, int n, void *v, socklen_t *l) override {
        return R(REAL(getsockopt)(fd, lv, n, v, l));
    }
    ztnx::Result SetSockOpt(int fd, int lv, int n, const void *v, socklen_t l) override {
        return R(REAL(setsockopt)(fd, lv, n, v, l));
    }
    ztnx::Result Fcntl(int fd, int cmd, int arg) override { return R(REAL(fcntl)(fd, cmd, arg)); }
    int Errno(ztnx::Err e) override {
        switch (e) {
            case ztnx::Err::Again: return EAGAIN;
            case ztnx::Err::InProgress: return EINPROGRESS;
            case ztnx::Err::ConnRefused: return ECONNREFUSED;
            case ztnx::Err::ConnReset: return ECONNRESET;
            case ztnx::Err::NotConn: return ENOTCONN;
            case ztnx::Err::BadF: return EBADF;
            case ztnx::Err::Inval: return EINVAL;
            case ztnx::Err::AddrInUse: return EADDRINUSE;
            case ztnx::Err::IsConn: return EISCONN;
            case ztnx::Err::TimedOut: return ETIMEDOUT;
            case ztnx::Err::Pipe: return EPIPE;
            case ztnx::Err::AfNoSupport: return EAFNOSUPPORT;
            case ztnx::Err::NoBufs: return ENOBUFS;
        }
        return EINVAL;
    }
    int DontWaitFlag() override { return MSG_DONTWAIT; }
    int NonBlockFlag() override { return O_NONBLOCK; }

private:
    static ztnx::Result R(int64_t r) { return {r, r < 0 ? errno : 0}; }
};

// ---- global state ---------------------------------------------------------

struct State {
    LibcBackend backend;
    std::unique_ptr<ztnx::HostSession> session;
    std::unique_ptr<ztnx::VSock> vsock;
};

std::once_flag g_once;
// Set once initialization finished; null forever if inactive. libSystem calls
// some interposed functions (e.g. close) while it is still initializing, when
// thread-locals don't work yet, so nothing touches TLS until this is set, and
// only the application's first socket() triggers initialization.
std::atomic<State *> g_state{nullptr};
// Our image's constructor runs after its dependencies (libSystem, libc++) are
// initialized; socket() calls before that must not start anything.
std::atomic<bool> g_loaded{false};
__attribute__((constructor)) void OnLoad() { g_loaded.store(true, std::memory_order_release); }

// At exit the engine thread dies with the process. Give it a moment first to
// send what programs left behind (the last bytes of a connection and its
// close): iperf3's server, for one, stays "busy" for good if the client's
// final message never arrives.
__attribute__((destructor)) void OnUnload() {
    State *st = g_state.load(std::memory_order_acquire);
    if (!st || ztnx::Runtime::InInternal()) return;
    for (int i = 0; i < 50; i++) {
        const bool busy = st->session->runtime().Read([](ZtnxStack *s) { return ztnx_stack_out_pending(s) || ztnx_net_buffer_usage(s) > 0; });
        if (!busy) break;
        usleep(10000);
    }
    usleep(20000);
}
// While Init runs, the engine thread it starts already makes socket calls;
// they (and everything else) pass through rather than wait on g_once.
std::atomic<bool> g_initializing{false};

std::string Env(const char *name, const char *def = "") {
    const char *v = getenv(name);
    return v ? v : def;
}

void Init() {
    const std::string state = Env("ZTNX_STATE"), nwid = Env("ZTNX_NWID");
    if (state.empty() || nwid.empty()) return;
    g_initializing = true;
    struct Done {
        ~Done() { g_initializing = false; }
    } done;
    auto *st = new State();
    const bool log = Env("ZTNX_LOG") == "1";
    ztnx::HostOptions opt;
    opt.state = state;
    opt.nwid = strtoull(nwid.c_str(), nullptr, 16);
    opt.port = static_cast<uint16_t>(atoi(Env("ZTNX_PORT", "0").c_str()));
    opt.gen_identity = Env("ZTNX_GEN_IDENTITY") == "1";
    opt.log = log;
    if (const unsigned long stack = strtoul(Env("ZTNX_ENGINE_STACK", "0").c_str(), nullptr, 0)) opt.engine_stack = stack;
    int log_level = atoi(Env("ZTNX_LOG_LEVEL", log ? "3" : "0").c_str());
    if (log_level > 0)
        ztnx_set_log_callback([](uint32_t level, const char *msg) { fprintf(stderr, "[ztnx %u] %s\n", level, msg); },
                              static_cast<uint32_t>(log_level));
    std::string err;
    st->session = ztnx::HostSession::Start(opt, &err);
    if (!st->session) {
        fprintf(stderr, "[ztnx] disabled: %s\n", err.c_str());
        delete st;
        return;
    }
    st->vsock = std::make_unique<ztnx::VSock>(st->backend, st->session->runtime());
    g_state = st;
    // ZTNX_HEAP_LOG=<ms>: print the Rust heap periodically (memory tests).
    if (int ms = atoi(Env("ZTNX_HEAP_LOG", "0").c_str()); ms > 0) {
        std::thread([ms] {
            for (;;) {
                size_t cur = 0, peak = 0;
                ztnx_heap_stats(&cur, &peak);
                fprintf(stderr, "[ztnx heap] %zu %zu\n", cur, peak);
                usleep(static_cast<useconds_t>(ms) * 1000);
            }
        }).detach();
    }
    // ZTNX_WAIT_READY=1: hold the first socket call until the network is up.
    if (Env("ZTNX_WAIT_READY") == "1" && !st->session->WaitUp(std::chrono::seconds(60))) {
        fprintf(stderr, "[ztnx] warning: the network is not up after 60 s\n");
    }
}

// Returns the virtualization layer, or null to pass the call straight through.
// `may_init`: this call may start the engine (only socket() does).
ztnx::VSock *Layer(bool may_init = false) {
    State *st = g_state.load(std::memory_order_acquire);
    if (!st && may_init && g_loaded.load(std::memory_order_acquire) && !g_initializing) {
        std::call_once(g_once, Init);
        st = g_state.load(std::memory_order_acquire);
    }
    if (!st || ztnx::Runtime::InInternal()) return nullptr;
    return st->vsock.get();
}

bool Tracing() {
    static int on = -1;
    if (on < 0) on = Env("ZTNX_TRACE") == "1";
    return on == 1;
}

template <class T>
T Ret(const ztnx::Result &r) {
    if (r.ret < 0) errno = r.err;
    return static_cast<T>(r.ret);
}

template <class T>
T Traced(const char *name, int fd, const ztnx::Result &r) {
    if (Tracing()) fprintf(stderr, "[ztnx] %s(%d) = %lld%s%s\n", name, fd, static_cast<long long>(r.ret),
                           r.ret < 0 ? " errno " : "", r.ret < 0 ? strerror(r.err) : "");
    return Ret<T>(r);
}

// A thread must not be cancelled while it is inside the layer: it may hold
// the runtime's lock, which would then stay locked for good (iperf3 3.16+
// cancels its stream threads at the end of a test, and hung in its next
// call). Cancellation waits until the call returns.
// (Re-enabling can act on a pending cancellation at once, unwinding from
// inside the destructor: it must be allowed to.)
struct NoCancel {
    int old = 0;
    NoCancel() { pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old); }
    ~NoCancel() noexcept(false) { pthread_setcancelstate(old, nullptr); }
};

}  // namespace

// Socket calls made by the engine itself (its thread, or I/O it performs on
// a caller's thread) must reach the OS directly: Layer() returns null then.

#define WRAP(ret, name, params, args, call)                   \
    extern "C" ret ztnx_##name params {                       \
        ztnx::VSock *v = Layer();                              \
        if (!v) return REAL(name) args;                        \
        NoCancel no_cancel;                                    \
        return Traced<ret>(#name, FirstArg args, call);        \
    }

// The fd argument, for tracing (-1 for calls that don't take one first).
template <class T, class... Rest>
static inline int FirstArg(T first, Rest...) {
    if constexpr (std::is_integral_v<T>) return static_cast<int>(first);
    else return -1;
}

extern "C" int ztnx_socket(int d, int t, int p) {
    // libSystem opens AF_UNIX sockets (logging) during its own initialization,
    // when starting threads would crash; only an internet socket can start us.
    ztnx::VSock *v = Layer(/*may_init=*/d == AF_INET || d == AF_INET6);
    if (!v) return REAL(socket)(d, t, p);
    NoCancel no_cancel;
    return Ret<int>(v->Socket(d, t, p));
}
WRAP(int, close, (int fd), (fd), v->Close(fd))
WRAP(int, connect, (int fd, const sockaddr *a, socklen_t l), (fd, a, l), v->Connect(fd, a, l))
WRAP(int, bind, (int fd, const sockaddr *a, socklen_t l), (fd, a, l), v->Bind(fd, a, l))
WRAP(int, listen, (int fd, int b), (fd, b), v->Listen(fd, b))
WRAP(int, accept, (int fd, sockaddr *a, socklen_t *l), (fd, a, l), v->Accept(fd, a, l))
WRAP(ssize_t, send, (int fd, const void *b, size_t n, int f), (fd, b, n, f), v->Send(fd, b, n, f))
WRAP(ssize_t, sendto, (int fd, const void *b, size_t n, int f, const sockaddr *a, socklen_t l), (fd, b, n, f, a, l),
     v->SendTo(fd, b, n, f, a, l))
WRAP(ssize_t, recv, (int fd, void *b, size_t n, int f), (fd, b, n, f), v->Recv(fd, b, n, f))
WRAP(ssize_t, recvfrom, (int fd, void *b, size_t n, int f, sockaddr *a, socklen_t *l), (fd, b, n, f, a, l),
     v->RecvFrom(fd, b, n, f, a, l))
WRAP(int, poll, (pollfd * fds, nfds_t n, int t), (fds, n, t), v->Poll(fds, n, t))
WRAP(int, shutdown, (int fd, int h), (fd, h), v->Shutdown(fd, h))
WRAP(int, getsockname, (int fd, sockaddr *a, socklen_t *l), (fd, a, l), v->GetSockName(fd, a, l))
WRAP(int, getpeername, (int fd, sockaddr *a, socklen_t *l), (fd, a, l), v->GetPeerName(fd, a, l))
WRAP(int, getsockopt, (int fd, int lv, int n, void *val, socklen_t *l), (fd, lv, n, val, l),
     v->GetSockOpt(fd, lv, n, val, l))
WRAP(int, setsockopt, (int fd, int lv, int n, const void *val, socklen_t l), (fd, lv, n, val, l),
     v->SetSockOpt(fd, lv, n, val, l))

extern "C" ssize_t ztnx_read(int fd, void *b, size_t n) {
    ztnx::VSock *v = Layer();
    if (!v || !v->IsVirtual(fd)) return REAL(read)(fd, b, n);
    NoCancel no_cancel;
    return Traced<ssize_t>("read", fd, v->Recv(fd, b, n, 0));
}

extern "C" ssize_t ztnx_write(int fd, const void *b, size_t n) {
    ztnx::VSock *v = Layer();
    if (!v || !v->IsVirtual(fd)) return REAL(write)(fd, b, n);
    NoCancel no_cancel;
    return Traced<ssize_t>("write", fd, v->Send(fd, b, n, 0));
}

extern "C" int ztnx_fcntl(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    int arg = va_arg(ap, int);  // all commands we care about take an int
    va_end(ap);
    ztnx::VSock *v = Layer();
    if (!v) return REAL(fcntl)(fd, cmd, arg);
    NoCancel no_cancel;
    return Ret<int>(v->Fcntl(fd, cmd, arg));
}

extern "C" int ztnx_ioctl(int fd, unsigned long req, ...) {
    va_list ap;
    va_start(ap, req);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    ztnx::VSock *v = Layer();
    if (v && req == FIONBIO && arg) v->NoteNonBlocking(fd, *static_cast<int *>(arg) != 0);
    return REAL(ioctl)(fd, req, arg);
}

extern "C" int ztnx_select(int nfds, fd_set *r, fd_set *w, fd_set *e, timeval *tv) {
    ztnx::VSock *v = Layer();
    bool any = false;
    if (v) {
        for (int fd = 0; fd < nfds && !any; fd++)
            if (((r && FD_ISSET(fd, r)) || (w && FD_ISSET(fd, w))) && v->IsVirtual(fd)) any = true;
    }
    if (!any) return REAL(select)(nfds, r, w, e, tv);
    // Express as poll so virtual sockets are handled.
    std::vector<pollfd> p;
    for (int fd = 0; fd < nfds; fd++) {
        short ev = 0;
        if (r && FD_ISSET(fd, r)) ev |= POLLIN;
        if (w && FD_ISSET(fd, w)) ev |= POLLOUT;
        if (ev) p.push_back({fd, ev, 0});
    }
    int timeout = tv ? static_cast<int>(tv->tv_sec * 1000 + tv->tv_usec / 1000) : -1;
    ztnx::Result res = v->Poll(p.data(), p.size(), timeout);
    if (res.ret < 0) return Ret<int>(res);
    if (r) FD_ZERO(r);
    if (w) FD_ZERO(w);
    if (e) FD_ZERO(e);
    int count = 0;
    for (auto &x : p) {
        if (r && (x.revents & (POLLIN | POLLHUP | POLLERR))) {
            FD_SET(x.fd, r);
            count++;
        }
        if (w && (x.revents & (POLLOUT | POLLERR))) {
            FD_SET(x.fd, w);
            count++;
        }
    }
    return count;
}

// ---- symbol binding ----------------------------------------------------------

#ifdef __APPLE__
#define INTERPOSE(name)                                                                       \
    __attribute__((used)) static struct {                                                     \
        const void *replacement;                                                              \
        const void *original;                                                                 \
    } interpose_##name __attribute__((section("__DATA,__interpose"))) = {                     \
        reinterpret_cast<const void *>(&ztnx_##name), reinterpret_cast<const void *>(&::name)}
#else
// Linux: export the libc names, forwarding to the wrappers.
#define INTERPOSE(name) extern "C" __attribute__((alias("ztnx_" #name), visibility("default"))) decltype(::name) name
#endif

INTERPOSE(socket);
INTERPOSE(close);
INTERPOSE(connect);
INTERPOSE(bind);
INTERPOSE(listen);
INTERPOSE(accept);
INTERPOSE(send);
INTERPOSE(sendto);
INTERPOSE(recv);
INTERPOSE(recvfrom);
INTERPOSE(poll);
INTERPOSE(shutdown);
INTERPOSE(getsockname);
INTERPOSE(getpeername);
INTERPOSE(getsockopt);
INTERPOSE(setsockopt);
INTERPOSE(read);
INTERPOSE(write);
INTERPOSE(fcntl);
INTERPOSE(ioctl);
INTERPOSE(select);
