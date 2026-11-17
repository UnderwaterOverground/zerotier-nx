// Socket virtualization: the decision layer between an application's BSD
// socket calls and either the real network stack or the tunnel overlay.
//
// Every socket is created for real, so fd numbers stay unique and plain
// traffic is untouched. A socket becomes (partly) virtual when it is
// connected/sent to a tunnel address (our own, or inside the network's
// subnets and managed routes: IsTunnel), bound to a tunnel address, or bound to the wildcard
// address (then it is reachable from both sides: a "dual" socket). Virtual
// traffic goes through the ztnx engine's overlay sockets.
//
// The same code serves the macOS/Linux interpose shim (tests on the dev
// machine) and the Switch bsd:u MITM; `Backend` abstracts the real stack and
// errno numbering, which differ between them.
#pragma once

#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>

#include "runtime.hpp"

namespace ztnx {

// Outcome of a socket call: `ret` as the call would return, `err` an errno
// value in the backend's numbering when ret < 0.
struct Result {
    int64_t ret;
    int err;
    static Result Ok(int64_t r) { return {r, 0}; }
};

enum class Err { Again, InProgress, ConnRefused, ConnReset, NotConn, BadF, Inval, AddrInUse, IsConn, TimedOut, Pipe, AfNoSupport, NoBufs };

// The real socket API (libc on hosts, forwarded bsd:u requests on Horizon).
class Backend {
public:
    virtual ~Backend() = default;
    virtual Result Socket(int domain, int type, int protocol) = 0;
    virtual Result Close(int fd) = 0;
    virtual Result Connect(int fd, const sockaddr *addr, socklen_t len) = 0;
    virtual Result Bind(int fd, const sockaddr *addr, socklen_t len) = 0;
    virtual Result Listen(int fd, int backlog) = 0;
    virtual Result Accept(int fd, sockaddr *addr, socklen_t *len) = 0;
    virtual Result Send(int fd, const void *buf, size_t len, int flags) = 0;
    virtual Result SendTo(int fd, const void *buf, size_t len, int flags, const sockaddr *to, socklen_t tolen) = 0;
    virtual Result Recv(int fd, void *buf, size_t len, int flags) = 0;
    virtual Result RecvFrom(int fd, void *buf, size_t len, int flags, sockaddr *from, socklen_t *fromlen) = 0;
    virtual Result Poll(pollfd *fds, nfds_t n, int timeout_ms) = 0;
    virtual Result Shutdown(int fd, int how) = 0;
    virtual Result GetSockName(int fd, sockaddr *addr, socklen_t *len) = 0;
    virtual Result GetPeerName(int fd, sockaddr *addr, socklen_t *len) = 0;
    virtual Result GetSockOpt(int fd, int level, int name, void *val, socklen_t *len) = 0;
    virtual Result SetSockOpt(int fd, int level, int name, const void *val, socklen_t len) = 0;
    virtual Result Fcntl(int fd, int cmd, int arg) = 0;
    // errno value for a virtual-socket error, in this backend's numbering.
    virtual int Errno(Err e) = 0;
    // Flag for "don't block" in recv flags (MSG_DONTWAIT).
    virtual int DontWaitFlag() = 0;
    // O_NONBLOCK as F_GETFL/F_SETFL carry it.
    virtual int NonBlockFlag() = 0;
};

class VSock {
public:
    VSock(Backend &real, Runtime &rt) : real_(real), rt_(rt) {}

    Result Socket(int domain, int type, int protocol);
    Result Close(int fd);
    Result Connect(int fd, const sockaddr *addr, socklen_t len);
    Result Bind(int fd, const sockaddr *addr, socklen_t len);
    Result Listen(int fd, int backlog);
    Result Accept(int fd, sockaddr *addr, socklen_t *len);
    Result Send(int fd, const void *buf, size_t len, int flags);
    Result SendTo(int fd, const void *buf, size_t len, int flags, const sockaddr *to, socklen_t tolen);
    Result Recv(int fd, void *buf, size_t len, int flags);
    Result RecvFrom(int fd, void *buf, size_t len, int flags, sockaddr *from, socklen_t *fromlen);
    Result Poll(pollfd *fds, nfds_t n, int timeout_ms);
    Result Shutdown(int fd, int how);
    Result GetSockName(int fd, sockaddr *addr, socklen_t *len);
    Result GetPeerName(int fd, sockaddr *addr, socklen_t *len);
    Result GetSockOpt(int fd, int level, int name, void *val, socklen_t *len);
    Result SetSockOpt(int fd, int level, int name, const void *val, socklen_t len);
    Result Fcntl(int fd, int cmd, int arg);
    // FIONBIO-style non-blocking toggle (ioctl), tracked like O_NONBLOCK.
    void NoteNonBlocking(int fd, bool on);

    // True if fd is known to this layer and has a virtual side.
    bool IsVirtual(int fd);
    // True if fd was created through this layer.
    bool IsKnown(int fd);
    // Sockets tracked for this client (diagnostics: a leak shows as growth).
    size_t Tracked();
    // Long waits re-check this once a second and give up (EAGAIN) once it
    // returns false, e.g. when the calling process has exited.
    void SetAliveCheck(std::function<bool()> alive) { alive_ = std::move(alive); }
    // Closes the virtual side of every socket (the client went away).
    void CloseAll();
    // Whether a datagram socket bound to the wildcard address gets its
    // overlay side right away (receives from the tunnel before sending
    // there) or only once it sends to a tunnel address, which saves its
    // buffers for the many sockets that never do. Default: right away.
    void SetEagerDualUdp(bool eager) { eager_dual_udp_ = eager; }
    // Whether addr goes through the tunnel: inside one of the routes
    // (SetRoutes: our own subnets and the network's managed routes), except
    // addresses on our own LAN (SetLocalNet), which are reached directly as
    // with any on-link route, and special ones (loopback, link-local,
    // multicast, broadcast), which a 0.0.0.0/0 route would otherwise take.
    static bool IsTunnel(const sockaddr *addr);
    // The network's routes (see ZtLink), whenever its configuration changes. At most
    // MaxRoutes are used.
    static constexpr size_t MaxRoutes = 64;
    static void SetRoutes(const ZtnxPrefix *routes, size_t n);
    // Our LAN: IPv4 address (host byte order; 0 = offline) and prefix length.
    static void SetLocalNet(uint32_t ip, unsigned len);
    // Test knob: send LAN addresses through the tunnel too when a route
    // covers them (forces a stream from a local host through the server).
    static void SetTunnelLan(bool on);

    // Stand-in addresses for peers. Moonlight sends 1392-byte video packets
    // to private addresses (10/8, 172.16/12, 192.168/16) and 1024-byte ones
    // to everything else; the big ones don't fit the tunnel's MTU, so each
    // arrives in two fragments and the Switch receives twice the datagrams.
    // Peer names therefore resolve to a stand-in in 100.127.0.0/16 (hosts
    // file), and this layer swaps it for the peer's real address on the way
    // out and back on the way in, for the sockets that used it. Stand-ins
    // always go through the tunnel. Addresses in host byte order.
    struct Alias {
        uint32_t alias;
        uint32_t real;
    };
    static constexpr size_t MaxAliases = 32;
    static void SetAliases(const Alias *aliases, size_t n);
    // The stand-in for a private peer address, or 0 for one that needs none.
    static uint32_t AliasFor(uint32_t real);
    // Swap a stand-in for its real address (ToReal) or back (ToAlias) in
    // place; false (unchanged) if ip isn't one.
    static bool ToReal(uint32_t *ip);
    static bool ToAlias(uint32_t *ip);

private:
    struct VFd {
        int type = 0;  // SOCK_STREAM or SOCK_DGRAM
        int domain = AF_INET;
        bool nonblock = false;
        int32_t tcp = 0;     // engine TCP connection id
        int32_t listen = 0;  // engine TCP listener id
        int32_t udp = 0;     // engine UDP socket id
        bool connecting = false;
        bool connected_virtual = false;
        bool has_udp_peer = false;
        bool aliased = false;  // sent to a stand-in: show its peer as one too
        ZtnxAddr udp_peer{};
        uint16_t port = 0;       // locally bound port
        bool bound_any = false;  // bound to the wildcard address
        bool virtual_only = false;  // no usable real side (tunnel-bound, accepted)
        bool real_used = false;     // real side carried traffic (must be polled)
        int so_error = 0;
        int rcv_timeout_ms = -1, snd_timeout_ms = -1;
    };

    // Swaps a stand-in destination for the real address, noting it in v.
    static void Unalias(ZtnxAddr *a, VFd &v);
    // Shows a peer address as its stand-in if v used one.
    static void Realias(ZtnxAddr *a, const VFd &v);

    // Copies the state for fd (false if unknown).
    bool Get(int fd, VFd *out);
    void Put(int fd, const VFd &v);
    Result Fail(Err e) { return {-1, real_.Errno(e)}; }
    Result EngineErr(int32_t code);
    // Ensures the socket has an engine UDP socket on its port.
    bool EnsureUdp(int fd, VFd &v);
    // Waits for virtual readiness bits (ZTNX_READABLE/WRITABLE/HUP) on id.
    bool WaitEngine(int32_t id, uint32_t mask, int timeout_ms);
    // rt_.WaitFor in slices, stopping early if the caller is no longer alive.
    bool WaitSliced(const std::function<bool(ZtnxStack *)> &ready, const Runtime::Clock::time_point *deadline);

    Backend &real_;
    Runtime &rt_;
    std::function<bool()> alive_;
    bool eager_dual_udp_ = true;
    std::mutex mu_;
    std::map<int, VFd> fds_;
};

}  // namespace ztnx
