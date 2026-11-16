// See ztnx_driver.h.
#include "ztnx_driver.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef __SWITCH__
#include <switch.h>
#include <switch/services/bsd.h>
#include <sys/iosupport.h>
#endif

// Rounds in a row ztnx_driver_poll may skip poll() while the socket is
// backlogged, before it polls anyway (for the caller's other fds).
#define UDP_BACKLOG_ROUNDS 8
// Datagrams are read UDP_STAGED at a time into sbuf (page-aligned: on the
// Switch it is also the socket service's message buffer), UDP_SLOT bytes
// each (ZeroTier's physical datagrams are 1432 bytes at most by default),
// and handed to the caller from there.
#define UDP_STAGED ZTNX_DRIVER_BATCH
#define UDP_SLOT 2048
#define SBUF_SIZE (UDP_STAGED * UDP_SLOT)

static const char *volatile g_step;
#define STEP(s) (g_step = (s))
const char *ztnx_driver_step(void) { return g_step; }

struct ZtnxDriver {
    int udp_fd;
    uint16_t udp_port;
    // Where the UDP socket is in the caller's pollfds (-1: not polled).
    int poll_udp;
    // Datagrams of the last recv (in sbuf).
    uint8_t *sbuf;
    struct {
        const uint8_t *data;
        size_t len;
        uint32_t ip_be;
        uint16_t port;
    } staged[UDP_STAGED];
    int n_staged;
    int backlog;               // the last recv filled a batch: likely more queued
    int backlog_rounds;        // polls skipped in a row for it
    // Batched receive (Switch): 1 works, 0 not known yet, -1 off (and the
    // socket service's errno, if a call failed); misses: batches that came
    // back empty while recvfrom then found a datagram.
    int mmsg_state, mmsg_errno, mmsg_misses;
    // Why the last failed send failed: its errno, negated if it was the hop
    // limit that couldn't be set; and how many of those there were.
    int send_errno;
    unsigned int send_ttl_failures;
    // The socket service has dropped the UDP socket (it does when the
    // network goes away, e.g. Airplane Mode, without a sleep): every send
    // fails and poll() returns at once. The engine thread reopens it
    // (ztnx_driver_reopen); reopens counts how often.
    int broken;
    unsigned int reopens;
};

// Errors that mean the socket itself is gone, not that a datagram failed.
static int socket_gone(int e) { return e == EPIPE || e == EBADF || e == ENOTSOCK || e == ENOTCONN; }

uint64_t ztnx_driver_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

ZtnxDriver *ztnx_driver_new(void) {
    ZtnxDriver *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->sbuf = aligned_alloc(0x1000, SBUF_SIZE);
    if (!d->sbuf) {
        free(d);
        return NULL;
    }
#ifdef __SWITCH__
    if (hosversionBefore(7, 0, 0)) d->mmsg_state = -1;  // its RecvMMsg is 7.0.0+
#else
    d->mmsg_state = -1;
#endif
    d->udp_fd = -1;
    d->poll_udp = -1;
    return d;
}

void ztnx_driver_free(ZtnxDriver *d) {
    if (!d) return;
    free(d->sbuf);
    if (d->udp_fd >= 0) close(d->udp_fd);
    free(d);
}

uint16_t ztnx_driver_udp_port(const ZtnxDriver *d) { return d->udp_fd >= 0 ? d->udp_port : 0; }

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// The socket service drops datagrams that arrive while a socket's receive
// buffer is full, before we can read them: at 48 KB, about one video
// frame's burst, that was 1-12% of packets under a 15.5 Mbit/s Artemis
// stream. The buffer comes out of our socket pool (main.cpp), not new
// memory, but every other socket needs room in it too: 160 KB leaves room
// for a DNS socket and the update check's connection (a new socket that
// doesn't fit fails with ENOBUFS). More would lose less still (under a
// 28 Mbit/s stream, 160 KB lost up to 8% in bursts and 240 KB almost
// nothing); ZTNX_UDP_RCVBUF overrides it for experiments.
#ifndef ZTNX_UDP_RCVBUF
#define ZTNX_UDP_RCVBUF (160 * 1024)
#endif
#define UDP_RCVBUF ZTNX_UDP_RCVBUF

static void grow_rcvbuf(int fd) {
    for (int size = UDP_RCVBUF; size >= 32 * 1024; size -= 32 * 1024) {
        int got = 0;
        socklen_t len = sizeof got;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof size) == 0 &&
            getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &got, &len) == 0 && got >= size)
            return;
    }
}

int ztnx_driver_open_udp(ZtnxDriver *d, uint16_t port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    socklen_t len = sizeof sin;
    if (bind(fd, (struct sockaddr *)&sin, sizeof sin) != 0 || set_nonblocking(fd) != 0 ||
        getsockname(fd, (struct sockaddr *)&sin, &len) != 0) {
        close(fd);
        return -1;
    }
    grow_rcvbuf(fd);
    d->udp_fd = fd;
    d->udp_port = ntohs(sin.sin_port);
    return 0;
}

void ztnx_driver_suspend(ZtnxDriver *d) {
    if (d->udp_fd >= 0) {
        close(d->udp_fd);
        d->udp_fd = -1;
    }
    d->broken = 0;
    d->backlog = 0;
    d->n_staged = 0;
    d->poll_udp = -1;
}

int ztnx_driver_resume(ZtnxDriver *d) {
    if (d->udp_fd >= 0 || !d->udp_port) return 0;
    // Same port as before, so peers' notion of our endpoint stays valid.
    return ztnx_driver_open_udp(d, d->udp_port) == 0 ? 0 : ztnx_driver_open_udp(d, 0);
}

int ztnx_driver_broken(const ZtnxDriver *d) { return d->broken; }

unsigned int ztnx_driver_reopens(const ZtnxDriver *d) { return d->reopens; }

int ztnx_driver_reopen(ZtnxDriver *d) {
    if (!d->udp_port) return -1;
    STEP("UDP reopen");
    ztnx_driver_suspend(d);
    d->reopens++;
    if (ztnx_driver_resume(d) == 0) return 0;
    d->broken = 1;  // e.g. still offline: try again later
    return -1;
}

int ztnx_driver_send(ZtnxDriver *d, uint32_t ip_be, uint16_t port, const void *data, size_t len, unsigned int ttl) {
    STEP("UDP send");
    if (d->udp_fd < 0) return -1;
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip_be;
    sin.sin_port = htons(port);
    // ZeroTier sends a few packets with a low hop limit on purpose: they open
    // our side of a NAT and are meant to die before reaching the other.
    int limited = 0;
    if (ttl) {
        const int hops = (int)ttl;
        limited = setsockopt(d->udp_fd, IPPROTO_IP, IP_TTL, &hops, sizeof hops) == 0;
        if (!limited) {
            // Sent at full range it would be the wrong packet.
            d->send_errno = -errno;
            d->send_ttl_failures++;
            return -1;
        }
    }
    // A full socket buffer drops the datagram.
    const ssize_t sent = sendto(d->udp_fd, data, len, 0, (struct sockaddr *)&sin, sizeof sin);
    if (limited) {
        const int hops = 64;
        setsockopt(d->udp_fd, IPPROTO_IP, IP_TTL, &hops, sizeof hops);
    }
    if (sent == (ssize_t)len) return 0;
    d->send_errno = sent < 0 ? errno : EMSGSIZE;
    if (sent < 0 && socket_gone(errno)) d->broken = 1;
    return -1;
}

int ztnx_driver_send_error(const ZtnxDriver *d, unsigned int *ttl_failures) {
    if (ttl_failures) *ttl_failures = d->send_ttl_failures;
    return d->send_errno;
}

// Reads one datagram into buf. Returns its length, or -1 when there's
// nothing (more) to read.
static ssize_t udp_read(ZtnxDriver *d, uint8_t *buf, size_t cap, struct sockaddr_in *from) {
    socklen_t flen = sizeof *from;
    memset(from, 0, sizeof *from);
    ssize_t got = recvfrom(d->udp_fd, buf, cap, 0, (struct sockaddr *)from, &flen);
    if (got < 0 && socket_gone(errno)) d->broken = 1;
    if (got < 0 || from->sin_family != AF_INET) return -1;
    return got;
}

// Reads datagrams one call each into sbuf's slots. Returns how many.
static int stage_each(ZtnxDriver *d) {
    int n = 0;
    while (n < UDP_STAGED) {
        uint8_t *slot = d->sbuf + (size_t)n * UDP_SLOT;
        struct sockaddr_in from;
        ssize_t got = udp_read(d, slot, UDP_SLOT, &from);
        if (got < 0) break;
        d->staged[n].ip_be = from.sin_addr.s_addr;
        d->staged[n].port = ntohs(from.sin_port);
        d->staged[n].data = slot;
        d->staged[n++].len = (size_t)got;
    }
    return n;
}

#ifdef __SWITCH__
// One bsdRecvMMsg for up to UDP_STAGED datagrams. libnx's recvmmsg mallocs,
// which libstratosphere's shim aborts on, so this does what it does with
// sbuf (page-aligned, like libnx's buffer): a 0x08 byte, then per message
// u32 namelen, name, s32 iovlen, iovlen x (u64 len, data), u32 controllen,
// control, s32 flags, s32 msg_len, rewritten by the reply with the actual
// lengths. Returns how many, or -1 with the socket service's errno in *err.
#define MMSG_HEAD (4 + 16 + 4 + 8)
#define MMSG_TAIL (4 + 4 + 4)
#define MMSG_CAP ((SBUF_SIZE - 1) / UDP_STAGED - MMSG_HEAD - MMSG_TAIL)
_Static_assert(MMSG_CAP >= 1500, "batched receive slots must hold a full datagram");
#define BSD_EAGAIN 11  // the socket service's errno numbering (Linux's)
// The same errors as socket_gone(), in that numbering.
static int bsd_socket_gone(int e) { return e == 32 /* EPIPE */ || e == 9 /* EBADF */ || e == 88 /* ENOTSOCK */ || e == 107 /* ENOTCONN */; }

static void put(uint8_t **p, const void *v, size_t n) {
    memcpy(*p, v, n);
    *p += n;
}

static int stage_batch(ZtnxDriver *d, int *err) {
    __handle *h = __get_handle(d->udp_fd);
    if (!h || !h->fileStruct) {
        *err = 0;
        return -1;
    }
    const int fd = *(const int *)h->fileStruct;  // as libnx's own fd lookup
    uint8_t *p = d->sbuf;
    *p++ = 0x08;
    for (int i = 0; i < UDP_STAGED; i++) {
        const uint32_t namelen = 16, controllen = 0;
        const int32_t iovlen = 1, zero = 0;
        const uint64_t cap = MMSG_CAP;
        put(&p, &namelen, 4);
        memset(p, 0, 16);
        p += 16;
        put(&p, &iovlen, 4);
        put(&p, &cap, 8);
        p += MMSG_CAP;
        put(&p, &controllen, 4);
        put(&p, &zero, 4);
        put(&p, &zero, 4);
    }
    struct timespec no_timeout = {0};  // read unconditionally
    int n = bsdRecvMMsg(fd, d->sbuf, SBUF_SIZE, UDP_STAGED, MSG_DONTWAIT, &no_timeout);
    if (n < 0) {
        *err = g_bsdErrno;
        return -1;
    }
    const size_t size = SBUF_SIZE;
    size_t off = 1;
    int got = 0;
    for (int i = 0; i < n && i < UDP_STAGED; i++) {
        uint32_t namelen, controllen;
        int32_t iovlen;
        struct sockaddr_in from;
        memset(&from, 0, sizeof from);
        if (off + 4 > size) break;
        memcpy(&namelen, d->sbuf + off, 4);
        off += 4;
        if (namelen > size - off) break;
        memcpy(&from, d->sbuf + off, namelen < sizeof from ? namelen : sizeof from);
        off += namelen;
        if (off + 4 > size) break;
        memcpy(&iovlen, d->sbuf + off, 4);
        off += 4;
        const uint8_t *data = NULL;
        uint64_t len = 0;
        int ok = iovlen >= 0;
        for (int32_t v = 0; v < iovlen && ok; v++) {
            uint64_t l;
            if (off + 8 > size) {
                ok = 0;
                break;
            }
            memcpy(&l, d->sbuf + off, 8);
            off += 8;
            if (l > size - off) {
                ok = 0;
                break;
            }
            if (v == 0) {
                data = d->sbuf + off;
                len = l;
            }
            off += (size_t)l;
        }
        if (!ok || off + 4 > size) break;
        memcpy(&controllen, d->sbuf + off, 4);
        off += 4;
        if (controllen > size - off || off + controllen + 8 > size) break;
        int32_t msg_len;
        memcpy(&msg_len, d->sbuf + off + controllen + 4, 4);
        off += controllen + 8;  // control, flags, msg_len
        // The datagram's size is msg_len: the reply can leave the iovec at
        // its full capacity.
        if (msg_len >= 0 && (uint64_t)msg_len < len) len = (uint64_t)msg_len;
        if (!data || from.sin_family != AF_INET) continue;
        d->staged[got].ip_be = from.sin_addr.s_addr;
        d->staged[got].port = ntohs(from.sin_port);
        d->staged[got].data = data;
        d->staged[got++].len = (size_t)len;
    }
    return got;
}
#endif

// Reads up to UDP_STAGED datagrams into d->staged (called when the socket
// was reported readable). Returns how many.
static int stage(ZtnxDriver *d) {
#ifdef __SWITCH__
    if (d->mmsg_state >= 0) {
        int err = 0;
        int n = stage_batch(d, &err);
        if (n > 0) {
            d->mmsg_state = 1;
            return n;
        }
        if (n < 0 && bsd_socket_gone(err)) {
            d->broken = 1;  // the socket, not batching, is what failed
            return 0;
        }
        if (n < 0 && err != BSD_EAGAIN) {
            d->mmsg_state = -1;  // unsupported here: one datagram per call
            d->mmsg_errno = err;
        } else if (d->mmsg_state == 0) {
            // Empty though poll said readable: check that it isn't the
            // batch that's broken (then recvfrom finds a datagram).
            n = stage_each(d);
            if (n > 0 && ++d->mmsg_misses >= 3) d->mmsg_state = -1;
            return n;
        } else {
            return 0;
        }
    }
#endif
    return stage_each(d);
}

int ztnx_driver_pollfds(ZtnxDriver *d, struct pollfd *fds, int cap) {
    int n = 0;
    d->poll_udp = -1;
    if (d->udp_fd >= 0 && n < cap) {
        d->poll_udp = n;
        fds[n].fd = d->udp_fd;
        fds[n].events = POLLIN;
        fds[n++].revents = 0;
    }
    return n;
}

int ztnx_driver_recv(ZtnxDriver *d, const struct pollfd *fds) {
    d->n_staged = 0;
    if (d->udp_fd < 0 || d->poll_udp < 0) return 0;
    const short rev = fds[d->poll_udp].revents;
    if (rev & POLLNVAL) {
        d->broken = 1;
    } else if (rev & (POLLERR | POLLHUP)) {
        // Reading SO_ERROR clears an error left by an ICMP message (port
        // unreachable and the like), which would otherwise make every
        // poll() return at once; only a gone socket needs reopening.
        int err = 0;
        socklen_t len = sizeof err;
        if (getsockopt(d->udp_fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 ? socket_gone(errno) : socket_gone(err))
            d->broken = 1;
    }
    if (d->broken || !(rev & POLLIN)) return 0;
    STEP("UDP receive");
    d->n_staged = stage(d);
    d->backlog = d->n_staged >= UDP_STAGED;
    return d->n_staged;
}

void ztnx_driver_staged(const ZtnxDriver *d, int i, const uint8_t **data, size_t *len, uint32_t *ip_be, uint16_t *port) {
    *data = d->staged[i].data;
    *len = d->staged[i].len;
    *ip_be = d->staged[i].ip_be;
    *port = d->staged[i].port;
}

int ztnx_driver_poll(ZtnxDriver *d, struct pollfd *fds, int nfds, int wait_ms) {
    if (d->backlog && d->poll_udp >= 0 && d->backlog_rounds < UDP_BACKLOG_ROUNDS) {
        d->backlog_rounds++;
        for (int i = 0; i < nfds; i++) fds[i].revents = 0;
        fds[d->poll_udp].revents = POLLIN;
        return 1;
    }
    d->backlog = 0;  // the recv after this poll sets it again
    d->backlog_rounds = 0;
    STEP("poll");
    return poll(fds, (nfds_t)nfds, wait_ms);
}

int ztnx_driver_batched_receive(ZtnxDriver *d, int *bsd_errno) {
    if (bsd_errno) *bsd_errno = d->mmsg_errno;
    return d->mmsg_state;
}
