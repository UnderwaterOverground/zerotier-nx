// See ztnx_driver.h.
#include "ztnx_driver.h"

#include "ztnx_dns.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
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

#ifdef ZTNX_NO_STDIO
// Builds without newlib's printf (the sysmodule) supply this instead.
int ztnx_snprintf(char *dst, size_t size, const char *fmt, ...);
#define snprintf ztnx_snprintf
#endif

// Datagrams read per readiness report: the rest wait for the next round, so
// a socket that keeps "returning" something can't hold the loop.
#define UDP_RECV_BATCH 64
// Rounds in a row ztnx_driver_poll may skip poll() while the socket is
// backlogged, before it polls anyway (for the caller's other fds).
#define UDP_BACKLOG_ROUNDS 8
// Datagrams are read UDP_STAGED at a time into sbuf (page-aligned: on the
// Switch it is also the socket service's message buffer), UDP_SLOT bytes
// each (underlay datagrams fit), and handed to the engine from there.
#define UDP_STAGED 16
#define UDP_SLOT 2048
#define SBUF_SIZE (UDP_STAGED * UDP_SLOT)

static const char *volatile g_step;
#define STEP(s) (g_step = (s))
const char *ztnx_driver_step(void) { return g_step; }

struct ZtnxDriver {
    ZtnxEngine *engine;
    ztnx_event_fn on_event;
    void *ctx;
    int udp_fd;
    uint16_t udp_port;
    int resolve_inline;
    // Bookkeeping between prepare and dispatch.
    int poll_udp, poll_udp_fd;
    uint64_t poll_deadline;  // the engine's next deadline when prepared
    // Datagrams read but not yet handed to the engine (in sbuf).
    uint8_t *sbuf;
    struct {
        const uint8_t *data;
        size_t len;
        ZtnxAddr src;
    } staged[UDP_STAGED];
    int n_staged, staged_all;  // staged_all: the socket was drained
    int prefetched;            // staged by ztnx_driver_prefetch, without the caller's lock
    int backlog;               // the last prefetch filled a batch: likely more queued
    int backlog_rounds;        // polls skipped in a row for it
    // Batched receive (Switch): 1 works, 0 not known yet, -1 off (and the
    // socket service's errno, if a call failed); misses: batches that came
    // back empty while recvfrom then found a datagram.
    int mmsg_state, mmsg_errno, mmsg_misses;
};

uint64_t ztnx_driver_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

ZtnxDriver *ztnx_driver_new(ZtnxEngine *engine, ztnx_event_fn on_event, void *ctx) {
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
    d->engine = engine;
    d->on_event = on_event;
    d->ctx = ctx;
    d->udp_fd = -1;
    d->poll_udp_fd = -1;
    d->resolve_inline = 1;
    return d;
}

void ztnx_driver_free(ZtnxDriver *d) {
    if (!d) return;
    free(d->sbuf);
    if (d->udp_fd >= 0) close(d->udp_fd);
    free(d);
}

void ztnx_driver_resolve_inline(ZtnxDriver *d, int on) { d->resolve_inline = on; }

uint16_t ztnx_driver_udp_port(const ZtnxDriver *d) { return d->udp_fd >= 0 ? d->udp_port : 0; }

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void to_ztnx_addr(const struct sockaddr_in *sin, ZtnxAddr *out) {
    memset(out, 0, sizeof *out);
    out->family = 4;
    memcpy(out->ip, &sin->sin_addr, 4);
    out->port = ntohs(sin->sin_port);
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
    d->backlog = 0;
}

int ztnx_driver_resume(ZtnxDriver *d) {
    if (d->udp_fd >= 0 || !d->udp_port) return 0;
    // Same port as before, so peers' notion of our endpoint stays valid.
    return ztnx_driver_open_udp(d, d->udp_port) == 0 ? 0 : ztnx_driver_open_udp(d, 0);
}

static void udp_send(ZtnxDriver *d, const ZtnxAddr *to, const uint8_t *data, size_t len) {
    STEP("UDP send");
    if (d->udp_fd < 0 || to->family != 4) return;  // IPv6 underlay: not yet
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    memcpy(&sin.sin_addr, to->ip, 4);
    sin.sin_port = htons(to->port);
    // Best effort, like any UDP send: a full socket buffer drops the datagram.
    sendto(d->udp_fd, data, len, 0, (struct sockaddr *)&sin, sizeof sin);
}

// Reads one datagram into buf. Returns its length, or -1 when there's
// nothing (more) to read.
static ssize_t udp_read(ZtnxDriver *d, uint8_t *buf, size_t cap, ZtnxAddr *src) {
    struct sockaddr_in from;
    socklen_t flen = sizeof from;
    memset(&from, 0, sizeof from);
    ssize_t got = recvfrom(d->udp_fd, buf, cap, 0, (struct sockaddr *)&from, &flen);
    if (got < 0 || from.sin_family != AF_INET) return -1;
    to_ztnx_addr(&from, src);
    return got;
}

// Reads datagrams one call each into sbuf's slots. Returns how many.
static int stage_each(ZtnxDriver *d) {
    int n = 0;
    while (n < UDP_STAGED) {
        uint8_t *slot = d->sbuf + (size_t)n * UDP_SLOT;
        ssize_t got = udp_read(d, slot, UDP_SLOT, &d->staged[n].src);
        if (got < 0) break;
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
        to_ztnx_addr(&from, &d->staged[got].src);
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

void ztnx_driver_prefetch(ZtnxDriver *d, const struct pollfd *fds) {
    d->n_staged = 0;
    d->staged_all = 0;
    d->prefetched = 1;
    if (d->poll_udp < 0 || !(fds[d->poll_udp].revents & POLLIN)) return;
    STEP("UDP prefetch");
    d->n_staged = stage(d);
    d->staged_all = d->n_staged < UDP_STAGED;
    d->backlog = !d->staged_all;
}

int ztnx_driver_poll(ZtnxDriver *d, struct pollfd *fds, int nfds, int wait_ms) {
    if (d->backlog && d->poll_udp >= 0 && d->backlog_rounds < UDP_BACKLOG_ROUNDS) {
        d->backlog_rounds++;
        for (int i = 0; i < nfds; i++) fds[i].revents = 0;
        fds[d->poll_udp].revents = POLLIN;
        return 1;
    }
    d->backlog = 0;  // the prefetch after this poll sets it again
    d->backlog_rounds = 0;
    return poll(fds, (nfds_t)nfds, wait_ms);
}

// Hands the staged datagrams to the engine, then reads and hands over more
// until the socket is drained (or UDP_RECV_BATCH, so it can't hold the loop).
// After a prefetch it reads no more: the caller holds its lock now, and an
// app reading what we deliver would wait out every read. A video frame
// arrives as a burst of datagrams, and delivered all at once it overflows
// the app's socket queue; the rest is read by the next round's prefetch.
static void udp_receive(ZtnxDriver *d) {
    int handled = 0;
    const int prefetched = d->prefetched;
    d->prefetched = 0;
    for (;;) {
        for (int i = 0; i < d->n_staged; i++)
            ztnx_engine_udp(d->engine, &d->staged[i].src, d->staged[i].data, d->staged[i].len, ztnx_driver_now_ns());
        handled += d->n_staged;
        const int drained = d->staged_all;
        d->n_staged = 0;
        d->staged_all = 0;
        if (drained || prefetched || handled >= UDP_RECV_BATCH) return;
        STEP("UDP receive");
        d->n_staged = stage(d);
        d->staged_all = d->n_staged < UDP_STAGED;
    }
}

int ztnx_driver_batched_receive(ZtnxDriver *d, int *bsd_errno) {
    if (bsd_errno) *bsd_errno = d->mmsg_errno;
    return d->mmsg_state;
}

// Answers a RESOLVE event with a blocking lookup (see ztnx_driver_resolve_inline).
static void resolve_endpoint(ZtnxDriver *d, const ZtnxEvent *ev) {
    STEP("endpoint lookup");
    uint32_t ip;
    if (ztnx_resolve_ipv4(ev->text, &ip) != 0) return;
    ZtnxAddr addr;
    memset(&addr, 0, sizeof addr);
    addr.family = 4;
    memcpy(addr.ip, &ip, 4);
    addr.port = ev->port;
    ztnx_engine_set_peer_endpoint(d->engine, ev->value, &addr, ztnx_driver_now_ns());
}

// Drains engine I/O requests and events.
static void pump_engine(ZtnxDriver *d) {
    STEP("engine I/O");
    ZtnxIo io;
    while (ztnx_engine_poll_io(d->engine, &io))
        if (io.kind == ZTNX_IO_SEND_UDP) udp_send(d, &io.addr, io.data, io.len);
    ZtnxEvent ev;
    while (ztnx_engine_poll_event(d->engine, &ev)) {
        if (ev.kind == ZTNX_EVENT_RESOLVE && d->resolve_inline) resolve_endpoint(d, &ev);
        if (d->on_event) d->on_event(d->ctx, &ev);
    }
}

void ztnx_driver_pump(ZtnxDriver *d) { pump_engine(d); }

int ztnx_driver_prepare(ZtnxDriver *d, struct pollfd *fds, int cap, int max_wait_ms, int *wait_ms) {
    uint64_t now = ztnx_driver_now_ns();
    if (now >= ztnx_engine_next_deadline(d->engine)) ztnx_engine_timeout(d->engine, now);
    pump_engine(d);

    int n = 0;
    d->poll_udp = -1;
    d->poll_udp_fd = -1;
    if (d->udp_fd >= 0 && n < cap) {
        d->poll_udp = n;
        d->poll_udp_fd = d->udp_fd;
        fds[n].fd = d->udp_fd;
        fds[n].events = POLLIN;
        fds[n++].revents = 0;
    }

    uint64_t deadline = ztnx_engine_next_deadline(d->engine);
    d->poll_deadline = deadline;
    now = ztnx_driver_now_ns();
    int wait = max_wait_ms;
    if (deadline <= now) {
        wait = 0;
    } else if ((deadline - now) / 1000000 < (uint64_t)wait) {
        wait = (int)((deadline - now) / 1000000) + 1;
    }
    *wait_ms = wait;
    return n;
}

int ztnx_driver_poll_stale(ZtnxDriver *d, uint64_t until_ns) {
    if (d->udp_fd != d->poll_udp_fd) return 1;
    // The poll's timeout is rounded up past the deadline it was set for, so
    // only a deadline earlier than that one is news.
    const uint64_t deadline = ztnx_engine_next_deadline(d->engine);
    return deadline < d->poll_deadline && deadline < until_ns;
}

void ztnx_driver_dispatch(ZtnxDriver *d, const struct pollfd *fds) {
    if (d->poll_udp >= 0 && (fds[d->poll_udp].revents & POLLIN)) udp_receive(d);
    pump_engine(d);
}

int ztnx_driver_run_once(ZtnxDriver *d, int max_wait_ms) {
    struct pollfd fds[ZTNX_DRIVER_MAX_FDS];
    int wait;
    int n = ztnx_driver_prepare(d, fds, ZTNX_DRIVER_MAX_FDS, max_wait_ms, &wait);
    int rc = poll(fds, (nfds_t)n, wait);
    if (rc < 0 && errno != EINTR) return -1;
    if (rc > 0) ztnx_driver_dispatch(d, fds);
    return 0;
}
