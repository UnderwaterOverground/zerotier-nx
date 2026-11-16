// The engine's UDP socket: opening it, reading datagrams a batch at a time,
// sending. Portable (POSIX sockets + poll): runs unchanged on macOS/Linux
// for testing and on Horizon via libnx's BSD socket layer.
//
// It knows nothing of ZeroTier or the stack. Everything here is called by
// the engine thread (native/runtime), without the runtime lock: each socket
// call is an IPC on the Switch, and callers of the stack must not wait
// those out.
#pragma once

#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ZtnxDriver ZtnxDriver;

ZtnxDriver *ztnx_driver_new(void);
void ztnx_driver_free(ZtnxDriver *d);

// Opens the UDP socket on `port` (0 = any). Returns 0, or -1 on failure
// (the engine then cannot talk to anyone).
int ztnx_driver_open_udp(ZtnxDriver *d, uint16_t port);
// The port the UDP socket is bound to (0 if none).
uint16_t ztnx_driver_udp_port(const ZtnxDriver *d);
// Why the last failed send failed: its errno, negated if it was setting a
// packet's hop limit that failed (those packets are then not sent at all;
// ttl_failures counts them). 0 if none has failed.
int ztnx_driver_send_error(const ZtnxDriver *d, unsigned int *ttl_failures);

// The last place the driver entered (a static string, NULL before any): if
// the thread driving it seems stuck, this names where it went last.
const char *ztnx_driver_step(void);

// Closes the UDP socket, e.g. before the console sleeps. Resume reopens it
// (on the same port if possible).
void ztnx_driver_suspend(ZtnxDriver *d);
int ztnx_driver_resume(ZtnxDriver *d);

// Whether the socket service has dropped the UDP socket (a send or receive
// said so): the network went away without a sleep, e.g. Airplane Mode. The
// engine thread then reopens it, same port if possible; reopens counts
// those. Engine thread only.
int ztnx_driver_broken(const ZtnxDriver *d);
int ztnx_driver_reopen(ZtnxDriver *d);
unsigned int ztnx_driver_reopens(const ZtnxDriver *d);

// Whether the UDP socket is read a burst per call (Switch only): 1 yes, 0
// not known yet, -1 no (*bsd_errno: the socket service's errno if a call
// failed, else 0).
int ztnx_driver_batched_receive(ZtnxDriver *d, int *bsd_errno);

// Most file descriptors the driver polls (its UDP socket).
#define ZTNX_DRIVER_MAX_FDS 1
// Most datagrams one ztnx_driver_recv returns.
#define ZTNX_DRIVER_BATCH 16

// One round:
//   n = ztnx_driver_pollfds(d, fds, cap);        // fills fds[0..n)
//   ztnx_driver_poll(d, fds, n + extra, wait);   // extra: the caller's own fds
//   m = ztnx_driver_recv(d, fds);                // reads what the poll reported
//   for (i < m) ztnx_driver_staged(d, i, ...);   // valid until the next recv
int ztnx_driver_pollfds(ZtnxDriver *d, struct pollfd *fds, int cap);

// poll(). When the last recv filled a whole batch the socket most likely has
// more queued: this reports it readable at once (and the caller's other fds
// idle) instead of spending a poll on it, for up to a few rounds in a row. A
// burst then drains a batch per round with one socket call each, rather
// than overflowing the socket's buffer while the loop waits on poll().
int ztnx_driver_poll(ZtnxDriver *d, struct pollfd *fds, int nfds, int wait_ms);

// Reads up to ZTNX_DRIVER_BATCH datagrams if the poll reported the socket
// readable. Returns how many. A busy socket stays readable: the next round
// reads the rest (handing an app a whole burst at once overflows its queue).
int ztnx_driver_recv(ZtnxDriver *d, const struct pollfd *fds);
// The i-th datagram of the last recv: its bytes and sender (address in
// network byte order, port in host order).
void ztnx_driver_staged(const ZtnxDriver *d, int i, const uint8_t **data, size_t *len, uint32_t *ip_be, uint16_t *port);

// Sends a datagram, best effort like any UDP send. ttl 0 is the default; a
// value sets the packet's hop limit for this one send. Returns 0, or -1 if
// the socket is closed or the send failed.
int ztnx_driver_send(ZtnxDriver *d, uint32_t ip_be, uint16_t port, const void *data, size_t len, unsigned int ttl);

// Monotonic clock in nanoseconds, as fed to the stack.
uint64_t ztnx_driver_now_ns(void);

#ifdef __cplusplus
}
#endif
