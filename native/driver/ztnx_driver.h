// Portable (POSIX sockets + poll) driver for the ztnx engine. Runs unchanged
// on macOS/Linux for testing and on Horizon via libnx's BSD socket layer.
#pragma once

#include <poll.h>
#include <stdint.h>

#include "ztnx.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ZtnxDriver ZtnxDriver;

// Called for every engine status event.
typedef void (*ztnx_event_fn)(void *ctx, const ZtnxEvent *ev);

ZtnxDriver *ztnx_driver_new(ZtnxEngine *engine, ztnx_event_fn on_event, void *ctx);
void ztnx_driver_free(ZtnxDriver *d);

// Opens the engine's UDP socket on `port` (0 = any). Returns 0, or -1 on
// failure (the engine then cannot talk to anyone).
int ztnx_driver_open_udp(ZtnxDriver *d, uint16_t port);
// The port the UDP socket is bound to (0 if none).
uint16_t ztnx_driver_udp_port(const ZtnxDriver *d);

// The last place the driver entered (a static string, NULL before any): if
// the thread driving it seems stuck, this names where it went last.
const char *ztnx_driver_step(void);

// Closes the UDP socket, e.g. before the console sleeps. Resume reopens it
// (on the same port if possible); call ztnx_engine_network_up afterwards
// so peers are contacted again at once.
void ztnx_driver_suspend(ZtnxDriver *d);
int ztnx_driver_resume(ZtnxDriver *d);

// Whether the driver answers ZTNX_EVENT_RESOLVE itself with a blocking
// ztnx_resolve_ipv4 (default: yes) before forwarding the event. Embedders
// that must not block the engine thread turn this off and resolve from the
// event on their own, then call ztnx_engine_set_peer_endpoint.
void ztnx_driver_resolve_inline(ZtnxDriver *d, int on);

// Whether the UDP socket is read a burst per call (Switch only): 1 yes, 0
// not known yet, -1 no (*bsd_errno: the socket service's errno if a call
// failed, else 0).
int ztnx_driver_batched_receive(ZtnxDriver *d, int *bsd_errno);

// Most file descriptors the driver polls (its UDP socket).
#define ZTNX_DRIVER_MAX_FDS 1

// Split form of ztnx_driver_run_once, for callers that poll extra fds or
// must not hold a lock while blocked (see native/runtime):
//   n = ztnx_driver_prepare(d, fds, cap, max_wait, &wait);  // fills fds[0..n)
//   poll(fds, n + extra, wait);
//   ztnx_driver_dispatch(d, fds);                           // reads fds[0..n)
int ztnx_driver_prepare(ZtnxDriver *d, struct pollfd *fds, int cap, int max_wait_ms, int *wait_ms);
void ztnx_driver_dispatch(ZtnxDriver *d, const struct pollfd *fds);

// Optional, between poll and dispatch, on the thread that dispatches: reads
// datagrams the poll reported into the driver's own buffers. It touches no
// engine state, so a caller that serializes engine access can run it
// without that lock and hold the lock for less time. The dispatch after it
// then hands over only those (up to 16) and reads no more: a busy socket
// stays readable, and the next round's prefetch reads the rest.
void ztnx_driver_prefetch(ZtnxDriver *d, const struct pollfd *fds);

// poll() for the split form. When the last prefetch filled a whole batch the
// socket most likely has more queued: this reports it readable at once (and
// the caller's other fds idle) instead of spending a poll on it, for up to
// a few rounds in a row. A burst then drains a batch per round with one
// socket call each, rather than overflowing the socket's buffer while the
// loop waits on poll(); each poll is an IPC on the Switch.
int ztnx_driver_poll(ZtnxDriver *d, struct pollfd *fds, int nfds, int wait_ms);

// Performs engine I/O queued since the last call (e.g. after overlay socket
// operations) without waiting.
void ztnx_driver_pump(ZtnxDriver *d);

// After ztnx_driver_prepare: whether a poll it set up, which waits until
// `until_ns` at the latest, no longer covers everything (the socket was
// reopened, or the engine's next deadline moved earlier). Callers that wake
// a sleeping poll after engine calls only need to when this is true.
int ztnx_driver_poll_stale(ZtnxDriver *d, uint64_t until_ns);

// Performs pending engine I/O, waits up to max_wait_ms for the socket or
// the engine's next deadline, and dispatches results. Returns 0, or -1 on
// a fatal driver error.
int ztnx_driver_run_once(ZtnxDriver *d, int max_wait_ms);

// Monotonic clock in nanoseconds, as fed to the engine.
uint64_t ztnx_driver_now_ns(void);

#ifdef __cplusplus
}
#endif
