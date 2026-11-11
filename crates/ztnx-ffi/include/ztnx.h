// C interface to the ztnx Rust core (crates/ztnx-ffi): the userspace TCP/IP
// stack homebrew sockets are mapped onto, its Ethernet layer, and TLS for the
// update check. ZeroTier's core is separate (native/zt/ztnx_engine.h).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *ztnx_version(void);

// Routes the core's log records to cb (level 1 error .. 5 trace; msg valid
// only during the call). max_level 0 disables logging.
typedef void (*ztnx_log_fn)(uint32_t level, const char *msg);
void ztnx_set_log_callback(ztnx_log_fn cb, uint32_t max_level);

// Rust heap usage (bytes): current and high-water mark.
void ztnx_heap_stats(size_t *current, size_t *peak);

// Live Rust heap by allocation size class as text ("<=64:12K/310 ..." =
// KB/allocations per class), NUL-terminated. Returns the length written.
size_t ztnx_heap_classes(char *buf, size_t len);

// Seeds the core's CSPRNG with 32 bytes of entropy. Call once at startup.
void ztnx_seed_rng(const uint8_t seed[32]);

// Fills buf from the core's CSPRNG. False if it has not been seeded yet.
bool ztnx_random_bytes(uint8_t *buf, size_t len);

// Wall-clock time (Unix seconds) used for certificate validity checks (the
// update check's TLS).
void ztnx_set_unix_time(uint64_t unix_secs);

// Standalone TLS 1.3 session; the caller moves bytes between it and a socket.
typedef struct ZtnxTls ZtnxTls;
#define ZTNX_TLS_ESTABLISHED 1u
#define ZTNX_TLS_PEER_CLOSED 2u
#define ZTNX_TLS_FAILED 4u
ZtnxTls *ztnx_tls_new(const char *server_name);
void ztnx_tls_free(ZtnxTls *s);
int ztnx_tls_feed(ZtnxTls *s, const uint8_t *data, size_t len);
int ztnx_tls_write(ZtnxTls *s, const uint8_t *data, size_t len);
size_t ztnx_tls_take_outgoing(ZtnxTls *s, uint8_t *buf, size_t cap);
size_t ztnx_tls_read(ZtnxTls *s, uint8_t *buf, size_t cap);
uint32_t ztnx_tls_state(const ZtnxTls *s);
const char *ztnx_tls_last_error(const ZtnxTls *s);

// ---- The stack ---------------------------------------------------------------
// One per process, guarded by the caller's lock. Time is the caller's
// monotonic clock in nanoseconds.
//
// Every use is bracketed: ztnx_stack_begin(now), then socket calls and/or
// frames arriving, then ztnx_stack_end(), which runs the TCP/IP stack once
// over all of it and says whether frames are waiting to be sent. The one
// thread that may call ZeroTier takes them with ztnx_l2_next_out.

typedef struct ZtnxStack ZtnxStack;

typedef struct ZtnxAddr {
    uint8_t family;  // 4 or 6
    uint8_t ip[16];  // IPv4 uses the first 4 bytes
    uint16_t port;
} ZtnxAddr;

typedef struct ZtnxPrefix {
    uint8_t family;  // 4 or 6
    uint8_t len;
    uint8_t ip[16];  // IPv4 uses the first 4 bytes
    uint8_t reserved[6];
} ZtnxPrefix;

// One of our addresses on the network, with its prefix length.
typedef struct ZtnxV4Net {
    uint8_t ip[4];
    uint8_t prefix;
    uint8_t reserved[3];
} ZtnxV4Net;

// A managed route: target/prefix through via, or on-link if has_via is 0.
typedef struct ZtnxV4Route {
    uint8_t target[4];
    uint8_t prefix;
    uint8_t has_via;
    uint8_t reserved[2];
    uint8_t via[4];
} ZtnxV4Route;

typedef struct ZtnxStackStats {
    uint32_t arp_broadcasts;  // broadcast ARP requests sent
    uint32_t arp_limited;     // requests held back by the broadcast budget
    uint32_t unresolved;      // packets dropped waiting for a neighbour's MAC
    uint32_t unroutable;      // packets with nowhere to go
    uint32_t out_queued;      // IP packets waiting to be sent
    uint32_t reserved;
} ZtnxStackStats;

ZtnxStack *ztnx_stack_new(uint64_t now_ns);
void ztnx_stack_free(ZtnxStack *s);

#define ZTNX_OUT_PENDING 1u  // frames are waiting for ztnx_l2_next_out
#define ZTNX_CHANGED 2u      // socket state may have changed: wake waiters
void ztnx_stack_begin(ZtnxStack *s, uint64_t now_ns);
uint32_t ztnx_stack_end(ZtnxStack *s);

// When begin/end should next run if nothing happens first (TCP timers, ARP
// retries); UINT64_MAX if never.
uint64_t ztnx_stack_next_deadline(ZtnxStack *s);
bool ztnx_stack_out_pending(ZtnxStack *s);
// After a sleep or a change of network underneath: drops what was queued and
// re-checks neighbours as they are used.
void ztnx_stack_link_reset(ZtnxStack *s);
void ztnx_stack_stats(ZtnxStack *s, ZtnxStackStats *out);

// ---- Ethernet (the ZeroTier side) --------------------------------------------
// MACs are 48-bit values as ZeroTier writes them: first octet in bits 40-47.

#define ZTNX_ETHERTYPE_IPV4 0x0800u
#define ZTNX_ETHERTYPE_ARP 0x0806u

// The network is up, or its configuration changed. mac is ours; mtu the
// network's. False if there is no address or an argument is invalid.
bool ztnx_l2_configure(ZtnxStack *s, uint64_t nwid, uint64_t mac, uint16_t mtu,
                       const ZtnxV4Net *addrs, size_t n_addrs,
                       const ZtnxV4Route *routes, size_t n_routes);
// The network is gone. Sockets stay open; their packets go nowhere.
void ztnx_l2_down(ZtnxStack *s);
// A frame arrived from the network. Call between begin and end.
void ztnx_l2_frame_in(ZtnxStack *s, uint64_t src_mac, uint64_t dst_mac, uint32_t ethertype,
                      const uint8_t *data, size_t len);
// Takes the next frame to send: its payload into buf, returning the length,
// or 0 if there is none this time or it needs more room than cap
// (ztnx_stack_out_pending says whether to ask again; a frame that didn't fit
// is kept for the next call). The source MAC is ours.
size_t ztnx_l2_next_out(ZtnxStack *s, uint8_t *buf, size_t cap, uint64_t *dst_mac, uint32_t *ethertype);

// A device on the network whose MAC is known (from ARP).
typedef struct {
    uint64_t mac;
    uint8_t ip[4];
    uint8_t reserved[4];
} ZtnxNeighbor;
// Those devices: up to max into out. Returns how many were written (the
// stack keeps at most 32).
size_t ztnx_l2_neighbors(ZtnxStack *s, ZtnxNeighbor *out, size_t max);

// ---- Overlay sockets (network side) ------------------------------------------
// Non-blocking. Ids are > 0; errors are negative ZTNX_E* codes. Call between
// begin and end (ztnx_net_udp_recvfrom, readiness and the address getters
// need neither).

#define ZTNX_EAGAIN (-1)
#define ZTNX_ENOTCONN (-2)
#define ZTNX_EBADF (-3)
#define ZTNX_EADDRINUSE (-4)
#define ZTNX_ECONNREFUSED (-5)
#define ZTNX_ECONNRESET (-6)
#define ZTNX_EINVAL (-7)
#define ZTNX_ENOBUFS (-8)

#define ZTNX_READABLE 1u
#define ZTNX_WRITABLE 2u
#define ZTNX_HUP 4u

int32_t ztnx_net_tcp_connect(ZtnxStack *s, const ZtnxAddr *dst);
int32_t ztnx_net_tcp_listen(ZtnxStack *s, uint16_t port, uint32_t backlog);
int32_t ztnx_net_tcp_accept(ZtnxStack *s, int32_t id, ZtnxAddr *peer);
int32_t ztnx_net_send(ZtnxStack *s, int32_t id, const uint8_t *data, size_t len);
int32_t ztnx_net_recv(ZtnxStack *s, int32_t id, uint8_t *buf, size_t len);
int32_t ztnx_net_shutdown(ZtnxStack *s, int32_t id);
int32_t ztnx_net_udp_bind(ZtnxStack *s, uint16_t port);
int32_t ztnx_net_udp_sendto(ZtnxStack *s, int32_t id, const uint8_t *data, size_t len, const ZtnxAddr *dst);
int32_t ztnx_net_udp_recvfrom(ZtnxStack *s, int32_t id, uint8_t *buf, size_t len, ZtnxAddr *src);
uint32_t ztnx_net_readiness(ZtnxStack *s, int32_t id);
// Bytes of overlay socket buffers in use (TCP buffers, queued datagrams).
size_t ztnx_net_buffer_usage(ZtnxStack *s);
// Most bytes of overlay socket buffers allowed at once (new TCP connections
// get smaller buffers as it fills; past it they fail with ZTNX_ENOBUFS).
void ztnx_net_set_budget(ZtnxStack *s, size_t bytes);
void ztnx_net_close(ZtnxStack *s, int32_t id);
int32_t ztnx_net_local_addr(ZtnxStack *s, int32_t id, ZtnxAddr *out);
int32_t ztnx_net_peer_addr(ZtnxStack *s, int32_t id, ZtnxAddr *out);

// Must be provided by the embedding program on no_std targets. Called with a
// (non NUL-terminated) panic message; must not return.
#ifdef __cplusplus
[[noreturn]]
#else
_Noreturn
#endif
void ztnx_platform_panic(const uint8_t *msg, size_t len);

#ifdef __cplusplus
}
#endif
