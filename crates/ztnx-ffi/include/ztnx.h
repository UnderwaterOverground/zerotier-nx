// C interface to the ztnx Rust core (crates/ztnx-ffi).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Selftest failure codes returned by ztnx_selftest().
enum ztnx_selftest_failure {
    ZTNX_SELFTEST_OK = 0,
    ZTNX_SELFTEST_X25519 = 1,
    ZTNX_SELFTEST_AEAD_SEAL = 2,
    ZTNX_SELFTEST_AEAD_OPEN = 3,
    ZTNX_SELFTEST_AEAD_TAMPER = 4,
    ZTNX_SELFTEST_BLAKE2S = 5,
};

const char *ztnx_version(void);
uint32_t ztnx_selftest(void);
uint64_t ztnx_bench_aead(size_t packet_len, uint32_t iterations);
uint64_t ztnx_bench_x25519(uint32_t iterations);

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

// ---- Engine ----------------------------------------------------------------
// A WireGuard interface configured from a wg-quick style .conf. The caller
// owns the UDP socket and the clock: perform the sends it requests, feed
// datagrams back, answer ZTNX_EVENT_RESOLVE, and call ztnx_engine_timeout by
// ztnx_engine_next_deadline. Times are monotonic nanoseconds.

typedef struct ZtnxEngine ZtnxEngine;

typedef struct {
    const char *conf;  // the .conf text (UTF-8; need not be NUL-terminated)
    size_t conf_len;
} ZtnxConfig;

typedef struct {
    uint8_t family;  // 4 or 6
    uint8_t ip[16];  // IPv4 in the first 4 bytes
    uint16_t port;
} ZtnxAddr;

typedef struct {
    uint8_t family;       // 4 or 6
    uint8_t len;          // prefix length
    uint8_t ip[16];       // IPv4 in the first 4 bytes
    uint8_t reserved[6];
} ZtnxPrefix;             // 24 bytes

#define ZTNX_IO_SEND_UDP 1u  // send data as one datagram to addr from the engine's UDP socket

typedef struct {
    uint32_t kind;
    uint32_t reserved;
    const uint8_t *data;  // valid until the next ztnx_engine_poll_io
    size_t len;
    ZtnxAddr addr;
} ZtnxIo;

#define ZTNX_EVENT_LOG 0u
#define ZTNX_EVENT_ADDRESSES 1u  // text "10.7.0.2/24 ..."; value = count. Once per reload.
#define ZTNX_EVENT_PEERS 2u      // value = configured peers. Once per reload.
#define ZTNX_EVENT_ERROR 3u
// value = peer index, text = its Endpoint's host name, port = the port:
// resolve it and call ztnx_engine_set_peer_endpoint. Repeated every 30 s
// while the peer stays silent (the C driver answers it itself unless a
// resolver hook takes over; see ztnx_driver.h).
#define ZTNX_EVENT_RESOLVE 4u
#define ZTNX_EVENT_HANDSHAKE 5u  // value = peer index, text = its name: a handshake completed
#define ZTNX_EVENT_PEER_LOST 6u  // value = peer index, text = its name: no answer for 15 s; re-handshaking

typedef struct {
    uint32_t kind;
    uint32_t value;
    uint16_t port;     // RESOLVE
    uint16_t reserved;
    const char *text;  // valid until the next ztnx_engine_poll_event
} ZtnxEvent;

// An interface with no configuration yet (no address, no peers).
ZtnxEngine *ztnx_engine_new(uint64_t now_ns, uint64_t unix_secs);
// Parses and applies a .conf. On failure nothing changes and the reason
// ("line 12: PublicKey: not valid base64") is in err[err_cap] (may be NULL/0).
// Sessions start over; overlay socket ids stay valid.
bool ztnx_engine_reload(ZtnxEngine *e, const ZtnxConfig *cfg, uint64_t now_ns, char *err, size_t err_cap);
void ztnx_engine_free(ZtnxEngine *e);
bool ztnx_engine_configured(ZtnxEngine *e);
bool ztnx_engine_poll_io(ZtnxEngine *e, ZtnxIo *out);
bool ztnx_engine_poll_event(ZtnxEngine *e, ZtnxEvent *out);
// A datagram arrived on the engine's UDP socket.
void ztnx_engine_udp(ZtnxEngine *e, const ZtnxAddr *src, const uint8_t *data, size_t len, uint64_t now_ns);
void ztnx_engine_timeout(ZtnxEngine *e, uint64_t now_ns);
uint64_t ztnx_engine_next_deadline(ZtnxEngine *e);
// The network came back or changed (Wi-Fi after a wake, a new address):
// host names are resolved again and every reachable peer is contacted now.
void ztnx_engine_network_up(ZtnxEngine *e, uint64_t now_ns);
// Answer to ZTNX_EVENT_RESOLVE (any time; also overrides an endpoint).
void ztnx_engine_set_peer_endpoint(ZtnxEngine *e, uint32_t peer, const ZtnxAddr *addr, uint64_t now_ns);
// [Interface] ListenPort, 0 if none: bind the UDP socket there.
uint16_t ztnx_engine_listen_port(ZtnxEngine *e);
uint16_t ztnx_engine_mtu(ZtnxEngine *e);
// Our [Interface] addresses with prefix lengths. Returns how many there are.
size_t ztnx_engine_addresses(ZtnxEngine *e, ZtnxPrefix *out, size_t cap);
// Destinations that belong to the tunnel, for the socket layer: our own
// addresses (/32, /128), then every peer's AllowedIPs, each once. Fixed
// between reloads. Returns how many there are (can exceed cap).
size_t ztnx_engine_routes(ZtnxEngine *e, ZtnxPrefix *out, size_t cap);
// "a.b.c.d name\n" for this interface (if its .conf names it) and every
// peer with an IPv4 /32 AllowedIP; NUL-terminated, truncated to cap.
// Returns the full length (like snprintf).
size_t ztnx_engine_hosts(ZtnxEngine *e, char *buf, size_t cap);

#define ZTNX_PEER_SESSION 1u         // a handshake in the last 180 s
#define ZTNX_PEER_ENDPOINT_NAME 2u   // Endpoint= is a host name ...
#define ZTNX_PEER_RESOLVING 4u       // ... not resolved yet (nothing to send to)
#define ZTNX_PEER_ROAMED 8u          // endpoint differs from the configured one (learned from traffic)
#define ZTNX_PEER_KEEPALIVE 16u      // PersistentKeepalive set
#define ZTNX_PEER_PSK 32u            // PresharedKey set
#define ZTNX_PEER_DEFAULT_ROUTE 64u  // AllowedIPs has 0.0.0.0/0 or ::/0
typedef struct {
    char name[32];              // NUL-terminated; from "# Name = ..." or "peerN"
    uint8_t ipv4[4];            // first IPv4 /32 AllowedIP, else 0.0.0.0
    uint8_t endpoint_ip[4];     // current endpoint, 0.0.0.0 if none
    uint16_t endpoint_port;
    uint16_t keepalive_s;       // PersistentKeepalive, 0 = off
    uint32_t last_handshake_s;  // seconds ago; UINT32_MAX = never
    uint32_t last_rx_s;         // seconds since the last authenticated packet; UINT32_MAX = never
    uint32_t flags;             // ZTNX_PEER_*
    uint64_t rx_bytes;          // wire bytes (like `wg show ... transfer`)
    uint64_t tx_bytes;
    uint32_t allowed_ips;       // prefix count
    uint32_t reserved;
} ZtnxPeerInfo;                 // 80 bytes
#ifdef __cplusplus
static_assert(sizeof(ZtnxPeerInfo) == 80, "ZtnxPeerInfo layout");
static_assert(sizeof(ZtnxPrefix) == 24, "ZtnxPrefix layout");
#endif
// Every configured peer, in .conf order, up to max of them into out.
// Returns how many there are (can exceed max).
size_t ztnx_engine_peers(ZtnxEngine *e, ZtnxPeerInfo *out, size_t max);

// ---- Overlay sockets (tunnel side) ------------------------------------------
// Non-blocking. Ids are > 0; errors are negative ZTNX_E* codes.

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

int32_t ztnx_net_tcp_connect(ZtnxEngine *e, const ZtnxAddr *dst);
int32_t ztnx_net_tcp_listen(ZtnxEngine *e, uint16_t port, uint32_t backlog);
int32_t ztnx_net_tcp_accept(ZtnxEngine *e, int32_t id, ZtnxAddr *peer);
int32_t ztnx_net_send(ZtnxEngine *e, int32_t id, const uint8_t *data, size_t len);
int32_t ztnx_net_recv(ZtnxEngine *e, int32_t id, uint8_t *buf, size_t len);
int32_t ztnx_net_shutdown(ZtnxEngine *e, int32_t id);
int32_t ztnx_net_udp_bind(ZtnxEngine *e, uint16_t port);
int32_t ztnx_net_udp_sendto(ZtnxEngine *e, int32_t id, const uint8_t *data, size_t len, const ZtnxAddr *dst);
int32_t ztnx_net_udp_recvfrom(ZtnxEngine *e, int32_t id, uint8_t *buf, size_t len, ZtnxAddr *src);
uint32_t ztnx_net_readiness(ZtnxEngine *e, int32_t id);
// Bytes of overlay socket buffers in use (TCP buffers, queued datagrams).
size_t ztnx_net_buffer_usage(ZtnxEngine *e);
// Most bytes of overlay socket buffers allowed at once (new TCP connections
// get smaller buffers as it fills; past it they fail with ZTNX_ENOBUFS).
void ztnx_net_set_budget(ZtnxEngine *e, size_t bytes);
void ztnx_net_close(ZtnxEngine *e, int32_t id);
int32_t ztnx_net_local_addr(ZtnxEngine *e, int32_t id, ZtnxAddr *out);
int32_t ztnx_net_peer_addr(ZtnxEngine *e, int32_t id, ZtnxAddr *out);

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
