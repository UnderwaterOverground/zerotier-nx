// The ZeroTier core behind a small C ABI (see ztnx_engine.cpp).
//
// Everything here is for the engine thread only, with no runtime lock held:
// the core's call paths need far more stack than a bsd:u MITM thread has
// (Multicaster::send alone has a 64 KB frame), and its callbacks must never
// call back into it. So the callbacks only record: frames go to an arena,
// the latest network configuration and a few events are kept, and the caller
// picks them up after the call that produced them has returned.
//
// Times (now_ms) are milliseconds on a clock that looks like wall time and
// never goes backwards: a fixed epoch base plus the monotonic clock.
#ifndef ZTNX_ENGINE_H
#define ZTNX_ENGINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ztnx.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ZtnxEngine ZtnxEngine;

// State objects kept between runs (the values of ZT_StateObjectType). The
// peer cache and moons are not offered to the hooks at all.
#define ZTNX_STATE_IDENTITY_PUBLIC 1
#define ZTNX_STATE_IDENTITY_SECRET 2
#define ZTNX_STATE_PLANET 3
#define ZTNX_STATE_NETWORK_CONFIG 6

typedef struct ZtnxEngineHooks {
    void *ctx;
    // Sends a datagram from the engine's UDP socket to ip:port (ip in
    // network byte order, port in host order). ttl 0 means the default.
    // Returns 0 if it was sent.
    int (*wire_send)(void *ctx, uint32_t ip_be, uint16_t port, const void *data, unsigned int len, unsigned int ttl);
    // Reads a state object into buf. Returns its length, or -1 if there is
    // none (or it doesn't fit). id is the network ID for a network config.
    int (*state_get)(void *ctx, int type, uint64_t id, void *buf, unsigned int cap);
    // Stores a state object; len < 0 deletes it. May be slow (SD card).
    void (*state_put)(void *ctx, int type, uint64_t id, const void *data, int len);
} ZtnxEngineHooks;

// Result codes from ZeroTier (ZT_ResultCode): 0 is success, 1-99 are fatal.
#define ZTNX_ENGINE_OK 0
#define ZTNX_ENGINE_OUT_OF_MEMORY 1
#define ZTNX_ENGINE_DATA_STORE_FAILED 2
#define ZTNX_ENGINE_INTERNAL 3

// Creates the node. It needs a stored identity (state_get of
// ZTNX_STATE_IDENTITY_SECRET); without a valid one this fails with
// ZTNX_ENGINE_INTERNAL: see ztnx_engine_generate_identity. *rc gets the
// result code.
ZtnxEngine *ztnx_engine_new(const ZtnxEngineHooks *hooks, int64_t now_ms, int *rc);
void ztnx_engine_free(ZtnxEngine *e);

// Our 40-bit ZeroTier address (the node ID to authorize).
uint64_t ztnx_engine_address(const ZtnxEngine *e);

// Joins a network (one at a time: joining another leaves the first).
int ztnx_engine_join(ZtnxEngine *e, uint64_t nwid);
int ztnx_engine_leave(ZtnxEngine *e);

// A datagram arrived on the UDP socket.
void ztnx_engine_wire_in(ZtnxEngine *e, uint32_t ip_be, uint16_t port, const void *data, unsigned int len, int64_t now_ms);
// Sends an Ethernet frame into the network (source MAC: ours).
void ztnx_engine_frame_out(ZtnxEngine *e, uint64_t dst_mac, unsigned int ethertype, const void *data, unsigned int len, int64_t now_ms);
// Runs ZeroTier's timers. Call when now_ms reaches ztnx_engine_deadline_ms.
void ztnx_engine_background(ZtnxEngine *e, int64_t now_ms);
int64_t ztnx_engine_deadline_ms(const ZtnxEngine *e);

// The network underneath changed (start, wake from sleep, new address):
// tells ZeroTier our local address, for direct paths on the same LAN, and
// makes its timers run at once. local_ip_be 0 if unknown.
void ztnx_engine_network_up(ZtnxEngine *e, uint32_t local_ip_be, uint16_t port, int64_t now_ms);

// Frames received from the network since ztnx_engine_frames_done, in order.
typedef struct ZtnxFrame {
    uint64_t src_mac;
    uint64_t dst_mac;
    uint32_t ethertype;
    uint32_t len;
    const uint8_t *data;
} ZtnxFrame;
size_t ztnx_engine_frames(ZtnxEngine *e, const ZtnxFrame **out);
void ztnx_engine_frames_done(ZtnxEngine *e);
// True when the arena is more than half full: take the frames before
// feeding ZeroTier more datagrams, or some will be dropped.
bool ztnx_engine_frames_high(const ZtnxEngine *e);

// ZtnxNetConfig.status (the values of ZT_VirtualNetworkStatus, plus DOWN).
#define ZTNX_NET_REQUESTING 0
#define ZTNX_NET_OK 1
#define ZTNX_NET_ACCESS_DENIED 2  // not authorized (yet) by the controller
#define ZTNX_NET_NOT_FOUND 3
#define ZTNX_NET_PORT_ERROR 4
#define ZTNX_NET_CLIENT_TOO_OLD 5
#define ZTNX_NET_AUTH_REQUIRED 6  // the network wants single sign-on
#define ZTNX_NET_DOWN 100         // left, or the node is shutting down

// ZtnxNetConfig.truncated: parts of the controller's configuration that
// didn't fit this build (patches/zerotier-0006).
#define ZTNX_TRUNCATED_RULES 0x01u
#define ZTNX_TRUNCATED_ROUTES 0x02u
#define ZTNX_TRUNCATED_ADDRESSES 0x04u
#define ZTNX_TRUNCATED_CAPABILITIES 0x08u
#define ZTNX_TRUNCATED_TAGS 0x10u
#define ZTNX_TRUNCATED_SPECIALISTS 0x20u
#define ZTNX_TRUNCATED_CERTIFICATES 0x40u
#define ZTNX_CONFIG_TOO_LARGE 0x80u  // too large to receive: none of it applied

#define ZTNX_MAX_ADDRS 8
#define ZTNX_MAX_ROUTES 32

// The joined network as ZeroTier last reported it (IPv4 parts only).
typedef struct ZtnxNetConfig {
    uint64_t nwid;
    uint64_t mac;
    uint32_t status;
    uint32_t truncated;
    uint32_t revision;
    uint16_t mtu;
    uint8_t broadcast;  // the network allows ff:ff:ff:ff:ff:ff (ARP needs it)
    uint8_t is_private;
    uint8_t n_addrs;
    uint8_t n_routes;
    uint8_t reserved[2];
    char name[128];
    ZtnxV4Net addrs[ZTNX_MAX_ADDRS];
    ZtnxV4Route routes[ZTNX_MAX_ROUTES];
} ZtnxNetConfig;
// Copies out the latest configuration if it changed since the last call.
bool ztnx_engine_take_config(ZtnxEngine *e, ZtnxNetConfig *out);

#define ZTNX_EVENT_ONLINE 1   // a root server answered
#define ZTNX_EVENT_OFFLINE 2  // none has for a while
#define ZTNX_EVENT_IDENTITY_COLLISION 3  // another device has our address: fatal
// Takes the oldest event not yet taken (0 if none).
uint32_t ztnx_engine_take_event(ZtnxEngine *e);

// Subscribes to the ARP multicast group of each of our IPv4 addresses on the
// joined network (network byte order), and drops subscriptions for addresses
// no longer in the list. Without this nobody's ARP requests for us arrive.
void ztnx_engine_multicast_sync(ZtnxEngine *e, const uint32_t *ipv4_be, size_t n);

#define ZTNX_PEER_LEAF 0    // an ordinary device
#define ZTNX_PEER_MOON 1
#define ZTNX_PEER_PLANET 2  // one of ZeroTier's root servers
typedef struct ZtnxPeerInfo {
    uint64_t address;
    int32_t latency_ms;   // -1 if unknown
    uint32_t last_rx_ms;  // since the last packet on the direct path
    uint8_t path_ip[4];   // the direct path's address; zero if relayed
    uint16_t path_port;
    uint8_t role;
    uint8_t direct;       // 1 if there is a live direct path, 0 if relayed
    uint8_t version[3];   // 0.0.0 if unknown
    uint8_t reserved[5];
} ZtnxPeerInfo;
// Every peer ZeroTier knows, up to max of them. Returns how many there are
// (can exceed max). Allocates about 2 KB per peer while it runs: call it
// rarely.
size_t ztnx_engine_peers(ZtnxEngine *e, ZtnxPeerInfo *out, size_t max, int64_t now_ms);

// Identities, as the text of identity.secret / identity.public.
#define ZTNX_IDENTITY_TEXT_MAX 384
#define ZTNX_IDENTITY_SCRATCH (2u << 20)
// Makes a new identity. scratch is ZTNX_IDENTITY_SCRATCH bytes of memory the
// work needs (it is why this is not done inside the node); it takes seconds.
// Writes NUL-terminated text into both buffers (ZTNX_IDENTITY_TEXT_MAX each)
// and returns the new address, or 0 on failure.
uint64_t ztnx_engine_generate_identity(void *scratch, char *secret, char *public_);
// The address in a secret identity's text, or 0 if the text is not a valid
// identity with its private key.
uint64_t ztnx_engine_identity_address(const char *secret);

// Provided by the platform where there is no /dev/urandom (the sysmodule):
// cryptographically secure random bytes. Must not fail.
void ztnx_secure_random(void *buf, unsigned int len);

// Checks that C++ exceptions work in this binary: a throw and catch, unwinding
// through a destructor, std::bad_alloc from operator new, and a throw inside
// the core itself (a node without an identity). The core relies on all four;
// Atmosphère's default link turns them into aborts. Returns 0 if all passed,
// else one bit per failed check (1, 2, 4, 8).
uint32_t ztnx_engine_selftest(void);

#ifdef __cplusplus
}
#endif

#endif
