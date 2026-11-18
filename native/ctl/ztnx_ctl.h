// ztnx:ctl, the zerotier-nx sysmodule's control service (status, peers,
// pause, stop). Shared by the sysmodule and its clients (the overlay).
//
//   cmd 0  GetStatus()                -> ZtnxCtlStatus (raw)
//   cmd 1  SetPaused(u8 paused)
//   cmd 2  GetLastError(out buffer)   -> u32 length (0: none)
//   cmd 3  Stop()                     -> u32 ZTNX_CTL_STOP_*, u32 detail.
//          Ends the process unless that could disturb the console or an
//          app; the reply says why not. On ZTNX_CTL_STOP_OK the process
//          exits shortly after replying: close the session and wait for it
//          to be gone before starting it again.
//   cmd 4  GetPeers(out buffer)       -> u32 count. Fills the buffer with up
//          to ZTNX_CTL_MAX_PEERS ZtnxCtlPeer (fewer if it's smaller): what
//          ZeroTier is in contact with, its root servers included. The
//          count is how many there are, which can be more than were written.
//   cmd 5  GetNetworkName(out buffer) -> u32 length: the joined network's
//          name as its controller gave it, "" until then.
//   cmd 6  SetNetwork(u64 nwid): join this network now, leaving the one
//          joined (if any). Doesn't touch config.ini: the overlay writes
//          that. 0 is ignored. Sent before the engine has started (the
//          first boot's wait for the identity), it is joined once it has.
#pragma once
#include <stdint.h>

#include "ztnx.h"

#define ZTNX_CTL_SERVICE "ztnx:ctl"
#define ZTNX_CTL_VERSION 1
#define ZTNX_CTL_MAX_PEERS 32
// Free system memory below this is a warning: the next module to start
// (Nintendo's included) can fail to, and the console crashes (2001-0132).
#define ZTNX_CTL_LOW_SYSTEM_FREE_KB 512
// Longest network name, including the NUL.
#define ZTNX_CTL_NAME_MAX 128

enum {
    ZTNX_CTL_STARTING = 0,    // waiting for the network / starting up
    ZTNX_CTL_CONNECTING = 1,  // joined, but not on the network (yet): net_status says why
    ZTNX_CTL_CONNECTED = 2,   // on the network, with an address
    ZTNX_CTL_PAUSED = 3,      // switched off by the user (survives reboots)
    ZTNX_CTL_STOPPING = 4,    // stopped from the overlay; exiting (or idle until restart)
};

enum {
    ZTNX_CTL_STOP_OK = 0,        // exiting now
    ZTNX_CTL_STOP_HOMEBREW = 1,  // refused: homebrew has sockets through us (detail: sessions)
    ZTNX_CTL_STOP_BUSY = 2,      // refused: a sleep or wake, or setup, is under way; try again
    ZTNX_CTL_STOP_FAILED = 3,    // couldn't finish safely: stays idle until the console restarts
};

enum {
    ZTNX_CTL_FLAG_MITM = 1,        // homebrew sockets reach the network
    ZTNX_CTL_FLAG_HOSTS = 2,       // configured names in Atmosphere's hosts file
    ZTNX_CTL_FLAG_OFFLINE = 4,     // the console has no internet connection
    ZTNX_CTL_FLAG_CONF_ERROR = 8,  // config.ini names no network (GetLastError says what to do)
    ZTNX_CTL_FLAG_NO_ROOTS = 16,   // ZeroTier's root servers don't answer (UDP blocked?)
    ZTNX_CTL_FLAG_MAKING_ID = 32,  // first boot: waiting to make this Switch's identity, or making it
    ZTNX_CTL_FLAG_ID_NO_MEMORY = 64,  // ...and too little system memory is free to make it
};

// net_status: where joining the network stands (the values of
// ZT_VirtualNetworkStatus, as ZTNX_NET_* in ztnx_engine.h).
enum {
    ZTNX_CTL_NET_REQUESTING = 0,     // asking the network's controller
    ZTNX_CTL_NET_OK = 1,
    ZTNX_CTL_NET_ACCESS_DENIED = 2,  // authorize `node` in the controller
    ZTNX_CTL_NET_NOT_FOUND = 3,      // no such network
    ZTNX_CTL_NET_PORT_ERROR = 4,
    ZTNX_CTL_NET_CLIENT_TOO_OLD = 5,
    ZTNX_CTL_NET_AUTH_REQUIRED = 6,  // the network wants single sign-on (not supported)
    ZTNX_CTL_NET_DOWN = 100,
};

typedef struct {
    uint32_t version;    // ZTNX_CTL_VERSION
    uint32_t state;      // ZTNX_CTL_*
    uint8_t ipv4[4];     // our address on the network, 0.0.0.0 if none
    uint32_t peers;      // devices ZeroTier is in contact with (not its root servers)
    uint32_t peers_up;   // of those, with a direct path (the rest are relayed)
    uint32_t flags;      // ZTNX_CTL_FLAG_*
    uint32_t memory_kb;       // what zerotier-nx takes (fixed), 0 if unknown
    uint32_t system_free_kb;  // free system memory, which sysmodules share
    // Seconds since the engine loop last ran a round (it runs at least once
    // a second), 0 below 3 s or while paused or asleep: anything more means
    // it's stuck.
    uint32_t engine_stalled_s;
    uint32_t net_status;  // ZTNX_CTL_NET_*
    uint64_t node;        // our ZeroTier address (10 hex digits): the ID to authorize
    uint64_t nwid;        // the network joined (16 hex digits), 0 if none
    // Parts of the network's configuration that didn't fit this build
    // (ZTNX_TRUNCATED_* / ZTNX_CONFIG_TOO_LARGE in ztnx_engine.h), 0 if all did.
    uint32_t truncated;
    uint32_t reserved;
} ZtnxCtlStatus;

#define ZTNX_CTL_PEER_LEAF 0
#define ZTNX_CTL_PEER_MOON 1
#define ZTNX_CTL_PEER_PLANET 2  // one of ZeroTier's root servers

typedef struct {
    uint64_t address;     // its ZeroTier address
    int32_t latency_ms;   // -1 if unknown
    uint32_t last_rx_ms;  // since the last packet on the direct path
    uint8_t path_ip[4];   // the direct path's address; zero if relayed
    uint16_t path_port;
    uint8_t role;         // ZTNX_CTL_PEER_*
    uint8_t direct;       // 1 if there is a live direct path, 0 if relayed
    uint8_t version[3];   // 0.0.0 if unknown
    uint8_t reserved;
    uint8_t ipv4[4];      // its address on the network, if it has talked to us; else zero
    char name[32];        // the configured name for that address, if any
} ZtnxCtlPeer;

#ifdef __cplusplus
static_assert(sizeof(ZtnxCtlStatus) == 64, "ZtnxCtlStatus layout");
static_assert(sizeof(ZtnxCtlPeer) == 64, "ZtnxCtlPeer layout");
#endif
