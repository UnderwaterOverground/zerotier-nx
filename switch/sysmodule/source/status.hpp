// What the sysmodule is doing, for ztnx:ctl clients (the overlay), plus the
// user-facing side effects of state changes: Ultrahand toasts and the
// pause switch.
#pragma once
#include <stratosphere.hpp>

extern "C" {
#include "ztnx.h"
#include "ztnx_engine.h"
}
#include "ztnx_ctl.h"

namespace ztnx {
    class Runtime;
}

namespace ams::status {

    // Once the runtime exists. Starts paused if the user left it paused.
    // `connect_notice`: a 5 s toast with our address on the first connection
    // after boot (unless the overlay turned it off).
    void Initialize(::ztnx::Runtime &rt, u32 flags, bool connect_notice);

    // A newer release (version without the "v") is out: a toast saying so.
    void AnnounceUpdate(const char *latest);
    // Little system memory was left free during boot: a toast saying so.
    void AnnounceLowMemory(u32 free_kb);

    // The engine loop ran a round (engine thread); GetStatus reports how
    // long ago, so a stuck engine shows as such in the overlay.
    void EngineRan(u64 now_ns);
    // What the engine loop is busy with outside the engine (nullptr when
    // done), named in the log if it gets stuck there.
    void EngineStep(const char *what);
    // Whether the console has an internet connection (engine thread).
    void SetOffline(bool offline);

    // Our ZeroTier address and the network config.ini names.
    void SetNode(u64 node, u64 nwid);
    // Something the user has to fix before anything can work (no network=
    // in config.ini, no identity): kept for the overlay, with a toast.
    void SetConfigError(const char *message);
    // The network as ZeroTier reports it (engine thread, no lock held):
    // CONNECTED once it is up with an address, with a toast the first time;
    // a toast saying what to do when the controller refuses us.
    void SetNetwork(const ZtnxNetConfig &c);
    // ZTNX_EVENT_* from the engine.
    void OnEngineEvent(u32 event);
    // The peers ZeroTier knows (engine thread): n of them in peers, of
    // `total` there are.
    void SetPeers(const ZtnxPeerInfo *peers, size_t n, size_t total);
    ZtnxCtlStatus Get();
    size_t GetLastError(char *out, size_t cap);
    size_t GetNetworkName(char *out, size_t cap);
    // Up to max of them into out; returns how many there are.
    size_t GetPeers(ZtnxCtlPeer *out, size_t max);

    // Pauses or resumes the tunnel (persisted). Not from the engine thread.
    void SetPaused(bool paused);
    bool IsPaused();
    // On the network with an address (not starting, refused or paused).
    bool IsConnected();

    // Stopped from the overlay: ZTNX_CTL_STOPPING from now on.
    void SetStopping();
    bool IsStopping();

}
