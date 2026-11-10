// What the sysmodule is doing, for ztnx:ctl clients (the overlay), plus the
// user-facing side effects of state changes: Ultrahand toasts and the
// pause switch.
#pragma once
#include <stratosphere.hpp>

extern "C" {
#include "ztnx.h"
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

    // A .conf was applied (name, peer count): CONNECTING until a handshake.
    // Or it failed: the error is kept for the overlay, with a toast.
    void SetConf(const char *name, u32 peers);
    void SetConfError(const char *name, const char *error);
    // No .conf to load: `message` says what to do (shown as it is).
    void SetConfMissing(const char *message);
    // Engine events (engine thread, runtime lock held).
    void OnEvent(const ZtnxEvent &ev);
    // Every peer (engine thread, every round): n is how many there are, of
    // which up to ZTNX_CTL_MAX_PEERS are in peers.
    void SetPeers(const ZtnxPeerInfo *peers, size_t n);

    ZtnxCtlStatus Get();
    size_t GetLastError(char *out, size_t cap);
    size_t GetConfName(char *out, size_t cap);
    // Up to max of them into out; returns how many there are.
    size_t GetPeers(ZtnxPeerInfo *out, size_t max);

    // Pauses or resumes the tunnel (persisted). Not from the engine thread.
    void SetPaused(bool paused);
    bool IsPaused();
    // A peer handshake has completed (not starting, unconfigured or paused).
    bool IsConnected();

    // Stopped from the overlay: ZTNX_CTL_STOPPING from now on.
    void SetStopping();
    bool IsStopping();

}
