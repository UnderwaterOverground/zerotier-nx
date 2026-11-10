// Peer names for the whole console through Atmosphère's DNS MITM: tunnel
// names are kept in a managed block of the hosts file Atmosphère is using,
// and Atmosphère is asked to reload it. Apps resolve names via sfdnsres,
// which never reaches the engine, so this is the hook that works for all.
//
// Atmosphère's own rules are never weakened. It checks later entries first
// (each is inserted at the front), so our block, last in the file, is
// consulted first; but our entries are exact peer names (no wildcards,
// nothing containing "nintendo"), which only ever match themselves.
#pragma once

extern "C" {
#include "ztnx.h"
}

namespace ams::hosts {

    // Builds the managed block from the engine's current peers (call with
    // the runtime lock held). Returns whether it changed, for Write(). With
    // aliases, private peer addresses are written as stand-ins the socket
    // layer translates (VSock::SetAliases), so Moonlight sizes its packets
    // to fit the tunnel.
    bool Collect(ZtnxEngine *engine, bool aliases);

    // Rewrites the managed block with what Collect() built, without the
    // runtime lock: it reads and rewrites a file on the SD card, which can
    // take most of a second. Never creates a hosts file, never touches
    // lines outside the block, and skips writing if anything looks off.
    void Write();

}
