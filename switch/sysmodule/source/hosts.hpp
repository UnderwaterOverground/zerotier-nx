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
#include "ztnx_engine.h"
}

namespace ams::hosts {

    // Builds the managed block from the configured names ("ip name\n"
    // lines, from config.ini's host= entries) and the learned GameStream
    // hosts (lines in the same form, named by their own address; see
    // LearnGameStreamHost) for the network as it is now. Returns whether it
    // changed, for Write(). With aliases, private addresses are written as
    // stand-ins the socket layer translates (VSock::SetAliases), so
    // Moonlight sizes its packets to fit one ZeroTier datagram.
    bool Collect(const char *names, const char *learned, const ZtnxNetConfig &net, bool aliases);

    // Moonlight sizes its video packets by the address it resolves its
    // host to: 1392 bytes for a private one (which ZeroTier splits in two),
    // 1024 otherwise. A host added by name gets a stand-in from its host=
    // line; one added by its ZeroTier address can get one too, because
    // libnx sends every getaddrinfo to sfdnsres, numeric ones included, and
    // Atmosphère's hosts file takes any string as a name. So the address of
    // a PC an app has connected to on a GameStream port (47984, 47989)
    // through the tunnel is named, as itself, after its stand-in. Moonlight
    // always asks the PC for its state over HTTP before streaming, so the
    // name is there by the time it resolves the address to stream.
    //
    // Only GameStream hosts: for a name that Atmosphère redirects, its
    // getaddrinfo aborts (taking the console down) on a service given by
    // name rather than number ("http"), which Moonlight never does.
    //
    // LearnGameStreamHost runs on MITM threads: it only queues the address
    // (host byte order), dropping it when the queue is full; the engine
    // thread takes them (TakeLearned) and rebuilds the block.
    void LearnGameStreamHost(uint32_t ip, uint16_t port);
    size_t TakeLearned(uint32_t *out, size_t max);
    // Rewrites the managed block with what Collect() built, without the
    // runtime lock: it reads and rewrites a file on the SD card, which can
    // take most of a second. Never creates a hosts file, never touches
    // lines outside the block, and skips writing if anything looks off.
    void Write();

}
