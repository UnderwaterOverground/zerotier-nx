# Vendored code

## ZeroTierOne

- Upstream: https://github.com/zerotier/ZeroTierOne
- Location: `third_party/ZeroTierOne` (git submodule)
- Tag: `1.16.2`
- Commit: `fc5c3ec22090b5b2a0f274e863651fe9ca489bf4` (2026-05-27)
- License: the core (`node/`, `include/`) is MPL 2.0 (`LICENSE-MPL.txt`); no
  file carries the "Incompatible With Secondary Licenses" notice. Only `node/`
  and `include/` are built into zerotier-nx. `nonfree/` (the network
  controller) is source-available for non-commercial use only
  (`nonfree/LICENSE.md`): it is built for the Docker test network and never
  shipped.

The submodule's commit is upstream's. Our changes to it are the patches below,
applied to its working tree by `make zerotier-patches` (a patch that is already
applied is skipped). The patched files stay MPL 2.0.

| Patch | What it does |
|---|---|
| `zerotier-0001-identity-no-local-hash.patch` | With `ZT_NO_LOCAL_IDENTITY_VALIDATION`: no 2 MB memory-hard check of our own identity at start; a HELLO from an unknown address gets a WHOIS to the roots instead of the check. |
| `zerotier-0002-tunable-constants-ifndef.patch` | Wraps the size limits in `#ifndef` so a build can lower them with `-D`. |
| `zerotier-0003-switch-platform.patch` | ARM feature flags without `auxv`; random bytes from the embedder (`ZT_SECURE_RANDOM_HOOK`). |
| `zerotier-0004-no-threads.patch` | With `ZT_NO_THREADS`: the two detached `std::thread`s in `Switch.cpp` are not started (IPv6 NDP emulation is not answered; frames to our own address are dropped). |
| `zerotier-0005-config-bounds.patch` | Bounds checks when reading capabilities and tags from a network config, and when reporting multicast subscriptions. |
| `zerotier-0006-config-truncated-flag.patch` | `ZT_VirtualNetworkConfig::truncated`: says which parts of a config did not fit the build's limits, or that it was too large to receive. |
| `zerotier-0007-identity-external-buffer.patch` | `Identity::generate()` can use a caller's 2 MB buffer; with `ZT_NO_LOCAL_IDENTITY_VALIDATION` a node without an identity fails instead of generating one. |
| `zerotier-0008-rx-fragment-size.patch` | With `ZT_RX_FRAGMENT_MAX`, the receive queue keeps a packet's later fragments as payloads of at most that size instead of in whole-packet buffers (10 KB each, six per entry); larger fragments are dropped. |
| `zerotier-0009-small-statics.patch` | Two static buffers: the random generator's 64 KB one gets a size (`ZT_SECURE_RANDOM_BUFFER_SIZE`), and with `ZT_NETWORKCONFIG_RESET_IN_PLACE` a network config is cleared in place instead of from a 45 KB empty copy. |
| `zerotier-0010-ed25519-no-base-table.patch` | With `ZT_ED25519_NO_BASE_TABLE`, multiples of Ed25519's base point are computed by the routine verification uses instead of from a 109 KB table. Slower and not constant-time: acceptable only because a network member makes its own key pair and signs nothing. |
| `zerotier-0011-stack-frames.patch` | Two large stack frames: with `ZT_NO_SEND_COMPRESSION` packets are sent uncompressed (compressing is the sender's choice; its buffers took 36 KB of stack), and `ZT_MULTICAST_SEND_STACK_INDEXES` sizes the index array `Multicaster::send` keeps on the stack (32 KB by default; larger groups use the heap either way). |

Headers in `native/zt/stubs/` replace upstream ones at build time by taking
their include guards: no-op metrics and bonding, a multiplexer without threads,
and on the Switch a mutex on libnx and the two `OSUtils` helpers the core uses.
`stubs/Trace.cpp` is built instead of `node/Trace.cpp`: remote tracing, which a
network's controller can switch on, does nothing here.

The build's limits (`native/zt/Makefile`): receive queue 8, rules 64, routes 32,
specialists 16, capabilities 8, tags 8, assigned addresses 8, paths per peer 8.
