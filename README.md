# zerotier-nx

A ZeroTier client for a modded Nintendo Switch (Atmosphère), as a sysmodule:
homebrew such as Moonlight reaches the devices on your ZeroTier network through
its normal sockets, and a Tesla overlay shows status.

**Work in progress. Nothing here is usable yet.** The tree started as
[wireguard-nx](https://github.com/UnderwaterOverground/wireguard-nx) and its
WireGuard engine is being replaced with ZeroTier's core
(`third_party/ZeroTierOne`, 1.16.2). Until that is done, the code and the files
under `docs/` still describe WireGuard.

## License

The sysmodule, overlay and socket layer are GPL-2.0-or-later. The Rust code
under `crates/` is BSD-3-Clause. ZeroTier's core is MPL-2.0; the changes made
to it are in `patches/`. See `THIRD_PARTY_NOTICES.md`.
