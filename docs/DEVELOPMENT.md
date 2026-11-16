# Developing zerotier-nx

How the code is laid out, how to build and test it (mostly on a Mac or Linux
machine, without a console), and what we learned along the way.

## Layout

| Path | What |
|---|---|
| `crates/ztnx-core` | Sans-IO engine, `no_std + alloc`. It contains: <ul><li>the wg-quick `.conf` parser (`config.rs`)</li><li>WireGuard via vendored `ts_tunnel`, plus what it leaves to us: AllowedIPs routing, endpoints and roaming, keepalives, the 15 s re-handshake rule, statistics (`engine/`)</li><li>smoltcp netstack with a socket API</li><li>a pure-Rust rustls provider (for the update check)</li></ul> It never touches sockets, clocks or OS RNGs; drivers inject them. |
| `crates/ztnx-ffi` | C ABI (`include/ztnx.h`), built as a staticlib for the Switch and for host C tests |
| `crates/ztnx-host` | Rust host driver: `up --conf`, `check`, `genkey`, `selftest`, `tls-probe` |
| `native/driver` | Portable POSIX C driver loop (one UDP socket) plus shared app logic (clock check, echo test, update check). The same code runs on macOS and libnx. |
| `native/host` | `ztnx-c`, a host CLI over the C driver, to test the Switch code paths on the Mac (including suspend/resume) |
| `native/runtime` | C++ runtime: runs the engine on its own thread for multi-threaded callers |
| `native/vsock` | Socket virtualization. It decides per socket between the real stack and the tunnel (`IsTunnel`: our addresses and every peer's AllowedIPs, minus the local network), splits poll/select, and handles blocking semantics. The MITM is built on it. |
| `native/interpose` | `libztnx_interpose`: runs unmodified programs through `native/vsock` (DYLD on macOS, LD_PRELOAD on Linux), plus `vsock-test` |
| `switch/sysmodule` | The boot2 sysmodule (libstratosphere): engine, `bsd:u` MITM (plus `bsd:s` for sys-ftpd), the hosts file for peer names, the `ztnx:ctl` status service, sleep handling and the crash guard |
| `switch/overlay` | Tesla/Ultrahand overlay: status, pause switch, stop/start, peers with details, config picker |
| `switch/app` | `ztnx-app.nro`: the engine in a homebrew app, with status, an echo self-test and a crypto benchmark (developer tool) |
| `switch/speedtest` | `speedtest.nro`: throughput, socket call costs and SD card writes through the sysmodule, against `tools/speedtest-server.py` (developer tool) |
| `third_party/tailscale-rs` | Vendored, `no_std`-ported crates from tailscale-rs (BSD-3): `ts_tunnel`, `ts_noise`, `ts_keys`, `ts_packet`, `ts_time`, `ts_util`. See `VENDORED.md`. |
| `e2e/` | Two stock WireGuard peers (the Docker VM's kernel WireGuard through `wg-quick`) with TCP/UDP echo (port 7), HTTP (8080) and iperf3 (5201), plus an AmneziaWG peer (amneziawg-go built from source) with a plain and a header-protected interface. `run-tests.sh` is the automated suite. |

## Build and test

Requirements: Rust (stable for the host, nightly is pulled into the Docker image) and Docker.

```sh
make host-test        # unit tests: crypto vectors, the .conf parser, two engines handshaking, netstack
make docker-image     # once: devkitA64 + libnx + Rust nightly (native arm64)
make sysmodule        # switch/sysmodule/dist: atmosphere/contents/4200000000005A54 (exefs.nsp, boot2 flag)
make overlay          # switch/overlay/zerotier-nx.ovl
tools/stage-sd.sh     # dist/sd: a ready-to-copy SD tree (Atmosphère, hekate, sysmodule, overlay)
make nro              # switch/app/ztnx-app.nro
make host-c           # target/ztnx-c (C driver + FFI on the Mac)
make interpose        # target/libztnx_interpose.dylib + target/vsock-test
make routes-test      # the socket layer's tunnel-address rules
make runtime-test     # the runtime's non-blocking pause and resume (links the shim)
make e2e              # local WireGuard peers + the full end-to-end suite (Docker)
```

`make e2e` checks the following against the kernel WireGuard in Docker's VM:
- TCP/UDP echo after a handshake; handshake retries after 20 s of packet loss
- inbound ICMP; PersistentKeepalive traffic while idle
- the socket virtualization suite and unmodified curl through the shim
- a 50 Mbit/s UDP stream (Moonlight-like) and a TCP bulk upload through the shim
- inbound listeners reachable (no access rules); a subnet reached only when AllowedIPs has it
- pre-shared keys (and a wrong one refused); an `Endpoint` host name that only resolves later
- roaming to a new port; several peers; an endpoint-less peer contacted by the server
- a broken `.conf` reported with its line, with the shim staying out of the way
- `ztnx-c --sleep-test`: echo again right after suspend/resume (the console's wake path)
- AmneziaWG: echo and handshake against amneziawg-go with junk, padding and disguised headers; the same keys without them refused
- AmneziaWG 3 header protection: echo, handshake and the UDP/TCP throughput tests through it; the same parameters without the key refused

Typical results on a Mac's Docker VM: 50 Mbit/s UDP at 0% loss; about 590 Mbit/s TCP up.

### Local peers (no console needed)

```sh
e2e/setup.sh          # WireGuard peers (10.7.0.1, 10.7.0.9), an AmneziaWG peer (10.7.1.1) and client .conf files in e2e/state/
# Rust driver (host side; the peers are only reachable from the compose network):
cd e2e && docker compose run --rm ztnx up --conf /state/client.conf --echo-test 10.7.0.1 --expect-handshake
# C driver (what the Switch runs):
docker compose run --rm --entrypoint /src/target/linux/ztnx-c ztnx --conf /state/client.conf --echo-test 10.7.0.1
e2e/down.sh           # tear down and delete state
```

On the Mac itself, two engines can talk through real sockets: make two
confs with `ztnx-host genkey`, run `ztnx-host up --conf b.conf` (with a
`ListenPort`) and `ztnx-host up --conf a.conf --expect-handshake`.

The AmneziaWG peer's ports are published on the host (UDP 51821 for `awg0`,
51822 for the header-protected `awg1`), so a console on the same network can
test against it: copy `e2e/state/awgswitch.conf` or `awghpswitch.conf` to
the SD card (its `Endpoint` is this machine's address; set `ZTNX_LAN_IP`
before `setup.sh` if it guessed wrong).

The sysmodule's boot-time update check (`native/driver/ztnx_update.c`) runs
the same way against the real GitHub. Pass the version to compare with:

```sh
target/ztnx-c --update-check 1.0.0
```

### Running unmodified programs through the tunnel (the MITM's code paths)

```sh
ZTNX_CONF=e2e/state/preload.conf ZTNX_WAIT_READY=1 \
DYLD_INSERT_LIBRARIES=target/libztnx_interpose.dylib target/vsock-test 10.7.0.1 1.1.1.1:443 10.7.0.3
```

`ZTNX_TRACE=1` logs every intercepted socket call. `ZTNX_LOG_LEVEL=1..5` shows
the core's logs. SIP-protected binaries (`/usr/bin/curl`) ignore
`DYLD_INSERT_LIBRARIES`; use the Linux container for those (`e2e/run-tests.sh`
shows how).

### On the console

Sysmodule loop (a console with sys-ftpd, reachable at `<switch ip>`):

1. `make sysmodule` (and `make overlay`), then copy
   `switch/sysmodule/dist/atmosphere/contents/4200000000005A54/exefs.nsp`
   (and `switch/overlay/zerotier-nx.ovl`) over FTP.
2. Reboot, or **Stop** and then **Start** in the overlay (close homebrew
   first: the `bsd:u` MITM must outlive every client session, so Stop refuses
   while any is open). The Sysmodules overlay must never kill it.
3. Watch the log: set `log_udp=<your ip>:5514` in
   `config/zerotier-nx/config.ini` and listen with a small UDP socket, or
   read `config/zerotier-nx/sysmodule.log(.1)`.

Crashes are logged with module-relative offsets (`CRASH desc ... pc +0x...`);
resolve them with `aarch64-none-elf-addr2line -e switch/sysmodule/zerotier-nx.elf`.

`switch/app` (`ztnx-app.nro`) runs the same engine as an ordinary homebrew
app with an echo self-test and a crypto benchmark (`make nxlink
NXLINK_HOST=<switch ip>` streams its output). Don't run it alongside the
sysmodule with the same `.conf`: the server would see one key from two
places.

`switch/speedtest` (`speedtest.nro`) measures what homebrew gets through
the sysmodule: TCP and UDP throughput each way, the cost of single socket
calls, SD card write speed and the crypto benchmark. Run
`tools/speedtest-server.py` (port 5300, Python 3) on a wired machine that is
also a peer, then give the test both of its addresses, so each result has a
LAN baseline next to it:

```sh
make nxlink-speedtest NXLINK_HOST=<switch ip> SPEEDTEST_SERVERS="<lan ip> <tunnel ip>"
# only some tests: SPEEDTEST_ARGS=+sc (b crypto, s SD card, c call costs, t TCP, u UDP)
```

Results (handheld on Wi-Fi, server on 2.5 GbE, Unraid's kernel WireGuard):
on the LAN, TCP about 44 Mbit/s down and 54 up, and UDP without loss up to
30 Mbit/s down and 50 up. Through the tunnel, UDP without loss up to
35 Mbit/s down (10% lost at 40) and about 38 up; TCP about 17 down and
13 up. tailscale-nx 1.2.0 on the same console managed 35 down / 37 up UDP
through its tunnel and about 13 TCP each way, so the data path (the same
ChaCha20-Poly1305 in `ts_tunnel` and smoltcp, with a 1420-byte MTU instead
of 1280) is on par.

### Moonlight stream test

The bitrate limits in the README come from streaming the hardest picture
there is for a video encoder, full-screen moving noise, from Sunshine to
Artemis for two minutes per setting. Start the stream first, then the
noise on the host, so it's on top of everything (Steam Big Picture covers
noise started earlier):

```sh
ffplay -f lavfi -i 'nullsrc=s=1920x1080:r=60,geq=random(1)*255:128:128' -fs
```

A setting counts as safe when Artemis's **Performance** page (MINUS + PLUS
during a stream) holds about 60 FPS and Sunshine's log, at
`min_log_level = debug`, shows no more than an occasional
`IDX_REQUEST_IDR_FRAME` (Moonlight asking for a fresh frame after a loss).
Noise makes the encoder go over the set bitrate: 25 Mbit/s put about 26
through the tunnel at 720p and 33 at 1080p.

Moonlight sends 1392-byte video packets to hosts at private addresses and
1024-byte packets to everything else, including `100.64.0.0/10`
(`moonlight-common-c`, `Connection.c`). With the 1420-byte tunnel MTU a
1392-byte packet arrives as two fragments, so the Switch receives twice
the datagrams. The limit is the console's socket service, which runs on
core 3 and was 84 to 96% busy at the edge: about 3,300 to 4,000
datagrams a second, however the sysmodule reads them. That's why peer
names resolve to stand-ins in `100.127.0.0/16` (`VSock::SetAliases`,
`hosts.cpp`). Moonlight's remote mode also takes 500 kbit/s off the
video bitrate for audio and turns off DSCP marking, which a tunnel
doesn't carry anyway. tailscale-nx 1.2.0 on the same console, with the
PC at its `100.x` address, had the same limits as zerotier-nx by peer
name.

### A complete SD card tree

`tools/stage-sd.sh` stages `dist/sd/`: Atmosphère 1.12.0, hekate, the
sysmodule, the overlay and the test app. It's handy for setting up a test
console. Copy it with rsync, which merges folders. Finder's "Replace"
deletes what's already in a folder, such as other sysmodules or
`hekate_ipl.ini`:

```sh
rsync -rtv --exclude .DS_Store dist/sd/ /Volumes/<SD card>/
dot_clean -m /Volumes/<SD card>
```

### Test-only settings

- `tunnel_lan=on` in `config.ini` sends addresses on the console's own LAN
  through the tunnel too when `AllowedIPs` covers them (normally they're
  reached directly), to test a stream from a local host through the server.

## Releases

`make release` builds `dist/zerotier-nx-<version>.zip` (the files to
extract to the SD card root). The version comes from `Cargo.toml` and must
match `switch/overlay/Makefile` and `switch/sysmodule/res/app.json`.
Pushing a `v*` tag builds and publishes the same zip on GitHub
(`.github/workflows/publish.yml`).

The sysmodule's Atmosphère libraries (`third_party/Atmosphere`) refuse to
start on firmware with a newer major version than they know, before
anything is logged; the overlay then says which firmware the build runs on.
(Unpatched, they refuse a newer minor version too;
`patches/atmosphere-firmware-major-only.patch` relaxes that, so 23.0's
build also runs on 23.5. If a minor update did break something, the crash
guard turns zerotier-nx off after three crashed boots.) So a new major
firmware needs a release built with an Atmosphère that knows it.

## Memory

The sysmodule takes exactly 2.5 MB (`tools/footprint.sh` sizes the heap to
fill it; `heap_size.h` is committed with the code that moved it).
`tools/map-sizes.py switch/sysmodule/build/zerotier-nx.map` shows what the
binary is made of. Compared with tailscale-nx 1.2.0, dropping the control
plane, DERP, disco and Taildrop took the Rust code from 615 KB to 430 KB
and grew the heap from 768 KB to 952 KB; rustls (the update check) is the
largest remaining piece after WireGuard and the netstack.

## Notes and findings

- **`ts_tunnel` leaves endpoints, keepalives and routing to the caller.** The
  engine keeps a current endpoint per peer (configured, resolved from a
  name, or wherever its last authenticated packet came from: roaming works
  in both roles), routes outbound packets by longest AllowedIPs prefix and
  drops inbound ones whose source isn't in the peer's AllowedIPs
  (cryptokey routing), and sends an empty packet as the keepalive. With a
  live session that packet becomes a 32-byte keepalive; without one it
  queues and `ts_tunnel` starts a handshake, so the same "kick" serves
  PersistentKeepalive, first contact, reconnecting after a wake and the
  15 s no-response rule.
- **The engine adds WireGuard's "no response for 15 s, re-handshake" rule**,
  which `ts_tunnel` lacks, and records the last handshake time (a small
  `// ztnx:` patch to `ts_tunnel`).
- **Host names in `Endpoint=`** are resolved by the driver on request
  (`ZTNX_EVENT_RESOLVE`): at start, after the network changes, every 30 s
  while there is no handshake and again when the last one is older than
  135 s (wg-quick's reresolve-dns). On the console the lookup runs off the
  runtime lock, between engine rounds, so it never stalls homebrew.
- **A `.conf` can be swapped at runtime** (`ztnx_engine_reload`): the
  netstack and its socket ids survive, sessions start over. A broken file
  leaves what was running in place.
- **Consoles often have wrong clocks** (HATS-style DNS blocklists block
  Nintendo NTP; one test console was at 2053), which breaks TLS, and
  WireGuard too: handshake timestamps must never go backwards for a key,
  or the peer ignores the initiation as a replay. The sysmodule falls back
  to github.com's HTTP `Date` (bounded to [build date, build date + 3 years]).
