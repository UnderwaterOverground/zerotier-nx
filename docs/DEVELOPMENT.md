# Developing zerotier-nx

How the code is laid out, how to build and test it (mostly on a Mac or Linux
machine, without a console), and what we learned along the way.

## Layout

| Path | What |
|---|---|
| `third_party/ZeroTierOne` | ZeroTier 1.16.2 (submodule). Only its core (`node/`, `include/`) is built in, with the changes in `patches/zerotier-*.patch` (listed in `VENDORED.md`): no threads, a member-only node, smaller limits, a bounded peer table, and an identity made in borrowed memory. |
| `native/zt` | The glue around ZeroTier's core (`ztnx_engine.cpp`): one node, one network, state files, the network config turned into a plain struct, frames in and out. Its `Makefile` builds the core for the Switch and for the host. |
| `crates/ztnx-core` | Sans-IO Rust, `no_std + alloc`: the smoltcp TCP/IP stack that homebrew sockets are mapped onto, the Ethernet layer between it and ZeroTier (ARP, routes, MTU), and rustls with a pure-Rust provider for the update check. It never touches sockets, clocks or OS RNGs; drivers inject them. |
| `crates/ztnx-ffi` | C ABI (`include/ztnx.h`), built as a staticlib for the Switch and for host C tests |
| `native/driver` | Portable POSIX C: the UDP socket ZeroTier uses (batched receive on the console, reopened when the system drops it), DNS, the clock check and the update check. The same code runs on macOS, Linux and libnx. |
| `native/runtime` | C++ runtime: runs ZeroTier and the stack on one engine thread, carries frames between them, and lets other threads use sockets (pause, sleep and wake included) |
| `native/vsock` | Socket virtualization. It decides per socket between the real stack and the network (`IsTunnel`: the network's subnets and managed routes, minus the local network), splits poll/select, and handles blocking semantics. The MITM is built on it. |
| `native/interpose` | `libztnx_interpose`: runs unmodified programs through `native/vsock` (DYLD on macOS, LD_PRELOAD on Linux), plus `vsock-test` |
| `native/host` | Host tools and tests: `ztnx-c` (the sysmodule's parts without the MITM), `zt-smoke` (everything on one thread), `zt-selftest`, `runtime-test`, `routes-test` |
| `native/ctl` | The `ztnx:ctl` status service's types, shared by the sysmodule and the overlay |
| `switch/sysmodule` | The boot2 sysmodule (libstratosphere): ZeroTier, the `bsd:u` MITM (plus `bsd:s` for sys-ftpd), the hosts file for names, the status service, sleep handling and the crash guard |
| `switch/overlay` | Tesla/Ultrahand overlay: status, devices with details, network, pause, stop/start |
| `switch/mitm-test` | `mitm-test.nro`: the socket virtualization suite as plain homebrew, through the sysmodule's MITM (developer tool) |
| `switch/speedtest` | `speedtest.nro`: throughput, socket call costs and SD card writes through the sysmodule, against `tools/speedtest-server.py` (developer tool) |
| `e2e/` | A ZeroTier network in Docker: a self-hosted controller, a stock `zerotier-one` peer (TCP/UDP echo on port 7, HTTP on 8080, iperf3 on 5201) and a client container that runs our Linux builds. `run-tests.sh` is the automated suite. |

## Build and test

Requirements: Rust (stable for the host; nightly is pulled into the Docker
image) and Docker. Check out the submodules first
(`git submodule update --init`).

```sh
make host-test        # unit tests: the stack, ARP and routes, TLS; ZeroTier's
                      # exceptions; the runtime against a fake engine; routes
make docker-image     # once: devkitA64 + libnx + Rust nightly (native arm64)
make sysmodule        # switch/sysmodule/dist: atmosphere/contents/4200000000005A54 (exefs.nsp, boot2 flag)
make overlay          # switch/overlay/zerotier-nx.ovl
tools/stage-sd.sh     # dist/sd: a ready-to-copy SD tree (Atmosphère, hekate, sysmodule, overlay)
make host-c           # target/ztnx-c (the sysmodule's parts on the Mac)
make interpose        # target/libztnx_interpose.dylib + target/vsock-test
make e2e              # the Docker network + the end-to-end suite
```

`make sysmodule` builds libstratosphere once (a few minutes) and applies
the patches in `patches/` to the submodules' working trees first, so
`git status` shows them as modified; that's expected. Never commit inside
the submodules.

### The test network (no console needed)

`make e2e` (or `e2e/setup.sh`, then `e2e/run-tests.sh`) brings up the
controller, the peer and the client, makes a private network
(10.147.17.0/24), joins and authorizes the peer, builds our Linux tools
in the client, and checks:
- a new identity; an unauthorized node told so; an address once authorized
- UDP echo of 2000 bytes (two ZeroTier packets each way); ping and a
  1300-byte ping from the peer; 300 KB of TCP echo from the peer
- the runtime's own tests; TCP and UDP echo from another thread; suspend
  closing the socket within 2.5 s, and echo again after resume
- the socket virtualization suite and unmodified curl through the shim
- a burst of 60 fragmented datagrams; iperf3 TCP (at least 50 Mbit/s) and
  20 Mbit/s of UDP to the peer

The nodes meet through ZeroTier's root servers, so the suite needs the
internet. `e2e/ctl.sh` drives the controller (make networks, authorize
members, change routes); `e2e/down.sh` tears it all down.

The sysmodule's boot-time update check (`native/driver/ztnx_update.c`) runs
the same way against the real GitHub. Pass the version to compare with:

```sh
target/ztnx-c --update-check 1.0.0
```

### Running unmodified programs through the network (the MITM's code paths)

`e2e/run-tests.sh` shows how: inside the client container, with
`LD_PRELOAD=/out/libztnx_interpose.so`, `ZTNX_STATE=<state dir>`,
`ZTNX_NWID=<network id>` and `ZTNX_WAIT_READY=1`, any program's sockets to
the network's addresses go through ZeroTier. `ZTNX_TRACE=1` logs every
intercepted socket call.

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
   read `config/zerotier-nx/sysmodule.log(.1)` (the current one can't be
   read over FTP while the sysmodule runs).

Crashes are logged with module-relative offsets (`CRASH desc ... pc +0x...`);
resolve them with `aarch64-none-elf-addr2line -e switch/sysmodule/zerotier-nx.elf`.

The log's once-a-minute lines are the first place to look:
`heap:` (use and peak of the fixed heap), `zerotier: datagrams in/out`,
`loop: busy N%` (the engine thread's time outside `poll()`: near 100% means
it, not the network, limits throughput; about 50% with nothing in the other
columns means `poll()` is returning at once, i.e. a socket is in an error
state) and `stacks used:`.

`switch/mitm-test` (`make nxlink-mitm-test NXLINK_HOST=<switch ip>
MITM_PEER=<a peer's ZeroTier ip>`) runs the socket suite through the MITM
against TCP and UDP echo on port 7 of a device on the network
(`tools/echo-server.py`, or the e2e peer).

`switch/speedtest` (`speedtest.nro`) measures what homebrew gets through
the sysmodule: TCP and UDP throughput each way, the cost of single socket
calls and SD card write speed. Run `tools/speedtest-server.py` (port 5300,
Python 3) on a wired machine that is also on the network, then give the
test both of its addresses, so each result has a LAN baseline next to it:

```sh
make nxlink-speedtest NXLINK_HOST=<switch ip> SPEEDTEST_SERVERS="<lan ip> <zerotier ip>"
# only some tests: SPEEDTEST_ARGS=+sc (s SD card, c call costs, t TCP, u UDP)
```

### Moonlight stream test

The bitrate limits in the README come from streaming the hardest picture
there is for a video encoder, full-screen moving noise, from Sunshine to
Artemis for a minute or two per setting, from a wired PC with a direct
ZeroTier path to the console. Start the stream first, then the noise on
the host, so it's on top of everything (Steam Big Picture covers noise
started earlier):

```sh
ffplay -f lavfi -i 'nullsrc=s=1920x1080:r=60,geq=random(1)*255:128:128' -fs
```

A setting counts as safe when Artemis's **Performance** page (MINUS + PLUS
during a stream) holds about 60 FPS with no loss. Noise makes the encoder go
over the set bitrate.

Moonlight sends 1392-byte video packets to hosts at private addresses and
1024-byte packets to everything else (`moonlight-common-c`,
`Connection.c`). ZeroTier carries at most about 1394 bytes of a UDP packet
in one physical datagram (1432 bytes of payload), so every 1392-byte video
packet is split in two and the console receives twice the datagrams. The
limit is reading them: the engine thread spends about 220 us per datagram
in `bsdRecvMMsg` (the console's socket service) against about 15 us in
ZeroTier, so it tops out near 3,900 datagrams a second (`loop: busy` goes
from 75% at 25 Mbit/s to 95% when a stream collapses). Measured at 720p:

| Host (video packet size) | Clean | Marginal | Collapsed |
|---|---|---|---|
| Private address, no stand-in (1392 B) | 20 Mbit/s | 25 Mbit/s | 30 Mbit/s |
| Through a stand-in (1024 B) | 25 Mbit/s | 28 Mbit/s | 30 Mbit/s |

That's why named hosts resolve to stand-ins in `100.127.0.0/16`
(`VSock::SetAliases`, `hosts.cpp`). For comparison, the same console with
no MITM at all, on its LAN, is flat at 31 Mbit/s and collapses from 33.

A PC added to Moonlight by its address gets one too. libnx's `getaddrinfo`
asks the resolver even for a numeric address, and Atmosphère's hosts file
matches any string as a name, so a line `100.127.c.d a.b.c.d` makes the
address itself resolve to its stand-in. The MITM can't know which
addresses Moonlight will stream from ahead of time, so it learns them: a
TCP connect through the tunnel to port 47984 or 47989 (GameStream's HTTPS
and HTTP ports, which Moonlight polls before any stream) queues the
address (`hosts::LearnGameStreamHost`, lock-free, from the MITM thread),
and the engine loop adds the line and rewrites the hosts file (up to 8,
forgotten when the network changes or at reboot). Only GameStream ports:
for a redirected name, Atmosphère's `dns_mitm` aborts if the lookup's
service isn't numeric (`GetAddrInfoRequest`, `AMS_ABORT_UNLESS`), so a
hosts line for an address an app looks up with a service name such as
`"http"` would crash it. moonlight-common-c passes no service.

Streamed on the console that way (1.0.0, Artemis 1.5.4 with the PC added
by its ZeroTier address, a wired sender, HEVC noise; one run each, watched
for two to three minutes): 720p at 25 and 28 Mbit/s clean (0% loss,
network FPS equal to the host's, 99% of datagrams received, loop 65-74%
busy); 1080p at 20 clean (about 24 Mbit/s on the wire); 720p at 30
collapsed (50% loss, 30 FPS, about 12% of datagrams lost before `recv`
with the loop 78% busy). The sender's frames and physical datagrams were
one to one, so no video packet was split.

### A complete SD card tree

`tools/stage-sd.sh` stages `dist/sd/`: Atmosphère 1.12.0, hekate, the
sysmodule and the overlay. It's handy for setting up a test console. Copy
it with rsync, which merges folders. Finder's "Replace" deletes what's
already in a folder, such as other sysmodules or `hekate_ipl.ini`:

```sh
rsync -rtv --exclude .DS_Store dist/sd/ /Volumes/<SD card>/
dot_clean -m /Volumes/<SD card>
```

### Test-only settings

- `tunnel_lan=on` in `config.ini` sends addresses on the console's own LAN
  over ZeroTier too when a route covers them (normally they're reached
  directly), to test a stream from a local host through ZeroTier.

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

The sysmodule takes exactly 2.5 MB, the same as tailscale-nx and
wireguard-nx (`tools/footprint.sh` sizes the heap to fill it, about
1.2 MB; `heap_size.h` is committed with the code that moved it).
`tools/map-sizes.py switch/sysmodule/build/zerotier-nx.map` shows what the
binary is made of. An idle network member uses about 320 KB of the heap,
and a join peaks near 600 KB.

The build must not pick up libstratosphere's precompiled header: it's
built at -O2, and the sysmodule's code from Atmosphère's headers would come
out about 25 KB larger than at -Os. GCC only uses it when every macro
matches (including the git revision it was made at), so it was silently
used by some builds and not others. The Makefile deletes it after building
the library.

## Notes and findings

- **One thread runs ZeroTier.** The core isn't thread-safe, and its send
  path alone has a 64 KB stack frame, far more than the MITM's threads
  have. Every ZeroTier and driver call happens on the engine thread
  (`native/runtime`); other threads hand it work under a lock and wake it
  through a loopback socket pair.
- **ZeroTier's own threads are gone** (`ZT_NO_THREADS`), and so is
  everything a plain member doesn't need (`ZT_LEAF_ONLY`: relaying for
  others, multicast replication, the controller). Its limits are compiled
  down (`-D` in `native/zt/Makefile`, patch 0002) to 16 routes, 8 addresses,
  128 rules and 48 peers; a network that has more is truncated and says so
  (patch 0006). A network with more rules than that has its traffic
  blocked instead.
- **The MITM never allocates what an app asks for without a bound.** Its
  threads serve every app's socket calls, and a failed allocation there
  takes the sysmodule down. `recvmmsg` receives straight into the app's
  buffer, and a `poll()` of more than 256 entries goes to the console's own
  service.
- **C++ exceptions must work.** ZeroTier's core throws on malformed
  packets and catches at its entry points. `zt-selftest` (and the
  sysmodule's first log lines) check that a throw is caught.
- **Making an identity needs 2 MB** of scratch memory (a memory-hard hash),
  more than the whole heap. The sysmodule borrows it from the system once,
  two minutes after power-on and only with 3 MB free, so it never competes
  with the boot. With `ZT_NO_LOCAL_IDENTITY_VALIDATION` the node doesn't
  re-check its own identity at each start (the same 2 MB).
- **The UDP port is derived from the node's ID** (20000-65499, always the
  same for a console) rather than 9993, so it can't clash with a computer
  on the same Wi-Fi using ZeroTier's usual port.
- **The console drops every socket when the network goes away without a
  sleep** (Airplane Mode, a lost access point): sends fail with EPIPE, and
  `poll()` reports the socket invalid, or, for several seconds first, ready
  with nothing to read. The driver treats an error, or 64 rounds of ready
  but empty in a row, as a dropped socket and reopens it on the same port;
  the runtime remakes its wake pair. Both happen at most once a second. A
  sleep closes and reopens everything anyway.
- **Consoles often have wrong clocks** (HATS-style DNS blocklists block
  Nintendo NTP; one test console was at 2053), which breaks TLS. The
  sysmodule falls back to github.com's HTTP `Date` for the update check
  (bounded to [build date, build date + 3 years]).
