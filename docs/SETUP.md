# Setting up zerotier-nx

zerotier-nx connects a modded Switch to your own
[WireGuard](https://www.wireguard.com) server. It runs in the background
from boot. Homebrew such as Moonlight can then reach your PC and home network
through the tunnel, from anywhere.

It affects **homebrew only** (apps launched from hbmenu or another homebrew
launcher, and home-screen forwarders). Games and Nintendo's own apps never
see the tunnel.

## What you need

- **Atmosphère**: tested with 1.12.0 on firmware 22.5.0. To set it up, follow
  the [NH Switch Guide](https://switch.hacks.guide/).
- **[Ultrahand Overlay](https://github.com/ppkantorski/Ultrahand-Overlay)**
  with nx-ovlloader. It is optional, but you need it for the status screen,
  the peer list, the config picker and the notifications.
- A **WireGuard server** you can add a peer to (see below).

## Install

The [README](../README.md#installation) walks through it step by step, including
how to copy the files on Windows and on a Mac. In short, copy these to the SD
card, adding them to the folders already there:

| Path | What |
|---|---|
| `atmosphere/contents/4200000000005A54/` | The sysmodule. `flags/boot2.flag` makes it start at boot. |
| `switch/.overlays/zerotier-nx.ovl` | The overlay: status, peers, a pause switch, config picker, stop and start |
| `config/zerotier-nx/config.ini.example` | Settings template (optional; see below) |
| `config/zerotier-nx/<name>.conf` | Your tunnel configuration, from your server (see below) |

Then restart the console.

## The configuration file

zerotier-nx reads the same `[Interface]` / `[Peer]` file as `wg-quick` and
every WireGuard app. Your server makes one when you add a peer for the
Switch; save it in `config/zerotier-nx` on the SD card. Any name ending
`.conf` works; with several, pick one under **Config** in the overlay.

The `PrivateKey` line is the Switch's private key. Your server makes it
along with the matching public key when you add the peer, keeps the public
one, and puts the private one in the file it gives you. Copy the file as it
is; there's nothing to make on the Switch.

```ini
[Interface]
PrivateKey = <the Switch's private key>
Address = 10.253.0.2/32

[Peer]
# Name = gaming-pc
PublicKey = <the server's public key>
PresharedKey = <optional>
AllowedIPs = 10.253.0.1/32, 192.168.1.0/24
Endpoint = home.example.com:51820
PersistentKeepalive = 25
```

- **`AllowedIPs`** is what the Switch reaches through the tunnel: the
  server's tunnel address, plus your home network if the server routes it.
  `0.0.0.0/0` sends all of homebrew's internet traffic through the server
  (fine, but slower, and your server sees it all).
- **`Endpoint`** is the server as seen from the internet: a host name
  (dynamic DNS is fine; it's looked up again when the tunnel goes quiet)
  or an address, and the UDP port forwarded to it.
- **`PersistentKeepalive = 25`** keeps NAT mappings alive. Add it if your
  server's file doesn't have it.
- **`# Name = gaming-pc`** under a `[Peer]` names it (the overlay, and the
  hosts file, so Moonlight can use the name). Unraid's `#Tower` style and
  wg-easy's `### Client: name` are understood too. Names are lowercased and
  spaces become `-`.
- `DNS`, `MTU`, `ListenPort` and the `PostUp`-style lines of wg-quick are
  accepted; `DNS` and the scripts are ignored. Several `[Peer]` sections
  work, as do IPv6 addresses inside the tunnel.

### On common servers

- **Unraid (VPN Manager):** Settings → VPN Manager, add a peer with
  "Remote access to LAN" (so the Switch reaches your network), Apply, then
  download its config or scan nothing: copy the text from "Peer
  configuration". Set the tunnel active.
- **wg-easy:** add a client, download its `.conf`.
- **UniFi, Fritz!Box, MikroTik, OPNsense (Peer generator):** each has a
  WireGuard page where you add a peer and download or copy its
  configuration.
- **pfSense, Linux with `wg`:** these want the Switch's public key, so make
  the keys yourself (below).

### Making the keys yourself

Some servers only take the Switch's public key. Make a key pair on any
computer, then write the Switch's file from the example above:

- **With `wg`** (Linux, or macOS with `brew install wireguard-tools`):
  `wg genkey | tee switch.key | wg pubkey > switch.pub`. `switch.key` is
  the private key for the Switch's file; `switch.pub` goes to the server.
- **With the WireGuard app** (Windows, macOS): **Add empty tunnel**. It
  shows a new private key in the text and the public key above it. Copy
  both, then delete the tunnel.

Give the server the public key, with `AllowedIPs` set to the Switch's
tunnel address (e.g. `10.253.0.2/32`).

Treat the `.conf` like a password: it contains the Switch's private key,
and anyone with it can join your network as the Switch.

## Using it

- **Moonlight:** add your PC by its peer name (e.g. `gaming-pc`) or by an
  address the tunnel reaches. At home, Moonlight may also find the PC on
  the local network and use that, which is fine. Away from home, it uses the
  tunnel.
- **Peer names:** names from the `.conf` are written into the hosts file
  Atmosphère is using (`atmosphere/hosts/emummc.txt`, `sysmmc.txt` or
  `default.txt`), pointing at each peer's first `/32` in `AllowedIPs`.
  - A private address (`10.x`, `172.16.x` to `172.31.x`, `192.168.x`) is
    written as a stand-in in `100.127.0.0/16` with the same last two
    numbers (`10.253.0.1` becomes `100.127.0.1`), so Moonlight sends video
    packets that fit the tunnel (see the
    [README](../README.md#moonlight)). Homebrew reaching the
    stand-in reaches the real address, and sees the stand-in as the other
    end. Other programs don't use the tunnel, so they're unaffected.
    `aliases=off` in `config.ini` writes the real addresses instead.
  - A stand-in always goes through the tunnel, even at home, so a stream
    by name takes the trip through the server there too.
- **Other names:** a `# Host = gaming-pc 192.168.1.50` line anywhere in the
  `.conf` names an address that isn't a peer, such as a PC on the server's
  home network, the same way. The address must be inside a peer's
  `AllowedIPs`, and the name must not be a peer's; otherwise the log says
  why it was skipped.
  - Atmosphère's Nintendo blocking is left alone, and names containing
    "nintendo" are never added.
  - If there's no hosts file, names stay off. zerotier-nx never creates
    one. `hosts=off` in `config.ini` turns this off.
- **Connected notice:** after each boot, a 5-second toast shows
  "Connected. IP: 10.x.y.z" the first time a peer handshakes. It doesn't
  appear again on wake or reconnect. Turn it off with **Connection notice**
  in the overlay.
- **Update notice:** after each boot, 10 seconds after it connects,
  zerotier-nx asks GitHub for the latest release. If it's newer than the
  installed one, a 10-second toast says so. If GitHub can't be reached,
  nothing happens (the reason is in `sysmodule.log`). This request shows
  GitHub the console's public IP address, as any web request does. Nothing
  else is sent. Turn it off with **Check for updates** in the overlay.
- **Connections:** the overlay's **Connections** page lists every peer in
  the `.conf` with the time of its last handshake: green within the last 3
  minutes (a live session), yellow if older, grey if never. Press **A** on
  a peer for its endpoint, how much was sent and received, keepalive,
  allowed IPs and whether it uses a pre-shared key.
- **Config:** with several `.conf` files in `config/zerotier-nx`, the
  overlay's **Config** page switches between them at once. The choice is
  written to `config.ini` (`conf=`), so it stays at the next boot. A
  `ListenPort` change takes effect at the next start.
- **Pause:** use the **WireGuard** switch in the overlay. While paused,
  tunnel connections fail at once and everything else works normally.
- **Stop and start:** **Stop zerotier-nx** in the overlay ends the
  sysmodule and frees its memory, until the next boot or until you press
  **Start zerotier-nx**. Its boot setting doesn't change.
  - Close homebrew apps first. Stop is refused while one has sockets through
    zerotier-nx, because closing them would break the app. It's also
    refused for a moment around sleep and wake.
  - With `mitm=homebrew,sys-ftpd`, stopping restarts sys-ftpd, which drops
    any FTP connection.
  - Start works whether or not the boot setting is on, but not while
    `config/zerotier-nx/disabled` exists.
- **Turn it off completely:** in the **Sysmodules** overlay
  (ovl-sysmodules), turn off zerotier-nx's boot setting, then use **Stop**
  or restart. The Sysmodules overlay can't stop it itself: Atmosphère would
  freeze if its socket hook disappeared without being removed first.

## AllowedIPs and your own network

Addresses on the network the Switch is on are always reached directly,
never through the tunnel, even when `AllowedIPs` covers them: at home,
Moonlight talks to the PC over Wi-Fi as it always did. Away from home the
same addresses go through the tunnel. Loopback, link-local, multicast and
broadcast addresses never go through the tunnel either.

Everything else in `AllowedIPs` goes through the tunnel, including a
`0.0.0.0/0` default route (for homebrew only; the console's own traffic is
never touched). Inbound connections work the same way: anything your peers
may send reaches homebrew listening on the Switch (an FTP server, say), as
with any WireGuard interface. There are no access rules beyond that.

## Settings (`config/zerotier-nx/config.ini`)

All settings are optional. They take effect after a restart (the overlay's
Config page switches `.conf` files at once).

| Key | Default | What |
|---|---|---|
| `conf` | the only `.conf` there is, else `wg0.conf` | Which `.conf` in `config/zerotier-nx` to use |
| `hosts` | `on` | `off` stops writing peer names to the hosts file |
| `aliases` | `on` | `off` writes peers' real private addresses to the hosts file, not stand-ins (see [Using it](#using-it)) |
| `connect_notice` | `on` | `off` turns off the "Connected" toast at boot (as does the overlay switch) |
| `update_check` | `on` | `off` stops checking GitHub for a newer release at boot (as does the overlay switch) |
| `mitm` | `homebrew` | Which programs can reach the tunnel: `homebrew`, `off`, or `homebrew,sys-ftpd` (see below) |
| `mitm_titles` | none | Title IDs of home-screen forwarders that aren't found automatically, up to 16 (see below) |
| `overlay_budget_kb` | `320` | Memory for tunnel sockets, shared by all apps (128–384). Raise it only if apps report "no buffer space". |
| `log_udp` | none | Send the log to `ip:port` over UDP (a tunnel address works from anywhere) |

### Home-screen forwarders

Homebrew started from a home-screen forwarder runs as its own title, not
through hbmenu. zerotier-nx still serves it when its title ID doesn't start
with `01`, which is the case for forwarders made by the usual tools (their
IDs mostly start with `05`); Nintendo's games and apps all start with `01`.

A forwarder whose ID does start with `01` needs listing: add its title ID
(16 hex digits) to `mitm_titles`, separating several with commas or spaces:

```ini
mitm_titles=01FF000000001000, 01FF000000002000
```

The title ID is the one the forwarder was made with. The tool that made it
shows it, and title managers such as DBI or Goldleaf list installed titles
with their IDs; when a forwarder uses the tunnel, the log shows its ID
("session from program ..."). List only forwarders, and restart after
changing it. The log shows which IDs were accepted. `mitm=off` turns all of
this off.

### FTP through the tunnel (sys-ftpd)

With `mitm=homebrew,sys-ftpd`, the sys-ftpd sysmodule is also reachable on
the Switch's tunnel address, e.g. `ftp://10.253.0.2:5000`. This costs about
70 KB more memory, and zerotier-nx restarts sys-ftpd once at boot to take
it over. FTP on the local network keeps working as before.

sys-ftpd itself has two limits, with or without zerotier-nx:
- **Speed:** about 11–14 Mbit/s on the local network and less through the
  tunnel.
- **Back-to-back transfers:** after two large transfers in a row, it refuses
  connections for about 10 seconds while its sockets close.

For big transfers, the ftpd homebrew app is much faster. It reaches the
tunnel with the default `mitm=homebrew`.

Serving sys-ftpd also uses extra system sessions, which every sysmodule
shares. On consoles running many sysmodules, other homebrew (such as
Moonlight) may be unable to connect while it's on. If that happens, go back
to `mitm=homebrew`.

## Memory

zerotier-nx uses exactly **2.5 MB** of the memory the system sets aside for
sysmodules, taken once when it starts. It never grows or shrinks: about
0.8 MB of code and 1.7 MB of data, including a fixed heap of about 950 KB.
Busy tunnel sockets use more of that heap, up to the `overlay_budget_kb`
limit.

- The overlay shows how much system memory is free with everything loaded.
  Keep some free: Nintendo starts some system modules only when they're
  needed, and when there's no room one of them crashes (error 2001-0132,
  often in `hid`). If you see that, turn off a sysmodule you don't need.
  - This is the room left under the system's limit for sysmodules, the
    figure those crashes depend on. Other overlays, such as Sysmodules, may
    show a higher figure: they count unused memory instead.
- At boot zerotier-nx starts before most other sysmodules, so it can't
  tell yet how much they will leave. It watches for the first two minutes:
  if less than 512 KB was ever free, it says so in a notification (with
  Ultrahand) and in the log, and the overlay's memory line turns red while
  free memory stays that low.
- Started later from the overlay, it can tell: if less than 1 MB would be
  left, it doesn't start, and the overlay and the log say why.

## Troubleshooting

- **The overlay says "No config".**
  - There's no `.conf` to use in `config/zerotier-nx`, and the message says
    what to do: copy one there, or, if `config.ini`'s `conf=` names a file
    that isn't there, pick one of the others on the Config page.
  - A file saved as `wg0.conf.txt` (Windows hides the `.txt` by default) is
    renamed to `wg0.conf` at boot, so it works as it is.
- **The overlay says "Config error".**
  - It names the `.conf` and the line it couldn't read (a key that isn't
    valid base64, a missing `PrivateKey` or `Address`, an unknown setting).
    Fix the file and restart, or pick another file on the Config page.
- **The overlay says "Connecting..." and "No handshake yet".**
  - The server didn't answer. Check the `Endpoint` (host name or address,
    and port), that the port is forwarded to the server if you're away from
    home, that the server has the Switch's public key as a peer, and the
    pre-shared key if there is one. **Connections** shows per peer whether
    its endpoint is resolved and when it last answered.
  - A console whose clock is badly wrong can't handshake either (WireGuard
    checks timestamps). zerotier-nx corrects a wrong clock from the
    network; if the log says it couldn't, set the clock.
- **The overlay says "Idle".**
  - It was connected, but no peer has answered for 3 minutes. Without
    `PersistentKeepalive`, that's normal when nothing uses the tunnel; the
    next connection handshakes again. If it stays like this while an app is
    trying, the server has gone away.
- **The overlay says the sysmodule isn't running.**
  - If it says which firmware this version runs on, the console's firmware
    is newer than that: update zerotier-nx. A new major firmware (24.0,
    say) needs a new zerotier-nx built for it, which can take a few days
    after Atmosphère supports it; minor updates (23.5 to 23.6) don't.
  - Check that `atmosphere/contents/4200000000005A54/flags/boot2.flag`
    exists.
  - If `config/zerotier-nx/crashed` exists, zerotier-nx turned itself off.
    It does this after 3 boots in a row that ended within 3 minutes, or 2
    sleeps the console never woke from. The file says which. **Turn back on**
    in the overlay deletes it and starts zerotier-nx again.
  - If `config/zerotier-nx/disabled` exists, delete it.
  - If tailscale-nx is also installed and running, only one of the two can
    serve homebrew: turn the other off in Sysmodules.
- **The overlay says "No internet connection."**
  - The Switch lost its internet connection. zerotier-nx reconnects on its
    own once it's back. On hotel or café Wi-Fi, sign in to the network
    first.
- **The overlay says "Not responding".**
  - zerotier-nx has stopped answering. Restart the console, and send us
    `sysmodule.log.1` (the boot before the restart).
- **What happened?**
  - The log is in `config/zerotier-nx/sysmodule.log`, and the previous
    boot's log is in `sysmodule.log.1`.
  - To watch it live, set `log_udp` to a computer's address.
- **An app reports "no buffer space" (errno 105).**
  - All apps share the tunnel socket memory. Raise `overlay_budget_kb`.
- **Moonlight is slow or choppy away from home.**
  - Check Moonlight's bitrate is within the
    [limits we found safe](../README.md#moonlight), and that
    the PC is added by name (a peer name, or a `# Host =` line): a PC added
    by a local-network address (`10.x`, `172.16.x` to `172.31.x`,
    `192.168.x`) is only safe up to 20 Mbit/s at 720p.
- **Moonlight finds the PC at home but not away.**
  - Check that Moonlight's saved host includes the peer name or a tunnel
    address, that `AllowedIPs` covers the PC's address, and that the overlay
    shows **Connected**.

Still stuck? Ask on [Discord](https://discord.gg/GjUuBEqRYb) or
[open an issue](https://github.com/UnderwaterOverground/zerotier-nx/issues),
with your `sysmodule.log`.
