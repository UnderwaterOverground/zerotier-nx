# Setting up zerotier-nx

zerotier-nx puts a modded Switch on your [ZeroTier](https://www.zerotier.com)
network. It runs in the background from boot. Homebrew such as Moonlight can
then reach your PC and the other devices on the network, from anywhere,
without port forwarding.

It affects **homebrew only** (apps launched from hbmenu or another homebrew
launcher, and home-screen forwarders). Games and Nintendo's own apps never
see the network.

## What you need

- **Atmosphère**: tested with 1.12.2 on firmware 22.5.0. To set it up,
  follow the [NH Switch Guide](https://switch.hacks.guide/).
- **[Ultrahand Overlay](https://github.com/ppkantorski/Ultrahand-Overlay)**
  with nx-ovlloader. It is optional, but you need it to see the Switch's
  ZeroTier ID easily, and for the status screen, the device list and the
  notifications.
- A **ZeroTier network**: make one at [my.zerotier.com](https://my.zerotier.com)
  (free), or on a controller of your own. Install ZeroTier on the devices
  the Switch should reach (your PC, say) and join them to it.

## Install

The [README](../README.md#installation) walks through it step by step,
including how to copy the files on Windows and on a Mac. In short, copy these
to the SD card, adding them to the folders already there:

| Path | What |
|---|---|
| `atmosphere/contents/4200000000005A54/` | The sysmodule. `flags/boot2.flag` makes it start at boot. |
| `switch/.overlays/zerotier-nx.ovl` | The overlay: status, this Switch's ID, devices, a pause switch, stop and start |
| `config/zerotier-nx/config.ini.example` | Settings template: copy it to `config.ini` and set `network=` |

Then restart the console.

## Joining the network

Two things are needed: the Switch must know which network to join, and the
network must let the Switch in.

1. **The network ID.** Copy `config/zerotier-nx/config.ini.example` to
   `config.ini` in the same folder, and set `network=` to the network's
   16-character ID (on the network's page at my.zerotier.com). Only that
   line is needed. Restart.
2. **Authorize the Switch.** Networks are private by default: a new member
   waits until it's authorized. The overlay shows **Authorize** with the
   Switch's 10-character ZeroTier ID. At my.zerotier.com, open the network,
   find that ID under **Members** and authorize it; on your own controller,
   authorize it there (`zerotier-cli` or the controller's web interface).
   The Switch notices within a few seconds and shows **Connected** with its
   address. Giving it a name in the member list helps you find it later.

The address comes from the network's settings, like any member's. To keep
it the same (handy for the devices that connect to the Switch), assign one
in the member list.

### The Switch's identity

Every ZeroTier device has an identity: its 10-character ID and the keys
that go with it. zerotier-nx makes the Switch's at the first boot and keeps
it in `config/zerotier-nx/identity.secret` (and `identity.public`).

- Making one borrows 2 MB of memory for a few seconds, so zerotier-nx waits
  until the console has finished starting up: about two minutes after
  power-on, and until 3 MB is free. The overlay shows the ID once it's
  there.
- If the console never has 3 MB free, the overlay says so. Turn off a
  sysmodule you don't need, or make an identity on a computer with ZeroTier
  installed and copy it over:

  ```sh
  zerotier-idtool generate identity.secret identity.public
  ```

  Copy both files to `config/zerotier-nx` and restart.
- The identity is the Switch's membership. Keep `identity.secret` private,
  and don't copy it to a second console: two devices with one ID take turns
  dropping each other off the network. Deleting it gives the Switch a new ID
  at the next boot, which then needs authorizing again.

## Using it

- **Moonlight:** add your PC by a name (below) rather than its ZeroTier
  address. At home, Moonlight may also find the PC on the local network and
  use that, which is fine. Away from home, it goes over ZeroTier.
- **Names:** ZeroTier itself has no device names, so name the devices you
  use in `config.ini`, one line each:

  ```ini
  host = gaming-pc 10.147.17.5
  host = nas 192.168.1.20
  ```

  The address can be a member's ZeroTier address or any address the
  network routes to (see [Routes and your own network](#routes-and-your-own-network)).
  The names are written into the hosts file Atmosphère is using
  (`atmosphere/hosts/emummc.txt`, `sysmmc.txt` or `default.txt`), so every
  homebrew app can use them.
  - A private address (`10.x`, `172.16.x` to `172.31.x`, `192.168.x`, which
    is where ZeroTier networks usually are) is written as a stand-in in
    `100.127.0.0/16` with the same last two numbers (`10.147.17.5` becomes
    `100.127.17.5`), so Moonlight sends video packets that fit one ZeroTier
    packet (see the [README](../README.md#moonlight)). Homebrew reaching the
    stand-in reaches the real address, and sees the stand-in as the other
    end. Other programs don't use the network, so they're unaffected.
    `aliases=off` in `config.ini` writes the real addresses instead.
  - A stand-in always goes over ZeroTier, even at home, so a stream by name
    takes that path there too.
  - Atmosphère's Nintendo blocking is left alone, and names containing
    "nintendo" are never added.
  - If there's no hosts file, names stay off. zerotier-nx never creates
    one. `hosts=off` in `config.ini` turns this off.
- **Connected notice:** after each boot, a 5-second toast shows
  "Connected. IP: 10.x.y.z" once the Switch is on the network. It doesn't
  appear again on wake or reconnect. Turn it off with **Connection notice**
  in the overlay.
- **Update notice:** after each boot, 10 seconds after it connects,
  zerotier-nx asks GitHub for the latest release. If it's newer than the
  installed one, a 10-second toast says so. If GitHub can't be reached,
  nothing happens (the reason is in `sysmodule.log`). This request shows
  GitHub the console's public IP address, as any web request does. Nothing
  else is sent. Turn it off with **Check for updates** in the overlay.
- **Devices:** the overlay's **Devices** page lists the devices the Switch
  is in contact with: green when connected directly, with the latency;
  yellow when relayed through ZeroTier's servers (slower; usually a network
  that blocks direct connections at one end). Press **A** on one for its
  ZeroTier ID, its address on the network, the path, when the last packet
  arrived and its ZeroTier version. ZeroTier's own servers are listed too.
- **Network:** the overlay's **Network** page shows the network's name and
  ID, this Switch's ID and address, and the network's status, with a
  warning if some of its settings didn't fit (see [Limits](#limits)).
- **Pause:** use the **ZeroTier** switch in the overlay. While paused,
  connections to the network fail at once and everything else works
  normally. The setting survives a restart.
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

## Routes and your own network

Homebrew reaches the network's own addresses (its subnet, such as
`10.147.17.0/24`) and every managed route in the network's settings.

To reach devices that don't run ZeroTier, such as everything else on your
home network, one member at home has to forward traffic for them, and the
network needs a managed route for their subnet through that member (for
example `192.168.1.0/24` via `10.147.17.5`). ZeroTier's guide
[Route between ZeroTier and physical networks](https://docs.zerotier.com/route-between-phys-and-virt/)
covers the member's side. Nothing needs setting on the Switch: it follows
the network's routes as they change.

- Addresses on the network the Switch is on are always reached directly,
  never over ZeroTier, even when a route covers them: at home, Moonlight
  talks to the PC over Wi-Fi as it always did. Away from home the same
  addresses go over ZeroTier. Loopback, link-local, multicast and broadcast
  addresses never go over ZeroTier either.
- A default route (`0.0.0.0/0`) is ignored: homebrew's internet traffic
  never goes through the network, and the console's own traffic is never
  touched.
- Inbound connections work too: anything the network's rules let through
  reaches homebrew listening on the Switch (an FTP server, say).

## Settings (`config/zerotier-nx/config.ini`)

Only `network` is needed. The others are optional, and take effect after a
restart. `config.ini.example` has them all, with notes.

| Key | Default | What |
|---|---|---|
| `network` | none | The network to join: its 16-character ID |
| `host` | none | `host = name address`: a name for an address on the network (any number of lines; see [Using it](#using-it)) |
| `port` | worked out from the Switch's ID | ZeroTier's UDP port. The default is between 20000 and 65499 and always the same for a Switch, so it can't clash with a computer on the same Wi-Fi using ZeroTier's usual 9993. Set it only if you forward a port to the Switch. |
| `hosts` | `on` | `off` stops writing names to the hosts file |
| `aliases` | `on` | `off` writes the real private addresses to the hosts file, not stand-ins (see [Using it](#using-it)) |
| `connect_notice` | `on` | `off` turns off the "Connected" toast at boot (as does the overlay switch) |
| `update_check` | `on` | `off` stops checking GitHub for a newer release at boot (as does the overlay switch) |
| `mitm` | `homebrew` | Which programs can reach the network: `homebrew`, `off`, or `homebrew,sys-ftpd` (see below) |
| `mitm_titles` | none | Title IDs of home-screen forwarders that aren't found automatically, up to 16 (see below) |
| `overlay_budget_kb` | `320` | Memory for the network's sockets, shared by all apps (128–384). Raise it only if apps report "no buffer space". |
| `log_udp` | none | Send the log to `ip:port` over UDP (an address on the network works from anywhere) |

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
with their IDs; when a forwarder uses the network, the log shows its ID
("session from program ..."). List only forwarders, and restart after
changing it. The log shows which IDs were accepted. `mitm=off` turns all of
this off.

### FTP over ZeroTier (sys-ftpd)

With `mitm=homebrew,sys-ftpd`, the sys-ftpd sysmodule is also reachable on
the Switch's ZeroTier address, e.g. `ftp://10.147.17.20:5000`. This costs
about 70 KB more memory, and zerotier-nx restarts sys-ftpd once at boot to
take it over. FTP on the local network keeps working as before.

sys-ftpd itself has two limits, with or without zerotier-nx:
- **Speed:** about 11–14 Mbit/s on the local network, and less over
  ZeroTier.
- **Back-to-back transfers:** after two large transfers in a row, it refuses
  connections for about 10 seconds while its sockets close.

For big transfers, the ftpd homebrew app is much faster. It reaches the
network with the default `mitm=homebrew`.

Serving sys-ftpd also uses extra system sessions, which every sysmodule
shares. On consoles running many sysmodules, other homebrew (such as
Moonlight) may be unable to connect while it's on. If that happens, go back
to `mitm=homebrew`.

## Limits

To fit in 2.5 MB, zerotier-nx holds less of a network's settings than
ZeroTier on a computer does. Ordinary networks are far inside these limits:

- 16 managed routes, 8 addresses for the Switch, and 128 rule entries. If
  a network has more routes or addresses than that, the rest are left out
  and the overlay says so. If it has more rules, its traffic is blocked,
  and the overlay says that too.
- 48 devices in contact at once. Past that, the one heard from longest ago
  makes room, and is found again when it's needed, so more than 48 devices
  talking to the Switch at the same time get slow and unreliable
  connections (fine for a network that big where only a few talk to it).
  The Devices page lists the first 32.
- One network, IPv4 only. IPv6 addresses (including 6PLANE and RFC 4193)
  aren't used, and neither is the network's DNS setting.
- Networks that need single sign-on (SSO) can't be joined.

## Memory

zerotier-nx uses exactly **2.5 MB** of the memory the system sets aside for
sysmodules, taken once when it starts. It never grows or shrinks: about
1.3 MB of code and fixed data, and a heap of about 1.2 MB that holds
ZeroTier's state and the network's sockets (up to the `overlay_budget_kb`
limit).

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

- **The overlay says "No network set".**
  - There's no `config/zerotier-nx/config.ini`, or it has no `network=`
    line. Copy `config.ini.example` to `config.ini`, set `network=` and
    restart. (On Windows, check the file isn't really `config.ini.txt`.)
- **The overlay says "Not authorized".**
  - Authorize the ID it shows in the network's member list. If the ID isn't
    listed there, check that `network=` is the right network.
- **The overlay says "No such network".**
  - No controller knows that network ID: check `network=`. (A network
    deleted at my.zerotier.com says this too.)
- **The overlay says "Asking the network's controller..." for a long time.**
  - The controller doesn't answer. At my.zerotier.com that's rare and
    passes; a self-hosted controller must be running and reachable over
    UDP.
- **The overlay says "ZeroTier's servers don't answer."**
  - The Wi-Fi network blocks ZeroTier's UDP traffic. Some hotel, school and
    work networks do; try another network or a phone's hotspot.
- **A device is yellow (relayed) on the Devices page.**
  - It works, but more slowly: ZeroTier couldn't connect the two directly,
    usually because of strict NAT or a firewall at one end. Streaming over
    a relay is unlikely to be smooth. Forwarding a UDP port to the PC (its
    ZeroTier port, 9993 by default) often fixes it.
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
  - If tailscale-nx or wireguard-nx is also installed and running, only one
    of them can serve homebrew: turn the others off in Sysmodules.
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
  - All apps share the network's socket memory. Raise `overlay_budget_kb`.
- **Moonlight is slow or choppy away from home.**
  - Check Moonlight's bitrate is within the
    [limits we found safe](../README.md#moonlight), that the PC is added by
    a name from a `host =` line (a PC added by its ZeroTier address is only
    safe up to 20 Mbit/s at 720p), and that the PC is green (direct) on the
    Devices page.
- **Moonlight finds the PC at home but not away.**
  - Check that Moonlight's saved host is the name from your `host =` line
    (or a ZeroTier address), and that the overlay shows **Connected**.

Still stuck? Ask on [Discord](https://discord.gg/GjUuBEqRYb) or
[open an issue](https://github.com/UnderwaterOverground/zerotier-nx/issues),
with your `sysmodule.log`.
