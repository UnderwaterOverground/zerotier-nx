# zerotier-nx

[![Release](https://img.shields.io/github/v/release/UnderwaterOverground/zerotier-nx)](https://github.com/UnderwaterOverground/zerotier-nx/releases/latest)
[![License](https://img.shields.io/badge/license-GPL--2.0%20%2F%20BSD--3%20%2F%20MPL--2.0-blue)](#licence)
[![Discord](https://img.shields.io/badge/Discord-join-5865F2?logo=discord&logoColor=white)](https://discord.gg/YgHetJguaF)

ZeroTier for the Nintendo Switch. Connect your homebrew to your ZeroTier network to stream from your PC with Moonlight, reach your NAS, or use your home network while you're away.

It runs in the background on Atmosphère. You don't need port forwarding or a server of your own. ZeroTier helps your devices find each other, and they connect directly when the network allows it.

> Unofficial project. Not affiliated with Nintendo or ZeroTier, Inc. ZeroTier is a trademark of ZeroTier, Inc.

## What it does

<img src="docs/images/devices.png" align="right" width="280" alt="ZeroTier devices in Ultrahand">

- Starts at boot and reconnects after sleep, a Wi-Fi change or a dropped connection.
- Works with homebrew launched through hbmenu, including supported home-screen forwarders.
- Joins a ZeroTier network hosted at [my.zerotier.com](https://my.zerotier.com) or on your own controller.
- Supports managed routes, so a device at home can give your Switch access to the rest of your home network.
- Lets you set your network ID on the Switch, from the overlay.
- Makes Moonlight send smaller packets that fit ZeroTier's, whether you add your PC by its ZeroTier address or by a name you give it.
- Includes an Ultrahand overlay with connection status, your Switch's ZeroTier ID, the network to join, and the devices it's in contact with. You can see latency and whether each connection is direct or relayed, or pause, start and stop the service.
- Offers optional update notifications and [sys-ftpd](https://github.com/cathery/sys-ftpd) access over ZeroTier.
- Uses a fixed 2.5 MB of memory.

## What you'll need

- A Switch running [Atmosphère](https://github.com/Atmosphere-NX/Atmosphere). Tested on a Mariko with Atmosphère 1.12.2 and firmware 22.5.0.
- [Ultrahand](https://github.com/ppkantorski/Ultrahand-Overlay) for the overlay and notifications. It's optional, but recommended; the setup steps below use it.
- A ZeroTier network. A free account at [my.zerotier.com](https://my.zerotier.com) is the easiest way to make one. A self-hosted controller works too.

## Installation

### 1. Download and extract the ZIP

Download the ZIP from **Assets** on the [latest release](https://github.com/UnderwaterOverground/zerotier-nx/releases/latest) page. Choose the release ZIP, not either of the “Source code” downloads, then extract it on your computer.

### 2. Copy the files to your SD card

Turn the Switch off before removing its SD card, then open the card on your computer.

The **SD card root** means the first folder you see when you open the card. Your existing `atmosphere` and `switch` folders should be there. All the destinations below start from that folder.

Copy these three items from the extracted ZIP:

| In the extracted ZIP | Where to put it on the SD card |
|---|---|
| The `4200000000005A54` folder inside `atmosphere/contents` | Inside `atmosphere/contents` |
| The `zerotier-nx.ovl` file inside `switch/.overlays` | Inside `switch/.overlays` |
| The `zerotier-nx` folder inside `config` | Inside `config` |

Create any missing destination folders first. Copy the whole `4200000000005A54` and `zerotier-nx` folders, including everything inside them.

**On macOS:** press **Cmd + Shift + .** in Finder to show the hidden `.overlays` folder. Follow the table above rather than dragging the ZIP's whole `atmosphere`, `config` or `switch` folders onto the card. Finder may replace an existing folder, which could remove files from the rest of your setup.

To check you've put things in the right place, look for these files on the card:

```text
SD card
├── atmosphere
│   └── contents
│       └── 4200000000005A54
│           └── exefs.nsp
├── switch
│   └── .overlays
│       └── zerotier-nx.ovl
└── config
    └── zerotier-nx
        └── config.ini.example
```

This only shows the files to check. Keep the other files copied from the ZIP, along with everything that was already on your card.

### 3. Enter your network ID

Put the SD card back in and turn the Switch on. Open Ultrahand with **L + D-pad Down + R3**, select **ZeroTier**, then select **Network**.

Enter your network's 16-character ID on the keypad, by touch or with the D-pad and **A**, then select **Join**. You'll find the ID on your network's page at [my.zerotier.com](https://my.zerotier.com), or in your controller if you're hosting one yourself.

The ID is saved on the `network=` line of `config/zerotier-nx/config.ini`. You can also set it there on a computer instead: copy `config.ini.example` to `config.ini` in that folder and put your ID on its `network=` line.

### 4. Find the Switch's ID

On the first boot, zerotier-nx creates the Switch's ZeroTier identity about two minutes after power-on, once the console has finished starting up. Until then the overlay shows **Getting ready**. You can enter the network ID meanwhile.

Once the identity exists, the overlay shows **Not authorized**, with **Authorize** and a 10-character ID below it.

The 10-character ID identifies your Switch. It's different from the 16-character network ID you entered.

### 5. Authorise the Switch

Open your network at [my.zerotier.com](https://my.zerotier.com), find the Switch's 10-character ID under **Members**, and authorise it. If you use your own controller, approve the Switch in its member list.

After a few seconds, the overlay should show **Connected** and the Switch's ZeroTier address. From then on, you'll get a connection notification after each boot if you're using Ultrahand.

### If it doesn't connect

The overlay should tell you what's missing:

| Message or problem | What to check |
|---|---|
| **No network set** | Select **Network** in the overlay and enter your network's ID. |
| **Too little memory** | Creating the Switch's identity needs 3 MB of free memory once. Turn off a sysmodule you don't need, or create the identity on a computer: see [the Switch's identity](docs/SETUP.md#the-switchs-identity). |
| **Not authorized** | Authorise the Switch's ID in your network's member list. |
| **No such network** | Check the network ID: select **Network** in the overlay to see or change it. |
| **ZeroTier's servers don't answer** | The Wi-Fi network may be blocking ZeroTier's UDP traffic. Some hotel, school and work networks do this. |
| **No ZeroTier menu in Ultrahand** | Check that `zerotier-nx.ovl` is inside `switch/.overlays` on the SD card. |

There's more detail in the [setup and troubleshooting guide](docs/SETUP.md).

### Updating

Download and extract the newer release ZIP, then copy its files to the same locations on your SD card and restart the Switch. Replace older files when prompted.

Keep the existing folders and copy the new files into them. Don't delete the folders first or choose an option that replaces an entire folder. Your settings and the Switch's identity are kept when you update this way.

## Using Moonlight

Add your PC to Moonlight by its ZeroTier address, or by a name you give it.

Moonlight treats private IP addresses, which most ZeroTier networks use, as local connections. It then sends packets too large to fit in a single ZeroTier packet. zerotier-nx maps the PC to a stand-in address that makes Moonlight use smaller packets. With an address, that happens as soon as Moonlight first contacts the PC, which it does when it lists it.

To use a name instead, add a `host` line to `config/zerotier-nx/config.ini`:

```ini
host = gaming-pc 10.147.17.5
```

Replace `10.147.17.5` with your PC's ZeroTier address. You can keep `gaming-pc` or choose another name. Restart the Switch, then add that name in Moonlight.

Names and stand-ins are written to Atmosphère's hosts file, so you'll need an existing hosts file in `atmosphere/hosts`. Most setups already have one.

At **720p and 60 FPS**, these are the bitrates I found reliable when testing with full-screen moving noise:

| Packets Moonlight sends | Reliable bitrate in my testing |
|---|---|
| Smaller (through the stand-in) | 25 Mbit/s |
| Larger (no hosts file) | 20 Mbit/s |

Artemis defaults to 35 Mbit/s at 1080p. Lower that to 20 Mbit/s, or use 720p.

## Reaching the rest of your home network

You can also reach devices that don't run ZeroTier, such as a NAS or printer, or connect to your PC using its home LAN address. You'll need two things set up first:

1. A device at home that's on your ZeroTier network and configured to route traffic to your home network.
2. A managed route in ZeroTier that sends traffic for your home subnet through that device. For example, `192.168.1.0/24` via `10.147.17.5`.

ZeroTier's [guide to routing between ZeroTier and physical networks](https://docs.zerotier.com/route-between-phys-and-virt/) covers that setup. Once it's done, zerotier-nx follows the managed routes automatically. There's nothing extra to configure on the Switch.

Devices on the Wi-Fi network your Switch is currently using are reached directly, without going through ZeroTier.

## Limitations

- **Homebrew only.** Games and Nintendo services don't use ZeroTier. Home-screen forwarders with title IDs starting `01` need an entry in `mitm_titles`; see the [forwarder setup instructions](docs/SETUP.md#home-screen-forwarders).
- **One network at a time, IPv4 only.** IPv6 addresses, including 6PLANE and RFC 4193, aren't used.
- **No default route.** Homebrew's internet traffic doesn't go through ZeroTier, even if your network has a `0.0.0.0/0` route.
- **ZeroTier's DNS settings aren't used.** Give devices names with `host =` lines in `config.ini` instead.
- **Networks requiring single sign-on (SSO) aren't supported.**
- **Stopping it takes a little care.** Close your homebrew first, then choose **Stop** in the ZeroTier overlay. That stops it without a reboot. If you disable it in Sysmodules instead, you'll need to restart the Switch.
- **Tested on one Mariko Switch so far.** Reports from other models are welcome.

## FAQ

**Will this affect online games or Nintendo services?**

No. It only handles homebrew traffic going to your ZeroTier network's addresses and routes. It also leaves Atmosphère's Nintendo-server blocking alone.

**Will it keep working after a system update?**

Minor updates (say 23.5 to 23.6) are fine. A new major version (24.0) needs a new zerotier-nx: until then it won't start, and the overlay tells you which firmware it runs on. Update Atmosphère first, as you would anyway. A new release normally follows soon after Atmosphère's, and the update notification lets you know when it's out.

**Can I run it alongside tailscale-nx or wireguard-nx?**

You can have all three installed, but only one can handle homebrew traffic at a time. Disable the others in Sysmodules.

**Is the connection private?**

ZeroTier encrypts traffic end to end between devices on the network. Its root servers help devices find each other and relay traffic when a direct connection isn't possible, but they can't read that traffic. Your network's controller, whether that's my.zerotier.com or your own, decides who can join.

The optional update check contacts GitHub.

**Why do I get an orange screen when waking the Switch during a Moonlight stream?**

That's a [Moonlight-Switch issue](https://github.com/XITRIX/Moonlight-Switch/issues/306) that also happens without zerotier-nx. End the stream before putting the Switch to sleep.

**Where can I get help?**

Have a look at the [troubleshooting guide](docs/SETUP.md#troubleshooting), join [Discord](https://discord.gg/YgHetJguaF), or [open an issue](https://github.com/UnderwaterOverground/zerotier-nx/issues). If you're reporting a bug, include `config/zerotier-nx/sysmodule.log`.

## Building and credits

Build instructions are in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). The build runs in Docker, and most tests don't need a Switch.

This project is forked from [wireguard-nx](https://github.com/UnderwaterOverground/wireguard-nx), itself a fork of [tailscale-nx](https://github.com/UnderwaterOverground/tailscale-nx). It replaces the WireGuard engine with [ZeroTier](https://github.com/zerotier/ZeroTierOne)'s core.

It uses [libstratosphere](https://github.com/Atmosphere-NX/Atmosphere), [libnx](https://github.com/switchbrew/libnx), [libtesla](https://github.com/WerWolv/libtesla), [smoltcp](https://github.com/smoltcp-rs/smoltcp), [rustls](https://github.com/rustls/rustls) and [RustCrypto](https://github.com/RustCrypto). It also draws on [sys-GRID0](https://github.com/redluigi323/sys-GRID0) and [ryu_ldn_nx](https://github.com/Ethiquema/ryu_ldn_nx).

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for third-party licences.

## Licence

The sysmodule, overlay and socket layer are GPL-2.0-or-later ([LICENSE](LICENSE)). The Rust code under `crates/` is BSD-3-Clause ([crates/LICENSE](crates/LICENSE)). ZeroTier's core is MPL-2.0; the changes made to it are in `patches/` and listed in [VENDORED.md](VENDORED.md).

## Found it useful?

If zerotier-nx helped you, a ⭐ on the repo is always appreciated. It's how
we know it's helping someone.
