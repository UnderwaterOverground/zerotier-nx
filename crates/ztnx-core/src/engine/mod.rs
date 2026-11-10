//! The WireGuard engine: one tunnel interface configured from a wg-quick
//! style file (see [`crate::config`]), the peers it lists, and the overlay
//! netstack homebrew sockets live on. Sans-IO like everything else: the
//! driver performs [`Io`], delivers datagrams with [`Engine::handle_udp`],
//! answers [`Event::Resolve`] with [`Engine::set_peer_endpoint`], and calls
//! [`Engine::handle_timeout`] at [`Engine::next_deadline`].
//!
//! What the vendored `ts_tunnel` leaves to us: cryptokey routing (AllowedIPs
//! both ways), endpoints and roaming, PersistentKeepalive, the "no answer
//! for 15 s: handshake again" rule, and per-peer statistics.

pub mod packet;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;

use ts_keys::{NodeKeyPair, NodePrivateKey, NodePublicKey};
use ts_packet::PacketMut;
use ts_tunnel::{PeerConfig, PeerId};

use crate::awg;
use crate::config::{EndpointHost, WgConfig};
use crate::netstack::Netstack;
use crate::time::Instant;
pub use packet::Prefix;

/// Socket work for the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Io {
    /// Send a datagram from the engine's UDP socket.
    SendUdp { dst: SocketAddr, data: Vec<u8> },
}

/// Status changes for the UI / logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// This interface's addresses (once per [`Engine::reload`]).
    Addresses(Vec<Prefix>),
    /// Peer table replaced; how many peers (once per reload).
    Peers(usize),
    Error(String),
    Log(String),
    /// A peer's `Endpoint` is a host name: resolve it and call
    /// [`Engine::set_peer_endpoint`]. Repeated while the peer stays silent.
    Resolve { peer: usize, host: String, port: u16 },
    /// A handshake with the peer completed (either role).
    Handshake { peer: usize },
    /// Data went unanswered for [`NO_RESPONSE_REKEY`]: the session was
    /// dropped and a new handshake starts.
    PeerLost { peer: usize },
}

/// WireGuard's default interface MTU.
pub const DEFAULT_MTU: usize = 1420;
/// WireGuard: if data was sent but nothing received for KEEPALIVE_TIMEOUT +
/// REKEY_TIMEOUT, start a new handshake (ts_tunnel doesn't implement this).
pub const NO_RESPONSE_REKEY: Duration = Duration::from_secs(15);
/// Minimum spacing of handshakes started because of undecryptable data.
const HANDSHAKE_REPAIR_INTERVAL: Duration = Duration::from_secs(5);
/// A host-name endpoint is resolved again when there has been no handshake
/// for this long (wg-quick's reresolve-dns), at most every RESOLVE_MIN_INTERVAL.
const RERESOLVE_AFTER: Duration = Duration::from_secs(135);
const RESOLVE_MIN_INTERVAL: Duration = Duration::from_secs(30);
/// How often buffers that grew for a burst are shrunk back.
const TRIM_INTERVAL: Duration = Duration::from_secs(15);
/// WireGuard's REJECT_AFTER_TIME: a session whose handshake is older than
/// this is over. The UI's "up" means a handshake within it.
pub const SESSION_FRESH: Duration = Duration::from_secs(180);

struct Peer {
    name: String,
    key: NodePublicKey,
    psk: [u8; 32],
    has_psk: bool,
    /// What this peer may source, and what we route to it.
    allowed_ips: Vec<Prefix>,
    wg: PeerId,
    endpoint_conf: Option<(EndpointHost, u16)>,
    /// Where its packets go: the configured address, the resolved name, or
    /// wherever its last authenticated packet came from (roaming).
    endpoint: Option<SocketAddr>,
    keepalive: Option<Duration>,
    /// Any wire packet we sent it (keepalive timer base).
    last_tx: Option<Instant>,
    /// Last authenticated packet from it.
    last_rx: Option<Instant>,
    last_handshake: Option<Instant>,
    /// First data sent since we last heard anything from the peer.
    unanswered_since: Option<Instant>,
    /// Last time undecryptable data from this peer made us re-handshake.
    last_session_repair: Option<Instant>,
    last_resolve: Option<Instant>,
    rx_bytes: u64,
    tx_bytes: u64,
    no_endpoint_logged: bool,
    /// Handshake MACs and the peer's cookie, for AmneziaWG framing.
    macs: awg::PeerMacs,
}

/// A peer as the UI sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub name: String,
    /// Its first IPv4 /32 AllowedIP.
    pub ipv4: Option<Ipv4Addr>,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: Option<Duration>,
    /// Time since the last handshake.
    pub last_handshake: Option<Duration>,
    /// Time since the last authenticated packet from it.
    pub last_rx: Option<Duration>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// A handshake within [`SESSION_FRESH`].
    pub session: bool,
    /// `Endpoint` is a host name ...
    pub endpoint_name: bool,
    /// ... not resolved yet.
    pub resolving: bool,
    /// The endpoint differs from the configured one (learned from traffic).
    pub roamed: bool,
    pub psk: bool,
    pub default_route: bool,
    pub allowed_ips: usize,
}

pub struct Engine {
    wg: ts_tunnel::Endpoint,
    net: Netstack,
    addresses: Vec<Prefix>,
    mtu: usize,
    listen_port: Option<u16>,
    self_name: Option<String>,
    /// `# Host =` names the tunnel reaches, for the hosts file.
    extra_hosts: Vec<(Ipv4Addr, String)>,
    configured: bool,
    /// In .conf order; `PeerId(i + 1)`.
    peers: Vec<Peer>,
    /// AmneziaWG framing, when the .conf asks for it.
    awg: Option<awg::Params>,
    my_macs: awg::MyMacs,
    io: VecDeque<Io>,
    events: VecDeque<Event>,
    now: Instant,
    last_trim: Instant,
    /// Wall clock reference: at monotonic `.0`, Unix time was `.1`.
    wall: (Instant, Duration),
}

/// A WireGuard transport message carrying data: type 4, longer than the
/// 32 bytes (header + tag) of an empty keepalive.
fn is_wg_data(wire: &[u8]) -> bool {
    wire.len() > 32 && wire[0] == 4
}

impl Engine {
    /// An interface with no configuration yet: the netstack is up (so
    /// socket ids handed out later stay valid across reloads), with no
    /// address and no peers. Call [`Engine::reload`] to configure it.
    pub fn new(now: Instant, unix_time: Duration) -> Self {
        crate::tls::CLOCK.set(unix_time.as_secs());
        // Replaced by the configured key at reload; any key will do here.
        let placeholder = crate::rng::bytes32().unwrap_or([0x5a; 32]);
        Self {
            wg: ts_tunnel::Endpoint::new(NodeKeyPair::from(NodePrivateKey::from_bytes(placeholder))),
            net: Netstack::new(now, DEFAULT_MTU),
            addresses: Vec::new(),
            mtu: DEFAULT_MTU,
            listen_port: None,
            self_name: None,
            extra_hosts: Vec::new(),
            configured: false,
            peers: Vec::new(),
            awg: None,
            my_macs: awg::MyMacs::new(&crate::crypto::x25519_public(&placeholder)),
            io: VecDeque::new(),
            events: VecDeque::new(),
            now,
            last_trim: now,
            wall: (now, unix_time),
        }
    }

    /// Applies a configuration: a new WireGuard identity, peer table, MTU
    /// and addresses. Sessions start over; overlay sockets survive (ones
    /// bound to an address that went away will stall).
    #[inline(never)]
    pub fn reload(&mut self, cfg: WgConfig, now: Instant) {
        self.now = now;
        let mut wg = ts_tunnel::Endpoint::new(NodeKeyPair::from(NodePrivateKey::from_bytes(cfg.interface.private_key)));
        wg.set_wall_clock(self.wall.0, self.wall.1);
        let mut peers = Vec::with_capacity(cfg.peers.len());
        let mut errors = Vec::new();
        for (i, p) in cfg.peers.into_iter().enumerate() {
            let id = PeerId(i as u32 + 1);
            let key = NodePublicKey::from_bytes(p.public_key);
            wg.upsert_peer(PeerConfig::new(id, key, p.preshared_key.unwrap_or([0; 32])));
            let endpoint = match &p.endpoint {
                Some((EndpointHost::Ip(IpAddr::V4(ip)), port)) => Some(SocketAddr::new(IpAddr::V4(*ip), *port)),
                Some((EndpointHost::Ip(IpAddr::V6(_)), _)) => {
                    errors.push(format!("{}: IPv6 endpoints are not supported (the console connects over IPv4)", p.name));
                    None
                }
                _ => None,
            };
            peers.push(Peer {
                name: p.name,
                key,
                psk: p.preshared_key.unwrap_or([0; 32]),
                has_psk: p.preshared_key.is_some(),
                allowed_ips: p.allowed_ips,
                wg: id,
                endpoint_conf: p.endpoint,
                endpoint,
                keepalive: p.persistent_keepalive.map(|s| Duration::from_secs(s.into())),
                last_tx: None,
                last_rx: None,
                last_handshake: None,
                unanswered_since: None,
                last_session_repair: None,
                last_resolve: None,
                rx_bytes: 0,
                tx_bytes: 0,
                no_endpoint_logged: false,
                macs: awg::PeerMacs::new(&p.public_key),
            });
        }
        self.wg = wg;
        self.peers = peers;
        self.my_macs = awg::MyMacs::new(&crate::crypto::x25519_public(&cfg.interface.private_key));
        let awg_params = cfg.interface.awg;
        // S4 bytes ride on every transport message: with no MTU set, make
        // room for them, as the default 1420 does for WireGuard's own 60.
        let default_mtu = DEFAULT_MTU - usize::from(awg_params.prefix[3]);
        if awg_params.is_plain() {
            self.awg = None;
        } else {
            self.events.push_back(Event::Log(format!("AmneziaWG: {}", awg_params.summary())));
            self.awg = Some(awg_params);
        }
        self.mtu = cfg.interface.mtu.map_or(default_mtu, usize::from);
        self.net.set_mtu(self.mtu);
        let addrs: Vec<IpAddr> = cfg.interface.addresses.iter().map(|p| p.addr).collect();
        if self.net.addresses() != addrs.as_slice() {
            self.net.set_addresses(&addrs);
        }
        self.addresses = cfg.interface.addresses;
        self.listen_port = cfg.interface.listen_port;
        self.self_name = cfg.interface.name;
        self.extra_hosts.clear();
        for (name, ip) in cfg.hosts {
            if self.route(IpAddr::V4(ip)).is_none() {
                self.events.push_back(Event::Log(format!("Host {name}: {ip} isn't in any peer's AllowedIPs; not naming it")));
            } else if self.self_name.as_deref() == Some(name.as_str()) || self.peers.iter().any(|p| p.name == name) {
                self.events.push_back(Event::Log(format!("Host {name}: a peer already has that name; not naming {ip}")));
            } else {
                self.extra_hosts.push((ip, name));
            }
        }
        self.configured = true;
        self.events.push_back(Event::Addresses(self.addresses.clone()));
        self.events.push_back(Event::Peers(self.peers.len()));
        for e in errors {
            self.events.push_back(Event::Error(e));
        }
        for i in 0..self.peers.len() {
            if self.peers[i].default_route() {
                self.events.push_back(Event::Log(format!("{}: AllowedIPs has a default route; all of homebrew's internet traffic goes through it", self.peers[i].name)));
            }
            self.request_resolve(i);
            // Contact every peer we can now, so the UI shows the tunnel up
            // without waiting for an app to use it.
            if self.peers[i].endpoint.is_some() {
                self.kick(i);
            }
        }
        self.pump();
    }

    pub fn is_configured(&self) -> bool {
        self.configured
    }

    pub fn poll_io(&mut self) -> Option<Io> {
        self.io.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Our addresses with their prefix lengths, as configured.
    pub fn addresses(&self) -> &[Prefix] {
        &self.addresses
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// `[Interface] ListenPort`, if set.
    pub fn listen_port(&self) -> Option<u16> {
        self.listen_port
    }

    /// Everything that belongs to the tunnel, for the socket layer: our own
    /// addresses (as /32 and /128), then every peer's AllowedIPs, each once.
    pub fn routes(&self) -> Vec<Prefix> {
        let mut out: Vec<Prefix> = self.addresses.iter().map(|p| Prefix { addr: p.addr, len: if p.addr.is_ipv4() { 32 } else { 128 } }).collect();
        for p in self.peers.iter().flat_map(|p| p.allowed_ips.iter()) {
            if !out.contains(p) {
                out.push(*p);
            }
        }
        out
    }

    /// IPv4 address and name of this interface (if its .conf names it), of
    /// every peer with an IPv4 /32 AllowedIP and of each `# Host =` line,
    /// for a hosts file.
    pub fn hosts(&self) -> Vec<(Ipv4Addr, &str)> {
        let mut out = Vec::new();
        if let Some(name) = &self.self_name {
            if let Some(a) = self.addresses.iter().find_map(|p| match p.addr {
                IpAddr::V4(a) => Some(a),
                _ => None,
            }) {
                out.push((a, name.as_str()));
            }
        }
        for p in &self.peers {
            if let Some(a) = p.ipv4() {
                out.push((a, p.name.as_str()));
            }
        }
        for (a, name) in &self.extra_hosts {
            out.push((*a, name.as_str()));
        }
        out
    }

    /// Every peer, in .conf order.
    pub fn peers_info(&self) -> Vec<PeerInfo> {
        let now = self.now;
        let ago = |t: Option<Instant>| t.map(|t| now.saturating_duration_since(t));
        self.peers
            .iter()
            .map(|p| PeerInfo {
                name: p.name.clone(),
                ipv4: p.ipv4(),
                endpoint: p.endpoint,
                keepalive: p.keepalive,
                last_handshake: ago(p.last_handshake),
                last_rx: ago(p.last_rx),
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
                session: p.last_handshake.is_some_and(|t| now.saturating_duration_since(t) < SESSION_FRESH),
                endpoint_name: matches!(p.endpoint_conf, Some((EndpointHost::Name(_), _))),
                resolving: matches!(p.endpoint_conf, Some((EndpointHost::Name(_), _))) && p.endpoint.is_none(),
                roamed: match (&p.endpoint_conf, p.endpoint) {
                    (Some((EndpointHost::Ip(ip), port)), Some(cur)) => cur != SocketAddr::new(*ip, *port),
                    _ => false,
                },
                psk: p.has_psk,
                default_route: p.default_route(),
                allowed_ips: p.allowed_ips.len(),
            })
            .collect()
    }

    /// The overlay socket API. Call [`Engine::flush`] after using it so
    /// queued packets are sent.
    pub fn net(&mut self) -> &mut Netstack {
        &mut self.net
    }

    /// Re-runs the stack and flushes output after socket API calls.
    pub fn flush(&mut self, now: Instant) {
        self.now = now;
        self.pump();
    }

    pub fn next_deadline(&mut self) -> Instant {
        let now = self.now;
        let mut t = self.last_trim + TRIM_INTERVAL;
        if let Some(r) = self.wg.next_event() {
            t = t.min(r.end());
        }
        if let Some(at) = self.net.poll_at(now) {
            t = t.min(at);
        }
        for p in &self.peers {
            if let Some(u) = p.unanswered_since {
                t = t.min(u + NO_RESPONSE_REKEY);
            }
            if let (Some(ka), Some(_)) = (p.keepalive, p.endpoint) {
                t = t.min(p.last_tx.map_or(now, |l| l + ka));
            }
            if let Some(at) = self.resolve_due(p) {
                t = t.min(at);
            }
        }
        t
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        self.now = now;
        let ev = self.wg.dispatch_events(now);
        for (peer, pkts) in ev.to_peers {
            self.transmit(peer, pkts);
        }
        self.tick();
        self.pump();
        if now >= self.last_trim + TRIM_INTERVAL {
            self.last_trim = now;
            self.net.trim();
            self.io.shrink_to_fit();
            self.events.shrink_to_fit();
        }
    }

    /// A datagram arrived on the engine's UDP socket.
    pub fn handle_udp(&mut self, src: SocketAddr, data: &[u8], now: Instant) {
        self.now = now;
        self.handle_wg(data, src);
        self.pump();
    }

    /// The underlying network came back or changed (Wi-Fi after a wake, a
    /// new address): host names are resolved again and every reachable
    /// peer is contacted now, so the tunnel is back within a round trip
    /// instead of at the next keepalive.
    pub fn network_up(&mut self, now: Instant) {
        self.now = now;
        for i in 0..self.peers.len() {
            self.peers[i].last_resolve = None;
            self.request_resolve(i);
            if self.peers[i].endpoint.is_some() {
                self.kick(i);
            }
        }
        self.pump();
    }

    /// Answers [`Event::Resolve`] (or overrides a peer's endpoint).
    pub fn set_peer_endpoint(&mut self, peer: usize, addr: SocketAddr, now: Instant) {
        self.now = now;
        let Some(p) = self.peers.get_mut(peer) else { return };
        p.last_resolve = Some(now);
        if p.endpoint != Some(addr) {
            log::info!("{}: endpoint {addr}", p.name);
            p.endpoint = Some(addr);
        }
        p.no_endpoint_logged = false;
        self.kick(peer);
        self.pump();
    }

    // ---- plumbing --------------------------------------------------------

    fn index(&self, wg: PeerId) -> Option<usize> {
        let i = wg.0.checked_sub(1)? as usize;
        (i < self.peers.len()).then_some(i)
    }

    /// Finds the peer whose AllowedIPs contain `dst` (longest prefix).
    fn route(&self, dst: IpAddr) -> Option<usize> {
        self.peers
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.allowed_ips.iter().filter(|pre| pre.contains(dst)).map(|pre| pre.len).max().map(|l| (l, i)))
            .max_by_key(|(l, _)| *l)
            .map(|(_, i)| i)
    }

    /// Overlay stack -> tunnel.
    fn pump(&mut self) {
        self.net.poll(self.now);
        let outbound: Vec<Vec<u8>> = self.net.take_outbound().collect();
        if outbound.is_empty() {
            return;
        }
        let mut by_peer: BTreeMap<u32, Vec<PacketMut>> = BTreeMap::new();
        for mut pkt in outbound {
            let Some(dst) = packet::dst(&pkt) else { continue };
            let Some(i) = self.route(dst) else {
                log::debug!("no route to {dst}");
                continue;
            };
            log::debug!("outbound {} bytes to {dst} via {}", pkt.len(), self.peers[i].name);
            packet::pad(&mut pkt, self.mtu);
            by_peer.entry(self.peers[i].wg.0).or_default().push(PacketMut::from(pkt));
        }
        let res = self.wg.send(self.now, by_peer.into_iter().map(|(id, p)| (PeerId(id), p)));
        for (peer, pkts) in res.to_peers {
            self.transmit(peer, pkts);
        }
    }

    /// Sends WireGuard wire packets to a peer's endpoint.
    fn transmit(&mut self, wg: PeerId, pkts: Vec<PacketMut>) {
        let Some(i) = self.index(wg) else { return };
        let now = self.now;
        let peer = &mut self.peers[i];
        peer.last_tx = Some(now);
        // As in WireGuard, only data we send expects an answer: keepalives
        // and handshake messages don't (a peer never replies to keepalives).
        if peer.unanswered_since.is_none() && pkts.iter().any(|p| is_wg_data(p.as_ref())) {
            peer.unanswered_since = Some(now);
        }
        let Some(dst) = peer.endpoint else {
            if !peer.no_endpoint_logged {
                peer.no_endpoint_logged = true;
                log::info!("{}: no endpoint yet; waiting for it to contact us", peer.name);
            }
            return;
        };
        let unix_secs = (self.wall.1 + now.saturating_duration_since(self.wall.0)).as_secs() as u32;
        for p in pkts {
            let wire = p.as_ref();
            let data = match &self.awg {
                None => wire.to_vec(),
                Some(awg) => {
                    if wire.first() == Some(&1) {
                        for junk in awg.preamble(unix_secs) {
                            peer.tx_bytes += junk.len() as u64;
                            self.io.push_back(Io::SendUdp { dst, data: junk });
                        }
                    }
                    awg.wrap(wire, &mut peer.macs, now)
                }
            };
            peer.tx_bytes += data.len() as u64;
            self.io.push_back(Io::SendUdp { dst, data });
        }
    }

    /// An AmneziaWG cookie reply: for whichever peer's last handshake
    /// message it answers (the one at its source address, most likely).
    fn cookie_reply(&mut self, src: SocketAddr, nonce: [u8; 24], sealed: [u8; 32]) {
        let now = self.now;
        let first = self.peer_for_source(src);
        let order = first.into_iter().chain((0..self.peers.len()).filter(|i| Some(*i) != first));
        for i in order {
            if self.peers[i].macs.receive_cookie(&nonce, &sealed, now) {
                log::debug!("{}: cookie reply taken; the next handshake carries mac2", self.peers[i].name);
                return;
            }
        }
        log::debug!("cookie reply from {src} matched no handshake of ours");
    }

    /// Sends the peer an empty packet: a keepalive if a session is up, else
    /// it queues and a handshake starts (ts_tunnel retries that itself).
    fn kick(&mut self, i: usize) {
        let wg = self.peers[i].wg;
        let res = self.wg.send(self.now, [(wg, alloc::vec![PacketMut::from(Vec::new())])]);
        for (peer, pkts) in res.to_peers {
            self.transmit(peer, pkts);
        }
    }

    /// The peer sent transport data for a session we don't have (we
    /// restarted or reset it). It will keep doing so until a new handshake,
    /// so start one now instead of waiting for its rekey timers.
    fn repair_session(&mut self, i: usize) {
        let now = self.now;
        let p = &mut self.peers[i];
        if p.last_session_repair.is_some_and(|t| now.saturating_duration_since(t) < HANDSHAKE_REPAIR_INTERVAL) {
            return;
        }
        p.last_session_repair = Some(now);
        log::info!("{} sent data for an unknown WireGuard session; re-handshaking", p.name);
        self.kick(i);
    }

    /// Drops the WireGuard session with a peer so the next packet starts a
    /// fresh handshake.
    fn reset_wg_session(&mut self, i: usize, why: &str) {
        let p = &mut self.peers[i];
        log::info!("resetting WireGuard session with {}: {why}", p.name);
        p.unanswered_since = None;
        p.last_handshake = None;
        let (wg, key, psk) = (p.wg, p.key, p.psk);
        self.wg.remove_peer(wg);
        self.wg.upsert_peer(PeerConfig::new(wg, key, psk));
    }

    fn peer_for_source(&self, src: SocketAddr) -> Option<usize> {
        self.peers.iter().position(|p| p.endpoint == Some(src))
    }

    fn handle_wg(&mut self, data: &[u8], src: SocketAddr) {
        let pkt = match &self.awg {
            None => data.to_vec(),
            Some(awg) => match awg.unwrap(data, &self.my_macs) {
                awg::Inbound::Message(m) => m,
                awg::Inbound::CookieReply { nonce, sealed } => return self.cookie_reply(src, nonce, sealed),
                awg::Inbound::Junk => {
                    log::trace!("awg: {} bytes from {src} are not a message", data.len());
                    return;
                }
            },
        };
        let ty = pkt.first().copied().unwrap_or(0);
        let res = self.wg.recv(self.now, [PacketMut::from(pkt)]);
        log::trace!(
            "wg in type {ty} len {} from {src}: {} to local, {} replies",
            data.len(),
            res.to_local.values().map(Vec::len).sum::<usize>(),
            res.to_peers.values().map(Vec::len).sum::<usize>()
        );
        // The sender proved its identity if the tunnel decrypted something
        // (an entry exists even for an empty keepalive) or answered its
        // handshake message (a response to an initiation, or the
        // confirmation of a response). ts_tunnel never sends cookie replies.
        let authed = res.to_local.keys().next().copied().or_else(|| {
            res.to_peers.iter().find(|(_, pkts)| pkts.iter().any(|p| matches!(p.as_ref().first(), Some(2 | 4)))).map(|(id, _)| *id)
        });
        if ty == 4 && authed.is_none() {
            // Transport data that produced nothing: a session we don't have.
            if let Some(i) = self.peer_for_source(src) {
                self.repair_session(i);
            }
        }
        if let Some(i) = authed.and_then(|wg| self.index(wg)) {
            let hs = self.wg.peer_last_handshake(self.peers[i].wg);
            let now = self.now;
            let p = &mut self.peers[i];
            p.last_rx = Some(now);
            p.unanswered_since = None;
            p.rx_bytes += data.len() as u64;
            if p.endpoint != Some(src) {
                log::info!("{}: now at {src}", p.name);
                p.endpoint = Some(src);
                p.no_endpoint_logged = false;
            }
            if hs.is_some() && hs != p.last_handshake {
                p.last_handshake = hs;
                self.events.push_back(Event::Handshake { peer: i });
            }
        }
        for (wg, pkts) in res.to_local {
            let Some(i) = self.index(wg) else { continue };
            for p in pkts {
                let mut p = p.as_ref().to_vec();
                // Keepalives are empty.
                let Some(len) = packet::ip_len(&p) else { continue };
                if len > p.len() {
                    continue;
                }
                p.truncate(len);
                // Cryptokey routing: the peer may only source its AllowedIPs.
                let Some(src_ip) = packet::src(&p) else { continue };
                if !self.peers[i].allowed_ips.iter().any(|pre| pre.contains(src_ip)) {
                    log::debug!("dropping packet from {src_ip}: not in {}'s AllowedIPs", self.peers[i].name);
                    continue;
                }
                self.net.inject(p);
            }
        }
        for (peer, pkts) in res.to_peers {
            self.transmit(peer, pkts);
        }
    }

    /// Periodic work: the 15 s rule, keepalives, re-resolving names.
    fn tick(&mut self) {
        let now = self.now;
        for i in 0..self.peers.len() {
            if self.peers[i].unanswered_since.is_some_and(|t| now.saturating_duration_since(t) >= NO_RESPONSE_REKEY) {
                self.reset_wg_session(i, "no response for 15s");
                self.events.push_back(Event::PeerLost { peer: i });
                if self.peers[i].endpoint.is_some() {
                    self.kick(i);
                }
            }
            let p = &self.peers[i];
            if let (Some(ka), Some(_)) = (p.keepalive, p.endpoint) {
                if p.last_tx.is_none_or(|t| now.saturating_duration_since(t) >= ka) {
                    self.kick(i);
                }
            }
            if self.resolve_due(&self.peers[i]).is_some_and(|at| now >= at) {
                self.request_resolve(i);
            }
        }
    }

    /// When a peer's host name should be resolved (again), if it has one.
    fn resolve_due(&self, p: &Peer) -> Option<Instant> {
        let Some((EndpointHost::Name(_), _)) = &p.endpoint_conf else { return None };
        let earliest = p.last_resolve.map_or(self.now, |t| t + RESOLVE_MIN_INTERVAL);
        let stale = match p.last_handshake {
            None => earliest,
            Some(h) => earliest.max(h + RERESOLVE_AFTER),
        };
        Some(stale)
    }

    fn request_resolve(&mut self, i: usize) {
        let p = &mut self.peers[i];
        let Some((EndpointHost::Name(host), port)) = &p.endpoint_conf else { return };
        p.last_resolve = Some(self.now);
        self.events.push_back(Event::Resolve { peer: i, host: host.clone(), port: *port });
    }
}

impl Peer {
    fn ipv4(&self) -> Option<Ipv4Addr> {
        self.allowed_ips.iter().find_map(|p| match p.addr {
            IpAddr::V4(a) if p.len == 32 => Some(a),
            _ => None,
        })
    }

    fn default_route(&self) -> bool {
        self.allowed_ips.iter().any(|p| p.len == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Interface, PeerConf};

    const A_ADDR: &str = "192.0.2.1:41641";
    const B_ADDR: &str = "192.0.2.2:51820";
    const A_PRIV: [u8; 32] = [11; 32];
    const B_PRIV: [u8; 32] = [22; 32];

    fn prefix(s: &str) -> Prefix {
        crate::config::address(s).unwrap()
    }

    fn conf(private: [u8; 32], addr: &str, peers: Vec<PeerConf>) -> WgConfig {
        conf_awg(private, addr, peers, Default::default())
    }

    fn conf_awg(private: [u8; 32], addr: &str, peers: Vec<PeerConf>, awg: awg::Params) -> WgConfig {
        WgConfig { interface: Interface { private_key: private, addresses: alloc::vec![prefix(addr)], listen_port: None, mtu: None, name: None, awg }, peers, hosts: Vec::new() }
    }

    fn awg_params() -> awg::Params {
        awg::Params {
            junk_count: 3,
            junk_min: 40,
            junk_max: 70,
            prefix: [15, 22, 4, 8],
            header: [awg::Range { lo: 100, hi: 200 }, awg::Range::one(300), awg::Range::one(400), awg::Range { lo: 500, hi: 600 }],
            signatures: alloc::vec![awg::Signature::parse("<b 0x474554><r 8>").unwrap()],
            header_key: None,
            random_trailers: false,
        }
    }

    fn peer(private_of_peer: [u8; 32], name: &str, allowed: &[&str], endpoint: Option<(EndpointHost, u16)>, keepalive: Option<u16>) -> PeerConf {
        PeerConf {
            public_key: crate::crypto::x25519_public(&private_of_peer),
            preshared_key: None,
            allowed_ips: allowed.iter().map(|a| prefix(a)).collect(),
            endpoint,
            persistent_keepalive: keepalive,
            name: name.into(),
        }
    }

    fn ep(addr: &str) -> Option<(EndpointHost, u16)> {
        let a: SocketAddr = addr.parse().unwrap();
        Some((EndpointHost::Ip(a.ip()), a.port()))
    }

    struct Pair {
        a: Engine,
        b: Engine,
        now: Instant,
        /// Where A's packets appear to come from, as seen by B.
        a_src: SocketAddr,
        drop_b_to_a: bool,
        a_sock: Option<u32>,
        b_sock: Option<u32>,
    }

    impl Pair {
        fn new(a_peer: PeerConf, b_peer: PeerConf) -> Self {
            crate::rng::seed(&[7; 32]);
            let now = Instant::from_nanos(1_000_000_000);
            let mut a = Engine::new(now, Duration::from_secs(1_700_000_000));
            let mut b = Engine::new(now, Duration::from_secs(1_700_000_000));
            a.reload(conf(A_PRIV, "10.7.0.2/24", alloc::vec![a_peer]), now);
            b.reload(conf(B_PRIV, "10.7.0.1/24", alloc::vec![b_peer]), now);
            Self { a, b, now, a_src: A_ADDR.parse().unwrap(), drop_b_to_a: false, a_sock: None, b_sock: None }
        }

        /// A knows B's address; B learns A's from traffic.
        fn client_server() -> Self {
            Self::new(peer(B_PRIV, "server", &["10.7.0.1/32", "10.123.0.0/24"], ep(B_ADDR), None), peer(A_PRIV, "switch", &["10.7.0.2/32"], None, None))
        }

        /// As `client_server`, each side with its own AmneziaWG settings.
        fn client_server_awg(a: awg::Params, b: awg::Params) -> Self {
            let mut p = Self::client_server();
            // Drop what the plain reloads sent, then configure for real.
            while p.a.poll_io().is_some() {}
            while p.b.poll_io().is_some() {}
            p.a.reload(conf_awg(A_PRIV, "10.7.0.2/24", alloc::vec![peer(B_PRIV, "server", &["10.7.0.1/32", "10.123.0.0/24"], ep(B_ADDR), None)], a), p.now);
            p.b.reload(conf_awg(B_PRIV, "10.7.0.1/24", alloc::vec![peer(A_PRIV, "switch", &["10.7.0.2/32"], None, None)], b), p.now);
            p
        }

        /// Moves datagrams between the engines until both are quiet.
        fn shuttle(&mut self) -> usize {
            let mut moved = 0;
            loop {
                let mut progress = false;
                while let Some(Io::SendUdp { dst, data }) = self.a.poll_io() {
                    assert_eq!(dst, B_ADDR.parse().unwrap());
                    self.b.handle_udp(self.a_src, &data, self.now);
                    progress = true;
                    moved += 1;
                }
                while let Some(Io::SendUdp { dst, data }) = self.b.poll_io() {
                    assert_eq!(dst, self.a_src);
                    if !self.drop_b_to_a {
                        self.a.handle_udp(B_ADDR.parse().unwrap(), &data, self.now);
                    }
                    progress = true;
                    moved += 1;
                }
                if !progress {
                    return moved;
                }
            }
        }

        fn advance(&mut self, d: Duration) {
            let target = self.now + d;
            while self.now < target {
                let next = self.a.next_deadline().min(self.b.next_deadline()).min(target).max(self.now + Duration::from_millis(1));
                self.now = next;
                self.a.handle_timeout(self.now);
                self.b.handle_timeout(self.now);
                self.shuttle();
            }
        }

        fn events(e: &mut Engine) -> Vec<Event> {
            core::iter::from_fn(|| e.poll_event()).collect()
        }
    }

    fn udp_echo(p: &mut Pair) -> bool {
        let b_sock = match p.b_sock {
            Some(s) => s,
            None => *p.b_sock.insert(p.b.net().udp_bind(7).unwrap()),
        };
        let a_sock = match p.a_sock {
            Some(s) => s,
            None => *p.a_sock.insert(p.a.net().udp_bind(0).unwrap()),
        };
        p.a.net().udp_send_to(a_sock, b"ping", "10.7.0.1:7".parse().unwrap()).unwrap();
        p.a.flush(p.now);
        p.shuttle();
        let mut buf = [0u8; 64];
        let Ok((n, from)) = p.b.net().udp_recv_from(b_sock, &mut buf) else { return false };
        assert_eq!((&buf[..n], from.ip()), (&b"ping"[..], "10.7.0.2".parse::<IpAddr>().unwrap()));
        p.b.net().udp_send_to(b_sock, b"pong", from).unwrap();
        p.b.flush(p.now);
        p.shuttle();
        matches!(p.a.net().udp_recv_from(a_sock, &mut buf), Ok((4, _)))
    }

    #[test]
    fn handshake_then_echo_and_the_server_learns_our_endpoint() {
        let mut p = Pair::client_server();
        // Reload contacted the server: initiation, response, confirmation.
        assert!(p.shuttle() >= 3);
        assert!(Pair::events(&mut p.a).contains(&Event::Handshake { peer: 0 }));
        assert!(Pair::events(&mut p.b).contains(&Event::Handshake { peer: 0 }));
        assert_eq!(p.b.peers_info()[0].endpoint, Some(p.a_src));
        assert!(p.a.peers_info()[0].session);
        assert!(udp_echo(&mut p));
        let info = &p.a.peers_info()[0];
        assert!(info.rx_bytes > 0 && info.tx_bytes > 0);
        assert_eq!(info.last_handshake, Some(Duration::ZERO));
    }

    #[test]
    fn amneziawg_peers_handshake_behind_junk_and_disguised_headers() {
        let mut p = Pair::client_server_awg(awg_params(), awg_params());
        assert!(Pair::events(&mut p.a).iter().any(|e| matches!(e, Event::Log(s) if s.starts_with("AmneziaWG: Jc=3"))));
        // The reload kicked B: nothing on the wire says WireGuard.
        let mut burst = Vec::new();
        while let Some(Io::SendUdp { data, .. }) = p.a.poll_io() {
            burst.push(data);
        }
        assert_eq!(burst.len(), 1 + 3 + 1, "I1, Jc junk, initiation");
        assert_eq!(&burst[0][..3], b"GET");
        assert!(burst[1..4].iter().all(|j| (40..70).contains(&j.len())));
        let init = &burst[4];
        assert_eq!(init.len(), 15 + 148);
        assert!((100..=200).contains(&u32::from_le_bytes(init[15..19].try_into().unwrap())));
        assert!(burst.iter().all(|d| d[0] != 1 || d.len() != 148));
        for d in burst {
            p.b.handle_udp(p.a_src, &d, p.now);
        }
        let Some(Io::SendUdp { data: resp, .. }) = p.b.poll_io() else { panic!("no response") };
        assert_eq!(resp.len(), 22 + 92);
        assert_eq!(u32::from_le_bytes(resp[22..26].try_into().unwrap()), 300);
        p.a.handle_udp(B_ADDR.parse().unwrap(), &resp, p.now);
        p.shuttle();
        assert!(Pair::events(&mut p.a).contains(&Event::Handshake { peer: 0 }));
        assert!(Pair::events(&mut p.b).contains(&Event::Handshake { peer: 0 }));
        assert_eq!(p.b.peers_info()[0].endpoint, Some(p.a_src));
        // Data flows, with S4 bytes and an H4 header on every datagram.
        assert!(udp_echo(&mut p));
        p.a.net().udp_send_to(p.a_sock.unwrap(), b"ping", "10.7.0.1:7".parse().unwrap()).unwrap();
        p.a.flush(p.now);
        let Some(Io::SendUdp { data, .. }) = p.a.poll_io() else { panic!("no data") };
        assert!((500..=600).contains(&u32::from_le_bytes(data[8..12].try_into().unwrap())));
        assert_eq!(data.len(), 8 + 16 + 32 + 16, "S4 + header + 32-byte IP packet + tag");
        // Junk in both directions is ignored, and a plain WireGuard
        // keepalive from a stranger too.
        p.a.handle_udp(B_ADDR.parse().unwrap(), &[0x55; 60], p.now);
        p.b.handle_udp(p.a_src, &[4, 0, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9], p.now);
        assert!(p.a.poll_io().is_none() && p.b.poll_io().is_none());
        assert!(udp_echo(&mut p));
        // Retried initiations get junk again.
        let mut a = Pair::client_server_awg(awg_params(), awg_params());
        a.drop_b_to_a = true;
        a.shuttle();
        let (rx, tx) = (a.b.peers_info()[0].rx_bytes, a.a.peers_info()[0].tx_bytes);
        a.advance(Duration::from_secs(6));
        assert_eq!(a.b.peers_info()[0].rx_bytes, rx + 15 + 148, "the retry reached B");
        assert!(a.a.peers_info()[0].tx_bytes >= tx + 11 + 3 * 40 + 15 + 148, "with junk ahead of it");
    }

    #[test]
    fn amneziawg_header_protection_handshakes_and_carries_data() {
        let hp = || awg::Params { prefix: [12, 22, 16, 13], header_key: Some([7; 32]), ..awg_params() };
        let mut p = Pair::client_server_awg(hp(), hp());
        assert!(Pair::events(&mut p.a).iter().any(|e| matches!(e, Event::Log(s) if s.contains("header protection on"))));
        let mut burst = Vec::new();
        while let Some(Io::SendUdp { data, .. }) = p.a.poll_io() {
            burst.push(data);
        }
        let init = burst.last().unwrap();
        assert_eq!(init.len(), 12 + 148);
        // The header is encrypted: the H1 value is not there to be read.
        assert!(!(100..=200).contains(&u32::from_le_bytes(init[12..16].try_into().unwrap())));
        for d in burst {
            p.b.handle_udp(p.a_src, &d, p.now);
        }
        p.shuttle();
        assert!(Pair::events(&mut p.a).contains(&Event::Handshake { peer: 0 }));
        assert!(Pair::events(&mut p.b).contains(&Event::Handshake { peer: 0 }));
        assert!(udp_echo(&mut p));
        assert_eq!(p.a.mtu(), DEFAULT_MTU - 13);
        // The same parameters with another key, or none, get nowhere.
        for b in [awg::Params { header_key: Some([8; 32]), ..hp() }, awg::Params { header_key: None, ..hp() }] {
            let mut q = Pair::client_server_awg(hp(), b);
            q.shuttle();
            q.advance(Duration::from_secs(12));
            assert!(!q.a.peers_info()[0].session && !q.b.peers_info()[0].session);
        }
    }

    #[test]
    fn amneziawg_and_plain_wireguard_do_not_mix() {
        for (a, b) in [(awg_params(), awg::Params::default()), (awg::Params::default(), awg_params()), (awg_params(), { let mut b = awg_params(); b.header[0] = awg::Range::one(7); b })] {
            let mut p = Pair::client_server_awg(a, b);
            p.shuttle();
            p.advance(Duration::from_secs(12));
            assert!(!Pair::events(&mut p.a).contains(&Event::Handshake { peer: 0 }));
            assert!(!p.a.peers_info()[0].session && !p.b.peers_info()[0].session);
            assert_eq!(p.b.peers_info()[0].endpoint, None, "B never authenticated A");
        }
    }

    #[test]
    fn s4_lowers_the_default_mtu() {
        let now = Instant::from_nanos(1_000_000_000);
        let mut e = Engine::new(now, Duration::from_secs(1_700_000_000));
        let mut awg = awg::Params::default();
        awg.prefix[3] = 100;
        e.reload(conf_awg(A_PRIV, "10.7.0.2/24", Vec::new(), awg.clone()), now);
        assert_eq!(e.mtu(), DEFAULT_MTU - 100);
        let mut c = conf_awg(A_PRIV, "10.7.0.2/24", Vec::new(), awg);
        c.interface.mtu = Some(1400);
        e.reload(c, now);
        assert_eq!(e.mtu(), 1400);
        e.reload(conf(A_PRIV, "10.7.0.2/24", Vec::new()), now);
        assert_eq!(e.mtu(), DEFAULT_MTU);
    }

    #[test]
    fn psk_mismatch_never_handshakes() {
        let mut a_peer = peer(B_PRIV, "server", &["10.7.0.1/32"], ep(B_ADDR), None);
        a_peer.preshared_key = Some([1; 32]);
        let mut b_peer = peer(A_PRIV, "switch", &["10.7.0.2/32"], None, None);
        b_peer.preshared_key = Some([2; 32]);
        let mut p = Pair::new(a_peer, b_peer);
        p.advance(Duration::from_secs(20));
        assert!(!Pair::events(&mut p.a).iter().any(|e| matches!(e, Event::Handshake { .. })));
        assert!(!p.a.peers_info()[0].session && !p.b.peers_info()[0].session);
        // The initiation itself is signed by A's static key, so B does learn
        // A's address from it (as wireguard-go does); only the session fails.
        assert_eq!(p.b.peers_info()[0].endpoint, Some(p.a_src));
    }

    #[test]
    fn roaming_follows_authenticated_traffic() {
        let mut p = Pair::client_server();
        p.shuttle();
        assert!(udp_echo(&mut p));
        p.a_src = "198.51.100.9:5000".parse().unwrap();
        assert!(udp_echo(&mut p));
        assert_eq!(p.b.peers_info()[0].endpoint, Some(p.a_src));
    }

    #[test]
    fn cryptokey_routing_drops_spoofed_sources() {
        // A's address isn't in B's AllowedIPs for it.
        let mut p = Pair::new(peer(B_PRIV, "server", &["10.7.0.1/32"], ep(B_ADDR), None), peer(A_PRIV, "switch", &["10.7.0.99/32"], None, None));
        p.shuttle();
        assert!(p.a.peers_info()[0].session);
        let b_sock = p.b.net().udp_bind(7).unwrap();
        let a_sock = p.a.net().udp_bind(0).unwrap();
        p.a.net().udp_send_to(a_sock, b"ping", "10.7.0.1:7".parse().unwrap()).unwrap();
        p.a.flush(p.now);
        p.shuttle();
        let mut buf = [0u8; 64];
        assert!(p.b.net().udp_recv_from(b_sock, &mut buf).is_err());
    }

    #[test]
    fn persistent_keepalive_cadence() {
        let mut p = Pair::new(peer(B_PRIV, "server", &["10.7.0.1/32"], ep(B_ADDR), Some(5)), peer(A_PRIV, "switch", &["10.7.0.2/32"], None, None));
        p.shuttle();
        let start = p.now;
        let mut keepalives = 0;
        let target = start + Duration::from_secs(31);
        while p.now < target {
            let next = p.a.next_deadline().min(p.b.next_deadline()).min(target).max(p.now + Duration::from_millis(1));
            p.now = next;
            p.a.handle_timeout(p.now);
            p.b.handle_timeout(p.now);
            while let Some(Io::SendUdp { data, .. }) = p.a.poll_io() {
                if data.len() == 32 && data[0] == 4 {
                    keepalives += 1;
                }
                p.b.handle_udp(p.a_src, &data, p.now);
            }
            while let Some(Io::SendUdp { data, .. }) = p.b.poll_io() {
                p.a.handle_udp(B_ADDR.parse().unwrap(), &data, p.now);
            }
        }
        assert!((5..=7).contains(&keepalives), "{keepalives} keepalives in 31 s");
        assert!(!p.a.peers_info()[0].session || p.a.peers_info()[0].last_handshake.unwrap() < Duration::from_secs(40));
    }

    #[test]
    fn unanswered_data_resets_the_session_after_15s() {
        let mut p = Pair::client_server();
        p.shuttle();
        p.drop_b_to_a = true;
        let a_sock = p.a.net().udp_bind(0).unwrap();
        p.a.net().udp_send_to(a_sock, b"hello?", "10.7.0.1:7".parse().unwrap()).unwrap();
        p.a.flush(p.now);
        p.shuttle();
        Pair::events(&mut p.a);
        p.advance(Duration::from_secs(16));
        let ev = Pair::events(&mut p.a);
        assert!(ev.contains(&Event::PeerLost { peer: 0 }), "{ev:?}");
        assert!(!p.a.peers_info()[0].session);
        // It handshakes again on its own once the peer answers.
        p.drop_b_to_a = false;
        p.advance(Duration::from_secs(6));
        assert!(p.a.peers_info()[0].session, "{:?}", p.a.peers_info());
    }

    #[test]
    fn host_name_endpoints_are_resolved_and_re_resolved() {
        let named = Some((EndpointHost::Name("vpn.example".into()), 51820));
        let mut p = Pair::new(peer(B_PRIV, "server", &["10.7.0.1/32"], named, None), peer(A_PRIV, "switch", &["10.7.0.2/32"], None, None));
        let resolve = Event::Resolve { peer: 0, host: "vpn.example".into(), port: 51820 };
        assert!(Pair::events(&mut p.a).contains(&resolve));
        assert_eq!(p.a.poll_io(), None, "nothing to send without an endpoint");
        let info = &p.a.peers_info()[0];
        assert!(info.endpoint_name && info.resolving);
        // Not resolved: asked again after 30 s, not before.
        p.advance(Duration::from_secs(20));
        assert!(!Pair::events(&mut p.a).contains(&resolve));
        p.advance(Duration::from_secs(11));
        assert!(Pair::events(&mut p.a).contains(&resolve));
        // Resolved: contact it; the handshake stops the re-resolving.
        p.a.set_peer_endpoint(0, B_ADDR.parse().unwrap(), p.now);
        p.shuttle();
        assert!(p.a.peers_info()[0].session);
        Pair::events(&mut p.a);
        p.advance(Duration::from_secs(60));
        assert!(!Pair::events(&mut p.a).contains(&resolve));
        // The network changing resolves again at once, and pings the peer.
        p.a.network_up(p.now);
        assert!(Pair::events(&mut p.a).contains(&resolve));
        assert!(p.shuttle() >= 1);
    }

    #[test]
    fn routes_hosts_and_info() {
        let p = Pair::client_server();
        assert_eq!(p.a.routes(), [prefix("10.7.0.2/32"), prefix("10.7.0.1/32"), prefix("10.123.0.0/24")]);
        assert_eq!(p.a.hosts(), [("10.7.0.1".parse().unwrap(), "server")]);
        let info = &p.a.peers_info()[0];
        assert_eq!((info.name.as_str(), info.allowed_ips, info.psk, info.default_route), ("server", 2, false, false));
        assert_eq!(info.ipv4, Some("10.7.0.1".parse().unwrap()));
        let unconfigured = Engine::new(p.now, Duration::ZERO);
        assert!(!unconfigured.is_configured() && unconfigured.routes().is_empty());
    }

    #[test]
    fn host_names_need_a_route_and_a_free_name() {
        let mut p = Pair::client_server();
        let mut c = conf(A_PRIV, "10.7.0.2/24", alloc::vec![peer(B_PRIV, "server", &["10.7.0.1/32", "10.123.0.0/24"], ep(B_ADDR), None)]);
        c.hosts = alloc::vec![
            ("gaming-pc".into(), "10.123.0.50".parse().unwrap()),
            ("elsewhere".into(), "192.168.9.9".parse().unwrap()),
            ("server".into(), "10.123.0.51".parse().unwrap()),
        ];
        p.a.reload(c, p.now);
        assert_eq!(p.a.hosts(), [("10.7.0.1".parse().unwrap(), "server"), ("10.123.0.50".parse().unwrap(), "gaming-pc")]);
        let logs: Vec<String> = Pair::events(&mut p.a).into_iter().filter_map(|e| if let Event::Log(m) = e { Some(m) } else { None }).collect();
        assert!(logs.iter().any(|m| m.contains("elsewhere") && m.contains("AllowedIPs")));
        assert!(logs.iter().any(|m| m.contains("Host server") && m.contains("already")));
    }

    #[test]
    fn reload_keeps_overlay_sockets() {
        let mut p = Pair::client_server();
        p.shuttle();
        let a_sock = p.a.net().udp_bind(0).unwrap();
        let before = p.a.net().local_addr(a_sock);
        p.a.reload(conf(A_PRIV, "10.7.0.2/24", alloc::vec![peer(B_PRIV, "server", &["10.7.0.1/32"], ep(B_ADDR), None)]), p.now);
        assert_eq!(p.a.net().local_addr(a_sock), before);
        assert!(!p.a.peers_info()[0].session, "sessions start over");
        p.shuttle();
        assert!(udp_echo(&mut p));
    }

    #[test]
    fn keepalives_and_handshakes_are_not_data() {
        let keepalive = [4u8, 0, 0, 0].iter().copied().chain([0u8; 28]).collect::<Vec<_>>();
        assert!(!is_wg_data(&keepalive));
        assert!(!is_wg_data(&[1u8; 148]));
        assert!(!is_wg_data(&[2u8; 92]));
        let mut data = keepalive.clone();
        data.extend_from_slice(&[0u8; 16]);
        assert!(is_wg_data(&data));
    }
}
