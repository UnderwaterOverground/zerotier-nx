//! Ethernet for the netstack.
//!
//! A ZeroTier network carries Ethernet frames; the netstack speaks IP. This
//! module sits between them: it answers ARP for our addresses, finds the MAC
//! behind each next hop (an ARP cache), and holds a few packets while it
//! asks. IPv4 only; anything else is dropped.
//!
//! Broadcast frames are expensive here. ZeroTier sends each one as a
//! multicast, and its core parks about 30 KB per frame for up to half a
//! minute (see `Multicaster::send`). So every broadcast this module sends, an
//! ARP request being the only kind, comes out of one small budget, and a
//! known neighbour is re-checked with a unicast request, which costs nothing.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use crate::time::Instant;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// ff:ff:ff:ff:ff:ff, as ZeroTier writes a MAC (first octet in the top byte).
pub const BROADCAST: u64 = 0xffff_ffff_ffff;

const SEC: u64 = 1_000_000_000;
/// Neighbours remembered. A ZeroTier MAC never changes for a device on a
/// network, so entries live long and are re-checked by unicast.
const ARP_CACHE: usize = 32;
/// An entry not confirmed for this long is asked again (unicast) when used...
const REFRESH_AFTER: u64 = 120 * SEC;
/// ...at most this often...
const REFRESH_EVERY: u64 = 30 * SEC;
/// ...and forgotten after this long without an answer or traffic.
const ENTRY_TTL: u64 = 600 * SEC;
/// Packets held while their next hop is being resolved (one per hop).
const PENDING_MAX: usize = 4;
const PENDING_TTL: u64 = 3 * SEC;
/// ARP frames waiting to go out.
const CTL_MAX: usize = 8;
/// Broadcasts allowed at once, and how fast the allowance comes back. Six in
/// flight is about 180 KB of ZeroTier's heap at worst.
const BROADCAST_BURST: u32 = 6;
const BROADCAST_REFILL: u64 = 5 * SEC;
/// Requests for one unanswered address: after 1 s, then 2, 4... up to 30.
const RETRY_FIRST: u64 = SEC;
const RETRY_MAX: u64 = 30 * SEC;
/// Addresses being resolved at once (more than the pending list, so an
/// address that just gave up keeps its back-off).
const RESOLVING_MAX: usize = 8;
/// Packets looked at per `next_out` call, so a queue of undeliverable ones
/// can't hold the caller.
const POP_MAX: usize = 64;

/// An IPv4 network: an address and its prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Net {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Net {
    fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix.min(32)))
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(self.addr) & self.mask() == u32::from(ip) & self.mask()
    }

    /// The network and broadcast addresses, which are nobody's (none on a
    /// /31 or /32).
    fn is_reserved(&self, ip: Ipv4Addr) -> bool {
        if self.prefix >= 31 {
            return false;
        }
        let host = u32::from(ip) & !self.mask();
        host == 0 || host == !self.mask()
    }
}

/// A managed route: `target` is reached through `via`, or directly if None.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub target: Net,
    pub via: Option<Ipv4Addr>,
}

/// What the network's controller assigned us.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    pub nwid: u64,
    pub mac: u64,
    pub addrs: Vec<Net>,
    pub routes: Vec<Route>,
}

/// A frame to hand to ZeroTier. The source MAC is always ours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub dst_mac: u64,
    pub ethertype: u16,
    pub payload: Vec<u8>,
}

/// Counters, for the log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Broadcast ARP requests sent.
    pub broadcasts: u32,
    /// Requests not sent because the broadcast budget was used up.
    pub limited: u32,
    /// Packets dropped while waiting for a neighbour (expired or displaced).
    pub unresolved: u32,
    /// Packets with nowhere to go (no route, broadcast, our own address).
    pub unroutable: u32,
}

struct Entry {
    ip: Ipv4Addr,
    mac: u64,
    confirmed: u64,
    used: u64,
    refresh_sent: u64,
}

struct Pending {
    hop: Ipv4Addr,
    pkt: Vec<u8>,
    since: u64,
}

struct Resolving {
    ip: Ipv4Addr,
    next_at: u64,
    backoff: u64,
}

enum Ctl {
    Reply { to_mac: u64, to_ip: Ipv4Addr, from_ip: Ipv4Addr },
    /// `to_mac` is BROADCAST, or a known neighbour's for a re-check.
    Request { target: Ipv4Addr, to_mac: u64 },
}

pub struct L2 {
    cfg: Option<Config>,
    cache: Vec<Entry>,
    pending: Vec<Pending>,
    resolving: Vec<Resolving>,
    ctl: VecDeque<Ctl>,
    /// Held packets whose neighbour has answered.
    ready: VecDeque<Frame>,
    tokens: u32,
    refilled: u64,
    stats: Stats,
}

fn ns(t: Instant) -> u64 {
    t.as_nanos() as u64
}

fn mac_bytes(mac: u64) -> [u8; 6] {
    let b = mac.to_be_bytes();
    [b[2], b[3], b[4], b[5], b[6], b[7]]
}

fn mac_from(b: &[u8]) -> u64 {
    b.iter().take(6).fold(0u64, |m, &x| (m << 8) | u64::from(x))
}

/// Broadcast and multicast MACs have the low bit of the first octet set.
fn is_group(mac: u64) -> bool {
    (mac >> 40) & 1 == 1
}

fn ipv4_at(b: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3])
}

/// An ARP packet for Ethernet and IPv4 (28 bytes).
fn arp(op: u16, sha: u64, spa: Ipv4Addr, tha: u64, tpa: Ipv4Addr) -> Vec<u8> {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4]);
    p.extend_from_slice(&op.to_be_bytes());
    p.extend_from_slice(&mac_bytes(sha));
    p.extend_from_slice(&spa.octets());
    p.extend_from_slice(&mac_bytes(tha));
    p.extend_from_slice(&tpa.octets());
    p
}

impl Default for L2 {
    fn default() -> Self {
        Self::new()
    }
}

impl L2 {
    pub fn new() -> Self {
        Self {
            cfg: None,
            cache: Vec::new(),
            pending: Vec::new(),
            resolving: Vec::new(),
            ctl: VecDeque::new(),
            ready: VecDeque::new(),
            tokens: BROADCAST_BURST,
            refilled: 0,
            stats: Stats::default(),
        }
    }

    pub fn config(&self) -> Option<&Config> {
        self.cfg.as_ref()
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// The network is up with this configuration. Neighbours are kept unless
    /// the network or our MAC changed; anything queued is dropped.
    pub fn configure(&mut self, cfg: Config) {
        let same_link = self.cfg.as_ref().is_some_and(|old| old.nwid == cfg.nwid && old.mac == cfg.mac);
        if !same_link {
            self.cache.clear();
        }
        self.clear_queues();
        self.cfg = Some(cfg);
    }

    /// The network is gone.
    pub fn down(&mut self) {
        self.cfg = None;
        self.cache.clear();
        self.clear_queues();
    }

    /// After a sleep or a change of network underneath: drop what was queued
    /// and re-check every neighbour the next time it is used.
    pub fn link_reset(&mut self, now: Instant) {
        self.clear_queues();
        let now = ns(now);
        for e in &mut self.cache {
            e.confirmed = e.confirmed.min(now.saturating_sub(REFRESH_AFTER + 1));
            e.refresh_sent = 0;
        }
    }

    fn clear_queues(&mut self) {
        self.pending.clear();
        self.resolving.clear();
        self.ctl.clear();
        self.ready.clear();
    }

    /// True if a frame is waiting that didn't come from the netstack's queue
    /// (an ARP reply or request, or a packet whose neighbour just answered).
    pub fn has_frames(&self) -> bool {
        !self.ctl.is_empty() || !self.ready.is_empty()
    }

    /// The neighbours whose MAC is known: (MAC, address), in no particular
    /// order.
    pub fn neighbors(&self) -> impl Iterator<Item = (u64, Ipv4Addr)> + '_ {
        self.cache.iter().map(|e| (e.mac, e.ip))
    }

    /// The neighbour's address behind a MAC, if known (for naming peers).
    pub fn ip_of(&self, mac: u64) -> Option<Ipv4Addr> {
        self.cache.iter().find(|e| e.mac == mac).map(|e| e.ip)
    }

    /// A frame arrived from the network. Returns the IPv4 packet inside, for
    /// the netstack, if there is one.
    pub fn frame_in(&mut self, src_mac: u64, dst_mac: u64, ethertype: u16, payload: &[u8], now: Instant) -> Option<Vec<u8>> {
        let cfg = self.cfg.as_ref()?;
        if dst_mac != cfg.mac && !is_group(dst_mac) {
            return None;
        }
        let now = ns(now);
        match ethertype {
            ETHERTYPE_ARP => {
                self.arp_in(src_mac, payload, now);
                None
            }
            ETHERTYPE_IPV4 => {
                if payload.len() < 20 || payload[0] >> 4 != 4 {
                    return None;
                }
                // Ethernet may pad a short packet; the IP header says where it ends.
                let total = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
                if total < 20 || total > payload.len() {
                    return None;
                }
                let src = ipv4_at(payload, 12);
                if let Some(e) = self.cache.iter_mut().find(|e| e.ip == src && e.mac == src_mac) {
                    e.confirmed = now;
                }
                Some(payload[..total].to_vec())
            }
            _ => None,
        }
    }

    fn arp_in(&mut self, src_mac: u64, p: &[u8], now: u64) {
        let Some(cfg) = self.cfg.as_ref() else { return };
        if p.len() < 28 || p[..6] != [0, 1, 0x08, 0x00, 6, 4] {
            return;
        }
        let op = u16::from_be_bytes([p[6], p[7]]);
        let sha = mac_from(&p[8..14]);
        let spa = ipv4_at(p, 14);
        let tpa = ipv4_at(p, 24);
        let ours = |ip: Ipv4Addr| cfg.addrs.iter().any(|a| a.addr == ip);
        // ZeroTier vouches for the frame's source MAC, not for what the ARP
        // packet claims: only believe a sender speaking for itself.
        let learn = sha == src_mac
            && !is_group(sha)
            && !ours(spa)
            && cfg.addrs.iter().any(|a| a.contains(spa) && !a.is_reserved(spa));
        let reply = (op == 1 && ours(tpa) && !is_group(sha)).then_some(Ctl::Reply { to_mac: sha, to_ip: spa, from_ip: tpa });
        if learn {
            self.learn(spa, sha, now);
        }
        if let Some(reply) = reply {
            if self.ctl.len() < CTL_MAX {
                self.ctl.push_back(reply);
            }
        }
    }

    fn learn(&mut self, ip: Ipv4Addr, mac: u64, now: u64) {
        match self.cache.iter_mut().find(|e| e.ip == ip) {
            Some(e) => {
                e.mac = mac;
                e.confirmed = now;
            }
            None => {
                if self.cache.len() >= ARP_CACHE {
                    if let Some(oldest) = (0..self.cache.len()).min_by_key(|&i| self.cache[i].used) {
                        self.cache.swap_remove(oldest);
                    }
                }
                self.cache.push(Entry { ip, mac, confirmed: now, used: now, refresh_sent: 0 });
            }
        }
        self.resolving.retain(|r| r.ip != ip);
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].hop == ip {
                let p = self.pending.remove(i);
                self.ready.push_back(Frame { dst_mac: mac, ethertype: ETHERTYPE_IPV4, payload: p.pkt });
            } else {
                i += 1;
            }
        }
    }

    /// Where to send a packet for `dst`: the address to resolve, or None if
    /// it has nowhere to go.
    fn next_hop(cfg: &Config, dst: Ipv4Addr) -> Option<Ipv4Addr> {
        if dst.is_unspecified() || dst.is_broadcast() || dst.is_multicast() || dst.is_loopback() {
            return None;
        }
        if cfg.addrs.iter().any(|a| a.addr == dst) {
            return None;
        }
        let on_link = |ip: Ipv4Addr| cfg.addrs.iter().find(|a| a.contains(ip));
        if let Some(net) = on_link(dst) {
            return (!net.is_reserved(dst)).then_some(dst);
        }
        let route = cfg.routes.iter().filter(|r| r.target.contains(dst)).max_by_key(|r| r.target.prefix)?;
        match route.via {
            Some(gw) => on_link(gw).is_some_and(|net| !net.is_reserved(gw)).then_some(gw),
            None => Some(dst),
        }
    }

    fn refill(&mut self, now: u64) {
        let earned = now.saturating_sub(self.refilled) / BROADCAST_REFILL;
        if earned > 0 {
            self.tokens = (u64::from(self.tokens) + earned).min(u64::from(BROADCAST_BURST)) as u32;
            self.refilled += earned * BROADCAST_REFILL;
        }
    }

    /// Queues a broadcast ARP request for `hop` if its back-off and the
    /// broadcast budget allow one now.
    fn resolve(&mut self, hop: Ipv4Addr, now: u64) {
        let at = self.resolving.iter().position(|r| r.ip == hop);
        if at.is_some_and(|i| now < self.resolving[i].next_at) {
            return;
        }
        self.refill(now);
        if self.tokens == 0 || self.ctl.len() >= CTL_MAX {
            self.stats.limited += 1;
            return;
        }
        self.tokens -= 1;
        self.stats.broadcasts += 1;
        self.ctl.push_back(Ctl::Request { target: hop, to_mac: BROADCAST });
        match at {
            Some(i) => {
                let r = &mut self.resolving[i];
                r.backoff = (r.backoff * 2).min(RETRY_MAX);
                r.next_at = now + r.backoff;
            }
            None => {
                if self.resolving.len() >= RESOLVING_MAX {
                    if let Some(oldest) = (0..self.resolving.len()).min_by_key(|&i| self.resolving[i].next_at) {
                        self.resolving.swap_remove(oldest);
                    }
                }
                self.resolving.push(Resolving { ip: hop, next_at: now + RETRY_FIRST, backoff: RETRY_FIRST });
            }
        }
    }

    fn hold(&mut self, hop: Ipv4Addr, pkt: Vec<u8>, now: u64) {
        // One packet per hop, the newest: a retransmitted SYN replaces the
        // one before it, and a newer datagram is worth more than an older.
        if let Some(p) = self.pending.iter_mut().find(|p| p.hop == hop) {
            p.pkt = pkt;
            self.stats.unresolved += 1;
            return;
        }
        if self.pending.len() >= PENDING_MAX {
            self.pending.remove(0);
            self.stats.unresolved += 1;
        }
        self.pending.push(Pending { hop, pkt, since: now });
    }

    /// Runs the timers: drops held packets and neighbours that have waited
    /// too long, and asks again for hops that still have a packet held.
    fn expire(&mut self, now: u64) {
        let before = self.pending.len();
        self.pending.retain(|p| now.saturating_sub(p.since) < PENDING_TTL);
        self.stats.unresolved += (before - self.pending.len()) as u32;
        self.cache.retain(|e| now.saturating_sub(e.confirmed) < ENTRY_TTL);
        let pending = &self.pending;
        self.resolving.retain(|r| pending.iter().any(|p| p.hop == r.ip) || now < r.next_at + RETRY_MAX);
        for i in 0..self.pending.len() {
            let hop = self.pending[i].hop;
            self.resolve(hop, now);
        }
    }

    /// When `next_out` should next be called even if nothing arrives.
    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        if self.has_frames() {
            return Some(now);
        }
        let expiry = self.pending.iter().map(|p| p.since + PENDING_TTL);
        let retry = self.resolving.iter().filter(|r| self.pending.iter().any(|p| p.hop == r.ip)).map(|r| r.next_at);
        expiry.chain(retry).min().map(Instant::from_nanos)
    }

    fn lookup(&mut self, hop: Ipv4Addr, now: u64) -> Option<u64> {
        let e = self.cache.iter_mut().find(|e| e.ip == hop)?;
        e.used = now;
        let mac = e.mac;
        if now.saturating_sub(e.confirmed) > REFRESH_AFTER
            && (e.refresh_sent == 0 || now.saturating_sub(e.refresh_sent) > REFRESH_EVERY)
            && self.ctl.len() < CTL_MAX
        {
            e.refresh_sent = now.max(1);
            self.ctl.push_back(Ctl::Request { target: hop, to_mac: mac });
        }
        Some(mac)
    }

    fn ctl_frame(cfg: &Config, c: Ctl) -> Option<Frame> {
        let payload = match c {
            Ctl::Reply { to_mac, to_ip, from_ip } => arp(2, cfg.mac, from_ip, to_mac, to_ip),
            Ctl::Request { target, .. } => {
                // Ask from our address on the target's network.
                let from = cfg.addrs.iter().find(|a| a.contains(target)).or(cfg.addrs.first())?.addr;
                arp(1, cfg.mac, from, 0, target)
            }
        };
        let dst_mac = match c {
            Ctl::Reply { to_mac, .. } | Ctl::Request { to_mac, .. } => to_mac,
        };
        Some(Frame { dst_mac, ethertype: ETHERTYPE_ARP, payload })
    }

    /// The next frame to send. `pop` yields the netstack's outgoing IP
    /// packets, oldest first; each one popped is sent, held or dropped, never
    /// put back, so the netstack's queue always drains.
    pub fn next_out(&mut self, now: Instant, mut pop: impl FnMut() -> Option<Vec<u8>>) -> Option<Frame> {
        let now = ns(now);
        self.expire(now);
        for _ in 0..POP_MAX {
            if let Some(cfg) = self.cfg.as_ref() {
                if let Some(c) = self.ctl.pop_front() {
                    match Self::ctl_frame(cfg, c) {
                        Some(f) => return Some(f),
                        None => continue,
                    }
                }
                if let Some(f) = self.ready.pop_front() {
                    return Some(f);
                }
            }
            let pkt = pop()?;
            let Some(cfg) = self.cfg.as_ref() else {
                self.stats.unroutable += 1;
                continue;
            };
            if pkt.len() < 20 || pkt[0] >> 4 != 4 {
                self.stats.unroutable += 1;
                continue;
            }
            let Some(hop) = Self::next_hop(cfg, ipv4_at(&pkt, 16)) else {
                self.stats.unroutable += 1;
                continue;
            };
            match self.lookup(hop, now) {
                Some(mac) => return Some(Frame { dst_mac: mac, ethertype: ETHERTYPE_IPV4, payload: pkt }),
                None => {
                    self.hold(hop, pkt, now);
                    self.resolve(hop, now);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const NWID: u64 = 0x8056_c2e2_1c00_0001;
    const OUR_MAC: u64 = 0x32_11_22_33_44_55;
    const PEER_MAC: u64 = 0x32_aa_bb_cc_dd_01;
    const GW_MAC: u64 = 0x32_aa_bb_cc_dd_fe;
    const OUR_IP: Ipv4Addr = Ipv4Addr::new(10, 20, 30, 2);
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 20, 30, 7);
    const GW_IP: Ipv4Addr = Ipv4Addr::new(10, 20, 30, 254);

    fn at(ms: u64) -> Instant {
        Instant::from_millis(ms)
    }

    fn net(a: [u8; 4], prefix: u8) -> Net {
        Net { addr: Ipv4Addr::from(a), prefix }
    }

    fn config() -> Config {
        Config {
            nwid: NWID,
            mac: OUR_MAC,
            addrs: vec![Net { addr: OUR_IP, prefix: 24 }],
            routes: vec![
                Route { target: net([10, 20, 30, 0], 24), via: None },
                Route { target: net([192, 168, 50, 0], 24), via: Some(GW_IP) },
                Route { target: net([192, 168, 50, 128], 25), via: Some(PEER_IP) },
                Route { target: net([172, 16, 9, 0], 24), via: Some(Ipv4Addr::new(10, 99, 0, 1)) },
            ],
        }
    }

    fn up() -> L2 {
        let mut l2 = L2::new();
        l2.configure(config());
        l2
    }

    /// A minimal IPv4 packet (header only plus `extra` bytes) to `dst`.
    fn ip(dst: Ipv4Addr, extra: usize) -> Vec<u8> {
        let mut p = vec![0u8; 20 + extra];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + extra) as u16).to_be_bytes());
        p[12..16].copy_from_slice(&OUR_IP.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p
    }

    fn ip_from(src: Ipv4Addr, extra: usize) -> Vec<u8> {
        let mut p = ip(OUR_IP, extra);
        p[12..16].copy_from_slice(&src.octets());
        p
    }

    /// Calls next_out with `pkts` as the netstack's queue; returns the frames
    /// produced until both are exhausted.
    fn drain(l2: &mut L2, now: Instant, pkts: Vec<Vec<u8>>) -> Vec<Frame> {
        let mut q: VecDeque<Vec<u8>> = pkts.into();
        let mut out = Vec::new();
        while let Some(f) = l2.next_out(now, || q.pop_front()) {
            out.push(f);
        }
        assert!(q.is_empty(), "every packet popped is consumed");
        out
    }

    fn reply_from(l2: &mut L2, ip: Ipv4Addr, mac: u64, now: Instant) {
        let p = arp(2, mac, ip, OUR_MAC, OUR_IP);
        assert_eq!(l2.frame_in(mac, OUR_MAC, ETHERTYPE_ARP, &p, now), None);
    }

    #[test]
    fn answers_arp_for_our_address_byte_for_byte() {
        let mut l2 = up();
        let request = arp(1, PEER_MAC, PEER_IP, 0, OUR_IP);
        assert_eq!(l2.frame_in(PEER_MAC, BROADCAST, ETHERTYPE_ARP, &request, at(0)), None);
        let out = drain(&mut l2, at(0), vec![]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].dst_mac, PEER_MAC);
        assert_eq!(out[0].ethertype, ETHERTYPE_ARP);
        #[rustfmt::skip]
        assert_eq!(out[0].payload, vec![
            0, 1, 0x08, 0x00, 6, 4, 0, 2,
            0x32, 0x11, 0x22, 0x33, 0x44, 0x55, 10, 20, 30, 2,
            0x32, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 10, 20, 30, 7,
        ]);
    }

    #[test]
    fn ignores_arp_for_other_addresses() {
        let mut l2 = up();
        let request = arp(1, PEER_MAC, PEER_IP, 0, Ipv4Addr::new(10, 20, 30, 99));
        l2.frame_in(PEER_MAC, BROADCAST, ETHERTYPE_ARP, &request, at(0));
        assert!(drain(&mut l2, at(0), vec![]).is_empty());
    }

    #[test]
    fn request_is_what_zerotier_turns_into_a_per_address_multicast() {
        // Switch::onLocalEthernet only uses the address-resolution group for
        // a broadcast frame that is exactly an Ethernet/IPv4 ARP request,
        // reading the target address at offset 24.
        let mut l2 = up();
        let out = drain(&mut l2, at(0), vec![ip(PEER_IP, 8)]);
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!((f.dst_mac, f.ethertype), (BROADCAST, ETHERTYPE_ARP));
        let p = &f.payload;
        assert!(p.len() >= 28);
        assert_eq!((p[2], p[3], p[4], p[5], p[7]), (0x08, 0x00, 6, 4, 0x01));
        assert_eq!(&p[24..28], &PEER_IP.octets());
        assert_eq!(&p[8..14], &mac_bytes(OUR_MAC));
        assert_eq!(&p[14..18], &OUR_IP.octets());
    }

    #[test]
    fn holds_a_packet_until_the_neighbour_answers() {
        let mut l2 = up();
        let pkt = ip(PEER_IP, 100);
        let out = drain(&mut l2, at(0), vec![pkt.clone()]);
        assert_eq!(out.len(), 1, "only the ARP request so far");
        reply_from(&mut l2, PEER_IP, PEER_MAC, at(40));
        let out = drain(&mut l2, at(40), vec![]);
        assert_eq!(out, vec![Frame { dst_mac: PEER_MAC, ethertype: ETHERTYPE_IPV4, payload: pkt }]);
        // Known now: later packets go straight out, with no ARP.
        let out = drain(&mut l2, at(50), vec![ip(PEER_IP, 1), ip(PEER_IP, 2)]);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|f| f.dst_mac == PEER_MAC && f.ethertype == ETHERTYPE_IPV4));
        assert_eq!(l2.stats().broadcasts, 1);
    }

    #[test]
    fn learns_from_a_request_so_the_reply_path_needs_no_broadcast() {
        let mut l2 = up();
        let request = arp(1, PEER_MAC, PEER_IP, 0, OUR_IP);
        l2.frame_in(PEER_MAC, BROADCAST, ETHERTYPE_ARP, &request, at(0));
        let out = drain(&mut l2, at(1), vec![ip(PEER_IP, 10)]);
        assert_eq!(out.len(), 2, "our ARP reply, then the packet");
        assert_eq!(out[1].dst_mac, PEER_MAC);
        assert_eq!(l2.stats().broadcasts, 0);
        assert_eq!(l2.ip_of(PEER_MAC), Some(PEER_IP));
    }

    #[test]
    fn lists_neighbours() {
        let mut l2 = up();
        let other_mac = PEER_MAC + 1;
        let other_ip = Ipv4Addr::from(u32::from(PEER_IP) + 1);
        l2.frame_in(PEER_MAC, BROADCAST, ETHERTYPE_ARP, &arp(1, PEER_MAC, PEER_IP, 0, OUR_IP), at(0));
        l2.frame_in(other_mac, BROADCAST, ETHERTYPE_ARP, &arp(1, other_mac, other_ip, 0, OUR_IP), at(5));
        let seen: Vec<(u64, Ipv4Addr)> = l2.neighbors().collect();
        assert_eq!(seen.len(), 2);
        assert!(seen.contains(&(PEER_MAC, PEER_IP)) && seen.contains(&(other_mac, other_ip)));
    }

    #[test]
    fn does_not_learn_what_the_sender_cannot_vouch_for() {
        let mut l2 = up();
        // Speaks for another MAC.
        let p = arp(2, PEER_MAC, PEER_IP, OUR_MAC, OUR_IP);
        l2.frame_in(GW_MAC, OUR_MAC, ETHERTYPE_ARP, &p, at(0));
        // Claims our address, a broadcast MAC, an off-link address, the
        // network's broadcast address.
        for (mac, ip) in [
            (PEER_MAC, OUR_IP),
            (BROADCAST, PEER_IP),
            (PEER_MAC, Ipv4Addr::new(192, 168, 50, 3)),
            (PEER_MAC, Ipv4Addr::new(10, 20, 30, 255)),
        ] {
            let p = arp(2, mac, ip, OUR_MAC, OUR_IP);
            l2.frame_in(mac, OUR_MAC, ETHERTYPE_ARP, &p, at(0));
        }
        assert_eq!(l2.ip_of(PEER_MAC), None);
        assert!(l2.cache.is_empty());
        // Data packets confirm an entry but never create one.
        l2.frame_in(PEER_MAC, OUR_MAC, ETHERTYPE_IPV4, &ip_from(PEER_IP, 4), at(0));
        assert!(l2.cache.is_empty());
    }

    #[test]
    fn pending_list_is_bounded_and_one_per_hop() {
        let mut l2 = up();
        let hops: Vec<Ipv4Addr> = (10..16).map(|i| Ipv4Addr::new(10, 20, 30, i)).collect();
        let mut pkts = Vec::new();
        for h in &hops {
            pkts.push(ip(*h, 1));
            pkts.push(ip(*h, 2));
        }
        drain(&mut l2, at(0), pkts);
        assert_eq!(l2.pending.len(), PENDING_MAX);
        // The newest packet of each of the last four hops is the one kept.
        for (p, h) in l2.pending.iter().zip(&hops[2..]) {
            assert_eq!((p.hop, p.pkt.len()), (*h, 22));
        }
        // Six second packets displaced a first one, and two hops fell off.
        assert_eq!(l2.stats().unresolved, 6 + 2);
    }

    #[test]
    fn held_packets_expire() {
        let mut l2 = up();
        drain(&mut l2, at(0), vec![ip(PEER_IP, 1)]);
        assert_eq!(l2.next_deadline(at(0)), Some(at(1000)), "the first retry");
        drain(&mut l2, at(2999), vec![]);
        assert_eq!(l2.pending.len(), 1);
        drain(&mut l2, at(3000), vec![]);
        assert!(l2.pending.is_empty());
        assert_eq!(l2.next_deadline(at(3000)), None);
        // A late answer finds nothing to release.
        reply_from(&mut l2, PEER_IP, PEER_MAC, at(3100));
        assert!(drain(&mut l2, at(3100), vec![]).is_empty());
    }

    #[test]
    fn broadcasts_are_rate_limited() {
        let mut l2 = up();
        // Fifty different unknown addresses in one second.
        let mut sent = 0;
        for i in 0..50u64 {
            let dst = Ipv4Addr::new(10, 20, 30, 100 + i as u8);
            sent += drain(&mut l2, at(i * 20), vec![ip(dst, 1)]).len();
        }
        assert_eq!(sent, BROADCAST_BURST as usize);
        assert_eq!(l2.stats().broadcasts, BROADCAST_BURST);
        assert!(l2.stats().limited > 0);
        // One more is earned every five seconds, up to the burst.
        let out = drain(&mut l2, at(6_000), vec![ip(Ipv4Addr::new(10, 20, 30, 200), 1), ip(Ipv4Addr::new(10, 20, 30, 201), 1)]);
        assert_eq!(out.len(), 1);
        let pkts: Vec<Vec<u8>> = (0..20).map(|i| ip(Ipv4Addr::new(10, 20, 30, 210 + i), 1)).collect();
        let out = drain(&mut l2, at(600_000), pkts);
        assert_eq!(out.len(), BROADCAST_BURST as usize);
    }

    #[test]
    fn one_silent_address_backs_off() {
        let mut l2 = up();
        let mut asked = Vec::new();
        // An app sending to a dead address ten times a second for a minute.
        for t in (0..60_000).step_by(100) {
            if !drain(&mut l2, at(t), vec![ip(PEER_IP, 1)]).is_empty() {
                asked.push(t);
            }
        }
        assert_eq!(asked, vec![0, 1000, 3000, 7000, 15000, 31000]);
    }

    #[test]
    fn stale_neighbours_are_rechecked_by_unicast() {
        let mut l2 = up();
        reply_from(&mut l2, PEER_IP, PEER_MAC, at(0));
        // Fresh: nothing but the packet.
        assert_eq!(drain(&mut l2, at(60_000), vec![ip(PEER_IP, 1)]).len(), 1);
        // Stale: the packet still goes, and a request follows, to the
        // neighbour alone.
        let out = drain(&mut l2, at(130_000), vec![ip(PEER_IP, 1)]);
        assert_eq!(out.len(), 2);
        assert_eq!((out[0].dst_mac, out[0].ethertype), (PEER_MAC, ETHERTYPE_IPV4));
        assert_eq!((out[1].dst_mac, out[1].ethertype), (PEER_MAC, ETHERTYPE_ARP));
        assert_eq!(out[1].payload[7], 1);
        // Not again for a while.
        assert_eq!(drain(&mut l2, at(140_000), vec![ip(PEER_IP, 1)]).len(), 1);
        assert_eq!(drain(&mut l2, at(161_000), vec![ip(PEER_IP, 1)]).len(), 2);
        assert_eq!(l2.stats().broadcasts, 0);
        // Traffic from the neighbour counts as an answer.
        l2.frame_in(PEER_MAC, OUR_MAC, ETHERTYPE_IPV4, &ip_from(PEER_IP, 4), at(200_000));
        assert_eq!(drain(&mut l2, at(260_000), vec![ip(PEER_IP, 1)]).len(), 1);
        // Ten minutes of silence: forgotten, so it is asked for by broadcast.
        let out = drain(&mut l2, at(200_000 + 600_000), vec![ip(PEER_IP, 1)]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].dst_mac, BROADCAST);
    }

    #[test]
    fn routes_pick_the_gateway_by_longest_prefix() {
        let mut l2 = up();
        reply_from(&mut l2, GW_IP, GW_MAC, at(0));
        reply_from(&mut l2, PEER_IP, PEER_MAC, at(0));
        let out = drain(
            &mut l2,
            at(1),
            vec![ip(Ipv4Addr::new(192, 168, 50, 9), 1), ip(Ipv4Addr::new(192, 168, 50, 200), 1), ip(PEER_IP, 1)],
        );
        let macs: Vec<u64> = out.iter().map(|f| f.dst_mac).collect();
        assert_eq!(macs, vec![GW_MAC, PEER_MAC, PEER_MAC]);
        // The packet itself is untouched: it still names the far address.
        assert_eq!(&out[0].payload[16..20], &[192, 168, 50, 9]);
    }

    #[test]
    fn nowhere_to_go_is_dropped_not_resolved() {
        let mut l2 = up();
        let nowhere = [
            Ipv4Addr::new(8, 8, 8, 8),        // no route
            Ipv4Addr::new(172, 16, 9, 1),     // route through a gateway that isn't on-link
            OUR_IP,                           // ourselves
            Ipv4Addr::new(10, 20, 30, 255),   // the subnet's broadcast address
            Ipv4Addr::new(10, 20, 30, 0),     // and its network address
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 251),
        ];
        let pkts: Vec<Vec<u8>> = nowhere.iter().map(|d| ip(*d, 1)).collect();
        let n = pkts.len() as u32;
        assert!(drain(&mut l2, at(0), pkts).is_empty());
        assert_eq!(l2.stats().unroutable, n);
        assert_eq!(l2.stats().broadcasts, 0);
        // Not IPv4.
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        assert!(drain(&mut l2, at(0), vec![v6, vec![0x45; 5]]).is_empty());
    }

    #[test]
    fn a_link_that_is_down_still_consumes_packets() {
        let mut l2 = L2::new();
        let mut q: VecDeque<Vec<u8>> = (0..200).map(|_| ip(PEER_IP, 1)).collect();
        // Each call looks at a bounded number of packets, so the caller
        // comes back while its queue has any.
        let mut calls = 0;
        while !q.is_empty() {
            assert!(l2.next_out(at(0), || q.pop_front()).is_none());
            calls += 1;
        }
        assert_eq!(calls, 200usize.div_ceil(POP_MAX));
        assert_eq!(l2.stats().unroutable, 200);
        // And ignores what arrives.
        assert_eq!(l2.frame_in(PEER_MAC, OUR_MAC, ETHERTYPE_IPV4, &ip_from(PEER_IP, 4), at(0)), None);
    }

    #[test]
    fn inbound_ipv4_is_checked_and_trimmed() {
        let mut l2 = up();
        let mut padded = ip_from(PEER_IP, 6);
        padded.extend_from_slice(&[0; 20]);  // Ethernet padding
        let got = l2.frame_in(PEER_MAC, OUR_MAC, ETHERTYPE_IPV4, &padded, at(0)).expect("delivered");
        assert_eq!(got.len(), 26);
        // Shorter than its header says, not IPv4, for another MAC, another
        // ethertype: all dropped.
        assert_eq!(l2.frame_in(PEER_MAC, OUR_MAC, ETHERTYPE_IPV4, &padded[..22], at(0)), None);
        let mut v6 = padded.clone();
        v6[0] = 0x60;
        assert_eq!(l2.frame_in(PEER_MAC, OUR_MAC, ETHERTYPE_IPV4, &v6, at(0)), None);
        assert_eq!(l2.frame_in(PEER_MAC, GW_MAC, ETHERTYPE_IPV4, &padded, at(0)), None);
        assert_eq!(l2.frame_in(PEER_MAC, OUR_MAC, 0x86dd, &padded, at(0)), None);
        // Broadcast frames are let through (the netstack decides).
        assert!(l2.frame_in(PEER_MAC, BROADCAST, ETHERTYPE_IPV4, &padded, at(0)).is_some());
    }

    #[test]
    fn reconfiguring_keeps_neighbours_on_the_same_link_only() {
        let mut l2 = up();
        reply_from(&mut l2, PEER_IP, PEER_MAC, at(0));
        drain(&mut l2, at(0), vec![ip(GW_IP, 1)]);
        assert_eq!(l2.pending.len(), 1);
        // A new revision of the same network: neighbours stay, queues go.
        let mut cfg = config();
        cfg.routes.clear();
        l2.configure(cfg);
        assert!(l2.pending.is_empty() && !l2.has_frames());
        assert_eq!(l2.ip_of(PEER_MAC), Some(PEER_IP));
        // Another network: everything goes.
        let mut cfg = config();
        cfg.nwid ^= 1;
        l2.configure(cfg);
        assert_eq!(l2.ip_of(PEER_MAC), None);
        reply_from(&mut l2, PEER_IP, PEER_MAC, at(0));
        l2.down();
        assert_eq!(l2.ip_of(PEER_MAC), None);
        assert!(l2.config().is_none());
    }

    #[test]
    fn link_reset_rechecks_neighbours_without_broadcasting() {
        let mut l2 = up();
        reply_from(&mut l2, PEER_IP, PEER_MAC, at(1_000_000));
        drain(&mut l2, at(1_000_000), vec![ip(GW_IP, 1)]);
        l2.link_reset(at(1_000_100));
        assert!(l2.pending.is_empty() && !l2.has_frames());
        let out = drain(&mut l2, at(1_000_200), vec![ip(PEER_IP, 1)]);
        assert_eq!(out.len(), 2);
        assert_eq!((out[1].dst_mac, out[1].ethertype), (PEER_MAC, ETHERTYPE_ARP));
    }

    #[test]
    fn cache_evicts_the_least_recently_used() {
        let mut l2 = up();
        let mut cfg = config();
        cfg.addrs = vec![Net { addr: Ipv4Addr::new(10, 20, 0, 2), prefix: 16 }];
        l2.configure(cfg);
        for i in 0..ARP_CACHE as u8 {
            let p = arp(2, PEER_MAC + u64::from(i), Ipv4Addr::new(10, 20, 1, i), OUR_MAC, Ipv4Addr::new(10, 20, 0, 2));
            l2.frame_in(PEER_MAC + u64::from(i), OUR_MAC, ETHERTYPE_ARP, &p, at(u64::from(i)));
        }
        // Use all but number 3, then learn one more.
        for i in (0..ARP_CACHE as u8).filter(|i| *i != 3) {
            drain(&mut l2, at(1000 + u64::from(i)), vec![ip(Ipv4Addr::new(10, 20, 1, i), 1)]);
        }
        let p = arp(2, GW_MAC, Ipv4Addr::new(10, 20, 2, 1), OUR_MAC, Ipv4Addr::new(10, 20, 0, 2));
        l2.frame_in(GW_MAC, OUR_MAC, ETHERTYPE_ARP, &p, at(2000));
        assert_eq!(l2.cache.len(), ARP_CACHE);
        assert_eq!(l2.ip_of(PEER_MAC + 3), None);
        assert_eq!(l2.ip_of(GW_MAC), Some(Ipv4Addr::new(10, 20, 2, 1)));
    }
}
