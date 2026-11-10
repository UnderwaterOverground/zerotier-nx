//! The netstack and its Ethernet layer as one object: what the socket layer
//! and the ZeroTier glue talk to.
//!
//! Callers bracket their work with [`Stack::begin`] and [`Stack::end`]:
//! `begin` gives the stack the time, the calls in between (socket calls,
//! frames arriving) only change state, and `end` runs smoltcp once over all
//! of it. Outgoing frames are then taken with [`Stack::next_out`], by the
//! one thread that may call into ZeroTier.

use alloc::vec::Vec;
use core::net::IpAddr;

use crate::l2::{self, Frame, L2};
use crate::netstack::Netstack;
use crate::time::Instant;

/// The largest inner IP packet ZeroTier carries in one physical datagram
/// (its 1432-byte default physical MTU less 38 bytes of framing). TCP
/// segments are kept to it; a larger packet becomes two datagrams, and the
/// console's socket service is the bottleneck for datagrams.
pub const TCP_MTU: usize = 1394;
/// ZeroTier's default network MTU, until the network says otherwise.
pub const DEFAULT_MTU: usize = 2800;
/// How often spare queue capacity is given back.
const TRIM_EVERY_NS: u64 = 15_000_000_000;

/// What [`Stack::end`] found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    /// Frames are waiting for [`Stack::next_out`].
    pub out_pending: bool,
    /// Socket state may have changed: wake whoever waits on readiness.
    pub changed: bool,
}

pub struct Stack {
    net: Netstack,
    l2: L2,
    now: Instant,
    trimmed: u64,
    injected: bool,
}

impl Stack {
    pub fn new(now: Instant) -> Self {
        let mut net = Netstack::new(now, TCP_MTU);
        net.set_mtus(TCP_MTU, DEFAULT_MTU);
        Self { net, l2: L2::new(), now, trimmed: now.as_nanos() as u64, injected: false }
    }

    /// Sets the time for the calls that follow. Time never goes backwards.
    pub fn begin(&mut self, now: Instant) {
        if now.as_nanos() > self.now.as_nanos() {
            self.now = now;
        }
    }

    /// Runs the netstack over everything since [`Self::begin`].
    pub fn end(&mut self) -> Flags {
        let changed = self.net.poll(self.now) | core::mem::take(&mut self.injected);
        let now = self.now.as_nanos() as u64;
        if now.saturating_sub(self.trimmed) >= TRIM_EVERY_NS {
            self.trimmed = now;
            self.net.trim();
        }
        Flags { out_pending: self.out_pending(), changed }
    }

    /// The sockets. Use between [`Self::begin`] and [`Self::end`].
    pub fn net(&mut self) -> &mut Netstack {
        &mut self.net
    }

    pub fn l2(&self) -> &L2 {
        &self.l2
    }

    pub fn out_pending(&self) -> bool {
        self.net.outbound_len() > 0 || self.l2.has_frames()
    }

    /// The network is up (or its configuration changed).
    pub fn configure(&mut self, cfg: l2::Config, mtu: usize) {
        let addrs: Vec<IpAddr> = cfg.addrs.iter().map(|a| IpAddr::V4(a.addr)).collect();
        self.net.set_addresses(&addrs);
        self.net.set_mtus(TCP_MTU.min(mtu), mtu);
        self.l2.configure(cfg);
    }

    /// The network is gone. Sockets stay; their packets go nowhere.
    pub fn down(&mut self) {
        self.l2.down();
        self.net.set_addresses(&[]);
        self.net.clear_outbound();
    }

    /// After a sleep or a change of network underneath: what was queued is
    /// stale.
    pub fn link_reset(&mut self) {
        self.l2.link_reset(self.now);
        self.net.clear_outbound();
    }

    /// A frame arrived from the network.
    pub fn frame_in(&mut self, src_mac: u64, dst_mac: u64, ethertype: u16, payload: &[u8]) {
        if let Some(packet) = self.l2.frame_in(src_mac, dst_mac, ethertype, payload, self.now) {
            self.net.inject(packet);
            // A datagram goes straight to its socket's queue, which the
            // netstack's poll doesn't report.
            self.injected = true;
        }
    }

    /// The next frame to send, if any. None doesn't always mean the queue is
    /// empty (each call looks at a bounded number of packets): check
    /// [`Self::out_pending`].
    pub fn next_out(&mut self) -> Option<Frame> {
        let Self { net, l2, now, .. } = self;
        l2.next_out(*now, || net.pop_outbound())
    }

    /// When [`Self::begin`]/[`Self::end`] should next run if nothing happens
    /// before (TCP timers, ARP retries).
    pub fn next_deadline(&mut self) -> Option<Instant> {
        if self.out_pending() {
            return Some(self.now);
        }
        let net = self.net.poll_at(self.now);
        let l2 = self.l2.next_deadline(self.now);
        match (net, l2) {
            (Some(a), Some(b)) => Some(if a.as_nanos() <= b.as_nanos() { a } else { b }),
            (a, b) => a.or(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l2::{Config, Net, Route, BROADCAST, ETHERTYPE_ARP};
    use alloc::vec;
    use core::net::{Ipv4Addr, SocketAddr};

    const NWID: u64 = 0x8056_c2e2_1c00_0001;

    struct Node {
        stack: Stack,
        mac: u64,
        ip: Ipv4Addr,
        /// (destination MAC, ethertype) of every frame sent.
        sent: Vec<(u64, u16)>,
    }

    fn node(mac: u64, ip: Ipv4Addr) -> Node {
        let mut stack = Stack::new(Instant::from_millis(0));
        let net = Net { addr: ip, prefix: 24 };
        stack.configure(
            Config { nwid: NWID, mac, addrs: vec![net], routes: vec![Route { target: Net { addr: Ipv4Addr::new(10, 20, 30, 0), prefix: 24 }, via: None }] },
            2800,
        );
        Node { stack, mac, ip, sent: Vec::new() }
    }

    /// Delivers everything `from` has to send. True if there was anything.
    fn carry(from: &mut Node, to: &mut Node, now: Instant) -> bool {
        let mut moved = false;
        while let Some(f) = from.stack.next_out() {
            moved = true;
            from.sent.push((f.dst_mac, f.ethertype));
            if f.dst_mac == to.mac || f.dst_mac == BROADCAST {
                to.stack.begin(now);
                to.stack.frame_in(from.mac, f.dst_mac, f.ethertype, &f.payload);
            }
        }
        moved
    }

    /// Runs both nodes at `now` and carries frames between them until
    /// neither has any.
    fn settle(a: &mut Node, b: &mut Node, now: Instant) {
        for _ in 0..1000 {
            a.stack.begin(now);
            b.stack.begin(now);
            a.stack.end();
            b.stack.end();
            if !(carry(a, b, now) | carry(b, a, now)) {
                return;
            }
        }
        panic!("frames never stopped");
    }

    #[test]
    fn two_stacks_find_each_other_and_talk_tcp() {
        let mut a = node(0x32_00_00_00_00_0a, Ipv4Addr::new(10, 20, 30, 2));
        let mut b = node(0x32_00_00_00_00_0b, Ipv4Addr::new(10, 20, 30, 7));
        let listener = b.stack.net().tcp_listen(7, 4).unwrap();
        let mut now = Instant::from_millis(1);
        a.stack.begin(now);
        let client = a.stack.net().tcp_connect(SocketAddr::new(IpAddr::V4(b.ip), 7)).unwrap();
        assert!(a.stack.end().out_pending, "a SYN is waiting");
        settle(&mut a, &mut b, now);
        // One broadcast found the neighbour; the other side learned from it.
        assert_eq!(a.sent[0], (BROADCAST, ETHERTYPE_ARP));
        assert_eq!(a.stack.l2().stats().broadcasts, 1);
        assert_eq!(b.stack.l2().stats().broadcasts, 0);
        assert!(b.sent.iter().all(|(mac, _)| *mac == a.mac));

        let (server, peer) = b.stack.net().tcp_accept(listener).expect("connected");
        assert_eq!(peer.ip(), IpAddr::V4(a.ip));
        // 100 KB there and back.
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let (mut sent, mut echoed, mut got) = (0usize, 0usize, Vec::new());
        let mut buf = [0u8; 16384];
        for _ in 0..5000 {
            now = now + core::time::Duration::from_millis(1);
            a.stack.begin(now);
            b.stack.begin(now);
            if sent < data.len() {
                if let Ok(n) = a.stack.net().send(client, &data[sent..]) {
                    sent += n;
                }
            }
            while let Ok(n) = b.stack.net().recv(server, &mut buf) {
                if n == 0 {
                    break;
                }
                let mut off = 0;
                while off < n {
                    match b.stack.net().send(server, &buf[off..n]) {
                        Ok(m) => off += m,
                        Err(_) => break,
                    }
                }
                // (A full send buffer would lose the rest in a real echo
                // server; here the window is far larger than one read.)
                assert_eq!(off, n);
                echoed += n;
            }
            while let Ok(n) = a.stack.net().recv(client, &mut buf) {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            settle(&mut a, &mut b, now);
            if got.len() == data.len() {
                break;
            }
        }
        assert_eq!(echoed, data.len());
        assert!(got == data, "echo differs (got {} bytes)", got.len());
        // No further broadcasts, and no segment over ZeroTier's single-datagram size.
        assert_eq!(a.stack.l2().stats().broadcasts + b.stack.l2().stats().broadcasts, 1);
    }

    #[test]
    fn deadline_covers_arp_retries_and_tcp_timers() {
        let mut a = node(0x32_00_00_00_00_0a, Ipv4Addr::new(10, 20, 30, 2));
        assert_eq!(a.stack.next_deadline(), None, "idle");
        let t0 = Instant::from_millis(10);
        a.stack.begin(t0);
        a.stack.net().tcp_connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 9)), 80)).unwrap();
        assert!(a.stack.end().out_pending);
        assert_eq!(a.stack.next_deadline(), Some(t0), "frames waiting: now");
        // Nobody answers: the SYN is held, the request went out.
        let f = a.stack.next_out().expect("the ARP request");
        assert_eq!((f.dst_mac, f.ethertype), (BROADCAST, ETHERTYPE_ARP));
        assert_eq!(a.stack.next_out(), None);
        assert!(!a.stack.out_pending());
        // Next: the ARP retry at one second, or TCP's own retransmit if sooner.
        let next = a.stack.next_deadline().expect("a timer");
        let ms = next.as_nanos() as u64 / 1_000_000;
        assert!(ms > 10 && ms <= 1010, "deadline at {ms} ms");
    }

    #[test]
    fn down_and_link_reset_drop_what_is_queued() {
        let mut a = node(0x32_00_00_00_00_0a, Ipv4Addr::new(10, 20, 30, 2));
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 9)), 9);
        a.stack.begin(Instant::from_millis(1));
        let udp = a.stack.net().udp_bind(0).unwrap();
        for _ in 0..10 {
            a.stack.net().udp_send_to(udp, b"x", peer).unwrap();
        }
        assert!(a.stack.end().out_pending);
        a.stack.link_reset();
        assert!(!a.stack.out_pending());
        a.stack.net().udp_send_to(udp, b"x", peer).unwrap();
        a.stack.down();
        assert!(!a.stack.out_pending());
        // With the network gone there is no source address to send from.
        assert!(a.stack.net().udp_send_to(udp, b"x", peer).is_err());
        assert_eq!(a.stack.next_out(), None);
    }

    #[test]
    fn a_low_network_mtu_lowers_tcp_too() {
        let mut a = node(0x32_00_00_00_00_0a, Ipv4Addr::new(10, 20, 30, 2));
        let cfg = a.stack.l2().config().unwrap().clone();
        a.stack.configure(cfg, 1280);
        a.stack.begin(Instant::from_millis(1));
        a.stack.net().tcp_connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 9)), 80)).unwrap();
        a.stack.end();
        let syn = a.stack.net().pop_outbound().expect("a SYN");
        assert_eq!(u16::from_be_bytes([syn[42], syn[43]]), 1280 - 40);
    }
}
