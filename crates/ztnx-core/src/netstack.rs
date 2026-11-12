//! Userspace TCP/IP stack for the network's side, built on smoltcp.
//!
//! IP packets that arrived over the network are injected here; packets the
//! stack emits are drained and sent through it (see `l2` and `stack`). On top sits a small
//! BSD-like socket API (ids, non-blocking calls, readiness) that the socket
//! MITM layer maps intercepted `bsd:u` calls onto.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};

use crate::time::Instant;

/// The MTU until the stack is configured (see `stack::TCP_MTU`).
pub const DEFAULT_MTU: usize = 1420;

// Overlay socket memory. On the Switch every byte comes out of the
// sysmodule's fixed heap, shared with the engine and with every app's
// sockets, so buffers are smaller there and all of them draw from one
// budget: past it, new TCP sockets are refused and datagrams dropped
// instead of the heap running out.
//
// TCP buffers are sized per connection from what is left of the budget (see
// `tcp_buffer_size`): the first connections get the full size, later ones
// less, down to TCP_MIN. A crowded budget makes connections slower (a TCP
// window caps throughput at window / RTT) instead of refusing them.
#[cfg(not(any(target_os = "horizon", feature = "switch-limits")))]
mod limits {
    /// Largest receive / send buffer of one TCP connection.
    pub const TCP_RX: usize = 64 << 10;
    pub const TCP_TX: usize = 64 << 10;
    /// Datagrams queued per UDP socket (bytes, counting allocation size).
    pub const UDP_RX: usize = 512 << 10;
    pub const BUDGET: usize = usize::MAX;
    /// Packets waiting for the tunnel (see `Queues`), and their bytes.
    pub const OUT_PKTS: usize = 256;
    pub const OUT_BYTES: usize = 1 << 20;
    /// Packets from the tunnel waiting for the next poll.
    pub const IN_PKTS: usize = 1024;
}
// Measured on the console: a Moonlight stream keeps 0-6 KB queued while the
// app reads; only a suspended app (HOME menu) fills a queue, and stale video
// is useless then anyway. Heap fragmentation, not the total, is the limit.
#[cfg(any(target_os = "horizon", feature = "switch-limits"))]
mod limits {
    pub const TCP_RX: usize = 32 << 10;
    pub const TCP_TX: usize = 32 << 10;
    pub const UDP_RX: usize = 64 << 10;
    /// Default; the sysmodule's config can change it (`set_budget`).
    pub const BUDGET: usize = 320 << 10;
    pub const OUT_PKTS: usize = 64;
    /// 64 full TCP segments, or 34 datagrams of the largest size.
    pub const OUT_BYTES: usize = 96 << 10;
    pub const IN_PKTS: usize = 64;
}
use limits::*;
/// Smallest TCP buffer (each direction): a few full-size segments.
const TCP_MIN: usize = 4 << 10;

/// Buffer size (each direction) for a new TCP connection when `free` budget
/// bytes are left: a tenth of it, rounded down to a power of two, between
/// TCP_MIN and `max`. With the Switch's 320 KB: one connection at 32 KB, four
/// at 16, four at 8 and eight at 4 (17 at once, before UDP queues).
fn tcp_buffer_size(free: usize, max: usize) -> usize {
    let tenth = free / 10;
    if tenth < TCP_MIN {
        return TCP_MIN;
    }
    (1usize << (usize::BITS - 1 - tenth.leading_zeros())).clamp(TCP_MIN, max)
}

/// Zero bytes: `len` of them, or half as many and so on down to TCP_MIN
/// when the allocator can't provide that many in one piece.
fn zeroed_up_to(mut len: usize) -> Option<Vec<u8>> {
    loop {
        let mut v = Vec::new();
        if v.try_reserve_exact(len).is_ok() {
            v.resize(len, 0);
            return Some(v);
        }
        if len / 2 < TCP_MIN {
            return None;
        }
        len /= 2;
    }
}

const EPHEMERAL_PORTS: core::ops::RangeInclusive<u16> = 49152..=65535;

pub type SockId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    WouldBlock,
    NotConnected,
    InvalidSocket,
    AddrInUse,
    ConnectionRefused,
    ConnectionReset,
    Invalid,
    /// The overlay memory budget is used up.
    NoBuffers,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Readiness {
    pub readable: bool,
    pub writable: bool,
    /// Peer closed / reset: reads return EOF or an error.
    pub hup: bool,
}

/// Packet queues that smoltcp reads from and writes to.
// The engine drains `outbound` every time it runs. While it doesn't (paused,
// or asleep) apps' datagrams would pile up without limit and exhaust the heap,
// so past OUT_PKTS new ones are dropped, as a full network card would, and TCP
// keeps its data in the socket's send buffer until the next poll.
#[derive(Default)]
struct Queues {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    /// Bytes in `outbound`.
    out_bytes: usize,
    /// Largest IP packet smoltcp (TCP, ICMP) sends.
    mtu: usize,
    /// Largest IP packet a UDP socket may send. It can be larger than `mtu`
    /// when the link below splits big packets itself and TCP should stay
    /// under the size at which it does.
    udp_mtu: usize,
}

impl Queues {
    fn outbound_full(&self) -> bool {
        self.outbound.len() >= OUT_PKTS || self.out_bytes >= OUT_BYTES
    }

    fn push_outbound(&mut self, pkt: Vec<u8>) {
        self.out_bytes += pkt.len();
        self.outbound.push_back(pkt);
    }

    fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        let pkt = self.outbound.pop_front()?;
        self.out_bytes -= pkt.len();
        Some(pkt)
    }
}

struct RxToken(Vec<u8>);
struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    bytes: &'a mut usize,
}

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        *self.bytes += len;
        self.queue.push_back(buf);
        r
    }
}

impl Device for Queues {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(RxToken, TxToken<'_>)> {
        let pkt = self.inbound.pop_front()?;
        Some((RxToken(pkt), TxToken { queue: &mut self.outbound, bytes: &mut self.out_bytes }))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<TxToken<'_>> {
        if self.outbound_full() {
            return None;
        }
        Some(TxToken { queue: &mut self.outbound, bytes: &mut self.out_bytes })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

enum Sock {
    Tcp(SocketHandle),
    /// A listener keeps one smoltcp socket listening at a time and moves
    /// connected ones to `ready` (smoltcp listeners accept a single peer).
    /// `listening` is funded only when a SYN arrives for the port and freed
    /// again if none is pending, so an idle listener costs no buffers.
    Listener { port: u16, listening: Option<SocketHandle>, ready: VecDeque<SocketHandle>, backlog: usize },
    /// UDP is handled here rather than by smoltcp: received datagrams are
    /// queued as they arrive, so an idle socket costs nothing.
    Udp { port: u16, rx: VecDeque<(SocketAddr, Vec<u8>)>, rx_bytes: usize },
}

pub struct Netstack {
    iface: Interface,
    sockets: SocketSet<'static>,
    dev: Queues,
    socks: BTreeMap<SockId, Sock>,
    /// Closed TCP sockets still finishing their shutdown handshake.
    closing: Vec<SocketHandle>,
    next_id: SockId,
    next_port: u16,
    addrs: Vec<IpAddr>,
    /// Overlay buffer bytes currently allocated (see `limits`).
    used: usize,
    /// Most overlay buffer bytes that may be allocated at once.
    budget: usize,
    /// Datagrams for an open UDP socket thrown away because its queue (or the
    /// budget) was full: the app wasn't reading fast enough.
    udp_dropped: u32,
    /// Rebuilds IPv4 datagrams that arrived fragmented (see `reasm`).
    reasm: reasm::Reassembler,
    /// The most recent time [`Self::poll`] saw, for ageing out fragments.
    last_now: Instant,
}

fn random_ephemeral_port() -> u16 {
    let mut b = [0u8; 2];
    let _ = crate::rng::fill(&mut b);
    let span = EPHEMERAL_PORTS.end() - EPHEMERAL_PORTS.start() + 1;
    EPHEMERAL_PORTS.start() + u16::from_le_bytes(b) % span
}

fn smol_now(now: Instant) -> smoltcp::time::Instant {
    smoltcp::time::Instant::from_micros((now.as_nanos() / 1000) as i64)
}

/// The stack speaks IPv4 only (smoltcp is built without IPv6).
fn endpoint(addr: SocketAddr) -> Option<IpEndpoint> {
    match addr.ip() {
        IpAddr::V4(v4) => Some(IpEndpoint::new(IpAddress::Ipv4(v4), addr.port())),
        IpAddr::V6(_) => None,
    }
}

fn socket_addr(ep: IpEndpoint) -> SocketAddr {
    SocketAddr::new(ep.addr.into(), ep.port)
}

impl Netstack {
    pub fn new(now: Instant, mtu: usize) -> Self {
        let mut dev = Queues { mtu, udp_mtu: mtu, ..Default::default() };
        let iface = Self::new_iface(&mut dev, now);
        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            dev,
            socks: BTreeMap::new(),
            closing: Vec::new(),
            next_id: 1,
            // Random start: after a restart with the same address, reusing
            // the previous run's 4-tuples would collide with connections the
            // peer still considers established.
            next_port: random_ephemeral_port(),
            addrs: Vec::new(),
            used: 0,
            budget: BUDGET,
            udp_dropped: 0,
            reasm: reasm::Reassembler::new(),
            last_now: now,
        }
    }

    fn new_iface(dev: &mut Queues, now: Instant) -> Interface {
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, dev, smol_now(now));
        // Everything not on-link goes "out the tunnel"; with Medium::Ip the
        // gateway is never resolved, it only has to exist.
        let _ = iface.routes_mut().add_default_ipv4_route(core::net::Ipv4Addr::new(192, 0, 2, 1));
        iface
    }

    /// Sets the interface's MTU (packets built here are limited to it).
    pub fn set_mtu(&mut self, mtu: usize) {
        self.dev.mtu = mtu;
        self.dev.udp_mtu = mtu;
    }

    /// Sets the largest IP packet TCP and ICMP send, and the largest a UDP
    /// socket may send. smoltcp reads its device's MTU once, when the
    /// interface is made, so a new TCP limit means a new interface; sockets
    /// are not part of it and carry on (connections keep the segment size
    /// they agreed).
    pub fn set_mtus(&mut self, mtu: usize, udp_mtu: usize) {
        self.dev.udp_mtu = udp_mtu;
        if mtu != self.dev.mtu {
            self.dev.mtu = mtu;
            self.iface = Self::new_iface(&mut self.dev, self.last_now);
            let addrs = core::mem::take(&mut self.addrs);
            self.set_addresses(&addrs);
        }
    }

    /// Sets this interface's addresses.
    pub fn set_addresses(&mut self, addrs: &[IpAddr]) {
        self.addrs = addrs.to_vec();
        self.iface.update_ip_addrs(|cidrs| {
            cidrs.clear();
            for a in addrs {
                if let IpAddr::V4(v4) = a {
                    let _ = cidrs.push(IpCidr::new(IpAddress::Ipv4(*v4), 32));
                }
            }
        });
    }

    pub fn addresses(&self) -> &[IpAddr] {
        &self.addrs
    }

    /// Delivers an IP packet received from the tunnel.
    pub fn inject(&mut self, packet: Vec<u8>) {
        // A fragment is held until its datagram is whole; smoltcp and the UDP
        // parser both need the complete packet (Sunshine video, for one,
        // exceeds the tunnel MTU and arrives fragmented).
        let packet = if reasm::is_fragment(&packet) {
            match self.reasm.accept(packet, self.last_now) {
                Some(whole) => whole,
                None => return,
            }
        } else {
            packet
        };
        if let Some(packet) = self.deliver_udp(packet) {
            // Every caller polls after injecting, which empties this queue;
            // the cap is for one that doesn't.
            if self.dev.inbound.len() >= IN_PKTS {
                return;
            }
            if let Some(port) = self.syn_port(&packet) {
                self.arm_listener(port);
            }
            self.dev.inbound.push_back(packet);
        }
    }

    /// Overlay buffer bytes in use (TCP socket buffers, queued datagrams).
    pub fn buffer_usage(&self) -> usize {
        self.used
    }

    /// Datagrams dropped because a UDP socket's queue or the budget was full.
    pub fn udp_dropped(&self) -> u32 {
        self.udp_dropped
    }

    /// Releases spare queue capacity (see [`crate::trim_vec`]).
    pub fn trim(&mut self) {
        self.dev.inbound.shrink_to_fit();
        self.dev.outbound.shrink_to_fit();
        crate::trim_vec(&mut self.closing);
        for s in self.socks.values_mut() {
            match s {
                Sock::Udp { rx, .. } => rx.shrink_to_fit(),
                Sock::Listener { ready, .. } => ready.shrink_to_fit(),
                Sock::Tcp(_) => {}
            }
        }
    }

    /// Sets the overlay buffer budget (bytes). Applies to new allocations;
    /// existing buffers are kept.
    pub fn set_budget(&mut self, bytes: usize) {
        self.budget = bytes;
    }

    /// Runs the stack. Returns true if socket state may have changed.
    pub fn poll(&mut self, now: Instant) -> bool {
        self.last_now = now;
        let changed = self.iface.poll(smol_now(now), &mut self.dev, &mut self.sockets)
            != smoltcp::iface::PollResult::None;
        self.service_listeners();
        self.reap_closing();
        changed
    }

    /// Takes IP packets the stack wants to send into the tunnel.
    pub fn take_outbound(&mut self) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.dev.out_bytes = 0;
        self.dev.outbound.drain(..)
    }

    /// Takes the oldest IP packet the stack wants to send.
    pub fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.dev.pop_outbound()
    }

    /// Packets waiting to be sent.
    pub fn outbound_len(&self) -> usize {
        self.dev.outbound.len()
    }

    /// Drops the packets waiting to be sent (after a sleep they are stale).
    pub fn clear_outbound(&mut self) {
        self.dev.outbound.clear();
        self.dev.out_bytes = 0;
    }

    /// When [`Self::poll`] should next run (absent new input).
    pub fn poll_at(&mut self, now: Instant) -> Option<Instant> {
        let at = self.iface.poll_at(smol_now(now), &self.sockets)?;
        Some(Instant::from_nanos(at.total_micros().max(0) as u64 * 1000))
    }

    // ---- socket API ------------------------------------------------------

    pub fn tcp_connect(&mut self, remote: SocketAddr) -> Result<SockId, NetError> {
        let remote = endpoint(remote).ok_or(NetError::Invalid)?;
        let handle = self.new_tcp()?;
        let port = self.ephemeral_port();
        let sock = self.sockets.get_mut::<tcp::Socket>(handle);
        if sock.connect(self.iface.context(), remote, port).is_err() {
            self.remove_tcp(handle);
            return Err(NetError::Invalid);
        }
        Ok(self.insert(Sock::Tcp(handle)))
    }

    pub fn tcp_listen(&mut self, port: u16, backlog: usize) -> Result<SockId, NetError> {
        let in_use = self.socks.values().any(|s| matches!(s, Sock::Listener { port: p, .. } if *p == port));
        if in_use || port == 0 {
            return Err(NetError::AddrInUse);
        }
        Ok(self.insert(Sock::Listener { port, listening: None, ready: VecDeque::new(), backlog: backlog.max(1) }))
    }

    /// Accepts a pending connection on a listener.
    pub fn tcp_accept(&mut self, id: SockId) -> Result<(SockId, SocketAddr), NetError> {
        loop {
            let Some(Sock::Listener { ready, .. }) = self.socks.get_mut(&id) else {
                return Err(NetError::InvalidSocket);
            };
            let handle = ready.pop_front().ok_or(NetError::WouldBlock)?;
            match self.sockets.get::<tcp::Socket>(handle).remote_endpoint() {
                Some(peer) => return Ok((self.insert(Sock::Tcp(handle)), socket_addr(peer))),
                // Reset while queued: free it and try the next one, as a
                // kernel would (servers treat a failed accept after poll
                // said "ready" as fatal; sys-ftpd restarts itself).
                None => self.remove_tcp(handle),
            }
        }
    }

    pub fn send(&mut self, id: SockId, data: &[u8]) -> Result<usize, NetError> {
        let sock = self.tcp(id)?;
        if !sock.may_send() {
            return Err(if sock.state() == tcp::State::SynSent { NetError::WouldBlock } else { NetError::NotConnected });
        }
        match sock.send_slice(data) {
            Ok(0) if !data.is_empty() => Err(NetError::WouldBlock),
            Ok(n) => Ok(n),
            Err(_) => Err(NetError::NotConnected),
        }
    }

    /// Reads stream data. `Ok(0)` means the peer closed (EOF).
    pub fn recv(&mut self, id: SockId, buf: &mut [u8]) -> Result<usize, NetError> {
        let sock = self.tcp(id)?;
        match sock.recv_slice(buf) {
            Ok(0) if sock.may_recv() || sock.state() == tcp::State::SynSent => Err(NetError::WouldBlock),
            Ok(n) => Ok(n),
            Err(tcp::RecvError::Finished) => Ok(0),
            Err(tcp::RecvError::InvalidState) => {
                if sock.state() == tcp::State::Closed {
                    Err(NetError::ConnectionReset)
                } else {
                    Err(NetError::WouldBlock)
                }
            }
        }
    }

    /// Half-closes the sending side (FIN).
    pub fn shutdown_write(&mut self, id: SockId) -> Result<(), NetError> {
        self.tcp(id)?.close();
        Ok(())
    }

    pub fn udp_bind(&mut self, port: u16) -> Result<SockId, NetError> {
        let port = if port == 0 { self.ephemeral_port() } else { port };
        if self.udp_port_in_use(port) {
            return Err(NetError::AddrInUse);
        }
        Ok(self.insert(Sock::Udp { port, rx: VecDeque::new(), rx_bytes: 0 }))
    }

    pub fn udp_send_to(&mut self, id: SockId, data: &[u8], dst: SocketAddr) -> Result<(), NetError> {
        let Some(Sock::Udp { port, .. }) = self.socks.get(&id) else { return Err(NetError::InvalidSocket) };
        let src = self.addrs.iter().copied().find(|a| a.is_ipv4() == dst.is_ipv4()).ok_or(NetError::Invalid)?;
        let pkt = udp::build(SocketAddr::new(src, *port), dst, data, self.dev.udp_mtu).ok_or(NetError::Invalid)?;
        if !self.dev.outbound_full() {
            self.dev.push_outbound(pkt);
        }
        Ok(())
    }

    pub fn udp_recv_from(&mut self, id: SockId, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
        let Some(Sock::Udp { rx, rx_bytes, .. }) = self.socks.get_mut(&id) else { return Err(NetError::InvalidSocket) };
        let (from, data) = rx.pop_front().ok_or(NetError::WouldBlock)?;
        let cost = data.capacity();
        *rx_bytes -= cost;
        self.used -= cost;
        // Like a truncating recv: a datagram larger than `buf` loses its tail.
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((n, from))
    }

    pub fn readiness(&self, id: SockId) -> Readiness {
        match self.socks.get(&id) {
            Some(Sock::Tcp(h)) => {
                let s = self.sockets.get::<tcp::Socket>(*h);
                let closed = matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait);
                Readiness {
                    readable: s.can_recv() || (!s.may_recv() && s.state() != tcp::State::SynSent),
                    writable: s.can_send(),
                    hup: closed || !s.may_recv() && s.state() != tcp::State::SynSent,
                }
            }
            Some(Sock::Listener { ready, .. }) => Readiness { readable: !ready.is_empty(), ..Default::default() },
            Some(Sock::Udp { rx, .. }) => Readiness { readable: !rx.is_empty(), writable: true, hup: false },
            None => Readiness { hup: true, ..Default::default() },
        }
    }

    pub fn local_addr(&self, id: SockId) -> Option<SocketAddr> {
        match self.socks.get(&id)? {
            Sock::Tcp(h) => self.sockets.get::<tcp::Socket>(*h).local_endpoint().map(socket_addr),
            Sock::Listener { port, .. } => Some(SocketAddr::new(*self.addrs.first()?, *port)),
            Sock::Udp { port, .. } => Some(SocketAddr::new(*self.addrs.first()?, *port)),
        }
    }

    pub fn peer_addr(&self, id: SockId) -> Option<SocketAddr> {
        match self.socks.get(&id)? {
            Sock::Tcp(h) => self.sockets.get::<tcp::Socket>(*h).remote_endpoint().map(socket_addr),
            _ => None,
        }
    }

    /// Closes a TCP connection with a reset, dropping unsent and unread
    /// data (other sockets: same as [`Self::close`]).
    pub fn abort(&mut self, id: SockId) {
        if let Some(Sock::Tcp(h)) = self.socks.get(&id) {
            self.sockets.get_mut::<tcp::Socket>(*h).abort();
        }
        self.close(id);
    }

    pub fn close(&mut self, id: SockId) {
        match self.socks.remove(&id) {
            Some(Sock::Tcp(h)) => {
                self.sockets.get_mut::<tcp::Socket>(h).close();
                self.closing.push(h);
            }
            Some(Sock::Listener { listening, ready, .. }) => {
                if let Some(h) = listening {
                    self.remove_tcp(h);
                }
                for h in ready {
                    self.sockets.get_mut::<tcp::Socket>(h).abort();
                    self.closing.push(h);
                }
            }
            Some(Sock::Udp { rx_bytes, .. }) => {
                self.used -= rx_bytes;
            }
            None => {}
        }
    }

    // ---- internals -------------------------------------------------------

    fn insert(&mut self, s: Sock) -> SockId {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.socks.insert(id, s);
        id
    }

    fn tcp(&mut self, id: SockId) -> Result<&mut tcp::Socket<'static>, NetError> {
        match self.socks.get(&id) {
            Some(Sock::Tcp(h)) => Ok(self.sockets.get_mut::<tcp::Socket>(*h)),
            _ => Err(NetError::InvalidSocket),
        }
    }

    /// A TCP socket with its buffers, if the budget allows. Closed sockets
    /// still finishing their shutdown give way first (oldest first): apps
    /// like Moonlight open and close many connections in a burst, and a
    /// live connection matters more than a polite goodbye on a dead one.
    fn new_tcp(&mut self) -> Result<SocketHandle, NetError> {
        while self.used.saturating_add(2 * TCP_MIN) > self.budget && !self.closing.is_empty() {
            let h = self.closing.remove(0);
            // Dropped without its RST; the peer gets one if it sends again.
            self.remove_tcp(h);
        }
        if self.used.saturating_add(2 * TCP_MIN) > self.budget {
            return Err(NetError::NoBuffers);
        }
        let free = self.budget - self.used;
        // The budget doesn't see fragmentation: on the Switch's fixed heap a
        // buffer can fail to fit with budget to spare. Take smaller ones
        // then (a smaller window, a slower connection), and refuse the socket
        // only below TCP_MIN, rather than abort.
        let (Some(rx), Some(tx)) = (zeroed_up_to(tcp_buffer_size(free, TCP_RX)), zeroed_up_to(tcp_buffer_size(free, TCP_TX))) else {
            return Err(NetError::NoBuffers);
        };
        self.used += rx.len() + tx.len();
        let mut sock = tcp::Socket::new(tcp::SocketBuffer::new(rx), tcp::SocketBuffer::new(tx));
        sock.set_nagle_enabled(false);
        sock.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));
        Ok(self.sockets.add(sock))
    }

    fn remove_tcp(&mut self, h: SocketHandle) {
        self.used -= tcp_buffers(self.sockets.get::<tcp::Socket>(h));
        self.sockets.remove(h);
    }

    fn new_listening(&mut self, port: u16) -> Result<SocketHandle, NetError> {
        let handle = self.new_tcp()?;
        if self.sockets.get_mut::<tcp::Socket>(handle).listen(port).is_err() {
            self.remove_tcp(handle);
            return Err(NetError::Invalid);
        }
        Ok(handle)
    }

    fn udp_port_in_use(&self, port: u16) -> bool {
        self.socks.values().any(|s| matches!(s, Sock::Udp { port: p, .. } if *p == port))
    }

    /// Queues a UDP datagram for a bound socket. Returns the packet if it is
    /// not one (smoltcp then handles or drops it).
    fn deliver_udp(&mut self, packet: Vec<u8>) -> Option<Vec<u8>> {
        let Some(d) = udp::parse(&packet) else { return Some(packet) };
        if !self.addrs.contains(&d.dst.ip()) {
            return Some(packet);
        }
        let port = d.dst.port();
        let Some(Sock::Udp { rx, rx_bytes, .. }) = self.socks.values_mut().find(|s| matches!(s, Sock::Udp { port: p, .. } if *p == port))
        else {
            return Some(packet);
        };
        let (src, range) = (d.src, d.payload);
        let mut data = packet;
        data.truncate(range.end);
        data.drain(..range.start);
        let cost = data.capacity();
        // Full: drop the oldest datagrams of this socket (a reader that falls
        // behind wants fresh data; a stalled one shouldn't pin stale bytes).
        while !rx.is_empty() && (*rx_bytes + cost > UDP_RX || self.used.saturating_add(cost) > self.budget) {
            let (_, old) = rx.pop_front().expect("non-empty");
            *rx_bytes -= old.capacity();
            self.used -= old.capacity();
            self.udp_dropped = self.udp_dropped.wrapping_add(1);
        }
        if *rx_bytes + cost > UDP_RX || self.used.saturating_add(cost) > self.budget {
            self.udp_dropped = self.udp_dropped.wrapping_add(1);
            return None;  // still no room (other sockets hold the budget): drop
        }
        *rx_bytes += cost;
        self.used += cost;
        rx.push_back((src, data));
        None
    }

    fn ephemeral_port(&mut self) -> u16 {
        let p = self.next_port;
        self.next_port = if p == *EPHEMERAL_PORTS.end() { *EPHEMERAL_PORTS.start() } else { p + 1 };
        p
    }

    /// The destination port of a TCP SYN (connection attempt) to one of our
    /// addresses, if `packet` is one.
    fn syn_port(&self, packet: &[u8]) -> Option<u16> {
        let (dst, tcp): (IpAddr, &[u8]) = match packet.first()? >> 4 {
            4 => {
                let ihl = usize::from(packet.first()? & 0x0f) * 4;
                if *packet.get(9)? != 6 || ihl < 20 {
                    return None;
                }
                let d: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
                (IpAddr::from(d), packet.get(ihl..)?)
            }
            6 => {
                if *packet.get(6)? != 6 {
                    return None;
                }
                let d: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
                (IpAddr::from(d), packet.get(40..)?)
            }
            _ => return None,
        };
        let flags = *tcp.get(13)?;
        let syn_only = flags & 0x02 != 0 && flags & 0x10 == 0;
        (syn_only && self.addrs.contains(&dst)).then(|| u16::from_be_bytes([tcp[2], tcp[3]]))
    }

    /// Funds a listening socket for `port` (a SYN is about to arrive), if a
    /// listener there has none, room in its backlog, and budget.
    fn arm_listener(&mut self, port: u16) {
        let Some(id) = self.socks.iter().find_map(|(&id, s)| match s {
            Sock::Listener { port: p, listening: None, ready, backlog } if *p == port && ready.len() < *backlog => Some(id),
            _ => None,
        }) else {
            return;
        };
        if let Ok(h) = self.new_listening(port) {
            if let Some(Sock::Listener { listening, .. }) = self.socks.get_mut(&id) {
                *listening = Some(h);
            }
        }
    }

    /// Moves connected listener sockets to the accept queue, and frees
    /// listening sockets no connection attempt is pending for.
    fn service_listeners(&mut self) {
        let mut dead = Vec::new();
        let idle_ok = self.dev.inbound.is_empty();
        for s in self.socks.values_mut() {
            if let Sock::Listener { listening, ready, backlog, .. } = s {
                // Connections reset before being accepted: readiness must
                // only report live ones.
                ready.retain(|&h| {
                    let alive = self.sockets.get::<tcp::Socket>(h).remote_endpoint().is_some();
                    if !alive {
                        dead.push(h);
                    }
                    alive
                });
                let Some(h) = *listening else { continue };
                match self.sockets.get::<tcp::Socket>(h).state() {
                    tcp::State::SynReceived => {}
                    // Nothing pending (or the attempt was reset).
                    tcp::State::Listen => {
                        if idle_ok {
                            dead.push(h);
                            *listening = None;
                        }
                    }
                    _ if ready.len() < *backlog => {
                        ready.push_back(h);
                        *listening = None;
                    }
                    _ => {}
                }
            }
        }
        for h in dead {
            self.remove_tcp(h);
        }
    }

    fn reap_closing(&mut self) {
        let sockets = &mut self.sockets;
        let mut freed = 0;
        self.closing.retain(|&h| {
            // TIME_WAIT only guards against stray old segments; not worth
            // holding a socket's buffers for.
            let done = matches!(sockets.get::<tcp::Socket>(h).state(), tcp::State::Closed | tcp::State::TimeWait);
            if done {
                freed += tcp_buffers(sockets.get::<tcp::Socket>(h));
                sockets.remove(h);
            }
            !done
        });
        self.used -= freed;
    }
}

/// Overlay budget bytes a TCP socket's buffers take.
fn tcp_buffers(sock: &tcp::Socket) -> usize {
    sock.recv_capacity() + sock.send_capacity()
}

/// IPv4/IPv6 + UDP framing for the overlay's own UDP sockets.
mod udp {
    use alloc::vec::Vec;
    use core::net::{IpAddr, SocketAddr};
    use core::ops::Range;

    const PROTO_UDP: u8 = 17;

    pub struct Datagram {
        pub src: SocketAddr,
        pub dst: SocketAddr,
        /// Payload bytes within the packet.
        pub payload: Range<usize>,
    }

    /// Parses an unfragmented UDP packet (no IPv6 extension headers).
    pub fn parse(p: &[u8]) -> Option<Datagram> {
        let (src, dst, off) = match p.first()? >> 4 {
            4 => {
                let ihl = usize::from(p[0] & 0x0f) * 4;
                let total = usize::from(u16::from_be_bytes([*p.get(2)?, *p.get(3)?]));
                let frag = u16::from_be_bytes([*p.get(6)?, *p.get(7)?]);
                // More-fragments set, or a non-zero offset: not ours to take.
                if ihl < 20 || total > p.len() || *p.get(9)? != PROTO_UDP || frag & 0x3fff != 0 {
                    return None;
                }
                let src: [u8; 4] = p[12..16].try_into().ok()?;
                let dst: [u8; 4] = p[16..20].try_into().ok()?;
                (IpAddr::from(src), IpAddr::from(dst), ihl)
            }
            6 => {
                if p.len() < 40 || p[6] != PROTO_UDP {
                    return None;
                }
                let src: [u8; 16] = p[8..24].try_into().ok()?;
                let dst: [u8; 16] = p[24..40].try_into().ok()?;
                (IpAddr::from(src), IpAddr::from(dst), 40)
            }
            _ => return None,
        };
        let h = p.get(off..off + 8)?;
        let len = usize::from(u16::from_be_bytes([h[4], h[5]]));
        if len < 8 || off + len > p.len() {
            return None;
        }
        Some(Datagram {
            src: SocketAddr::new(src, u16::from_be_bytes([h[0], h[1]])),
            dst: SocketAddr::new(dst, u16::from_be_bytes([h[2], h[3]])),
            payload: off + 8..off + len,
        })
    }

    /// Builds an IP packet carrying one datagram (None if it exceeds `mtu`).
    pub fn build(src: SocketAddr, dst: SocketAddr, data: &[u8], mtu: usize) -> Option<Vec<u8>> {
        let ip_len = if src.is_ipv4() { 20 } else { 40 };
        let udp_len = 8 + data.len();
        if ip_len + udp_len > mtu || src.is_ipv4() != dst.is_ipv4() {
            return None;
        }
        let mut p = Vec::with_capacity(ip_len + udp_len);
        match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let total = (ip_len + udp_len) as u16;
                p.extend_from_slice(&[0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, PROTO_UDP, 0, 0]);
                p[2..4].copy_from_slice(&total.to_be_bytes());
                p.extend_from_slice(&s.octets());
                p.extend_from_slice(&d.octets());
                let sum = !fold(sum_bytes(0, &p[..20]));
                p[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                p.extend_from_slice(&[0x60, 0, 0, 0]);
                p.extend_from_slice(&(udp_len as u16).to_be_bytes());
                p.extend_from_slice(&[PROTO_UDP, 64]);
                p.extend_from_slice(&s.octets());
                p.extend_from_slice(&d.octets());
            }
            _ => return None,
        }
        p.extend_from_slice(&src.port().to_be_bytes());
        p.extend_from_slice(&dst.port().to_be_bytes());
        p.extend_from_slice(&(udp_len as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(data);
        // Checksum over the pseudo-header, header and payload.
        let mut acc = match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => sum_bytes(sum_bytes(0, &s.octets()), &d.octets()),
            (IpAddr::V6(s), IpAddr::V6(d)) => sum_bytes(sum_bytes(0, &s.octets()), &d.octets()),
            _ => return None,
        };
        acc += u32::from(PROTO_UDP) + udp_len as u32;
        acc = sum_bytes(acc, &p[ip_len..]);
        let sum = match !fold(acc) {
            0 => 0xffff,  // 0 means "no checksum" in UDP
            s => s,
        };
        p[ip_len + 6..ip_len + 8].copy_from_slice(&sum.to_be_bytes());
        Some(p)
    }

    fn sum_bytes(mut acc: u32, b: &[u8]) -> u32 {
        let mut chunks = b.chunks_exact(2);
        for c in &mut chunks {
            acc += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [last] = chunks.remainder() {
            acc += u32::from(*last) << 8;
        }
        acc
    }

    fn fold(mut acc: u32) -> u16 {
        while acc > 0xffff {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        acc as u16
    }
}

/// IPv4 fragment reassembly.
///
/// The UDP fast path ([`udp::parse`]) and smoltcp both need a whole datagram.
/// A sender whose path to us crosses a smaller MTU than its own (Sunshine
/// sends video packets larger than fit, for one) fragments the
/// inner IP packet; without reassembly every fragment is dropped and, e.g.,
/// Moonlight never receives video. We rebuild the original packet here before
/// delivery. Bounded in entries, bytes and age so a lost tail or a flood can't
/// grow the fixed heap. IPv6 has no in-header fragmentation, so this is v4
/// only; the engine's underlay is v4 regardless.
mod reasm {
    use alloc::vec::Vec;
    use core::time::Duration;

    use crate::time::Instant;

    /// Datagrams reassembled at once; past this the oldest is evicted. Sized
    /// to absorb a sender's startup/keyframe burst, where many fragmented
    /// packets are in flight at once (a too-small table evicts them
    /// incomplete, and a stream's opening keyframe arrives broken).
    const MAX_ENTRIES: usize = 128;
    /// Payload bytes buffered across all entries before the oldest is dropped.
    const BUDGET: usize = 192 << 10;
    /// An incomplete datagram is discarded this long after its first fragment.
    const TIMEOUT: Duration = Duration::from_secs(5);
    /// An IPv4 packet (header + payload) can be no larger than this.
    const IP_MAX: usize = u16::MAX as usize;

    #[derive(PartialEq, Eq, Clone, Copy)]
    struct Key {
        src: [u8; 4],
        dst: [u8; 4],
        id: u16,
        proto: u8,
    }

    struct Entry {
        key: Key,
        /// IP header (IHL bytes) from the offset-0 fragment; empty until seen.
        header: Vec<u8>,
        /// Payload, each fragment written at its offset.
        data: Vec<u8>,
        /// Covered payload byte ranges, kept merged and sorted.
        have: Vec<(usize, usize)>,
        /// Payload length, known once the last fragment (MF=0) is in.
        total: Option<usize>,
        /// Monotonic time this datagram is abandoned at.
        deadline: Instant,
    }

    impl Entry {
        fn bytes(&self) -> usize {
            self.header.len() + self.data.len()
        }
        /// The payload length if every byte [0, total) has arrived with a
        /// header, else `None`.
        fn complete(&self) -> Option<usize> {
            let total = self.total?;
            (!self.header.is_empty() && self.have.as_slice() == [(0, total)]).then_some(total)
        }
    }

    pub struct Reassembler {
        entries: Vec<Entry>,
    }

    /// True if `p` is an IPv4 fragment (more-fragments set, or a non-zero
    /// offset): the only packets [`Reassembler::accept`] should be given.
    pub fn is_fragment(p: &[u8]) -> bool {
        p.len() >= 20 && p[0] >> 4 == 4 && u16::from_be_bytes([p[6], p[7]]) & 0x3fff != 0
    }

    impl Reassembler {
        pub fn new() -> Self {
            Self { entries: Vec::new() }
        }

        fn used(&self) -> usize {
            self.entries.iter().map(Entry::bytes).sum()
        }

        /// Drops datagrams whose deadline has passed.
        fn expire(&mut self, now: Instant) {
            self.entries.retain(|e| e.deadline.as_nanos() > now.as_nanos());
        }

        /// Takes one IPv4 fragment (as classified by [`is_fragment`]). Returns
        /// the rebuilt packet once the last hole is filled, else `None`.
        pub fn accept(&mut self, p: Vec<u8>, now: Instant) -> Option<Vec<u8>> {
            self.expire(now);

            let ihl = usize::from(p[0] & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([p[2], p[3]]));
            let frag = u16::from_be_bytes([p[6], p[7]]);
            let more = frag & 0x2000 != 0;
            let offset = usize::from(frag & 0x1fff) * 8;
            // Trust the IP total-length field, but never read past the buffer.
            if ihl < 20 || total_len < ihl || total_len > p.len() {
                return None;
            }
            let payload_len = total_len - ihl;
            let end = offset + payload_len;
            // A non-final fragment with no payload, or one that would overflow
            // an IP packet, is bogus.
            if (more && payload_len == 0) || end + ihl > IP_MAX {
                return None;
            }
            let key = Key {
                src: p[12..16].try_into().unwrap(),
                dst: p[16..20].try_into().unwrap(),
                id: u16::from_be_bytes([p[4], p[5]]),
                proto: p[9],
            };

            let idx = match self.entries.iter().position(|e| e.key == key) {
                Some(i) => i,
                None => {
                    if self.entries.len() >= MAX_ENTRIES {
                        self.evict_oldest(key);
                    }
                    self.entries.push(Entry {
                        key,
                        header: Vec::new(),
                        data: Vec::new(),
                        have: Vec::new(),
                        total: None,
                        deadline: now + TIMEOUT,
                    });
                    self.entries.len() - 1
                }
            };

            {
                let e = &mut self.entries[idx];
                if offset == 0 && e.header.is_empty() {
                    e.header = p[..ihl].to_vec();
                }
                if !more {
                    e.total = Some(end);
                }
                let grow = end.saturating_sub(e.data.len());
                if grow > 0 && e.data.try_reserve(grow).is_err() {
                    // Out of memory: abandon this datagram, don't abort.
                    self.entries.swap_remove(idx);
                    return None;
                }
                if e.data.len() < end {
                    e.data.resize(end, 0);
                }
                e.data[offset..end].copy_from_slice(&p[ihl..total_len]);
                insert_range(&mut e.have, offset, end);
            }

            if let Some(total) = self.entries[idx].complete() {
                let e = &mut self.entries[idx];
                let mut out = core::mem::take(&mut e.header);
                out.extend_from_slice(&e.data[..total]);
                self.entries.swap_remove(idx);
                let pkt = rebuild(out, total);
                // A mis-reassembled datagram (fragments aliased under a burst)
                // would fail its UDP checksum; drop it rather than feed the app
                // garbage, leaving the sender's FEC/retransmit to recover it.
                if udp_cksum_bad(&pkt) {
                    return None;
                }
                return Some(pkt);
            }

            // Hold the byte budget by dropping the oldest *other* datagrams.
            while self.used() > BUDGET {
                if !self.evict_oldest(key) {
                    break;
                }
            }
            None
        }

        /// Removes the entry nearest its deadline whose key is not `keep`.
        /// Returns false if none qualifies.
        fn evict_oldest(&mut self, keep: Key) -> bool {
            let Some(victim) = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.key != keep)
                .min_by_key(|(_, e)| e.deadline.as_nanos())
                .map(|(i, _)| i)
            else {
                return false;
            };
            self.entries.swap_remove(victim);
            true
        }
    }

    /// True if `pkt` is a UDP/IPv4 packet carrying a non-zero UDP checksum
    /// that fails to verify. A zero checksum (verification disabled by the
    /// sender) is accepted.
    fn udp_cksum_bad(pkt: &[u8]) -> bool {
        const PROTO_UDP: u8 = 17;
        if pkt.len() < 20 || pkt[0] >> 4 != 4 || pkt[9] != PROTO_UDP {
            return false;
        }
        let ihl = usize::from(pkt[0] & 0x0f) * 4;
        if pkt.len() < ihl + 8 {
            return false;
        }
        let udp = &pkt[ihl..];
        if u16::from_be_bytes([udp[6], udp[7]]) == 0 {
            return false; // checksum not in use
        }
        let mut acc = 0u32;
        for c in pkt[12..20].chunks(2) {
            acc += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        acc += u32::from(PROTO_UDP) + udp.len() as u32; // pseudo-header
        let mut chunks = udp.chunks_exact(2);
        for c in &mut chunks {
            acc += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [last] = chunks.remainder() {
            acc += u32::from(*last) << 8;
        }
        while acc > 0xffff {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        (acc as u16) != 0xffff
    }

    /// Rebuilds a whole IPv4 packet from its reassembled header+payload:
    /// `pkt` is the IHL-byte header followed by `payload_total` payload bytes.
    /// Fixes total length, clears the fragment fields and recomputes the
    /// header checksum.
    fn rebuild(mut pkt: Vec<u8>, payload_total: usize) -> Vec<u8> {
        let ihl = pkt.len() - payload_total;
        let total = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        pkt[6] = 0;
        pkt[7] = 0;
        pkt[10] = 0;
        pkt[11] = 0;
        let sum = header_checksum(&pkt[..ihl]);
        pkt[10..12].copy_from_slice(&sum.to_be_bytes());
        pkt
    }

    fn header_checksum(h: &[u8]) -> u16 {
        let mut acc = 0u32;
        let mut chunks = h.chunks_exact(2);
        for c in &mut chunks {
            acc += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [last] = chunks.remainder() {
            acc += u32::from(*last) << 8;
        }
        while acc > 0xffff {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        !(acc as u16)
    }

    /// Inserts `[start, end)` into a sorted, merged range set.
    fn insert_range(ranges: &mut Vec<(usize, usize)>, start: usize, end: usize) {
        if start >= end {
            return;
        }
        ranges.push((start, end));
        ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
        for &(s, e) in ranges.iter() {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        *ranges = merged;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    /// A burst loss early in a bulk transfer (DERP drops when a client's send
    /// queue overflows) must be recovered by retransmission.
    #[test]
    fn tcp_recovers_from_burst_loss() {
        let a_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
        let b_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));
        let mut now = Instant::from_millis(0);
        let mut a = Netstack::new(now, DEFAULT_MTU);
        let mut b = Netstack::new(now, DEFAULT_MTU);
        a.set_addresses(&[a_ip]);
        b.set_addresses(&[b_ip]);
        let listener = b.tcp_listen(5201, 4).unwrap();
        let client = a.tcp_connect(SocketAddr::new(b_ip, 5201)).unwrap();
        let total = 300_000usize;
        let (mut sent, mut got, mut server) = (0usize, 0usize, None);
        let mut a_to_b = 0usize;
        for _ in 0..20_000 {
            now = now + core::time::Duration::from_millis(1);
            if a.readiness(client).writable && sent < total {
                let chunk = alloc::vec![0x5au8; (total - sent).min(65536)];
                if let Ok(n) = a.send(client, &chunk) {
                    sent += n;
                }
            }
            a.poll(now);
            let out: Vec<_> = a.take_outbound().collect();
            for p in out {
                a_to_b += 1;
                // Drop data packets 4..=22 of the connection (a burst).
                if (4..=22).contains(&a_to_b) {
                    continue;
                }
                b.inject(p);
            }
            b.poll(now);
            if server.is_none() {
                server = b.tcp_accept(listener).ok().map(|(s, _)| s);
            }
            if let Some(s) = server {
                let mut buf = [0u8; 65536];
                while let Ok(n) = b.recv(s, &mut buf) {
                    if n == 0 {
                        break;
                    }
                    got += n;
                }
            }
            b.poll(now);
            let back: Vec<_> = b.take_outbound().collect();
            back.into_iter().for_each(|p| a.inject(p));
            if got == total {
                break;
            }
        }
        assert_eq!(got, total, "transfer stalled after burst loss (sent {sent})");
    }

    /// The stack answers pings to its own addresses.
    #[test]
    fn answers_icmp_echo() {
        let mut net = Netstack::new(Instant::from_millis(0), DEFAULT_MTU);
        net.set_addresses(&[IpAddr::V4(Ipv4Addr::new(100, 64, 0, 4))]);
        // 100.64.0.1 -> 100.64.0.4 ICMP echo request, id 1 seq 1, no payload.
        let mut pkt = alloc::vec![
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 100, 64, 0, 1, 100, 64, 0, 4, //
            8, 0, 0, 0, 0, 1, 0, 1,
        ];
        let csum = |b: &[u8]| {
            let mut s: u32 = b.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32).sum();
            while s > 0xffff {
                s = (s & 0xffff) + (s >> 16);
            }
            !(s as u16)
        };
        let ip = csum(&pkt[..20]).to_be_bytes();
        pkt[10..12].copy_from_slice(&ip);
        let icmp = csum(&pkt[20..]).to_be_bytes();
        pkt[22..24].copy_from_slice(&icmp);
        net.inject(pkt);
        net.poll(Instant::from_millis(1));
        let out: Vec<_> = net.take_outbound().collect();
        assert_eq!(out.len(), 1, "expected an echo reply");
        assert_eq!(out[0][20], 0, "ICMP type 0 = echo reply");
        assert_eq!(&out[0][16..20], &[100, 64, 0, 1]);
    }

    /// While nothing drains the outbound queue (the engine is paused), an
    /// app's datagrams are dropped past OUT_PKTS instead of exhausting the
    /// heap, and TCP waits in its send buffer.
    #[test]
    fn outbound_queue_is_bounded() {
        let a_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)), 47998);
        let mut net = Netstack::new(Instant::from_millis(0), DEFAULT_MTU);
        net.set_addresses(&[a_ip]);
        let udp = net.udp_bind(0).unwrap();
        for _ in 0..10 * OUT_PKTS {
            net.udp_send_to(udp, &[0u8; 1000], b).unwrap();
        }
        let tcp = net.tcp_connect(SocketAddr::new(b.ip(), 48010)).unwrap();
        net.poll(Instant::from_millis(1));
        assert_eq!(net.take_outbound().count(), OUT_PKTS);
        let _ = tcp;
        // Drained: the TCP SYN that waited goes out on the next poll.
        net.poll(Instant::from_millis(2));
        assert_eq!(net.take_outbound().count(), 1);
    }

    /// Two stacks wired back to back exchange a TCP stream and a datagram.
    #[test]
    fn tcp_and_udp_between_two_stacks() {
        let a_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
        let b_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));
        let mut now = Instant::from_millis(0);
        let mut a = Netstack::new(now, DEFAULT_MTU);
        let mut b = Netstack::new(now, DEFAULT_MTU);
        a.set_addresses(&[a_ip]);
        b.set_addresses(&[b_ip]);

        let listener = b.tcp_listen(7, 4).unwrap();
        let client = a.tcp_connect(SocketAddr::new(b_ip, 7)).unwrap();
        let ua = a.udp_bind(5000).unwrap();
        let ub = b.udp_bind(6000).unwrap();
        a.udp_send_to(ua, b"datagram", SocketAddr::new(b_ip, 6000)).unwrap();

        let mut server = None;
        let mut sent = false;
        let mut got = Vec::new();
        let mut dgram = None;
        for _ in 0..200 {
            now = now + core::time::Duration::from_millis(10);
            a.poll(now);
            let to_b: Vec<_> = a.take_outbound().collect();
            to_b.into_iter().for_each(|p| b.inject(p));
            b.poll(now);
            let to_a: Vec<_> = b.take_outbound().collect();
            to_a.into_iter().for_each(|p| a.inject(p));
            a.poll(now);

            if server.is_none() {
                if let Ok((s, peer)) = b.tcp_accept(listener) {
                    assert_eq!(peer.ip(), a_ip);
                    server = Some(s);
                }
            }
            if !sent && a.readiness(client).writable {
                assert_eq!(a.send(client, b"hello over smoltcp").unwrap(), 18);
                sent = true;
            }
            if let Some(s) = server {
                let mut buf = [0u8; 64];
                if let Ok(n) = b.recv(s, &mut buf) {
                    got.extend_from_slice(&buf[..n]);
                }
            }
            let mut buf = [0u8; 64];
            if let Ok((n, from)) = b.udp_recv_from(ub, &mut buf) {
                dgram = Some((buf[..n].to_vec(), from));
            }
        }
        assert_eq!(got, b"hello over smoltcp");
        assert_eq!(dgram, Some((b"datagram".to_vec(), SocketAddr::new(a_ip, 5000))));
    }

    #[test]
    fn udp_checksums_are_valid() {
        use smoltcp::wire::{IpAddress, Ipv4Packet, UdpPacket};
        let v4 = udp::build("100.64.0.1:5000".parse().unwrap(), "100.64.0.2:53".parse().unwrap(), b"hello", DEFAULT_MTU).unwrap();
        let ip = Ipv4Packet::new_checked(&v4[..]).unwrap();
        assert!(ip.verify_checksum());
        let u = UdpPacket::new_checked(ip.payload()).unwrap();
        assert!(u.verify_checksum(&IpAddress::Ipv4(ip.src_addr()), &IpAddress::Ipv4(ip.dst_addr())));
        assert_eq!(u.payload(), b"hello");

        let d = udp::parse(&v4).unwrap();
        assert_eq!(d.dst, "100.64.0.2:53".parse().unwrap());
        assert_eq!(&v4[d.payload], b"hello");
        assert!(udp::build("100.64.0.1:1".parse().unwrap(), "100.64.0.2:1".parse().unwrap(), &[0; DEFAULT_MTU], DEFAULT_MTU).is_none());
    }

    #[test]
    fn buffers_are_accounted_and_released() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        let mut n = Netstack::new(Instant::from_nanos(0), DEFAULT_MTU);
        n.set_addresses(&[ip]);
        let t = n.tcp_connect("100.64.0.2:80".parse().unwrap()).unwrap();
        assert_eq!(n.buffer_usage(), TCP_RX + TCP_TX);
        let u = n.udp_bind(9).unwrap();
        let pkt = udp::build("100.64.0.2:1234".parse().unwrap(), SocketAddr::new(ip, 9), b"ping", DEFAULT_MTU).unwrap();
        n.inject(pkt);
        assert!(n.readiness(u).readable);
        assert!(n.buffer_usage() > TCP_RX + TCP_TX);
        let mut buf = [0u8; 16];
        assert_eq!(n.udp_recv_from(u, &mut buf).unwrap(), (4, "100.64.0.2:1234".parse().unwrap()));
        assert_eq!(n.buffer_usage(), TCP_RX + TCP_TX);
        n.close(u);
        n.close(t);
        // An unanswered SYN: abort-close frees the buffers once reaped.
        for i in 0..200 {
            n.poll(Instant::from_nanos(i * 1_000_000_000));
        }
        let l = n.tcp_listen(80, 1).unwrap();
        n.close(l);
        assert_eq!(n.buffer_usage(), 0, "everything released");
    }

    /// Runs two stacks back to back for `ms` milliseconds.
    fn exchange(a: &mut Netstack, b: &mut Netstack, now: &mut Instant, ms: u64) {
        for _ in 0..ms / 10 {
            *now = *now + core::time::Duration::from_millis(10);
            a.poll(*now);
            let to_b: Vec<_> = a.take_outbound().collect();
            to_b.into_iter().for_each(|p| b.inject(p));
            b.poll(*now);
            let to_a: Vec<_> = b.take_outbound().collect();
            to_a.into_iter().for_each(|p| a.inject(p));
        }
    }

    /// A gracefully closed connection frees its buffers once the FIN
    /// exchange is done, without sitting out TIME_WAIT.
    #[test]
    fn closed_connection_frees_buffers_promptly() {
        let (a_ip, b_ip) = (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)));
        let mut now = Instant::from_millis(0);
        let (mut a, mut b) = (Netstack::new(now, DEFAULT_MTU), Netstack::new(now, DEFAULT_MTU));
        a.set_addresses(&[a_ip]);
        b.set_addresses(&[b_ip]);
        let listener = b.tcp_listen(7, 4).unwrap();
        let client = a.tcp_connect(SocketAddr::new(b_ip, 7)).unwrap();
        exchange(&mut a, &mut b, &mut now, 200);
        let (server, _) = b.tcp_accept(listener).unwrap();
        a.close(client);
        exchange(&mut a, &mut b, &mut now, 200);
        b.close(server);
        exchange(&mut a, &mut b, &mut now, 500);
        assert_eq!(a.buffer_usage(), 0, "client side released before TIME_WAIT ends");
    }

    /// With the budget used up by closing sockets, a new connection still
    /// gets buffers (the Switch's limits; `--features switch-limits`).
    #[cfg(any(target_os = "horizon", feature = "switch-limits"))]
    #[test]
    fn closing_sockets_give_way_to_new_ones() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        let mut n = Netstack::new(Instant::from_nanos(0), DEFAULT_MTU);
        n.set_addresses(&[ip]);
        let peer = |port| SocketAddr::new("100.64.0.2".parse().unwrap(), port);
        // Unanswered connects hold their buffers until the budget runs out.
        let mut open = Vec::new();
        while let Ok(s) = n.tcp_connect(peer(80 + open.len() as u16)) {
            open.push(s);
        }
        assert_eq!(open.len(), 17, "connections that fit in the Switch's budget");
        for &s in &open[..2] {
            n.close(s);
        }
        n.tcp_connect(peer(2)).expect("a closing socket gave way");
        while n.tcp_connect(peer(3)).is_ok() {}
        for &s in &open[2..] {
            assert!(n.peer_addr(s).is_some(), "open ones are never evicted");
        }
        assert!(n.buffer_usage() <= BUDGET);
    }

    #[test]
    fn idle_listeners_hold_no_buffers() {
        let (a_ip, b_ip): (IpAddr, IpAddr) = ("100.64.0.1".parse().unwrap(), "100.64.0.2".parse().unwrap());
        let mut now = Instant::from_millis(0);
        let (mut a, mut b) = (Netstack::new(now, DEFAULT_MTU), Netstack::new(now, DEFAULT_MTU));
        a.set_addresses(&[a_ip]);
        b.set_addresses(&[b_ip]);
        let listener = b.tcp_listen(80, 4).unwrap();
        b.poll(now);
        assert_eq!(b.buffer_usage(), 0, "listening alone costs nothing");
        for round in 0..3 {
            let client = a.tcp_connect(SocketAddr::new(b_ip, 80)).unwrap();
            exchange(&mut a, &mut b, &mut now, 200);
            let (server, _) = b.tcp_accept(listener).unwrap_or_else(|_| panic!("round {round}: accepted"));
            assert_eq!(a.send(client, b"hi").unwrap(), 2);
            exchange(&mut a, &mut b, &mut now, 200);
            let mut buf = [0u8; 8];
            assert_eq!(b.recv(server, &mut buf).unwrap(), 2);
            b.close(server);
            a.close(client);
            exchange(&mut a, &mut b, &mut now, 200);
            assert_eq!(b.buffer_usage(), 0, "round {round}: back to nothing once closed");
        }
        // No listener on the port: refused, nothing allocated.
        let refused = a.tcp_connect(SocketAddr::new(b_ip, 81)).unwrap();
        exchange(&mut a, &mut b, &mut now, 200);
        assert!(a.readiness(refused).hup);
        assert_eq!(b.buffer_usage(), 0);
    }

    #[test]
    fn tcp_buffers_shrink_as_the_budget_fills() {
        let k = 1024;
        assert_eq!(tcp_buffer_size(320 * k, 32 * k), 32 * k);
        assert_eq!(tcp_buffer_size(256 * k, 32 * k), 16 * k);
        assert_eq!(tcp_buffer_size(100 * k, 32 * k), 8 * k);
        assert_eq!(tcp_buffer_size(50 * k, 32 * k), 4 * k);
        assert_eq!(tcp_buffer_size(9 * k, 32 * k), 4 * k);
        assert_eq!(tcp_buffer_size(usize::MAX, 64 * k), 64 * k);
    }

    #[test]
    fn full_udp_queue_keeps_the_newest() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        let mut n = Netstack::new(Instant::from_nanos(0), DEFAULT_MTU);
        n.set_addresses(&[ip]);
        let u = n.udp_bind(9).unwrap();
        let mut sent = 0u32;
        // Far more than fits: the queue holds only the most recent ones.
        while sent < 2000 {
            let payload = sent.to_be_bytes();
            n.inject(udp::build("100.64.0.2:1".parse().unwrap(), SocketAddr::new(ip, 9), &payload, DEFAULT_MTU).unwrap());
            sent += 1;
        }
        assert!(n.buffer_usage() <= UDP_RX);
        let mut buf = [0u8; 4];
        let mut last = None;
        let mut received = 0u32;
        while let Ok((4, _)) = n.udp_recv_from(u, &mut buf) {
            last = Some(u32::from_be_bytes(buf));
            received += 1;
        }
        assert_eq!(last, Some(1999), "the newest datagram survives");
        assert_eq!(n.udp_dropped(), sent - received, "every datagram is delivered or counted as dropped");
        assert_eq!(n.buffer_usage(), 0);
    }

    /// Splits a complete IPv4/UDP packet into `chunk`-sized IP fragments
    /// (each but the last a multiple of 8 payload bytes).
    fn fragment(full: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        let ihl = 20usize;
        let body = &full[ihl..];
        let mut out = Vec::new();
        let mut off = 0;
        while off < body.len() {
            let len = chunk.min(body.len() - off);
            let more = off + len < body.len();
            let mut f = full[..ihl].to_vec();
            f[2..4].copy_from_slice(&((ihl + len) as u16).to_be_bytes());
            let frag = ((off / 8) as u16) | if more { 0x2000 } else { 0 };
            f[6..8].copy_from_slice(&frag.to_be_bytes());
            f.extend_from_slice(&body[off..off + len]);
            out.push(f);
            off += len;
        }
        out
    }

    fn recv_one(net: &mut Netstack, sock: SockId) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buf = [0u8; 8192];
        net.udp_recv_from(sock, &mut buf).ok().map(|(n, from)| (buf[..n].to_vec(), from))
    }

    /// A datagram larger than the tunnel MTU arrives in fragments and is
    /// reassembled and delivered whole (the Moonlight video case).
    #[test]
    fn reassembles_fragmented_udp() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), 48000);
        let dst_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));
        let mut net = Netstack::new(Instant::from_millis(0), DEFAULT_MTU);
        net.set_addresses(&[dst_ip]);
        let sock = net.udp_bind(47998).unwrap();
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        // Build past the MTU cap (usize::MAX): a real sender just fragments it.
        let full = udp::build(src, SocketAddr::new(dst_ip, 47998), &payload, usize::MAX).unwrap();
        let frags = fragment(&full, 1400);
        assert_eq!(frags.len(), 3, "3000 bytes over 1400 = three fragments");
        for f in &frags {
            assert!(super::reasm::is_fragment(f));
            net.inject(f.clone());
        }
        let (got, from) = recv_one(&mut net, sock).expect("datagram delivered");
        assert_eq!(got, payload);
        assert_eq!(from, src);
    }

    /// Fragments reassemble regardless of arrival order.
    #[test]
    fn reassembles_out_of_order() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), 48000);
        let dst_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));
        let mut net = Netstack::new(Instant::from_millis(0), DEFAULT_MTU);
        net.set_addresses(&[dst_ip]);
        let sock = net.udp_bind(47998).unwrap();
        let payload: Vec<u8> = (0..2600u32).map(|i| (i * 7) as u8).collect();
        let full = udp::build(src, SocketAddr::new(dst_ip, 47998), &payload, usize::MAX).unwrap();
        let mut frags = fragment(&full, 1024);
        frags.reverse();
        for f in frags {
            net.inject(f);
        }
        assert_eq!(recv_one(&mut net, sock).unwrap().0, payload);
    }

    /// A missing fragment never delivers a partial datagram, and a stale
    /// partial is aged out without blocking a later, whole one.
    #[test]
    fn incomplete_is_not_delivered() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), 48000);
        let dst_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));
        let mut net = Netstack::new(Instant::from_millis(0), DEFAULT_MTU);
        net.set_addresses(&[dst_ip]);
        let sock = net.udp_bind(47998).unwrap();
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let full = udp::build(src, SocketAddr::new(dst_ip, 47998), &payload, usize::MAX).unwrap();
        let frags = fragment(&full, 1400);
        // Drop the middle fragment.
        net.inject(frags[0].clone());
        net.inject(frags[2].clone());
        assert!(recv_one(&mut net, sock).is_none(), "no partial delivery");
        // Age the partial out, then send a fresh whole datagram.
        net.poll(Instant::from_millis(10_000));
        for f in fragment(&full, 1400) {
            net.inject(f);
        }
        assert_eq!(recv_one(&mut net, sock).unwrap().0, payload);
    }

    /// Many distinct datagrams, their fragments fully interleaved (all first
    /// fragments, then all second), still all reassemble — the table absorbs
    /// a burst instead of evicting them incomplete.
    #[test]
    fn reassembles_interleaved_burst() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), 48000);
        let dst_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));
        let mut net = Netstack::new(Instant::from_millis(0), DEFAULT_MTU);
        net.set_addresses(&[dst_ip]);
        let sock = net.udp_bind(47998).unwrap();
        let n: u16 = 50;
        let (mut firsts, mut seconds) = (Vec::new(), Vec::new());
        for i in 0..n {
            let payload: Vec<u8> = (0..2000u32).map(|x| (x + u32::from(i) * 7) as u8).collect();
            let mut full = udp::build(src, SocketAddr::new(dst_ip, 47998), &payload, usize::MAX).unwrap();
            full[4..6].copy_from_slice(&(i + 1).to_be_bytes()); // a distinct IP id
            let frags = fragment(&full, 1400);
            assert_eq!(frags.len(), 2);
            firsts.push(frags[0].clone());
            seconds.push(frags[1].clone());
        }
        // Hold every first fragment at once (stresses the table to 50 live
        // entries), then complete and drain one at a time so the socket's own
        // receive queue never overflows (that cap is tested elsewhere).
        for f in firsts {
            net.inject(f);
        }
        let mut got = 0;
        for f in seconds {
            net.inject(f);
            if recv_one(&mut net, sock).is_some() {
                got += 1;
            }
        }
        assert_eq!(got, usize::from(n), "every interleaved datagram reassembled");
    }

    /// A datagram whose fragments carry corrupt bytes (a bad UDP checksum)
    /// is dropped, never handed to the app.
    #[test]
    fn corrupt_reassembly_is_dropped() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), 48000);
        let dst_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));
        let mut net = Netstack::new(Instant::from_millis(0), DEFAULT_MTU);
        net.set_addresses(&[dst_ip]);
        let sock = net.udp_bind(47998).unwrap();
        let payload: Vec<u8> = (0..2000u32).map(|i| i as u8).collect();
        let full = udp::build(src, SocketAddr::new(dst_ip, 47998), &payload, usize::MAX).unwrap();
        let mut frags = fragment(&full, 1400);
        frags[0][40] ^= 0xff; // flip a payload byte -> UDP checksum now wrong
        for f in frags {
            net.inject(f);
        }
        assert!(recv_one(&mut net, sock).is_none(), "corrupt datagram must be dropped");
    }

    /// A whole (unfragmented) datagram is untouched by the reassembly path.
    #[test]
    fn whole_datagram_passes_through() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), 48000);
        let dst_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));
        let mut net = Netstack::new(Instant::from_millis(0), DEFAULT_MTU);
        net.set_addresses(&[dst_ip]);
        let sock = net.udp_bind(47998).unwrap();
        let pkt = udp::build(src, SocketAddr::new(dst_ip, 47998), b"hello", DEFAULT_MTU).unwrap();
        assert!(!super::reasm::is_fragment(&pkt));
        net.inject(pkt);
        assert_eq!(recv_one(&mut net, sock).unwrap().0, b"hello");
    }

    /// With the link below splitting anything over 1394 bytes in two, TCP is
    /// told to stay under it while UDP may still send up to the network's MTU.
    #[test]
    fn tcp_and_udp_have_separate_size_limits() {
        let me = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 2));
        let peer = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 7));
        let mut net = Netstack::new(Instant::from_millis(0), DEFAULT_MTU);
        net.set_addresses(&[me]);
        net.set_mtus(1394, 2800);

        net.tcp_connect(SocketAddr::new(peer, 80)).unwrap();
        net.poll(Instant::from_millis(1));
        let syn = net.pop_outbound().expect("a SYN");
        assert_eq!(syn[9], 6);
        // The first option of the SYN is the MSS: kind 2, length 4.
        assert_eq!(&syn[40..42], &[2, 4]);
        assert_eq!(u16::from_be_bytes([syn[42], syn[43]]), 1394 - 40);
        assert_eq!(net.outbound_len(), 0);

        let udp = net.udp_bind(4000).unwrap();
        let dst = SocketAddr::new(peer, 4001);
        assert_eq!(net.udp_send_to(udp, &alloc::vec![7u8; 2800 - 28], dst), Ok(()));
        assert_eq!(net.udp_send_to(udp, &alloc::vec![7u8; 2800 - 27], dst), Err(NetError::Invalid));
        assert_eq!(net.pop_outbound().map(|p| p.len()), Some(2800));
        assert_eq!(net.pop_outbound(), None);

        // A datagram that large coming in is delivered whole.
        let big = udp::build(dst, SocketAddr::new(me, 4000), &alloc::vec![9u8; 2800 - 28], 2800).unwrap();
        net.inject(big);
        let mut buf = [0u8; 4096];
        assert_eq!(net.udp_recv_from(udp, &mut buf), Ok((2800 - 28, dst)));
    }

    /// The outbound queue is bounded in bytes as well as packets: large
    /// datagrams reach the byte limit long before the packet limit.
    #[test]
    fn outbound_queue_is_bounded_in_bytes() {
        let me = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 2));
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 7)), 4001);
        let mut net = Netstack::new(Instant::from_millis(0), DEFAULT_MTU);
        net.set_addresses(&[me]);
        net.set_mtus(1394, 2800);
        let udp = net.udp_bind(4000).unwrap();
        for _ in 0..2 * OUT_PKTS {
            assert_eq!(net.udp_send_to(udp, &alloc::vec![7u8; 2800 - 28], dst), Ok(()));
        }
        let queued = net.outbound_len();
        assert_eq!(queued, OUT_PKTS.min(OUT_BYTES.div_ceil(2800)));
        // Draining makes room again, and the count stays right.
        let mut bytes = 0;
        while let Some(p) = net.pop_outbound() {
            bytes += p.len();
        }
        assert_eq!(bytes, queued * 2800);
        assert_eq!(net.udp_send_to(udp, &[1, 2, 3], dst), Ok(()));
        assert_eq!(net.outbound_len(), 1);
        net.clear_outbound();
        assert_eq!(net.outbound_len(), 0);
        for _ in 0..OUT_PKTS + 5 {
            net.udp_send_to(udp, &[1], dst).unwrap();
        }
        assert_eq!(net.outbound_len(), OUT_PKTS);
    }

    /// Packets injected without a poll in between don't pile up without
    /// limit.
    #[test]
    fn inbound_queue_is_bounded() {
        let me = Ipv4Addr::new(10, 20, 30, 2);
        let mut net = Netstack::new(Instant::from_millis(0), DEFAULT_MTU);
        net.set_addresses(&[IpAddr::V4(me)]);
        // TCP segments to a port nobody listens on (not UDP, which never
        // enters this queue).
        let mut pkt = alloc::vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 20, 30, 7]);
        pkt[16..20].copy_from_slice(&me.octets());
        for _ in 0..IN_PKTS + 50 {
            net.inject(pkt.clone());
        }
        assert_eq!(net.dev.inbound.len(), IN_PKTS);
        net.poll(Instant::from_millis(1));
        assert_eq!(net.dev.inbound.len(), 0);
    }
}
