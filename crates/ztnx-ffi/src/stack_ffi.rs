//! The netstack and its Ethernet layer over the C ABI. The caller owns the
//! clock and the lock; see `include/ztnx.h` for the contract.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ztnx_core::l2::{Config, Frame, Net, Route};
use ztnx_core::netstack::{NetError, Netstack};
use ztnx_core::stack::Stack;
use ztnx_core::time::Instant;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZtnxAddr {
    /// 4 or 6.
    pub family: u8,
    /// IPv4 uses the first 4 bytes.
    pub ip: [u8; 16],
    pub port: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZtnxPrefix {
    /// 4 or 6.
    pub family: u8,
    pub len: u8,
    /// IPv4 uses the first 4 bytes.
    pub ip: [u8; 16],
    pub reserved: [u8; 6],
}

/// One of our addresses on the network, with its prefix length.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZtnxV4Net {
    pub ip: [u8; 4],
    pub prefix: u8,
    pub reserved: [u8; 3],
}

/// A managed route: `target`/`prefix` through `via`, or on-link if
/// `has_via` is 0.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZtnxV4Route {
    pub target: [u8; 4],
    pub prefix: u8,
    pub has_via: u8,
    pub reserved: [u8; 2],
    pub via: [u8; 4],
}

/// Counters for the log.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ZtnxStackStats {
    /// Broadcast ARP requests sent.
    pub arp_broadcasts: u32,
    /// ARP requests held back by the broadcast budget.
    pub arp_limited: u32,
    /// Packets dropped waiting for a neighbour's MAC.
    pub unresolved: u32,
    /// Packets with nowhere to go.
    pub unroutable: u32,
    /// IP packets waiting to be sent.
    pub out_queued: u32,
    /// Datagrams dropped because the app's UDP socket queue was full.
    pub udp_dropped: u32,
}

const _: () = assert!(core::mem::size_of::<ZtnxPrefix>() == 24);
const _: () = assert!(core::mem::size_of::<ZtnxV4Net>() == 8);
const _: () = assert!(core::mem::size_of::<ZtnxV4Route>() == 12);
const _: () = assert!(core::mem::size_of::<ZtnxStackStats>() == 24);

/// A device on the network whose MAC is known.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ZtnxNeighbor {
    pub mac: u64,
    pub ip: [u8; 4],
    pub reserved: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<ZtnxNeighbor>() == 16);

pub struct ZtnxStack {
    stack: Stack,
    /// A frame taken from the stack that didn't fit the caller's buffer;
    /// it is offered again on the next call.
    held: Option<Frame>,
}

/// A buffer this large takes any frame; one that still doesn't fit is
/// dropped rather than held forever.
const ANY_FRAME: usize = 10240;

/// Creates the stack, with no network yet (see `ztnx_l2_configure`).
#[no_mangle]
pub extern "C" fn ztnx_stack_new(now_ns: u64) -> *mut ZtnxStack {
    Box::into_raw(Box::new(ZtnxStack { stack: Stack::new(Instant::from_nanos(now_ns)), held: None }))
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_stack_free(s: *mut ZtnxStack) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}

/// Sets the time for the calls that follow, up to `ztnx_stack_end`.
#[no_mangle]
pub unsafe extern "C" fn ztnx_stack_begin(s: *mut ZtnxStack, now_ns: u64) {
    (*s).stack.begin(Instant::from_nanos(now_ns));
}

pub const ZTNX_OUT_PENDING: u32 = 1;
pub const ZTNX_CHANGED: u32 = 2;

/// Runs the netstack once over everything since `ztnx_stack_begin`.
#[no_mangle]
pub unsafe extern "C" fn ztnx_stack_end(s: *mut ZtnxStack) -> u32 {
    let f = (*s).stack.end();
    ((f.out_pending || (*s).held.is_some()) as u32 * ZTNX_OUT_PENDING) | (f.changed as u32 * ZTNX_CHANGED)
}

/// When begin/end should next run if nothing happens first (TCP timers, ARP
/// retries), in the clock's nanoseconds; UINT64_MAX if never.
#[no_mangle]
pub unsafe extern "C" fn ztnx_stack_next_deadline(s: *mut ZtnxStack) -> u64 {
    if (*s).held.is_some() {
        return 0;
    }
    (*s).stack.next_deadline().map_or(u64::MAX, |t| t.as_nanos())
}

/// Frames are waiting for `ztnx_l2_next_out`.
#[no_mangle]
pub unsafe extern "C" fn ztnx_stack_out_pending(s: *mut ZtnxStack) -> bool {
    (*s).held.is_some() || (*s).stack.out_pending()
}

/// After a sleep or a change of network underneath: drops what was queued
/// and re-checks neighbours as they are used.
#[no_mangle]
pub unsafe extern "C" fn ztnx_stack_link_reset(s: *mut ZtnxStack) {
    (*s).held = None;
    (*s).stack.link_reset();
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_stack_stats(s: *mut ZtnxStack, out: *mut ZtnxStackStats) {
    let stack = &mut (*s).stack;
    let l2 = stack.l2().stats();
    *out = ZtnxStackStats {
        arp_broadcasts: l2.broadcasts,
        arp_limited: l2.limited,
        unresolved: l2.unresolved,
        unroutable: l2.unroutable,
        out_queued: stack.net().outbound_len() as u32,
        udp_dropped: stack.net().udp_dropped(),
    };
}

/// The network is up, or its configuration changed. `mac` is ours as
/// ZeroTier writes it (first octet in bits 40-47); `mtu` the network's.
/// False if there is no address or the arguments are invalid.
#[no_mangle]
pub unsafe extern "C" fn ztnx_l2_configure(
    s: *mut ZtnxStack,
    nwid: u64,
    mac: u64,
    mtu: u16,
    addrs: *const ZtnxV4Net,
    n_addrs: usize,
    routes: *const ZtnxV4Route,
    n_routes: usize,
) -> bool {
    let addrs = if n_addrs == 0 { &[] } else { core::slice::from_raw_parts(addrs, n_addrs) };
    let routes = if n_routes == 0 { &[] } else { core::slice::from_raw_parts(routes, n_routes) };
    if addrs.is_empty() || mtu < 576 || addrs.iter().any(|a| a.prefix > 32) || routes.iter().any(|r| r.prefix > 32) {
        return false;
    }
    let cfg = Config {
        nwid,
        mac,
        addrs: addrs.iter().map(|a| Net { addr: Ipv4Addr::from(a.ip), prefix: a.prefix }).collect(),
        routes: routes
            .iter()
            .map(|r| Route {
                target: Net { addr: Ipv4Addr::from(r.target), prefix: r.prefix },
                via: (r.has_via != 0).then_some(Ipv4Addr::from(r.via)),
            })
            .collect::<Vec<_>>(),
    };
    (*s).stack.configure(cfg, usize::from(mtu));
    true
}

/// The network is gone. Sockets stay open; their packets go nowhere.
#[no_mangle]
pub unsafe extern "C" fn ztnx_l2_down(s: *mut ZtnxStack) {
    (*s).held = None;
    (*s).stack.down();
}

/// The devices whose MAC is known: up to `max` into `out`. Returns how many
/// were written (the stack keeps at most 32).
#[no_mangle]
pub unsafe extern "C" fn ztnx_l2_neighbors(s: *mut ZtnxStack, out: *mut ZtnxNeighbor, max: usize) -> usize {
    let mut n = 0;
    for (mac, ip) in (*s).stack.l2().neighbors().take(max) {
        *out.add(n) = ZtnxNeighbor { mac, ip: ip.octets(), reserved: [0; 4] };
        n += 1;
    }
    n
}

/// A frame arrived from the network. Call between begin and end.
#[no_mangle]
pub unsafe extern "C" fn ztnx_l2_frame_in(s: *mut ZtnxStack, src_mac: u64, dst_mac: u64, ethertype: u32, data: *const u8, len: usize) {
    let Ok(ethertype) = u16::try_from(ethertype) else { return };
    (*s).stack.frame_in(src_mac, dst_mac, ethertype, core::slice::from_raw_parts(data, len));
}

/// Takes the next frame to send: its payload into `buf`, returning the
/// length, or 0 if there is none this time or it needs more room than `cap`
/// (`ztnx_stack_out_pending` says whether to ask again; the frame is kept
/// for the next call).
#[no_mangle]
pub unsafe extern "C" fn ztnx_l2_next_out(s: *mut ZtnxStack, buf: *mut u8, cap: usize, dst_mac: *mut u64, ethertype: *mut u32) -> usize {
    let s = &mut *s;
    while let Some(f) = s.held.take().or_else(|| s.stack.next_out()) {
        if f.payload.len() > cap {
            if cap < ANY_FRAME {
                s.held = Some(f);
                return 0;
            }
            continue;
        }
        core::ptr::copy_nonoverlapping(f.payload.as_ptr(), buf, f.payload.len());
        *dst_mac = f.dst_mac;
        *ethertype = u32::from(f.ethertype);
        return f.payload.len();
    }
    0
}

// ---- overlay sockets ------------------------------------------------------
//
// Call these between `ztnx_stack_begin` and `ztnx_stack_end`: they change
// socket state, and `end` is what sends the result.

pub const ZTNX_EAGAIN: i32 = -1;
pub const ZTNX_ENOTCONN: i32 = -2;
pub const ZTNX_EBADF: i32 = -3;
pub const ZTNX_EADDRINUSE: i32 = -4;
pub const ZTNX_ECONNREFUSED: i32 = -5;
pub const ZTNX_ECONNRESET: i32 = -6;
pub const ZTNX_EINVAL: i32 = -7;
/// The overlay memory budget is used up (try again later).
pub const ZTNX_ENOBUFS: i32 = -8;

fn err(e: NetError) -> i32 {
    match e {
        NetError::WouldBlock => ZTNX_EAGAIN,
        NetError::NotConnected => ZTNX_ENOTCONN,
        NetError::InvalidSocket => ZTNX_EBADF,
        NetError::AddrInUse => ZTNX_EADDRINUSE,
        NetError::ConnectionRefused => ZTNX_ECONNREFUSED,
        NetError::ConnectionReset => ZTNX_ECONNRESET,
        NetError::Invalid => ZTNX_EINVAL,
        NetError::NoBuffers => ZTNX_ENOBUFS,
    }
}

fn to_sockaddr(a: &ZtnxAddr) -> Option<SocketAddr> {
    let ip = match a.family {
        4 => IpAddr::V4(Ipv4Addr::new(a.ip[0], a.ip[1], a.ip[2], a.ip[3])),
        6 => IpAddr::V6(Ipv6Addr::from(a.ip)),
        _ => return None,
    };
    Some(SocketAddr::new(ip, a.port))
}

fn from_sockaddr(s: SocketAddr) -> ZtnxAddr {
    let mut ip = [0u8; 16];
    let family = match s.ip() {
        IpAddr::V4(v4) => {
            ip[..4].copy_from_slice(&v4.octets());
            4
        }
        IpAddr::V6(v6) => {
            ip = v6.octets();
            6
        }
    };
    ZtnxAddr { family, ip, port: s.port() }
}

unsafe fn net<'a>(s: *mut ZtnxStack) -> &'a mut Netstack {
    (*s).stack.net()
}

/// Starts a TCP connection to an address on the network. Returns a socket
/// id (> 0) or a negative ZTNX_E* code. Poll writability to learn when it's
/// up.
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_tcp_connect(s: *mut ZtnxStack, dst: *const ZtnxAddr) -> i32 {
    let Some(dst) = to_sockaddr(&*dst) else { return ZTNX_EINVAL };
    net(s).tcp_connect(dst).map(|id| id as i32).unwrap_or_else(err)
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_tcp_listen(s: *mut ZtnxStack, port: u16, backlog: u32) -> i32 {
    net(s).tcp_listen(port, backlog as usize).map(|id| id as i32).unwrap_or_else(err)
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_tcp_accept(s: *mut ZtnxStack, id: i32, peer: *mut ZtnxAddr) -> i32 {
    match net(s).tcp_accept(id as u32) {
        Ok((sock, addr)) => {
            if !peer.is_null() {
                *peer = from_sockaddr(addr);
            }
            sock as i32
        }
        Err(x) => err(x),
    }
}

/// Sends stream data. Returns bytes accepted or a negative ZTNX_E* code.
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_send(s: *mut ZtnxStack, id: i32, data: *const u8, len: usize) -> i32 {
    let data = core::slice::from_raw_parts(data, len);
    net(s).send(id as u32, data).map(|x| x as i32).unwrap_or_else(err)
}

/// Receives stream data. Returns bytes read, 0 at EOF, or a negative code.
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_recv(s: *mut ZtnxStack, id: i32, buf: *mut u8, len: usize) -> i32 {
    let buf = core::slice::from_raw_parts_mut(buf, len);
    net(s).recv(id as u32, buf).map(|x| x as i32).unwrap_or_else(err)
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_shutdown(s: *mut ZtnxStack, id: i32) -> i32 {
    net(s).shutdown_write(id as u32).map(|_| 0).unwrap_or_else(err)
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_udp_bind(s: *mut ZtnxStack, port: u16) -> i32 {
    net(s).udp_bind(port).map(|id| id as i32).unwrap_or_else(err)
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_udp_sendto(s: *mut ZtnxStack, id: i32, data: *const u8, len: usize, dst: *const ZtnxAddr) -> i32 {
    let Some(dst) = to_sockaddr(&*dst) else { return ZTNX_EINVAL };
    let data = core::slice::from_raw_parts(data, len);
    net(s).udp_send_to(id as u32, data, dst).map(|_| len as i32).unwrap_or_else(err)
}

/// Takes a queued datagram. Needs no begin/end: nothing is sent.
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_udp_recvfrom(s: *mut ZtnxStack, id: i32, buf: *mut u8, len: usize, src: *mut ZtnxAddr) -> i32 {
    let buf = core::slice::from_raw_parts_mut(buf, len);
    match net(s).udp_recv_from(id as u32, buf) {
        Ok((got, from)) => {
            if !src.is_null() {
                *src = from_sockaddr(from);
            }
            got as i32
        }
        Err(x) => err(x),
    }
}

pub const ZTNX_READABLE: u32 = 1;
pub const ZTNX_WRITABLE: u32 = 2;
pub const ZTNX_HUP: u32 = 4;

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_readiness(s: *mut ZtnxStack, id: i32) -> u32 {
    let r = net(s).readiness(id as u32);
    (r.readable as u32 * ZTNX_READABLE) | (r.writable as u32 * ZTNX_WRITABLE) | (r.hup as u32 * ZTNX_HUP)
}

/// Bytes of overlay socket buffers in use (TCP buffers, queued datagrams).
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_buffer_usage(s: *mut ZtnxStack) -> usize {
    net(s).buffer_usage()
}

/// Sets the overlay socket buffer budget (bytes; see Netstack::set_budget).
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_set_budget(s: *mut ZtnxStack, bytes: usize) {
    net(s).set_budget(bytes);
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_close(s: *mut ZtnxStack, id: i32) {
    net(s).close(id as u32);
}

/// The overlay socket's local address (our address + port). 0 or error.
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_local_addr(s: *mut ZtnxStack, id: i32, out: *mut ZtnxAddr) -> i32 {
    match net(s).local_addr(id as u32) {
        Some(a) => {
            *out = from_sockaddr(a);
            0
        }
        None => ZTNX_ENOTCONN,
    }
}

/// The overlay TCP socket's peer address. 0 or error.
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_peer_addr(s: *mut ZtnxStack, id: i32, out: *mut ZtnxAddr) -> i32 {
    match net(s).peer_addr(id as u32) {
        Some(a) => {
            *out = from_sockaddr(a);
            0
        }
        None => ZTNX_ENOTCONN,
    }
}
