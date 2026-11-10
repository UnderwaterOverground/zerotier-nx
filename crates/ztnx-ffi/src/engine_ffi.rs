//! The engine over the C ABI. The C driver owns the UDP socket and the
//! clock; see `include/ztnx.h` for the contract.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_char;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::time::Duration;

use ztnx_core::engine::{Engine, Event, Io, Prefix};
use ztnx_core::netstack::NetError;
use ztnx_core::time::Instant;

#[repr(C)]
pub struct ZtnxConfig {
    /// The .conf text (UTF-8, need not be NUL-terminated).
    pub conf: *const c_char,
    pub conf_len: usize,
}

pub const ZTNX_IO_SEND_UDP: u32 = 1;

#[repr(C)]
pub struct ZtnxIo {
    pub kind: u32,
    pub reserved: u32,
    /// Bytes to send. Valid until the next `ztnx_engine_poll_io`.
    pub data: *const u8,
    pub len: usize,
    pub addr: ZtnxAddr,
}

pub const ZTNX_EVENT_LOG: u32 = 0;
pub const ZTNX_EVENT_ADDRESSES: u32 = 1;
pub const ZTNX_EVENT_PEERS: u32 = 2;
pub const ZTNX_EVENT_ERROR: u32 = 3;
pub const ZTNX_EVENT_RESOLVE: u32 = 4;
pub const ZTNX_EVENT_HANDSHAKE: u32 = 5;
pub const ZTNX_EVENT_PEER_LOST: u32 = 6;

#[repr(C)]
pub struct ZtnxEvent {
    pub kind: u32,
    /// Peer index or count.
    pub value: u32,
    /// RESOLVE: the port to use with the resolved address.
    pub port: u16,
    pub reserved: u16,
    /// NUL-terminated text. Valid until the next `ztnx_engine_poll_event`.
    pub text: *const c_char,
}

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

pub const ZTNX_PEER_SESSION: u32 = 1;
pub const ZTNX_PEER_ENDPOINT_NAME: u32 = 2;
pub const ZTNX_PEER_RESOLVING: u32 = 4;
pub const ZTNX_PEER_ROAMED: u32 = 8;
pub const ZTNX_PEER_KEEPALIVE: u32 = 16;
pub const ZTNX_PEER_PSK: u32 = 32;
pub const ZTNX_PEER_DEFAULT_ROUTE: u32 = 64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZtnxPeerInfo {
    pub name: [c_char; 32],
    pub ipv4: [u8; 4],
    pub endpoint_ip: [u8; 4],
    pub endpoint_port: u16,
    pub keepalive_s: u16,
    pub last_handshake_s: u32,
    pub last_rx_s: u32,
    pub flags: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub allowed_ips: u32,
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<ZtnxPeerInfo>() == 80);
const _: () = assert!(core::mem::size_of::<ZtnxPrefix>() == 24);

pub struct ZtnxEngine {
    engine: Engine,
    now: Instant,
    io_data: Vec<u8>,
    event_text: Vec<u8>,
}

/// Creates an engine with no configuration (see `ztnx_engine_reload`).
#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_new(now_ns: u64, unix_secs: u64) -> *mut ZtnxEngine {
    let now = Instant::from_nanos(now_ns);
    Box::into_raw(Box::new(ZtnxEngine { engine: Engine::new(now, Duration::from_secs(unix_secs)), now, io_data: Vec::new(), event_text: Vec::new() }))
}

/// Parses `cfg->conf` and applies it. On failure nothing changes and the
/// reason ("line 12: PublicKey: not valid base64") is written to
/// `err[err_cap]` (NUL-terminated; may be NULL/0).
#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_reload(e: *mut ZtnxEngine, cfg: *const ZtnxConfig, now_ns: u64, err: *mut c_char, err_cap: usize) -> bool {
    let e = &mut *e;
    e.now = Instant::from_nanos(now_ns);
    let write_err = |msg: &str| {
        if !err.is_null() && err_cap > 0 {
            let n = msg.len().min(err_cap - 1);
            core::ptr::copy_nonoverlapping(msg.as_ptr(), err.cast::<u8>(), n);
            *err.add(n) = 0;
        }
    };
    let cfg = &*cfg;
    if cfg.conf.is_null() {
        write_err("no configuration");
        return false;
    }
    let text = core::slice::from_raw_parts(cfg.conf.cast::<u8>(), cfg.conf_len);
    let Ok(text) = core::str::from_utf8(text) else {
        write_err("the file is not UTF-8 text");
        return false;
    };
    match ztnx_core::config::parse(text) {
        Ok(parsed) => {
            e.engine.reload(parsed, e.now);
            true
        }
        Err(pe) => {
            write_err(&alloc::format!("{pe}"));
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_free(e: *mut ZtnxEngine) {
    if !e.is_null() {
        drop(Box::from_raw(e));
    }
}

/// Takes the next I/O request. Returns false when there is none.
#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_poll_io(e: *mut ZtnxEngine, out: *mut ZtnxIo) -> bool {
    let e = &mut *e;
    let Some(Io::SendUdp { dst, data }) = e.engine.poll_io() else { return false };
    e.io_data = data;
    *out = ZtnxIo { kind: ZTNX_IO_SEND_UDP, reserved: 0, data: e.io_data.as_ptr(), len: e.io_data.len(), addr: from_sockaddr(dst) };
    true
}

/// A datagram arrived on the engine's UDP socket.
#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_udp(e: *mut ZtnxEngine, src: *const ZtnxAddr, data: *const u8, len: usize, now_ns: u64) {
    let e = &mut *e;
    e.now = Instant::from_nanos(now_ns);
    if let Some(src) = to_sockaddr(&*src) {
        e.engine.handle_udp(src, core::slice::from_raw_parts(data, len), e.now);
    }
}

/// Takes the next status event. Returns false when there is none.
#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_poll_event(e: *mut ZtnxEngine, out: *mut ZtnxEvent) -> bool {
    let e = &mut *e;
    let Some(ev) = e.engine.poll_event() else { return false };
    let mut port = 0;
    let (kind, value, text) = match ev {
        Event::Addresses(a) => {
            let text = a.iter().map(|p| alloc::format!("{}/{}", p.addr, p.len)).collect::<Vec<_>>().join(" ");
            (ZTNX_EVENT_ADDRESSES, a.len() as u32, text)
        }
        Event::Peers(n) => (ZTNX_EVENT_PEERS, n as u32, String::new()),
        Event::Error(s) => (ZTNX_EVENT_ERROR, 0, s),
        Event::Log(s) => (ZTNX_EVENT_LOG, 0, s),
        Event::Resolve { peer, host, port: p } => {
            port = p;
            (ZTNX_EVENT_RESOLVE, peer as u32, host)
        }
        Event::Handshake { peer } => (ZTNX_EVENT_HANDSHAKE, peer as u32, peer_name(&e.engine, peer)),
        Event::PeerLost { peer } => (ZTNX_EVENT_PEER_LOST, peer as u32, peer_name(&e.engine, peer)),
    };
    e.event_text = text.into_bytes();
    e.event_text.retain(|&b| b != 0);
    e.event_text.push(0);
    *out = ZtnxEvent { kind, value, port, reserved: 0, text: e.event_text.as_ptr().cast() };
    true
}

fn peer_name(engine: &Engine, peer: usize) -> String {
    engine.peers_info().get(peer).map(|p| p.name.clone()).unwrap_or_default()
}

/// Runs timers. Call when `ztnx_engine_next_deadline` has passed (calling it
/// more often is harmless).
#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_timeout(e: *mut ZtnxEngine, now_ns: u64) {
    let e = &mut *e;
    e.now = Instant::from_nanos(now_ns);
    e.engine.handle_timeout(e.now);
}

/// The network came back or changed: host names are resolved again and
/// every reachable peer is contacted now.
#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_network_up(e: *mut ZtnxEngine, now_ns: u64) {
    let e = &mut *e;
    e.now = Instant::from_nanos(now_ns);
    e.engine.network_up(e.now);
}

/// Answers ZTNX_EVENT_RESOLVE (or overrides a peer's endpoint).
#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_set_peer_endpoint(e: *mut ZtnxEngine, peer: u32, addr: *const ZtnxAddr, now_ns: u64) {
    let e = &mut *e;
    e.now = Instant::from_nanos(now_ns);
    if let Some(a) = to_sockaddr(&*addr) {
        e.engine.set_peer_endpoint(peer as usize, a, e.now);
    }
}

/// Monotonic time (ns) by which `ztnx_engine_timeout` should be called.
#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_next_deadline(e: *mut ZtnxEngine) -> u64 {
    (*e).engine.next_deadline().as_nanos()
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_listen_port(e: *mut ZtnxEngine) -> u16 {
    (*e).engine.listen_port().unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_mtu(e: *mut ZtnxEngine) -> u16 {
    (*e).engine.mtu() as u16
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_configured(e: *mut ZtnxEngine) -> bool {
    (*e).engine.is_configured()
}

fn put_prefixes(list: &[Prefix], out: *mut ZtnxPrefix, cap: usize) -> usize {
    for (i, p) in list.iter().take(cap).enumerate() {
        let mut o = ZtnxPrefix { family: 4, len: p.len, ip: [0; 16], reserved: [0; 6] };
        match p.addr {
            IpAddr::V4(a) => o.ip[..4].copy_from_slice(&a.octets()),
            IpAddr::V6(a) => {
                o.family = 6;
                o.ip = a.octets();
            }
        }
        unsafe { *out.add(i) = o };
    }
    list.len()
}

/// Our [Interface] addresses with prefix lengths; returns how many there are.
#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_addresses(e: *mut ZtnxEngine, out: *mut ZtnxPrefix, cap: usize) -> usize {
    put_prefixes((*e).engine.addresses(), out, cap)
}

/// Destinations that belong to the tunnel (our addresses, then every
/// peer's AllowedIPs); returns how many there are (can exceed cap).
#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_routes(e: *mut ZtnxEngine, out: *mut ZtnxPrefix, cap: usize) -> usize {
    put_prefixes(&(*e).engine.routes(), out, cap)
}

/// Writes "a.b.c.d name\n" for this interface (if named) and every named
/// peer with an IPv4 /32 AllowedIP, NUL-terminated and truncated to cap.
/// Returns the full length (like snprintf).
#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_hosts(e: *mut ZtnxEngine, buf: *mut c_char, cap: usize) -> usize {
    use core::fmt::Write;
    let mut s = String::new();
    for (ip, name) in (*e).engine.hosts() {
        let _ = writeln!(s, "{ip} {name}");
    }
    if !buf.is_null() && cap > 0 {
        let n = s.len().min(cap - 1);
        core::ptr::copy_nonoverlapping(s.as_ptr(), buf.cast::<u8>(), n);
        *buf.add(n) = 0;
    }
    s.len()
}

fn secs_ago(d: Option<Duration>) -> u32 {
    d.map_or(u32::MAX, |d| d.as_secs().min(u32::MAX as u64 - 1) as u32)
}

/// Every configured peer, in .conf order, up to max of them into out.
/// Returns how many there are (can exceed max).
#[no_mangle]
pub unsafe extern "C" fn ztnx_engine_peers(e: *mut ZtnxEngine, out: *mut ZtnxPeerInfo, max: usize) -> usize {
    let peers = (*e).engine.peers_info();
    for (i, p) in peers.iter().take(max).enumerate() {
        let o = &mut *out.add(i);
        *o = ZtnxPeerInfo {
            name: [0; 32],
            ipv4: p.ipv4.map_or([0; 4], |a| a.octets()),
            endpoint_ip: match p.endpoint.map(|a| a.ip()) {
                Some(IpAddr::V4(a)) => a.octets(),
                _ => [0; 4],
            },
            endpoint_port: p.endpoint.map_or(0, |a| a.port()),
            keepalive_s: p.keepalive.map_or(0, |k| k.as_secs().min(u16::MAX as u64) as u16),
            last_handshake_s: secs_ago(p.last_handshake),
            last_rx_s: secs_ago(p.last_rx),
            rx_bytes: p.rx_bytes,
            tx_bytes: p.tx_bytes,
            flags: (p.session as u32 * ZTNX_PEER_SESSION)
                | (p.endpoint_name as u32 * ZTNX_PEER_ENDPOINT_NAME)
                | (p.resolving as u32 * ZTNX_PEER_RESOLVING)
                | (p.roamed as u32 * ZTNX_PEER_ROAMED)
                | (p.keepalive.is_some() as u32 * ZTNX_PEER_KEEPALIVE)
                | (p.psk as u32 * ZTNX_PEER_PSK)
                | (p.default_route as u32 * ZTNX_PEER_DEFAULT_ROUTE),
            allowed_ips: p.allowed_ips as u32,
            reserved: 0,
        };
        for (dst, src) in o.name.iter_mut().zip(p.name.bytes().take(31)) {
            *dst = src as c_char;
        }
    }
    peers.len()
}

// ---- overlay sockets ------------------------------------------------------

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

/// Runs a socket operation, then lets the engine send what it produced.
unsafe fn with_net<T>(e: *mut ZtnxEngine, f: impl FnOnce(&mut ztnx_core::netstack::Netstack) -> T) -> T {
    let e = &mut *e;
    let r = f(e.engine.net());
    e.engine.flush(e.now);
    r
}

/// Starts a TCP connection to a tunnel address. Returns a socket id (> 0)
/// or a negative ZTNX_E* code. Poll writability to learn when it's up.
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_tcp_connect(e: *mut ZtnxEngine, dst: *const ZtnxAddr) -> i32 {
    let Some(dst) = to_sockaddr(&*dst) else { return ZTNX_EINVAL };
    with_net(e, |n| n.tcp_connect(dst).map(|id| id as i32).unwrap_or_else(err))
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_tcp_listen(e: *mut ZtnxEngine, port: u16, backlog: u32) -> i32 {
    with_net(e, |n| n.tcp_listen(port, backlog as usize).map(|id| id as i32).unwrap_or_else(err))
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_tcp_accept(e: *mut ZtnxEngine, id: i32, peer: *mut ZtnxAddr) -> i32 {
    with_net(e, |n| match n.tcp_accept(id as u32) {
        Ok((sock, addr)) => {
            if !peer.is_null() {
                *peer = from_sockaddr(addr);
            }
            sock as i32
        }
        Err(x) => err(x),
    })
}

/// Sends stream data. Returns bytes accepted or a negative ZTNX_E* code.
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_send(e: *mut ZtnxEngine, id: i32, data: *const u8, len: usize) -> i32 {
    let data = core::slice::from_raw_parts(data, len);
    with_net(e, |n| n.send(id as u32, data).map(|x| x as i32).unwrap_or_else(err))
}

/// Receives stream data. Returns bytes read, 0 at EOF, or a negative code.
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_recv(e: *mut ZtnxEngine, id: i32, buf: *mut u8, len: usize) -> i32 {
    let buf = core::slice::from_raw_parts_mut(buf, len);
    with_net(e, |n| n.recv(id as u32, buf).map(|x| x as i32).unwrap_or_else(err))
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_shutdown(e: *mut ZtnxEngine, id: i32) -> i32 {
    with_net(e, |n| n.shutdown_write(id as u32).map(|_| 0).unwrap_or_else(err))
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_udp_bind(e: *mut ZtnxEngine, port: u16) -> i32 {
    with_net(e, |n| n.udp_bind(port).map(|id| id as i32).unwrap_or_else(err))
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_udp_sendto(e: *mut ZtnxEngine, id: i32, data: *const u8, len: usize, dst: *const ZtnxAddr) -> i32 {
    let Some(dst) = to_sockaddr(&*dst) else { return ZTNX_EINVAL };
    let data = core::slice::from_raw_parts(data, len);
    with_net(e, |n| n.udp_send_to(id as u32, data, dst).map(|_| len as i32).unwrap_or_else(err))
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_udp_recvfrom(e: *mut ZtnxEngine, id: i32, buf: *mut u8, len: usize, src: *mut ZtnxAddr) -> i32 {
    let buf = core::slice::from_raw_parts_mut(buf, len);
    // Only takes a queued datagram: nothing for the engine to send, so no
    // flush (a datagram read per video packet made it a hot path).
    match (*e).engine.net().udp_recv_from(id as u32, buf) {
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
pub unsafe extern "C" fn ztnx_net_readiness(e: *mut ZtnxEngine, id: i32) -> u32 {
    let r = (*e).engine.net().readiness(id as u32);
    (r.readable as u32 * ZTNX_READABLE) | (r.writable as u32 * ZTNX_WRITABLE) | (r.hup as u32 * ZTNX_HUP)
}

/// Bytes of overlay socket buffers in use (TCP buffers, queued datagrams).
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_buffer_usage(e: *mut ZtnxEngine) -> usize {
    (*e).engine.net().buffer_usage()
}

/// Sets the overlay socket buffer budget (bytes; see Netstack::set_budget).
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_set_budget(e: *mut ZtnxEngine, bytes: usize) {
    (*e).engine.net().set_budget(bytes);
}

#[no_mangle]
pub unsafe extern "C" fn ztnx_net_close(e: *mut ZtnxEngine, id: i32) {
    with_net(e, |n| n.close(id as u32));
}

/// The overlay socket's local address (our tunnel IP + port). 0 or error.
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_local_addr(e: *mut ZtnxEngine, id: i32, out: *mut ZtnxAddr) -> i32 {
    match (*e).engine.net().local_addr(id as u32) {
        Some(a) => {
            *out = from_sockaddr(a);
            0
        }
        None => ZTNX_ENOTCONN,
    }
}

/// The overlay TCP socket's peer address. 0 or error.
#[no_mangle]
pub unsafe extern "C" fn ztnx_net_peer_addr(e: *mut ZtnxEngine, id: i32, out: *mut ZtnxAddr) -> i32 {
    match (*e).engine.net().peer_addr(id as u32) {
        Some(a) => {
            *out = from_sockaddr(a);
            0
        }
        None => ZTNX_ENOTCONN,
    }
}
