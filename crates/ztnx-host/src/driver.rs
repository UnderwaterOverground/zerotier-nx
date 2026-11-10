//! Host driver: runs the sans-IO engine over a real UDP socket with a
//! simple non-blocking polling loop. Fine for development; the Switch driver
//! uses poll(2) on libnx sockets instead.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use ztnx_core::config::WgConfig;
use ztnx_core::engine::{Engine, Event, Io};
use ztnx_core::time::Instant;

pub struct Clock(StdInstant);

impl Clock {
    pub fn new() -> Self {
        Self(StdInstant::now())
    }

    pub fn now(&self) -> Instant {
        Instant::from_nanos(self.0.elapsed().as_nanos() as u64)
    }
}

pub fn unix_now() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

pub struct Sockets {
    udp: UdpSocket,
}

impl Sockets {
    pub fn new(udp_port: u16) -> std::io::Result<Self> {
        let udp = UdpSocket::bind(("0.0.0.0", udp_port))?;
        udp.set_nonblocking(true)?;
        Ok(Self { udp })
    }

    pub fn apply(&mut self, io: Io) {
        let Io::SendUdp { dst, data } = io;
        if let Err(e) = self.udp.send_to(&data, dst) {
            log::debug!("udp send to {dst}: {e}");
        }
    }

    /// Reads whatever datagrams are waiting.
    pub fn poll(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut out = Vec::new();
        let mut buf = [0u8; 65536];
        while let Ok((n, src)) = self.udp.recv_from(&mut buf) {
            out.push((src, buf[..n].to_vec()));
        }
        out
    }
}

/// Answers a Resolve event with the OS resolver (IPv4 only, like the
/// console's underlay).
fn resolve(engine: &mut Engine, peer: usize, host: &str, port: u16, now: Instant) {
    match (host, port).to_socket_addrs() {
        Ok(addrs) => match addrs.filter(|a| a.is_ipv4()).next() {
            Some(a) => engine.set_peer_endpoint(peer, a, now),
            None => log::warn!("{host}: no IPv4 address"),
        },
        Err(e) => log::warn!("{host}: {e}"),
    }
}

/// Runs the engine until `step` returns false. `step` is called after every
/// loop iteration with the engine, to drive tests or print status.
pub fn run_engine(
    cfg: WgConfig,
    udp_port: u16,
    mut on_event: impl FnMut(&Event),
    mut step: impl FnMut(&mut Engine, &Clock) -> bool,
) -> Result<(), String> {
    let clock = Clock::new();
    let mut engine = Engine::new(clock.now(), unix_now());
    let port = if udp_port != 0 { udp_port } else { cfg.interface.listen_port.unwrap_or(0) };
    let mut sockets = Sockets::new(port).map_err(|e| format!("udp bind: {e}"))?;
    engine.reload(cfg, clock.now());
    loop {
        if clock.now() >= engine.next_deadline() {
            engine.handle_timeout(clock.now());
        }
        while let Some(io) = engine.poll_io() {
            sockets.apply(io);
        }
        let datagrams = sockets.poll();
        let idle = datagrams.is_empty();
        for (src, data) in datagrams {
            engine.handle_udp(src, &data, clock.now());
        }
        while let Some(ev) = engine.poll_event() {
            if let Event::Resolve { peer, host, port } = &ev {
                resolve(&mut engine, *peer, host, *port, clock.now());
            }
            on_event(&ev);
        }
        if !step(&mut engine, &clock) {
            return Ok(());
        }
        engine.flush(clock.now());
        if idle {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
