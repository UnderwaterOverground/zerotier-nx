//! Host driver for ztnx-core: runs a .conf against real peers on the
//! development machine, plus diagnostics.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use ztnx_core::tls::{self, TlsClient};

/// Counts heap usage so the Switch builds' heap budget can be sized from
/// real runs (printed at exit).
mod heap {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering};
    pub static CUR: AtomicUsize = AtomicUsize::new(0);
    pub static PEAK: AtomicUsize = AtomicUsize::new(0);
    pub struct Counting;
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            let p = System.alloc(l);
            if !p.is_null() {
                let n = CUR.fetch_add(l.size(), Ordering::Relaxed) + l.size();
                PEAK.fetch_max(n, Ordering::Relaxed);
            }
            p
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            CUR.fetch_sub(l.size(), Ordering::Relaxed);
            System.dealloc(p, l)
        }
    }
}
#[global_allocator]
static ALLOC: heap::Counting = heap::Counting;

mod driver;
mod echo;

const USAGE: &str = "selftest | genkey | tls-probe [host[:port]] [path] | check --conf FILE | up --conf FILE [--port N] [--echo-test IP] [--expect-handshake] [--duration SECS] [--bulk BYTES]";

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    ztnx_core::rng::seed_from_os();
    tls::CLOCK.set(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());

    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("selftest") | None => selftest(),
        Some("genkey") => genkey(),
        Some("tls-probe") => tls_probe(args.get(1).map(String::as_str).unwrap_or("github.com"), args.get(2).map(String::as_str).unwrap_or("/")),
        Some("check") => check(&args[1..]),
        Some("up") => up(&args[1..]),
        Some(other) => Err(format!("unknown command {other:?}; try {USAGE}")),
    };
    log::info!(
        "heap: {} KB in use, peak {} KB",
        heap::CUR.load(std::sync::atomic::Ordering::Relaxed) / 1024,
        heap::PEAK.load(std::sync::atomic::Ordering::Relaxed) / 1024
    );
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Prints a new private key and its public key, base64 as .conf files use.
fn genkey() -> Result<(), String> {
    use base64::Engine as _;
    let private = ztnx_core::rng::bytes32().map_err(|_| "rng not seeded")?;
    let b64 = base64::engine::general_purpose::STANDARD;
    println!("PrivateKey = {}", b64.encode(private));
    println!("PublicKey = {}", b64.encode(ztnx_core::crypto::x25519_public(&private)));
    Ok(())
}

fn selftest() -> Result<(), String> {
    ztnx_core::selftest::run().map_err(|f| format!("selftest failed: {f:?}"))?;
    println!("ztnx-host {}: selftest ok", ztnx_core::VERSION);
    Ok(())
}

/// HTTPS GET over the sans-IO TLS client, pumping a blocking TcpStream (the
/// update check's code path).
fn tls_probe(target: &str, path: &str) -> Result<(), String> {
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|e| e.to_string())?),
        None => (target, 443),
    };
    let config = tls::client_config(&[]).map_err(|e| e.to_string())?;
    let mut tls = TlsClient::new(config, host).map_err(|e| format!("{e:?}"))?;
    let mut sock = TcpStream::connect((host, port)).map_err(|e| e.to_string())?;
    tls.write(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).map_err(|e| format!("{e:?}"))?;

    let mut response = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        let out = tls.take_outgoing();
        if !out.is_empty() {
            sock.write_all(&out).map_err(|e| e.to_string())?;
        }
        let n = sock.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        tls.feed(&buf[..n]).map_err(|e| format!("{e:?}"))?;
        response.extend(tls.take_plaintext());
        if tls.peer_closed() {
            break;
        }
    }
    println!("established={} received {} bytes", tls.is_established(), response.len());
    let text = String::from_utf8_lossy(&response);
    println!("{}", text.lines().take(12).collect::<Vec<_>>().join("\n"));
    if !tls.is_established() {
        return Err("handshake did not complete".into());
    }
    Ok(())
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn load_conf(args: &[String]) -> Result<ztnx_core::config::WgConfig, String> {
    let path = flag(args, "--conf").ok_or("--conf FILE is required")?;
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    ztnx_core::config::parse(&text).map_err(|e| format!("{path}: {e}"))
}

/// Parses a .conf and prints what the engine makes of it.
fn check(args: &[String]) -> Result<(), String> {
    let cfg = load_conf(args)?;
    let i = &cfg.interface;
    println!(
        "interface{}: {} listen {} mtu {}",
        i.name.as_deref().map(|n| format!(" {n}")).unwrap_or_default(),
        i.addresses.iter().map(|p| format!("{}/{}", p.addr, p.len)).collect::<Vec<_>>().join(" "),
        i.listen_port.map_or("any".to_string(), |p| p.to_string()),
        i.mtu.unwrap_or(ztnx_core::engine::DEFAULT_MTU as u16)
    );
    for p in &cfg.peers {
        let endpoint = match &p.endpoint {
            Some((ztnx_core::config::EndpointHost::Ip(ip), port)) => format!("{ip}:{port}"),
            Some((ztnx_core::config::EndpointHost::Name(n), port)) => format!("{n}:{port} (name)"),
            None => "none".into(),
        };
        println!(
            "peer {}: endpoint {endpoint}, allowed {}, keepalive {}, psk {}",
            p.name,
            p.allowed_ips.iter().map(|q| format!("{}/{}", q.addr, q.len)).collect::<Vec<_>>().join(" "),
            p.persistent_keepalive.map_or("off".to_string(), |k| format!("{k} s")),
            if p.preshared_key.is_some() { "yes" } else { "no" }
        );
    }
    Ok(())
}

fn up(args: &[String]) -> Result<(), String> {
    let cfg = load_conf(args)?;
    let bulk = flag(args, "--bulk").map(|n| n.parse().expect("--bulk bytes")).unwrap_or(0);
    let mut echo = flag(args, "--echo-test").map(|ip| echo::EchoTest::new(ip.parse().expect("--echo-test IP"), bulk));
    let handshaken = std::cell::Cell::new(false);
    let expect_handshake = args.iter().any(|a| a == "--expect-handshake");
    let duration = flag(args, "--duration").map(|s| std::time::Duration::from_secs(s.parse().expect("--duration seconds")));
    let started = std::time::Instant::now();
    let udp_port = flag(args, "--port").map(|p| p.parse().expect("--port")).unwrap_or(0);
    let result = driver::run_engine(
        cfg,
        udp_port,
        |ev| {
            if matches!(ev, ztnx_core::engine::Event::Handshake { .. }) {
                handshaken.set(true);
            }
            log::info!("{ev:?}");
        },
        |engine, clock| {
            if duration.is_some_and(|d| started.elapsed() >= d) {
                return false;
            }
            match echo.as_mut() {
                Some(t) => t.step(engine, clock),
                // Nothing to wait for but the handshake, if one is expected.
                None => !(expect_handshake && duration.is_none() && handshaken.get()),
            }
        },
    );
    if expect_handshake && !handshaken.get() {
        return Err("no handshake completed".into());
    }
    if let Some(t) = echo {
        return t.result();
    }
    result
}
