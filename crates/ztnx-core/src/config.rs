//! wg-quick style configuration files (`wg0.conf`).
//!
//! The format is `wg(8)`'s with wg-quick's `[Interface]` extras: sections
//! `[Interface]` and `[Peer]`, `Key = Value` lines, `#` comments. Keys the
//! engine has no use for (`DNS`, `Table`, `PostUp`, ...) are accepted and
//! ignored so a file that works with wg-quick works here too.
//!
//! Peers have no names in the format, so a comment inside a section names
//! it: `# Name = gaming-pc` (also `# Name: x`, wg-easy's `### Client: x`,
//! and a bare `#gaming-pc` line as Unraid writes). Names end up in the
//! overlay and in the console's hosts file.
//!
//! `# Host = gaming-pc 192.168.1.50`, anywhere in the file, names another
//! address the tunnel reaches (a PC on the server's network) for the hosts
//! file. A malformed one is logged and ignored, never an error: other tools'
//! comments may start with "Host" too.
//!
//! AmneziaWG's `[Interface]` keys (`Jc`, `Jmin`, `Jmax`, `S1`..`S4`,
//! `H1`..`H4`, `I1`..`I5`, `HeaderProtectionKey`, `RandomTrailers`) are
//! accepted as amneziawg-tools writes them; see [`crate::awg`]. Its
//! client-side extras (content padding, timings, `DisableCookies`) change
//! nothing the peer needs, so they are logged and ignored, and a range
//! `PersistentKeepalive = 22-30` uses its low end.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr};

use base64::Engine as _;

pub use crate::engine::packet::Prefix;

/// Largest name kept (the C ABI carries 32-byte name fields).
pub const NAME_MAX: usize = 31;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgConfig {
    pub interface: Interface,
    pub peers: Vec<PeerConf>,
    /// From `# Host = name a.b.c.d` comments, in file order.
    pub hosts: Vec<(String, Ipv4Addr)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub private_key: [u8; 32],
    /// `Address` lines; a bare address means /32 or /128.
    pub addresses: Vec<Prefix>,
    pub listen_port: Option<u16>,
    /// `MTU`, 576..=1500 if present.
    pub mtu: Option<u16>,
    /// From a name comment in `[Interface]`, for the hosts file.
    pub name: Option<String>,
    /// AmneziaWG settings; the default is plain WireGuard.
    pub awg: crate::awg::Params,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointHost {
    Ip(IpAddr),
    /// A host name the driver resolves.
    Name(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConf {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub allowed_ips: Vec<Prefix>,
    pub endpoint: Option<(EndpointHost, u16)>,
    /// `PersistentKeepalive` in seconds; `off`, 0 and absent are None.
    pub persistent_keepalive: Option<u16>,
    /// Never empty: from a name comment, else `peerN` (1-based).
    pub name: String,
}

impl PeerConf {
    /// The first IPv4 /32 in AllowedIPs: the address the peer is known by.
    pub fn ipv4(&self) -> Option<core::net::Ipv4Addr> {
        self.allowed_ips.iter().find_map(|p| match p.addr {
            IpAddr::V4(a) if p.len == 32 => Some(a),
            _ => None,
        })
    }

    /// AllowedIPs contains a default route (0.0.0.0/0 or ::/0).
    pub fn default_route(&self) -> bool {
        self.allowed_ips.iter().any(|p| p.len == 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line, 0 when the problem is the file as a whole.
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "{}", self.msg)
        } else {
            write!(f, "line {}: {}", self.line, self.msg)
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Section {
    None,
    Interface,
    Peer,
}

/// Keys wg-quick accepts in `[Interface]` that the engine ignores.
const IGNORED_INTERFACE_KEYS: &[&str] = &["dns", "table", "preup", "postup", "predown", "postdown", "fwmark", "saveconfig"];
/// AmneziaWG 3 settings that only change what their owner sends or when it
/// handshakes; the peer needs nothing from them. Lowercase, then as spelled.
const AWG_SENDER_KEYS: &[(&str, &str)] = &[
    ("contentpaddingaddition", "ContentPaddingAddition"),
    ("rekeyaftertime", "RekeyAfterTime"),
    ("rekeytimeout", "RekeyTimeout"),
    ("rejectaftertime", "RejectAfterTime"),
    ("keepalivetimeout", "KeepaliveTimeout"),
    ("maxhandshakeattempts", "MaxHandshakeAttempts"),
    ("disablecookies", "DisableCookies"),
];
const KNOWN_KEYS: &[&str] = &[
    "privatekey",
    "address",
    "listenport",
    "mtu",
    "publickey",
    "presharedkey",
    "allowedips",
    "endpoint",
    "persistentkeepalive",
    "dns",
    "table",
    "preup",
    "postup",
    "predown",
    "postdown",
    "fwmark",
    "saveconfig",
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "s3",
    "s4",
    "h1",
    "h2",
    "h3",
    "h4",
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
    "headerprotectionkey",
    "randomtrailers",
    "contentpaddingaddition",
    "rekeyaftertime",
    "rekeytimeout",
    "rejectaftertime",
    "keepalivetimeout",
    "maxhandshakeattempts",
    "disablecookies",
];

struct PeerBuilder {
    public_key: Option<[u8; 32]>,
    preshared_key: Option<[u8; 32]>,
    allowed_ips: Vec<Prefix>,
    endpoint: Option<(EndpointHost, u16)>,
    persistent_keepalive: Option<u16>,
    name: Option<String>,
    implied_name: Option<String>,
    line: usize,
}

struct InterfaceBuilder {
    private_key: Option<[u8; 32]>,
    addresses: Vec<Prefix>,
    listen_port: Option<u16>,
    mtu: Option<u16>,
    name: Option<String>,
    implied_name: Option<String>,
    awg: crate::awg::Params,
    /// `I1`..`I5` by slot; the set ones go into `awg.signatures` in order.
    signatures: [Option<crate::awg::Signature>; 5],
}

pub fn parse(text: &str) -> Result<WgConfig, ParseError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let err = |line: usize, msg: String| ParseError { line, msg };
    let mut section = Section::None;
    let mut iface: Option<InterfaceBuilder> = None;
    let mut peers: Vec<PeerBuilder> = Vec::new();
    let mut hosts: Vec<(String, Ipv4Addr)> = Vec::new();

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            match host_from_comment(comment) {
                Some(Ok(host)) => {
                    if !hosts.iter().any(|(n, _)| *n == host.0) {
                        hosts.push(host);
                    }
                    continue;
                }
                Some(Err(())) => {
                    log::warn!("conf line {line_no}: ignoring Host comment (expected \"# Host = name a.b.c.d\")");
                    continue;
                }
                None => {}
            }
            let (explicit, implied) = name_from_comment(comment);
            match section {
                Section::Interface => {
                    let b = iface.as_mut().expect("interface builder");
                    if explicit.is_some() {
                        b.name = explicit;
                    } else if b.implied_name.is_none() {
                        b.implied_name = implied;
                    }
                }
                Section::Peer => {
                    let b = peers.last_mut().expect("peer builder");
                    if explicit.is_some() {
                        b.name = explicit;
                    } else if b.implied_name.is_none() {
                        b.implied_name = implied;
                    }
                }
                Section::None => {}
            }
            continue;
        }
        if line.starts_with('[') {
            let name = line.strip_suffix(']').ok_or_else(|| err(line_no, "malformed section header".into()))?;
            let name = name[1..].trim();
            if name.eq_ignore_ascii_case("Interface") {
                if iface.is_some() {
                    return Err(err(line_no, "more than one [Interface] section".into()));
                }
                iface = Some(InterfaceBuilder {
                    private_key: None,
                    addresses: Vec::new(),
                    listen_port: None,
                    mtu: None,
                    name: None,
                    implied_name: None,
                    awg: Default::default(),
                    signatures: Default::default(),
                });
                section = Section::Interface;
            } else if name.eq_ignore_ascii_case("Peer") {
                peers.push(PeerBuilder {
                    public_key: None,
                    preshared_key: None,
                    allowed_ips: Vec::new(),
                    endpoint: None,
                    persistent_keepalive: None,
                    name: None,
                    implied_name: None,
                    line: line_no,
                });
                section = Section::Peer;
            } else {
                return Err(err(line_no, format!("unknown section [{name}]")));
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(err(line_no, "expected Key = Value".into()));
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match section {
            Section::None => return Err(err(line_no, format!("{key} before any section"))),
            Section::Interface => {
                let b = iface.as_mut().expect("interface builder");
                match key.as_str() {
                    "privatekey" => b.private_key = Some(key32(value).map_err(|m| err(line_no, format!("PrivateKey: {m}")))?),
                    "address" => {
                        for item in list(value) {
                            b.addresses.push(address(item).ok_or_else(|| err(line_no, format!("Address: bad address {item:?}")))?);
                        }
                    }
                    "listenport" => {
                        b.listen_port = Some(value.parse().map_err(|_| err(line_no, format!("ListenPort: bad port {value:?}")))?)
                    }
                    "mtu" => {
                        let mtu: u16 = value.parse().map_err(|_| err(line_no, format!("MTU: bad value {value:?}")))?;
                        if !(576..=1500).contains(&mtu) {
                            return Err(err(line_no, format!("MTU: {mtu} is outside 576..1500")));
                        }
                        b.mtu = Some(mtu);
                    }
                    "jc" | "jmin" | "jmax" => {
                        // AmneziaWG reads an empty value as 0.
                        let n: u32 = if value.is_empty() { 0 } else { value.parse().map_err(|_| err(line_no, format!("{}: bad value {value:?}", upper(&key))))? };
                        match key.as_str() {
                            "jc" => b.awg.junk_count = n,
                            "jmin" => b.awg.junk_min = n,
                            _ => b.awg.junk_max = n,
                        }
                    }
                    "s1" | "s2" | "s3" | "s4" => {
                        let n: u16 = if value.is_empty() { 0 } else { value.parse().map_err(|_| err(line_no, format!("{}: bad value {value:?}", upper(&key))))? };
                        b.awg.prefix[slot(&key)] = n;
                    }
                    "h1" | "h2" | "h3" | "h4" => {
                        b.awg.header[slot(&key)] = crate::awg::Range::parse(value).map_err(|m| err(line_no, format!("{}: {m}", upper(&key))))?;
                    }
                    "i1" | "i2" | "i3" | "i4" | "i5" => {
                        b.signatures[slot(&key)] = Some(crate::awg::Signature::parse(value).map_err(|m| err(line_no, format!("{}: {m}", upper(&key))))?);
                    }
                    "headerprotectionkey" => b.awg.header_key = Some(key32(value).map_err(|m| err(line_no, format!("HeaderProtectionKey: {m}")))?),
                    "randomtrailers" => b.awg.random_trailers = flag(value).ok_or_else(|| err(line_no, format!("RandomTrailers: bad value {value:?}")))?,
                    k if AWG_SENDER_KEYS.iter().any(|(lower, _)| *lower == k) => {
                        let name = AWG_SENDER_KEYS.iter().find(|(lower, _)| *lower == k).map(|(_, name)| *name).unwrap_or(k);
                        log::info!("conf: {name} is an AmneziaWG sender-side setting the Switch doesn't use; ignored");
                    }
                    k if IGNORED_INTERFACE_KEYS.contains(&k) => log::debug!("conf: ignoring {k}"),
                    k => return Err(err(line_no, format!("unknown [Interface] key {k:?}"))),
                }
            }
            Section::Peer => {
                let b = peers.last_mut().expect("peer builder");
                match key.as_str() {
                    "publickey" => b.public_key = Some(key32(value).map_err(|m| err(line_no, format!("PublicKey: {m}")))?),
                    "presharedkey" => {
                        b.preshared_key = Some(key32(value).map_err(|m| err(line_no, format!("PresharedKey: {m}")))?)
                    }
                    "allowedips" => {
                        for item in list(value) {
                            b.allowed_ips.push(address(item).ok_or_else(|| err(line_no, format!("AllowedIPs: bad prefix {item:?}")))?);
                        }
                    }
                    "endpoint" => b.endpoint = Some(endpoint(value).ok_or_else(|| err(line_no, format!("Endpoint: bad value {value:?}")))?),
                    "persistentkeepalive" => {
                        // AmneziaWG 3 allows a range (`22-30`): the low end does.
                        b.persistent_keepalive = if value.eq_ignore_ascii_case("off") {
                            None
                        } else {
                            let r = crate::awg::Range::parse(value).ok().filter(|r| r.hi <= u16::MAX as u32);
                            let n = r.map(|r| r.lo as u16).ok_or_else(|| err(line_no, format!("PersistentKeepalive: bad value {value:?}")))?;
                            (n > 0).then_some(n)
                        }
                    }
                    k => return Err(err(line_no, format!("unknown [Peer] key {k:?}"))),
                }
            }
        }
    }

    let Some(iface) = iface else { return Err(err(0, "no [Interface] section".into())) };
    let Some(private_key) = iface.private_key else { return Err(err(0, "[Interface] has no PrivateKey".into())) };
    if iface.addresses.is_empty() {
        return Err(err(0, "[Interface] has no Address".into()));
    }
    let mut awg = iface.awg;
    awg.signatures = iface.signatures.into_iter().flatten().collect();
    awg.validate().map_err(|m| err(0, format!("AmneziaWG: {m}")))?;
    let our_public = crate::crypto::x25519_public(&private_key);
    let mut out_peers: Vec<PeerConf> = Vec::with_capacity(peers.len());
    for (i, p) in peers.into_iter().enumerate() {
        let Some(public_key) = p.public_key else { return Err(err(p.line, "[Peer] has no PublicKey".into())) };
        if public_key == our_public {
            return Err(err(p.line, "[Peer] PublicKey is this interface's own key".into()));
        }
        if out_peers.iter().any(|q| q.public_key == public_key) {
            return Err(err(p.line, "[Peer] PublicKey repeats an earlier peer's".into()));
        }
        let mut name = p.name.or(p.implied_name).map(|n| normalize_name(&n)).filter(|n| !n.is_empty()).unwrap_or_else(|| format!("peer{}", i + 1));
        // Two peers with the same name would be one hosts entry.
        let base = name.clone();
        let mut n = 2;
        while out_peers.iter().any(|q| q.name == name) {
            let suffix = format!("-{n}");
            let keep = base.len().min(NAME_MAX - suffix.len());
            name = format!("{}{suffix}", &base[..keep]);
            n += 1;
        }
        out_peers.push(PeerConf {
            public_key,
            preshared_key: p.preshared_key,
            allowed_ips: p.allowed_ips,
            endpoint: p.endpoint,
            persistent_keepalive: p.persistent_keepalive,
            name,
        });
    }
    Ok(WgConfig {
        interface: Interface {
            private_key,
            addresses: iface.addresses,
            listen_port: iface.listen_port,
            mtu: iface.mtu,
            name: iface.name.or(iface.implied_name).map(|n| normalize_name(&n)).filter(|n| !n.is_empty()),
            awg,
        },
        peers: out_peers,
        hosts,
    })
}

/// `S1`, `H4`, `I5` -> 0, 3, 4.
fn slot(key: &str) -> usize {
    usize::from(key.as_bytes()[1] - b'1')
}

/// The AmneziaWG key as its documentation spells it: `jmin` -> `Jmin`.
fn upper(key: &str) -> String {
    let mut s = key.to_string();
    s[..1].make_ascii_uppercase();
    s
}

/// A boolean as amneziawg-tools reads one.
fn flag(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "on" | "yes" | "1" => Some(true),
        "false" | "off" | "no" | "0" => Some(false),
        _ => None,
    }
}

/// A `Host = name a.b.c.d` (or `Host: ...`) comment: None if the comment
/// isn't one, Err if it is but doesn't hold a name and an IPv4 address.
fn host_from_comment(comment: &str) -> Option<Result<(String, Ipv4Addr), ()>> {
    let text = comment.trim_start_matches('#').trim();
    if !text.get(..4).is_some_and(|w| w.eq_ignore_ascii_case("host")) {
        return None;
    }
    let rest = text[4..].trim_start();
    let rest = rest.strip_prefix('=').or_else(|| rest.strip_prefix(':'))?;
    // The address first or last; the rest is the name ("Gaming PC" too).
    let rest = rest.trim();
    let (first, last) = (rest.split_whitespace().next()?, rest.split_whitespace().last()?);
    let (name, ip) = if let Ok(ip) = last.parse::<Ipv4Addr>() {
        (rest[..rest.len() - last.len()].trim(), ip)
    } else if let Ok(ip) = first.parse::<Ipv4Addr>() {
        (rest[first.len()..].trim(), ip)
    } else {
        return Some(Err(()));
    };
    if name.parse::<Ipv4Addr>().is_ok() {
        return Some(Err(()));
    }
    let name = normalize_name(name);
    if name.is_empty() {
        return Some(Err(()));
    }
    Some(Ok((name, ip)))
}

/// The name a comment line gives its section: (explicit, implied).
/// Explicit: `Name = x`, `Name: x`, `Client: x` (wg-easy, with a trailing
/// `(id)` dropped). Implied: a bare word that isn't a key name (`#switch`).
fn name_from_comment(comment: &str) -> (Option<String>, Option<String>) {
    let text = comment.trim_start_matches('#').trim();
    let lower = text.to_ascii_lowercase();
    for prefix in ["name", "client"] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            let rest_trim = rest.trim_start();
            if let Some(sep) = rest_trim.chars().next().filter(|c| *c == '=' || *c == ':') {
                let _ = sep;
                let value = &text[text.len() - rest_trim.len() + 1..];
                let value = value.trim();
                // wg-easy: "### Client: name (uuid)"
                let value = match value.rfind(" (") {
                    Some(i) if value.ends_with(')') => &value[..i],
                    _ => value,
                };
                return (Some(value.trim().to_string()), None);
            }
        }
    }
    let bare = !text.is_empty()
        && !text.contains(char::is_whitespace)
        && !text.contains('=')
        && !text.contains(':')
        && !KNOWN_KEYS.contains(&lower.as_str())
        && text.chars().any(|c| c.is_ascii_alphanumeric());
    (None, bare.then(|| text.to_string()))
}

/// Lowercase `[a-z0-9-]`, runs of anything else collapsed to `-`, at most
/// NAME_MAX bytes: a host name label, as the hosts file needs.
pub fn normalize_name(s: &str) -> String {
    let mut out = String::new();
    let mut dash = true;
    for c in s.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
            dash = false;
        } else if !dash {
            out.push('-');
            dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    truncate(&out)
}

fn truncate(s: &str) -> String {
    let mut s = s.to_string();
    s.truncate(NAME_MAX);
    while s.ends_with('-') {
        s.pop();
    }
    s
}

fn key32(b64: &str) -> Result<[u8; 32], String> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|_| "not valid base64".to_string())?;
    bytes.as_slice().try_into().map_err(|_| format!("{} bytes, not 32", bytes.len()))
}

fn list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// `a.b.c.d/len`, `addr` (= /32 or /128), or `[v6]/len`.
pub fn address(s: &str) -> Option<Prefix> {
    match s.split_once('/') {
        Some((ip, len)) => {
            let addr: IpAddr = ip.trim().parse().ok()?;
            let len: u8 = len.trim().parse().ok()?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            (len <= max).then_some(Prefix { addr, len })
        }
        None => {
            let addr: IpAddr = s.parse().ok()?;
            Some(Prefix { addr, len: if addr.is_ipv4() { 32 } else { 128 } })
        }
    }
}

/// `host:port`, `a.b.c.d:port` or `[v6]:port`.
fn endpoint(s: &str) -> Option<(EndpointHost, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (v6, port) = rest.split_once("]:")?;
        (EndpointHost::Ip(IpAddr::V6(v6.parse().ok()?)), port)
    } else {
        let (host, port) = s.rsplit_once(':')?;
        let host = host.trim();
        if host.is_empty() || host.contains(char::is_whitespace) {
            return None;
        }
        match host.parse::<IpAddr>() {
            Ok(ip) => (EndpointHost::Ip(ip), port),
            Err(_) => (EndpointHost::Name(host.to_string()), port),
        }
    };
    let port: u16 = port.trim().parse().ok()?;
    (port > 0).then_some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const KEY_B: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const KEY_C: &str = "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=";
    const KEY_D: &str = "gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=";

    #[test]
    fn wg_quick_sample() {
        let text = format!(
            "[Interface]\nAddress = 10.192.122.1/24\nAddress = 10.10.0.1/16\nSaveConfig = true\nPrivateKey = {KEY_A}\nListenPort = 51820\n\n[Peer]\nPublicKey = {KEY_B}\nEndpoint = 192.95.5.67:1234\nAllowedIPs = 10.192.122.3/32, 10.192.124.1/24\n\n[Peer]\nPublicKey = {KEY_C}\nEndpoint = [2607:5300:60:6b0::c05f:543]:2468\nAllowedIPs = 10.192.122.4/32, 192.168.0.0/16\n\n[Peer]\nPublicKey = {KEY_D}\nEndpoint = test.wireguard.com:18981\nAllowedIPs = 10.10.10.230/32\n"
        );
        let c = parse(&text).unwrap();
        assert_eq!(c.interface.addresses.len(), 2);
        assert_eq!(c.interface.listen_port, Some(51820));
        assert_eq!(c.peers.len(), 3);
        assert_eq!(c.peers[0].name, "peer1");
        assert_eq!(c.peers[0].endpoint, Some((EndpointHost::Ip("192.95.5.67".parse().unwrap()), 1234)));
        assert_eq!(c.peers[0].allowed_ips[1], Prefix { addr: "10.192.124.1".parse().unwrap(), len: 24 });
        assert!(matches!(c.peers[1].endpoint, Some((EndpointHost::Ip(IpAddr::V6(_)), 2468))));
        assert_eq!(c.peers[2].endpoint, Some((EndpointHost::Name("test.wireguard.com".into()), 18981)));
        assert_eq!(c.peers[2].ipv4(), Some("10.10.10.230".parse().unwrap()));
        assert_eq!(c.peers[0].persistent_keepalive, None);
    }

    #[test]
    fn host_comments_name_other_addresses() {
        let text = format!(
            "# Host = Gaming PC 192.168.1.50\n[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2/32\n#host: 192.168.1.60 nas\n[Peer]\n# Name = router\n#Hostname\n# Host: my home server\n# Host = nas 192.168.1.61\n# Hosts = a 1.2.3.4\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.1, 192.168.1.0/24\n"
        );
        let c = parse(&text).unwrap();
        // "my home server" has no address: ignored. The first "nas" wins.
        assert_eq!(c.hosts, [("gaming-pc".to_string(), "192.168.1.50".parse().unwrap()), ("nas".to_string(), "192.168.1.60".parse().unwrap())]);
        assert_eq!(c.peers[0].name, "router");
        let text = format!("[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2/32\n# Host = gaming-pc 192.168.1.50\n[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 10.0.0.1\n");
        assert_eq!(parse(&text).unwrap().hosts, [("gaming-pc".to_string(), "192.168.1.50".parse().unwrap())]);
        assert_eq!(host_from_comment(" Hostname = x"), None);
        assert_eq!(host_from_comment(" Host = 192.168.1.50"), Some(Err(())));
        assert_eq!(host_from_comment(" Host = 10.0.0.1 10.0.0.2"), Some(Err(())));
        assert_eq!(host_from_comment(" Host ="), None);
        assert_eq!(host_from_comment("é"), None);
    }

    #[test]
    fn wg_easy_client() {
        let text = format!(
            "\u{feff}[Interface]\r\nPrivateKey = {KEY_A}\r\nAddress = 10.8.0.2/24\r\nDNS = 1.1.1.1\r\n\r\n[Peer]\r\n### Client: Living Room PC (3f2a)\r\nPublicKey = {KEY_B}\r\nPresharedKey = {KEY_C}\r\nAllowedIPs = 0.0.0.0/0, ::/0\r\nPersistentKeepalive = 0\r\nEndpoint = vpn.example.com:51820\r\n"
        );
        let c = parse(&text).unwrap();
        assert_eq!(c.peers[0].name, "living-room-pc");
        assert!(c.peers[0].preshared_key.is_some());
        assert!(c.peers[0].default_route());
        assert_eq!(c.peers[0].persistent_keepalive, None);
        assert_eq!(c.peers[0].ipv4(), None);
    }

    #[test]
    fn unraid_bare_comment_names_and_ignored_keys() {
        let text = format!(
            "[Interface]\n#switch\nPrivateKey={KEY_A}\nAddress=10.253.0.2\nPostUp=iptables -t nat -A POSTROUTING -o br0 -j MASQUERADE\nPostDown=iptables -t nat -D POSTROUTING -o br0 -j MASQUERADE\n\n[Peer]\n#Tower\nPublicKey={KEY_B}\nPresharedKey={KEY_C}\nAllowedIPs=10.253.0.1/32\nAllowedIPs=192.168.1.0/24\nEndpoint=192.168.1.10:51820\nPersistentKeepalive=25\n"
        );
        let c = parse(&text).unwrap();
        assert_eq!(c.interface.name.as_deref(), Some("switch"));
        assert_eq!(c.interface.addresses, [Prefix { addr: "10.253.0.2".parse().unwrap(), len: 32 }]);
        assert_eq!(c.peers[0].name, "tower");
        assert_eq!(c.peers[0].allowed_ips.len(), 2);
        assert_eq!(c.peers[0].persistent_keepalive, Some(25));
    }

    #[test]
    fn explicit_name_beats_bare_comment_and_keys_are_case_insensitive() {
        let text = format!("[interface]\nprivatekey = {KEY_A}\naddress = 10.0.0.2/32\n[PEER]\n#stale\n# Name: Gaming PC!\npublickey = {KEY_B}\nallowedips = 10.0.0.1\npersistentkeepalive = off\n");
        let c = parse(&text).unwrap();
        assert_eq!(c.peers[0].name, "gaming-pc");
        assert_eq!(c.peers[0].allowed_ips, [Prefix { addr: "10.0.0.1".parse().unwrap(), len: 32 }]);
        assert_eq!(c.peers[0].persistent_keepalive, None);
    }

    #[test]
    fn duplicate_names_get_suffixes_and_long_names_are_cut() {
        let long = "a".repeat(40);
        let text = format!(
            "[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2\n[Peer]\n# Name = {long}\nPublicKey = {KEY_B}\n[Peer]\n# Name = {long}\nPublicKey = {KEY_C}\n[Peer]\nPublicKey = {KEY_D}\n"
        );
        let c = parse(&text).unwrap();
        assert_eq!(c.peers[0].name.len(), NAME_MAX);
        assert!(c.peers[1].name.ends_with("-2"));
        assert_eq!(c.peers[2].name, "peer3");
    }

    #[test]
    fn errors_name_the_line() {
        let e = |t: &str| parse(t).unwrap_err();
        assert_eq!(e("[Interface]\nPrivateKey = nope!\n"), ParseError { line: 2, msg: "PrivateKey: not valid base64".into() });
        assert_eq!(e(&format!("[Interface]\nAddress = 10.0.0.2\n[Peer]\nPublicKey = {KEY_B}\n")).msg, "[Interface] has no PrivateKey");
        assert_eq!(e(&format!("[Interface]\nPrivateKey = {KEY_A}\n")).msg, "[Interface] has no Address");
        assert_eq!(e(&format!("[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2\n[Interface]\n")).line, 4);
        assert_eq!(e(&format!("[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2\nBogus = 1\n")).line, 4);
        assert_eq!(e(&format!("[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2\nMTU = 100\n")).line, 4);
        assert_eq!(e(&format!("[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2\n[Peer]\nPublicKey = {KEY_B}\n[Peer]\nPublicKey = {KEY_B}\n")).line, 6);
        assert_eq!(e(&format!("[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2\n[Peer]\nAllowedIPs = 10.0.0.1\n")).line, 4);
        assert_eq!(e("PrivateKey = x\n").line, 1);
        assert_eq!(e("[Interface]\nPrivateKey\n").msg, "expected Key = Value");
        let own = parse(&format!("[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2\n[Peer]\nPublicKey = {}\n", {
            use base64::Engine as _;
            let k = key32(KEY_A).unwrap();
            base64::engine::general_purpose::STANDARD.encode(crate::crypto::x25519_public(&k))
        }))
        .unwrap_err();
        assert!(own.msg.contains("own key"), "{own}");
        assert_eq!(format!("{}", e("[Interface]\nPrivateKey = nope!\n")), "line 2: PrivateKey: not valid base64");
    }

    #[test]
    fn amneziawg_keys() {
        use crate::awg::Range;
        // As the Amnezia app and amneziawg-tools write a client .conf.
        let text = format!(
            "[Interface]\nAddress = 10.8.1.2/32\nDNS = 1.1.1.1\nPrivateKey = {KEY_A}\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 22\nH1 = 1234567\nH2 = 2345678\nH3 = 3456789\nH4 = 4567890\n\n[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.5:51820\n"
        );
        let c = parse(&text).unwrap();
        let a = &c.interface.awg;
        assert_eq!((a.junk_count, a.junk_min, a.junk_max), (4, 40, 70));
        assert_eq!(a.prefix, [15, 22, 0, 0]);
        assert_eq!(a.header, [Range::one(1234567), Range::one(2345678), Range::one(3456789), Range::one(4567890)]);
        assert!(a.signatures.is_empty() && !a.is_plain());
        // AmneziaWG 2: ranges, S3/S4, signature packets (I3 set, I1 not).
        let text = format!("[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2\nH1 = 100-200\nH4 = 5\nS3 = 1\nS4 = 20\nI3 = <b 0x474554><r 8>\nI2 = <t>\n[Peer]\nPublicKey = {KEY_B}\n");
        let a = parse(&text).unwrap().interface.awg;
        assert_eq!(a.header, [Range { lo: 100, hi: 200 }, Range::one(2), Range::one(3), Range::one(5)]);
        assert_eq!(a.prefix, [0, 0, 1, 20]);
        assert_eq!(a.signatures.len(), 2);
        assert_eq!(a.signatures[0].len(), 4, "I2 comes first");
        assert_eq!(a.signatures[1].len(), 11);
        // A conf without the keys is plain WireGuard.
        assert!(parse(&format!("[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2\n")).unwrap().interface.awg.is_plain());

        let e = |extra: &str| parse(&format!("[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2\n{extra}\n")).unwrap_err();
        assert_eq!(e("Jc = x"), ParseError { line: 4, msg: "Jc: bad value \"x\"".into() });
        assert_eq!(e("Jmin = 80\nJmax = 70"), ParseError { line: 0, msg: "AmneziaWG: Jmin 80 is more than Jmax 70".into() });
        assert_eq!(e("H1 = 5\nH2 = 1-10").msg, "AmneziaWG: H1 5 and H2 1-10 overlap");
        assert_eq!(e("H3 = 9-8"), ParseError { line: 4, msg: "H3: 9-8 is backwards".into() });
        assert_eq!(e("S4 = 70000").msg, "S4: bad value \"70000\"");
        assert_eq!(e("S4 = 900").msg, "AmneziaWG: S4 900: the most is 844");
        assert_eq!(e("I1 = <zz 3>"), ParseError { line: 4, msg: "I1: unknown tag <zz>".into() });
        // AmneziaWG 3: a header protection key, which needs S1-S4 >= 12.
        let text = format!("[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2\nS1 = 12\nS2 = 30\nS3 = 16\nS4 = 14\nHeaderProtectionKey = {KEY_B}\n[Peer]\nPublicKey = {KEY_B}\n");
        let a = parse(&text).unwrap().interface.awg;
        assert_eq!(a.header_key, Some(key32(KEY_B).unwrap()));
        assert!(!a.is_plain());
        assert_eq!(e("HeaderProtectionKey = 00"), ParseError { line: 4, msg: "HeaderProtectionKey: not valid base64".into() });
        assert_eq!(e(&format!("S1 = 12\nS2 = 12\nS3 = 12\nHeaderProtectionKey = {KEY_B}")).msg, "AmneziaWG: S4 0: HeaderProtectionKey needs S1-S4 of at least 12");
        // The rest of AmneziaWG 3 as a client conf may carry it: sender-side
        // settings are ignored, RandomTrailers is kept, a keepalive range
        // uses its low end, and an empty value is 0.
        let text = format!("[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2\nJc = 3\nJmin = \nJmax = 50\nS3 = \nContentPaddingAddition = 1-64\nRekeyAfterTime = 100-120\nRekeyTimeout = 5\nRejectAfterTime = 180\nKeepaliveTimeout = 10\nMaxHandshakeAttempts = 20\nDisableCookies = true\nRandomTrailers = on\n[Peer]\nPublicKey = {KEY_B}\nPersistentKeepalive = 22-30\n");
        let c = parse(&text).unwrap();
        assert!(c.interface.awg.random_trailers);
        assert_eq!((c.interface.awg.junk_min, c.interface.awg.prefix[2]), (0, 0));
        assert_eq!(c.peers[0].persistent_keepalive, Some(22));
        assert_eq!(e("RandomTrailers = maybe").msg, "RandomTrailers: bad value \"maybe\"");
        assert_eq!(e("ContentPaddingAddition = 1-64\nUnknownThing = 1").msg, "unknown [Interface] key \"unknownthing\"");
    }

    #[test]
    fn endpoints() {
        assert_eq!(endpoint("1.2.3.4:51820"), Some((EndpointHost::Ip("1.2.3.4".parse().unwrap()), 51820)));
        assert_eq!(endpoint("vpn.example.com:51820"), Some((EndpointHost::Name("vpn.example.com".into()), 51820)));
        assert_eq!(endpoint("[::1]:7"), Some((EndpointHost::Ip("::1".parse().unwrap()), 7)));
        assert_eq!(endpoint("1.2.3.4"), None);
        assert_eq!(endpoint("1.2.3.4:0"), None);
        assert_eq!(endpoint("a b:1"), None);
    }

    #[test]
    fn names_normalize() {
        assert_eq!(normalize_name("Gaming PC"), "gaming-pc");
        assert_eq!(normalize_name("  --Sam's Mac--  "), "sam-s-mac");
        assert_eq!(normalize_name("日本"), "");
        assert_eq!(name_from_comment("# Name = x"), (Some("x".into()), None));
        assert_eq!(name_from_comment("## Client: Phone (abc)"), (Some("Phone".into()), None));
        assert_eq!(name_from_comment("tower"), (None, Some("tower".into())));
        assert_eq!(name_from_comment("PrivateKey"), (None, None));
        assert_eq!(name_from_comment("some words here"), (None, None));
    }
}
