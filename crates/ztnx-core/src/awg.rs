//! AmneziaWG: WireGuard with a disguise on the wire.
//!
//! An AmneziaWG peer speaks ordinary WireGuard inside each datagram, but
//! (1) sends `Jc` junk datagrams of random size and the `I1`..`I5`
//! "signature" datagrams before every handshake initiation, (2) prefixes
//! each message with `S1`..`S4` random bytes (one value per message type),
//! and (3) replaces the 4-byte message type (1..4) with a value drawn from
//! `H1`..`H4`.
//!
//! All of that is framing outside the Noise protocol, so it lives here,
//! between `ts_tunnel` and the socket: [`Params::wrap`] disguises what
//! ts_tunnel built and [`Params::unwrap`] restores what arrived. The one
//! complication: the handshake MACs (`mac1`, and `mac2` once a peer has
//! sent us a cookie) cover the type field, so after the type changes they
//! are computed again here, with the same keys ts_tunnel uses. For the same
//! reason cookie replies are handled here and never reach ts_tunnel: the
//! cookie is sealed against the `mac1` the peer actually saw, which is ours.
//!
//! AmneziaWG 3 adds header protection (`HeaderProtectionKey`, a shared
//! 32-byte key): the first 12 bytes of a message's random prefix are the
//! nonce of a ChaCha20 keystream that is XORed over the whole handshake
//! message, or over the 16-byte header of a transport message, so no
//! low-entropy WireGuard field is left on the wire. It needs every `S` to
//! be at least 12. That happens last on the way out and first on the way
//! in, around everything above.
//!
//! AmneziaWG 3's other settings are client-side and change only what a
//! sender does: content padding and random trailers pad what it sends, the
//! timing keys move its handshake timers. The Switch doesn't send any of
//! that (a peer accepts the plain sizes regardless), but with
//! `RandomTrailers` on it accepts the peer's trailed handshake messages.
//!
//! Reference: amneziawg-go, `device/{send,receive,noise-protocol,obf*}.go`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::time::Duration;

use blake2::digest::consts::U16;
use blake2::digest::Mac as _;
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::XChaCha20Poly1305;

use crate::time::Instant;

/// Wire sizes of the four message types (the transport one is a minimum).
const SIZES: [usize; 4] = [148, 92, 64, 32];
/// What header protection encrypts: a whole handshake message, but only
/// the type, receiver and counter of a transport message.
const PROTECTED: [usize; 4] = [148, 92, 64, 16];
/// The prefix bytes that are the header-protection nonce.
pub const HEADER_NONCE: usize = 12;
/// WireGuard's cookie lifetime.
const COOKIE_LIFETIME: Duration = Duration::from_secs(120);
/// Largest junk or signature datagram, and the most junk per handshake:
/// anything bigger fragments on the way, which defeats the purpose.
pub const MAX_JUNK: usize = 1280;
pub const MAX_JUNK_COUNT: u32 = 128;
/// Largest `S1`..`S4`: a padded handshake message still fits in one
/// datagram on a 1280-byte path; `S4` leaves the tunnel MTU at least 576.
pub const MAX_PREFIX: [u16; 4] = [1132, 1188, 1216, 844];

/// A header value, or a range to draw one from (`H1 = 100-200`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub lo: u32,
    pub hi: u32,
}

impl Range {
    pub const fn one(v: u32) -> Self {
        Self { lo: v, hi: v }
    }

    /// `a` or `a-b` (a <= b), decimal.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (lo, hi) = match s.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (s.trim(), s.trim()),
        };
        let lo: u32 = lo.parse().map_err(|_| format!("bad number {lo:?}"))?;
        let hi: u32 = hi.parse().map_err(|_| format!("bad number {hi:?}"))?;
        if hi < lo {
            return Err(format!("{lo}-{hi} is backwards"));
        }
        Ok(Self { lo, hi })
    }

    pub fn contains(&self, v: u32) -> bool {
        self.lo <= v && v <= self.hi
    }

    pub fn overlaps(&self, o: &Range) -> bool {
        self.lo <= o.hi && o.lo <= self.hi
    }

    fn pick(&self) -> u32 {
        let span = u64::from(self.hi) - u64::from(self.lo) + 1;
        self.lo + (rand_u64() % span) as u32
    }
}

impl core::fmt::Display for Range {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

/// One `<tag>` of a signature packet template.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tag {
    /// `<b 0x...>`: these bytes.
    Bytes(Vec<u8>),
    /// `<r N>`: N random bytes.
    Random(usize),
    /// `<rc N>`: N random letters.
    Chars(usize),
    /// `<rd N>`: N random digits.
    Digits(usize),
    /// `<t>`: Unix time, 4 bytes big-endian.
    Timestamp,
    /// `<dz N>`: the payload's length in N bytes; the payload is empty.
    Zeros(usize),
}

/// An `I1`..`I5` template: a datagram sent before each handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    tags: Vec<Tag>,
}

impl Signature {
    /// `<b 0xc0ffee><r 16><t>`; text outside the tags is ignored, as
    /// amneziawg-go does.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut tags = Vec::new();
        let mut rest = spec;
        while let Some(start) = rest.find('<') {
            let after = &rest[start + 1..];
            let Some(end) = after.find('>') else { return Err("missing >".into()) };
            let mut parts = after[..end].split_whitespace();
            let key = parts.next().ok_or_else(|| "empty <>".to_string())?;
            let arg = parts.next();
            let size = |arg: Option<&str>| -> Result<usize, String> {
                let a = arg.ok_or_else(|| format!("<{key}> needs a size"))?;
                let n: usize = a.parse().map_err(|_| format!("<{key} {a}>: bad size"))?;
                if n > MAX_JUNK {
                    return Err(format!("<{key} {a}>: more than {MAX_JUNK} bytes"));
                }
                Ok(n)
            };
            tags.push(match key {
                "b" => {
                    let hex = arg.ok_or_else(|| "<b> needs hex bytes".to_string())?;
                    let hex = hex.strip_prefix("0x").unwrap_or(hex);
                    if hex.is_empty() || hex.len() % 2 != 0 {
                        return Err(format!("<b {hex}>: expected an even number of hex digits"));
                    }
                    let bytes: Result<Vec<u8>, _> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16)).collect();
                    Tag::Bytes(bytes.map_err(|_| format!("<b {hex}>: not hex"))?)
                }
                "r" => Tag::Random(size(arg)?),
                "rc" => Tag::Chars(size(arg)?),
                "rd" => Tag::Digits(size(arg)?),
                "t" => Tag::Timestamp,
                "dz" => Tag::Zeros(size(arg)?),
                // Payload tags: a signature packet carries no payload.
                "d" | "ds" => Tag::Bytes(Vec::new()),
                other => return Err(format!("unknown tag <{other}>")),
            });
            rest = &after[end + 1..];
        }
        if tags.is_empty() {
            return Err("no <tags>".into());
        }
        let s = Self { tags };
        if s.len() > MAX_JUNK {
            return Err(format!("{} bytes; the most is {MAX_JUNK}", s.len()));
        }
        Ok(s)
    }

    pub fn len(&self) -> usize {
        self.tags
            .iter()
            .map(|t| match t {
                Tag::Bytes(b) => b.len(),
                Tag::Random(n) | Tag::Chars(n) | Tag::Digits(n) | Tag::Zeros(n) => *n,
                Tag::Timestamp => 4,
            })
            .sum()
    }

    pub fn render(&self, unix_secs: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());
        for t in &self.tags {
            match t {
                Tag::Bytes(b) => out.extend_from_slice(b),
                Tag::Random(n) => random_into(&mut out, *n, None),
                Tag::Chars(n) => random_into(&mut out, *n, Some(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")),
                Tag::Digits(n) => random_into(&mut out, *n, Some(b"0123456789")),
                Tag::Timestamp => out.extend_from_slice(&unix_secs.to_be_bytes()),
                Tag::Zeros(n) => out.resize(out.len() + n, 0),
            }
        }
        out
    }
}

fn random_into(out: &mut Vec<u8>, n: usize, alphabet: Option<&[u8]>) {
    let at = out.len();
    out.resize(at + n, 0);
    let _ = crate::rng::fill(&mut out[at..]);
    if let Some(a) = alphabet {
        for b in &mut out[at..] {
            *b = a[usize::from(*b) % a.len()];
        }
    }
}

fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    let _ = crate::rng::fill(&mut b);
    u64::from_le_bytes(b)
}

/// The `[Interface]` AmneziaWG settings. [`Default`] is plain WireGuard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    /// `Jc`, `Jmin`, `Jmax`.
    pub junk_count: u32,
    pub junk_min: u32,
    pub junk_max: u32,
    /// `S1`..`S4`: random bytes before each message type.
    pub prefix: [u16; 4],
    /// `H1`..`H4`: what the message type field says.
    pub header: [Range; 4],
    /// `I1`..`I5`, in that order, the ones that are set.
    pub signatures: Vec<Signature>,
    /// `HeaderProtectionKey` (AmneziaWG 3).
    pub header_key: Option<[u8; 32]>,
    /// `RandomTrailers` (AmneziaWG 3): the peer may append random bytes to
    /// its handshake messages, so their sizes are minimums too.
    pub random_trailers: bool,
}

impl Default for Params {
    fn default() -> Self {
        Self { junk_count: 0, junk_min: 0, junk_max: 0, prefix: [0; 4], header: [Range::one(1), Range::one(2), Range::one(3), Range::one(4)], signatures: Vec::new(), header_key: None, random_trailers: false }
    }
}

/// What [`Params::unwrap`] made of a datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum Inbound {
    /// A WireGuard message in its standard form, for ts_tunnel.
    Message(Vec<u8>),
    /// A cookie reply: give it to the peer's [`PeerMacs`].
    CookieReply { nonce: [u8; 24], sealed: [u8; 32] },
    /// Junk, a signature packet, or anything else that isn't a message.
    Junk,
}

impl Params {
    /// Nothing to do on the wire: every setting at its WireGuard value.
    pub fn is_plain(&self) -> bool {
        self.junk_count == 0 && self.prefix == [0; 4] && self.header == Self::default().header && self.signatures.is_empty() && self.header_key.is_none() && !self.random_trailers
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.junk_min > self.junk_max {
            return Err(format!("Jmin {} is more than Jmax {}", self.junk_min, self.junk_max));
        }
        if self.junk_max as usize > MAX_JUNK {
            return Err(format!("Jmax {}: the most is {MAX_JUNK}", self.junk_max));
        }
        if self.junk_count > MAX_JUNK_COUNT {
            return Err(format!("Jc {}: the most is {MAX_JUNK_COUNT}", self.junk_count));
        }
        for (i, (s, max)) in self.prefix.iter().zip(MAX_PREFIX).enumerate() {
            if *s > max {
                return Err(format!("S{} {s}: the most is {max}", i + 1));
            }
            if self.header_key.is_some() && usize::from(*s) < HEADER_NONCE {
                return Err(format!("S{} {s}: HeaderProtectionKey needs S1-S4 of at least {HEADER_NONCE}", i + 1));
            }
        }
        for i in 0..4 {
            for j in i + 1..4 {
                if self.header[i].overlaps(&self.header[j]) {
                    return Err(format!("H{} {} and H{} {} overlap", i + 1, self.header[i], j + 1, self.header[j]));
                }
            }
        }
        Ok(())
    }

    /// For the log.
    pub fn summary(&self) -> String {
        let [s1, s2, s3, s4] = self.prefix;
        let [h1, h2, h3, h4] = self.header;
        format!(
            "Jc={} Jmin={} Jmax={} S1={s1} S2={s2} S3={s3} S4={s4} H1={h1} H2={h2} H3={h3} H4={h4} I={} header protection {} trailers {}",
            self.junk_count,
            self.junk_min,
            self.junk_max,
            self.signatures.len(),
            if self.header_key.is_some() { "on" } else { "off" },
            if self.random_trailers { "on" } else { "off" }
        )
    }

    /// The datagrams to send ahead of a handshake initiation: the
    /// signature packets, then the junk.
    pub fn preamble(&self, unix_secs: u32) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = self.signatures.iter().map(|s| s.render(unix_secs)).collect();
        for _ in 0..self.junk_count {
            // As amneziawg-go: Jmin + rand(Jmax - Jmin), so Jmax itself
            // never comes up unless it equals Jmin.
            let span = u64::from(self.junk_max - self.junk_min);
            let n = self.junk_min as usize + if span == 0 { 0 } else { (rand_u64() % span) as usize };
            let mut junk = Vec::new();
            random_into(&mut junk, n, None);
            out.push(junk);
        }
        out
    }

    /// Disguises a message ts_tunnel built. `peer` is who it goes to: the
    /// MACs of a handshake message are redone with its keys.
    pub fn wrap(&self, wire: &[u8], peer: &mut PeerMacs, now: Instant) -> Vec<u8> {
        let t = wire.first().copied().unwrap_or(0) as usize;
        if !(1..=4).contains(&t) || wire.len() < SIZES[t - 1] {
            return wire.to_vec();
        }
        let s = self.prefix[t - 1] as usize;
        let mut out = Vec::with_capacity(s + wire.len());
        random_into(&mut out, s, None);
        out.extend_from_slice(wire);
        out[s..s + 4].copy_from_slice(&self.header[t - 1].pick().to_le_bytes());
        if t <= 2 {
            peer.write_macs(&mut out[s..], now);
        }
        if let Some(mut cipher) = self.header_cipher(&out) {
            cipher.apply_keystream(&mut out[s..s + PROTECTED[t - 1]]);
        }
        out
    }

    /// Restores a datagram from the wire. `me` checks a handshake
    /// message's `mac1` the way ts_tunnel will once the type is back.
    pub fn unwrap(&self, data: &[u8], me: &MyMacs) -> Inbound {
        let Some(t) = self.classify(data) else { return Inbound::Junk };
        let s = self.prefix[t - 1] as usize;
        // A handshake message ends where its type says; what follows is a trailer.
        let mut msg = if t == 4 { data[s..].to_vec() } else { data[s..s + SIZES[t - 1]].to_vec() };
        if let Some(mut cipher) = self.header_cipher(data) {
            cipher.apply_keystream(&mut msg[..PROTECTED[t - 1]]);
        }
        if t <= 2 && !me.mac1_ok(&msg) {
            return Inbound::Junk;
        }
        if t == 3 {
            return Inbound::CookieReply { nonce: msg[8..32].try_into().unwrap(), sealed: msg[32..64].try_into().unwrap() };
        }
        msg[..4].copy_from_slice(&(t as u32).to_le_bytes());
        if t <= 2 {
            me.write_mac1(&mut msg);
        }
        Inbound::Message(msg)
    }

    /// Which message type a datagram is, by its size and header: exact
    /// sizes for the handshake messages, a minimum for transport data.
    /// Under header protection the header is read through the keystream
    /// (the same first 4 bytes of it whichever prefix it sits behind).
    fn classify(&self, data: &[u8]) -> Option<usize> {
        let mut mask = [0u8; 4];
        if let Some(mut cipher) = self.header_cipher(data) {
            cipher.apply_keystream(&mut mask);
        } else if self.header_key.is_some() {
            return None;
        }
        (1..=4).find(|&t| {
            let s = self.prefix[t - 1] as usize;
            let size = s + SIZES[t - 1];
            let fits = if t == 4 || self.random_trailers { data.len() >= size } else { data.len() == size };
            fits && {
                let mut h: [u8; 4] = data[s..s + 4].try_into().unwrap();
                for (b, m) in h.iter_mut().zip(mask) {
                    *b ^= m;
                }
                self.header[t - 1].contains(u32::from_le_bytes(h))
            }
        })
    }

    /// The header-protection keystream for a datagram, whose first
    /// [`HEADER_NONCE`] bytes are the nonce. None without a key, or for a
    /// datagram too short to carry one.
    fn header_cipher(&self, datagram: &[u8]) -> Option<ChaCha20> {
        let key = self.header_key.as_ref()?;
        let nonce: &[u8; HEADER_NONCE] = datagram.get(..HEADER_NONCE)?.try_into().ok()?;
        Some(ChaCha20::new(key.into(), nonce.into()))
    }
}

fn label_key(label: &[u8], public: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2s256::new_with_prefix(label);
    h.update(public);
    h.finalize().into()
}

fn mac16(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = Blake2sMac::<U16>::new_from_slice(key).expect("key is at most 32 bytes");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// Checks and rewrites `mac1` on handshake messages addressed to us.
pub struct MyMacs {
    mac1_key: [u8; 32],
}

impl MyMacs {
    pub fn new(my_public: &[u8; 32]) -> Self {
        Self { mac1_key: label_key(b"mac1----", my_public) }
    }

    fn mac1_ok(&self, msg: &[u8]) -> bool {
        let n = msg.len();
        let mut m = Blake2sMac::<U16>::new_from_slice(&self.mac1_key).expect("32-byte key");
        m.update(&msg[..n - 32]);
        m.verify_slice(&msg[n - 32..n - 16]).is_ok()
    }

    fn write_mac1(&self, msg: &mut [u8]) {
        let n = msg.len();
        let mac = mac16(&self.mac1_key, &msg[..n - 32]);
        msg[n - 32..n - 16].copy_from_slice(&mac);
    }
}

/// Writes the MACs on handshake messages to one peer, and keeps the
/// cookie it may send us.
pub struct PeerMacs {
    mac1_key: [u8; 32],
    cookie_key: [u8; 32],
    /// The `mac1` of the last handshake message sent: a cookie reply is
    /// sealed against it.
    last_mac1: Option<[u8; 16]>,
    cookie: Option<([u8; 16], Instant)>,
}

impl PeerMacs {
    pub fn new(peer_public: &[u8; 32]) -> Self {
        Self { mac1_key: label_key(b"mac1----", peer_public), cookie_key: label_key(b"cookie--", peer_public), last_mac1: None, cookie: None }
    }

    fn write_macs(&mut self, msg: &mut [u8], now: Instant) {
        let n = msg.len();
        let mac1 = mac16(&self.mac1_key, &msg[..n - 32]);
        msg[n - 32..n - 16].copy_from_slice(&mac1);
        self.last_mac1 = Some(mac1);
        let mac2 = match self.cookie {
            Some((cookie, until)) if until > now => mac16(&cookie, &msg[..n - 16]),
            _ => [0; 16],
        };
        msg[n - 16..].copy_from_slice(&mac2);
    }

    /// Takes a cookie reply; true if it was for our last handshake message.
    pub fn receive_cookie(&mut self, nonce: &[u8; 24], sealed: &[u8; 32], now: Instant) -> bool {
        let Some(aad) = &self.last_mac1 else { return false };
        let cipher = <XChaCha20Poly1305 as chacha20poly1305::KeyInit>::new(&self.cookie_key.into());
        let Ok(cookie) = cipher.decrypt(nonce.into(), Payload { msg: sealed, aad }) else { return false };
        let Ok(cookie) = <[u8; 16]>::try_from(cookie) else { return false };
        self.cookie = Some((cookie, now + COOKIE_LIFETIME));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const ME: [u8; 32] = [3; 32];
    const SERVER: [u8; 32] = [4; 32];

    fn params() -> Params {
        Params {
            junk_count: 3,
            junk_min: 40,
            junk_max: 70,
            prefix: [7, 9, 3, 5],
            header: [Range { lo: 11, hi: 20 }, Range::one(30), Range { lo: 40, hi: 41 }, Range { lo: 1000, hi: 2000 }],
            signatures: vec![Signature::parse("<b 0x16><r 10>").unwrap()],
            header_key: None,
            random_trailers: false,
        }
    }

    /// AmneziaWG 3: the same, with prefixes long enough for a nonce and a key.
    fn protected() -> Params {
        Params { prefix: [12, 20, 16, 13], header_key: Some([9; 32]), ..params() }
    }

    /// A standard-form message of type `t`, with a valid mac1 for `to`.
    fn message(t: u8, len: usize, to: &[u8; 32]) -> Vec<u8> {
        let mut m = vec![0u8; len];
        let _ = crate::rng::fill(&mut m);
        m[..4].copy_from_slice(&u32::from(t).to_le_bytes());
        if t <= 2 {
            let n = m.len();
            m[n - 32..].fill(0);
            let mac = mac16(&label_key(b"mac1----", to), &m[..n - 32]);
            m[n - 32..n - 16].copy_from_slice(&mac);
        }
        m
    }

    fn header(data: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn ranges() {
        assert_eq!(Range::parse("5"), Ok(Range::one(5)));
        assert_eq!(Range::parse(" 10 - 20 "), Ok(Range { lo: 10, hi: 20 }));
        assert!(Range::parse("20-10").is_err());
        assert!(Range::parse("x").is_err());
        assert!(Range::parse("1-2-3").is_err());
        assert!(Range { lo: 1, hi: 10 }.overlaps(&Range::one(10)));
        assert!(!Range { lo: 1, hi: 10 }.overlaps(&Range::one(11)));
        assert_eq!(format!("{}", Range { lo: 1, hi: 2 }), "1-2");
        crate::rng::seed(&[1; 32]);
        for _ in 0..100 {
            assert!(Range { lo: 40, hi: 41 }.contains(Range { lo: 40, hi: 41 }.pick()));
        }
        // The widest ranges don't overflow.
        let _ = Range { lo: 0, hi: u32::MAX }.pick();
        assert_eq!(Range::one(u32::MAX).pick(), u32::MAX);
    }

    #[test]
    fn signature_templates() {
        crate::rng::seed(&[2; 32]);
        let s = Signature::parse("GET <b 0xc0ffee><r 4> <rc 3><rd 2><t><dz 2><d>").unwrap();
        assert_eq!(s.len(), 18);
        let r = s.render(0x0102_0304);
        assert_eq!(r.len(), 18);
        assert_eq!(&r[..3], &[0xc0, 0xff, 0xee]);
        assert!(r[7..10].iter().all(u8::is_ascii_alphabetic));
        assert!(r[10..12].iter().all(u8::is_ascii_digit));
        assert_eq!(&r[12..16], &[1, 2, 3, 4]);
        assert_eq!(&r[16..], &[0, 0]);
        for bad in ["", "abc", "<>", "<x 1>", "<b 0xabc>", "<b>", "<r>", "<r x>", "<b 0x12", "<r 2000>"] {
            assert!(Signature::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn validation() {
        assert!(params().validate().is_ok());
        assert!(Params::default().validate().is_ok());
        assert!(Params::default().is_plain());
        assert!(!params().is_plain());
        let p = |f: fn(&mut Params)| {
            let mut p = params();
            f(&mut p);
            p.validate().unwrap_err()
        };
        assert!(p(|p| p.junk_min = 80).contains("Jmin"));
        assert!(p(|p| p.junk_max = 2000).contains("Jmax"));
        assert!(p(|p| p.junk_count = 1000).contains("Jc"));
        assert!(p(|p| p.prefix[3] = 1000).contains("S4"));
        assert!(p(|p| p.header[2] = Range { lo: 5, hi: 15 }).contains("H1 11-20 and H3 5-15 overlap"));
        // Jmin/Jmax without Jc change nothing on the wire.
        let mut quiet = Params::default();
        quiet.junk_max = 50;
        assert!(quiet.is_plain());
    }

    #[test]
    fn handshake_messages_round_trip_with_fresh_macs() {
        crate::rng::seed(&[3; 32]);
        let p = params();
        let now = Instant::from_nanos(1_000_000_000);
        let mut to_server = PeerMacs::new(&SERVER);
        let server = MyMacs::new(&SERVER);
        for (t, len, s, h) in [(1u8, 148usize, 7usize, 0usize), (2, 92, 9, 1)] {
            let std = message(t, len, &SERVER);
            let wire = p.wrap(&std, &mut to_server, now);
            assert_eq!(wire.len(), s + len);
            assert!(p.header[h].contains(header(&wire, s)), "type {t}");
            // The disguised message carries a mac1 over the disguised bytes...
            assert!(server.mac1_ok(&wire[s..]));
            assert_eq!(&wire[s + 4..s + len - 32], &std[4..len - 32]);
            // ...and comes back as the standard message, mac1 and all.
            assert_eq!(p.unwrap(&wire, &server), Inbound::Message(std.clone()));
        }
    }

    #[test]
    fn transport_messages_only_change_their_header() {
        crate::rng::seed(&[4; 32]);
        let p = params();
        let now = Instant::from_nanos(1_000_000_000);
        let mut macs = PeerMacs::new(&SERVER);
        let me = MyMacs::new(&ME);
        for len in [32usize, 100, 1400] {
            let std = message(4, len, &SERVER);
            let wire = p.wrap(&std, &mut macs, now);
            assert_eq!(wire.len(), 5 + len);
            assert!(p.header[3].contains(header(&wire, 5)));
            assert_eq!(&wire[9..], &std[4..]);
            assert_eq!(p.unwrap(&wire, &me), Inbound::Message(std));
        }
        // Plain parameters leave everything as it was (bytes and MACs).
        let plain = Params::default();
        let std = message(1, 148, &SERVER);
        assert_eq!(plain.wrap(&std, &mut macs, now), std);
    }

    #[test]
    fn junk_and_tampering_are_dropped() {
        crate::rng::seed(&[5; 32]);
        let p = params();
        let now = Instant::from_nanos(1_000_000_000);
        let mut macs = PeerMacs::new(&SERVER);
        let server = MyMacs::new(&SERVER);
        for junk in p.preamble(0) {
            assert_eq!(p.unwrap(&junk, &server), Inbound::Junk);
        }
        let wire = p.wrap(&message(1, 148, &SERVER), &mut macs, now);
        assert!(matches!(p.unwrap(&wire, &server), Inbound::Message(_)));
        let mut bad = wire.clone();
        bad[7..11].copy_from_slice(&21u32.to_le_bytes()); // header outside H1
        assert_eq!(p.unwrap(&bad, &server), Inbound::Junk);
        let mut bad = wire.clone();
        bad[20] ^= 1; // body changed: mac1 fails
        assert_eq!(p.unwrap(&bad, &server), Inbound::Junk);
        assert_eq!(p.unwrap(&wire[..wire.len() - 1], &server), Inbound::Junk);
        assert_eq!(p.unwrap(&wire, &MyMacs::new(&ME)), Inbound::Junk, "not addressed to us");
        // A plain WireGuard message doesn't pass as AmneziaWG.
        assert_eq!(p.unwrap(&message(1, 148, &SERVER), &server), Inbound::Junk);
        assert_eq!(p.unwrap(&message(4, 100, &SERVER), &server), Inbound::Junk);
        assert_eq!(p.unwrap(&[], &server), Inbound::Junk);
    }

    #[test]
    fn preamble_is_signatures_then_junk() {
        crate::rng::seed(&[6; 32]);
        let p = params();
        let pre = p.preamble(7);
        assert_eq!(pre.len(), 4);
        assert_eq!(pre[0].len(), 11);
        assert_eq!(pre[0][0], 0x16);
        for junk in &pre[1..] {
            assert!((40..70).contains(&junk.len()), "{}", junk.len());
        }
        let mut same = params();
        same.junk_min = 50;
        same.junk_max = 50;
        assert!(same.preamble(0)[1..].iter().all(|j| j.len() == 50));
        assert!(Params::default().preamble(0).is_empty());
    }

    #[test]
    fn cookie_replies_give_the_next_initiation_a_mac2() {
        crate::rng::seed(&[8; 32]);
        let p = params();
        let now = Instant::from_nanos(1_000_000_000);
        let mut to_server = PeerMacs::new(&SERVER);
        let server = MyMacs::new(&SERVER);
        let me = MyMacs::new(&ME);
        let init = p.wrap(&message(1, 148, &SERVER), &mut to_server, now);
        assert_eq!(&init[init.len() - 16..], &[0; 16], "no cookie yet");
        // The server, under load, answers with a cookie sealed against the
        // mac1 it saw, and wrapped like any other message (S3, H3).
        let cookie = [0xab; 16];
        let nonce = [0xcd; 24];
        let mac1_seen: [u8; 16] = init[init.len() - 32..init.len() - 16].try_into().unwrap();
        let cipher = <XChaCha20Poly1305 as chacha20poly1305::KeyInit>::new(&label_key(b"cookie--", &SERVER).into());
        let sealed = cipher.encrypt(&nonce.into(), Payload { msg: &cookie, aad: &mac1_seen }).unwrap();
        let mut reply = vec![3u8, 0, 0, 0, 1, 0, 0, 0];
        reply.extend_from_slice(&nonce);
        reply.extend_from_slice(&sealed);
        let reply = p.wrap(&reply, &mut PeerMacs::new(&ME), now);
        assert_eq!(reply.len(), 3 + 64);
        let Inbound::CookieReply { nonce: n, sealed: s } = p.unwrap(&reply, &me) else { panic!("not a cookie reply") };
        assert_eq!(n, nonce);
        assert!(!PeerMacs::new(&SERVER).receive_cookie(&n, &s, now), "no handshake sent");
        assert!(!to_server.receive_cookie(&[0; 24], &s, now), "wrong nonce");
        assert!(to_server.receive_cookie(&n, &s, now));
        // The next initiation carries mac2 = MAC(cookie, message up to mac2).
        let again = p.wrap(&message(1, 148, &SERVER), &mut to_server, now + Duration::from_secs(1));
        let n = again.len();
        assert_eq!(&again[n - 16..], &mac16(&cookie, &again[7..n - 16]));
        assert!(server.mac1_ok(&again[7..]));
        // Cookies expire.
        let later = p.wrap(&message(1, 148, &SERVER), &mut to_server, now + Duration::from_secs(121));
        assert_eq!(&later[later.len() - 16..], &[0; 16]);
    }

    /// The keystream as amneziawg-go derives it (ChaCha20, IETF nonce, counter 0).
    fn keystream(key: &[u8; 32], nonce: &[u8], n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        ChaCha20::new(key.into(), nonce[..12].into()).apply_keystream(&mut out);
        out
    }

    #[test]
    fn header_protection_hides_every_message_and_round_trips() {
        crate::rng::seed(&[9; 32]);
        let p = protected();
        let now = Instant::from_nanos(1_000_000_000);
        let mut to_server = PeerMacs::new(&SERVER);
        let server = MyMacs::new(&SERVER);
        let key = p.header_key.unwrap();
        for (t, len, s) in [(1u8, 148usize, 12usize), (2, 92, 20), (3, 64, 16), (4, 32, 13), (4, 1400, 13)] {
            let std = message(t, len, &SERVER);
            let wire = p.wrap(&std, &mut to_server, now);
            assert_eq!(wire.len(), s + len, "type {t}");
            // The nonce is the start of the prefix; under the keystream the
            // header is in range, and the plain header value never shows.
            let ks = keystream(&key, &wire[..12], len);
            let h = u32::from_le_bytes([wire[s] ^ ks[0], wire[s + 1] ^ ks[1], wire[s + 2] ^ ks[2], wire[s + 3] ^ ks[3]]);
            assert!(p.header[usize::from(t) - 1].contains(h), "type {t}: {h}");
            assert_eq!(p.classify(&wire), Some(usize::from(t)));
            let covered = if t == 4 { 16 } else { len };
            assert_eq!(&wire[s + covered..], &std[covered..], "type {t}: only {covered} bytes are encrypted");
            let decrypted: Vec<u8> = wire[s..s + covered].iter().zip(&ks).map(|(a, b)| a ^ b).collect();
            if t <= 2 {
                assert!(server.mac1_ok(&[&decrypted[..], &wire[s + covered..]].concat()), "mac1 covers the disguised, unencrypted message");
            }
            match (t, p.unwrap(&wire, &server)) {
                (3, Inbound::CookieReply { nonce, sealed }) => {
                    assert_eq!(nonce[..], std[8..32]);
                    assert_eq!(sealed[..], std[32..64]);
                }
                (3, other) => panic!("cookie reply came back as {other:?}"),
                (_, got) => assert_eq!(got, Inbound::Message(std.clone()), "type {t}"),
            }
        }
    }

    #[test]
    fn header_protection_keys_must_match() {
        crate::rng::seed(&[10; 32]);
        let p = protected();
        let now = Instant::from_nanos(1_000_000_000);
        let server = MyMacs::new(&SERVER);
        let init = p.wrap(&message(1, 148, &SERVER), &mut PeerMacs::new(&SERVER), now);
        let data = p.wrap(&message(4, 100, &SERVER), &mut PeerMacs::new(&SERVER), now);
        let mut other = protected();
        other.header_key = Some([10; 32]);
        let mut none = protected();
        none.header_key = None;
        for q in [other, none] {
            assert_eq!(q.unwrap(&init, &server), Inbound::Junk);
            assert_eq!(q.unwrap(&data, &server), Inbound::Junk);
            assert_eq!(p.unwrap(&q.wrap(&message(1, 148, &SERVER), &mut PeerMacs::new(&SERVER), now), &server), Inbound::Junk);
        }
        // A flipped bit anywhere in a handshake message fails mac1.
        let mut bad = init.clone();
        bad[12 + 60] ^= 1;
        assert_eq!(p.unwrap(&bad, &server), Inbound::Junk);
        assert_eq!(p.unwrap(&init[..11], &server), Inbound::Junk);
        assert_eq!(p.unwrap(&[], &server), Inbound::Junk);
        // Short prefixes can't carry the nonce.
        let mut short = protected();
        short.prefix[2] = 11;
        assert_eq!(short.validate(), Err("S3 11: HeaderProtectionKey needs S1-S4 of at least 12".to_string()));
        assert!(protected().validate().is_ok());
        assert!(!protected().is_plain());
        assert!(protected().summary().contains("header protection on trailers off"));
        assert!(params().summary().contains("header protection off"));
    }

    #[test]
    fn random_trailers_are_accepted_only_when_enabled() {
        crate::rng::seed(&[11; 32]);
        let now = Instant::from_nanos(1_000_000_000);
        let server = MyMacs::new(&SERVER);
        for p in [params(), protected()] {
            let mut trailed = Params { random_trailers: true, ..p.clone() };
            for (t, len) in [(1u8, 148usize), (2, 92), (3, 64)] {
                let std = message(t, len, &SERVER);
                let mut wire = p.wrap(&std, &mut PeerMacs::new(&SERVER), now);
                wire.extend_from_slice(&[0x5a; 37]);
                assert_eq!(p.unwrap(&wire, &server), Inbound::Junk, "type {t}: a trailer is junk unless enabled");
                let got = trailed.unwrap(&wire, &server);
                match t {
                    3 => assert!(matches!(got, Inbound::CookieReply { .. }), "type {t}"),
                    _ => assert_eq!(got, Inbound::Message(std), "type {t}: the trailer is dropped"),
                }
                // Without the trailer it still works, and the message is not
                // confused with a longer one.
                assert_ne!(trailed.unwrap(&wire[..wire.len() - 37], &server), Inbound::Junk);
            }
            trailed.random_trailers = false;
            assert!(!Params { random_trailers: true, ..Params::default() }.is_plain());
        }
    }
}
