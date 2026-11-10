//! X25519, for the TLS key exchange (`tls::provider`).

/// X25519 scalar multiplication (RFC 7748).
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*scalar, *point)
}

/// Derives the X25519 public key for a private scalar.
pub fn x25519_public(scalar: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*scalar, x25519_dalek::X25519_BASEPOINT_BYTES)
}
