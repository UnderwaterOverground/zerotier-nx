//! The sans-IO core beside ZeroTier's: the userspace TCP/IP stack homebrew
//! sockets are mapped onto, the Ethernet layer between it and ZeroTier, and
//! TLS for the update check.
//!
//! This crate never performs I/O, reads clocks, or spawns threads. Drivers
//! (the host tools, the sysmodule) feed it bytes and time and drain the work
//! it wants done. That keeps every path testable with plain `cargo test` on
//! the development machine.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

/// Gives back a buffer's spare capacity. Buffers that grew for a burst (a
/// full netmap, a backlog of TLS records) otherwise keep that size for the
/// connection's lifetime; on the Switch every such byte is sysmodule heap.
/// Called periodically ([`stack::Stack::end`]), not per read, so
/// a busy stream doesn't reallocate on every packet.
pub(crate) fn trim_vec<T>(v: &mut alloc::vec::Vec<T>) {
    if v.capacity() > v.len() + 256 {
        v.shrink_to(v.len());
    }
}

pub mod crypto;
pub mod l2;
pub mod netstack;
pub mod rng;
pub mod stack;
pub mod time;
pub mod tls;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
