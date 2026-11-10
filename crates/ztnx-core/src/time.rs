//! Monotonic time supplied by the driver. The core never reads a clock.

/// A point on the driver's monotonic clock (nanoseconds since an arbitrary
/// origin). Shared with the vendored tailscale-rs crates.
pub use ts_time::Instant;
