//! Monotonic time supplied by the driver. The core never reads a clock.

use core::ops::Add;
use core::time::Duration;

/// A point on the driver's monotonic clock: nanoseconds since an origin of
/// the driver's choosing. Only differences between instants mean anything.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Instant(u64);

impl Instant {
    pub const fn from_nanos(nanos: u64) -> Self {
        Instant(nanos)
    }

    pub const fn from_millis(millis: u64) -> Self {
        Instant(millis.saturating_mul(1_000_000))
    }

    pub const fn as_nanos(&self) -> u64 {
        self.0
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    /// Saturates at the end of the clock (584 years).
    fn add(self, rhs: Duration) -> Instant {
        Instant(self.0.saturating_add(u64::try_from(rhs.as_nanos()).unwrap_or(u64::MAX)))
    }
}
