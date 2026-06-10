//! Virtual time.
//!
//! The protocol core never reads a clock. The runtime owns real time and
//! passes logical time into every entry point; the core only does arithmetic
//! on these values. This is what makes deterministic replay possible.

use core::ops::{Add, AddAssign, Sub};

/// A point in logical time, in microseconds since an arbitrary runtime epoch.
///
/// The epoch is owned by the runtime; the core only ever compares instants
/// and adds durations to them. Monotonicity is an explicit assumption:
/// the runtime must never hand the core an `Instant` earlier than one it has
/// already handed it (Assumption A-TIME-1 in `docs/TRACEABILITY.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    micros: u64,
}

impl Instant {
    /// The zero instant (the runtime epoch).
    pub const ZERO: Instant = Instant { micros: 0 };

    /// Construct from microseconds since the runtime epoch.
    #[inline]
    pub const fn from_micros(micros: u64) -> Self {
        Instant { micros }
    }

    /// Construct from milliseconds since the runtime epoch.
    #[inline]
    pub const fn from_millis(millis: u64) -> Self {
        Instant { micros: millis * 1_000 }
    }

    /// Construct from seconds since the runtime epoch.
    #[inline]
    pub const fn from_secs(secs: u64) -> Self {
        Instant { micros: secs * 1_000_000 }
    }

    /// Microseconds since the runtime epoch.
    #[inline]
    pub const fn as_micros(self) -> u64 {
        self.micros
    }

    /// Time elapsed since `earlier`, saturating to zero if `earlier` is later.
    #[inline]
    pub const fn saturating_since(self, earlier: Instant) -> Duration {
        Duration { micros: self.micros.saturating_sub(earlier.micros) }
    }
}

/// A span of logical time, in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration {
    micros: u64,
}

impl Duration {
    /// The zero-length duration.
    pub const ZERO: Duration = Duration { micros: 0 };

    /// Construct from microseconds.
    #[inline]
    pub const fn from_micros(micros: u64) -> Self {
        Duration { micros }
    }

    /// Construct from milliseconds.
    #[inline]
    pub const fn from_millis(millis: u64) -> Self {
        Duration { micros: millis * 1_000 }
    }

    /// Construct from seconds.
    #[inline]
    pub const fn from_secs(secs: u64) -> Self {
        Duration { micros: secs * 1_000_000 }
    }

    /// Total microseconds.
    #[inline]
    pub const fn as_micros(self) -> u64 {
        self.micros
    }

    /// Total whole milliseconds.
    #[inline]
    pub const fn as_millis(self) -> u64 {
        self.micros / 1_000
    }

    /// Saturating multiplication by an integer factor.
    #[inline]
    pub const fn saturating_mul(self, rhs: u32) -> Duration {
        Duration { micros: self.micros.saturating_mul(rhs as u64) }
    }

    /// Integer division.
    #[inline]
    pub const fn div(self, rhs: u32) -> Duration {
        Duration { micros: self.micros / rhs as u64 }
    }

    /// Saturating addition.
    #[inline]
    pub const fn saturating_add(self, rhs: Duration) -> Duration {
        Duration { micros: self.micros.saturating_add(rhs.micros) }
    }

    /// Saturating subtraction.
    #[inline]
    pub const fn saturating_sub(self, rhs: Duration) -> Duration {
        Duration { micros: self.micros.saturating_sub(rhs.micros) }
    }

    /// The larger of two durations.
    #[inline]
    pub const fn max(self, rhs: Duration) -> Duration {
        if self.micros >= rhs.micros { self } else { rhs }
    }

    /// The smaller of two durations.
    #[inline]
    pub const fn min(self, rhs: Duration) -> Duration {
        if self.micros <= rhs.micros { self } else { rhs }
    }

    /// Clamp into `[lo, hi]`.
    #[inline]
    pub const fn clamp(self, lo: Duration, hi: Duration) -> Duration {
        self.max(lo).min(hi)
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;
    #[inline]
    fn add(self, rhs: Duration) -> Instant {
        Instant { micros: self.micros.saturating_add(rhs.micros) }
    }
}

impl AddAssign<Duration> for Instant {
    #[inline]
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;
    /// Saturating: returns `Duration::ZERO` if `rhs` is later than `self`.
    #[inline]
    fn sub(self, rhs: Instant) -> Duration {
        self.saturating_since(rhs)
    }
}

impl Add<Duration> for Duration {
    type Output = Duration;
    #[inline]
    fn add(self, rhs: Duration) -> Duration {
        self.saturating_add(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic() {
        let t0 = Instant::from_millis(100);
        let t1 = t0 + Duration::from_millis(50);
        assert_eq!(t1.as_micros(), 150_000);
        assert_eq!((t1 - t0).as_millis(), 50);
        assert_eq!((t0 - t1), Duration::ZERO); // saturating
        assert_eq!(Duration::from_secs(1).saturating_mul(2).as_millis(), 2000);
        let d = Duration::from_millis(500);
        assert_eq!(d.clamp(Duration::from_secs(1), Duration::from_secs(60)), Duration::from_secs(1));
    }
}
