//! TCP sequence-number arithmetic (RFC 9293 §3.4).
//!
//! All comparisons are modulo 2^32 and valid only when the compared numbers
//! are within 2^31 of each other — guaranteed by TCP's window rules.
//! Deliberately *not* `PartialOrd`: ordinary `<` on sequence numbers is the
//! classic wraparound bug, so comparisons must be spelled out.

/// A TCP sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct SeqNr(pub u32);

impl SeqNr {
    /// `self + n` modulo 2^32.
    #[inline]
    #[must_use]
    pub const fn add(self, n: u32) -> SeqNr {
        SeqNr(self.0.wrapping_add(n))
    }

    /// `self - n` modulo 2^32.
    #[inline]
    #[must_use]
    pub const fn sub(self, n: u32) -> SeqNr {
        SeqNr(self.0.wrapping_sub(n))
    }

    /// Bytes from `earlier` to `self` modulo 2^32 (callers must know
    /// `earlier` precedes `self`).
    #[inline]
    pub const fn since(self, earlier: SeqNr) -> u32 {
        self.0.wrapping_sub(earlier.0)
    }

    /// `self < other` in sequence space.
    #[inline]
    pub const fn lt(self, other: SeqNr) -> bool {
        (other.0.wrapping_sub(self.0) as i32) > 0
    }

    /// `self <= other` in sequence space.
    #[inline]
    pub const fn le(self, other: SeqNr) -> bool {
        !other.lt(self)
    }

    /// `self > other` in sequence space.
    #[inline]
    pub const fn gt(self, other: SeqNr) -> bool {
        other.lt(self)
    }

    /// `self >= other` in sequence space.
    #[inline]
    pub const fn ge(self, other: SeqNr) -> bool {
        !self.lt(other)
    }

    /// The later of two sequence numbers.
    #[inline]
    #[must_use]
    pub const fn max(self, other: SeqNr) -> SeqNr {
        if self.ge(other) { self } else { other }
    }

    /// The earlier of two sequence numbers.
    #[inline]
    #[must_use]
    pub const fn min(self, other: SeqNr) -> SeqNr {
        if self.le(other) { self } else { other }
    }

    /// RFC 9293 §3.4 window test: `start <= self < start + len`.
    #[inline]
    pub const fn in_window(self, start: SeqNr, len: u32) -> bool {
        self.since(start) < len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_across_wraparound() {
        let a = SeqNr(u32::MAX - 1);
        let b = a.add(10); // wraps to 8
        assert_eq!(b, SeqNr(8));
        assert!(a.lt(b) && b.gt(a) && a.le(b) && b.ge(a));
        assert!(!b.lt(a));
        assert_eq!(b.since(a), 10);
        assert_eq!(b.sub(10), a);
        assert_eq!(a.max(b), b);
        assert_eq!(a.min(b), a);
    }

    #[test]
    fn window_membership() {
        let start = SeqNr(u32::MAX - 4);
        assert!(start.in_window(start, 1));
        assert!(start.add(9).in_window(start, 10));
        assert!(!start.add(10).in_window(start, 10));
        assert!(!start.sub(1).in_window(start, 10));
        // Zero-length window contains nothing.
        assert!(!start.in_window(start, 0));
    }

    #[test]
    fn equal_is_not_less() {
        let a = SeqNr(1000);
        assert!(a.le(a) && a.ge(a) && !a.lt(a) && !a.gt(a));
    }

    /// Cross-check against the characterizations proved in Coq
    /// (`formal/seq_arith.v`): lt ⟺ forward distance in [1, 2³¹−1];
    /// le ⟺ distance ≤ 2³¹ (antipode included); `since` IS the forward
    /// distance; `in_window` compares it to the length; add/since
    /// round-trips. Exhaustive over a lattice of wraparound/antipode
    /// boundary values, so the hand-mirrored Coq definitions and this code
    /// cannot drift apart silently at the values where they could disagree.
    #[test]
    fn coq_characterizations_hold_on_boundary_lattice() {
        const HW: u64 = 1 << 31;
        const W: u64 = 1 << 32;
        let pts = [
            0u32,
            1,
            2,
            0x7FFF_FFFE,
            0x7FFF_FFFF, // HW - 1
            0x8000_0000, // HW (the antipode distance pivot)
            0x8000_0001,
            0xFFFF_FFFE,
            0xFFFF_FFFF,
            12_345,
            0xDEAD_BEEF,
        ];
        for &a in &pts {
            for &b in &pts {
                let (sa, sb) = (SeqNr(a), SeqNr(b));
                let d = (u64::from(b) + W - u64::from(a)) % W; // forward distance
                assert_eq!(sa.lt(sb), (1..HW).contains(&d), "ltb_charact {a:#x} {b:#x}");
                assert_eq!(sa.le(sb), d <= HW, "leb_charact {a:#x} {b:#x}");
                assert_eq!(u64::from(sb.since(sa)), d, "since is the distance");
                assert_eq!(sa.add(sb.since(sa)), sb, "since_add round-trip");
                for len in [0u32, 1, 5, u32::MAX] {
                    assert_eq!(
                        sb.in_window(sa, len),
                        d < u64::from(len),
                        "in_window_spec {a:#x} {b:#x} {len}"
                    );
                }
            }
        }
    }
}
