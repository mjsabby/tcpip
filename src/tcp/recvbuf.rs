//! Fixed-capacity receive buffer with bounded out-of-order tracking.
//!
//! A byte ring whose offset 0 is the next byte the application will read.
//! In-order data extends `readable`; out-of-order data is written at its
//! offset within the window and tracked in a bounded range list, which also
//! feeds the SACK blocks we advertise (RFC 2018 §3/§4).
//!
//! Invariants (`check_invariants`, exercised by tests and the fuzz harness):
//! ranges are sorted, disjoint, non-adjacent, start beyond `readable`, and
//! end within the buffer.
//!
//! Capacity `CAP` is const-generic (see [`crate::tcp::sendbuf`] for the
//! rationale); the out-of-order range budget [`MAX_OOO_RANGES`] is a separate
//! fixed bound.

use crate::config::MAX_OOO_RANGES;
use crate::util::BoundedVec;

/// One out-of-order range, offsets relative to the ring start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Range {
    start: u32,
    end: u32,
    /// Insertion recency; RFC 2018 §4 wants the most recent block first.
    stamp: u32,
}

/// Receive-side byte ring of capacity `CAP` plus reassembly bookkeeping.
pub struct RecvBuffer<const CAP: usize> {
    buf: [u8; CAP],
    /// Ring index of offset 0.
    start: usize,
    /// Contiguous bytes ready for the application (offset 0..readable).
    readable: u32,
    /// Out-of-order ranges beyond `readable`.
    ranges: BoundedVec<Range, MAX_OOO_RANGES>,
    stamp: u32,
}

impl<const CAP: usize> Default for RecvBuffer<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of inserting received bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inserted {
    /// How far the contiguous edge (RCV.NXT) advanced.
    pub advance: u32,
    /// False if the bytes had to be dropped (out-of-order budget exhausted);
    /// the peer will retransmit. The window never overflows by construction.
    pub stored: bool,
}

impl<const CAP: usize> RecvBuffer<CAP> {
    /// An empty buffer.
    pub fn new() -> Self {
        RecvBuffer {
            buf: [0; CAP],
            start: 0,
            readable: 0,
            ranges: BoundedVec::new(),
            stamp: 0,
        }
    }

    /// Total capacity in bytes.
    pub const fn capacity(&self) -> usize {
        CAP
    }

    /// Bytes ready for the application.
    pub fn readable(&self) -> usize {
        self.readable as usize
    }

    /// Window to advertise: free space beyond the contiguous edge.
    /// Out-of-order data lives inside this window, so it does not shrink it.
    pub fn window(&self) -> u32 {
        CAP as u32 - self.readable
    }

    /// Insert `data` whose first byte is `off` bytes past RCV.NXT… measured
    /// from the ring start: `off` is relative to offset 0 (the unread edge),
    /// i.e. `off == readable` for exactly-in-order data. Caller has already
    /// trimmed `data` to the advertised window, so it always fits the ring.
    pub fn insert(&mut self, off: u32, data: &[u8]) -> Inserted {
        debug_assert!(off >= self.readable, "caller trims below RCV.NXT");
        let end = off + data.len() as u32;
        debug_assert!(end as usize <= CAP, "caller trims to window");
        if data.is_empty() {
            return Inserted { advance: 0, stored: true };
        }

        // Write the bytes at their position in the ring.
        let from = (self.start + off as usize) % CAP;
        let first = data.len().min(CAP - from);
        self.buf[from..from + first].copy_from_slice(&data[..first]);
        self.buf[..data.len() - first].copy_from_slice(&data[first..]);

        // Merge [off, end) into the range list (coalescing overlaps and
        // adjacency), then absorb anything now contiguous with `readable`.
        self.stamp = self.stamp.wrapping_add(1);
        let mut new = Range { start: off, end, stamp: self.stamp };
        let mut merged: BoundedVec<Range, MAX_OOO_RANGES> = BoundedVec::new();
        let mut placed = false;
        let mut overflow = false;
        for &r in self.ranges.iter() {
            if r.end < new.start || new.end < r.start {
                // Disjoint and non-adjacent.
                if r.start > new.end && !placed {
                    overflow |= merged.push(new).is_err();
                    placed = true;
                }
                overflow |= merged.push(r).is_err();
            } else {
                // Overlapping or adjacent: coalesce into `new`.
                new.start = new.start.min(r.start);
                new.end = new.end.max(r.end);
            }
        }
        if !placed {
            overflow |= merged.push(new).is_err();
        }
        if overflow {
            // Out-of-order budget exhausted: drop the new bytes, keep the
            // previous consistent state (peer retransmits; bounded memory
            // beats completeness here).
            return Inserted { advance: 0, stored: false };
        }
        self.ranges = merged;

        let mut advance = 0;
        if let Some(&first_range) = self.ranges.iter().next()
            && first_range.start <= self.readable
        {
            advance = first_range.end - self.readable;
            self.readable = first_range.end;
            self.ranges.remove(0);
        }
        self.check_invariants();
        Inserted { advance, stored: true }
    }

    /// Copy out up to `out.len()` readable bytes, freeing window space.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.readable as usize);
        let first = n.min(CAP - self.start);
        out[..first].copy_from_slice(&self.buf[self.start..self.start + first]);
        out[first..n].copy_from_slice(&self.buf[..n - first]);
        self.start = (self.start + n) % CAP;
        self.readable -= n as u32;
        // Offsets are relative to the ring start, which just moved.
        for r in self.ranges.as_mut_slice() {
            r.start -= n as u32;
            r.end -= n as u32;
        }
        self.check_invariants();
        n
    }

    /// Out-of-order ranges as offsets relative to RCV.NXT, most recent
    /// first (for SACK generation; RFC 2018 §4). Returns up to `max`
    /// `(start, end)` pairs via the provided buffer.
    pub fn sack_ranges<const N: usize>(&self, out: &mut BoundedVec<(u32, u32), N>) {
        out.clear();
        // Most recently updated first.
        let mut order: BoundedVec<usize, MAX_OOO_RANGES> = BoundedVec::new();
        for i in 0..self.ranges.len() {
            let _ = order.push(i);
        }
        order.as_mut_slice().sort_unstable_by_key(|&i| {
            // Newest stamp first.
            u32::MAX - self.ranges[i].stamp
        });
        for &i in order.iter() {
            let r = self.ranges[i];
            if out.push((r.start - self.readable, r.end - self.readable)).is_err() {
                break;
            }
        }
    }

    fn check_invariants(&self) {
        #[cfg(debug_assertions)]
        {
            let mut prev_end = self.readable;
            for r in self.ranges.iter() {
                debug_assert!(r.start > prev_end, "ranges sorted/disjoint/non-adjacent");
                debug_assert!(r.start < r.end);
                debug_assert!(r.end as usize <= CAP);
                prev_end = r.end;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small capacity keeps the tests legible; the logic is size-independent.
    const CAP: usize = 256;

    #[test]
    fn in_order_flow() {
        let mut b: RecvBuffer<CAP> = RecvBuffer::new();
        assert_eq!(b.insert(0, b"hello"), Inserted { advance: 5, stored: true });
        assert_eq!(b.readable(), 5);
        assert_eq!(b.window(), (CAP - 5) as u32);
        let mut out = [0u8; 8];
        assert_eq!(b.read(&mut out), 5);
        assert_eq!(&out[..5], b"hello");
        assert_eq!(b.window(), CAP as u32);
    }

    #[test]
    fn out_of_order_merge_and_sack() {
        let mut b: RecvBuffer<CAP> = RecvBuffer::new();
        // Hole at [0,5); store [5,10) then [12,15).
        assert_eq!(b.insert(5, b"BBBBB"), Inserted { advance: 0, stored: true });
        assert_eq!(b.insert(12, b"DDD"), Inserted { advance: 0, stored: true });
        let mut blocks: BoundedVec<(u32, u32), 4> = BoundedVec::new();
        b.sack_ranges(&mut blocks);
        // Most recent first.
        assert_eq!(blocks.as_slice(), &[(12, 15), (5, 10)]);
        // Bridge [10,12): coalesces to [5,15).
        assert_eq!(b.insert(10, b"CC"), Inserted { advance: 0, stored: true });
        b.sack_ranges(&mut blocks);
        assert_eq!(blocks.as_slice(), &[(5, 15)]);
        // Fill the head: everything becomes readable.
        assert_eq!(b.insert(0, b"AAAAA"), Inserted { advance: 15, stored: true });
        assert_eq!(b.readable(), 15);
        let mut out = [0u8; 15];
        b.read(&mut out);
        assert_eq!(&out, b"AAAAABBBBBCCDDD");
    }

    #[test]
    fn duplicate_and_overlap_are_idempotent() {
        let mut b: RecvBuffer<CAP> = RecvBuffer::new();
        b.insert(3, b"xyz");
        b.insert(3, b"xyz"); // exact duplicate
        b.insert(2, b"wxyzA"); // overlaps + extends both sides
        let mut blocks: BoundedVec<(u32, u32), 4> = BoundedVec::new();
        b.sack_ranges(&mut blocks);
        assert_eq!(blocks.as_slice(), &[(2, 7)]);
        b.insert(0, b"ab");
        assert_eq!(b.readable(), 7);
        let mut out = [0u8; 7];
        b.read(&mut out);
        assert_eq!(&out, b"abwxyzA");
    }

    #[test]
    fn ooo_budget_exhaustion_drops_new_bytes() {
        let mut b: RecvBuffer<CAP> = RecvBuffer::new();
        // MAX_OOO_RANGES disjoint ranges (each separated by a 1-byte hole).
        for i in 0..MAX_OOO_RANGES as u32 {
            assert!(b.insert(1 + i * 3, &[7, 7]).stored);
        }
        // One more disjoint range cannot be tracked.
        let r = b.insert(1 + MAX_OOO_RANGES as u32 * 3, &[7, 7]);
        assert!(!r.stored);
        // But coalescing inserts still work.
        assert!(b.insert(1, &[7, 7, 7]).stored);
    }

    #[test]
    fn read_shifts_pending_ranges() {
        let mut b: RecvBuffer<CAP> = RecvBuffer::new();
        b.insert(0, b"abc");
        b.insert(5, b"zz");
        let mut out = [0u8; 2];
        b.read(&mut out); // ranges shift down by 2
        let mut blocks: BoundedVec<(u32, u32), 4> = BoundedVec::new();
        b.sack_ranges(&mut blocks);
        // Relative to RCV.NXT (readable edge = 1 now): hole [1,3), data [3,5).
        assert_eq!(blocks.as_slice(), &[(2, 4)]);
    }

    #[test]
    fn ring_wraparound_preserves_bytes() {
        let mut b: RecvBuffer<CAP> = RecvBuffer::new();
        let big = std::vec![1u8; CAP - 4];
        assert_eq!(b.insert(0, &big).advance as usize, big.len());
        let mut sink = std::vec![0u8; big.len()];
        b.read(&mut sink);
        // Ring start is now near the end; this insert wraps.
        let pattern: std::vec::Vec<u8> = (0..32).collect();
        assert_eq!(b.insert(0, &pattern).advance, 32);
        let mut out = [0u8; 32];
        b.read(&mut out);
        assert_eq!(&out[..], &pattern[..]);
    }
}
