//! Send-side SACK scoreboard (RFC 2018, supporting RFC 6675-style recovery).
//!
//! Tracks which ranges above SND.UNA the peer has selectively acknowledged.
//! Per RFC 2018 §8 the data receiver may renege, so SACKed ranges are purely
//! advisory: bytes are never released from the send buffer until cumulatively
//! acknowledged, and the scoreboard is cleared on RTO.

use super::seq::SeqNr;
use crate::config::MAX_SACK_RANGES;
use crate::util::BoundedVec;

/// Send-side scoreboard of SACKed ranges, sorted, disjoint, within
/// `(SND.UNA, SND.NXT]`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SackScoreboard {
    ranges: BoundedVec<(SeqNr, SeqNr), MAX_SACK_RANGES>,
}

impl SackScoreboard {
    /// Empty scoreboard.
    pub fn new() -> Self {
        SackScoreboard {
            ranges: BoundedVec::new(),
        }
    }

    /// Ingest the SACK blocks of one ACK. Returns true if any *new* range
    /// was learned (used for duplicate-ACK accounting per RFC 6675 §2).
    pub fn ingest(&mut self, blocks: &[(u32, u32)], snd_una: SeqNr, snd_nxt: SeqNr) -> bool {
        let mut learned = false;
        for &(l, r) in blocks {
            let (mut l, r) = (SeqNr(l), SeqNr(r));
            if l.ge(r) {
                continue; // malformed block
            }
            if r.le(snd_una) {
                continue; // D-SACK / stale: below the cumulative point
            }
            if r.gt(snd_nxt) || l.lt(snd_una.sub(1 << 20)) {
                continue; // acknowledges data never sent / absurdly old
            }
            if l.lt(snd_una) {
                l = snd_una;
            }
            learned |= self.merge(l, r);
        }
        learned
    }

    /// Merge one validated range; true if it added previously unknown bytes.
    fn merge(&mut self, mut l: SeqNr, mut r: SeqNr) -> bool {
        // Quick containment check.
        for &(s, e) in self.ranges.iter() {
            if s.le(l) && r.le(e) {
                return false;
            }
        }
        let mut merged: BoundedVec<(SeqNr, SeqNr), MAX_SACK_RANGES> = BoundedVec::new();
        let mut placed = false;
        let mut overflow = false;
        for &(s, e) in self.ranges.iter() {
            if e.lt(l) {
                overflow |= merged.push((s, e)).is_err();
            } else if r.lt(s) {
                if !placed {
                    overflow |= merged.push((l, r)).is_err();
                    placed = true;
                }
                overflow |= merged.push((s, e)).is_err();
            } else {
                // Overlapping or adjacent: absorb.
                l = l.min(s);
                r = r.max(e);
            }
        }
        if !placed {
            overflow |= merged.push((l, r)).is_err();
        }
        if overflow {
            // Bounded state: ignore the new information rather than grow.
            return false;
        }
        self.ranges = merged;
        true
    }

    /// Cumulative ACK advanced: discard ranges at or below `snd_una`.
    pub fn on_ack_advance(&mut self, snd_una: SeqNr) {
        self.ranges.retain(|&(_, e)| e.gt(snd_una));
        for range in self.ranges.as_mut_slice() {
            if range.0.lt(snd_una) {
                range.0 = snd_una;
            }
        }
    }

    /// Forget everything (on RTO, per RFC 2018 §8 reneging caution).
    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    /// Total SACKed bytes (for the RFC 6675 pipe estimate).
    pub fn sacked_bytes(&self) -> u32 {
        self.ranges.iter().map(|&(s, e)| e.since(s)).sum()
    }

    /// Highest SACKed sequence number, if any.
    pub fn high_sacked(&self) -> Option<SeqNr> {
        self.ranges.iter().last().map(|&(_, e)| e)
    }

    /// True if `[seq, seq+len)` is entirely SACKed.
    pub fn is_sacked(&self, seq: SeqNr, len: u32) -> bool {
        let end = seq.add(len);
        self.ranges.iter().any(|&(s, e)| s.le(seq) && end.le(e))
    }

    /// First hole at or after `from`, strictly below `high_sacked`:
    /// `(start, max_len)` where `max_len` runs to the next SACKed range.
    /// Holes below the highest SACK are the retransmission candidates of
    /// SACK-based recovery (RFC 6675 §4 NextSeg rule 1, simplified).
    pub fn next_hole(&self, from: SeqNr) -> Option<(SeqNr, u32)> {
        let high = self.high_sacked()?;
        if from.ge(high) {
            return None;
        }
        let mut at = from;
        for &(s, e) in self.ranges.iter() {
            if at.lt(s) {
                return Some((at, s.since(at)));
            }
            if at.lt(e) {
                at = e; // inside a SACKed range; skip past it
            }
        }
        // Past every range but below high: impossible since high is the last
        // range's end, so at >= high here.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sb(una: u32, nxt: u32, blocks: &[(u32, u32)]) -> SackScoreboard {
        let mut s = SackScoreboard::new();
        s.ingest(blocks, SeqNr(una), SeqNr(nxt));
        s
    }

    #[test]
    fn ingest_validates_blocks() {
        let mut s = SackScoreboard::new();
        // Malformed, stale, and beyond-SND.NXT blocks are ignored.
        assert!(!s.ingest(&[(50, 40)], SeqNr(100), SeqNr(1000)));
        assert!(!s.ingest(&[(40, 90)], SeqNr(100), SeqNr(1000)));
        assert!(!s.ingest(&[(900, 1100)], SeqNr(100), SeqNr(1000)));
        assert_eq!(s.sacked_bytes(), 0);
        // Straddling SND.UNA is clamped.
        assert!(s.ingest(&[(90, 200)], SeqNr(100), SeqNr(1000)));
        assert_eq!(s.sacked_bytes(), 100);
    }

    #[test]
    fn merge_coalesces() {
        let mut s = sb(0, 10000, &[(100, 200), (300, 400)]);
        assert_eq!(s.sacked_bytes(), 200);
        // Duplicate adds nothing new.
        assert!(!s.ingest(&[(100, 200)], SeqNr(0), SeqNr(10000)));
        // Bridge merges everything.
        assert!(s.ingest(&[(150, 350)], SeqNr(0), SeqNr(10000)));
        assert_eq!(s.sacked_bytes(), 300);
        assert_eq!(s.high_sacked(), Some(SeqNr(400)));
        assert!(s.is_sacked(SeqNr(100), 300));
        assert!(!s.is_sacked(SeqNr(99), 2));
    }

    #[test]
    fn holes_for_retransmission() {
        let s = sb(100, 1000, &[(200, 300), (500, 600)]);
        // Hole 1: [100, 200).
        assert_eq!(s.next_hole(SeqNr(100)), Some((SeqNr(100), 100)));
        // From inside a SACKed range: next hole after it.
        assert_eq!(s.next_hole(SeqNr(250)), Some((SeqNr(300), 200)));
        // From the last hole's middle.
        assert_eq!(s.next_hole(SeqNr(400)), Some((SeqNr(400), 100)));
        // Nothing above high_sacked.
        assert_eq!(s.next_hole(SeqNr(600)), None);
    }

    #[test]
    fn ack_advance_trims() {
        let mut s = sb(100, 1000, &[(200, 300), (500, 600)]);
        s.on_ack_advance(SeqNr(250));
        assert_eq!(s.sacked_bytes(), 150);
        s.on_ack_advance(SeqNr(600));
        assert_eq!(s.sacked_bytes(), 0);
        assert_eq!(s.high_sacked(), None);
    }

    #[test]
    fn wraparound_ranges() {
        let una = u32::MAX - 100;
        let mut s = SackScoreboard::new();
        assert!(s.ingest(&[(u32::MAX - 50, 50)], SeqNr(una), SeqNr(una).add(500)));
        assert_eq!(s.sacked_bytes(), 101);
        assert_eq!(s.next_hole(SeqNr(una)), Some((SeqNr(una), 50)));
    }
}
