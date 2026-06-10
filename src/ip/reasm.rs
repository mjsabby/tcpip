//! Fragment reassembly (RFC 791 §3.2 / RFC 815 hole algorithm / RFC 8200
//! §4.5), shared by IPv4 and IPv6.
//!
//! Fixed capacity: [`REASM_SLOTS`] concurrent datagrams of at most
//! [`REASM_BUF_SIZE`] bytes with at most [`REASM_MAX_HOLES`] holes each.
//! Anything exceeding a bound drops the affected datagram — the peer's
//! transport retransmits (bounded loss, never unbounded memory).
//!
//! Security: any *conflicting* overlap drops the whole datagram (mandatory
//! for IPv6 per RFC 5722; we apply it to IPv4 as well, I-REASM-2). Exact
//! duplicate fragments with identical bytes are tolerated as benign network
//! duplication.

use super::ReasmKey;
use crate::config::{REASM_BUF_SIZE, REASM_MAX_HOLES, REASM_SLOTS};
use crate::time::{Duration, Instant};
use crate::util::BoundedVec;

/// Result of offering one fragment to the reassembler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasmResult {
    /// Datagram complete; fetch it with [`Reassembler::take`].
    Complete {
        /// Slot holding the completed datagram.
        slot: usize,
    },
    /// Fragment stored; more fragments are needed.
    Pending,
    /// Fragment (and possibly the whole datagram) discarded.
    Dropped,
}

#[derive(Clone, Copy)]
struct Slot {
    key: ReasmKey,
    /// Missing byte ranges `[start, end)`. `end == u32::MAX` means
    /// "unbounded" until the final fragment fixes the total length.
    holes: BoundedVec<(u32, u32), REASM_MAX_HOLES>,
    total_len: Option<u32>,
    deadline: Instant,
    in_use: bool,
    buf: [u8; REASM_BUF_SIZE],
}

impl Default for Slot {
    fn default() -> Self {
        Slot {
            key: ReasmKey::default(),
            holes: BoundedVec::new(),
            total_len: None,
            deadline: Instant::ZERO,
            in_use: false,
            buf: [0; REASM_BUF_SIZE],
        }
    }
}

/// Fixed-capacity fragment reassembler.
pub struct Reassembler {
    slots: [Slot; REASM_SLOTS],
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// An empty reassembler.
    pub fn new() -> Self {
        Reassembler { slots: [Slot::default(); REASM_SLOTS] }
    }

    /// Offer a fragment. `offset` is in bytes; `more` is the MF flag.
    /// `timeout` applies from the first fragment of a datagram (RFC 791
    /// §3.2: the timer runs from the first fragment seen).
    pub fn push(
        &mut self,
        now: Instant,
        timeout: Duration,
        key: ReasmKey,
        offset: u32,
        more: bool,
        data: &[u8],
    ) -> ReasmResult {
        // Non-final fragments must carry a multiple of 8 bytes (RFC 791 /
        // RFC 8200 §4.5); anything else is malformed.
        if more && data.len() % 8 != 0 {
            return ReasmResult::Dropped;
        }
        if data.is_empty() && more {
            return ReasmResult::Dropped;
        }
        let end = offset + data.len() as u32;
        if end as usize > REASM_BUF_SIZE {
            // Datagram cannot fit: drop the whole reassembly, not just the
            // fragment, so we don't hold state we can never complete.
            self.drop_key(&key);
            return ReasmResult::Dropped;
        }

        let slot_idx = match self.find_or_alloc(now, timeout, &key) {
            Some(i) => i,
            None => return ReasmResult::Dropped,
        };
        let slot = &mut self.slots[slot_idx];

        // Final fragment fixes the total length.
        if !more {
            if let Some(t) = slot.total_len {
                if t != end {
                    // Conflicting final fragments: hostile or corrupt.
                    slot.in_use = false;
                    return ReasmResult::Dropped;
                }
            } else {
                // While the total is unknown, everything past the highest
                // stored byte is one unbounded hole `(hs, u32::MAX)`. Data
                // stored at or beyond `end` therefore shows up as that
                // hole starting *after* `end` — a conflict with this final
                // fragment.
                let unbounded_start =
                    slot.holes.iter().find(|h| h.1 == u32::MAX).map(|h| h.0);
                if unbounded_start.is_none_or(|hs| hs > end) {
                    slot.in_use = false;
                    return ReasmResult::Dropped;
                }
                // Truncate the hole list to the now-known total.
                slot.holes.retain(|&(hs, _)| hs < end);
                for h in slot.holes.as_mut_slice() {
                    if h.1 > end {
                        h.1 = end;
                    }
                }
                slot.total_len = Some(end);
            }
        }
        if let Some(t) = slot.total_len
            && end > t
        {
            slot.in_use = false;
            return ReasmResult::Dropped;
        }
        if data.is_empty() {
            // Final, empty fragment (degenerate but legal once total known).
            return Self::finish(slot, slot_idx);
        }

        // RFC 815 hole algorithm with strict overlap policy: the fragment
        // must lie entirely inside holes (fresh) or entirely inside filled
        // space with identical bytes (duplicate). Anything else is a
        // conflicting overlap and drops the datagram.
        let mut covered = 0u32;
        for &(hs, he) in slot.holes.iter() {
            let s = offset.max(hs);
            let e = end.min(he);
            if s < e {
                covered += e - s;
            }
        }
        if covered == 0 {
            // Entirely within filled space: benign duplicate iff identical.
            if slot.buf[offset as usize..end as usize] == *data {
                return ReasmResult::Pending;
            }
            slot.in_use = false;
            return ReasmResult::Dropped;
        }
        if covered != data.len() as u32 {
            // Partial overlap with existing data: conflicting (I-REASM-2).
            slot.in_use = false;
            return ReasmResult::Dropped;
        }

        // Split every hole the fragment intersects.
        let old_holes = slot.holes;
        slot.holes.clear();
        let mut overflow = false;
        for &(hs, he) in old_holes.iter() {
            if end <= hs || offset >= he {
                overflow |= slot.holes.push((hs, he)).is_err();
                continue;
            }
            if hs < offset {
                overflow |= slot.holes.push((hs, offset)).is_err();
            }
            if end < he {
                overflow |= slot.holes.push((end, he)).is_err();
            }
        }
        if overflow {
            slot.in_use = false;
            return ReasmResult::Dropped;
        }
        slot.buf[offset as usize..end as usize].copy_from_slice(data);
        Self::finish(slot, slot_idx)
    }

    fn finish(slot: &mut Slot, idx: usize) -> ReasmResult {
        if slot.total_len.is_some() && slot.holes.is_empty() {
            ReasmResult::Complete { slot: idx }
        } else {
            ReasmResult::Pending
        }
    }

    /// Copy a completed datagram out and free its slot. Returns the key and
    /// payload length. `out` must be at least [`REASM_BUF_SIZE`] bytes.
    pub fn take(&mut self, slot: usize, out: &mut [u8]) -> Option<(ReasmKey, usize)> {
        let s = &mut self.slots[slot];
        if !s.in_use || s.total_len.is_none() || !s.holes.is_empty() {
            return None;
        }
        let len = s.total_len.unwrap_or(0) as usize;
        out[..len].copy_from_slice(&s.buf[..len]);
        s.in_use = false;
        Some((s.key, len))
    }

    /// Expire a slot whose reassembly timer fired (RFC 791 §3.2: discard on
    /// timer expiry).
    pub fn on_timer(&mut self, slot: usize) {
        if let Some(s) = self.slots.get_mut(slot) {
            s.in_use = false;
        }
    }

    /// Desired timer deadline per slot, for the stack's reconciliation.
    pub fn deadline(&self, slot: usize) -> Option<Instant> {
        let s = self.slots.get(slot)?;
        s.in_use.then_some(s.deadline)
    }

    fn drop_key(&mut self, key: &ReasmKey) {
        for s in &mut self.slots {
            if s.in_use && s.key == *key {
                s.in_use = false;
            }
        }
    }

    fn find_or_alloc(&mut self, now: Instant, timeout: Duration, key: &ReasmKey) -> Option<usize> {
        // Existing reassembly for this key?
        for (i, s) in self.slots.iter().enumerate() {
            if s.in_use && s.key == *key {
                return Some(i);
            }
        }
        // Free or expired slot? (Expired slots are reaped lazily here as
        // well as by their timers, so a missed timer cannot wedge a slot.)
        for (i, s) in self.slots.iter_mut().enumerate() {
            if !s.in_use || s.deadline <= now {
                s.key = *key;
                s.deadline = now + timeout;
                s.in_use = true;
                s.total_len = None;
                s.holes.clear();
                let _ = s.holes.push((0, u32::MAX));
                return Some(i);
            }
        }
        // Table full: drop the *new* datagram, keep older ones (favors
        // completing in-progress work; an attacker gains nothing by
        // flooding since slots are time-bounded).
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::IpAddr;

    const T0: Instant = Instant::ZERO;
    const TMO: Duration = Duration::from_secs(30);

    fn key(ident: u32) -> ReasmKey {
        ReasmKey {
            src: IpAddr::v4(10, 0, 0, 1),
            dst: IpAddr::v4(10, 0, 0, 2),
            proto: 6,
            ident,
        }
    }

    #[test]
    fn in_order_and_reverse_reassembly() {
        for order in [[0usize, 1, 2], [2, 1, 0], [1, 2, 0]] {
            let mut r = Reassembler::new();
            let frags = [(0u32, true, [1u8; 16]), (16, true, [2u8; 16]), (32, false, [3u8; 16])];
            let mut done = None;
            for &i in &order {
                let (off, more, ref data) = frags[i];
                match r.push(T0, TMO, key(1), off, more, data) {
                    ReasmResult::Complete { slot } => done = Some(slot),
                    ReasmResult::Pending => {}
                    ReasmResult::Dropped => panic!("dropped in order {order:?}"),
                }
            }
            let mut out = [0u8; REASM_BUF_SIZE];
            let (k, len) = r.take(done.expect("completed"), &mut out).unwrap();
            assert_eq!(k, key(1));
            assert_eq!(len, 48);
            assert_eq!(&out[..16], &[1; 16]);
            assert_eq!(&out[16..32], &[2; 16]);
            assert_eq!(&out[32..48], &[3; 16]);
        }
    }

    #[test]
    fn exact_duplicate_tolerated_conflict_dropped() {
        let mut r = Reassembler::new();
        assert_eq!(r.push(T0, TMO, key(1), 0, true, &[7; 16]), ReasmResult::Pending);
        // Exact duplicate: benign.
        assert_eq!(r.push(T0, TMO, key(1), 0, true, &[7; 16]), ReasmResult::Pending);
        // Same range, different bytes: hostile, datagram dropped.
        assert_eq!(r.push(T0, TMO, key(1), 0, true, &[8; 16]), ReasmResult::Dropped);
        // Reassembly state is gone; a fresh final fragment alone completes
        // nothing.
        assert_eq!(r.push(T0, TMO, key(1), 16, false, &[9; 8]), ReasmResult::Pending);
    }

    #[test]
    fn partial_overlap_drops_datagram() {
        let mut r = Reassembler::new();
        assert_eq!(r.push(T0, TMO, key(1), 8, true, &[1; 16]), ReasmResult::Pending);
        // Overlaps [8,24) partially.
        assert_eq!(r.push(T0, TMO, key(1), 0, true, &[2; 16]), ReasmResult::Dropped);
    }

    #[test]
    fn oversize_and_misaligned_dropped() {
        let mut r = Reassembler::new();
        let big = [0u8; 64];
        assert_eq!(
            r.push(T0, TMO, key(1), (REASM_BUF_SIZE - 32) as u32, true, &big),
            ReasmResult::Dropped
        );
        // Non-final fragment not a multiple of 8.
        assert_eq!(r.push(T0, TMO, key(2), 0, true, &[0; 12]), ReasmResult::Dropped);
    }

    #[test]
    fn timer_expiry_frees_slot() {
        let mut r = Reassembler::new();
        r.push(T0, TMO, key(1), 0, true, &[1; 8]);
        assert!(r.deadline(0).is_some());
        r.on_timer(0);
        assert!(r.deadline(0).is_none());
        let mut out = [0u8; REASM_BUF_SIZE];
        assert!(r.take(0, &mut out).is_none());
    }

    #[test]
    fn slot_exhaustion_drops_new() {
        let mut r = Reassembler::new();
        for i in 0..REASM_SLOTS as u32 {
            assert_eq!(r.push(T0, TMO, key(i), 0, true, &[0; 8]), ReasmResult::Pending);
        }
        assert_eq!(r.push(T0, TMO, key(99), 0, true, &[0; 8]), ReasmResult::Dropped);
        // But expired slots are reclaimed lazily (offset 0 + !MF is a
        // complete single-fragment datagram, hence Complete).
        let later = T0 + TMO + Duration::from_secs(1);
        assert_eq!(
            r.push(later, TMO, key(99), 0, false, &[0; 8]),
            ReasmResult::Complete { slot: 0 }
        );
    }

    #[test]
    fn conflicting_final_fragments_drop() {
        let mut r = Reassembler::new();
        assert_eq!(r.push(T0, TMO, key(1), 32, false, &[1; 8]), ReasmResult::Pending);
        assert_eq!(r.push(T0, TMO, key(1), 48, false, &[1; 8]), ReasmResult::Dropped);
    }
}
