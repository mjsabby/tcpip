//! IPv4 egress fragmentation (RFC 791 §3.2).
//!
//! TCP itself never requires this — segments are sized within the path MTU
//! and sent with DF for PMTU discovery — but the IP layer provides
//! fragmentation for completeness (PLAN.md "IPv4 Required: fragmentation")
//! and for future non-TCP upper layers. Implemented as an iterator of
//! `(header fields, payload slice)` pairs so no payload bytes are copied.

use crate::wire::ipv4::{HEADER_LEN, Ipv4Emit};

/// Why a datagram could not be fragmented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragError {
    /// DF is set and the datagram exceeds the MTU.
    DontFragment,
    /// The MTU cannot hold the header plus an 8-byte aligned payload chunk.
    MtuTooSmall,
}

/// Iterator over the fragments of one IPv4 datagram.
pub struct Fragments<'a> {
    base: Ipv4Emit,
    payload: &'a [u8],
    /// Per-fragment payload capacity, 8-byte aligned.
    chunk: usize,
    at: usize,
    done: bool,
}

/// Plan fragmentation of `payload` (the complete upper-layer payload of a
/// datagram whose header fields are `base`) for a link of `mtu` bytes.
///
/// Returns an iterator yielding ready-to-emit `(Ipv4Emit, payload)` pairs.
/// If the datagram already fits, a single "fragment" is yielded unchanged.
pub fn fragment_v4(base: Ipv4Emit, payload: &[u8], mtu: u16) -> Result<Fragments<'_>, FragError> {
    let mtu = mtu as usize;
    if HEADER_LEN + payload.len() <= mtu {
        return Ok(Fragments { base, payload, chunk: payload.len().max(8), at: 0, done: false });
    }
    if base.dont_frag {
        return Err(FragError::DontFragment);
    }
    let chunk = (mtu.saturating_sub(HEADER_LEN)) & !7;
    if chunk == 0 {
        return Err(FragError::MtuTooSmall);
    }
    Ok(Fragments { base, payload, chunk, at: 0, done: false })
}

impl<'a> Iterator for Fragments<'a> {
    type Item = (Ipv4Emit, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let remaining = self.payload.len() - self.at;
        let take = remaining.min(self.chunk);
        let last = take == remaining;
        let mut h = self.base;
        h.frag_offset = self.base.frag_offset + self.at as u16;
        h.more_frags = self.base.more_frags || !last;
        let part = &self.payload[self.at..self.at + take];
        self.at += take;
        if last {
            self.done = true;
        }
        Some((h, part))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::ipv4;

    fn base(df: bool) -> Ipv4Emit {
        Ipv4Emit::datagram([10, 0, 0, 1], [10, 0, 0, 2], 6, 64, 42, df)
    }

    #[test]
    fn fits_unfragmented() {
        let payload = [9u8; 100];
        let frags: std::vec::Vec<_> = fragment_v4(base(true), &payload, 1500).unwrap().collect();
        assert_eq!(frags.len(), 1);
        assert!(!frags[0].0.more_frags && frags[0].0.frag_offset == 0);
        assert_eq!(frags[0].1.len(), 100);
    }

    #[test]
    fn df_blocks_fragmentation() {
        let payload = [9u8; 2000];
        assert!(matches!(fragment_v4(base(true), &payload, 1500), Err(FragError::DontFragment)));
    }

    #[test]
    fn splits_align_and_reassemble() {
        // Fragment, emit each on the wire, parse back, and reassemble.
        let mut payload = [0u8; 2000];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut out = [0u8; 2000];
        let mut seen = 0usize;
        let mut count = 0;
        for (h, part) in fragment_v4(base(false), &payload, 576).unwrap() {
            // Non-final fragments must be 8-byte aligned and fit the MTU.
            if h.more_frags {
                assert_eq!(part.len() % 8, 0);
            }
            assert!(ipv4::HEADER_LEN + part.len() <= 576);
            let mut wire = [0u8; 576];
            let hl = h.emit(part.len(), &mut wire);
            wire[hl..hl + part.len()].copy_from_slice(part);
            let (ph, ppay) = ipv4::parse(&wire[..hl + part.len()]).unwrap();
            assert_eq!(ph.ident, 42);
            out[ph.frag_offset as usize..ph.frag_offset as usize + ppay.len()]
                .copy_from_slice(ppay);
            seen += ppay.len();
            count += 1;
        }
        assert!(count > 1);
        assert_eq!(seen, 2000);
        assert_eq!(out, payload);
    }
}
