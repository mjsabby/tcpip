//! Internet checksum (RFC 1071) with IPv4/IPv6 pseudo-headers.

use crate::types::IpAddr;

/// Incremental ones-complement checksum accumulator.
///
/// Chunks of any length may be added in sequence; byte parity is carried
/// across calls so odd-length chunks compose correctly (needed because TCP
/// payloads may arrive as two ring-buffer slices).
#[derive(Debug, Clone, Copy)]
pub struct Checksum {
    sum: u32,
    odd: bool,
}

impl Default for Checksum {
    fn default() -> Self {
        Self::new()
    }
}

impl Checksum {
    /// Fresh accumulator.
    pub const fn new() -> Self {
        Checksum { sum: 0, odd: false }
    }

    /// Add a chunk of bytes.
    pub fn add_bytes(&mut self, data: &[u8]) {
        let mut i = 0;
        if self.odd && !data.is_empty() {
            self.sum += data[0] as u32;
            self.odd = false;
            i = 1;
        }
        while i + 1 < data.len() {
            self.sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
            // Fold eagerly enough that `sum` cannot overflow u32: each word
            // adds < 2^16 and we fold once it exceeds 2^24.
            if self.sum > 0x00ff_ffff {
                self.sum = (self.sum & 0xffff) + (self.sum >> 16);
            }
            i += 2;
        }
        if i < data.len() {
            self.sum += (data[i] as u32) << 8;
            self.odd = true;
        }
    }

    /// Add a 16-bit value (as if two big-endian bytes were appended).
    pub fn add_u16(&mut self, v: u16) {
        self.add_bytes(&v.to_be_bytes());
    }

    /// Add the IPv4 pseudo-header (RFC 9293 §3.1) for upper-layer checksums.
    pub fn add_pseudo_v4(&mut self, src: &[u8; 4], dst: &[u8; 4], proto: u8, len: u16) {
        self.add_bytes(src);
        self.add_bytes(dst);
        self.add_u16(proto as u16);
        self.add_u16(len);
    }

    /// Add the IPv6 pseudo-header (RFC 8200 §8.1).
    pub fn add_pseudo_v6(&mut self, src: &[u8; 16], dst: &[u8; 16], proto: u8, len: u32) {
        self.add_bytes(src);
        self.add_bytes(dst);
        self.add_bytes(&len.to_be_bytes());
        self.add_u16(proto as u16);
    }

    /// Add the pseudo-header matching the family of `src`/`dst`.
    ///
    /// Both addresses must be the same family (guaranteed by construction
    /// everywhere this is called: a connection's two endpoints always match).
    pub fn add_pseudo(&mut self, src: &IpAddr, dst: &IpAddr, proto: u8, len: u32) {
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => self.add_pseudo_v4(s, d, proto, len as u16),
            (IpAddr::V6(s), IpAddr::V6(d)) => self.add_pseudo_v6(s, d, proto, len),
            _ => debug_assert!(false, "mixed address families in pseudo-header"),
        }
    }

    /// Finish: fold and complement. The result is the value to place in a
    /// checksum field. Verifying a received structure: add everything
    /// including the transmitted checksum; the data is valid iff `finish()`
    /// returns 0.
    pub fn finish(mut self) -> u16 {
        while self.sum >> 16 != 0 {
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }
        !(self.sum as u16)
    }
}

/// One-shot checksum of a contiguous buffer.
pub fn over(data: &[u8]) -> u16 {
    let mut c = Checksum::new();
    c.add_bytes(data);
    c.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1071 §3 worked example.
    #[test]
    fn rfc1071_example() {
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(over(&data), !0xddf2);
    }

    #[test]
    fn parity_carries_across_chunks() {
        let whole = [1u8, 2, 3, 4, 5, 6, 7];
        let mut split = Checksum::new();
        split.add_bytes(&whole[..3]); // odd chunk
        split.add_bytes(&whole[3..6]);
        split.add_bytes(&whole[6..]);
        assert_eq!(split.finish(), over(&whole));
    }

    #[test]
    fn verify_round_trip() {
        let mut data = [
            0x45u8, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0, 0, 10, 0, 0, 1, 10, 0,
            0, 2,
        ];
        let cks = over(&data);
        data[10..12].copy_from_slice(&cks.to_be_bytes());
        assert_eq!(over(&data), 0);
    }

    #[test]
    fn no_overflow_on_large_input() {
        let data = [0xffu8; 65536];
        let mut c = Checksum::new();
        c.add_bytes(&data);
        let _ = c.finish(); // must not panic in debug (overflow checks on)
    }
}
