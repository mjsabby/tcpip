//! Initial sequence number generation (RFC 6528).
//!
//! `ISN = M + F(localip, localport, remoteip, remoteport, secretkey)` where
//! M is a 4-microsecond clock and F is SipHash-2-4 keyed by entropy the
//! runtime supplied via [`crate::Event::EntropyProvided`]. The protocol core
//! contains no entropy source of its own — given the same seed and the same
//! virtual clock, ISN generation replays exactly.

use super::seq::SeqNr;
use crate::time::Instant;
use crate::types::SocketAddr;

/// SipHash-2-4 (Aumasson & Bernstein), the F recommended by RFC 6528.
#[derive(Debug, Clone, Copy)]
struct SipHash24 {
    k0: u64,
    k1: u64,
}

impl SipHash24 {
    fn hash(&self, data: &[u8]) -> u64 {
        let mut v0 = self.k0 ^ 0x736f_6d65_7073_6575;
        let mut v1 = self.k1 ^ 0x646f_7261_6e64_6f6d;
        let mut v2 = self.k0 ^ 0x6c79_6765_6e65_7261;
        let mut v3 = self.k1 ^ 0x7465_6462_7974_6573;

        let mut chunks = data.chunks_exact(8);
        for chunk in &mut chunks {
            let m = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
            v3 ^= m;
            Self::round(&mut v0, &mut v1, &mut v2, &mut v3);
            Self::round(&mut v0, &mut v1, &mut v2, &mut v3);
            v0 ^= m;
        }
        let rem = chunks.remainder();
        let mut last = [0u8; 8];
        last[..rem.len()].copy_from_slice(rem);
        last[7] = data.len() as u8;
        let m = u64::from_le_bytes(last);
        v3 ^= m;
        Self::round(&mut v0, &mut v1, &mut v2, &mut v3);
        Self::round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;

        v2 ^= 0xff;
        for _ in 0..4 {
            Self::round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^ v1 ^ v2 ^ v3
    }

    #[inline]
    fn round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
        *v0 = v0.wrapping_add(*v1);
        *v1 = v1.rotate_left(13);
        *v1 ^= *v0;
        *v0 = v0.rotate_left(32);
        *v2 = v2.wrapping_add(*v3);
        *v3 = v3.rotate_left(16);
        *v3 ^= *v2;
        *v0 = v0.wrapping_add(*v3);
        *v3 = v3.rotate_left(21);
        *v3 ^= *v0;
        *v2 = v2.wrapping_add(*v1);
        *v1 = v1.rotate_left(17);
        *v1 ^= *v2;
        *v2 = v2.rotate_left(32);
    }
}

/// ISN generator; unusable until seeded.
#[derive(Debug, Clone, Copy)]
pub struct IsnGenerator {
    key: Option<SipHash24>,
}

impl Default for IsnGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl IsnGenerator {
    /// Unseeded generator.
    pub const fn new() -> Self {
        IsnGenerator { key: None }
    }

    /// Seed (or re-seed) from runtime-provided entropy.
    pub fn seed(&mut self, bytes: [u8; 16]) {
        self.key = Some(SipHash24 {
            k0: u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8])),
            k1: u64::from_le_bytes(bytes[8..].try_into().unwrap_or([0; 8])),
        });
    }

    /// True once seeded; connections cannot be created before this.
    pub fn ready(&self) -> bool {
        self.key.is_some()
    }

    /// RFC 6528 §3 ISN for a connection 4-tuple at virtual time `now`.
    pub fn generate(&self, now: Instant, local: SocketAddr, remote: SocketAddr) -> Option<SeqNr> {
        let key = self.key?;
        let mut buf = [0u8; 40];
        let mut at = 0;
        for (addr, port) in [(local, local.port), (remote, remote.port)] {
            match addr.ip {
                crate::types::IpAddr::V4(b) => {
                    buf[at..at + 4].copy_from_slice(&b);
                    at += 4;
                }
                crate::types::IpAddr::V6(b) => {
                    buf[at..at + 16].copy_from_slice(&b);
                    at += 16;
                }
            }
            buf[at..at + 2].copy_from_slice(&port.to_be_bytes());
            at += 2;
        }
        // M: 4-microsecond clock (RFC 6528 §3, mirroring RFC 793).
        let m = (now.as_micros() / 4) as u32;
        let f = key.hash(&buf[..at]) as u32;
        Some(SeqNr(m.wrapping_add(f)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::IpAddr;

    /// Reference vectors from the SipHash paper (key 00..0f).
    #[test]
    fn siphash24_reference_vectors() {
        let key = SipHash24 { k0: 0x0706_0504_0302_0100, k1: 0x0f0e_0d0c_0b0a_0908 };
        assert_eq!(key.hash(b""), 0x726f_db47_dd0e_0e31);
        assert_eq!(key.hash(&[0x00]), 0x74f8_39c5_93dc_67fd);
        let msg: [u8; 15] = core::array::from_fn(|i| i as u8);
        assert_eq!(key.hash(&msg), 0xa129_ca61_49be_45e5);
    }

    #[test]
    fn isn_depends_on_tuple_and_time() {
        let mut g = IsnGenerator::new();
        assert!(!g.ready());
        assert!(g.generate(Instant::ZERO, sa(1), sa(2)).is_none());
        g.seed([7; 16]);
        assert!(g.ready());
        let t = Instant::from_secs(1);
        let a = g.generate(t, sa(1), sa(2)).unwrap();
        let b = g.generate(t, sa(1), sa(3)).unwrap();
        assert_ne!(a, b, "different tuples must give unrelated ISNs");
        // Deterministic for the same inputs (replay requirement).
        assert_eq!(g.generate(t, sa(1), sa(2)).unwrap(), a);
        // The 4µs clock advances the ISN.
        let later = g.generate(t + crate::time::Duration::from_micros(40), sa(1), sa(2)).unwrap();
        assert_eq!(later.since(a), 10);
        // A different secret changes everything.
        let mut g2 = IsnGenerator::new();
        g2.seed([8; 16]);
        assert_ne!(g2.generate(t, sa(1), sa(2)).unwrap(), a);
    }

    fn sa(host: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::v4(10, 0, 0, host), 4000 + host as u16)
    }
}
