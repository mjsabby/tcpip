//! Path-MTU cache (RFC 1191 for IPv4, RFC 8201 for IPv6).
//!
//! Estimates only ever *decrease* in response to ICMP signals and recover by
//! aging out (RFC 1191 §6.3), so a forged ICMP message can at worst degrade
//! efficiency within fixed floors — never stop traffic (S-PMTU-1).

use super::{IPV4_MIN_PMTU, IPV6_MIN_PMTU};
use crate::time::{Duration, Instant};
use crate::types::IpAddr;

/// How long a lowered estimate is honored before re-probing at link MTU
/// (RFC 1191 §6.3 suggests 10 minutes).
pub const PMTU_TTL: Duration = Duration::from_secs(600);

/// RFC 1191 §7.1 plateau table, used when an old router reports MTU 0.
const PLATEAUS: [u16; 10] = [68, 296, 508, 1006, 1492, 2002, 4352, 8166, 17914, 32000];

#[derive(Debug, Clone, Copy)]
struct Entry {
    dst: IpAddr,
    mtu: u16,
    expires: Instant,
}

/// Fixed-capacity per-destination path-MTU cache.
pub struct PmtuCache<const N: usize> {
    entries: [Option<Entry>; N],
}

impl<const N: usize> Default for PmtuCache<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PmtuCache<N> {
    /// An empty cache.
    pub const fn new() -> Self {
        PmtuCache { entries: [None; N] }
    }

    /// Current path MTU toward `dst`, given the configured link MTU.
    pub fn get(&self, now: Instant, link_mtu: u16, dst: &IpAddr) -> u16 {
        for e in self.entries.iter().flatten() {
            if e.dst == *dst && e.expires > now {
                return e.mtu.min(link_mtu);
            }
        }
        link_mtu
    }

    /// Process a fragmentation-needed / packet-too-big report for `dst`.
    /// `reported` is the MTU field from the ICMP message (0 from pre-1191
    /// routers). Returns the floor-clamped estimate the report implies; the
    /// shared cache is only *lowered* (raises arrive only by aging out —
    /// S-PMTU-1), but the caller must still propagate the value to every
    /// connection toward `dst` whose own estimate exceeds it (DEF-H9).
    pub fn update(&mut self, now: Instant, link_mtu: u16, dst: &IpAddr, reported: u32) -> u16 {
        let current = self.get(now, link_mtu, dst);
        let floor = match dst {
            IpAddr::V4(_) => IPV4_MIN_PMTU,
            // RFC 8201 §4: an IPv6 node never reduces below 1280.
            IpAddr::V6(_) => IPV6_MIN_PMTU,
        };
        let candidate = if reported == 0 {
            // RFC 1191 §7: no MTU reported — drop to the next plateau below
            // the current estimate.
            PLATEAUS
                .iter()
                .rev()
                .copied()
                .find(|&p| p < current)
                .unwrap_or(floor)
        } else {
            reported.min(u16::MAX as u32) as u16
        };
        // DEF-H12: never assume `link_mtu >= floor`; a misconfigured `cfg.mtu`
        // would otherwise panic at `core::cmp::clamp` on the next ICMP PTB.
        let new = candidate.max(floor).min(link_mtu.max(floor));
        if new < current {
            self.insert(now, dst, new);
        }
        new
    }

    fn insert(&mut self, now: Instant, dst: &IpAddr, mtu: u16) {
        let entry = Entry {
            dst: *dst,
            mtu,
            expires: now + PMTU_TTL,
        };
        // Existing entry for dst, else an empty/expired slot, else evict the
        // entry expiring soonest (it is the least valuable to keep).
        let mut victim = 0;
        let mut victim_expiry = Instant::from_micros(u64::MAX);
        for (i, slot) in self.entries.iter_mut().enumerate() {
            match slot {
                Some(e) if e.dst == *dst => {
                    *e = entry;
                    return;
                }
                Some(e) if e.expires <= now => {
                    *slot = None;
                }
                _ => {}
            }
            let expiry = match slot {
                None => Instant::ZERO,
                Some(e) => e.expires,
            };
            if expiry < victim_expiry {
                victim = i;
                victim_expiry = expiry;
            }
        }
        self.entries[victim] = Some(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: Instant = Instant::ZERO;
    const LINK: u16 = 1500;

    #[test]
    fn lowers_and_ages_out() {
        let mut c: PmtuCache<4> = PmtuCache::new();
        let dst = IpAddr::v4(192, 0, 2, 1);
        assert_eq!(c.get(T0, LINK, &dst), 1500);
        assert_eq!(c.update(T0, LINK, &dst, 1280), 1280);
        assert_eq!(c.get(T0, LINK, &dst), 1280);
        // A *higher* report never raises the cached estimate (S-PMTU-1) but
        // the clamped value is still returned for per-conn propagation.
        assert_eq!(c.update(T0, LINK, &dst, 1400), 1400);
        assert_eq!(c.get(T0, LINK, &dst), 1280);
        // After the TTL the link MTU is used again.
        let later = T0 + PMTU_TTL + Duration::from_secs(1);
        assert_eq!(c.get(later, LINK, &dst), 1500);
    }

    #[test]
    fn zero_report_uses_plateau() {
        let mut c: PmtuCache<4> = PmtuCache::new();
        let dst = IpAddr::v4(192, 0, 2, 2);
        // From 1500 the next plateau down is 1492, then 1006...
        assert_eq!(c.update(T0, LINK, &dst, 0), 1492);
        assert_eq!(c.update(T0, LINK, &dst, 0), 1006);
    }

    #[test]
    fn family_floors_apply() {
        let mut c: PmtuCache<4> = PmtuCache::new();
        let v4 = IpAddr::v4(192, 0, 2, 3);
        let v6 = IpAddr::v6([0xfc00, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(c.update(T0, LINK, &v4, 100), IPV4_MIN_PMTU);
        assert_eq!(c.update(T0, LINK, &v6, 100), IPV6_MIN_PMTU);
        // Already at the floor: nothing lowers further.
        assert_eq!(c.update(T0, LINK, &v6, 64), IPV6_MIN_PMTU);
        assert_eq!(c.get(T0, LINK, &v6), IPV6_MIN_PMTU);
    }

    #[test]
    fn misconfigured_link_mtu_below_floor_does_not_panic() {
        // DEF-H12: cfg.mtu < family floor must not abort on the next ICMP PTB.
        let mut c: PmtuCache<4> = PmtuCache::new();
        let v6 = IpAddr::v6([0xfc00, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(c.update(T0, 1000, &v6, 800), IPV6_MIN_PMTU);
    }

    #[test]
    fn eviction_prefers_soonest_expiry() {
        let mut c: PmtuCache<2> = PmtuCache::new();
        let a = IpAddr::v4(1, 1, 1, 1);
        let b = IpAddr::v4(2, 2, 2, 2);
        let d = IpAddr::v4(3, 3, 3, 3);
        c.update(T0, LINK, &a, 1000);
        c.update(T0 + Duration::from_secs(10), LINK, &b, 1000);
        c.update(T0 + Duration::from_secs(20), LINK, &d, 900); // evicts a
        assert_eq!(c.get(T0 + Duration::from_secs(21), LINK, &a), 1500);
        assert_eq!(c.get(T0 + Duration::from_secs(21), LINK, &b), 1000);
        assert_eq!(c.get(T0 + Duration::from_secs(21), LINK, &d), 900);
    }
}
