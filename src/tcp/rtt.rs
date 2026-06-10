//! Round-trip time estimation and retransmission timeout (RFC 6298,
//! Jacobson/Karels).
//!
//! Karn's algorithm (RFC 6298 §3) is enforced by the *caller*: samples are
//! only taken for segments that were transmitted exactly once. This module
//! owns the arithmetic.

use crate::time::Duration;

/// Clock granularity G (RFC 6298 §2.4). Our virtual clock is microseconds;
/// 1 ms is a conservative granularity bound.
const GRANULARITY: Duration = Duration::from_millis(1);

/// RTT estimator state.
#[derive(Debug, Clone, Copy)]
pub struct RttEstimator {
    /// Smoothed RTT; `None` until the first sample (RFC 6298 §2.1/§2.2).
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    rto_min: Duration,
    rto_max: Duration,
}

impl RttEstimator {
    /// New estimator with the configured initial RTO and clamps.
    pub fn new(initial: Duration, rto_min: Duration, rto_max: Duration) -> Self {
        RttEstimator { srtt: None, rttvar: Duration::ZERO, rto: initial, rto_min, rto_max }
    }

    /// Current retransmission timeout.
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Smoothed RTT, if at least one sample has been taken.
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// Incorporate a measured RTT `r` (RFC 6298 §2.2/§2.3).
    pub fn on_sample(&mut self, r: Duration) {
        match self.srtt {
            None => {
                // First measurement: SRTT = R, RTTVAR = R/2.
                self.srtt = Some(r);
                self.rttvar = r.div(2);
            }
            Some(srtt) => {
                // RTTVAR = 3/4 RTTVAR + 1/4 |SRTT - R|
                let err = if srtt.as_micros() >= r.as_micros() {
                    srtt.saturating_sub(r)
                } else {
                    r.saturating_sub(srtt)
                };
                self.rttvar = self.rttvar.saturating_mul(3).div(4) + err.div(4);
                // SRTT = 7/8 SRTT + 1/8 R
                self.srtt = Some(srtt.saturating_mul(7).div(8) + r.div(8));
            }
        }
        let srtt = self.srtt.unwrap_or(Duration::ZERO);
        let var_term = GRANULARITY.max(self.rttvar.saturating_mul(4));
        self.rto = (srtt + var_term).clamp(self.rto_min, self.rto_max);
    }

    /// Back off after a retransmission timeout: RTO ← 2·RTO, capped
    /// (RFC 6298 §5.5/§5.6).
    pub fn backoff(&mut self) {
        self.rto = self.rto.saturating_mul(2).min(self.rto_max);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn est() -> RttEstimator {
        RttEstimator::new(Duration::from_secs(1), Duration::from_secs(1), Duration::from_secs(60))
    }

    #[test]
    fn first_sample_initializes() {
        let mut e = est();
        assert_eq!(e.rto(), Duration::from_secs(1));
        e.on_sample(Duration::from_millis(400));
        // SRTT=400ms, RTTVAR=200ms → RTO = 400 + 800 = 1200ms.
        assert_eq!(e.srtt(), Some(Duration::from_millis(400)));
        assert_eq!(e.rto(), Duration::from_millis(1200));
    }

    #[test]
    fn smooths_and_respects_min() {
        let mut e = est();
        for _ in 0..50 {
            e.on_sample(Duration::from_millis(10));
        }
        // Stable 10ms RTT: variance decays, RTO hits the 1s floor
        // (RFC 6298 §2.4).
        assert_eq!(e.rto(), Duration::from_secs(1));
        let srtt = e.srtt().unwrap().as_millis();
        assert!((9..=11).contains(&srtt), "srtt={srtt}ms");
    }

    #[test]
    fn variance_reacts_to_jitter() {
        let mut e = est();
        e.on_sample(Duration::from_millis(100));
        e.on_sample(Duration::from_millis(2000));
        // Large deviation should push RTO well above the floor.
        assert!(e.rto() > Duration::from_secs(1));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let mut e = est();
        e.on_sample(Duration::from_millis(500)); // RTO 500+1000 → 1.5s
        let r0 = e.rto();
        e.backoff();
        assert_eq!(e.rto(), r0.saturating_mul(2));
        for _ in 0..10 {
            e.backoff();
        }
        assert_eq!(e.rto(), Duration::from_secs(60));
    }
}
