//! Congestion control: Reno (RFC 5681) with NewReno fast-recovery window
//! accounting (RFC 6582) and the RFC 6675-style variant used when SACK is
//! available.
//!
//! This module owns the window arithmetic only; recovery *orchestration*
//! (duplicate-ACK counting, recovery point, retransmission selection) lives
//! in the connection, which calls these transitions at the RFC-mandated
//! moments.

/// Hard ceiling on cwnd to keep state bounded (far above any window this
/// stack's fixed buffers can use).
const CWND_MAX: u32 = 1 << 24;

/// Congestion-control state.
#[derive(Debug, Clone, Copy)]
pub struct CongestionControl {
    /// Congestion window in bytes.
    pub cwnd: u32,
    /// Slow-start threshold in bytes.
    pub ssthresh: u32,
    /// Sender MSS in bytes (tracks effective MSS, e.g. after PMTU drops).
    mss: u32,
}

impl CongestionControl {
    /// Initial state: IW per RFC 3390 (as referenced by RFC 5681 §3.1),
    /// ssthresh effectively unbounded.
    pub fn new(mss: u32) -> Self {
        CongestionControl { cwnd: Self::initial_window(mss), ssthresh: CWND_MAX, mss }
    }

    /// RFC 3390: IW = min(4*MSS, max(2*MSS, 4380 bytes)).
    fn initial_window(mss: u32) -> u32 {
        (4 * mss).min((2 * mss).max(4380))
    }

    /// True while in slow start (RFC 5681 §3.1: cwnd < ssthresh).
    pub fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// A new (cumulative) ACK of `acked` bytes arrived outside recovery.
    pub fn on_new_ack(&mut self, acked: u32) {
        if self.in_slow_start() {
            // RFC 5681 §3.1: cwnd += min(N, SMSS) per ACK.
            self.cwnd = (self.cwnd + acked.min(self.mss)).min(CWND_MAX);
        } else {
            // Congestion avoidance, RFC 5681 §3.1 eq. (3):
            // cwnd += max(1, SMSS*SMSS / cwnd) per ACK.
            let inc = (self.mss * self.mss / self.cwnd.max(1)).max(1);
            self.cwnd = (self.cwnd + inc).min(CWND_MAX);
        }
    }

    /// Retransmission timeout (RFC 5681 §3.1 eq. 4): ssthresh =
    /// max(FlightSize/2, 2*SMSS); cwnd = 1 "loss window" of one segment.
    pub fn on_rto(&mut self, flight: u32) {
        self.ssthresh = (flight / 2).max(2 * self.mss);
        self.cwnd = self.mss;
    }

    /// Enter NewReno fast recovery (RFC 5681 §3.2 steps 2–3): halve, then
    /// inflate by the three segments that left the network.
    pub fn enter_fast_recovery(&mut self, flight: u32) {
        self.ssthresh = (flight / 2).max(2 * self.mss);
        self.cwnd = self.ssthresh + 3 * self.mss;
    }

    /// Enter SACK-based recovery (RFC 6675 §5): halve; transmission is then
    /// gated by the pipe estimate, not by window inflation.
    pub fn enter_sack_recovery(&mut self, flight: u32) {
        self.ssthresh = (flight / 2).max(2 * self.mss);
        self.cwnd = self.ssthresh;
    }

    /// An additional duplicate ACK during NewReno recovery
    /// (RFC 5681 §3.2 step 4): inflate by one SMSS.
    pub fn inflate(&mut self) {
        self.cwnd = (self.cwnd + self.mss).min(CWND_MAX);
    }

    /// Partial ACK during NewReno recovery (RFC 6582 §3.2 step 5): deflate
    /// by the amount acknowledged, then add back one SMSS.
    pub fn on_partial_ack(&mut self, acked: u32) {
        self.cwnd = self.cwnd.saturating_sub(acked).max(self.mss) + self.mss;
    }

    /// Recovery completed (RFC 6582 §3.2 step 1 / RFC 6675 §5.1): deflate
    /// to ssthresh.
    pub fn exit_recovery(&mut self) {
        self.cwnd = self.ssthresh.max(self.mss);
    }

    /// Effective MSS changed (PMTU reduction or peer MSS learned).
    pub fn set_mss(&mut self, mss: u32) {
        self.mss = mss.max(1);
        self.cwnd = self.cwnd.max(self.mss);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: u32 = 1460;

    #[test]
    fn initial_window_rfc3390() {
        assert_eq!(CongestionControl::new(1460).cwnd, 4380); // max(2920,4380)
        assert_eq!(CongestionControl::new(536).cwnd, 2144); // min(2144, 4380)
        assert_eq!(CongestionControl::new(2400).cwnd, 4800); // min(9600, max(4800,4380))
    }

    #[test]
    fn slow_start_doubles_per_rtt() {
        let mut cc = CongestionControl::new(MSS);
        let start = cc.cwnd;
        assert!(cc.in_slow_start());
        // Three full-MSS ACKs grow cwnd by 3*MSS.
        for _ in 0..3 {
            cc.on_new_ack(MSS);
        }
        assert_eq!(cc.cwnd, start + 3 * MSS);
    }

    #[test]
    fn congestion_avoidance_is_linear() {
        let mut cc = CongestionControl::new(MSS);
        cc.ssthresh = cc.cwnd; // force CA
        let before = cc.cwnd;
        cc.on_new_ack(MSS);
        let inc = cc.cwnd - before;
        assert!(inc >= 1 && inc <= MSS * MSS / before + 1, "inc={inc}");
        assert!(!cc.in_slow_start());
    }

    #[test]
    fn rto_collapses_window() {
        let mut cc = CongestionControl::new(MSS);
        cc.cwnd = 20 * MSS;
        cc.ssthresh = 10 * MSS;
        cc.on_rto(20 * MSS);
        assert_eq!(cc.ssthresh, 10 * MSS);
        assert_eq!(cc.cwnd, MSS);
        // Floor: 2*SMSS.
        cc.on_rto(MSS);
        assert_eq!(cc.ssthresh, 2 * MSS);
    }

    #[test]
    fn newreno_recovery_window_accounting() {
        let mut cc = CongestionControl::new(MSS);
        cc.cwnd = 16 * MSS;
        cc.ssthresh = 16 * MSS;
        cc.enter_fast_recovery(16 * MSS);
        assert_eq!(cc.ssthresh, 8 * MSS);
        assert_eq!(cc.cwnd, 11 * MSS);
        cc.inflate();
        assert_eq!(cc.cwnd, 12 * MSS);
        cc.on_partial_ack(4 * MSS);
        assert_eq!(cc.cwnd, 9 * MSS);
        cc.exit_recovery();
        assert_eq!(cc.cwnd, 8 * MSS);
    }

    #[test]
    fn sack_recovery_halves_without_inflation() {
        let mut cc = CongestionControl::new(MSS);
        cc.cwnd = 16 * MSS;
        cc.ssthresh = 16 * MSS;
        cc.enter_sack_recovery(16 * MSS);
        assert_eq!(cc.cwnd, 8 * MSS);
        assert_eq!(cc.ssthresh, 8 * MSS);
    }
}
