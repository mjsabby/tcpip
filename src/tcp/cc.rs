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
    /// RFC 3465 (ABC) byte-counting accumulator for congestion avoidance:
    /// add one MSS to `cwnd` only after a full `cwnd`'s worth of bytes has
    /// been acknowledged. Without this, splitting one segment into N
    /// micro-ACKs grows `cwnd` N× faster (Savage et al. 1999, DEF-M9).
    ca_bytes_acked: u32,
    /// Remaining MSS-units of NewReno window inflation this recovery
    /// episode may grant. Unbounded inflation lets a malicious receiver
    /// stream dup-ACKs to blow `cwnd` to `CWND_MAX` (Savage et al. §4.2,
    /// DEF-M8); the cap is the segments-outstanding at recovery entry.
    inflate_budget: u32,
}

impl CongestionControl {
    /// Initial state: IW per RFC 3390 (as referenced by RFC 5681 §3.1),
    /// ssthresh effectively unbounded.
    pub fn new(mss: u32) -> Self {
        let mss = mss.clamp(1, u16::MAX as u32);
        CongestionControl {
            cwnd: Self::initial_window(mss),
            ssthresh: CWND_MAX,
            mss,
            ca_bytes_acked: 0,
            inflate_budget: 0,
        }
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
            // RFC 5681 §3.1: cwnd += min(N, SMSS) per ACK. This *is*
            // ACK-division-safe: splitting one segment's ACK into M
            // sub-ACKs of N/M bytes each yields M × min(N/M, mss) ≤ N —
            // growth is bounded by bytes acknowledged, not ACK count.
            // ABC's L=2 (RFC 3465 §2.2) would only *speed up* stretch
            // ACKs; the conservative L=1 here is the RFC 5681 default.
            self.cwnd = (self.cwnd + acked.min(self.mss)).min(CWND_MAX);
        } else {
            // Congestion avoidance, RFC 3465 (ABC): accumulate bytes
            // acknowledged and grow `cwnd` by one MSS per `cwnd` bytes
            // acked. Unlike per-ACK `mss²/cwnd`, this is immune to
            // ACK-division (DEF-M9).
            self.ca_bytes_acked = self.ca_bytes_acked.saturating_add(acked);
            if self.ca_bytes_acked >= self.cwnd {
                self.ca_bytes_acked -= self.cwnd;
                self.cwnd = (self.cwnd + self.mss).min(CWND_MAX);
            }
        }
    }

    /// Retransmission timeout (RFC 5681 §3.1 eq. 4): ssthresh =
    /// max(FlightSize/2, 2*SMSS); cwnd = 1 "loss window" of one segment.
    pub fn on_rto(&mut self, flight: u32) {
        self.ssthresh = (flight / 2).max(2 * self.mss);
        self.cwnd = self.mss;
        self.ca_bytes_acked = 0;
        self.inflate_budget = 0;
    }

    /// Enter NewReno fast recovery (RFC 5681 §3.2 steps 2–3): halve, then
    /// inflate by the three segments that left the network.
    pub fn enter_fast_recovery(&mut self, flight: u32) {
        self.ssthresh = (flight / 2).max(2 * self.mss);
        self.cwnd = self.ssthresh + 3 * self.mss;
        // Further inflation is bounded by the segments that were actually
        // in flight: each legitimate dup-ACK reflects one such segment
        // leaving the network (DEF-M8).
        self.inflate_budget = (flight / self.mss.max(1)).saturating_sub(3);
    }

    /// Enter SACK-based recovery (RFC 6675 §5): halve; transmission is then
    /// gated by the pipe estimate, not by window inflation.
    pub fn enter_sack_recovery(&mut self, flight: u32) {
        self.ssthresh = (flight / 2).max(2 * self.mss);
        self.cwnd = self.ssthresh;
    }

    /// An additional duplicate ACK during NewReno recovery
    /// (RFC 5681 §3.2 step 4): inflate by one SMSS, up to the per-episode
    /// budget set at recovery entry.
    pub fn inflate(&mut self) {
        if self.inflate_budget > 0 {
            self.inflate_budget -= 1;
            self.cwnd = (self.cwnd + self.mss).min(CWND_MAX);
        }
    }

    /// Partial ACK during NewReno recovery (RFC 6582 §3.2 step 5): deflate
    /// by the amount acknowledged, then add back one SMSS. The deflate term
    /// is floored at one SMSS so that a receiver splitting one segment's
    /// acknowledgment into N micro-ACKs cannot grow `cwnd` by ~N·SMSS
    /// (Savage et al. 1999 — the same attack DEF-M8/M9 close on the dup-ACK
    /// and CA paths; this was the third vector, DEF-H11).
    pub fn on_partial_ack(&mut self, acked: u32) {
        self.cwnd = self
            .cwnd
            .saturating_sub(acked.max(self.mss))
            .max(self.mss)
            .saturating_add(self.mss)
            .min(CWND_MAX);
    }

    /// Recovery completed (RFC 6582 §3.2 step 1 / RFC 6675 §5.1): deflate
    /// to ssthresh.
    pub fn exit_recovery(&mut self) {
        self.cwnd = self.ssthresh.max(self.mss);
        self.inflate_budget = 0;
        self.ca_bytes_acked = 0;
    }

    /// Effective MSS changed (PMTU reduction or peer MSS learned).
    pub fn set_mss(&mut self, mss: u32) {
        self.mss = mss.clamp(1, u16::MAX as u32);
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
        // ABC: a full cwnd of bytes acked → one MSS added.
        cc.on_new_ack(before);
        assert_eq!(cc.cwnd, before + MSS);
        assert!(!cc.in_slow_start());
    }

    /// DEF-M9: splitting one MSS-sized segment into byte-ACKs must not grow
    /// cwnd faster than one cumulative ACK would.
    #[test]
    fn ack_division_does_not_accelerate_ca() {
        let mut a = CongestionControl::new(MSS);
        let mut b = CongestionControl::new(MSS);
        a.ssthresh = a.cwnd;
        b.ssthresh = b.cwnd;
        let cwnd0 = a.cwnd;
        // One window's worth of data, ACKed as one chunk vs. as bytes.
        a.on_new_ack(cwnd0);
        for _ in 0..cwnd0 {
            b.on_new_ack(1);
        }
        assert_eq!(a.cwnd, b.cwnd, "ACK division must not accelerate CA growth");
    }

    /// DEF-M8: a flood of dup-ACKs cannot inflate cwnd past what
    /// segments-outstanding-at-entry would justify.
    #[test]
    fn dupack_inflation_is_bounded_by_flight() {
        let mut cc = CongestionControl::new(MSS);
        cc.cwnd = 16 * MSS;
        cc.enter_fast_recovery(16 * MSS);
        let after_entry = cc.cwnd; // ssthresh + 3*MSS
        for _ in 0..10_000 {
            cc.inflate();
        }
        // 16 segments in flight, 3 already accounted at entry → ≤ 13 more.
        assert!(cc.cwnd <= after_entry + 13 * MSS);
    }

    #[test]
    fn partial_ack_division_does_not_grow_cwnd() {
        // DEF-H11: a malicious receiver splitting one segment's
        // acknowledgment into N 1-byte partial ACKs must not grow cwnd
        // by ~N·MSS (the third Savage'99 vector — `inflate` and
        // `on_new_ack` were already guarded; `on_partial_ack` was not).
        let mut cc = CongestionControl::new(MSS);
        cc.cwnd = 16 * MSS;
        cc.enter_fast_recovery(16 * MSS);
        let after_entry = cc.cwnd;
        for _ in 0..1_000_000 {
            cc.on_partial_ack(1);
        }
        assert!(
            cc.cwnd <= after_entry,
            "cwnd grew under partial-ACK division: {} > {}",
            cc.cwnd,
            after_entry
        );
        assert!(cc.cwnd <= CWND_MAX);
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
        assert_eq!(cc.inflate_budget, 13);
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
