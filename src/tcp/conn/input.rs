//! Segment arrival processing: RFC 9293 §3.10.7 ("SEGMENT ARRIVES") with
//! the RFC 5961 blind-attack mitigations and RFC 2018/7323 option handling.
//!
//! The numbered steps below follow RFC 9293 §3.10.7.4 ("Other States"):
//! 1\. sequence-number acceptability, 2. RST, 4. SYN, 5. ACK, 7. text,
//! 8\. FIN. (Step 3 — security/compartment — and step 6 — URG — are
//! intentionally vacuous; see D-TCP-1/D-TCP-2 in `docs/TRACEABILITY.md`.)

use super::super::State;
use super::super::seq::SeqNr;
use super::{AckState, ConnEvent, Connection, Effects, ResetReply};
use crate::time::Instant;
use crate::types::{CloseReason, TimerKind};
use crate::wire::tcp::{TcpHeader, TcpOptions};

/// RFC 9293 §3.10.7.4 first check: is any part of the segment inside the
/// receive window?
fn seq_acceptable(rcv_nxt: SeqNr, wnd: u32, seq: SeqNr, seg_len: u32) -> bool {
    match (seg_len == 0, wnd == 0) {
        (true, true) => seq == rcv_nxt,
        (true, false) => seq.in_window(rcv_nxt, wnd),
        (false, true) => false,
        (false, false) => {
            seq.in_window(rcv_nxt, wnd) || seq.add(seg_len - 1).in_window(rcv_nxt, wnd)
        }
    }
}

impl<const SND: usize, const RCV: usize> Connection<SND, RCV> {
    /// Feed one validated, addressed-to-this-connection segment.
    pub fn on_segment(
        &mut self,
        now: Instant,
        h: &TcpHeader,
        opts: &TcpOptions,
        payload: &[u8],
        fx: &mut Effects,
    ) {
        match self.state {
            State::Closed => {}
            State::SynSent => self.on_segment_syn_sent(now, h, opts, fx),
            _ => self.on_segment_sync(now, h, opts, payload, fx),
        }
        self.update_send_timers(now);
        self.check_invariants();
    }

    /// RFC 9293 §3.10.7.3: SYN-SENT.
    fn on_segment_syn_sent(
        &mut self,
        now: Instant,
        h: &TcpHeader,
        opts: &TcpOptions,
        fx: &mut Effects,
    ) {
        let seq = SeqNr(h.seq);
        let ack = SeqNr(h.ack);

        // First: ACK check.
        let ack_acceptable = if h.flags.ack() {
            if ack.le(self.iss) || ack.gt(self.snd_nxt) {
                // "send a reset (unless the RST bit is set)" then drop.
                if !h.flags.rst() {
                    fx.reset_reply = Some(ResetReply {
                        seq: ack,
                        ack: None,
                    });
                }
                return;
            }
            true // SND.UNA < SEG.ACK <= SND.NXT holds (UNA == ISS here)
        } else {
            false
        };

        // Second: RST. Acceptable only alongside an acceptable ACK
        // (RFC 5961 §3 tightening of §3.10.7.3).
        if h.flags.rst() {
            if ack_acceptable {
                self.enter_closed(CloseReason::Refused, fx);
            }
            return;
        }

        // Fourth: SYN.
        if h.flags.syn() {
            self.irs = seq;
            self.rcv_nxt = seq.add(1);
            self.apply_syn_options(opts.mss, opts.window_scale, opts.sack_permitted);
            // RFC 7323 §2.2: the window in a SYN segment is never scaled.
            self.snd_wnd = h.window as u32;
            self.snd_max_wnd = self.snd_max_wnd.max(self.snd_wnd);
            self.snd_wl1 = seq;
            self.snd_wl2 = self.snd_una;

            if ack_acceptable {
                // Our SYN is acknowledged: SYN-SENT → ESTABLISHED.
                self.take_rtt_sample(now, ack);
                self.syn_acked = true;
                self.snd_una = ack;
                self.snd_wl2 = ack;
                self.rexmit_count = 0;
                self.timers[TimerKind::Rexmit as usize] = None;
                self.state = State::Established;
                self.reported = true;
                fx.event(ConnEvent::Connected);
                // ACK the SYN-ACK immediately (third leg of the handshake).
                self.set_ack(AckState::Now);
                // Data riding on a SYN-ACK is legal but rare; we do not
                // queue it (the peer retransmits it after the handshake) —
                // deviation D-TCP-3.
            } else {
                // Simultaneous open (RFC 9293 §3.10.7.3 / Figure 8):
                // SYN-SENT → SYN-RECEIVED; our SYN-ACK reuses ISS.
                self.state = State::SynReceived;
                self.syn_pending = true;
                self.timers[TimerKind::Rexmit as usize] = None;
            }
        }
        // Fifth: neither SYN nor RST → drop.
    }

    /// RFC 9293 §3.10.7.4: SYN-RECEIVED and all synchronized states.
    fn on_segment_sync(
        &mut self,
        now: Instant,
        h: &TcpHeader,
        opts: &TcpOptions,
        payload: &[u8],
        fx: &mut Effects,
    ) {
        let seq = SeqNr(h.seq);
        let ack = SeqNr(h.ack);
        let wnd = self.recv_buf.window();
        let seg_len = payload.len() as u32 + h.flags.syn() as u32 + h.flags.fin() as u32;

        // ---- Step 4 first: SYN (RFC 5961 §4.2) ----
        // RFC 5961 hoists the SYN check above the sequence-acceptability
        // check: a SYN MUST elicit a challenge ACK *irrespective of sequence
        // number*. Doing it after meant out-of-window SYNs took the
        // unconditional-ACK path while in-window SYNs consumed a challenge
        // token — a perfect oracle for the CVE-2016-5696 side channel
        // (DEF-M10).
        if h.flags.syn() && !h.flags.rst() {
            fx.wants_challenge = true;
            return;
        }

        // ---- Step 1: sequence acceptability ----
        if !seq_acceptable(self.rcv_nxt, wnd, seq, seg_len) {
            if h.flags.rst() {
                // Entirely outside the window: drop silently (RFC 5961 §3.2).
                return;
            }
            if self.state == State::TimeWait
                && h.flags.fin()
                && seq.add(seg_len) == self.rcv_nxt
            {
                // The genuine retransmitted FIN — and only it — restarts
                // the 2·MSL wait (RFC 9293 §3.10.7.4, TIME-WAIT special
                // case). An *arbitrary* out-of-window FIN must not, or an
                // off-path attacker who knows the 4-tuple can pin the slot
                // indefinitely (DEF-M21).
                self.enter_time_wait(now);
            }
            // RFC 9293 §3.10.7.4 step 1: "If the RCV.WND is zero … special
            // allowance should be made to accept valid ACKs". Without this,
            // a peer's piggybacked ACK is dropped whenever our receive
            // buffer is full, and our send side falsely aborts after
            // `max_data_retries` even though the peer is alive and
            // acknowledging every retransmit (DEF-M23).
            if h.flags.ack()
                && matches!(
                    self.state,
                    State::Established
                        | State::FinWait1
                        | State::FinWait2
                        | State::CloseWait
                        | State::Closing
                        | State::LastAck
                )
                && ack.le(self.snd_nxt)
                && ack.ge(self.snd_una.sub(self.snd_max_wnd.max(1)))
            {
                if self.snd_una.lt(ack) {
                    self.process_new_ack(now, ack, fx);
                }
                self.persist_count = 0;
            }
            // "send an acknowledgment: <SEQ=SND.NXT><ACK=RCV.NXT>"; this is
            // also the reply that answers zero-window probes.
            self.set_ack(AckState::Now);
            return;
        }

        // ---- Step 2: RST (RFC 5961 §3.2) ----
        if h.flags.rst() {
            if self.state == State::TimeWait {
                // RFC 1337 / RFC 9293 §3.10.7.4 note: ignore RST in
                // TIME-WAIT. Honoring it lets a rebooted peer's reflexive
                // RST destroy the 2·MSL quarantine and admit old segments
                // into a successor connection (DEF-H2).
                return;
            }
            if seq == self.rcv_nxt {
                self.process_rst(fx);
            } else {
                // In-window but not exact: challenge ACK instead of reset.
                fx.wants_challenge = true;
            }
            return;
        }

        // ---- Step 5: ACK ----
        if !h.flags.ack() {
            return; // "if the ACK bit is off, drop the segment"
        }

        if self.state == State::SynReceived {
            if self.snd_una.lt(ack) && ack.le(self.snd_nxt) {
                // SYN-RECEIVED → ESTABLISHED.
                self.state = State::Established;
                self.reported = true;
                fx.event(ConnEvent::Connected);
                // Fall through: the same segment may carry window/data/FIN.
            } else {
                // RFC 9293: "<SEQ=SEG.ACK><CTL=RST>" for an unacceptable
                // ACK in SYN-RECEIVED.
                fx.reset_reply = Some(ResetReply {
                    seq: ack,
                    ack: None,
                });
                return;
            }
        }

        // RFC 5961 §5.2 ACK acceptability for synchronized states:
        // SND.UNA - MAX.SND.WND <= SEG.ACK <= SND.NXT.
        if ack.gt(self.snd_nxt) || ack.lt(self.snd_una.sub(self.snd_max_wnd.max(1))) {
            self.set_ack(AckState::Now);
            return;
        }

        // SACK blocks inform the scoreboard before any dup-ack accounting
        // (RFC 6675 §2 DupAck definition).
        let new_sack = if self.sack_enabled && !opts.sack_blocks.is_empty() {
            self.scoreboard
                .ingest(opts.sack_blocks.as_slice(), self.snd_una, self.snd_nxt)
        } else {
            false
        };

        let old_una = self.snd_una;
        if self.snd_una.lt(ack) {
            self.process_new_ack(now, ack, fx);
        } else {
            // SEG.ACK <= SND.UNA: possibly a duplicate ACK (RFC 5681 §2).
            let pure = seg_len == 0;
            let window_unchanged = ((h.window as u32) << self.snd_scale) == self.snd_wnd;
            let outstanding = self.snd_nxt.since(self.snd_una) > 0;
            if ack == self.snd_una && pure && outstanding && (window_unchanged || new_sack) {
                self.on_dupack(new_sack);
            }
        }

        // Send-window update (RFC 9293 §3.10.7.4 step 5, second half).
        if ack.ge(old_una)
            && ack.le(self.snd_nxt)
            && (self.snd_wl1.lt(seq) || (self.snd_wl1 == seq && self.snd_wl2.le(ack)))
        {
            let new_wnd = (h.window as u32) << self.snd_scale;
            self.snd_wnd = new_wnd;
            self.snd_max_wnd = self.snd_max_wnd.max(new_wnd);
            self.snd_wl1 = seq;
            self.snd_wl2 = ack;
            // Any acceptable ACK proves the peer alive: reset the persist
            // abort counter (RFC 1122 §4.2.2.17 — probe indefinitely "as
            // long as the receiving TCP continues to send acknowledgments";
            // the cap in `on_timer` is for a silent peer only).
            self.persist_count = 0;
            if new_wnd > 0 {
                self.probe_pending = false;
            }
        }

        // ---- Step 6: URG — urgent pointer ignored (RFC 6093, D-TCP-2) ----

        // ---- Step 7: segment text ----
        if !payload.is_empty() {
            self.process_text(now, seq, payload, fx);
        }

        // ---- Step 8: FIN ----
        // Only states that have not yet processed the peer's FIN may record
        // one; otherwise a forged FIN at the (post-FIN) RCV.NXT would be
        // re-consumed, drifting RCV.NXT and emitting duplicate `PeerFin`
        // events (DEF-M1).
        if h.flags.fin()
            && matches!(
                self.state,
                State::SynReceived | State::Established | State::FinWait1 | State::FinWait2
            )
        {
            let fin_seq = seq.add(payload.len() as u32);
            // Only honor a FIN that is inside (or exactly at) the window;
            // one beyond the right edge was trimmed away with its data.
            // Never move an already-recorded FIN backward (an injected
            // earlier FIN would truncate the legitimate stream — DEF-H8).
            if (fin_seq == self.rcv_nxt || fin_seq.in_window(self.rcv_nxt, wnd.max(1)))
                && self.peer_fin.is_none_or(|f| fin_seq.ge(f))
            {
                self.peer_fin = Some(fin_seq);
            }
        }
        self.try_consume_fin(now, fx);
    }

    /// RFC 9293 §3.10.7.4 step 2 reset processing, per state group.
    fn process_rst(&mut self, fx: &mut Effects) {
        match self.state {
            // Passive SYN-RECEIVED returns to LISTEN silently; an active
            // (simultaneous-open) one reports refusal. `enter_closed`
            // handles the silent/reported distinction via `self.reported`.
            State::SynReceived => {
                let reason = if self.passive {
                    CloseReason::Reset
                } else {
                    CloseReason::Refused
                };
                self.enter_closed(reason, fx);
            }
            State::Established | State::FinWait1 | State::FinWait2 | State::CloseWait => {
                self.enter_closed(CloseReason::Reset, fx);
            }
            // Closing, LastAck, TimeWait: both sides were already done.
            _ => self.enter_closed(CloseReason::Normal, fx),
        }
    }

    /// SND.UNA < SEG.ACK <= SND.NXT: new data acknowledged.
    fn process_new_ack(&mut self, now: Instant, ack: SeqNr, fx: &mut Effects) {
        let acked_total = ack.since(self.snd_una);
        let mut acked_data = acked_total;
        if !self.syn_acked {
            // First new ACK in a synchronized state covers our SYN (it was
            // at SND.UNA == ISS). Positional `snd_una == iss` would re-fire
            // after `snd_una` wraps past `iss` (DEF-C3).
            self.syn_acked = true;
            acked_data -= 1;
        }
        let fin_acked = match self.fin_seq {
            Some(f) if ack.gt(f) => {
                acked_data -= 1; // our FIN unit
                true
            }
            _ => false,
        };
        self.send_buf.ack(acked_data as usize);
        self.snd_una = ack;
        self.scoreboard.on_ack_advance(ack);
        if self.sack_cursor.lt(ack) {
            self.sack_cursor = ack;
        }

        self.take_rtt_sample(now, ack);
        self.rexmit_count = 0;

        // RFC 6298 §5.3: restart the retransmission timer on new data
        // acked; §5.2: stop it when everything is acknowledged (the stop is
        // centralized in `update_send_timers`).
        if self.snd_nxt.since(self.snd_una) > 0 {
            self.timers[TimerKind::Rexmit as usize] = Some(now + self.rtt.rto());
        }

        // Congestion control / loss recovery.
        match self.recovery {
            Some(point) if ack.ge(point) => {
                // Full ACK: recovery complete (RFC 6582 §3.2 step 1).
                self.cc.exit_recovery();
                self.recovery = None;
                self.dupacks = 0;
            }
            Some(_) if !self.sack_enabled => {
                // NewReno partial ACK (RFC 6582 §3.2 step 5): retransmit
                // the segment now at the head, deflate.
                self.rexmit_now = true;
                self.cc.on_partial_ack(acked_total);
            }
            Some(_) => {
                // SACK recovery: pipe gating in the planner does the work.
                // DEF-L46: when the scoreboard is degenerate (no holes
                // above the cursor — e.g. a malicious receiver SACKed
                // only [una, una+1)), `plan_sack_rexmit` returns None and
                // recovery would idle until RTO. Fall back to a NewReno-
                // style head retransmit on the partial ACK so progress is
                // bounded by RTT, not RTO.
                if self.scoreboard.next_hole(self.snd_una).is_none() {
                    self.rexmit_now = true;
                }
            }
            None => {
                self.dupacks = 0;
                self.cc.on_new_ack(acked_total);
            }
        }

        // Writable edge: the app saw a full buffer at some point.
        if self.app_blocked && self.send_buf.space() > 0 {
            self.app_blocked = false;
            fx.event(ConnEvent::Writable);
        }

        if fin_acked {
            match self.state {
                State::FinWait1 => {
                    self.state = State::FinWait2;
                    if self.cfg_fin_wait2_timeout > crate::time::Duration::ZERO {
                        self.timers[TimerKind::Wait as usize] =
                            Some(now + self.cfg_fin_wait2_timeout);
                    }
                }
                State::Closing => self.enter_time_wait(now),
                State::LastAck => self.enter_closed(CloseReason::Normal, fx),
                _ => {}
            }
        }
    }

    /// RFC 5681 §2: duplicate-ACK accounting; §3.2: fast retransmit on the
    /// third, with SACK-based recovery (RFC 6675-style) when negotiated.
    fn on_dupack(&mut self, new_sack: bool) {
        if self.recovery.is_some() {
            if !self.sack_enabled {
                // RFC 5681 §3.2 step 4: inflate for each additional dup ACK.
                self.cc.inflate();
            }
            return;
        }
        self.dupacks = self.dupacks.saturating_add(1);
        let _ = new_sack;
        if self.dupacks == 3 {
            let flight = self.flight_size();
            self.recovery = Some(self.snd_nxt);
            self.rtt_sample = None; // Karn: retransmissions follow
            if self.sack_enabled {
                self.cc.enter_sack_recovery(flight);
                self.sack_cursor = self.snd_una;
            } else {
                self.cc.enter_fast_recovery(flight);
            }
            // Fast retransmit of the presumed-lost head segment.
            self.rexmit_now = true;
        }
    }

    /// RFC 9293 §3.10.7.4 step 7: deliver segment text.
    fn process_text(&mut self, now: Instant, seq: SeqNr, payload: &[u8], fx: &mut Effects) {
        if !matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        ) {
            // "This should not occur ... ignore the segment text"
            // (a FIN was already received from the peer).
            return;
        }
        // Left-trim anything before RCV.NXT (old duplicate bytes).
        let (start_off, data) = if seq.lt(self.rcv_nxt) {
            let skip = self.rcv_nxt.since(seq) as usize;
            if skip >= payload.len() {
                // Entirely duplicate: immediate ACK (RFC 5681 §4.2).
                self.set_ack(AckState::Now);
                return;
            }
            (0u32, &payload[skip..])
        } else {
            (seq.since(self.rcv_nxt), payload)
        };
        // Right-trim to the window — and to the peer's FIN if one is
        // recorded, so RCV.NXT can never step *past* the FIN sequence
        // (which would leave the FIN forever unconsumed and desync both
        // sides — DEF-M2). A well-behaved peer never sends data beyond its
        // FIN; this guards against injected or buggy segments.
        let mut room = self.recv_buf.window().saturating_sub(start_off);
        if let Some(f) = self.peer_fin {
            room = room.min(f.since(self.rcv_nxt).saturating_sub(start_off));
        }
        let take = (data.len() as u32).min(room) as usize;
        if take == 0 {
            self.set_ack(AckState::Now);
            return;
        }
        let was_readable = self.recv_buf.readable() > 0;
        let insert_at = self.recv_buf.readable() as u32 + start_off;
        let ins = self.recv_buf.insert(insert_at, &data[..take]);
        if !ins.stored {
            // Out-of-order budget exhausted: behave as a plain dup-ACK so
            // the sender retransmits in order.
            self.set_ack(AckState::Now);
            return;
        }
        if ins.advance > 0 {
            self.rcv_nxt = self.rcv_nxt.add(ins.advance);
            if !was_readable {
                fx.event(ConnEvent::Readable);
            }
            // DEF-L31: the FIN-WAIT-2 orphan timeout guards against a
            // *silent* peer; a peer that is provably alive (sending data)
            // refreshes it so a legitimate long half-close receive isn't
            // truncated.
            if self.state == State::FinWait2
                && self.cfg_fin_wait2_timeout > crate::time::Duration::ZERO
            {
                self.timers[TimerKind::Wait as usize] = Some(now + self.cfg_fin_wait2_timeout);
            }
            // RFC 1122 §4.2.3.2: an ACK at least every second full-sized
            // segment; otherwise the delayed-ACK timer covers it.
            self.segs_since_ack = self.segs_since_ack.saturating_add(1);
            if self.segs_since_ack >= 2 || take < data.len() {
                self.set_ack(AckState::Now);
            } else {
                self.ack_delayed(now);
            }
        } else {
            // Out-of-order segment: immediate duplicate ACK so the sender's
            // fast retransmit can trigger (RFC 5681 §3.2).
            self.set_ack(AckState::Now);
        }
    }

    /// RFC 9293 §3.10.7.4 step 8, deferred until the FIN is in order.
    fn try_consume_fin(&mut self, now: Instant, fx: &mut Effects) {
        // Only the pre-FIN states consume one; everywhere else the peer's
        // FIN is already accounted for (DEF-M1).
        if !matches!(
            self.state,
            State::SynReceived | State::Established | State::FinWait1 | State::FinWait2
        ) {
            return;
        }
        let Some(f) = self.peer_fin else { return };
        if f != self.rcv_nxt {
            return; // data before the FIN still missing
        }
        self.peer_fin = None;
        self.rcv_nxt = self.rcv_nxt.add(1);
        self.set_ack(AckState::Now);
        fx.event(ConnEvent::PeerFin);
        match self.state {
            State::SynReceived | State::Established => self.state = State::CloseWait,
            // If this same segment also acked our FIN, step 5 already moved
            // us to FIN-WAIT-2, handled below.
            State::FinWait1 => self.state = State::Closing,
            State::FinWait2 => self.enter_time_wait(now),
            _ => {}
        }
    }

    /// Take an RTT sample if the timed segment is covered and was never
    /// retransmitted (Karn's algorithm, RFC 6298 §3).
    fn take_rtt_sample(&mut self, now: Instant, ack: SeqNr) {
        if let Some((end, sent_at)) = self.rtt_sample
            && ack.ge(end)
        {
            self.rtt.on_sample(now.saturating_since(sent_at));
            self.rtt_sample = None;
        }
    }

    /// The stack granted a rate-limited challenge ACK (RFC 5961 §10).
    pub fn grant_challenge(&mut self) {
        self.set_ack(AckState::Now);
    }
}
