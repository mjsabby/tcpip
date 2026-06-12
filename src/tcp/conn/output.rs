//! Segment planning: decide what (single) segment to emit next.
//!
//! `next_segment` is called repeatedly by the stack's `poll_action`; each
//! call commits to one segment (state such as SND.NXT advances here), which
//! the stack serializes and transmits immediately. Priority order:
//! head retransmission, SACK-hole retransmission, new data, FIN,
//! zero-window probe, pure ACK.

use super::super::State;
use super::super::seq::SeqNr;
use super::{AckState, Connection};
use crate::time::Instant;
use crate::types::TimerKind;
use crate::util::BoundedVec;
use crate::wire::tcp::TcpFlags;

/// Options carried only on SYN / SYN-ACK segments.
#[derive(Debug, Clone, Copy)]
pub struct SynOpts {
    /// MSS we advertise (RFC 9293 §3.7.1).
    pub mss: u16,
    /// Window-scale shift to send (RFC 7323 §2.2).
    pub wscale: Option<u8>,
    /// SACK-permitted (RFC 2018 §2).
    pub sack_permitted: bool,
}

/// One planned segment. `payload_off` is relative to SND.UNA at plan time;
/// the stack serializes immediately, so the offset cannot go stale.
#[derive(Debug, Clone, Copy)]
pub struct SegmentPlan {
    /// Sequence number.
    pub seq: SeqNr,
    /// Acknowledgment number (sets the ACK flag when present).
    pub ack: Option<SeqNr>,
    /// SYN/FIN/PSH flags (ACK implied by `ack`).
    pub flags: TcpFlags,
    /// Window field value, already scaled down.
    pub window: u16,
    /// Payload offset from SND.UNA in the send buffer.
    pub payload_off: u32,
    /// Payload length.
    pub payload_len: u32,
    /// SYN options, present on SYN/SYN-ACK only.
    pub syn_opts: Option<SynOpts>,
    /// SACK blocks (absolute sequence numbers) to advertise (RFC 2018 §4).
    pub sack_blocks: BoundedVec<(u32, u32), 4>,
}

impl<const SND: usize, const RCV: usize> Connection<SND, RCV> {
    /// Plan the next segment to transmit, if any.
    pub fn next_segment(&mut self, now: Instant) -> Option<SegmentPlan> {
        let plan = match self.state {
            State::Closed => None,
            State::SynSent => self.plan_syn(now, false),
            State::SynReceived => self.plan_syn(now, true).or_else(|| self.plan_sync(now)),
            _ => self.plan_sync(now),
        };
        if plan.is_some() {
            self.update_send_timers(now);
        }
        self.check_invariants();
        plan
    }

    /// SYN (active) or SYN-ACK (passive / simultaneous open).
    fn plan_syn(&mut self, now: Instant, with_ack: bool) -> Option<SegmentPlan> {
        if !self.syn_pending {
            return None;
        }
        self.syn_pending = false;
        if self.timers[TimerKind::Rexmit as usize].is_none() {
            self.timers[TimerKind::Rexmit as usize] = Some(now + self.rtt.rto());
        }
        if self.rexmit_count == 0 {
            // Time the handshake for the first RTT sample (Karn-safe: the
            // sample is dropped on retransmission).
            self.rtt_sample = Some((self.snd_nxt, now));
        }
        // RFC 7323 §2.2: the window field in a SYN segment is not scaled.
        let window = self.recv_buf.window().min(u16::MAX as u32) as u16;
        self.last_wnd_advertised = window as u32;
        let syn_opts = if with_ack {
            // SYN-ACK: echo only what the peer's SYN enabled (RFC 7323
            // §2.2, RFC 2018 §2: don't send unless offered).
            SynOpts {
                mss: self.params.local_mss,
                wscale: self.wscale_on.then_some(self.rcv_scale),
                sack_permitted: self.sack_enabled,
            }
        } else {
            SynOpts {
                mss: self.params.local_mss,
                wscale: self.params.offer_wscale,
                sack_permitted: self.params.offer_sack,
            }
        };
        self.mark_ack_sent();
        Some(SegmentPlan {
            seq: self.iss,
            ack: with_ack.then_some(self.rcv_nxt),
            flags: TcpFlags::SYN,
            window,
            payload_off: 0,
            payload_len: 0,
            syn_opts: Some(syn_opts),
            sack_blocks: BoundedVec::new(),
        })
    }

    fn plan_sync(&mut self, now: Instant) -> Option<SegmentPlan> {
        if self.rexmit_now {
            self.rexmit_now = false;
            if let Some(p) = self.plan_head_rexmit(now) {
                return Some(p);
            }
        }
        if self.recovery.is_some()
            && self.sack_enabled
            && let Some(p) = self.plan_sack_rexmit(now)
        {
            return Some(p);
        }
        if let Some(p) = self.plan_data(now) {
            return Some(p);
        }
        if let Some(p) = self.plan_fin(now) {
            return Some(p);
        }
        if self.probe_pending {
            self.probe_pending = false;
            if let Some(p) = self.plan_probe(now) {
                return Some(p);
            }
        }
        if self.ack_state == AckState::Now {
            return Some(self.plan_pure_ack());
        }
        None
    }

    /// Retransmit the earliest unacknowledged segment (RTO, fast
    /// retransmit, NewReno partial ACK, or PMTU shrink).
    fn plan_head_rexmit(&mut self, now: Instant) -> Option<SegmentPlan> {
        // While the SYN is unacknowledged the head segment *is* the SYN /
        // SYN-ACK regardless of state — close() may have moved us out of
        // SYN-RECEIVED before the SYN-ACK was acknowledged (DEF-L32).
        if !self.syn_acked {
            self.syn_pending = true;
            return self.plan_syn(now, self.state != State::SynSent);
        }
        let data_avail = self.data_sent();
        // DEF-C5: charge SACK option bytes against the MSS budget so the IP
        // datagram never exceeds PMTU (RFC 6691).
        let sack_blocks = self.recv_sack_blocks();
        let mss = (self.eff_send_mss() as u32).saturating_sub(Self::sack_opt_len(&sack_blocks));
        let len = data_avail.min(mss.max(1));
        let fin_here = match self.fin_seq {
            Some(f) => f == self.snd_una.add(len) && f.lt(self.snd_nxt),
            None => false,
        };
        if len == 0 && !fin_here {
            return None; // nothing outstanding (stale flag)
        }
        self.rtt_sample = None; // Karn: anything covering this is tainted
        if self.timers[TimerKind::Rexmit as usize].is_none() {
            self.timers[TimerKind::Rexmit as usize] = Some(now + self.rtt.rto());
        }
        // RFC 6675: HighRxt covers the fast retransmit. Without this the
        // very next `plan_sack_rexmit` finds the same hole at SND.UNA and
        // emits the head segment a second time (DEF-L5).
        if self.sack_enabled && self.sack_cursor.lt(self.snd_una.add(len.max(1))) {
            self.sack_cursor = self.snd_una.add(len.max(1));
        }
        let mut flags = TcpFlags::default();
        if fin_here {
            flags = flags.union(TcpFlags::FIN);
        }
        if len > 0 {
            flags = flags.union(TcpFlags::PSH);
        }
        let window = self.advertise_window();
        self.mark_ack_sent();
        Some(SegmentPlan {
            seq: self.snd_una,
            ack: Some(self.rcv_nxt),
            flags,
            window,
            payload_off: 0,
            payload_len: len,
            syn_opts: None,
            sack_blocks,
        })
    }

    /// SACK-based recovery (RFC 6675-lite): retransmit the next hole below
    /// the highest SACKed sequence while the pipe has room.
    fn plan_sack_rexmit(&mut self, now: Instant) -> Option<SegmentPlan> {
        let pipe = self
            .flight_size()
            .saturating_sub(self.scoreboard.sacked_bytes());
        if pipe >= self.cc.cwnd {
            return None;
        }
        let from = if self.sack_cursor.lt(self.snd_una) {
            self.snd_una
        } else {
            self.sack_cursor
        };
        let (start, hole_len) = self.scoreboard.next_hole(from)?;
        // The hole may include our FIN's sequence slot; data lives below
        // `data_end`.
        let data_end = self.snd_una.add(self.data_sent());
        // DEF-C5: charge SACK option bytes against the MSS budget.
        let sack_blocks = self.recv_sack_blocks();
        let mss = (self.eff_send_mss() as u32).saturating_sub(Self::sack_opt_len(&sack_blocks));
        let mut flags = TcpFlags::default();
        let (len, fin_here) = if start.ge(data_end) {
            (0, self.fin_seq.is_some())
        } else {
            let avail = data_end.since(start);
            (hole_len.min(avail).min(mss.max(1)), false)
        };
        if len == 0 && !fin_here {
            return None;
        }
        if fin_here {
            flags = flags.union(TcpFlags::FIN);
        } else {
            flags = flags.union(TcpFlags::PSH);
        }
        self.sack_cursor = start.add(len.max(1));
        self.rtt_sample = None; // Karn
        if self.timers[TimerKind::Rexmit as usize].is_none() {
            self.timers[TimerKind::Rexmit as usize] = Some(now + self.rtt.rto());
        }
        let window = self.advertise_window();
        self.mark_ack_sent();
        Some(SegmentPlan {
            seq: start,
            ack: Some(self.rcv_nxt),
            flags,
            window,
            payload_off: start.since(self.snd_una),
            payload_len: len,
            syn_opts: None,
            sack_blocks,
        })
    }

    /// New data within min(SND.WND, cwnd), MSS-sized, Nagle-respecting.
    ///
    /// Data is transmittable wherever the local side may still send into the
    /// stream *or* is draining queued sends ahead of a FIN: ESTABLISHED and
    /// CLOSE-WAIT (app may still send), and FIN-WAIT-1 / LAST-ACK, where the
    /// app has closed but data queued before the FIN must still go out
    /// (RFC 9293 §3.10.4: "queue this until all preceding SENDs have been
    /// segmentized, then form a FIN segment"). Omitting LAST-ACK here strands
    /// any send-buffer bytes not yet transmitted when CLOSE-WAIT→LAST-ACK.
    fn plan_data(&mut self, now: Instant) -> Option<SegmentPlan> {
        // DEF-H7: include CLOSING — a simultaneous close that races queued
        // data must still drain it (RFC 9293 §3.10.4).
        if !matches!(
            self.state,
            State::Established
                | State::CloseWait
                | State::FinWait1
                | State::Closing
                | State::LastAck
        ) {
            return None;
        }
        if self.fin_seq.is_some() {
            return None; // never send data above our FIN
        }
        let unsent = self.unsent();
        if unsent == 0 {
            return None;
        }
        let in_flight_seq = self.snd_nxt.since(self.snd_una);
        let usable = self.snd_wnd.min(self.cc.cwnd).saturating_sub(in_flight_seq);
        if usable == 0 {
            return None; // zero window → persist machinery takes over
        }
        // DEF-C5: charge SACK option bytes against the MSS budget so the IP
        // datagram never exceeds PMTU (RFC 6691).
        let sack_blocks = self.recv_sack_blocks();
        let mss = (self.eff_send_mss() as u32).saturating_sub(Self::sack_opt_len(&sack_blocks));
        let len = unsent.min(usable).min(mss.max(1));
        // Nagle (RFC 9293 §3.7.4): hold small segments while data is in
        // flight — unless this small segment finishes the stream (FIN rides
        // along) or Nagle is disabled.
        let finishes_stream = self.fin_queued && len == unsent;
        if self.cfg_nagle && len < mss && self.bytes_in_flight() > 0 && !finishes_stream {
            return None;
        }
        // Sender-side SWS avoidance (RFC 9293 §3.8.6.2.1): independently of
        // Nagle, do not send a tiny segment into a tiny *peer* window unless
        // it empties our buffer — a peer that drip-feeds 1-byte windows
        // would otherwise elicit 1-byte segments at 40× header overhead.
        // Hold only while data is in flight (an ACK is en route to widen
        // the usable window); when idle, send what fits so the persist
        // mechanism — not silence — covers the small-window case
        // (RFC 9293 condition (4) "override timeout", DEF-L47).
        if len < mss
            && len < self.snd_max_wnd / 2
            && len < unsent
            && self.bytes_in_flight() > 0
        {
            return None;
        }
        let payload_off = self.data_sent();
        let seq = self.snd_nxt;
        self.snd_nxt = self.snd_nxt.add(len);
        let mut flags = TcpFlags::PSH;
        if finishes_stream {
            // Piggyback the FIN on the last data segment.
            self.fin_seq = Some(self.snd_nxt);
            self.snd_nxt = self.snd_nxt.add(1);
            flags = flags.union(TcpFlags::FIN);
        }
        if self.timers[TimerKind::Rexmit as usize].is_none() {
            self.timers[TimerKind::Rexmit as usize] = Some(now + self.rtt.rto());
        }
        if self.rtt_sample.is_none() && self.recovery.is_none() {
            self.rtt_sample = Some((self.snd_nxt, now));
        }
        let window = self.advertise_window();
        self.mark_ack_sent();
        Some(SegmentPlan {
            seq,
            ack: Some(self.rcv_nxt),
            flags,
            window,
            payload_off,
            payload_len: len,
            syn_opts: None,
            sack_blocks,
        })
    }

    /// A FIN of its own once all data is out (close, or peer-close reply).
    fn plan_fin(&mut self, now: Instant) -> Option<SegmentPlan> {
        if !self.fin_queued || self.fin_seq.is_some() || self.unsent() != 0 {
            return None;
        }
        // DEF-H7: include CLOSING — peer's FIN may arrive before ours leaves.
        if !matches!(self.state, State::FinWait1 | State::Closing | State::LastAck) {
            return None;
        }
        self.fin_seq = Some(self.snd_nxt);
        let seq = self.snd_nxt;
        self.snd_nxt = self.snd_nxt.add(1);
        if self.timers[TimerKind::Rexmit as usize].is_none() {
            self.timers[TimerKind::Rexmit as usize] = Some(now + self.rtt.rto());
        }
        let window = self.advertise_window();
        self.mark_ack_sent();
        Some(SegmentPlan {
            seq,
            ack: Some(self.rcv_nxt),
            flags: TcpFlags::FIN,
            window,
            payload_off: 0,
            payload_len: 0,
            syn_opts: None,
            sack_blocks: BoundedVec::new(),
        })
    }

    /// Zero-window probe (RFC 9293 §3.8.6.1): one byte at SND.NXT.
    ///
    /// SND.NXT *is* advanced (BSD/Linux behavior), so the probe byte is
    /// genuinely in flight: if the peer's window has reopened in the
    /// meantime and it accepts the byte, its ACK of `SND.NXT` is honored
    /// instead of being rejected by the `ack > SND.NXT` check (which would
    /// permanently wedge both directions — DEF-C4). Retransmission of an
    /// unanswered probe is the persist timer's job; `plan_head_rexmit`
    /// resends the same byte without consuming the data-retry budget.
    fn plan_probe(&mut self, now: Instant) -> Option<SegmentPlan> {
        if self.snd_wnd > 0 || self.send_buf.is_empty() {
            return None;
        }
        // First probe advances SND.NXT; subsequent persist fires retransmit
        // the same byte at SND.UNA (it is the head of the buffer either way).
        let seq = self.snd_una;
        if self.snd_nxt == self.snd_una {
            self.snd_nxt = self.snd_nxt.add(1);
        }
        let payload_off = 0;
        // The persist timer (not Rexmit) drives retransmission of this byte
        // so a peer that keeps ACKing with window 0 — alive but full — does
        // not march `rexmit_count` toward `max_data_retries`. A *silent*
        // peer is bounded by `max_persist_retries` instead (DEF-H1).
        let _ = now;
        let window = self.advertise_window();
        self.mark_ack_sent();
        Some(SegmentPlan {
            seq,
            ack: Some(self.rcv_nxt),
            flags: TcpFlags::default(),
            window,
            payload_off,
            payload_len: 1,
            syn_opts: None,
            sack_blocks: BoundedVec::new(),
        })
    }

    /// Pure ACK: window update, delayed/forced ACK, challenge ACK, dup ACK.
    fn plan_pure_ack(&mut self) -> SegmentPlan {
        let window = self.advertise_window();
        self.mark_ack_sent();
        SegmentPlan {
            seq: self.snd_nxt,
            ack: Some(self.rcv_nxt),
            flags: TcpFlags::default(),
            window,
            payload_off: 0,
            payload_len: 0,
            syn_opts: None,
            sack_blocks: self.recv_sack_blocks(),
        }
    }

    /// Window to advertise (RFC 7323 §2.3: shifted right by our scale).
    fn advertise_window(&mut self) -> u16 {
        // DEF-L35: never let the right edge `RCV.NXT + RCV.WND` retreat
        // (RFC 9293 §3.8.6.2.1 SHOULD-NOT). Scale truncation alone can
        // shrink it by up to `2^scale − 1` bytes per ACK; track the last
        // advertised right edge and floor the window at the distance to it.
        let buf_wnd = self.recv_buf.window();
        let edge_wnd = self.rcv_adv.since(self.rcv_nxt).min(buf_wnd);
        let w = buf_wnd.max(edge_wnd);
        let field = (w >> self.rcv_scale).min(u16::MAX as u32) as u16;
        // Track what the peer will perceive, for SWS and the next call.
        self.last_wnd_advertised = (field as u32) << self.rcv_scale;
        self.rcv_adv = self.rcv_nxt.add(self.last_wnd_advertised);
        field
    }

    /// SACK blocks describing our out-of-order queue (RFC 2018 §4).
    fn recv_sack_blocks(&self) -> BoundedVec<(u32, u32), 4> {
        let mut out: BoundedVec<(u32, u32), 4> = BoundedVec::new();
        if self.sack_enabled {
            let mut rel: BoundedVec<(u32, u32), 4> = BoundedVec::new();
            self.recv_buf.sack_ranges(&mut rel);
            for &(s, e) in rel.iter() {
                let _ = out.push((self.rcv_nxt.add(s).0, self.rcv_nxt.add(e).0));
            }
        }
        out
    }

    /// Bytes of TCP-option area `blocks` will occupy on the wire, including
    /// alignment NOPs (used to charge against `eff_send_mss` per RFC 6691 /
    /// RFC 9293 §3.7.1: the segment must fit in PMTU *with* its options).
    fn sack_opt_len(blocks: &BoundedVec<(u32, u32), 4>) -> u32 {
        if blocks.is_empty() {
            0
        } else {
            // 2× NOP + kind + len + 8 per block, padded to 4 (already aligned).
            4 + 8 * blocks.len() as u32
        }
    }

    /// Every emitted segment in a synchronized state carries an ACK: clear
    /// pending-ACK bookkeeping.
    fn mark_ack_sent(&mut self) {
        self.ack_state = AckState::None;
        self.segs_since_ack = 0;
        self.timers[TimerKind::DelAck as usize] = None;
    }
}
