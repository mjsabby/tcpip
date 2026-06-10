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
            if let Some(p) = self.plan_probe() {
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
        if self.state == State::SynReceived {
            // Head retransmission in SYN-RECEIVED is the SYN-ACK itself.
            self.syn_pending = true;
            return self.plan_syn(now, true);
        }
        let data_avail = self.data_sent();
        let len = data_avail.min(self.eff_send_mss() as u32);
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
            sack_blocks: self.recv_sack_blocks(),
        })
    }

    /// SACK-based recovery (RFC 6675-lite): retransmit the next hole below
    /// the highest SACKed sequence while the pipe has room.
    fn plan_sack_rexmit(&mut self, now: Instant) -> Option<SegmentPlan> {
        let pipe = self.flight_size().saturating_sub(self.scoreboard.sacked_bytes());
        if pipe >= self.cc.cwnd {
            return None;
        }
        let from = if self.sack_cursor.lt(self.snd_una) { self.snd_una } else { self.sack_cursor };
        let (start, hole_len) = self.scoreboard.next_hole(from)?;
        // The hole may include our FIN's sequence slot; data lives below
        // `data_end`.
        let data_end = self.snd_una.add(self.data_sent());
        let mut flags = TcpFlags::default();
        let (len, fin_here) = if start.ge(data_end) {
            (0, self.fin_seq.is_some())
        } else {
            let avail = data_end.since(start);
            (hole_len.min(avail).min(self.eff_send_mss() as u32), false)
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
            sack_blocks: self.recv_sack_blocks(),
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
        if !matches!(
            self.state,
            State::Established | State::CloseWait | State::FinWait1 | State::LastAck
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
        let mss = self.eff_send_mss() as u32;
        let len = unsent.min(usable).min(mss);
        // Nagle (RFC 9293 §3.7.4): hold small segments while data is in
        // flight — unless this small segment finishes the stream (FIN rides
        // along) or Nagle is disabled.
        let finishes_stream = self.fin_queued && len == unsent;
        if self.cfg_nagle && len < mss && self.bytes_in_flight() > 0 && !finishes_stream {
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
            sack_blocks: self.recv_sack_blocks(),
        })
    }

    /// A FIN of its own once all data is out (close, or peer-close reply).
    fn plan_fin(&mut self, now: Instant) -> Option<SegmentPlan> {
        if !self.fin_queued || self.fin_seq.is_some() || self.unsent() != 0 {
            return None;
        }
        if !matches!(self.state, State::FinWait1 | State::LastAck) {
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

    /// Zero-window probe (RFC 9293 §3.8.6.1): one byte *beyond* the
    /// advertised window, without advancing SND.NXT. The peer's
    /// acceptability test rejects it and answers with the ACK that tells us
    /// the current window.
    fn plan_probe(&mut self) -> Option<SegmentPlan> {
        if self.snd_wnd > 0 || self.unsent() == 0 || self.snd_nxt != self.snd_una {
            return None;
        }
        let window = self.advertise_window();
        self.mark_ack_sent();
        Some(SegmentPlan {
            seq: self.snd_nxt,
            ack: Some(self.rcv_nxt),
            flags: TcpFlags::default(),
            window,
            payload_off: self.data_sent(),
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
        let w = self.recv_buf.window();
        let field = (w >> self.rcv_scale).min(u16::MAX as u32) as u16;
        // Track what the peer will perceive, for the SWS update heuristic.
        self.last_wnd_advertised = (field as u32) << self.rcv_scale;
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

    /// Every emitted segment in a synchronized state carries an ACK: clear
    /// pending-ACK bookkeeping.
    fn mark_ack_sent(&mut self) {
        self.ack_state = AckState::None;
        self.segs_since_ack = 0;
        self.timers[TimerKind::DelAck as usize] = None;
    }
}
