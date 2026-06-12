//! One TCP connection as a deterministic state machine.
//!
//! A `Connection` never performs I/O and never sees a wall clock: inputs are
//! parsed segments, virtual-timer expirations and API calls (each taking
//! `now`); outputs are [`Effects`] (application events, reset replies) and
//! [`SegmentPlan`]s pulled by the stack's `poll_action`.
//!
//! Layout: this file holds state, construction, the application API and
//! timer handling; `input` implements RFC 9293 §3.10.7 segment arrival with
//! the RFC 5961 mitigations; `output` implements the segment planner.

mod input;
mod output;

pub use output::SegmentPlan;

use super::State;
use super::cc::CongestionControl;
use super::recvbuf::RecvBuffer;
use super::rtt::RttEstimator;
use super::sack::SackScoreboard;
use super::sendbuf::SendBuffer;
use super::seq::SeqNr;
use crate::config::Config;
use crate::time::{Duration, Instant};
use crate::types::{CloseReason, Error, SocketAddr, TimerKind};
use crate::util::BoundedVec;

/// Application-facing notifications produced by connection transitions
/// (the stack attaches the [`crate::SocketId`] and forwards them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnEvent {
    /// Placeholder for `BoundedVec` initialization; never emitted.
    #[default]
    None,
    /// Reached ESTABLISHED.
    Connected,
    /// New in-order data available.
    Readable,
    /// Send-buffer space available again after the app saw backpressure.
    Writable,
    /// Peer's FIN consumed (EOF after buffered data).
    PeerFin,
    /// Connection destroyed.
    Closed(CloseReason),
}

/// A reset the stack must send in reply to an offending segment
/// (RFC 9293 §3.10.7.3 / SYN-RECEIVED unacceptable ACK).
#[derive(Debug, Clone, Copy)]
pub struct ResetReply {
    /// Sequence number for the RST.
    pub seq: SeqNr,
    /// ACK value (RST|ACK form) if any.
    pub ack: Option<SeqNr>,
}

/// Side effects of feeding one input to a connection.
#[derive(Debug, Default)]
pub struct Effects {
    /// Application events, in order.
    pub events: BoundedVec<ConnEvent, 4>,
    /// RST the stack should emit for this (invalid) segment.
    pub reset_reply: Option<ResetReply>,
    /// The connection wants a challenge ACK (RFC 5961); the stack grants it
    /// from the rate-limit budget by calling [`Connection::grant_challenge`].
    pub wants_challenge: bool,
}

impl Effects {
    pub(crate) fn event(&mut self, ev: ConnEvent) {
        // Overflow is impossible by construction (≤ 4 events per input);
        // drop defensively rather than panic if it ever happens.
        let _ = self.events.push(ev);
    }
}

/// ACK transmission urgency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AckState {
    None,
    /// Delayed ACK armed (RFC 1122 §4.2.3.2).
    Delayed,
    /// Send an ACK at the next poll.
    Now,
}

/// Parameters fixed at connection creation by the stack.
#[derive(Debug, Clone, Copy)]
pub struct ConnParams {
    /// MSS we advertise (derived from local MTU or `Config::mss_override`).
    pub local_mss: u16,
    /// Window-scale shift to offer, `None` to omit the option.
    pub offer_wscale: Option<u8>,
    /// Offer SACK-permitted.
    pub offer_sack: bool,
    /// Initial MSS bound from the path MTU toward the peer.
    pub pmtu_mss: u16,
}

/// TCP connection state machine.
///
/// Generic over the send/receive buffer capacities `SND`/`RCV` (bytes), so a
/// deployment fixes its per-connection memory at compile time. The
/// [`crate::Stack`] threads these through; powers of two are
/// preferred (the ring buffers reduce to masking).
pub struct Connection<const SND: usize, const RCV: usize> {
    pub(crate) state: State,
    pub(crate) local: SocketAddr,
    pub(crate) remote: SocketAddr,

    // --- Send sequence space (RFC 9293 §3.3.1) ---
    pub(crate) iss: SeqNr,
    /// Our SYN has been acknowledged. This is explicit state, *not* derived
    /// from `iss` vs. `snd_una`: after ~4 GiB of transfer `snd_una` wraps
    /// past `iss`, and a positional test would mis-count the SYN as
    /// outstanding again — a 1-byte frameshift of the entire send stream
    /// (DEF-C3). The FIN cannot suffer the same wrap (`snd_nxt` never
    /// advances past `fin_seq + 1`), so it stays positional.
    pub(crate) syn_acked: bool,
    pub(crate) snd_una: SeqNr,
    pub(crate) snd_nxt: SeqNr,
    pub(crate) snd_wnd: u32,
    pub(crate) snd_wl1: SeqNr,
    pub(crate) snd_wl2: SeqNr,
    /// Largest window the peer ever advertised (RFC 5961 §5).
    pub(crate) snd_max_wnd: u32,

    // --- Receive sequence space ---
    pub(crate) irs: SeqNr,
    pub(crate) rcv_nxt: SeqNr,

    // --- Negotiated options ---
    pub(crate) params: ConnParams,
    pub(crate) peer_mss: u16,
    /// Shift applied to windows the peer sends (their offer), once enabled.
    pub(crate) snd_scale: u8,
    /// Shift applied to windows we advertise (our offer), once enabled.
    pub(crate) rcv_scale: u8,
    /// Both sides sent the window-scale option (RFC 7323 §2.2).
    pub(crate) wscale_on: bool,
    pub(crate) sack_enabled: bool,

    // --- Buffers ---
    pub(crate) send_buf: SendBuffer<SND>,
    pub(crate) recv_buf: RecvBuffer<RCV>,

    // --- Stream lifecycle ---
    /// Application requested close; FIN pending or in flight.
    pub(crate) fin_queued: bool,
    /// Sequence number our FIN occupies once first transmitted.
    pub(crate) fin_seq: Option<SeqNr>,
    /// Peer FIN sequence number once seen (consumed when in order).
    pub(crate) peer_fin: Option<SeqNr>,
    pub(crate) close_reason: Option<CloseReason>,

    // --- Output scheduling ---
    pub(crate) syn_pending: bool,
    pub(crate) ack_state: AckState,
    /// In-order data segments received since the last ACK we sent
    /// (RFC 1122: ACK at least every second full segment).
    pub(crate) segs_since_ack: u8,
    pub(crate) rexmit_now: bool,
    pub(crate) probe_pending: bool,
    /// Window advertised in the last segment we emitted.
    pub(crate) last_wnd_advertised: u32,
    /// Right edge `RCV.NXT + RCV.WND` last advertised; never moves left
    /// (RFC 9293 §3.8.6.2.1, DEF-L35).
    pub(crate) rcv_adv: SeqNr,
    /// Set when the app hit a full send buffer (Writable edge trigger).
    pub(crate) app_blocked: bool,

    // --- Timers: desired absolute deadlines, reconciled by the stack ---
    pub(crate) timers: [Option<Instant>; 4],

    // --- RTT / RTO (RFC 6298) ---
    pub(crate) rtt: RttEstimator,
    /// `(end_seq, sent_at)` of the segment being timed; invalidated by any
    /// retransmission (Karn's algorithm).
    pub(crate) rtt_sample: Option<(SeqNr, Instant)>,
    pub(crate) rexmit_count: u8,
    pub(crate) persist_count: u8,

    // --- Congestion control (RFC 5681 / 6582 / 6675-lite) ---
    pub(crate) cc: CongestionControl,
    pub(crate) dupacks: u8,
    /// Recovery point: SND.NXT when loss recovery was entered.
    pub(crate) recovery: Option<SeqNr>,
    pub(crate) scoreboard: SackScoreboard,
    /// Highest sequence retransmitted during the current SACK recovery.
    pub(crate) sack_cursor: SeqNr,

    // --- Path MTU ---
    pub(crate) pmtu_mss: u16,
    /// When to revert `pmtu_mss` to the link-derived value and re-probe
    /// (RFC 1191 §6.3). `None` means the link value is in effect.
    pub(crate) pmtu_expires: Option<Instant>,
    /// Earliest time another PMTU-triggered head retransmission is allowed
    /// (rate-limits the forged step-down PTB amplifier — DEF-M19).
    pub(crate) pmtu_rexmit_after: Instant,

    // --- Accounting ---
    pub(crate) passive: bool,
    pub(crate) listener_port: u16,
    /// `Connected` has been delivered to the application. A passive
    /// connection that dies before this is torn down silently (the app
    /// never knew it existed).
    pub(crate) reported: bool,

    // --- Config snapshot (only Copy scalars; keeps Connection self-contained) ---
    pub(crate) cfg_msl: Duration,
    pub(crate) cfg_max_syn_retries: u8,
    pub(crate) cfg_max_data_retries: u8,
    pub(crate) cfg_delayed_ack: Option<Duration>,
    pub(crate) cfg_nagle: bool,
    pub(crate) cfg_fin_wait2_timeout: Duration,
    pub(crate) cfg_max_persist_retries: u8,
}

impl<const SND: usize, const RCV: usize> Connection<SND, RCV> {
    fn common(
        cfg: &Config,
        params: ConnParams,
        local: SocketAddr,
        remote: SocketAddr,
        iss: SeqNr,
    ) -> Self {
        Connection {
            state: State::Closed,
            local,
            remote,
            iss,
            syn_acked: false,
            snd_una: iss,
            snd_nxt: iss.add(1), // the SYN occupies `iss`
            snd_wnd: 0,
            snd_wl1: SeqNr(0),
            snd_wl2: SeqNr(0),
            snd_max_wnd: 0,
            irs: SeqNr(0),
            rcv_nxt: SeqNr(0),
            params,
            peer_mss: if remote.ip.is_v4() { 536 } else { 1220 }, // RFC 9293 §3.7.1
            snd_scale: 0,
            rcv_scale: 0,
            wscale_on: false,
            sack_enabled: false,
            send_buf: SendBuffer::new(),
            recv_buf: RecvBuffer::new(),
            fin_queued: false,
            fin_seq: None,
            peer_fin: None,
            close_reason: None,
            syn_pending: true,
            ack_state: AckState::None,
            segs_since_ack: 0,
            rexmit_now: false,
            probe_pending: false,
            last_wnd_advertised: 0,
            rcv_adv: SeqNr(0),
            app_blocked: false,
            timers: [None; 4],
            rtt: RttEstimator::new(cfg.rto_initial, cfg.rto_min, cfg.rto_max),
            rtt_sample: None,
            rexmit_count: 0,
            persist_count: 0,
            cc: CongestionControl::new(536),
            dupacks: 0,
            recovery: None,
            scoreboard: SackScoreboard::new(),
            sack_cursor: iss,
            pmtu_mss: params.pmtu_mss,
            pmtu_expires: None,
            pmtu_rexmit_after: Instant::ZERO,
            passive: false,
            listener_port: 0,
            reported: false,
            cfg_msl: cfg.msl,
            cfg_max_syn_retries: cfg.max_syn_retries,
            cfg_max_data_retries: cfg.max_data_retries,
            cfg_delayed_ack: cfg.delayed_ack.then_some(cfg.delayed_ack_timeout),
            cfg_nagle: cfg.nagle,
            cfg_fin_wait2_timeout: cfg.fin_wait2_timeout,
            cfg_max_persist_retries: cfg.max_persist_retries,
        }
    }

    /// Active open (RFC 9293 §3.10.1): a SYN will be emitted at next poll.
    pub fn client(
        cfg: &Config,
        params: ConnParams,
        local: SocketAddr,
        remote: SocketAddr,
        iss: SeqNr,
    ) -> Self {
        let mut c = Self::common(cfg, params, local, remote, iss);
        c.state = State::SynSent;
        c.cc = CongestionControl::new(c.eff_send_mss() as u32);
        c
    }

    /// Passive open from a received SYN (stack/listener already validated
    /// addressing). `seg_*` carry the SYN's fields and options.
    #[allow(clippy::too_many_arguments)]
    pub fn server(
        cfg: &Config,
        params: ConnParams,
        local: SocketAddr,
        remote: SocketAddr,
        iss: SeqNr,
        seg_seq: SeqNr,
        seg_window: u16,
        opt_mss: Option<u16>,
        opt_wscale: Option<u8>,
        opt_sack_permitted: bool,
    ) -> Self {
        let mut c = Self::common(cfg, params, local, remote, iss);
        c.state = State::SynReceived;
        c.passive = true;
        c.listener_port = local.port;
        c.irs = seg_seq;
        c.rcv_nxt = seg_seq.add(1);
        // RFC 7323 §2.2: window fields in SYN segments are never scaled.
        c.snd_wnd = seg_window as u32;
        c.snd_max_wnd = c.snd_wnd;
        c.snd_wl1 = seg_seq;
        c.snd_wl2 = iss;
        c.apply_syn_options(opt_mss, opt_wscale, opt_sack_permitted);
        c
    }

    /// Record the peer's SYN options and fix the negotiated parameters
    /// (RFC 9293 §3.7.1, RFC 7323 §2.2, RFC 2018 §2).
    pub(crate) fn apply_syn_options(
        &mut self,
        mss: Option<u16>,
        wscale: Option<u8>,
        sack_permitted: bool,
    ) {
        if let Some(m) = mss {
            // Floor guards against absurd/hostile values.
            self.peer_mss = m.max(64);
        }
        match (self.params.offer_wscale, wscale) {
            (Some(ours), Some(theirs)) => {
                self.rcv_scale = ours;
                self.snd_scale = theirs;
                self.wscale_on = true;
            }
            _ => {
                self.rcv_scale = 0;
                self.snd_scale = 0;
                self.wscale_on = false;
            }
        }
        self.sack_enabled = self.params.offer_sack && sack_permitted;
        self.cc = CongestionControl::new(self.eff_send_mss() as u32);
    }

    // ----- Introspection used by the stack -----

    /// Current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Local endpoint.
    pub fn local(&self) -> SocketAddr {
        self.local
    }

    /// Remote endpoint.
    pub fn remote(&self) -> SocketAddr {
        self.remote
    }

    /// True once the connection has fully terminated and the slot can be
    /// reclaimed.
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Was this connection accepted via a listener?
    /// True when the connection is synchronized but the application has not
    /// yet been told (the `Connected` event was shed under backlog —
    /// DEF-M26). The sweep re-emits it.
    pub fn needs_connected_event(&self) -> bool {
        !self.reported
            && !matches!(
                self.state,
                State::Closed | State::SynSent | State::SynReceived
            )
    }

    /// Listener port this connection was accepted on, if passive.
    pub fn accepted_on(&self) -> Option<u16> {
        self.passive.then_some(self.listener_port)
    }

    /// Desired deadline for each timer kind (stack reconciliation).
    pub fn timer_deadline(&self, kind: TimerKind) -> Option<Instant> {
        self.timers[kind as usize]
    }

    /// Send-sequence variables `(SND.UNA, SND.NXT, SND.WND)` — test/diag aid.
    pub fn snd_state(&self) -> (u32, u32, u32) {
        (self.snd_una.0, self.snd_nxt.0, self.snd_wnd)
    }

    /// Receive-sequence variable RCV.NXT — test/diag aid.
    pub fn rcv_nxt(&self) -> u32 {
        self.rcv_nxt.0
    }

    /// Negotiated options `(peer_mss, snd_scale, rcv_scale, sack)` — diag aid.
    pub fn negotiated(&self) -> (u16, u8, u8, bool) {
        (
            self.peer_mss,
            self.snd_scale,
            self.rcv_scale,
            self.sack_enabled,
        )
    }

    // ----- Application API (call events) -----

    /// Queue application data; returns bytes accepted (0 ⇒ backpressure,
    /// a [`ConnEvent::Writable`] will follow when space frees).
    pub fn send(&mut self, data: &[u8]) -> Result<usize, Error> {
        if !self.state.may_send() || self.fin_queued {
            return Err(if self.state == State::Closed {
                Error::ConnectionGone
            } else {
                Error::InvalidState
            });
        }
        let n = self.send_buf.write(data);
        if n < data.len() {
            self.app_blocked = true;
        }
        Ok(n)
    }

    /// Read received data; `Ok(0)` means no data *currently* (or EOF if the
    /// peer FIN was delivered — the caller distinguishes via
    /// [`ConnEvent::PeerFin`]).
    pub fn recv(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.recv_buf.read(out);
        if n > 0 {
            // Receiver-side SWS avoidance (RFC 9293 §3.8.6.2.2): announce
            // the larger window only once it has grown by a full MSS (or
            // half the buffer); the planner sends the update.
            let grown = self
                .recv_buf
                .window()
                .saturating_sub(self.last_wnd_advertised);
            let threshold = (self.params.local_mss as u32).min(RCV as u32 / 2);
            if grown >= threshold && self.state.synchronized() {
                self.set_ack(AckState::Now);
            }
        }
        Ok(n)
    }

    /// Graceful close (RFC 9293 §3.10.4): no more sends; FIN after queued
    /// data drains. Receiving continues until the peer's FIN.
    pub fn close(&mut self, fx: &mut Effects) -> Result<(), Error> {
        match self.state {
            State::SynSent => {
                // Nothing on the wire the peer accepted: just delete.
                self.enter_closed(CloseReason::Normal, fx);
                Ok(())
            }
            State::SynReceived | State::Established => {
                self.fin_queued = true;
                self.state = State::FinWait1;
                Ok(())
            }
            State::CloseWait => {
                self.fin_queued = true;
                self.state = State::LastAck;
                Ok(())
            }
            State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::LastAck
            | State::TimeWait => Err(Error::InvalidState),
            State::Closed => Err(Error::ConnectionGone),
        }
    }

    /// Abort (RFC 9293 §3.10.5): RST to the peer, everything discarded.
    /// The stack emits the RST from the returned plan.
    pub fn abort(&mut self, fx: &mut Effects) -> Option<ResetReply> {
        let rst = if matches!(
            self.state,
            State::SynReceived
                | State::Established
                | State::FinWait1
                | State::FinWait2
                | State::CloseWait
                | State::Closing
                | State::LastAck
        ) {
            // RFC 9293 §3.10.5: <SEQ=SND.NXT><CTL=RST> (no ACK).
            Some(ResetReply {
                seq: self.snd_nxt,
                ack: None,
            })
        } else {
            None
        };
        self.enter_closed(CloseReason::Aborted, fx);
        rst
    }

    // ----- Timer expirations -----

    /// Handle a virtual-timer expiry.
    pub fn on_timer(&mut self, now: Instant, kind: TimerKind, fx: &mut Effects) {
        // Stale-fire guard (defense in depth): A-POLL-1 obliges the runtime
        // to suppress superseded expiries, but a non-compliant runtime that
        // delivers an old fire after a re-arm would otherwise be trusted —
        // for Rexmit that means a spurious cwnd collapse and a step toward
        // `max_data_retries`. If our desired deadline is still in the
        // future, this fire is stale; drop it. A fire for a timer we
        // *don't want at all* (`None`) is also stale by definition
        // (DEF-L29). Reconcile re-emits the StartTimer for any
        // still-desired deadline (the stack clears `emitted` on every
        // gen-matched fire, so an early-fire here triggers a re-arm
        // rather than leaving a zombie deadline — DEF-L30).
        if self.timers[kind as usize].is_none_or(|d| now < d) {
            return;
        }
        self.timers[kind as usize] = None;
        match kind {
            TimerKind::Rexmit => self.on_rexmit_timer(now, fx),
            TimerKind::Persist => {
                // RFC 9293 §3.8.6.1 / RFC 1122 §4.2.2.17 say probe
                // "indefinitely as long as the receiving TCP continues to
                // send acknowledgments". A peer that ACKs the probe (even
                // with window 0) resets `persist_count` via the window-update
                // path; reaching the cap means the peer is silent — abort
                // under RFC 9293 §3.8.3 R2 so a malicious or dead peer
                // cannot pin a slot forever (DEF-H1). `cfg = 0` opts back
                // into strict RFC 1122 indefinite probing.
                if self.cfg_max_persist_retries > 0
                    && self.persist_count >= self.cfg_max_persist_retries
                {
                    self.enter_closed(CloseReason::TimedOut, fx);
                    return;
                }
                self.probe_pending = true;
                self.persist_count = self.persist_count.saturating_add(1);
                self.arm_persist(now);
            }
            TimerKind::DelAck => {
                if self.ack_state == AckState::Delayed {
                    self.ack_state = AckState::Now;
                }
            }
            TimerKind::Wait => match self.state {
                // TIME-WAIT 2*MSL elapsed (RFC 9293 §3.10.7.4): graceful.
                State::TimeWait => self.enter_closed(CloseReason::Normal, fx),
                // FIN-WAIT-2 orphan timeout: the peer never sent its FIN.
                // Report this as a timeout, not a graceful close, so the
                // app can distinguish (DEF-L33).
                State::FinWait2 => self.enter_closed(CloseReason::TimedOut, fx),
                _ => {}
            },
        }
    }

    fn on_rexmit_timer(&mut self, now: Instant, fx: &mut Effects) {
        match self.state {
            State::SynSent | State::SynReceived => {
                if self.rexmit_count >= self.cfg_max_syn_retries {
                    self.enter_closed(CloseReason::TimedOut, fx);
                    return;
                }
                self.rexmit_count += 1;
                self.rtt.backoff();
                self.syn_pending = true;
                self.rtt_sample = None; // Karn
                self.timers[TimerKind::Rexmit as usize] = Some(now + self.rtt.rto());
            }
            _ if self.bytes_in_flight() > 0 || self.fin_in_flight() => {
                if self.rexmit_count >= self.cfg_max_data_retries {
                    self.enter_closed(CloseReason::TimedOut, fx);
                    return;
                }
                self.rexmit_count += 1;
                // RFC 6298 §5.4–5.7: back off, retransmit the earliest
                // unacknowledged segment, restart the timer.
                self.rtt.backoff();
                self.rtt_sample = None; // Karn
                self.cc.on_rto(self.flight_size());
                // RFC 2018 §8: scoreboard may be stale if the receiver
                // reneged; forget it.
                self.scoreboard.clear();
                self.recovery = None;
                self.dupacks = 0;
                self.rexmit_now = true;
                self.timers[TimerKind::Rexmit as usize] = Some(now + self.rtt.rto());
            }
            _ => {} // stale timer: nothing outstanding
        }
    }

    // ----- Shared helpers -----

    /// Effective send MSS: peer's advertised MSS bounded by the path MTU.
    pub(crate) fn eff_send_mss(&self) -> u16 {
        self.peer_mss.min(self.pmtu_mss).max(64)
    }

    /// Path MTU changed (stack plumbs ICMP signals here). A shrink triggers
    /// an immediate retransmission sized to the new MSS (RFC 1191 §3).
    pub fn on_pmtu_change(&mut self, now: Instant, pmtu_mss: u16) {
        let shrunk = pmtu_mss < self.pmtu_mss;
        if shrunk {
            self.pmtu_mss = pmtu_mss;
            // DEF-M18: a per-connection reduction also ages out — otherwise
            // one forged PTB degrades a long-lived connection forever even
            // after the shared cache has recovered.
            self.pmtu_expires = Some(now + crate::ip::pmtu::PMTU_TTL);
            self.cc.set_mss(self.eff_send_mss() as u32);
        }
        if shrunk && self.bytes_in_flight() > 0 && now >= self.pmtu_rexmit_after {
            // Don't count against the retry budget and don't collapse cwnd:
            // nothing was lost to congestion (RFC 1191 §3). Limit to one
            // retransmission per RTO so that a step-down PTB(N), PTB(N-1),
            // … flood cannot reflect ~N head segments toward the peer
            // (DEF-M19).
            self.rexmit_now = true;
            self.rtt_sample = None; // the in-flight segment will be resent
            self.pmtu_rexmit_after = now + self.rtt.rto();
        }
    }

    /// Re-probe the path MTU if the per-connection reduction has aged out
    /// (RFC 1191 §6.3 / DEF-M18). Called from the periodic sweep.
    pub(crate) fn maybe_age_pmtu(&mut self, now: Instant) {
        if self.pmtu_expires.is_some_and(|t| now >= t) {
            self.pmtu_mss = self.params.pmtu_mss;
            self.pmtu_expires = None;
            self.cc.set_mss(self.eff_send_mss() as u32);
        }
    }

    /// RFC 5927 §4 mitigation: an ICMP error quoting one of our segments is
    /// only honored if the quoted sequence number could currently be in
    /// flight. With nothing in flight, *no* quote is plausible — an idle
    /// connection has no segment on the wire for an ICMP error to refer to
    /// (DEF-L34).
    pub fn icmp_quote_plausible(&self, seq: SeqNr) -> bool {
        let span = self.snd_nxt.since(self.snd_una);
        span > 0 && seq.in_window(self.snd_una, span)
    }

    /// An ICMP hard error (port/protocol unreachable) for this connection.
    /// RFC 1122 §4.2.3.9: abort in SYN-SENT/SYN-RECEIVED; for synchronized
    /// states we treat it as advisory except when nothing is established
    /// yet (resilience against ICMP spoofing, RFC 5927 §4).
    pub fn on_icmp_unreachable(&mut self, fx: &mut Effects) {
        if matches!(self.state, State::SynSent | State::SynReceived) {
            self.enter_closed(CloseReason::Unreachable, fx);
        }
    }

    /// Count the control bits (SYN, FIN) whose sequence numbers fall in
    /// `[snd_una, snd_nxt)`.
    fn control_units_outstanding(&self) -> u32 {
        let span = self.snd_nxt.since(self.snd_una);
        let mut n = 0;
        // SYN occupies `iss`. Tested by explicit state, not position, so the
        // accounting survives `snd_una` wrapping past `iss` (DEF-C3).
        if !self.syn_acked && span > 0 {
            n += 1;
        }
        // FIN occupies `fin_seq`. Positional is safe here: once the FIN is
        // assigned, `snd_nxt` never advances past `fin_seq + 1`, so the
        // window cannot wrap back over it.
        if let Some(f) = self.fin_seq
            && f.since(self.snd_una) < span
        {
            n += 1;
        }
        n
    }

    /// Data bytes occupying sequence space between SND.UNA and SND.NXT
    /// (FlightSize per RFC 5681, excluding SYN/FIN control units).
    pub(crate) fn bytes_in_flight(&self) -> u32 {
        self.snd_nxt
            .since(self.snd_una)
            .saturating_sub(self.control_units_outstanding())
    }

    pub(crate) fn fin_in_flight(&self) -> bool {
        matches!(self.fin_seq, Some(f) if self.snd_una.le(f))
    }

    /// FlightSize per RFC 5681: data sent but not yet acknowledged.
    pub(crate) fn flight_size(&self) -> u32 {
        self.bytes_in_flight()
    }

    /// Unsent bytes sitting in the send buffer.
    pub(crate) fn unsent(&self) -> u32 {
        (self.send_buf.len() as u32).saturating_sub(self.data_sent())
    }

    /// Bytes of the send buffer already transmitted (offset of SND.NXT
    /// within the buffer, whose offset 0 is SND.UNA). Identical in value to
    /// [`Self::bytes_in_flight`]; named separately for call-site clarity.
    pub(crate) fn data_sent(&self) -> u32 {
        self.bytes_in_flight()
    }

    pub(crate) fn set_ack(&mut self, urgency: AckState) {
        match (self.ack_state, urgency) {
            (AckState::Now, _) | (_, AckState::None) => {}
            (_, AckState::Now) => {
                self.ack_state = AckState::Now;
                self.timers[TimerKind::DelAck as usize] = None;
            }
            (AckState::None, AckState::Delayed) => self.ack_state = AckState::Delayed,
            (AckState::Delayed, AckState::Delayed) => {}
        }
    }

    /// Arm the delayed-ACK timer if delayed acking is configured; otherwise
    /// escalate to an immediate ACK.
    pub(crate) fn ack_delayed(&mut self, now: Instant) {
        match self.cfg_delayed_ack {
            Some(timeout) if self.ack_state == AckState::None => {
                self.set_ack(AckState::Delayed);
                self.timers[TimerKind::DelAck as usize] = Some(now + timeout);
            }
            Some(_) => {} // already delayed or already immediate
            None => self.set_ack(AckState::Now),
        }
    }

    pub(crate) fn arm_persist(&mut self, now: Instant) {
        // Exponential persist backoff from the current RTO, capped at 60 s.
        let interval = self
            .rtt
            .rto()
            .saturating_mul(1u32 << self.persist_count.min(6))
            .clamp(self.rtt.rto(), Duration::from_secs(60));
        self.timers[TimerKind::Persist as usize] = Some(now + interval);
    }

    /// Recompute rexmit/persist timer demand after any state change. Called
    /// at the end of every input and every planned segment.
    pub(crate) fn update_send_timers(&mut self, now: Instant) {
        let outstanding = self.snd_nxt.since(self.snd_una) > 0;
        // Persist runs while the peer's window is closed and we have data to
        // send. The probe byte itself counts as outstanding once emitted, so
        // persist must stay armed across that single in-flight byte; it
        // disarms once the window opens or the buffer truly empties. While
        // persisting, the probe byte is *not* covered by Rexmit (a peer that
        // keeps ACKing with window 0 must not march toward
        // `max_data_retries`); a silent peer is bounded by
        // `max_persist_retries` instead (DEF-H1).
        let probing = self.snd_wnd == 0 && self.bytes_in_flight() <= 1 && !self.send_buf.is_empty();
        if !outstanding || probing {
            self.timers[TimerKind::Rexmit as usize] = None;
            if !outstanding {
                self.rexmit_count = 0;
            }
        } else if self.timers[TimerKind::Rexmit as usize].is_none() {
            // DEF-H10: outstanding sequence space with neither timer covering
            // it (the persist→idle edge when the peer reopens its window
            // without ACKing the probe byte) — arm Rexmit so the byte/FIN is
            // never stranded.
            self.timers[TimerKind::Rexmit as usize] = Some(now + self.rtt.rto());
        }
        let want_persist = probing;
        match (want_persist, self.timers[TimerKind::Persist as usize]) {
            (true, None) => self.arm_persist(now),
            (false, Some(_)) => {
                self.timers[TimerKind::Persist as usize] = None;
                self.persist_count = 0;
                self.probe_pending = false;
            }
            _ => {}
        }
    }

    /// Transition to TIME-WAIT: only the 2*MSL timer stays armed.
    pub(crate) fn enter_time_wait(&mut self, now: Instant) {
        self.state = State::TimeWait;
        self.timers = [None; 4];
        self.timers[TimerKind::Wait as usize] = Some(now + self.cfg_msl.saturating_mul(2));
    }

    pub(crate) fn enter_closed(&mut self, reason: CloseReason, fx: &mut Effects) {
        if self.state == State::Closed {
            return;
        }
        self.state = State::Closed;
        self.close_reason = Some(reason);
        self.timers = [None; 4];
        // A passive connection that never reached the application (e.g. RST
        // while SYN-RECEIVED, RFC 9293 §3.10.7.4: "return to LISTEN") dies
        // silently — the app never saw a handle for it.
        if self.reported || !self.passive {
            fx.event(ConnEvent::Closed(reason));
        }
    }

    /// Internal-consistency checks; used by tests and the fuzz harness
    /// (S-INV-1..4 in `docs/TRACEABILITY.md`).
    pub fn check_invariants(&self) {
        // SND.UNA <= SND.NXT within a half-space.
        debug_assert!(self.snd_nxt.since(self.snd_una) < 1 << 30);
        // Sequence space between UNA and NXT is backed by buffer + ctl bits.
        debug_assert!(self.data_sent() as usize <= self.send_buf.len());
        // Scoreboard lives within (UNA, NXT].
        if let Some(h) = self.scoreboard.high_sacked() {
            debug_assert!(h.le(self.snd_nxt));
        }
        // Recovery point never exceeds SND.NXT.
        if let Some(r) = self.recovery {
            debug_assert!(r.le(self.snd_nxt));
        }
        // FIN bookkeeping consistent with state.
        if matches!(
            self.state,
            State::FinWait1 | State::Closing | State::LastAck
        ) {
            debug_assert!(self.fin_queued);
        }
        // Window scaling bounded (RFC 7323 §2.3).
        debug_assert!(self.snd_scale <= 14 && self.rcv_scale <= 14);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::IpAddr;
    use crate::wire::tcp::{TcpFlags, TcpHeader, TcpOptions};

    type Conn = Connection<4096, 4096>;

    fn established(iss: u32, irs: u32) -> Conn {
        let cfg = Config::default();
        let p = ConnParams {
            local_mss: 1460,
            offer_wscale: Some(0),
            offer_sack: true,
            pmtu_mss: 1460,
        };
        let mut c = Conn::client(
            &cfg,
            p,
            SocketAddr::new(IpAddr::v4(10, 0, 0, 1), 50000),
            SocketAddr::new(IpAddr::v4(10, 0, 0, 2), 80),
            SeqNr(iss),
        );
        // Short-circuit to ESTABLISHED.
        c.state = State::Established;
        c.syn_acked = true;
        c.snd_una = SeqNr(iss.wrapping_add(1));
        c.snd_nxt = c.snd_una;
        c.irs = SeqNr(irs);
        c.rcv_nxt = SeqNr(irs.wrapping_add(1));
        c.snd_wnd = 65535;
        c.snd_max_wnd = 65535;
        c.snd_wl1 = c.irs;
        c.snd_wl2 = c.snd_una;
        c.reported = true;
        c
    }

    fn ack_seg(seq: u32, ack: u32, wnd: u16, fin: bool) -> (TcpHeader, TcpOptions) {
        let mut flags = TcpFlags::ACK;
        if fin {
            flags = flags.union(TcpFlags::FIN);
        }
        (
            TcpHeader {
                src_port: 80,
                dst_port: 50000,
                seq,
                ack,
                flags,
                window: wnd,
                header_len: 20,
            },
            TcpOptions::default(),
        )
    }

    /// DEF-C3: after `snd_una` wraps the 32-bit sequence space past `iss`,
    /// the SYN must NOT be re-counted as outstanding. Before the fix,
    /// `control_units_outstanding` tested `iss.since(snd_una) < span` — true
    /// again once `snd_una` wraps — which made `data_sent()` under-count by 1
    /// and shifted every subsequent byte one position in sequence space.
    #[test]
    fn syn_unit_is_not_recounted_after_seq_wrap() {
        // Place ISS so wrapping past it needs only a few segments.
        let iss = 100u32;
        let mut c = established(iss, 0);
        // Simulate ~4 GiB of transfer: SND.UNA wraps to just before ISS,
        // SND.NXT just past it, with one segment of real data in flight.
        let len = 200u32;
        assert_eq!(
            c.send(&std::vec![7u8; len as usize][..]).unwrap(),
            len as usize
        );
        c.snd_una = SeqNr(iss.wrapping_sub(50)); // 50 below iss
        c.snd_nxt = c.snd_una.add(len); // 150 above iss → iss is inside [una,nxt)
        // ISS is now inside the in-flight window. With the bug,
        // control_units_outstanding() = 1 → data_sent() = len - 1.
        assert_eq!(
            c.control_units_outstanding(),
            0,
            "SYN re-counted as outstanding after snd_una wrapped past iss"
        );
        assert_eq!(
            c.data_sent(),
            len,
            "data_sent() off by one — DEF-C3 frameshift"
        );
        // And an ACK that lands on `iss` exactly must not subtract a SYN unit.
        let mut fx = Effects::default();
        let (h, o) = ack_seg(c.rcv_nxt.0, iss, 65535, false);
        c.on_segment(Instant::ZERO, &h, &o, &[], &mut fx);
        // 50 bytes were ACKed (from una=iss-50 to iss); buffer popped 50, not 49.
        assert_eq!(
            c.send_buf.len(),
            (len - 50) as usize,
            "SYN unit re-subtracted at iss"
        );
    }

    /// DEF-C4: the zero-window probe advances SND.NXT, so a peer that opens
    /// its window and accepts the probe byte ACKs a value we honor instead of
    /// rejecting at the `ack > SND.NXT` gate (which would wedge both sides).
    #[test]
    fn zero_window_probe_ack_is_accepted() {
        let mut c = established(1000, 2000);
        c.send(&[0x55; 64]).unwrap();
        c.snd_wnd = 0;
        c.update_send_timers(Instant::ZERO);
        // Persist fires → probe planned.
        let mut fx = Effects::default();
        c.on_timer(Instant::from_secs(2), TimerKind::Persist, &mut fx);
        let plan = c.next_segment(Instant::from_secs(2)).expect("probe");
        assert_eq!(plan.payload_len, 1);
        let probe_end = plan.seq.add(1);
        assert_eq!(c.snd_nxt, probe_end, "probe must advance SND.NXT (DEF-C4)");
        // Peer's window opened: it accepted the byte and ACKs `probe_end`
        // with a non-zero window. This must be honored, not dropped.
        let (h, o) = ack_seg(c.rcv_nxt.0, probe_end.0, 4096, false);
        let una_before = c.snd_una;
        c.on_segment(Instant::from_secs(2), &h, &o, &[], &mut fx);
        assert_eq!(
            c.snd_una, probe_end,
            "probe-byte ACK rejected — both sides would wedge"
        );
        assert_ne!(c.snd_una, una_before);
        assert_eq!(c.snd_wnd, 4096, "window update from the probe-ACK was lost");
    }

    /// DEF-M11: a stale timer fire (delivered before the desired deadline)
    /// is dropped, not acted on as a real expiry.
    #[test]
    fn stale_timer_fire_is_ignored() {
        let mut c = established(1000, 2000);
        c.send(&[0u8; 100]).unwrap();
        c.snd_nxt = c.snd_una.add(100);
        let now = Instant::from_secs(10);
        c.timers[TimerKind::Rexmit as usize] = Some(now + Duration::from_secs(5));
        let cwnd_before = c.cc.cwnd;
        let mut fx = Effects::default();
        // Fire arrives at `now`, but the desired deadline is `now + 5 s`.
        c.on_timer(now, TimerKind::Rexmit, &mut fx);
        assert_eq!(c.cc.cwnd, cwnd_before, "stale Rexmit collapsed cwnd");
        assert_eq!(c.rexmit_count, 0, "stale Rexmit consumed a retry");
        assert!(
            c.timers[TimerKind::Rexmit as usize].is_some(),
            "stale fire cleared the deadline"
        );
    }
}
