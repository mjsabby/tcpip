//! The host stack: demultiplexing, listeners, the action queue and timer
//! reconciliation — the single object a runtime embeds.
//!
//! ## Runtime contract
//!
//! * Feed every received IP datagram via [`Stack::on_datagram`] (or
//!   [`Stack::handle`]), every timer expiry via [`Stack::on_timer`], and
//!   answer [`Action::RequestEntropy`] via [`Stack::on_entropy`].
//! * After **every** event or API call, call [`Stack::poll_action`] with a
//!   buffer of at least MTU bytes until it returns `None`, performing each
//!   action (transmit the buffer, arm/cancel timers, surface app events).
//! * Time is monotone non-decreasing across all calls (A-TIME-1).
//!
//! Given identical event sequences (including `now` values and entropy),
//! the stack's outputs are byte-identical — the deterministic-replay
//! property the whole design serves.

use crate::config::{
    ACTION_QUEUE_SIZE, CTL_QUEUE_SIZE, Config, ECHO_BUF_SIZE, MAX_LISTENERS, PMTU_CACHE_SIZE,
    REASM_BUF_SIZE, REASM_SLOTS, RECV_BUF_SIZE, SEND_BUF_SIZE,
};
use crate::ip::pmtu::PmtuCache;
use crate::ip::reasm::{ReasmResult, Reassembler};
use crate::ip::{IPV4_MIN_PMTU, IPV6_MIN_PMTU, ReasmKey};
use crate::tcp::State;
use crate::tcp::conn::{ConnEvent, ConnParams, Connection, Effects, ResetReply, SegmentPlan};
use crate::tcp::isn::IsnGenerator;
use crate::tcp::seq::SeqNr;
use crate::time::{Duration, Instant};
use crate::types::{
    Action, AppEvent, Error, Event, IpAddr, SocketAddr, SocketId, TimerKey, TimerKind,
};
use crate::util::{BoundedQueue, BoundedVec};
use crate::wire::tcp::{TcpEmit, TcpFlags, TcpOptionsEmit};
use crate::wire::{icmp, ipv4, ipv6, proto};

/// IPv4 header (20) + TCP header (20).
const V4_OVERHEAD: u16 = 40;
/// IPv6 header (40) + TCP header (20).
const V6_OVERHEAD: u16 = 60;

/// A fully-described control segment (RST or similar) owed to the network.
#[derive(Debug, Clone, Copy, Default)]
struct CtlSegment {
    local: SocketAddr,
    remote: SocketAddr,
    seq: SeqNr,
    ack: Option<SeqNr>,
}

/// A pending ICMP echo reply (one slot; floods are shed).
#[derive(Debug, Clone, Copy)]
struct EchoReply {
    /// Our address (source of the reply).
    local: IpAddr,
    /// Their address (destination of the reply).
    remote: IpAddr,
    rest: [u8; 4],
    len: usize,
}

/// Counters for observability and tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct StackStats {
    /// Datagrams handed to `on_datagram`.
    pub rx_datagrams: u64,
    /// Datagrams dropped as malformed (parse/checksum failures).
    pub rx_malformed: u64,
    /// Datagrams dropped because the destination is not local.
    pub rx_not_local: u64,
    /// TCP segments accepted by a connection or listener.
    pub segs_rx: u64,
    /// Datagrams transmitted.
    pub tx_datagrams: u64,
    /// RSTs generated (closed ports, invalid handshakes).
    pub rst_tx: u64,
    /// Challenge ACKs granted (RFC 5961).
    pub challenges_granted: u64,
    /// Challenge ACKs suppressed by the rate limit (RFC 5961 §10).
    pub challenges_limited: u64,
    /// Echo replies sent.
    pub echo_tx: u64,
}

/// The TCP/IP host stack with `CONNS` connection slots and per-connection
/// send/receive buffers of `SND`/`RCV` bytes.
///
/// All memory is inline: the `conns` array *is* the pre-allocated
/// connection pool. Place the whole stack in a `static`, a `Box` (see the
/// `alloc` feature), or any fixed arena. `CONNS` must be ≤ 256; `SND`/`RCV`
/// are preferably powers of two. Defaults are `Stack<8, 16384, 16384>`.
///
/// ```
/// # use tcp_sans_io::{Stack, IpAddr};
/// # use tcp_sans_io::config::Config;
/// // A constrained node: 4 connections, 4 KiB each way.
/// let stack: Stack<4, 4096, 4096> = Stack::new(Config::with_addr(IpAddr::v4(10,0,0,1)));
/// ```
pub struct Stack<
    const CONNS: usize = 8,
    const SND: usize = SEND_BUF_SIZE,
    const RCV: usize = RECV_BUF_SIZE,
> {
    cfg: Config,
    conns: [Option<Connection<SND, RCV>>; CONNS],
    generations: [u16; CONNS],
    listeners: BoundedVec<u16, MAX_LISTENERS>,
    isn: IsnGenerator,
    entropy_request_pending: bool,
    reasm: Reassembler,
    pmtu: PmtuCache<PMTU_CACHE_SIZE>,
    actions: BoundedQueue<Action, ACTION_QUEUE_SIZE>,
    ctl: BoundedQueue<CtlSegment, CTL_QUEUE_SIZE>,
    echo: Option<EchoReply>,
    echo_buf: [u8; ECHO_BUF_SIZE],
    /// Timer state as last told to the runtime, per conn slot and kind.
    emitted_conn_timers: [[Option<Instant>; 4]; CONNS],
    emitted_reasm_timers: [Option<Instant>; REASM_SLOTS],
    /// RFC 5961 §10 challenge-ACK budget.
    challenge_tokens: u8,
    challenge_refill_at: Instant,
    ip_ident: u16,
    next_ephemeral: u16,
    poll_cursor: usize,
    stats: StackStats,
}

impl<const CONNS: usize, const SND: usize, const RCV: usize> Stack<CONNS, SND, RCV> {
    /// Create a stack. The first `poll_action` returns
    /// [`Action::RequestEntropy`]; until the runtime answers, opens are
    /// refused with [`Error::NeedEntropy`] and inbound SYNs are dropped.
    pub fn new(cfg: Config) -> Self {
        assert!(CONNS <= 256, "SocketId index is 8 bits");
        assert!(!cfg.local_addrs.is_empty(), "stack needs at least one local address");
        Stack {
            cfg,
            conns: [const { None }; CONNS],
            generations: [0; CONNS],
            listeners: BoundedVec::new(),
            isn: IsnGenerator::new(),
            entropy_request_pending: true,
            reasm: Reassembler::new(),
            pmtu: PmtuCache::new(),
            actions: BoundedQueue::new(),
            ctl: BoundedQueue::new(),
            echo: None,
            echo_buf: [0; ECHO_BUF_SIZE],
            emitted_conn_timers: [[None; 4]; CONNS],
            emitted_reasm_timers: [None; REASM_SLOTS],
            challenge_tokens: 0,
            challenge_refill_at: Instant::ZERO,
            ip_ident: 0,
            next_ephemeral: 49152,
            poll_cursor: 0,
            stats: StackStats::default(),
        }
    }

    /// Stack configuration.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Counters.
    pub fn stats(&self) -> StackStats {
        self.stats
    }

    /// State of a connection, if the handle is live (test/diagnostic aid).
    pub fn state_of(&self, sock: SocketId) -> Option<State> {
        self.conn_ref(sock).map(|c| c.state())
    }

    /// Local port bound to a connection (test/diagnostic aid).
    pub fn local_port_of(&self, sock: SocketId) -> Option<u16> {
        self.conn_ref(sock).map(|c| c.local().port)
    }

    /// Send-sequence variables `(SND.UNA, SND.NXT, SND.WND)` for a live
    /// connection (test/diagnostic aid).
    pub fn snd_state_of(&self, sock: SocketId) -> Option<(u32, u32, u32)> {
        self.conn_ref(sock).map(|c| c.snd_state())
    }

    /// RCV.NXT for a live connection (test/diagnostic aid).
    pub fn rcv_nxt_of(&self, sock: SocketId) -> Option<u32> {
        self.conn_ref(sock).map(|c| c.rcv_nxt())
    }

    // ------------------------------------------------------------------
    // Event entry points
    // ------------------------------------------------------------------

    /// Feed one environment event.
    pub fn handle(&mut self, now: Instant, event: Event<'_>) {
        match event {
            Event::DatagramReceived(frame) => self.on_datagram(now, frame),
            Event::TimerExpired(key) => self.on_timer(now, key),
            Event::EntropyProvided(bytes) => self.on_entropy(bytes),
        }
    }

    /// Entropy arrived in answer to [`Action::RequestEntropy`].
    pub fn on_entropy(&mut self, bytes: [u8; 16]) {
        self.isn.seed(bytes);
    }

    /// A virtual timer fired.
    pub fn on_timer(&mut self, now: Instant, key: TimerKey) {
        match key {
            TimerKey::Conn { sock, kind } => {
                let idx = sock.index as usize;
                if idx >= CONNS || self.generations[idx] != sock.generation {
                    return; // stale timer for a recycled slot
                }
                self.emitted_conn_timers[idx][kind as usize] = None;
                let Some(conn) = self.conns[idx].as_mut() else { return };
                let mut fx = Effects::default();
                conn.on_timer(now, kind, &mut fx);
                self.process_effects(now, idx, fx);
            }
            TimerKey::Reasm { slot } => {
                let slot = slot as usize;
                if slot < REASM_SLOTS {
                    self.emitted_reasm_timers[slot] = None;
                    self.reasm.on_timer(slot);
                }
            }
        }
    }

    /// A whole IP datagram arrived from the link.
    pub fn on_datagram(&mut self, now: Instant, frame: &[u8]) {
        self.stats.rx_datagrams += 1;
        match frame.first().map(|b| b >> 4) {
            Some(4) => self.on_ipv4(now, frame),
            Some(6) => self.on_ipv6(now, frame),
            _ => self.stats.rx_malformed += 1,
        }
    }

    fn on_ipv4(&mut self, now: Instant, frame: &[u8]) {
        let Ok((h, payload)) = ipv4::parse(frame) else {
            self.stats.rx_malformed += 1;
            return;
        };
        let dst = IpAddr::V4(h.dst);
        if !self.cfg.is_local(&dst) {
            self.stats.rx_not_local += 1;
            return; // hosts do not forward (RFC 1122 §3.3.4)
        }
        let src = IpAddr::V4(h.src);
        if h.is_fragment() {
            let key =
                ReasmKey { src, dst, proto: h.proto, ident: h.ident as u32 };
            self.on_fragment(now, key, h.frag_offset as u32, h.more_frags, payload);
        } else {
            self.deliver(now, src, dst, h.proto, payload);
        }
    }

    fn on_ipv6(&mut self, now: Instant, frame: &[u8]) {
        let Ok((h, payload)) = ipv6::parse(frame) else {
            self.stats.rx_malformed += 1;
            return;
        };
        let dst = IpAddr::V6(h.dst);
        if !self.cfg.is_local(&dst) {
            self.stats.rx_not_local += 1;
            return;
        }
        let src = IpAddr::V6(h.src);
        if let Some(frag) = h.frag {
            let key = ReasmKey { src, dst, proto: frag.next, ident: frag.ident };
            self.on_fragment(now, key, frag.offset as u32, frag.more, payload);
        } else {
            self.deliver(now, src, dst, h.proto, payload);
        }
    }

    fn on_fragment(&mut self, now: Instant, key: ReasmKey, off: u32, more: bool, data: &[u8]) {
        let timeout = self.cfg.reassembly_timeout;
        if let ReasmResult::Complete { slot } = self.reasm.push(now, timeout, key, off, more, data)
        {
            let mut buf = [0u8; REASM_BUF_SIZE];
            if let Some((key, len)) = self.reasm.take(slot, &mut buf) {
                self.deliver(now, key.src, key.dst, key.proto, &buf[..len]);
            }
        }
    }

    fn deliver(&mut self, now: Instant, src: IpAddr, dst: IpAddr, proto_nr: u8, payload: &[u8]) {
        match proto_nr {
            proto::TCP => self.deliver_tcp(now, src, dst, payload),
            proto::ICMP if src.is_v4() => self.deliver_icmp4(now, src, dst, payload),
            proto::ICMPV6 if !src.is_v4() => self.deliver_icmp6(now, src, dst, payload),
            // Unknown transport: silently dropped. We do not generate ICMP
            // protocol-unreachable (D-ICMP-1).
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // API calls
    // ------------------------------------------------------------------

    /// Start accepting connections on `port` (any local address).
    pub fn listen(&mut self, port: u16) -> Result<(), Error> {
        if port == 0 {
            return Err(Error::Unaddressable);
        }
        if self.listeners.iter().any(|&p| p == port) {
            return Err(Error::AddrInUse);
        }
        self.listeners.push(port).map_err(|_| Error::BufferFull)
    }

    /// Stop accepting connections on `port` (existing connections live on).
    pub fn unlisten(&mut self, port: u16) {
        self.listeners.retain(|&p| p != port);
    }

    /// Active open to `remote` from an automatic local endpoint.
    pub fn connect(&mut self, now: Instant, remote: SocketAddr) -> Result<SocketId, Error> {
        let local_ip = *self
            .cfg
            .local_addrs
            .iter()
            .find(|a| a.same_family(&remote.ip))
            .ok_or(Error::Unaddressable)?;
        let port = self.alloc_ephemeral(&remote)?;
        self.connect_from(now, SocketAddr::new(local_ip, port), remote)
    }

    /// Active open with an explicit local endpoint.
    pub fn connect_from(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<SocketId, Error> {
        if !local.ip.same_family(&remote.ip) || remote.port == 0 {
            return Err(Error::Unaddressable);
        }
        if !self.cfg.is_local(&local.ip) {
            return Err(Error::Unaddressable);
        }
        if !self.isn.ready() {
            return Err(Error::NeedEntropy);
        }
        if self.find_conn(&local, &remote).is_some() {
            return Err(Error::AddrInUse);
        }
        let idx = self.free_slot().ok_or(Error::NoSlot)?;
        let params = self.conn_params(now, &remote.ip);
        let iss = self.isn.generate(now, local, remote).ok_or(Error::NeedEntropy)?;
        self.conns[idx] = Some(Connection::client(&self.cfg, params, local, remote, iss));
        Ok(SocketId { index: idx as u8, generation: self.generations[idx] })
    }

    /// Queue bytes for sending; returns how many were accepted.
    pub fn send(&mut self, sock: SocketId, data: &[u8]) -> Result<usize, Error> {
        self.conn_mut(sock)?.send(data)
    }

    /// Read received bytes; `Ok(0)` means none pending (EOF is signaled via
    /// [`AppEvent::PeerFinReceived`]).
    pub fn recv(&mut self, sock: SocketId, out: &mut [u8]) -> Result<usize, Error> {
        self.conn_mut(sock)?.recv(out)
    }

    /// Graceful close: FIN after queued data; receiving continues.
    pub fn close(&mut self, sock: SocketId) -> Result<(), Error> {
        let idx = self.index_of(sock)?;
        let mut fx = Effects::default();
        let result = match self.conns[idx].as_mut() {
            Some(conn) => conn.close(&mut fx),
            None => Err(Error::NotFound),
        };
        // `Instant::ZERO` is fine here: close() itself never arms timers.
        self.process_effects(Instant::ZERO, idx, fx);
        result
    }

    /// Abort: RST the peer and drop everything immediately.
    pub fn abort(&mut self, sock: SocketId) -> Result<(), Error> {
        let idx = self.index_of(sock)?;
        let mut fx = Effects::default();
        let (rst, local, remote) = match self.conns[idx].as_mut() {
            Some(conn) => (conn.abort(&mut fx), conn.local(), conn.remote()),
            None => return Err(Error::NotFound),
        };
        if let Some(r) = rst {
            self.queue_reset(local, remote, r);
        }
        self.process_effects(Instant::ZERO, idx, fx);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internals: lookup and bookkeeping
    // ------------------------------------------------------------------

    fn index_of(&self, sock: SocketId) -> Result<usize, Error> {
        let idx = sock.index as usize;
        if idx < CONNS && self.generations[idx] == sock.generation && self.conns[idx].is_some() {
            Ok(idx)
        } else {
            Err(Error::NotFound)
        }
    }

    fn conn_mut(&mut self, sock: SocketId) -> Result<&mut Connection<SND, RCV>, Error> {
        let idx = self.index_of(sock)?;
        self.conns[idx].as_mut().ok_or(Error::NotFound)
    }

    fn conn_ref(&self, sock: SocketId) -> Option<&Connection<SND, RCV>> {
        let idx = self.index_of(sock).ok()?;
        self.conns[idx].as_ref()
    }

    fn find_conn(&self, local: &SocketAddr, remote: &SocketAddr) -> Option<usize> {
        self.conns.iter().position(|c| {
            c.as_ref().is_some_and(|c| c.local() == *local && c.remote() == *remote)
        })
    }

    fn free_slot(&self) -> Option<usize> {
        self.conns.iter().position(|c| c.is_none())
    }

    fn alloc_ephemeral(&mut self, remote: &SocketAddr) -> Result<u16, Error> {
        // Deterministic rotation through the dynamic range (RFC 6335 §6).
        for _ in 0..=(u16::MAX - 49152) {
            let port = self.next_ephemeral;
            self.next_ephemeral =
                if self.next_ephemeral == u16::MAX { 49152 } else { self.next_ephemeral + 1 };
            let clash = self.conns.iter().flatten().any(|c| {
                c.local().port == port && c.remote() == *remote
            });
            if !clash {
                return Ok(port);
            }
        }
        Err(Error::NoSlot)
    }

    fn conn_params(&self, now: Instant, remote_ip: &IpAddr) -> ConnParams {
        let overhead = if remote_ip.is_v4() { V4_OVERHEAD } else { V6_OVERHEAD };
        let floor = if remote_ip.is_v4() { IPV4_MIN_PMTU } else { IPV6_MIN_PMTU };
        let local_mss = self
            .cfg
            .mss_override
            .unwrap_or_else(|| self.cfg.mtu.max(floor) - overhead);
        let pmtu = self.pmtu.get(now, self.cfg.mtu, remote_ip).max(floor);
        ConnParams {
            local_mss,
            offer_wscale: self.cfg.offer_window_scale.then_some(self.cfg.recv_window_scale.min(14)),
            offer_sack: self.cfg.sack,
            pmtu_mss: pmtu - overhead,
        }
    }

    fn sock_at(&self, idx: usize) -> SocketId {
        SocketId { index: idx as u8, generation: self.generations[idx] }
    }

    /// Translate connection effects into queued actions.
    fn process_effects(&mut self, now: Instant, idx: usize, fx: Effects) {
        if fx.wants_challenge {
            if self.take_challenge_token(now) {
                self.stats.challenges_granted += 1;
                if let Some(c) = self.conns[idx].as_mut() {
                    c.grant_challenge();
                }
            } else {
                self.stats.challenges_limited += 1;
            }
        }
        if let Some(r) = fx.reset_reply
            && let Some(c) = self.conns[idx].as_ref()
        {
            let (local, remote) = (c.local(), c.remote());
            self.queue_reset(local, remote, r);
        }
        let sock = self.sock_at(idx);
        for &ev in fx.events.iter() {
            let app = match ev {
                ConnEvent::None => continue,
                ConnEvent::Connected => AppEvent::Connected {
                    sock,
                    via_listener: self.conns[idx].as_ref().and_then(|c| c.accepted_on()),
                },
                ConnEvent::Readable => AppEvent::Readable { sock },
                ConnEvent::Writable => AppEvent::Writable { sock },
                ConnEvent::PeerFin => AppEvent::PeerFinReceived { sock },
                ConnEvent::Closed(reason) => AppEvent::Closed { sock, reason },
            };
            let _ = self.actions.push_back(Action::App(app));
        }
    }

    fn queue_reset(&mut self, local: SocketAddr, remote: SocketAddr, r: ResetReply) {
        self.stats.rst_tx += 1;
        let _ = self.ctl.push_back(CtlSegment { local, remote, seq: r.seq, ack: r.ack });
    }

    /// RFC 5961 §10: token-bucket limit on challenge ACKs.
    fn take_challenge_token(&mut self, now: Instant) -> bool {
        if now >= self.challenge_refill_at {
            self.challenge_tokens = self.cfg.challenge_acks_per_sec;
            self.challenge_refill_at = now + Duration::from_secs(1);
        }
        if self.challenge_tokens > 0 {
            self.challenge_tokens -= 1;
            true
        } else {
            false
        }
    }

    fn next_ident(&mut self) -> u16 {
        self.ip_ident = self.ip_ident.wrapping_add(1);
        self.ip_ident
    }

    // ------------------------------------------------------------------
    // TCP delivery
    // ------------------------------------------------------------------

    fn deliver_tcp(&mut self, now: Instant, src: IpAddr, dst: IpAddr, seg: &[u8]) {
        let Ok((h, opts, payload)) = crate::wire::tcp::parse(seg, &src, &dst) else {
            self.stats.rx_malformed += 1;
            return;
        };
        let local = SocketAddr::new(dst, h.dst_port);
        let remote = SocketAddr::new(src, h.src_port);

        if let Some(idx) = self.find_conn(&local, &remote) {
            self.stats.segs_rx += 1;
            let mut fx = Effects::default();
            if let Some(conn) = self.conns[idx].as_mut() {
                conn.on_segment(now, &h, &opts, payload, &mut fx);
            }
            self.process_effects(now, idx, fx);
            return;
        }

        // A SYN to a listening port creates a connection (LISTEN state per
        // RFC 9293 §3.10.7.2 lives here at the stack).
        if h.flags.syn()
            && !h.flags.ack()
            && !h.flags.rst()
            && self.listeners.iter().any(|&p| p == h.dst_port)
        {
            self.stats.segs_rx += 1;
            self.accept_syn(now, local, remote, h.seq, h.window, &opts);
            return;
        }

        // No matching connection (CLOSED, RFC 9293 §3.10.7.1): reset,
        // unless the offender is itself a reset.
        if h.flags.rst() {
            return;
        }
        let reply = if h.flags.ack() {
            // "<SEQ=SEG.ACK><CTL=RST>"
            CtlSegment { local, remote, seq: SeqNr(h.ack), ack: None }
        } else {
            // "<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>"
            let seg_len =
                payload.len() as u32 + h.flags.syn() as u32 + h.flags.fin() as u32;
            CtlSegment { local, remote, seq: SeqNr(0), ack: Some(SeqNr(h.seq).add(seg_len)) }
        };
        self.stats.rst_tx += 1;
        let _ = self.ctl.push_back(reply);
    }

    fn accept_syn(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        seq: u32,
        window: u16,
        opts: &crate::wire::tcp::TcpOptions,
    ) {
        if !self.isn.ready() {
            return; // no secure ISN available: drop, peer retries
        }
        let Some(idx) = self.free_slot() else {
            return; // table full: shed load silently (SYN cookies are out
            // of scope; a dropped SYN is retried by the peer)
        };
        let params = self.conn_params(now, &remote.ip);
        let Some(iss) = self.isn.generate(now, local, remote) else { return };
        self.conns[idx] = Some(Connection::server(
            &self.cfg,
            params,
            local,
            remote,
            iss,
            SeqNr(seq),
            window,
            opts.mss,
            opts.window_scale,
            opts.sack_permitted,
        ));
    }

    // ------------------------------------------------------------------
    // ICMP delivery
    // ------------------------------------------------------------------

    fn deliver_icmp4(&mut self, now: Instant, src: IpAddr, dst: IpAddr, body: &[u8]) {
        let Ok((m, rest)) = icmp::parse_v4(body) else {
            self.stats.rx_malformed += 1;
            return;
        };
        match (m.kind, m.code) {
            (icmp::v4::ECHO_REQUEST, 0) => self.queue_echo(src, dst, m.rest, rest),
            (icmp::v4::DEST_UNREACHABLE, code) => {
                let Ok((qh, ql4)) = ipv4::parse_quote(rest) else { return };
                if qh.proto != proto::TCP {
                    return;
                }
                let Ok(q) = icmp::quoted_tcp(ql4) else { return };
                let local = SocketAddr::new(IpAddr::V4(qh.src), q.src_port);
                let remote = SocketAddr::new(IpAddr::V4(qh.dst), q.dst_port);
                self.icmp_error_for(now, local, remote, SeqNr(q.seq), code, m.mtu());
            }
            _ => {} // time-exceeded etc.: advisory only
        }
    }

    fn deliver_icmp6(&mut self, now: Instant, src: IpAddr, dst: IpAddr, body: &[u8]) {
        let (IpAddr::V6(s6), IpAddr::V6(d6)) = (&src, &dst) else { return };
        let Ok((m, rest)) = icmp::parse_v6(body, s6, d6) else {
            self.stats.rx_malformed += 1;
            return;
        };
        match m.kind {
            icmp::v6::ECHO_REQUEST => self.queue_echo(src, dst, m.rest, rest),
            icmp::v6::PACKET_TOO_BIG | icmp::v6::DEST_UNREACHABLE => {
                let Ok((qsrc, qdst, qnext, ql4)) = ipv6::parse_quote(rest) else { return };
                if qnext != proto::TCP {
                    return;
                }
                let Ok(q) = icmp::quoted_tcp(ql4) else { return };
                let local = SocketAddr::new(IpAddr::V6(qsrc), q.src_port);
                let remote = SocketAddr::new(IpAddr::V6(qdst), q.dst_port);
                if m.kind == icmp::v6::PACKET_TOO_BIG {
                    // Map onto the v4 handler's "frag needed" path.
                    self.icmp_error_for(
                        now,
                        local,
                        remote,
                        SeqNr(q.seq),
                        icmp::v4::CODE_FRAG_NEEDED,
                        m.mtu(),
                    );
                } else if m.code == icmp::v6::CODE_PORT_UNREACHABLE {
                    self.icmp_error_for(now, local, remote, SeqNr(q.seq), u8::MAX, 0);
                }
            }
            _ => {}
        }
    }

    /// Common ICMP-error plumbing. `code` is normalized to the IPv4 codes;
    /// `u8::MAX` means "hard unreachable" from ICMPv6.
    fn icmp_error_for(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        quoted_seq: SeqNr,
        code: u8,
        reported_mtu: u32,
    ) {
        let Some(idx) = self.find_conn(&local, &remote) else { return };
        let Some(conn) = self.conns[idx].as_mut() else { return };
        // RFC 5927 §4: ignore errors whose quote could not be in flight.
        if !conn.icmp_quote_plausible(quoted_seq) {
            return;
        }
        if code == icmp::v4::CODE_FRAG_NEEDED {
            // Path MTU discovery (RFC 1191 / RFC 8201).
            let overhead = if remote.ip.is_v4() { V4_OVERHEAD } else { V6_OVERHEAD };
            if let Some(new_pmtu) = self.pmtu.update(now, self.cfg.mtu, &remote.ip, reported_mtu)
                && let Some(conn) = self.conns[idx].as_mut()
            {
                conn.on_pmtu_change(new_pmtu - overhead);
            }
        } else if code == icmp::v4::CODE_PORT_UNREACHABLE
            || code == icmp::v4::CODE_PROTO_UNREACHABLE
            || code == u8::MAX
        {
            // Hard error (RFC 1122 §4.2.3.9).
            let mut fx = Effects::default();
            conn.on_icmp_unreachable(&mut fx);
            self.process_effects(now, idx, fx);
        }
    }

    fn queue_echo(&mut self, src: IpAddr, dst: IpAddr, rest: [u8; 4], payload: &[u8]) {
        if !self.cfg.answer_echo || self.echo.is_some() {
            return; // one pending reply; floods are shed
        }
        let overhead = if src.is_v4() { 20 + 8 } else { 40 + 8 };
        if payload.len() + overhead > self.cfg.mtu as usize || payload.len() > ECHO_BUF_SIZE {
            return;
        }
        self.echo_buf[..payload.len()].copy_from_slice(payload);
        self.echo = Some(EchoReply { local: dst, remote: src, rest, len: payload.len() });
    }

    // ------------------------------------------------------------------
    // Output: poll_action and serialization
    // ------------------------------------------------------------------

    /// Drain the next pending action. `tx` must be at least MTU bytes; when
    /// the result is [`Action::Transmit`], the datagram occupies
    /// `tx[..len]`. Call repeatedly until `None` after every event.
    pub fn poll_action(&mut self, now: Instant, tx: &mut [u8]) -> Option<Action> {
        debug_assert!(tx.len() >= self.cfg.mtu as usize, "tx buffer must hold one MTU");
        if self.entropy_request_pending {
            self.entropy_request_pending = false;
            return Some(Action::RequestEntropy);
        }
        if let Some(a) = self.actions.pop_front() {
            return Some(a);
        }
        if let Some(c) = self.ctl.pop_front() {
            let len = self.emit_ctl(&c, tx);
            self.stats.tx_datagrams += 1;
            return Some(Action::Transmit { len });
        }
        if let Some(e) = self.echo.take() {
            let len = self.emit_echo(&e, tx);
            self.stats.tx_datagrams += 1;
            self.stats.echo_tx += 1;
            return Some(Action::Transmit { len });
        }
        // Connection transmissions, round-robin for inter-connection
        // fairness; a connection with more to send keeps the cursor.
        for i in 0..CONNS {
            let idx = (self.poll_cursor + i) % CONNS;
            let plan = match self.conns[idx].as_mut() {
                Some(conn) => conn.next_segment(now),
                None => None,
            };
            if let Some(plan) = plan {
                self.poll_cursor = idx;
                let len = self.emit_plan(idx, &plan, tx);
                self.stats.tx_datagrams += 1;
                self.reconcile_conn_timers(now, idx);
                return Some(Action::Transmit { len });
            }
        }
        // Quiescent: reconcile timers, free dead slots, surface anything
        // those steps queued.
        self.sweep(now);
        self.actions.pop_front()
    }

    fn sweep(&mut self, now: Instant) {
        for idx in 0..CONNS {
            if let Some(conn) = self.conns[idx].as_mut() {
                if conn.is_closed() {
                    self.conns[idx] = None;
                    self.generations[idx] = self.generations[idx].wrapping_add(1);
                    self.reconcile_conn_timers(now, idx); // emit cancels
                    continue;
                }
                conn.update_send_timers(now);
                self.reconcile_conn_timers(now, idx);
            }
        }
        for slot in 0..REASM_SLOTS {
            let desired = self.reasm.deadline(slot);
            let emitted = self.emitted_reasm_timers[slot];
            let key = TimerKey::Reasm { slot: slot as u8 };
            match (desired, emitted) {
                (Some(d), e) if e != Some(d) => {
                    let _ = self
                        .actions
                        .push_back(Action::StartTimer { key, after: d.saturating_since(now) });
                    self.emitted_reasm_timers[slot] = Some(d);
                }
                (None, Some(_)) => {
                    let _ = self.actions.push_back(Action::CancelTimer { key });
                    self.emitted_reasm_timers[slot] = None;
                }
                _ => {}
            }
        }
    }

    fn reconcile_conn_timers(&mut self, now: Instant, idx: usize) {
        const KINDS: [TimerKind; 4] =
            [TimerKind::Rexmit, TimerKind::Persist, TimerKind::DelAck, TimerKind::Wait];
        let desired: [Option<Instant>; 4] = match self.conns[idx].as_ref() {
            Some(c) => KINDS.map(|k| c.timer_deadline(k)),
            None => [None; 4],
        };
        let sock = self.sock_at(idx);
        for (k, kind) in KINDS.into_iter().enumerate() {
            let key = TimerKey::Conn { sock, kind };
            match (desired[k], self.emitted_conn_timers[idx][k]) {
                (Some(d), e) if e != Some(d) => {
                    let _ = self
                        .actions
                        .push_back(Action::StartTimer { key, after: d.saturating_since(now) });
                    self.emitted_conn_timers[idx][k] = Some(d);
                }
                (None, Some(_)) => {
                    let _ = self.actions.push_back(Action::CancelTimer { key });
                    self.emitted_conn_timers[idx][k] = None;
                }
                _ => {}
            }
        }
    }

    fn emit_plan(&mut self, idx: usize, plan: &SegmentPlan, tx: &mut [u8]) -> usize {
        let ident = self.next_ident();
        let ttl = self.cfg.ttl;
        let Some(conn) = self.conns[idx].as_ref() else { return 0 };
        let mut flags = plan.flags;
        if plan.ack.is_some() {
            flags = flags.union(TcpFlags::ACK);
        }
        let mut options = TcpOptionsEmit::default();
        if let Some(syn) = plan.syn_opts {
            options.mss = Some(syn.mss);
            options.window_scale = syn.wscale;
            options.sack_permitted = syn.sack_permitted;
        }
        options.sack_blocks = plan.sack_blocks;
        let emit = TcpEmit {
            src_port: conn.local().port,
            dst_port: conn.remote().port,
            seq: plan.seq.0,
            ack: plan.ack.map_or(0, |a| a.0),
            flags,
            window: plan.window,
            options,
        };
        let payload = conn.send_buf.read(plan.payload_off as usize, plan.payload_len as usize);
        let (local, remote) = (conn.local().ip, conn.remote().ip);
        emit_tcp_ip(&local, &remote, &emit, payload, ttl, ident, tx)
    }

    fn emit_ctl(&mut self, c: &CtlSegment, tx: &mut [u8]) -> usize {
        let mut flags = TcpFlags::RST;
        if c.ack.is_some() {
            flags = flags.union(TcpFlags::ACK);
        }
        let emit = TcpEmit {
            src_port: c.local.port,
            dst_port: c.remote.port,
            seq: c.seq.0,
            ack: c.ack.map_or(0, |a| a.0),
            flags,
            window: 0,
            options: TcpOptionsEmit::default(),
        };
        let ident = self.next_ident();
        emit_tcp_ip(&c.local.ip, &c.remote.ip, &emit, (&[], &[]), self.cfg.ttl, ident, tx)
    }

    fn emit_echo(&mut self, e: &EchoReply, tx: &mut [u8]) -> usize {
        let body = &self.echo_buf[..e.len];
        match (&e.local, &e.remote) {
            (IpAddr::V4(local), IpAddr::V4(remote)) => {
                let len = icmp::emit_v4(
                    icmp::v4::ECHO_REPLY,
                    0,
                    e.rest,
                    body,
                    &mut tx[ipv4::HEADER_LEN..],
                );
                let ident = self.next_ident();
                ipv4::Ipv4Emit::datagram(*local, *remote, proto::ICMP, self.cfg.ttl, ident, false)
                    .emit(len, tx);
                ipv4::HEADER_LEN + len
            }
            (IpAddr::V6(local), IpAddr::V6(remote)) => {
                let len = icmp::emit_v6(
                    icmp::v6::ECHO_REPLY,
                    0,
                    e.rest,
                    body,
                    local,
                    remote,
                    &mut tx[ipv6::HEADER_LEN..],
                );
                ipv6::emit(local, remote, proto::ICMPV6, self.cfg.ttl, len, tx);
                ipv6::HEADER_LEN + len
            }
            _ => 0,
        }
    }
}

/// Serialize a TCP segment inside an IPv4/IPv6 datagram. DF is set on IPv4:
/// TCP segments double as the path-MTU-discovery probes (RFC 1191 §3).
fn emit_tcp_ip(
    src: &IpAddr,
    dst: &IpAddr,
    emit: &TcpEmit,
    payload: (&[u8], &[u8]),
    ttl: u8,
    ident: u16,
    tx: &mut [u8],
) -> usize {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let seg_len = emit.emit(src, dst, payload, &mut tx[ipv4::HEADER_LEN..]);
            ipv4::Ipv4Emit::datagram(*s, *d, proto::TCP, ttl, ident, true).emit(seg_len, tx);
            ipv4::HEADER_LEN + seg_len
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let seg_len = emit.emit(src, dst, payload, &mut tx[ipv6::HEADER_LEN..]);
            ipv6::emit(s, d, proto::TCP, ttl, seg_len, tx);
            ipv6::HEADER_LEN + seg_len
        }
        _ => {
            debug_assert!(false, "mixed address families");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Instant;

    // A constrained node with non-default, distinct buffer sizes. Proves the
    // const-generic capacities propagate end-to-end (not just compile).
    type SmallStack = Stack<2, 4096, 8192>;

    fn seeded(addr: IpAddr) -> SmallStack {
        let mut s: SmallStack = Stack::new(Config::with_addr(addr));
        s.on_entropy([0x42; 16]);
        s
    }

    #[test]
    fn custom_recv_capacity_drives_advertised_window() {
        let mut s = seeded(IpAddr::v4(10, 0, 0, 1));
        let now = Instant::ZERO;
        let _sock = s.connect(now, SocketAddr::new(IpAddr::v4(10, 0, 0, 2), 80)).unwrap();
        // Drain to the SYN datagram and parse its window field.
        let mut tx = [0u8; 1500];
        let mut window = None;
        while let Some(a) = s.poll_action(now, &mut tx) {
            if let Action::Transmit { len } = a {
                let (_h, _p) = ipv4::parse(&tx[..len]).unwrap();
                let seg = &tx[ipv4::HEADER_LEN..len];
                let (th, _o, _pl) = crate::wire::tcp::parse(
                    seg,
                    &IpAddr::v4(10, 0, 0, 1),
                    &IpAddr::v4(10, 0, 0, 2),
                )
                .unwrap();
                window = Some(th.window);
                break;
            }
        }
        // RFC 7323 §2.2: SYN windows are unscaled, so the field equals the
        // full RCV capacity (8192), not the default 16384.
        assert_eq!(window, Some(8192));
    }

    #[test]
    fn slot_count_is_the_pool_size() {
        let mut s = seeded(IpAddr::v4(10, 0, 0, 1));
        let now = Instant::ZERO;
        // Two slots: two opens succeed, the third reports NoSlot.
        assert!(s.connect(now, SocketAddr::new(IpAddr::v4(10, 0, 0, 2), 1)).is_ok());
        assert!(s.connect(now, SocketAddr::new(IpAddr::v4(10, 0, 0, 2), 2)).is_ok());
        assert_eq!(
            s.connect(now, SocketAddr::new(IpAddr::v4(10, 0, 0, 2), 3)),
            Err(Error::NoSlot)
        );
    }
}
