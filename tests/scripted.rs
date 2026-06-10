//! Scripted-segment ("packetdrill-style") tests.
//!
//! packetdrill proper drives the *kernel's* socket syscalls and injects
//! packets on a tun device; it cannot test a userspace sans-I/O stack
//! directly. This is the equivalent for our core: a single `Stack` is driven
//! by a script that plays the remote peer **and** the clock, injecting
//! byte-exact segments and asserting byte-exact responses (flags, sequence
//! and acknowledgment numbers, window, and options).
//!
//! Each test reads like a packetdrill script:
//! ```text
//!  < S  seq=1000  win=65535 <mss 1460, wscale 7, sackOK>   (inject)
//!  > S. seq=ISS   ack=1001  <mss …>                        (expect)
//!  < .  ack=ISS+1                                           (inject)
//! ```
//! Timing is explicit (`at`/`advance`), so retransmission and delayed-ACK
//! behavior is exercised deterministically without any wall clock.

use std::collections::HashMap;
use tcp_sans_io::config::Config;
use tcp_sans_io::time::{Duration, Instant};
use tcp_sans_io::util::BoundedVec;
use tcp_sans_io::wire::tcp::{TcpEmit, TcpFlags, TcpOptionsEmit};
use tcp_sans_io::wire::{ipv4, proto};
use tcp_sans_io::{Action, AppEvent, IpAddr, SocketAddr, SocketId, Stack};

const STACK_IP: IpAddr = IpAddr::V4([10, 0, 0, 2]);
const PEER_IP: IpAddr = IpAddr::V4([10, 0, 0, 1]);
const STACK_PORT: u16 = 80;
const PEER_PORT: u16 = 40000;

/// A parsed segment the stack emitted.
#[derive(Debug, Clone)]
struct Seg {
    src_port: u16,
    flags: TcpFlags,
    seq: u32,
    ack: u32,
    window: u16,
    payload: Vec<u8>,
    mss: Option<u16>,
    wscale: Option<u8>,
    sack_permitted: bool,
    sack_blocks: Vec<(u32, u32)>,
}

/// Fields an injected segment carries (script → stack).
struct Inject {
    flags: TcpFlags,
    seq: u32,
    ack: u32,
    window: u16,
    payload: Vec<u8>,
    mss: Option<u16>,
    wscale: Option<u8>,
    sack_permitted: bool,
}

impl Inject {
    fn new(flags: TcpFlags, seq: u32, ack: u32) -> Self {
        Inject {
            flags,
            seq,
            ack,
            window: 65535,
            payload: Vec::new(),
            mss: None,
            wscale: None,
            sack_permitted: false,
        }
    }
    fn win(mut self, w: u16) -> Self {
        self.window = w;
        self
    }
    fn data(mut self, d: &[u8]) -> Self {
        self.payload = d.to_vec();
        self
    }
    fn syn_opts(mut self, mss: u16, wscale: Option<u8>, sack: bool) -> Self {
        self.mss = Some(mss);
        self.wscale = wscale;
        self.sack_permitted = sack;
        self
    }
}

/// The scripted-segment driver around one stack.
struct Pd {
    stack: Stack<2>,
    now: Instant,
    timers: HashMap<tcp_sans_io::TimerKey, Instant>,
    emitted: std::collections::VecDeque<Seg>,
    events: Vec<AppEvent>,
    /// The stack's initial send sequence, learned from its first SYN/SYN-ACK.
    iss: Option<u32>,
    /// The stack's local port for the connection under test (the listen port
    /// for a passive open; the learned ephemeral port for an active open).
    stack_port: u16,
}

impl Pd {
    fn new() -> Self {
        let mut cfg = Config::with_addr(STACK_IP);
        cfg.nagle = true;
        let mut stack: Stack<2> = Stack::new(cfg);
        stack.on_entropy([0x5A; 16]);
        let mut pd = Pd {
            stack,
            now: Instant::from_millis(1000),
            timers: HashMap::new(),
            emitted: Default::default(),
            events: Vec::new(),
            iss: None,
            stack_port: STACK_PORT,
        };
        pd.drain();
        pd
    }

    fn now(&self) -> Instant {
        self.now
    }

    /// Drain all pending actions, capturing emitted segments and timers.
    fn drain(&mut self) {
        let mut tx = [0u8; 1500];
        while let Some(a) = self.stack.poll_action(self.now, &mut tx) {
            match a {
                Action::None => {}
                Action::Transmit { len } => {
                    if let Some(seg) = parse_emitted(&tx[..len]) {
                        if self.iss.is_none() && seg.flags.contains(TcpFlags::SYN) {
                            self.iss = Some(seg.seq);
                        }
                        self.emitted.push_back(seg);
                    }
                }
                Action::StartTimer { key, after } => {
                    self.timers.insert(key, self.now + after);
                }
                Action::CancelTimer { key } => {
                    self.timers.remove(&key);
                }
                Action::RequestEntropy => self.stack.on_entropy([0x5A; 16]),
                Action::App(ev) => self.events.push(ev),
            }
        }
    }

    /// Advance the clock by `ms`, firing any timers that come due (earliest
    /// first), draining after each.
    fn advance(&mut self, ms: u64) {
        let target = self.now + Duration::from_millis(ms);
        loop {
            let next = self
                .timers
                .iter()
                .filter(|&(_, &t)| t <= target)
                .min_by_key(|&(_, &t)| t)
                .map(|(&k, &t)| (k, t));
            let Some((key, at)) = next else { break };
            self.timers.remove(&key);
            self.now = at;
            self.stack.on_timer(self.now, key);
            self.drain();
        }
        self.now = target;
    }

    /// Inject a segment from the peer to the stack.
    fn inject(&mut self, seg: Inject) {
        let mut buf = [0u8; 1500];
        let opts = TcpOptionsEmit {
            mss: seg.mss,
            window_scale: seg.wscale,
            sack_permitted: seg.sack_permitted,
            ..Default::default()
        };
        let emit = TcpEmit {
            src_port: PEER_PORT,
            dst_port: self.stack_port,
            seq: seg.seq,
            ack: seg.ack,
            flags: seg.flags,
            window: seg.window,
            options: opts,
        };
        let seg_len = emit.emit(&PEER_IP, &STACK_IP, (&seg.payload, &[]), &mut buf[ipv4::HEADER_LEN..]);
        let IpAddr::V4(s) = PEER_IP else { unreachable!() };
        let IpAddr::V4(d) = STACK_IP else { unreachable!() };
        ipv4::Ipv4Emit::datagram(s, d, proto::TCP, 64, 1, false).emit(seg_len, &mut buf);
        let total = ipv4::HEADER_LEN + seg_len;
        self.stack.on_datagram(self.now, &buf[..total]);
        self.drain();
    }

    /// Pop the next emitted segment, or panic with context.
    fn next_seg(&mut self, ctx: &str) -> Seg {
        self.emitted.pop_front().unwrap_or_else(|| panic!("expected a segment ({ctx}), got none"))
    }

    /// Assert no segment is pending.
    fn expect_silence(&mut self) {
        assert!(self.emitted.is_empty(), "expected silence, got {:?}", self.emitted);
    }

    fn iss(&self) -> u32 {
        self.iss.expect("stack ISS not yet learned")
    }

    fn connected_sock(&self) -> Option<SocketId> {
        self.events.iter().find_map(|e| match e {
            AppEvent::Connected { sock, .. } => Some(*sock),
            _ => None,
        })
    }
}

fn parse_emitted(datagram: &[u8]) -> Option<Seg> {
    let (_h, l4) = ipv4::parse(datagram).ok()?;
    let (th, opts, payload) = tcp_sans_io::wire::tcp::parse(l4, &STACK_IP, &PEER_IP).ok()?;
    Some(Seg {
        src_port: th.src_port,
        flags: th.flags,
        seq: th.seq,
        ack: th.ack,
        window: th.window,
        payload: payload.to_vec(),
        mss: opts.mss,
        wscale: opts.window_scale,
        sack_permitted: opts.sack_permitted,
        sack_blocks: opts.sack_blocks.as_slice().to_vec(),
    })
}

/// Flags compared ignoring PSH/URG (discretionary / unused).
fn core_flags(f: TcpFlags) -> u8 {
    f.0 & (TcpFlags::SYN.0 | TcpFlags::ACK.0 | TcpFlags::FIN.0 | TcpFlags::RST.0)
}

fn assert_flags(seg: &Seg, expected: TcpFlags, ctx: &str) {
    assert_eq!(core_flags(seg.flags), core_flags(expected), "flags mismatch ({ctx}): {seg:?}");
}

// ---------------------------------------------------------------------------

/// Passive open: SYN → SYN-ACK (exact ack, options) → ACK → ESTABLISHED.
#[test]
fn passive_open_handshake_exact() {
    let mut pd = Pd::new();
    pd.stack.listen(STACK_PORT).unwrap();

    // < S seq=1000 win=65535 <mss 1460, wscale 7, sackOK>
    pd.inject(Inject::new(TcpFlags::SYN, 1000, 0).win(65535).syn_opts(1460, Some(7), true));

    // > S. seq=ISS ack=1001 <mss …, wscale …, sackOK>
    let synack = pd.next_seg("SYN-ACK");
    assert_flags(&synack, TcpFlags::SYN.union(TcpFlags::ACK), "syn-ack");
    assert_eq!(synack.ack, 1001, "must ack the peer's SYN (seq+1)");
    assert!(synack.mss.is_some(), "SYN-ACK carries MSS");
    assert_eq!(synack.wscale, Some(0), "we offered window scale (recv shift 0)");
    assert!(synack.sack_permitted, "we accept SACK since peer offered it");
    // RFC 7323 §2.2: the SYN window is unscaled, so it is the full default
    // receive-buffer capacity (16384).
    assert_eq!(synack.window, 16384, "SYN-ACK advertises the unscaled recv window");
    let iss = pd.iss();

    // < . ack=ISS+1   → completes the handshake; no segment expected.
    pd.inject(Inject::new(TcpFlags::ACK, 1001, iss.wrapping_add(1)).win(65535));
    pd.expect_silence();
    assert_eq!(pd.stack.state_of(pd.connected_sock().unwrap()), Some(tcp_sans_io::tcp::State::Established));
}

/// Active open: connect → SYN (with options) → SYN-ACK → ACK.
#[test]
fn active_open_handshake_exact() {
    let mut pd = Pd::new();
    let sock = pd
        .stack
        .connect(pd.now(), SocketAddr::new(PEER_IP, PEER_PORT))
        .unwrap();
    pd.drain();

    // > S seq=ISS win=… <mss, wscale, sackOK>
    let syn = pd.next_seg("SYN");
    assert_flags(&syn, TcpFlags::SYN, "syn");
    assert!(syn.mss.is_some() && syn.wscale.is_some() && syn.sack_permitted);
    let iss = syn.seq;
    // The active opener chose an ephemeral local port; reply to *that* port.
    pd.stack_port = syn.src_port;

    // < S. seq=5000 ack=ISS+1
    pd.inject(
        Inject::new(TcpFlags::SYN.union(TcpFlags::ACK), 5000, iss.wrapping_add(1))
            .win(65535)
            .syn_opts(1460, Some(7), true),
    );

    // > . ack=5001  (third leg)
    let ack = pd.next_seg("handshake ACK");
    assert_flags(&ack, TcpFlags::ACK, "ack");
    assert_eq!(ack.ack, 5001, "acks the peer's SYN");
    assert_eq!(ack.seq, iss.wrapping_add(1));
    assert_eq!(pd.stack.state_of(sock), Some(tcp_sans_io::tcp::State::Established));
}

/// Data delivery produces an ACK with the exact cumulative ack number.
#[test]
fn data_segment_is_acked_exactly() {
    let mut pd = establish_passive();
    let iss = pd.iss();

    // < P. seq=1001 ack=ISS+1 data=10 bytes
    pd.inject(
        Inject::new(TcpFlags::ACK.union(TcpFlags::PSH), 1001, iss.wrapping_add(1))
            .data(b"0123456789"),
    );
    // A single in-order segment is delayed-ACKed (RFC 1122 §4.2.3.2), so no
    // immediate reply; the ACK arrives when the delayed-ACK timer fires.
    pd.expect_silence();
    pd.advance(250);
    // > . ack=1011  (acks all 10 bytes)
    let ack = pd.next_seg("delayed data ack");
    assert_flags(&ack, TcpFlags::ACK, "ack");
    assert_eq!(ack.ack, 1011, "cumulative ack covers exactly the 10 bytes");
}

/// An out-of-order segment elicits an immediate duplicate ACK pointing at the
/// gap, plus a SACK block describing the received range (RFC 2018 §4).
#[test]
fn out_of_order_segment_triggers_sack() {
    let mut pd = establish_passive();
    let iss = pd.iss();

    // Gap: peer's data starts at 1001; inject [1011,1021) leaving [1001,1011)
    // missing.
    pd.inject(
        Inject::new(TcpFlags::ACK, 1011, iss.wrapping_add(1)).data(b"AAAAAAAAAA"),
    );
    let dupack = pd.next_seg("dup ack with SACK");
    assert_flags(&dupack, TcpFlags::ACK, "dupack");
    assert_eq!(dupack.ack, 1001, "ack still points at the gap");
    assert_eq!(dupack.sack_blocks, vec![(1011, 1021)], "SACK reports the out-of-order range");
}

/// Retransmission: unacked data is resent identically after the RTO, with no
/// ACK from the peer in between.
#[test]
fn rto_retransmits_identically() {
    let mut pd = establish_passive();
    let iss = pd.iss();
    let sock = pd.connected_sock().unwrap();

    // App sends 4 bytes; capture the data segment.
    pd.stack.send(sock, b"ping").unwrap();
    pd.drain();
    let first = pd.next_seg("first data");
    assert_flags(&first, TcpFlags::ACK, "data");
    assert_eq!(first.seq, iss.wrapping_add(1));
    assert_eq!(first.payload, b"ping");
    pd.expect_silence();

    // No ACK arrives. Advance past the RTO (initial 1 s); expect an identical
    // retransmission.
    pd.advance(1200);
    let rexmit = pd.next_seg("retransmission");
    assert_eq!(rexmit.seq, first.seq, "same sequence number");
    assert_eq!(rexmit.payload, first.payload, "same bytes");
}

/// RFC 5961 §3.2: an in-window but non-exact RST yields a challenge ACK and
/// does NOT tear the connection down.
#[test]
fn inexact_rst_challenged_not_closed() {
    let mut pd = establish_passive();
    let iss = pd.iss();
    let sock = pd.connected_sock().unwrap();

    // RST whose seq is in the window but not == RCV.NXT (which is 1001).
    pd.inject(Inject::new(TcpFlags::RST, 1050, 0).win(65535));
    let chal = pd.next_seg("challenge ACK");
    assert_flags(&chal, TcpFlags::ACK, "challenge");
    assert_eq!(chal.ack, 1001, "challenge ACK names RCV.NXT");
    assert_eq!(chal.seq, iss.wrapping_add(1), "challenge ACK uses SND.NXT");
    assert_eq!(
        pd.stack.state_of(sock),
        Some(tcp_sans_io::tcp::State::Established),
        "connection survives the blind RST"
    );
}

/// An exact-sequence RST does tear the connection down (RFC 9293 §3.10.7.4).
#[test]
fn exact_rst_resets_connection() {
    let mut pd = establish_passive();
    let sock = pd.connected_sock().unwrap();
    // RST at exactly RCV.NXT (1001).
    pd.inject(Inject::new(TcpFlags::RST, 1001, 0).win(65535));
    assert_eq!(pd.stack.state_of(sock), None, "exact RST closed the connection");
}

/// FIN handling: peer FIN is acked and advances our state to CLOSE-WAIT.
#[test]
fn peer_fin_acked_exactly() {
    let mut pd = establish_passive();
    let iss = pd.iss();
    let sock = pd.connected_sock().unwrap();

    // < F. seq=1001 ack=ISS+1
    pd.inject(Inject::new(TcpFlags::FIN.union(TcpFlags::ACK), 1001, iss.wrapping_add(1)));
    let ack = pd.next_seg("fin ack");
    assert_flags(&ack, TcpFlags::ACK, "ack");
    assert_eq!(ack.ack, 1002, "acks the FIN's sequence (RCV.NXT advanced past it)");
    assert_eq!(pd.stack.state_of(sock), Some(tcp_sans_io::tcp::State::CloseWait));
}

// --- shared setup: a fully established passive connection ---------------

fn establish_passive() -> Pd {
    let mut pd = Pd::new();
    pd.stack.listen(STACK_PORT).unwrap();
    pd.inject(Inject::new(TcpFlags::SYN, 1000, 0).win(65535).syn_opts(1460, Some(7), true));
    let _synack = pd.next_seg("syn-ack");
    let iss = pd.iss();
    pd.inject(Inject::new(TcpFlags::ACK, 1001, iss.wrapping_add(1)).win(65535));
    pd.emitted.clear(); // discard anything from completing the handshake
    pd
}

// Keep an unused import meaningful regardless of feature flags.
#[allow(unused)]
fn _uses_bounded_vec() -> BoundedVec<u8, 1> {
    BoundedVec::new()
}
