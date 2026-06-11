//! In-memory two-host test harness driving real [`Stack`] instances through
//! a virtual network with a virtual clock.
//!
//! This is the runtime the protocol core was designed to be embedded in,
//! reduced to its essentials: it owns real time (here, simulated), real
//! timers (here, a priority list), entropy (here, a fixed seed), and the
//! "wire" (here, a vector with optional loss/reorder/duplication). Because
//! the core is sans-I/O and deterministic, the same seed and schedule
//! reproduce a run exactly.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::vec::Vec;
use tcp_sans_io::config::Config;
use tcp_sans_io::time::{Duration, Instant};
use tcp_sans_io::{
    Action, AppEvent, CloseReason, Event, IpAddr, SocketAddr, SocketId, Stack, TimerKey, TimerKind,
};

/// Maximum datagram the harness will carry (one MTU of headroom).
pub const FRAME: usize = 2048;

/// Upper bound on `poll_action` calls in one drain. Statically, a quiescing
/// stack can owe at most the action queue (64) + ctl queue (8) + one echo +
/// every connection's sendable window (≈ 16 KiB / MSS ≈ 12 segments × 8
/// conns) + a sweep's worth of timer diffs — well under 1k. A drain that
/// exceeds this bound means `poll_action` is not quiescing: a livelock.
pub const DRAIN_FUEL: usize = 8192;

/// How faithfully the harness honors the A-POLL-1 drain obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainPolicy {
    /// Drain to `None` after every event/API call (a compliant runtime).
    Eager,
    /// Skip each drain opportunity with probability `skip_permille`,
    /// seed-driven — a runtime that falls behind and catches up later.
    /// Models GC pauses, batching hosts, starved threads. The stack's
    /// degraded-mode claim ("delays, never loses") is tested in this mode.
    Lazy {
        /// Probability per mille of skipping a drain opportunity.
        skip_permille: u32,
    },
}

/// A datagram in flight, scheduled to arrive at `deliver_at`.
struct InFlight {
    deliver_at: Instant,
    to: Host,
    bytes: Vec<u8>,
    /// Tie-breaker so equal arrival times stay FIFO (deterministic order).
    seq: u64,
}

/// Which host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    A,
    B,
}

impl Host {
    fn other(self) -> Host {
        match self {
            Host::A => Host::B,
            Host::B => Host::A,
        }
    }
    fn idx(self) -> usize {
        self as usize
    }
}

/// A pending virtual timer.
#[derive(Clone, Copy)]
struct Timer {
    fire_at: Instant,
    host: Host,
    key: TimerKey,
    live: bool,
}

/// Network impairments applied to each datagram. Deterministic given the
/// harness RNG seed.
#[derive(Debug, Clone, Copy)]
pub struct NetModel {
    /// One-way propagation delay.
    pub delay: Duration,
    /// Drop probability in [0,1000): `loss` per mille.
    pub loss_permille: u32,
    /// Duplicate probability per mille.
    pub dup_permille: u32,
    /// Extra jitter up to this much, added pseudo-randomly.
    pub jitter: Duration,
    /// Corrupt-a-byte probability per mille (exercises checksum rejection).
    pub corrupt_permille: u32,
}

impl Default for NetModel {
    fn default() -> Self {
        NetModel {
            delay: Duration::from_millis(10),
            loss_permille: 0,
            dup_permille: 0,
            jitter: Duration::ZERO,
            corrupt_permille: 0,
        }
    }
}

/// Captured application event with the host it fired on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Captured {
    pub host: Host,
    pub event: AppEvent,
}

/// Deterministic xorshift64* PRNG (no external deps, replayable).
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, bound: u32) -> u32 {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() % bound as u64) as u32
    }
    pub fn chance_permille(&mut self, permille: u32) -> bool {
        self.below(1000) < permille
    }
}

/// Two stacks and the wire between them.
///
/// The stacks are boxed: each `Stack<8>` embeds all connection buffers
/// inline (no heap inside the core), so keeping two by value in a test-thread
/// stack frame would overflow it. The box moves that fixed arena to the heap
/// — exactly what a real runtime does when it places the stack in a `static`
/// or an allocation.
pub struct Net {
    pub a: Box<Stack<8>>,
    pub b: Box<Stack<8>>,
    pub addr_a: IpAddr,
    pub addr_b: IpAddr,
    clock: Instant,
    wire: Vec<InFlight>,
    timers: Vec<Timer>,
    pub model: NetModel,
    rng: Rng,
    seq: u64,
    pub events: Vec<Captured>,
    /// Total bytes the harness chose to drop (for assertions/logging).
    pub dropped: u64,
    /// Drain discipline (default: compliant `Eager`).
    pub drain_policy: DrainPolicy,
}

impl Net {
    /// Build a v4 network. `seed` drives all impairment decisions.
    pub fn new(model: NetModel, seed: u64) -> Self {
        Self::with_addrs(
            IpAddr::v4(10, 0, 0, 1),
            IpAddr::v4(10, 0, 0, 2),
            model,
            seed,
        )
    }

    /// Build a v6 network.
    pub fn new_v6(model: NetModel, seed: u64) -> Self {
        Self::with_addrs(
            IpAddr::v6([0xfc00, 0, 0, 0, 0, 0, 0, 1]),
            IpAddr::v6([0xfc00, 0, 0, 0, 0, 0, 0, 2]),
            model,
            seed,
        )
    }

    fn with_addrs(addr_a: IpAddr, addr_b: IpAddr, model: NetModel, seed: u64) -> Self {
        let mk = |addr| {
            let mut cfg = Config::with_addr(addr);
            cfg.mtu = 1500;
            cfg
        };
        let mut net = Net {
            a: Box::new(Stack::new(mk(addr_a))),
            b: Box::new(Stack::new(mk(addr_b))),
            addr_a,
            addr_b,
            clock: Instant::from_secs(1),
            wire: Vec::new(),
            timers: Vec::new(),
            model,
            rng: Rng::new(seed),
            seq: 0,
            events: Vec::new(),
            dropped: 0,
            drain_policy: DrainPolicy::Eager,
        };
        // Seed entropy on both stacks and clear the resulting actions.
        net.pump();
        net
    }

    /// Apply a custom config to both hosts (rebuilds the stacks).
    pub fn reconfigure(&mut self, mut cfg_a: Config, mut cfg_b: Config) {
        cfg_a.local_addrs = Config::with_addr(self.addr_a).local_addrs;
        cfg_b.local_addrs = Config::with_addr(self.addr_b).local_addrs;
        // Reuse the existing heap allocations rather than allocating new boxes.
        *self.a = Stack::new(cfg_a);
        *self.b = Stack::new(cfg_b);
        self.timers.clear();
        self.wire.clear();
        self.pump();
    }

    fn stack(&mut self, host: Host) -> &mut Stack<8> {
        match host {
            Host::A => &mut self.a,
            Host::B => &mut self.b,
        }
    }

    /// Read-only access for stats/state queries.
    pub fn host(&self, host: Host) -> &Stack<8> {
        match host {
            Host::A => &self.a,
            Host::B => &self.b,
        }
    }

    /// Endpoint of `host` on `port`.
    pub fn endpoint(&self, host: Host, port: u16) -> SocketAddr {
        SocketAddr::new(
            if host == Host::A {
                self.addr_a
            } else {
                self.addr_b
            },
            port,
        )
    }

    /// Current virtual time.
    pub fn now(&self) -> Instant {
        self.clock
    }

    /// Drain all pending actions from both hosts until quiescent, scheduling
    /// transmissions on the wire and timers in the timer list. Idempotent.
    pub fn pump(&mut self) {
        for host in [Host::A, Host::B] {
            self.drain(host);
        }
    }

    /// Drain `host` honoring the configured policy: a lazy runtime skips
    /// this opportunity (seed-driven) and catches up at a later drain.
    fn maybe_drain(&mut self, host: Host) {
        match self.drain_policy {
            DrainPolicy::Eager => self.drain(host),
            DrainPolicy::Lazy { skip_permille } => {
                if !self.rng.chance_permille(skip_permille) {
                    self.drain(host);
                }
            }
        }
    }

    fn drain(&mut self, host: Host) {
        let now = self.clock;
        let mut tx = [0u8; FRAME];
        let mut fuel = DRAIN_FUEL;
        loop {
            let action = self.stack(host).poll_action(now, &mut tx);
            let Some(action) = action else { break };
            // Anti-livelock: a quiescing stack owes a statically bounded
            // amount of work; burning all fuel means poll_action will yield
            // actions forever (e.g. an ACK/retransmit generation loop).
            fuel -= 1;
            assert!(
                fuel > 0,
                "poll_action did not quiesce within {DRAIN_FUEL} actions: livelock"
            );
            match action {
                Action::None => {}
                Action::RequestEntropy => {
                    // Distinct, fixed seeds per host: deterministic but
                    // different ISN streams.
                    let seed = match host {
                        Host::A => [0x11; 16],
                        Host::B => [0x22; 16],
                    };
                    self.stack(host).on_entropy(seed);
                }
                Action::Transmit { len } => {
                    self.launch(host, &tx[..len]);
                }
                Action::StartTimer { key, after } => {
                    self.arm(host, key, now + after);
                }
                Action::CancelTimer { key } => {
                    self.cancel(host, key);
                }
                Action::App(event) => {
                    self.events.push(Captured { host, event });
                }
            }
        }
    }

    fn launch(&mut self, from: Host, bytes: &[u8]) {
        let mut deliver = self.clock + self.model.delay;
        if self.model.jitter.as_micros() > 0 {
            deliver += Duration::from_micros(
                self.rng.below(self.model.jitter.as_micros() as u32 + 1) as u64,
            );
        }
        // Loss.
        if self.rng.chance_permille(self.model.loss_permille) {
            self.dropped += bytes.len() as u64;
            return;
        }
        let mut payload = bytes.to_vec();
        // Corruption: flip a byte. The receiver's checksum must reject it,
        // so it is effectively a (delayed) loss — exercises the verifier.
        if self.rng.chance_permille(self.model.corrupt_permille) && !payload.is_empty() {
            let i = self.rng.below(payload.len() as u32) as usize;
            payload[i] ^= 0x20;
        }
        self.push_wire(from.other(), deliver, payload.clone());
        // Duplication.
        if self.rng.chance_permille(self.model.dup_permille) {
            let extra = deliver + Duration::from_millis(1 + self.rng.below(5) as u64);
            self.push_wire(from.other(), extra, payload);
        }
    }

    fn push_wire(&mut self, to: Host, deliver_at: Instant, bytes: Vec<u8>) {
        self.seq += 1;
        self.wire.push(InFlight {
            deliver_at,
            to,
            bytes,
            seq: self.seq,
        });
    }

    fn arm(&mut self, host: Host, key: TimerKey, fire_at: Instant) {
        // One pending instance per (host,key): re-arming replaces it.
        for t in self.timers.iter_mut() {
            if t.host == host && same_key(t.key, key) && t.live {
                t.fire_at = fire_at;
                return;
            }
        }
        self.timers.push(Timer {
            fire_at,
            host,
            key,
            live: true,
        });
    }

    fn cancel(&mut self, host: Host, key: TimerKey) {
        for t in self.timers.iter_mut() {
            if t.host == host && same_key(t.key, key) {
                t.live = false;
            }
        }
    }

    /// Advance to the next scheduled event (delivery or timer), process it,
    /// and pump. Returns false when nothing is pending.
    pub fn step(&mut self) -> bool {
        let next_wire = self.wire.iter().map(|p| p.deliver_at).min();
        let next_timer = self
            .timers
            .iter()
            .filter(|t| t.live)
            .map(|t| t.fire_at)
            .min();
        let next = match (next_wire, next_timer) {
            (None, None) => return false,
            (Some(w), None) => w,
            (None, Some(t)) => t,
            (Some(w), Some(t)) => w.min(t),
        };
        if next > self.clock {
            self.clock = next;
        }

        // Fire all timers due now (deterministic order: by host then a
        // stable kind order via the vec order).
        let due: Vec<(Host, TimerKey)> = self
            .timers
            .iter()
            .filter(|t| t.live && t.fire_at <= self.clock)
            .map(|t| (t.host, t.key))
            .collect();
        for t in self.timers.iter_mut() {
            if t.live && t.fire_at <= self.clock {
                t.live = false;
            }
        }
        for (host, key) in due {
            let now = self.clock;
            self.stack(host).on_timer(now, key);
            self.maybe_drain(host);
        }

        // Deliver all datagrams due now, in (deliver_at, seq) order.
        let mut due_wire: Vec<usize> = (0..self.wire.len())
            .filter(|&i| self.wire[i].deliver_at <= self.clock)
            .collect();
        due_wire.sort_by_key(|&i| (self.wire[i].deliver_at, self.wire[i].seq));
        let delivered: Vec<(Host, Vec<u8>)> = due_wire
            .iter()
            .map(|&i| (self.wire[i].to, self.wire[i].bytes.clone()))
            .collect();
        // Remove delivered (descending index to keep positions valid).
        let mut idxs = due_wire;
        idxs.sort_unstable_by(|a, b| b.cmp(a));
        for i in idxs {
            self.wire.swap_remove(i);
        }
        for (to, bytes) in delivered {
            let now = self.clock;
            self.stack(to).on_datagram(now, &bytes);
            self.maybe_drain(to);
        }
        true
    }

    /// Run until quiescent or `max_steps` exhausted. Returns steps taken.
    pub fn run(&mut self, max_steps: usize) -> usize {
        let mut n = 0;
        while n < max_steps && self.step() {
            n += 1;
        }
        n
    }

    /// Advance virtual time by `d` with no traffic (e.g. to expire TIME-WAIT
    /// while the wire is idle), processing any timers that come due.
    pub fn idle(&mut self, d: Duration) {
        let target = self.clock + d;
        while let Some(next) = self
            .timers
            .iter()
            .filter(|t| t.live && t.fire_at <= target)
            .map(|t| t.fire_at)
            .min()
        {
            self.clock = next;
            if !self.step() {
                break;
            }
        }
        if target > self.clock {
            self.clock = target;
        }
    }

    // --- Convenience API wrappers that pump afterwards ---

    pub fn listen(&mut self, host: Host, port: u16) {
        self.stack(host).listen(port).expect("listen");
        self.maybe_drain(host);
    }

    pub fn connect(&mut self, host: Host, to: SocketAddr) -> SocketId {
        let now = self.clock;
        let id = self.stack(host).connect(now, to).expect("connect");
        self.maybe_drain(host);
        id
    }

    pub fn send(&mut self, host: Host, sock: SocketId, data: &[u8]) -> usize {
        let n = self.stack(host).send(sock, data).expect("send");
        self.maybe_drain(host);
        n
    }

    /// Fallible send: returns `None` if the socket is gone (e.g. it timed out
    /// under heavy loss). Used by the fuzzer where teardown is expected.
    pub fn try_send(&mut self, host: Host, sock: SocketId, data: &[u8]) -> Option<usize> {
        let r = self.stack(host).send(sock, data).ok();
        self.maybe_drain(host);
        r
    }

    /// Fallible recv: `None` if the socket is gone, else bytes read.
    pub fn try_recv(&mut self, host: Host, sock: SocketId, out: &mut [u8]) -> Option<usize> {
        let r = self.stack(host).recv(sock, out).ok();
        self.maybe_drain(host);
        r
    }

    /// True if the handle still maps to a live connection.
    pub fn alive(&self, host: Host, sock: SocketId) -> bool {
        match host {
            Host::A => self.a.state_of(sock).is_some(),
            Host::B => self.b.state_of(sock).is_some(),
        }
    }

    pub fn close(&mut self, host: Host, sock: SocketId) {
        let now = self.clock;
        self.stack(host).close(now, sock).expect("close");
        self.maybe_drain(host);
    }

    pub fn abort(&mut self, host: Host, sock: SocketId) {
        let now = self.clock;
        self.stack(host).abort(now, sock).expect("abort");
        self.maybe_drain(host);
    }

    pub fn recv(&mut self, host: Host, sock: SocketId, out: &mut [u8]) -> usize {
        let n = self.stack(host).recv(sock, out).unwrap_or(0);
        self.maybe_drain(host);
        n
    }

    /// Drain all currently-readable bytes from a socket into a Vec.
    pub fn recv_all(&mut self, host: Host, sock: SocketId) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = self.stack(host).recv(sock, &mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        self.maybe_drain(host);
        out
    }

    // --- Liveness oracles ---

    /// Two-sided timer-fidelity oracle. Force-drains `host` to quiescence,
    /// then asserts that the timers this harness has armed for `sock` are
    /// exactly the deadlines the stack currently wants. Any divergence is a
    /// boundary bug: a lost, phantom, or mis-keyed Start/CancelTimer. A
    /// wedged connection ("owes the network work but nothing scheduled to
    /// wake it") shows up here as desired-without-armed.
    pub fn assert_timer_fidelity(&mut self, host: Host, sock: SocketId) {
        self.drain(host); // quiesce: after this, emitted == desired
        const KINDS: [TimerKind; 4] = [
            TimerKind::Rexmit,
            TimerKind::Persist,
            TimerKind::DelAck,
            TimerKind::Wait,
        ];
        let desired = self.host(host).timer_deadlines_of(sock);
        for (i, kind) in KINDS.into_iter().enumerate() {
            let key = TimerKey::Conn { sock, kind };
            let armed = self
                .timers
                .iter()
                .find(|t| t.live && t.host == host && t.key == key)
                .map(|t| t.fire_at);
            let want = desired.and_then(|d| d[i]);
            match (want, armed) {
                (None, None) => {}
                (Some(w), Some(a)) => {
                    // A deadline already past when a (lazy) drain delivered
                    // it gets armed at the drain instant — between the
                    // deadline and the current clock.
                    assert!(
                        a == w || (w <= self.clock && a >= w && a <= self.clock),
                        "{host:?}/{kind:?}: armed {a:?} but stack wants {w:?} (clock {:?})",
                        self.clock
                    );
                }
                (want, armed) => panic!(
                    "{host:?}/{kind:?}: stack wants {want:?} but runtime armed {armed:?} — \
                     lost or phantom timer (boundary bug)"
                ),
            }
        }
    }

    // --- Event queries ---

    pub fn first_connected(&self, host: Host) -> Option<SocketId> {
        self.events.iter().find_map(|c| match c.event {
            AppEvent::Connected { sock, .. } if c.host == host => Some(sock),
            _ => None,
        })
    }

    pub fn accepted_socket(&self, host: Host) -> Option<(SocketId, u16)> {
        self.events.iter().find_map(|c| match c.event {
            AppEvent::Connected {
                sock,
                via_listener: Some(p),
            } if c.host == host => Some((sock, p)),
            _ => None,
        })
    }

    pub fn closed_reason(&self, host: Host, sock: SocketId) -> Option<CloseReason> {
        self.events.iter().rev().find_map(|c| match c.event {
            AppEvent::Closed { sock: s, reason } if c.host == host && s == sock => Some(reason),
            _ => None,
        })
    }

    pub fn saw_peer_fin(&self, host: Host, sock: SocketId) -> bool {
        self.events
            .iter()
            .any(|c| c.host == host && c.event == AppEvent::PeerFinReceived { sock })
    }

    /// Count of `PeerFinReceived` events delivered for a socket. The
    /// single-FIN oracle: this MUST be ≤ 1 over a connection's lifetime
    /// regardless of what arrives on the wire (DEF-M1).
    pub fn peer_fin_count(&self, host: Host, sock: SocketId) -> usize {
        self.count_events(|c| c.host == host && c.event == AppEvent::PeerFinReceived { sock })
    }

    pub fn count_events(&self, pred: impl Fn(&Captured) -> bool) -> usize {
        self.events.iter().filter(|c| pred(c)).count()
    }
}

fn same_key(a: TimerKey, b: TimerKey) -> bool {
    a == b
}

/// Group adjacent identical bytes for compact transfer logging.
pub fn histogram(data: &[u8]) -> BTreeMap<u8, usize> {
    let mut h = BTreeMap::new();
    for &b in data {
        *h.entry(b).or_insert(0) += 1;
    }
    h
}

/// Standard one-shot helper: establish A→B on `port`, returning both socket
/// handles `(client, server)`.
pub fn establish(net: &mut Net, port: u16) -> (SocketId, SocketId) {
    net.listen(Host::B, port);
    let server_ep = net.endpoint(Host::B, port);
    let client = net.connect(Host::A, server_ep);
    net.run(100);
    let server = net.accepted_socket(Host::B).expect("server accepted").0;
    assert_eq!(
        net.state_a(client),
        Some(tcp_sans_io::tcp::State::Established)
    );
    (client, server)
}

impl Net {
    pub fn state_a(&self, sock: SocketId) -> Option<tcp_sans_io::tcp::State> {
        self.a.state_of(sock)
    }
    pub fn state_b(&self, sock: SocketId) -> Option<tcp_sans_io::tcp::State> {
        self.b.state_of(sock)
    }

    /// Local port host A bound to a connection.
    pub fn client_port(&self, sock: SocketId) -> u16 {
        self.a.local_port_of(sock).expect("live socket")
    }

    /// RCV.NXT of an A-side connection (what A will accept next).
    pub fn a_rcv_nxt(&self, sock: SocketId) -> u32 {
        self.a.rcv_nxt_of(sock).expect("live socket")
    }

    /// SND.UNA of an A-side connection.
    pub fn a_snd_una(&self, sock: SocketId) -> u32 {
        self.a.snd_state_of(sock).expect("live socket").0
    }

    /// SND.WND of an A-side connection (peer's advertised window).
    pub fn a_snd_wnd(&self, sock: SocketId) -> u32 {
        self.a.snd_state_of(sock).expect("live socket").2
    }

    /// Drain both hosts' action queues after injecting a raw datagram with
    /// `on_datagram` directly (which does not auto-drain like the wrappers).
    pub fn pump_public(&mut self) {
        self.pump();
    }
}

// Re-export so scenario files can `use harness::*;` and name events.
pub use tcp_sans_io::tcp::State as TcpState;

// Keep `Event` referenced so the import is meaningful even if some scenario
// files use only the convenience wrappers.
#[allow(unused)]
fn _event_is_used(e: Event<'_>) -> Event<'_> {
    e
}
