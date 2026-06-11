//! Deterministic, seed-driven fuzzing of the whole stack over an impaired
//! network.
//!
//! For each seed we drive two stacks through a randomized schedule of
//! application sends, receives, and network impairment (loss, reordering,
//! duplication, corruption), then quiesce a clean tail and assert the two
//! core properties:
//!
//! * **Safety**: the bytes each side received are *exactly a prefix* of the
//!   bytes the other side sent — never reordered, never invented, never
//!   duplicated into the stream. Checked continuously, not just at the end.
//! * **Liveness**: once impairments stop, every byte that was submitted is
//!   eventually delivered.
//!
//! Determinism means any failure reproduces from its seed alone. The
//! connection's `debug_assert!` invariant checks (S-INV-*) run throughout,
//! so a violated internal invariant aborts the run with its seed.

mod harness;

use harness::{DrainPolicy, Host, Net, NetModel, Rng, TcpState};
use tcp_sans_io::time::Duration;

const PORT: u16 = 7;

/// Tracks one direction's submitted-vs-delivered byte streams and enforces
/// the prefix property on every delivery.
#[derive(Default)]
struct Stream {
    sent: Vec<u8>,
    received: Vec<u8>,
}

impl Stream {
    fn submit(&mut self, bytes: &[u8]) {
        self.sent.extend_from_slice(bytes);
    }
    fn deliver(&mut self, bytes: &[u8]) {
        let start = self.received.len();
        // Safety: each delivered byte must equal the corresponding submitted
        // byte. A mismatch means reordering, duplication into the stream, or
        // corruption slipped through — a TCP correctness bug.
        for (i, &b) in bytes.iter().enumerate() {
            let pos = start + i;
            assert!(pos < self.sent.len(), "received more bytes than were sent (pos {pos})");
            assert_eq!(b, self.sent[pos], "stream byte {pos} mismatched (out-of-order/dup/corrupt)");
        }
        self.received.extend_from_slice(bytes);
    }
    fn complete(&self) -> bool {
        self.received.len() == self.sent.len()
    }
}

/// Outcome of one fuzz run.
struct RunOutcome {
    /// The connection outlived the activity phase. Aborting under abuse
    /// (retry limit / user timeout) is legitimate TCP, so `!survived` is
    /// acceptable; a stall is `survived && !completed`.
    survived: bool,
    /// Every submitted byte was delivered after the clean tail.
    completed: bool,

    /// Deeper of the two hosts' action-queue high-water marks.
    peak: u16,
}

/// One fuzz run. Returns true if the transfer completed (liveness); the
/// prefix property (safety) is asserted internally throughout.
fn run_once(seed: u64, model: NetModel) -> bool {
    run_once_with(seed, model, DrainPolicy::Eager, 1).completed
}

/// As [`run_once`], with an explicit drain policy for the activity phase and
/// a timer-oracle cadence (`oracle_every` rounds — sparser checks let lazy
/// backlogs grow deeper). The clean tail always runs `Eager`: the lane
/// models a runtime that misbehaves and then recovers, and after recovery a
/// surviving connection has no excuse not to converge.
fn run_once_with(
    seed: u64,
    model: NetModel,
    policy: DrainPolicy,
    oracle_every: usize,
) -> RunOutcome {
    let mut net = Net::new(model, seed);
    net.drain_policy = policy;
    net.listen(Host::B, PORT);
    let ep = net.endpoint(Host::B, PORT);
    let client = net.connect(Host::A, ep);

    // Bring up the connection (may take retransmissions under loss).
    net.run(3000);
    net.pump();
    let Some(server) = net.accepted_socket(Host::B).map(|x| x.0) else {
        // Under extreme loss the handshake may not finish within budget;
        // that is acceptable for liveness (no impairment-free tail yet).
        return RunOutcome { survived: false, completed: false, peak: peak(&net) };
    };

    let mut rng = Rng::new(seed ^ 0xA5A5_A5A5);
    let mut a2b = Stream::default();
    let mut b2a = Stream::default();
    let mut rbuf = [0u8; 4096];

    // Randomized activity phase. If a connection is torn down (which is
    // legitimate under heavy loss once the retransmission limit is hit),
    // we stop submitting and the run simply does not "complete".
    let mut torn_down = false;
    for round in 0..400 {
        // Two-sided timer oracle: the harness's armed timers must mirror
        // the stack's desired deadlines at quiescence — a lost StartTimer
        // here is a future stall; a phantom one is a leak.
        if round % oracle_every == 0 {
            net.assert_timer_fidelity(Host::A, client);
            net.assert_timer_fidelity(Host::B, server);
        }
        if !net.alive(Host::A, client) || !net.alive(Host::B, server) {
            torn_down = true;
            break;
        }
        // Random sends in each direction.
        if rng.below(100) < 70 {
            let n = 1 + rng.below(2000) as usize;
            let chunk: Vec<u8> = (0..n).map(|i| (a2b.sent.len() + i) as u8).collect();
            if let Some(accepted) = net.try_send(Host::A, client, &chunk) {
                a2b.submit(&chunk[..accepted]);
            }
        }
        if rng.below(100) < 40 {
            let n = 1 + rng.below(800) as usize;
            let chunk: Vec<u8> = (0..n).map(|i| (b2a.sent.len() + i).wrapping_mul(3) as u8).collect();
            if let Some(accepted) = net.try_send(Host::B, server, &chunk) {
                b2a.submit(&chunk[..accepted]);
            }
        }

        // Advance the network a few steps.
        for _ in 0..1 + rng.below(4) {
            net.step();
        }

        // Drain receivers (randomly, to vary window pressure).
        if rng.below(100) < 80 {
            while let Some(n) = net.try_recv(Host::B, server, &mut rbuf).filter(|&n| n > 0) {
                a2b.deliver(&rbuf[..n]);
            }
        }
        if rng.below(100) < 80 {
            while let Some(n) = net.try_recv(Host::A, client, &mut rbuf).filter(|&n| n > 0) {
                b2a.deliver(&rbuf[..n]);
            }
        }
    }

    if torn_down {
        // Safety held throughout (asserted on every delivery); liveness is
        // not expected once a connection was reset by the retry limit. The
        // dead handles must leave no phantom timers armed runtime-side.
        net.pump();
        net.assert_timer_fidelity(Host::A, client);
        net.assert_timer_fidelity(Host::B, server);
        return RunOutcome { survived: false, completed: false, peak: peak(&net) };
    }

    // Clean tail: impairment stops AND the runtime recovers its drain
    // discipline. From here convergence is mandatory for a live connection.
    net.drain_policy = DrainPolicy::Eager;
    net.model = NetModel { delay: Duration::from_millis(5), ..Default::default() };
    for _ in 0..50_000 {
        let progressed = net.step();
        while let Some(n) = net.try_recv(Host::B, server, &mut rbuf).filter(|&n| n > 0) {
            a2b.deliver(&rbuf[..n]);
        }
        while let Some(n) = net.try_recv(Host::A, client, &mut rbuf).filter(|&n| n > 0) {
            b2a.deliver(&rbuf[..n]);
        }
        if a2b.complete() && b2a.complete() {
            break;
        }
        if !progressed && (!net.alive(Host::A, client) || !net.alive(Host::B, server)) {
            break;
        }
    }
    // Final drain pass (sockets may have closed; tolerate that).
    net.pump();
    while let Some(n) = net.try_recv(Host::B, server, &mut rbuf).filter(|&n| n > 0) {
        a2b.deliver(&rbuf[..n]);
    }
    while let Some(n) = net.try_recv(Host::A, client, &mut rbuf).filter(|&n| n > 0) {
        b2a.deliver(&rbuf[..n]);
    }
    net.assert_timer_fidelity(Host::A, client);
    net.assert_timer_fidelity(Host::B, server);

    // A compliant runtime must never see the stack shed an action: the
    // queue is provably deep enough when drained after every event.
    if policy == DrainPolicy::Eager {
        assert_eq!(sheds(&net), 0, "actions shed under a compliant runtime (seed {seed})");
    }

    // Reaching the tail means the connection survived the activity phase;
    // anything that dies during a clean, eagerly-drained tail will show up
    // as survived && !completed — the stall signature callers assert on.
    RunOutcome { survived: true, completed: a2b.complete() && b2a.complete(), peak: peak(&net) }
}

/// Total actions shed by both hosts (only possible under a drain backlog).
fn sheds(net: &Net) -> u64 {
    net.host(Host::A).stats().actions_shed + net.host(Host::B).stats().actions_shed
}

/// Deeper of the two hosts' action-queue high-water marks.
fn peak(net: &Net) -> u16 {
    net.host(Host::A).stats().actions_peak.max(net.host(Host::B).stats().actions_peak)
}

#[test]
fn fuzz_clean_network_always_completes() {
    // No impairment: every run must complete (pure safety + liveness sanity).
    for seed in 0..40u64 {
        let model = NetModel { delay: Duration::from_millis(5), ..Default::default() };
        assert!(run_once(seed, model), "clean run {seed} did not complete");
    }
}

#[test]
fn fuzz_lossy_network_completes_after_clean_tail() {
    // Moderate loss + reordering + duplication during the activity phase.
    // The prefix property is enforced inside run_once on every delivery;
    // the clean tail must let every run finish.
    let mut completed = 0;
    for seed in 0..60u64 {
        let model = NetModel {
            delay: Duration::from_millis(8),
            loss_permille: 100,
            dup_permille: 80,
            jitter: Duration::from_millis(30),
            corrupt_permille: 30,
        };
        if run_once(seed, model) {
            completed += 1;
        }
    }
    // Every seed should complete once impairment stops; allow no failures.
    assert_eq!(completed, 60, "some lossy runs failed to converge after a clean tail");
}

#[test]
fn fuzz_high_loss_preserves_safety() {
    // Aggressive loss. Liveness within budget is not guaranteed here, but the
    // prefix/no-dup/no-reorder safety property (asserted in Stream::deliver)
    // and all internal invariants MUST hold regardless.
    for seed in 0..50u64 {
        let model = NetModel {
            delay: Duration::from_millis(10),
            loss_permille: 350,
            dup_permille: 150,
            jitter: Duration::from_millis(50),
            corrupt_permille: 80,
        };
        // We don't assert completion, only that nothing panics and safety
        // holds throughout (run_once asserts internally).
        let _ = run_once(seed, model);
    }
}

#[test]
fn fuzz_lazy_runtime_backlog_still_converges() {
    // The hostile-runtime lane: the harness skips 70% of its drain
    // opportunities (seed-driven), creating real A-POLL-1 backlogs — the
    // regime where the shed-timer bug lived. Three claims are enforced:
    //   1. safety holds regardless (prefix property, asserted per delivery);
    //   2. the timer boundary stays faithful at every forced quiescence
    //      (assert_timer_fidelity inside run_once_with);
    //   3. delivery still completes once impairment stops — "a backlog
    //      delays output, never loses it".
    let mut completed = 0;
    let mut survived = 0;
    let mut max_peak = 0u16;
    for seed in 0..40u64 {
        let model = NetModel {
            delay: Duration::from_millis(8),
            loss_permille: 60,
            dup_permille: 40,
            jitter: Duration::from_millis(20),
            corrupt_permille: 20,
        };
        let o = run_once_with(seed, model, DrainPolicy::Lazy { skip_permille: 500 }, 8);
        // THE anti-stall theorem of this lane: a connection that survived
        // the abuse converges once the runtime recovers. "Alive but never
        // completes" is a wedge — exactly what the shed-timer bug caused.
        assert!(
            !o.survived || o.completed,
            "seed {seed}: connection survived the backlog but never converged (stall)"
        );
        survived += o.survived as usize;
        completed += o.completed as usize;
        max_peak = max_peak.max(o.peak);
    }
    // Aborting under a brutal drain backlog is legitimate (the peer looks
    // dead — RFC 9293 §3.8.3 R2), so survival isn't guaranteed. Queue depth
    // is structurally shallow with ONE connection (events are edge-triggered,
    // timers diff-reconciled): deep backlogs need breadth — see the
    // multi-connection lane below. The shed path itself is regression-tested
    // at the unit level (stack::tests::timer_action_shed_on_full_queue_is_retried).
    assert!(survived > 0, "no lazy run survived — soften the abuse");
    println!("lazy lane: {survived} survived, {completed} completed, peak queue {max_peak}");
    assert_eq!(survived, completed, "every survivor must converge");
}

#[test]
fn fuzz_lazy_runtime_many_connections_deep_backlog() {
    // Queue pressure scales with connection count (sweep emits up to four
    // timer diffs per conn; each conn contributes events), so the deep-
    // backlog lane runs 6 concurrent transfers on Stack<8> hosts under a
    // drain-skipping runtime. Asserts, per seed: per-stream prefix safety
    // (in Stream::deliver), timer fidelity across all sockets at every
    // forced quiescence, and convergence of every surviving stream once the
    // runtime recovers.
    const N: usize = 6;
    let mut max_peak = 0u16;
    let mut converged = 0usize;
    let mut total_streams = 0usize;
    for seed in 100..120u64 {
        let model = NetModel {
            delay: Duration::from_millis(8),
            loss_permille: 40,
            dup_permille: 30,
            jitter: Duration::from_millis(15),
            corrupt_permille: 10,
        };
        let mut net = Net::new(model, seed);
        net.listen(Host::B, PORT);
        let ep = net.endpoint(Host::B, PORT);

        // Establish N pairs one at a time (eager) so client↔server pairing
        // is deterministic, then turn the abuse on.
        let mut pairs: Vec<(tcp_sans_io::SocketId, tcp_sans_io::SocketId)> = Vec::new();
        for i in 0..N {
            let c = net.connect(Host::A, ep);
            net.run(3000);
            let accepted: Vec<_> = net
                .events
                .iter()
                .filter_map(|cap| match cap.event {
                    tcp_sans_io::AppEvent::Connected { sock, via_listener: Some(_) }
                        if cap.host == Host::B =>
                    {
                        Some(sock)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(accepted.len(), i + 1, "seed {seed}: pair {i} did not establish");
            pairs.push((c, accepted[i]));
        }
        net.drain_policy = DrainPolicy::Lazy { skip_permille: 600 };

        let mut rng = Rng::new(seed ^ 0x5117_BEEF);
        let mut streams: Vec<Stream> = (0..N).map(|_| Stream::default()).collect();
        let mut rbuf = [0u8; 4096];
        for round in 0..250 {
            if round % 16 == 0 {
                for &(c, s) in &pairs {
                    net.assert_timer_fidelity(Host::A, c);
                    net.assert_timer_fidelity(Host::B, s);
                }
            }
            for (i, &(c, _)) in pairs.iter().enumerate() {
                if rng.below(100) < 60 {
                    let n = 1 + rng.below(1200) as usize;
                    let base = streams[i].sent.len();
                    let chunk: Vec<u8> =
                        (0..n).map(|k| ((base + k) ^ (i * 31)) as u8).collect();
                    if let Some(accepted) = net.try_send(Host::A, c, &chunk) {
                        streams[i].submit(&chunk[..accepted]);
                    }
                }
            }
            for _ in 0..1 + rng.below(3) {
                net.step();
            }
            for (i, &(_, s)) in pairs.iter().enumerate() {
                if rng.below(100) < 70 {
                    while let Some(n) =
                        net.try_recv(Host::B, s, &mut rbuf).filter(|&n| n > 0)
                    {
                        streams[i].deliver(&rbuf[..n]);
                    }
                }
            }
        }

        // Runtime recovers; network goes clean: every surviving stream must
        // converge — anything alive-but-incomplete is a stall.
        net.drain_policy = DrainPolicy::Eager;
        net.model = NetModel { delay: Duration::from_millis(5), ..Default::default() };
        net.pump();
        for _ in 0..50_000 {
            let progressed = net.step();
            let mut all_done = true;
            for (i, &(c, s)) in pairs.iter().enumerate() {
                while let Some(n) = net.try_recv(Host::B, s, &mut rbuf).filter(|&n| n > 0) {
                    streams[i].deliver(&rbuf[..n]);
                }
                if !streams[i].complete() && net.alive(Host::A, c) {
                    all_done = false;
                }
            }
            if all_done || !progressed {
                break;
            }
        }
        net.pump();
        for (i, &(c, s)) in pairs.iter().enumerate() {
            while let Some(n) = net.try_recv(Host::B, s, &mut rbuf).filter(|&n| n > 0) {
                streams[i].deliver(&rbuf[..n]);
            }
            net.assert_timer_fidelity(Host::A, c);
            net.assert_timer_fidelity(Host::B, s);
            total_streams += 1;
            if net.alive(Host::A, c) && net.alive(Host::B, s) {
                assert!(
                    streams[i].complete(),
                    "seed {seed} stream {i}: alive but never converged (stall): \
                     {} of {} bytes",
                    streams[i].received.len(),
                    streams[i].sent.len()
                );
                converged += 1;
            }
        }
        max_peak = max_peak.max(peak(&net));
    }
    println!("multi lane: {converged}/{total_streams} streams converged, peak queue {max_peak}");
    assert!(converged > 0, "no stream survived the multi-conn abuse");
    // Observed peak stays in single digits even under 60% skipped drains:
    // edge-triggered events + emit-path timer reconciliation keep the queue
    // near-empty by construction, which is WHY the 64-slot queue cannot
    // shed at this scale (eager lanes assert shed == 0; the shed-retry path
    // is unit-tested). If this assert ever fires, that design property
    // regressed and the queue sizing needs re-deriving.
    assert!(max_peak < 32, "action queue unexpectedly deep ({max_peak}) — sizing margin eroded");
}

#[test]
fn fuzz_is_deterministic() {
    // The same seed must reproduce identical observable outcomes.
    let model = NetModel {
        delay: Duration::from_millis(8),
        loss_permille: 120,
        dup_permille: 60,
        jitter: Duration::from_millis(20),
        corrupt_permille: 40,
    };
    let a = run_once(12345, model);
    let b = run_once(12345, model);
    assert_eq!(a, b, "same seed produced different completion outcomes");
}

#[test]
fn fuzz_v6_clean_completes() {
    for seed in 0..20u64 {
        let mut net = Net::new_v6(NetModel { delay: Duration::from_millis(5), ..Default::default() }, seed);
        net.listen(Host::B, PORT);
        let ep = net.endpoint(Host::B, PORT);
        let client = net.connect(Host::A, ep);
        net.run(2000);
        let server = net.accepted_socket(Host::B).expect("v6 connect").0;
        assert_eq!(net.state_a(client), Some(TcpState::Established));

        let payload: Vec<u8> = (0..6000u32).map(|i| (i * 5) as u8).collect();
        let mut offered = 0;
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        for _ in 0..5000 {
            if offered < payload.len() {
                offered += net.send(Host::A, client, &payload[offered..]);
            }
            if !net.step() && offered >= payload.len() {
                break;
            }
            let n = net.recv(Host::B, server, &mut buf);
            got.extend_from_slice(&buf[..n]);
        }
        net.run(5000);
        got.extend_from_slice(&net.recv_all(Host::B, server));
        assert_eq!(got, payload, "v6 seed {seed} stream intact");
    }
}
