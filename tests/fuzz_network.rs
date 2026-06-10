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

use harness::{Host, Net, NetModel, Rng, TcpState};
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

/// One fuzz run. Returns true if the transfer completed (liveness); the
/// prefix property (safety) is asserted internally throughout.
fn run_once(seed: u64, model: NetModel) -> bool {
    let mut net = Net::new(model, seed);
    net.listen(Host::B, PORT);
    let ep = net.endpoint(Host::B, PORT);
    let client = net.connect(Host::A, ep);

    // Bring up the connection (may take retransmissions under loss).
    net.run(3000);
    let Some(server) = net.accepted_socket(Host::B).map(|x| x.0) else {
        // Under extreme loss the handshake may not finish within budget;
        // that is acceptable for liveness (no impairment-free tail yet).
        return false;
    };

    let mut rng = Rng::new(seed ^ 0xA5A5_A5A5);
    let mut a2b = Stream::default();
    let mut b2a = Stream::default();
    let mut rbuf = [0u8; 4096];

    // Randomized activity phase. If a connection is torn down (which is
    // legitimate under heavy loss once the retransmission limit is hit),
    // we stop submitting and the run simply does not "complete".
    let mut torn_down = false;
    for _round in 0..400 {
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
        // not expected once a connection was reset by the retry limit.
        return false;
    }

    // Clean tail: stop all impairment and drain to completion (liveness).
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
    while let Some(n) = net.try_recv(Host::B, server, &mut rbuf).filter(|&n| n > 0) {
        a2b.deliver(&rbuf[..n]);
    }
    while let Some(n) = net.try_recv(Host::A, client, &mut rbuf).filter(|&n| n > 0) {
        b2a.deliver(&rbuf[..n]);
    }

    a2b.complete() && b2a.complete()
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
