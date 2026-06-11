# tcp-sans-io

A **verification-first, sans-I/O, deterministic** TCP/IPv4/IPv6 protocol core
in Rust 2024, built for aerospace and safety-critical systems while staying a
good citizen on the public Internet.

It is the implementation of [`PLAN.md`](PLAN.md). The design goal is not to
beat Linux on throughput; it is to be **correct, deterministic, analyzable,
and interoperable**, with performance in the middle-to-upper half of deployed
TCP stacks (Reno/NewReno + SACK + window scaling).

```
┌─────────────────────────────────────────────┐
│ Application  (your code)                      │
├─────────────────────────────────────────────┤
│ Stack<CONNS>   demux · listeners · timers     │  src/stack.rs
├──────────────┬────────────────┬──────────────┤
│ TCP          │ IPv4 / IPv6    │ ICMP / ICMPv6 │  src/tcp, src/ip, src/wire
│ (RFC 9293…)  │ reasm · PMTU   │ echo · errors │
├──────────────┴────────────────┴──────────────┤
│ Link-layer adapter  (your code: TUN, NIC, …)  │   ← boundary is whole IP
└─────────────────────────────────────────────┘     datagrams; no ARP/ND here
```

## What "sans-I/O" means here

The protocol core never touches a clock, socket, thread, allocator, or
entropy source. Everything crosses an explicit boundary:

```
            ┌──────────────────────────┐
  Events ──▶│                          │──▶ Actions
            │   deterministic core     │
  (datagram │  (State,Event)→          │   (Transmit, StartTimer,
   timer,   │     (State,Actions)      │    CancelTimer, RequestEntropy,
   entropy) │                          │    App notifications)
            └──────────────────────────┘
```

* **Time** is a logical `Instant` you pass into every call; the core only
  does arithmetic on it. Timers are virtual: the core emits
  `StartTimer{key, after}` / `CancelTimer{key}` and you feed back
  `Event::TimerExpired(key)`.
* **Packets** enter as `Event::DatagramReceived(&[u8])` (one whole IP
  datagram). The core hands you datagrams to send by writing them into your
  buffer from `poll_action`.
* **Entropy** enters as `Event::EntropyProvided([u8;16])` in response to an
  `Action::RequestEntropy` — used for RFC 6528 initial sequence numbers. The
  core has no RNG of its own.
* **Memory** is fixed-capacity. `#![no_std]`, `#![forbid(unsafe_code)]`, no
  heap inside the core. Worst-case footprint is a compile-time constant. The
  per-connection send/receive buffer sizes are const-generic parameters of
  the `Stack` (`Stack<CONNS, SND, RCV>`), so each deployment fixes its
  connection pool at compile time — the `conns` array *is* the pool.

Given the same events (including the same `now` values and the same entropy
seed), the core produces byte-identical output. That is the property the
whole design serves: **deterministic replay** for debugging, testing, and
model checking.

## Quick start

```rust
use tcp_sans_io::{Stack, Action, Event, AppEvent, IpAddr, SocketAddr};
use tcp_sans_io::config::Config;
use tcp_sans_io::time::Instant;

let cfg = Config::with_addr(IpAddr::v4(10, 0, 0, 1));
let mut stack: Stack<8> = Stack::new(cfg);   // 8 connection slots, all inline

// Your runtime owns real time and the wire. After every call into the stack,
// drain poll_action until it returns None and perform each action.
let mut now = Instant::from_millis(0);
let mut tx = [0u8; 1500];                    // at least one MTU
loop {
    match stack.poll_action(now, &mut tx) {
        Some(Action::RequestEntropy)       => stack.on_entropy(get_random_16()),
        Some(Action::Transmit { len })     => nic_send(&tx[..len]),
        Some(Action::StartTimer { key, after }) => schedule(key, now + after),
        Some(Action::CancelTimer { key })  => unschedule(key),
        Some(Action::App(ev))              => handle_app_event(ev),
        None => break,
    }
}

// Open a connection (after entropy has been provided):
let sock = stack.connect(now, SocketAddr::new(IpAddr::v4(93,184,216,34), 80))?;
// ... feed Event::DatagramReceived / TimerExpired as they happen, draining
//     poll_action after each, and use stack.send / recv / close.
```

The runtime contract is spelled out on `Stack` and in
[`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) §5 (`A-POLL-1`, `A-TIME-1`,
`A-ENTROPY-1`, `A-MTU-1`). A complete worked runtime — two stacks, a virtual
clock, and a lossy wire — lives in [`tests/harness/`](tests/harness/mod.rs);
it is the clearest example of how to embed the core.

## The runtime contract, honestly

The embedding API is deliberately **pull-based**: no callback traits to
implement, no scheduler to integrate with — you call in, then drain. The
price is a small set of obligations the compiler cannot enforce. Here is
each one, and what actually happens if you get it wrong:

| Obligation | What you must do | If you get it wrong |
|---|---|---|
| **Drain after every call** (`A-POLL-1`) | Loop `poll_action` to `None` after every event or API call. | **Self-healing.** `poll_action` is level-triggered: it re-derives pending work (segments, timer diffs) from connection state, so a missed drain *delays* output until the next drain — nothing is lost. The only fatal form is a runtime that stops calling it altogether: retransmissions and closes stall. |
| **Timer fidelity** (`A-POLL-1`) | Keep one deadline per `TimerKey`; `StartTimer` for a live key **replaces** it; after a `CancelTimer` or a replacing `StartTimer`, the old expiry must not be delivered. | A **late** fire is safe (retransmit happens late). A **stale** fire — an old expiry delivered after a re-arm/cancel, the classic race in threaded timer wheels — is trusted and acted on; worst case the `Wait` timer tears down TIME-WAIT early. A single-threaded map like the harness's (`insert` replaces, `remove` cancels) is correct by construction. |
| **Monotonic time** (`A-TIME-1`) | `now` never decreases across calls. Use a monotonic source (elapsed-since-start), never wall clock. | Backwards time corrupts RTT/RTO arithmetic and timer scheduling. There is no internal defense; this is the one assumption taken entirely on faith. |
| **Real entropy** (`A-ENTROPY-1`) | Answer `Action::RequestEntropy` with 16 bytes an off-path attacker can't predict (`/dev/urandom`, hardware TRNG). | *Forgetting* is loud: `connect` returns `Error::NeedEntropy`, inbound SYNs are dropped — nothing works until you answer. *Weak bytes* are silent and serious: ISNs become predictable (RFC 6528 falls apart). For deterministic replay, record and replay the seed. |
| **One-MTU buffer** (`A-MTU-1`) | `tx` passed to `poll_action` holds at least `config().mtu` bytes. | `debug_assert` in debug builds; an out-of-bounds panic when a large datagram is serialized in release. Size it once (`[u8; 2048]` covers the 1500 default) and forget it. |

What you *cannot* get wrong, by construction:

* **Stale handles.** `SocketId` carries a generation counter; a handle kept
  past `AppEvent::Closed` is rejected (`Error::NotFound`), never aliased to a
  recycled slot. Timers for recycled slots are dropped the same way.
* **Queue overflow.** Every internal queue is bounded and sheds rather than
  grows. Shed timer actions leave the emitted/desired diff in place and are
  re-issued by the next reconcile (regression-tested:
  `stack::tests::timer_action_shed_on_full_queue_is_retried`); shed app
  events are recoverable because **events are notifications, state is the
  truth** — `recv` answers `Readable`, `state_of` answers
  `Connected`/`Closed`. Shedding is observable as `StackStats::actions_shed`,
  and is reachable only under an `A-POLL-1` backlog — a compliant runtime
  should assert it stays 0.
* **Re-entrancy.** There are no callbacks, so there is no "called back into
  the stack while it was borrowed" failure mode, and no action can fire at a
  moment your runtime isn't ready for it — you choose when to pull, which is
  also where backpressure comes from: a full NIC ring just means you stop
  polling, and unsent segments remain state, not buffered copies.

## Worked example: download a web page

[`tools/tun-harness/src/bin/fetch.rs`](tools/tun-harness/src/bin/fetch.rs)
fetches `http://www.bing.com/` from the real Internet with the sans-I/O stack
doing **all** of the TCP — SYN, ISN randomization, window management,
retransmission, FIN. The kernel is demoted to plumbing: it routes raw IP
datagrams (TUN device + NAT) and resolves the host name.

```sh
sudo tools/tun-harness/fetch.sh                # GET http://www.bing.com/
sudo tools/tun-harness/fetch.sh example.com    # any other host
```

The embedding is the `TunRuntime` from the interop harness (wall clock, real
timers, `/dev/urandom`, TUN as the wire); the application on top is ~60 lines:

```rust
let stack: Stack<16> = Stack::new(Config::with_addr(IpAddr::V4(STACK_IP)));
let mut rt = TunRuntime::new(stack, tun)?;
rt.poll();                                   // answers Action::RequestEntropy

let sock = rt.connect(SocketAddr::new(IpAddr::V4(remote_ip), 80))?;
let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");

let (mut sent, mut response, mut established, mut peer_fin) = (0, Vec::new(), false, false);
loop {
    rt.poll();                               // timers → stack, datagrams → stack, actions → wire
    for ev in rt.take_events() {
        match ev {
            AppEvent::Connected { .. }       => established = true,
            AppEvent::PeerFinReceived { .. } => peer_fin = true,
            AppEvent::Closed { .. }          => return Ok(response), // done
            _ => {}
        }
    }
    if !established { continue; }
    if sent < request.len()                  // push as buffer space allows
        && let Ok(n) = rt.send(sock, &request.as_bytes()[sent..]) { sent += n; }
    while let Ok(n) = rt.recv(sock, &mut buf) {        // drain arrivals
        if n == 0 { break; }
        response.extend_from_slice(&buf[..n]);
    }
    if peer_fin { let _ = rt.close(sock); }  // server hit EOF: finish the close
}
```

The example lives in the harness crate rather than `examples/` because
opening a TUN device needs one `ioctl` (`unsafe`), and this package forbids
unsafe code package-wide — tests and examples included.

## Standards implemented

| RFC | Title | Status |
|-----|-------|--------|
| 9293 | TCP | ✅ core state machine, RFC 1122 host-requirements subset |
| 791 / 815 | IPv4 + reassembly | ✅ parse/emit, fragmentation, hole-algorithm reassembly |
| 8200 | IPv6 | ✅ fixed header, extension-header walk, fragment header |
| 1191 / 8201 | Path MTU discovery | ✅ DF probing, per-destination cache, family floors |
| 5681 / 6582 | Reno / NewReno congestion control | ✅ slow start, CA, fast retransmit/recovery |
| 6298 | RTO | ✅ Jacobson/Karels estimator, Karn, backoff |
| 6528 | Cryptographic ISN | ✅ SipHash-2-4 keyed by runtime entropy |
| 5961 | Blind-attack mitigation | ✅ RST/SYN challenge ACKs, rate limit, tighter ACK check |
| 2018 | SACK | ✅ receiver blocks + sender scoreboard (RFC 6675-style recovery) |
| 7323 §2 | Window scaling | ✅ negotiated both ways |
| 7323 §3 | TCP timestamps / PAWS | ❌ intentionally omitted (`D-WS-1`) |
| 9438 / 9430 / 8985 | CUBIC / BBR / RACK | ❌ deferred/rejected per PLAN.md (`D-CC-1`) |

Every row traces to code and tests in
[`docs/TRACEABILITY.md`](docs/TRACEABILITY.md). Deliberate scope decisions are
recorded there as `D-*` deviations.

## Testing & verification

The proof strategy has three layers (PLAN.md "Recommended Proof Strategy");
this is the honest current state:

* **Property-based / fuzz (realized).**
  [`tests/fuzz_network.rs`](tests/fuzz_network.rs) drives two real stacks
  through a deterministic, seed-driven network with loss, reordering,
  duplication and corruption. It asserts the **stream-prefix safety
  property** (received bytes are always an exact prefix of sent bytes) on
  *every* delivery, and **liveness** (all flows converge once impairment
  stops). Any failure reproduces from its seed alone.
  The harness also fuzzes the **runtime contract itself**: hostile-runtime
  lanes skip 50–70 % of their `poll_action` drains (`DrainPolicy::Lazy`),
  and assert that every connection surviving the backlog converges once the
  runtime recovers — "alive but never completes" (the wedge) fails the run.
  Three standing oracles run throughout: a **two-sided timer-fidelity
  check** (the harness's armed timers must exactly equal
  `Stack::timer_deadlines_of` at every quiescence — a lost `StartTimer` is
  a future stall, a phantom one is a leak), a **drain fuel bound**
  (`poll_action` must quiesce within a static budget — anti-livelock), and
  `actions_shed == 0` under compliant drains (the action queue is deep
  enough by construction; observed peak ≤ 3 of 64 even under abuse).
* **Scenario & security suites.**
  [`tests/scenarios.rs`](tests/scenarios.rs) and
  [`tests/security_and_edge.rs`](tests/security_and_edge.rs) cover the
  Definition-of-Done feature list: handshake, bulk transfer, all close paths,
  TIME-WAIT, retransmission under 30 % loss, SACK recovery, window scaling,
  zero-window persist, PMTUD, ICMP echo, fragment reassembly, RFC 5961
  blind-attack mitigation, ISN unpredictability, checksum rejection, and
  **pool exhaustion**: a SYN flood pins at most `CONNS` slots, excess SYNs
  are shed with zero amplification (no SYN-ACK, no RST), half-opens expire
  on the retry budget, and service recovers.
* **Internal invariants (executable).** `Connection::check_invariants`
  (S-INV-1..5) runs in debug builds after every input and every emitted
  segment; the receive buffer and SACK scoreboard self-check too.
* **Scripted-segment ("packetdrill-style") tests.**
  [`tests/scripted.rs`](tests/scripted.rs) drives a single stack with a script
  that plays the remote peer and the clock, injecting byte-exact segments and
  asserting byte-exact responses (flags, seq/ack, window, options) — the
  packetdrill model, adapted to a userspace sans-I/O stack. Covers the
  handshakes, exact ACK numbers, SACK on reorder, RTO retransmission, FIN, and
  the RFC 5961 challenge/exact-RST distinction.
* **On-the-wire interop with the real Linux kernel.**
  [`tools/tun-harness`](tools/tun-harness) drives the stack against the live
  kernel TCP stack over a TUN device: kernel→stack and stack→kernel bulk
  transfers (128 KiB each, with half-close). Run it with `sudo
  tools/tun-harness/run.sh`. This is what a production interop check looks
  like — and it already earned its keep by catching a real bug (data stranded
  on `CLOSE-WAIT → LAST-ACK`; now fixed and covered by
  `scenarios::half_close_then_bulk_send_drains_in_last_ack`).
* **Model checking (TLC).** [`formal/tcp_fsm.tla`](formal/tcp_fsm.tla) models
  the connection FSM; `formal/check.sh` runs TLC over the full state space
  with *no error* for the safety invariant and two liveness properties.
  [`formal/runtime_boundary.tla`](formal/runtime_boundary.tla) models the
  stack↔runtime **timer reconcile protocol** (desired/emitted/queue/armed):
  TLC proves the shipped retry-on-shed protocol keeps the runtime's view
  faithful and convergent over the full state space — and, as a negative
  test, `check.sh` asserts TLC still finds the 5-state stall counterexample
  for the pre-fix protocol (record-on-shed), so the model can't rot.
* **Theorem proving (Coq, `seq.rs` done).**
  [`formal/seq_arith.v`](formal/seq_arith.v) (49 theorems, zero
  axioms/admits, Coq 8.20) proves the sequence-number arithmetic everything
  else stands on. Each definition mirrors `src/tcp/seq.rs`
  formula-for-formula — the `(b - a) as i32 > 0` comparison trick is
  modeled as a two's-complement reinterpretation and **characterized by
  theorem** (lt ⟺ forward distance in `[1, 2³¹−1]`), not assumed. Headline
  results: order laws under the half-space precondition (with the exact
  2³¹-antipode anomaly stated, not hidden), the add/since round-trip
  algebra, and spec-equivalences — `in_window_spec` (the O(1) window test
  accepts exactly the RFC 9293 set) and `ack_acceptance` (`SND.UNA <
  SEG.ACK ≤ SND.NXT` accepts exactly the in-flight bytes). Run
  `formal/prove.sh`. Remaining: the §3 invariants and buffer index math
  (TRACEABILITY §7).

```sh
cargo test                       # unit + scenario + security + scripted + fuzz
cargo clippy --all-targets       # lint (clean)
cargo build --release            # panic=abort, LTO, codegen-units=1
cargo build --lib --target thumbv7em-none-eabihf   # proves no_std / bare-metal
cargo build --features std       # opt-in std (Error trait, TUN runtime)
( cd formal && ./check.sh )      # TLC model check (needs Java + tla2tools.jar)
( cd formal && ./prove.sh )      # Coq proofs for seq.rs (needs coqc)
sudo tools/tun-harness/run.sh    # live interop vs the Linux kernel (needs root)
sudo tools/tun-harness/fetch.sh  # worked example: fetch bing.com through the stack
```

## Cargo features

| Feature | Effect |
|---------|--------|
| *(default)* | pure `#![no_std]`, no allocator — the certifiable configuration |
| `alloc` | links `alloc` for heap conveniences; the core still never allocates per-packet |
| `std` | implies `alloc`; adds `std::error::Error for Error` and enables the TUN host runtime |

## Definition of Done — status

From PLAN.md, with honest annotations:

| Requirement | Status |
|-------------|--------|
| RFC 9293 / 5681 / 6298 / 6528 / 5961 / 2018 / 7323-WS compliant | ✅ implemented + tested (see matrix) |
| 100 % sans-I/O | ✅ no clock/socket/thread/alloc/entropy in core |
| Deterministic replay | ✅ pure `(State,Event)→(State,Actions)`; fuzzer is seed-reproducible |
| Virtualized timers | ✅ `StartTimer`/`CancelTimer` + `TimerExpired` |
| Virtualized entropy | ✅ `RequestEntropy` + `EntropyProvided` |
| Bounded memory | ✅ `#![no_std]`, fixed-capacity everywhere, compile-time footprint |
| Executable specification | ✅ the core *is* the executable spec; FSM also in TLA+ |
| Model-checked core state machine | ✅ TLC checks safety + liveness over the full state space (`formal/check.sh`) |
| Property-based fuzz suite | ✅ deterministic network fuzzer + packetdrill-style scripted segments |
| Interop vs Linux / FreeBSD / Windows | ⚠️ **Linux: ✅** (live-kernel TUN harness, bulk + half-close). FreeBSD/Windows pending (same harness, run on those hosts) |
| No wall-clock / OS primitives in protocol logic | ✅ enforced by `#![no_std]` + review |

The one remaining gap to a certifiable release candidate is interop coverage
against FreeBSD and Windows (the harness is host-agnostic; it just needs to be
run on those kernels) and finishing the Layer-2 theorem-proving effort
(`seq.rs` is proved in Coq; the connection invariants and buffer index math
remain). Linux interop, model checking, and the full test stack are done and
reproducible above.

## Design notes

* **No link layer.** The core's boundary is whole IP datagrams. ARP and IPv6
  Neighbor Discovery belong to the runtime's link-layer adapter (a TUN device
  needs neither). This keeps the verifiable surface to the transport/network
  layers.
* **Bounded out-of-order data.** The receive reassembly queue and SACK
  scoreboard are fixed-size; excess out-of-order data is dropped and the peer
  retransmits. Bounded memory is preferred over completeness — a deliberate,
  documented trade (`config.rs`).
* **Fixed connection table with generations.** `SocketId` carries a
  generation counter so a stale handle to a recycled slot is rejected, not
  silently aliased.

## License

MIT OR Apache-2.0.
