# Traceability Matrix

This document is the "single source of truth" required by PLAN.md §4. Every
normative requirement the stack implements traces from an RFC clause to the
code that realizes it and the test that exercises it. Deliberate deviations,
internal invariants, and environmental assumptions are recorded with stable
identifiers (`D-*`, `S-INV-*`, `A-*`, `I-*`, `S-*`) that are cited in source
comments.

The identifiers are referenced from code via plain comments (e.g.
`// S-INV-1`); grep for an identifier to find its enforcement points.

---

## 1. Requirements → Code → Test

### RFC 9293 — TCP

| Req | Clause | Code | Test |
|-----|--------|------|------|
| R-TCP-1 | §3.5 three-way handshake | `tcp/conn/input.rs` `on_segment_syn_sent`, `on_segment_sync` (SYN-RECEIVED→ESTABLISHED); `tcp/conn/output.rs` `plan_syn` | `scenarios::three_way_handshake`, `fuzz_*` |
| R-TCP-2 | §3.5 simultaneous open | `input.rs` `on_segment_syn_sent` (SYN without ACK → SYN-RECEIVED) | covered by state machine; `fuzz_*` exercises races |
| R-TCP-3 | §3.6 graceful close, all FIN paths | `conn/mod.rs` `close`; `input.rs` `process_new_ack` (FIN-ACK transitions), `try_consume_fin` | `scenarios::graceful_close_four_way`, `simultaneous_close` |
| R-TCP-4 | §3.4 sequence arithmetic mod 2³² | `tcp/seq.rs` | `tcp::seq::tests::*` (incl. wraparound) |
| R-TCP-5 | §3.10.7.4 segment acceptability test | `input.rs` `seq_acceptable` | `tcp::*`, `security_and_edge::*` |
| R-TCP-6 | §3.8.6.1 zero-window probing (persist) | `conn/mod.rs` `arm_persist`, `on_timer(Persist)`; `output.rs` `plan_probe` | `security_and_edge::zero_window_then_reopen_via_persist` |
| R-TCP-7 | §3.8.6.2 silly-window avoidance (send: Nagle; recv: window update threshold) | `output.rs` `plan_data` (Nagle), `conn/mod.rs` `recv` (recv-SWS) | `scenarios::bulk_transfer_*` |
| R-TCP-8 | §3.4.1 TIME-WAIT 2·MSL | `conn/mod.rs` `enter_time_wait`, `on_timer(Wait)` | `security_and_edge::time_wait_absorbs_late_duplicate_and_expires` |
| R-TCP-9 | §3.1 checksum (with pseudo-header) verified on ingress, computed on egress | `wire/tcp.rs` `parse`/`emit`, `wire/checksum.rs` | `wire::tcp::tests::checksum_detects_corruption`, `security_and_edge::checksum_is_verified_on_ingress` |
| R-TCP-10 | §3.7.1 MSS option | `wire/tcp.rs` options; `conn/mod.rs` `apply_syn_options`, `eff_send_mss` | `wire::tcp::tests::emit_parse_round_trip` |
| R-TCP-11 | §3.10.7.1 RST generation to CLOSED port | `stack.rs` `deliver_tcp` (no-match branch) | `scenarios::connection_refused_to_closed_port` |

### RFC 1122 — Host Requirements

| Req | Clause | Code | Test |
|-----|--------|------|------|
| R-1122-1 | §4.2.3.2 delayed ACK < 500 ms, ACK every 2nd full segment | `conn/mod.rs` `ack_delayed`, `input.rs` `process_text` (`segs_since_ack`) | `scenarios::bulk_transfer_*` (ACK cadence drives flow) |
| R-1122-2 | §4.2.3.9 ICMP hard errors abort only unsynchronized; advisory otherwise | `conn/mod.rs` `on_icmp_unreachable`; `stack.rs` `icmp_error_for` | `security_and_edge` (ICMP paths), see also S-ICMP-1 |
| R-1122-3 | §3.2.1.1 silently discard malformed datagrams | `wire/*` parsers return `WireError`, `stack.rs` drops + counts | `wire::*::tests::rejects_malformed`, `corruption_is_rejected_by_checksum` |
| R-1122-4 | §3.2.2.6 answer ICMP echo | `stack.rs` `queue_echo`, `emit_echo` | `security_and_edge::icmp_echo_request_is_answered` |
| R-1122-5 | §3.3.4 host does not forward | `stack.rs` `on_ipv4`/`on_ipv6` (`is_local` gate) | `Stack` drops non-local (stat `rx_not_local`) |

### RFC 791 / RFC 815 / RFC 8200 — IP

| Req | Clause | Code | Test |
|-----|--------|------|------|
| R-IP-1 | RFC 791 §3.2 reassembly (RFC 815 hole algorithm) | `ip/reasm.rs` | `ip::reasm::tests::*` (in-order, reverse, overlap, timeout, exhaustion) |
| R-IP-2 | RFC 791 §3.2 egress fragmentation | `ip/frag.rs` | `ip::frag::tests::splits_align_and_reassemble` |
| R-IP-3 | RFC 791 IPv4 header parse/emit, TTL, checksum | `wire/ipv4.rs` | `wire::ipv4::tests::*` |
| R-IP-4 | RFC 8200 IPv6 header + extension-header walk + fragment header | `wire/ipv6.rs` | `wire::ipv6::tests::*` |
| R-IP-5 | RFC 1191 / RFC 8201 path-MTU discovery (DF set; cache; floors) | `ip/pmtu.rs`; `stack.rs` `emit_tcp_ip` (DF), `icmp_error_for` | `ip::pmtu::tests::*` |

### RFC 5681 / RFC 6582 — Congestion Control

| Req | Clause | Code | Test |
|-----|--------|------|------|
| R-CC-1 | §3.1 slow start (IW per RFC 3390) | `tcp/cc.rs` `initial_window`, `on_new_ack` | `tcp::cc::tests::initial_window_rfc3390`, `slow_start_doubles_per_rtt` |
| R-CC-2 | §3.1 congestion avoidance | `cc.rs` `on_new_ack` (CA branch) | `tcp::cc::tests::congestion_avoidance_is_linear` |
| R-CC-3 | §3.2 fast retransmit / fast recovery (NewReno, RFC 6582) | `cc.rs` `enter_fast_recovery`, `inflate`, `on_partial_ack`, `exit_recovery`; `input.rs` `on_dupack` | `tcp::cc::tests::newreno_recovery_window_accounting`; `scenarios::reordering_and_duplication_*` |
| R-CC-4 | §3.1 RTO collapse | `cc.rs` `on_rto`; `conn/mod.rs` `on_rexmit_timer` | `tcp::cc::tests::rto_collapses_window`; `scenarios::retransmission_recovers_*` |

### RFC 6298 — RTO

| Req | Clause | Code | Test |
|-----|--------|------|------|
| R-RTO-1 | §2 SRTT/RTTVAR estimator | `tcp/rtt.rs` `on_sample` | `tcp::rtt::tests::first_sample_initializes`, `smooths_and_respects_min` |
| R-RTO-2 | §2.4/§2.5 RTO clamps [1 s, 60 s] | `rtt.rs` `on_sample` clamp; `config.rs` defaults | `tcp::rtt::tests::smooths_and_respects_min` |
| R-RTO-3 | §3 Karn's algorithm (no sample on retransmit) | `conn/mod.rs`/`input.rs`/`output.rs` set `rtt_sample = None` on every retransmit | exercised by all lossy `fuzz_*` |
| R-RTO-4 | §5.5 exponential backoff | `rtt.rs` `backoff` | `tcp::rtt::tests::backoff_doubles_and_caps` |

### RFC 6528 — ISN

| Req | Clause | Code | Test |
|-----|--------|------|------|
| R-ISN-1 | §3 `ISN = M + F(4-tuple, secret)`, F = SipHash-2-4 | `tcp/isn.rs` | `tcp::isn::tests::siphash24_reference_vectors`, `isn_depends_on_tuple_and_time` |
| R-ISN-2 | secret seeded from runtime entropy only | `isn.rs` `seed`; `stack.rs` `on_entropy`, `Action::RequestEntropy` | `security_and_edge::isns_are_unpredictable_across_connections` |

### RFC 5961 — Blind-attack Mitigation

| Req | Clause | Code | Test |
|-----|--------|------|------|
| R-5961-1 | §3.2 in-window-but-inexact RST → challenge ACK | `input.rs` `on_segment_sync` (RST step) | `security_and_edge::in_window_rst_triggers_challenge_then_legit_rst_closes` |
| R-5961-2 | §3.2 out-of-window RST dropped | `input.rs` step 1 + RST handling | `security_and_edge::blind_rst_outside_window_is_ignored` |
| R-5961-3 | §4.2 in-window SYN → challenge ACK | `input.rs` `on_segment_sync` (SYN step) | `security_and_edge::blind_syn_in_window_is_challenged_not_accepted` |
| R-5961-4 | §5.2 stricter ACK acceptability | `input.rs` `on_segment_sync` (ACK window test using `snd_max_wnd`) | `fuzz_*`, `security_and_edge::*` |
| R-5961-5 | §10 challenge-ACK rate limit | `stack.rs` `take_challenge_token` | `security_and_edge::challenge_ack_rate_limited` |

### RFC 2018 — SACK

| Req | Clause | Code | Test |
|-----|--------|------|------|
| R-SACK-1 | §2 SACK-permitted negotiation | `conn/mod.rs` `apply_syn_options`; `output.rs` `plan_syn` | `wire::tcp::tests::emit_parse_round_trip` |
| R-SACK-2 | §3 SACK option emission (receiver) | `recvbuf.rs` `sack_ranges`; `output.rs` `recv_sack_blocks` | `tcp::recvbuf::tests::out_of_order_merge_and_sack` |
| R-SACK-3 | §4–5 sender scoreboard, hole retransmission (RFC 6675-style) | `tcp/sack.rs`; `output.rs` `plan_sack_rexmit` | `tcp::sack::tests::*`; `scenarios::reordering_and_duplication_*` |
| R-SACK-4 | §8 reneging tolerance (clear on RTO) | `conn/mod.rs` `on_rexmit_timer` (`scoreboard.clear`) | `fuzz_high_loss_preserves_safety` |

### RFC 7323 — Window Scaling

| Req | Clause | Code | Test |
|-----|--------|------|------|
| R-WS-1 | §2.2 window-scale option, both-sides negotiation | `conn/mod.rs` `apply_syn_options` (`wscale_on`); `output.rs` `plan_syn` | `scenarios::window_scaling_enables_large_in_flight_window` |
| R-WS-2 | §2.2 window field in SYN never scaled | `input.rs` `on_segment_syn_sent`/`server` (raw `h.window`); `output.rs` `plan_syn` | `scenarios::window_scaling_*` |
| R-WS-3 | §2.3 scale shift capped at 14 | `wire/tcp.rs` option parse; `conn/mod.rs` invariant | `tcp::conn` invariant `S-INV-5` |

> Timestamps (RFC 7323 §3) are intentionally **not** implemented (PLAN.md
> Phase 3). See `D-WS-1`.

---

## 2. Deliberate Deviations (`D-*`)

Each deviation is a conscious scope decision from PLAN.md, not an oversight.

- **D-IPV6-1** — IPv6 hop-by-hop / routing / destination-options extension
  headers are length-validated and skipped without acting on the per-option
  action bits (RFC 8200 §4.2). Rationale: this is a host, not a router, and
  it requests no options; unknown options in received traffic are ignored
  rather than triggering Parameter-Problem messages. `wire/ipv6.rs`.
- **D-TCP-1** — RFC 9293 §3.10.7 step 3 (security/compartment) is vacuous: no
  IPSO/CIPSO labeling. `input.rs`.
- **D-TCP-2** — The URG flag / urgent pointer (step 6) is accepted but never
  acted upon and never sent, per RFC 6093's recommendation against urgent
  data. `input.rs`, `wire/tcp.rs`.
- **D-TCP-3** — Data carried on a SYN or SYN-ACK is not queued; the peer
  retransmits it after the handshake. (TCP Fast Open, RFC 7413, is out of
  scope.) `input.rs`.
- **D-ICMP-1** — The stack does not generate ICMP protocol-unreachable for
  unknown upper-layer protocols; it silently drops them. `stack.rs`
  `deliver`.
- **D-WS-1** — RFC 7323 timestamps (and thus PAWS) are omitted. Window
  scaling is implemented; timestamps add state and proof burden for less
  value (PLAN.md). Consequence: no protection against wrapped sequence
  numbers on >1 Gbps long-fat networks — outside this stack's target regime.
- **D-CC-1** — Congestion control is Reno/NewReno only. CUBIC, BBR, RACK and
  TLP are explicitly rejected/deferred (PLAN.md). ECN is not implemented.
- **D-SYN-1** — No SYN-cookie fallback: when the connection table is full a
  SYN is dropped (the peer retries). Bounded memory is preferred over
  accepting unbounded half-open state. `stack.rs` `accept_syn`.

---

## 3. Safety Invariants (`S-INV-*`)

Enforced by `Connection::check_invariants` (run after every input and every
emitted segment in debug builds) and by `RecvBuffer`/`SackScoreboard`
internal `debug_assert!`s. These are the executable form of PLAN.md's
"Formal Verification Targets → Safety".

- **S-INV-1** — `SND.UNA ≤ SND.NXT` within a half sequence-space (never
  transmit sequence numbers ahead of what has been produced).
- **S-INV-2** — Bytes between `SND.UNA` and `SND.NXT` are backed by buffered
  data plus accounted control units (never acknowledge or retransmit data
  that does not exist).
- **S-INV-3** — The SACK scoreboard's highest block never exceeds `SND.NXT`
  (never claim to have sent what we have not).
- **S-INV-4** — The NewReno/SACK recovery point never exceeds `SND.NXT`.
- **S-INV-5** — Negotiated window scales are ≤ 14 (RFC 7323 §2.3).
- **S-INV-RECV** — Receive out-of-order ranges stay sorted, disjoint,
  non-adjacent, above `RCV.NXT`, and within the buffer (`recvbuf.rs`).

The end-to-end **stream-prefix property** (received bytes are always an exact
prefix of sent bytes — never reordered, duplicated into the stream, or
invented) is asserted continuously by the fuzz harness
(`fuzz_network.rs::Stream::deliver`) across loss, reordering, duplication and
corruption. This is the observable consequence of S-INV-1..4 plus correct
reassembly.

---

## 4. Liveness Properties

PLAN.md "Liveness": *eventually retransmit lost data, establish, and close,
under RFC assumptions.* Demonstrated (not proven) by:

- `scenarios::retransmission_recovers_from_total_loss_burst` (30 % loss).
- `fuzz_lossy_network_completes_after_clean_tail` — every seed converges once
  impairment stops.
- Bounded-retry termination: `config.max_syn_retries` / `max_data_retries`
  guarantee a connection either makes progress or is torn down with
  `CloseReason::TimedOut` (no infinite hang). The single intentional
  exception is zero-window persist, which probes indefinitely per RFC 1122
  §4.2.2.17 (`R-TCP-6`).

---

## 5. Environmental Assumptions (`A-*`)

The deterministic-core guarantees hold **only** if the runtime honors:

- **A-TIME-1** — `now` is monotone non-decreasing across all `Stack` calls
  (`time.rs`). Logical time never moves backward.
- **A-ENTROPY-1** — The 16 bytes supplied to `EntropyProvided` are
  unpredictable to off-path attackers (RFC 6528 §3 secret-key assumption).
  Determinism of *replay* uses a recorded seed; security uses a real one.
- **A-POLL-1** — After every event/API call the runtime drains
  `poll_action` until `None`, transmitting datagrams and arming/cancelling
  timers exactly as instructed. Timer identity is per `TimerKey`; re-arming
  replaces, and after a `CancelTimer` or replacing `StartTimer` the
  superseded expiry must not be delivered (`TimerExpired` is trusted; a
  stale fire is acted on as real). Drain *latency* is forgiving by design:
  `poll_action` re-derives pending segments from connection state and timer
  actions from the emitted/desired reconcile (which re-issues diffs shed by
  a full action queue), so a delayed drain delays output rather than losing
  it. A runtime that stops draining altogether stalls the protocol.
- **A-MTU-1** — The buffer passed to `poll_action` is at least one MTU.

### 5.1 Liveness & termination mechanization (`L-*`)

How "the stack does not stall, loop, or exhaust" is checked rather than
believed:

- **L-BOUND-1 (timer boundary, model-checked).**
  `formal/runtime_boundary.tla` models the reconcile protocol
  (desired/emitted/queue/armed). TLC verifies `QuiescentFaithful` (when the
  stack believes it is reconciled and the queue is drained, the runtime's
  armed timer equals the desired deadline) and `Converges` (`<>[](armed =
  desired)`) over the full state space; the pre-fix record-on-shed variant
  is kept as a negative test that must still yield the stall
  counterexample (`formal/check.sh`).
- **L-ORACLE-1 (timer boundary, executed).** The harness's
  `assert_timer_fidelity` compares its armed timers against
  `Stack::timer_deadlines_of` at every forced quiescence across the fuzz
  corpus, including hostile-runtime lanes that skip 50–70 % of drains
  (`DrainPolicy::Lazy`). Catches lost, phantom, and mis-keyed timer
  actions (e.g. reap-order generation bugs).
- **L-FUEL-1 (drain termination, executed).** Every harness drain asserts
  `poll_action` quiesces within `DRAIN_FUEL` actions; a violation means
  the stack yields work forever (livelock, e.g. an ACK-generation loop).
- **L-WEDGE-1 (no silent stall, executed).** Hostile-runtime fuzz lanes
  assert every connection that survives a drain backlog converges once the
  runtime recovers; aborting under abuse (R2, RFC 9293 §3.8.3) is
  legitimate, silence is not.
- **L-TERM-1 (loop termination, audited).** Every `loop`/`while` in the
  core has a strictly decreasing measure or static bound: the TCP options
  walk consumes ≥ 1 byte per iteration (`len < 2` rejected,
  `wire/tcp.rs::parse_options`); the IPv6 extension-header walk is bounded
  by `MAX_EXT_HEADERS`; checksum folding is bounded by carry width; all
  other iteration is over fixed-capacity arrays.
- **L-POOL-1 (resource exhaustion, executed).**
  `security_and_edge::syn_flood_fills_pool_sheds_silently_and_recovers`:
  a SYN flood pins at most `CONNS` slots, sheds the excess with zero
  amplification, expires half-opens on the SYN-ACK retry budget, and
  recovers. All queues are bounded and shed rather than grow
  (`StackStats::{actions_shed, actions_peak}` make this observable).
- **L-OOO-1 (receive path never wedges, executed).**
  `fuzz_heavy_reorder_never_wedges_receive_path` drives heavy
  jitter-induced reordering across 40 seeds and asserts every survivor
  converges in the clean tail — a connection that lives but never delivers
  is the DEF-C2 livelock signature.
- **L-FIN-1 (single-FIN oracle, executed).** Every fuzz run asserts
  `peer_fin_count ≤ 1` per socket (DEF-M1).

---

## 6. Security-relevant behaviors (`S-*`)

- **S-PMTU-1** — Path-MTU estimates only ever *decrease* on ICMP signal and
  recover by aging out, clamped to family floors (576 v4 / 1280 v6). A forged
  Packet-Too-Big can at worst reduce efficiency, never wedge a path.
  `ip/pmtu.rs`.
- **S-ICMP-1** — ICMP errors are accepted only if the quoted sequence number
  could currently be in flight (RFC 5927 §4), limiting blind ICMP attacks.
  `conn/mod.rs` `icmp_quote_plausible`; `stack.rs` `icmp_error_for`.
- **I-REASM-2** — Any *conflicting* fragment overlap drops the whole
  datagram (mandatory for IPv6 per RFC 5722; applied to IPv4 too). Exact
  duplicates are tolerated. `ip/reasm.rs`.
- **S-CHALLENGE-1** — The RFC 5961 §10 challenge-ACK budget is keyed-hash
  jittered per second in `[cap/2, cap]`, and SYN takes the challenge path
  *regardless* of sequence number (RFC 5961 §4.2). A fixed global cap is the
  CVE-2016-5696 side channel. `stack.rs` `take_challenge_token`, `input.rs`
  `on_segment_sync`. Tested by
  `security_and_edge::challenge_ack_budget_is_jittered_per_second` and
  `::syn_consumes_challenge_token_regardless_of_seq`.
- **S-MARTIAN-1** — Datagrams whose source is multicast, broadcast,
  unspecified, loopback-from-wire, or `src == dst` are silently dropped
  before any reply path (RFC 1122 §4.2.3.10). The stack cannot be used as a
  reflector toward such addresses. `types.rs` `is_unicast_source`; `stack.rs`
  `deliver_tcp`/`queue_echo`. Tested by
  `security_and_edge::martian_source_addresses_are_dropped`.
- **S-PORT-1** — Ephemeral source ports are RFC 6056 Algorithm-5
  double-hashed (SipHash-keyed), restoring ~14 bits of 4-tuple entropy
  against blind injection. `stack.rs` `alloc_ephemeral`. Tested by
  `security_and_edge::ephemeral_ports_are_not_sequential`.
- **S-IPID-1** — The IPv4 identification field is keyed-hashed, denying the
  idle-scan / cross-peer traffic-volume side channel of a global counter
  (RFC 7739). `stack.rs` `next_ident`.
- **S-GEN-1** — `SocketId` and `TimerKey::Reasm` carry generation counters
  (32-bit / 8-bit) so a stale handle or stale timer for a recycled slot is
  rejected, never aliased. `types.rs`, `ip/reasm.rs`.
- **S-TIMEWAIT-1** — RST is ignored in TIME-WAIT (RFC 1337). `input.rs`
  `on_segment_sync`. Tested by `security_and_edge::time_wait_ignores_rst`.
- **S-ISN-DEBUG** — `Debug` for the SipHash key is redacted. `tcp/isn.rs`.

---

## 7. Formal-methods status (honest)

PLAN.md proposes a three-layer proof strategy. Current state:

| Layer | Tool | Status |
|-------|------|--------|
| 1 — model checking | TLA+ / TLC | **Checked.** `formal/tcp_fsm.tla` models the connection FSM and sequence-space bookkeeping. TLC (`formal/check.sh`) explores the full state space (1,388 distinct states at `MaxSeq = 6`) and reports *no error* for the `Safety` invariant (S-INV-1/2 + type/consistency) and the liveness properties `ClosingTerminates` (TIME-WAIT ⇝ CLOSED) and `ClosedIsForever`. Not yet modeled: retransmission/timers, RFC 5961, SACK, windows. |
| 2 — theorem proving | Coq | **Started — `seq.rs` proved.** `formal/seq_arith.v` (Coq 8.20, 49 Qed, zero axioms/admits; run `formal/prove.sh`) mirrors every `seq.rs` definition formula-for-formula — including the `(b−a) as i32 > 0` comparison, modeled as two's-complement reinterpretation and *characterized* (`ltb_charact`/`leb_charact`: lt ⟺ forward distance ∈ [1, 2³¹−1]; le ⟺ ≤ 2³¹, antipode included). Proved on top: irreflexivity, global asymmetry/totality, antisymmetry & transitivity under the half-space precondition (with the 2³¹-antipode anomaly stated honestly in `le_antisym_cases`), the add/sub/since round-trip algebra, the triangle identity for distances, `in_window_spec` (the O(1) window test equals its RFC 9293 set definition), and `ack_acceptance` (the `una.lt(ack) && ack.le(nxt)` check accepts exactly SND.UNA+1 ..= SND.NXT under S-INV-1). The `seq.rs` unit tests are replayed as computed `Example`s. **Remaining:** port the §3 invariants and the buffer index arithmetic (`sendbuf`/`recvbuf`). |
| 3 — property-based testing | proptest/libFuzzer | **Realized** as the deterministic seed-driven fuzzer (`fuzz_network.rs`), the packetdrill-style scripted-segment suite (`tests/scripted.rs`), and the per-module unit tests. A `cargo-fuzz` libFuzzer target is a drop-in next step (the wire parsers are pure functions over `&[u8]`). |
| (cross-check) — live interop | TUN vs Linux kernel | **Realized** in `tools/tun-harness`: the stack exchanges bulk data (incl. half-close) with the real Linux TCP stack over a TUN device. Host-agnostic; FreeBSD/Windows pending. |

Reproduce the TLC run:

```sh
cd formal && TLA_TOOLS=/path/to/tla2tools.jar ./check.sh
# → "Model checking completed. No error has been found."
```

The model is intentionally co-maintained with the code: each TLA+ action
mirrors a transition in `tcp/conn/{input,output}.rs`. During development TLC
caught an incorrect type bound in the model itself (an `SND.UNA` range that
excluded the post-FIN value `MaxSeq+1`) — the kind of off-by-one the
model-checking layer exists to surface.

---

## 8. Defect provenance (what each verification layer caught)

A record of bugs surfaced by verification, and which layer found them — this
is the evidence that the layers are pulling their weight, and it guides where
to add coverage.

- **DEF-1 — data stranded on `CLOSE-WAIT → LAST-ACK`.** When a peer in
  CLOSE-WAIT closed with send-buffer bytes still untransmitted, the output
  planner (`tcp/conn/output.rs::plan_data`) did not list `LAST-ACK` among the
  data-sending states, so the queued tail (and the FIN behind it) never went
  out; the connection hung until the peer gave up. **Found by:** the live
  Linux-kernel interop harness (`tools/tun-harness`, scenario 1, a half-duplex
  echo) — *not* by the in-memory suites, whose scenarios never had unflushed
  send data at that exact transition. **Fix:** add `LAST-ACK` to `plan_data`'s
  state set (RFC 9293 §3.10.4). **Regression test:**
  `scenarios::half_close_then_bulk_send_drains_in_last_ack` (now reproduces it
  in-memory, no root required).
- **DEF-C1 — CVE-2016-5696 challenge-ACK side channel.** A single global
  `u8` budget refilled to a fixed constant on a fixed boundary let an
  off-path attacker with one connection of their own count returned
  challenge ACKs and binary-search a victim connection's `RCV.NXT`. Made
  worse by SYN-after-seq-check (DEF-M10). **Found by:** adversarial code
  review (3 of 13 lenses converged on it). **Fix:** keyed-hash jitter the
  per-second cap; hoist the SYN check above seq-acceptability. **Tests:**
  `security_and_edge::challenge_ack_budget_is_jittered_per_second`,
  `::syn_consumes_challenge_token_regardless_of_seq`.
- **DEF-C2 — receive-path livelock at OOO budget.** With `MAX_OOO_RANGES`
  disjoint far-offset ranges stored, an *in-order* segment that did not
  reach the first range overflowed the N-slot merge scratch *before* the
  absorption check, was refused (`stored: false`), `RCV.NXT` froze, and the
  peer retransmitted forever — 8 in-window packets, permanent. **Found by:**
  adversarial code review of `recvbuf.rs`. **Fix:** N+1 merge scratch;
  enforce the budget *after* absorption; evict the furthest range, never the
  head. **Tests:** `recvbuf::tests::in_order_data_never_refused_when_ooo_budget_full`,
  `security_and_edge::ooo_budget_saturation_cannot_wedge_receive_path`;
  fuzz lane `fuzz_heavy_reorder_never_wedges_receive_path`.
- **DEF-C3 — SYN unit re-counted after sequence-space wrap.** "Is the SYN
  outstanding?" was tested positionally (`iss.since(snd_una) < span`). After
  ~4 GiB of transfer `snd_una` wraps past `iss`, the SYN was re-counted,
  `data_sent()` under-read by 1, and every subsequent byte was emitted one
  position early — a silent 1-byte frameshift of the application stream.
  **Found by:** adversarial code review of the send path. **Fix:** explicit
  `syn_acked: bool`. **Test:** `conn::tests::syn_unit_is_not_recounted_after_seq_wrap`.
- **DEF-C4 — zero-window probe accepted by peer wedged both directions.**
  The probe sent one byte at `SND.NXT` *without* advancing `SND.NXT`. If the
  peer's window opened in flight and accepted the byte, its ACK of
  `SND.NXT+1` was rejected at `ack > SND.NXT` *before* the window update —
  `snd_wnd` stayed 0, and every subsequent peer segment carried the same
  rejected ACK, wedging the receive path too. **Fix:** advance `SND.NXT` on
  the first probe; persist (not Rexmit) drives retransmission so an alive
  zero-window peer is not aborted. **Test:**
  `conn::tests::zero_window_probe_ack_is_accepted`.
- **DEF-H1 — silent zero-window peer pinned a slot forever.** Persist had
  no abort path (RFC 1122 §4.2.2.17 read strictly). A peer that completed
  the handshake, advertised window 0, and went silent held its slot
  indefinitely — `CONNS` such peers exhaust the listener. **Fix:**
  `cfg.max_persist_retries`; an *acknowledging* peer resets the count. **Test:**
  `security_and_edge::silent_zero_window_peer_is_eventually_aborted`.
- **DEF-H2 — TIME-WAIT assassination (RFC 1337).** Exact-seq RST was
  honored in TIME-WAIT; a rebooted peer's reflexive RST destroyed the 2·MSL
  quarantine. **Fix:** ignore RST in TIME-WAIT. **Test:**
  `security_and_edge::time_wait_ignores_rst`.
- **DEF-M1/M2 — FIN re-consumption / `rcv_nxt` overshoot.** A forged FIN at
  the post-FIN `RCV.NXT` was re-recorded and re-consumed (drifting `RCV.NXT`,
  duplicate `PeerFin`); injected data past a recorded out-of-order FIN could
  step `RCV.NXT` past it so the FIN was never consumed. **Fix:** gate FIN
  recording/consumption on pre-FIN states; clamp `process_text` to
  `peer_fin`. **Test:** `security_and_edge::fin_is_consumed_at_most_once`;
  fuzz oracle `peer_fin_count ≤ 1`.
- **DEF-M6 — 4 KiB call-stack local on the reassembly→deliver path.** The
  reassembled payload was copied into a `[u8; REASM_BUF_SIZE]` local
  beneath the deep `deliver → on_segment` chain — thread-stack overflow on
  ≤ 8 KiB MCU stacks from a single attacker fragment. **Fix:** `Stack`
  split into `{reasm, core}`; `Reassembler::completed()` borrows the slot
  buffer in place; `core.deliver(&reasm.completed())` is a disjoint-field
  borrow with zero copy.
- **DEF-L13 — IPv6 Routing Header with Segments Left ≠ 0 was accepted.**
  Now discarded (RFC 8200 §4.4 / RFC 5095). `wire/ipv6.rs::parse`.
- **DEF-L14 — reassembled IPv6 payload starting with an extension header
  was dropped.** `walk_payload` re-walks the fragmentable part.
- **DEF-L17 — `frag.rs` `frag_offset + at as u16` could wrap.**
  `saturating_add`.
- **DEF-L18 — `TcpOptionsEmit` could exceed 60 B header cap.** Compile-time
  `const _: () = assert!(...)` per option group + release-mode `.min()`.
- **DEF-M7 — ICMPv4 Next-Hop-MTU read as 32 bits (RFC 1191: low 16).**
  Garbage in the unused field silently discarded a legitimate PMTU signal.
- **DEF-M8/M9 — Savage et al. 1999 receiver-driven CC bypass.** Unbounded
  NewReno dup-ACK inflation; per-ACK `mss²/cwnd` CA increment was
  ACK-division-able. **Fix:** inflation budget = segments-at-entry; RFC 3465
  ABC for CA. **Tests:** `cc::tests::dupack_inflation_is_bounded_by_flight`,
  `::ack_division_does_not_accelerate_ca`.
- **DEF-M11 — stale timer fire trusted as real.** Guarded:
  `now < desired ⇒ drop`. **Test:** `conn::tests::stale_timer_fire_is_ignored`.
- **DEF-L2 — reap-time `CancelTimer` shed was never retried.** The
  generation bumped regardless, orphaning the cancel. **Fix:** defer the
  reap (slot stays Closed-but-occupied) until cancels drain.
- **DEF-L5 — head segment retransmitted twice on SACK-recovery entry.**
  `rexmit_now` and `sack_cursor = snd_una` both fired. **Fix:**
  `plan_head_rexmit` advances `sack_cursor` past what it sent.
- **DEF-2 — model type-bound off-by-one (model only, not the code).** The TLA+
  `TypeOK` bounded `SND.UNA` to `0..MaxSeq`, excluding the legitimate
  post-FIN value `MaxSeq+1`. **Found by:** TLC. **Fix:** widen the bound.
  Demonstrates the model-checking layer catching a specification error.

---

This matrix should be updated whenever a requirement, deviation, or proof
status changes — it is the artifact a certification reviewer reads first.
