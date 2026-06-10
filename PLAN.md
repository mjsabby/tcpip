# plan.md

# Aerospace TCP/IP Stack Plan in Rust 2024

## Verification-First, Sans-I/O, Internet-Competent

### Mission

Build a formally verifiable TCP/IP stack in Rust suitable for aerospace and safety-critical systems while remaining competitive with mainstream Internet implementations.

The objective is not to outperform Linux, FreeBSD, or modern datacenter stacks. The objective is:

* Correctness first
* Formal verification first
* Deterministic behavior
* Sans-I/O architecture
* Fully virtualizable execution environment
* Internet interoperability
* Performance roughly in the middle-to-upper half of deployed TCP stacks
* Small enough state space for model checking and theorem proving

Success criterion:

> A device running this stack should interoperate cleanly on the public Internet and should not be viewed as "ancient" or "broken", while avoiding the complexity of Linux-grade TCP.

---

# Guiding Principles

## 1. Every External Dependency Must Be Virtualized

The protocol core must not directly access:

* clocks
* timers
* sockets
* interrupts
* DMA
* threads
* memory allocators
* entropy sources

Everything enters through explicit events.

Example:

```text
TCP State Machine

Input:
    SegmentReceived
    TimerExpired
    ConnectionOpen
    ConnectionClose
    EntropyProvided

Output:
    SendSegment
    StartTimer
    CancelTimer
    RequestEntropy
```

This architecture is mandatory.

---

## 2. Deterministic Core

Protocol state transition:

```text
(State, Event)
    ->
(NewState, Actions)
```

No hidden state.

No background tasks.

No asynchronous callbacks.

No global variables.

No wall clock access.

---

## 3. Verification Before Optimization

A feature should be rejected if:

* it dramatically expands the state space
* it introduces estimator-heavy behavior
* proving correctness becomes significantly harder

Correctness dominates throughput.

---

## 4. Single Source of Truth

RFC requirements should be encoded as:

```text
Invariant
Assumption
Requirement
Test
Proof
```

Every requirement should trace back to:

* RFC
* Safety requirement
* Security requirement

---

# Layer Architecture

```text
+---------------------+
| Application         |
+---------------------+
| TCP                 |
+---------------------+
| IPv4 / IPv6         |
+---------------------+
| ARP / ND            |
+---------------------+
| Link Layer Adapter  |
+---------------------+
```

All protocol layers follow the same model:

```text
(state, event) -> (state, actions)
```

---

# Phase 1: Minimal Viable Stack

Goal:

Reliable Internet communication.

Mandatory RFCs:

* RFC 9293 (TCP)
* RFC 791 (IPv4)
* RFC 8200 (IPv6)
* RFC 1122 host requirements

Features:

* Three-way handshake
* Graceful close
* Retransmission
* Basic flow control
* MSS negotiation
* Fragment reassembly (IP)
* Path MTU awareness

Not included:

* SACK
* timestamps
* congestion control beyond Reno

Verification target:

State-machine correctness.

---

# Phase 2: Production Internet Baseline

This phase gives the largest benefit-per-complexity ratio.

## RFC 5681

Implement:

* Slow Start
* Congestion Avoidance
* Fast Retransmit
* Fast Recovery

Reason:

Still the universal baseline.

Complexity remains manageable.

---

## RFC 6298

Implement:

* Jacobson/Karels RTT estimator
* Standard RTO calculation

Reason:

Extremely high value.

Low complexity.

---

## RFC 6528

Implement:

* Cryptographic ISN generation

Reason:

Modern Internet expectation.

Negligible verification burden.

---

## RFC 5961

Implement:

* Blind reset mitigation
* Blind injection mitigation

Reason:

Excellent security return.

Moderate complexity.

---

# Phase 3: High-Bandwidth WAN Support

This phase targets:

* aerospace WANs
* satellite links
* long-haul terrestrial links

## RFC 2018

Implement SACK.

Expected gain:

Very large.

Complexity:

Moderate.

Recommendation:

Required.

---

## RFC 7323

Implement:

* Window Scaling

Do NOT initially implement:

* Timestamps

Reason:

Window scaling solves a real throughput limitation.

Timestamps add complexity with less value.

---

# Features Explicitly Deferred

## RACK

RFC 8985

Deferred.

Reason:

Large state-space increase.

Verification burden exceeds value.

---

## Tail Loss Probe

Deferred.

Reason:

Internet optimization.

Not safety critical.

---

## CUBIC

RFC 9438

Deferred.

Reason:

Linux optimization.

Not verification-friendly.

---

## BBR

RFC 9430

Rejected.

Reason:

Estimator-heavy.

Large proof burden.

Behavioral complexity too high.

---

# IP Layer Requirements

## IPv4

Required:

* fragmentation
* reassembly
* TTL
* checksum

Optional:

* source routing

Default:

disabled

---

## IPv6

Required:

* extension header parsing
* PMTU support
* ICMPv6 processing

Not required initially:

* advanced extension-header routing

---

# Timer Model

All timers must be virtual.

Forbidden:

```text
sleep()
clock_gettime()
std::chrono::steady_clock::now()
```

Required:

```text
TimerExpired(id)
```

events.

Example:

```text
Output:
    StartTimer(
        id = Retransmission,
        duration = 500 ms
    )
```

Runtime owns real time.

Core owns logical time.

---

# Entropy Model

Forbidden:

```text
rand()
/dev/random
hardware RNG
```

inside protocol core.

Required:

```text
EntropyProvided(bytes)
```

event source.

Benefits:

* deterministic replay
* verification
* testing

---

# Memory Model

Preferred:

Fixed-capacity structures.

Example:

```text
ConnectionTable<128>
```

instead of:

```text
Vec<T>
malloc()
new
```

within protocol core.

Benefits:

* bounded state space
* analyzable memory usage
* certification friendliness

---

# Formal Verification Targets

## Safety

Never:

* transmit invalid sequence numbers
* acknowledge unsent data
* exceed advertised window
* enter impossible TCP state

---

## Liveness

Eventually:

* retransmit lost data
* establish connection
* close connection

under RFC assumptions.

---

## Security

Prove:

* ISN unpredictability assumptions
* reset validation
* sequence acceptance rules

---

# Recommended Proof Strategy

## Layer 1

Model checking.

Tool examples:

* TLA+
* Apalache

Focus:

* state machine correctness
* retransmission behavior

---

## Layer 2

Theorem proving.

Tool examples:

* Coq
* Isabelle
* Dafny
* SPARK

Focus:

* invariants
* safety properties

---

## Layer 3

Property-based testing.

Examples:

```text
QuickCheck
proptest
libFuzzer
```

Generate:

* malformed packets
* packet reordering
* duplication
* timer races

---

# Performance Goal

Not:

Top 5% Internet stack.

Not:

Research-grade throughput.

Target:

50th–80th percentile.

Expected characteristics:

* Reno/NewReno behavior
* SACK support
* Window Scaling
* RFC-compliant timers
* Moderate RTT environments
* Good satellite performance

This achieves most of the practical benefit of modern TCP while avoiding the complexity explosion associated with Linux TCP, CUBIC, BBR, RACK, and TLP.

---

# Definition of Done

A release candidate must satisfy:

* RFC 9293 compliant
* RFC 5681 compliant
* RFC 6298 compliant
* RFC 6528 compliant
* RFC 5961 compliant
* RFC 2018 compliant
* RFC 7323 Window Scaling compliant

And:

* 100% Sans-I/O
* deterministic replay
* virtualized timers
* virtualized entropy
* bounded memory
* executable specification
* model-checked core state machine
* property-based fuzz suite
* interoperability tested against Linux, FreeBSD, and Windows
* no dependency on wall clock or operating system primitives inside protocol logic

```
```

