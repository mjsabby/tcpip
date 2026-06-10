-------------------------------- MODULE tcp_fsm --------------------------------
(***************************************************************************)
(* Model-checking skeleton for the TCP connection state machine of        *)
(* tcp-sans-io (Proof Strategy Layer 1 in docs/TRACEABILITY.md §7).       *)
(*                                                                         *)
(* This models the RFC 9293 §3.3.2 state diagram as the Rust              *)
(* `tcp::State` enum implements it, plus the abstract sequence-space       *)
(* bookkeeping needed to state the core SAFETY invariants. It is          *)
(* deliberately abstract: bytes are counted, not carried, and the network *)
(* is a set of in-flight control events. It is a starting point for TLC   *)
(* or Apalache, not a discharged proof.                                    *)
(*                                                                         *)
(* The states and transitions here are intended to mirror, one-for-one,   *)
(* the transitions in src/tcp/conn/{input,output}.rs. When that code      *)
(* changes, this model should change with it.                             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxSeq          \* sequence-space bound for model checking (e.g. 8)

VARIABLES
    state,          \* the TCP state of our endpoint
    sndUna,         \* SND.UNA : oldest unacknowledged sequence number
    sndNxt,         \* SND.NXT : next sequence number to send
    rcvNxt,         \* RCV.NXT : next sequence number expected
    finSent,        \* have we put a FIN into the sequence stream?
    finAcked,       \* has our FIN been acknowledged?
    peerFin         \* have we received the peer's FIN?

vars == << state, sndUna, sndNxt, rcvNxt, finSent, finAcked, peerFin >>

States == { "SynSent", "SynReceived", "Established", "FinWait1",
            "FinWait2", "CloseWait", "Closing", "LastAck", "TimeWait",
            "Closed" }

Synchronized == state \notin { "SynSent", "SynReceived", "Closed" }

----------------------------------------------------------------------------
(* Initial conditions: an active opener that has just sent its SYN.        *)
(* (A passive opener would start in SynReceived; both are explored by      *)
(* letting the initial state range, but we fix one here for clarity.)      *)

Init ==
    /\ state   = "SynSent"
    /\ sndUna  = 0
    /\ sndNxt  = 1          \* the SYN occupies sequence 0
    /\ rcvNxt  = 0
    /\ finSent = FALSE
    /\ finAcked = FALSE
    /\ peerFin = FALSE

----------------------------------------------------------------------------
(* Transitions. Each corresponds to a branch in the Rust state machine.    *)

\* Handshake completes (SYN-ACK received and our SYN acknowledged).
RcvSynAck ==
    /\ state = "SynSent"
    /\ state' = "Established"
    /\ sndUna' = sndNxt          \* SYN acknowledged
    /\ rcvNxt' = 1               \* consumed the peer's SYN
    /\ UNCHANGED << sndNxt, finSent, finAcked, peerFin >>

\* Simultaneous open: SYN (no ACK) received in SYN-SENT.
RcvSyn ==
    /\ state = "SynSent"
    /\ state' = "SynReceived"
    /\ rcvNxt' = 1
    /\ UNCHANGED << sndUna, sndNxt, finSent, finAcked, peerFin >>

\* Passive/simultaneous SYN-RECEIVED gets its SYN-ACK acknowledged.
RcvAckOfSyn ==
    /\ state = "SynReceived"
    /\ state' = "Established"
    /\ sndUna' = sndNxt
    /\ UNCHANGED << sndNxt, rcvNxt, finSent, finAcked, peerFin >>

\* Send one byte of data (abstract: just advance SND.NXT).
SendData ==
    /\ state \in { "Established", "CloseWait" }
    /\ ~finSent
    /\ sndNxt < MaxSeq
    /\ sndNxt' = sndNxt + 1
    /\ UNCHANGED << state, sndUna, rcvNxt, finSent, finAcked, peerFin >>

\* Peer acknowledges some outstanding data.
RcvAck ==
    /\ Synchronized
    /\ sndUna < sndNxt
    /\ sndUna' = sndUna + 1
    /\ IF finSent /\ sndUna' = sndNxt THEN finAcked' = TRUE
                                      ELSE finAcked' = finAcked
    /\ UNCHANGED << state, sndNxt, rcvNxt, finSent, peerFin >>

\* Receive one byte of in-order data from the peer.
RcvData ==
    /\ state \in { "Established", "FinWait1", "FinWait2" }
    /\ ~peerFin
    /\ rcvNxt < MaxSeq
    /\ rcvNxt' = rcvNxt + 1
    /\ UNCHANGED << state, sndUna, sndNxt, finSent, finAcked, peerFin >>

\* Application closes: emit FIN (Established -> FIN-WAIT-1, CloseWait -> LastAck).
AppClose ==
    /\ state \in { "Established", "CloseWait" }
    /\ ~finSent
    /\ finSent' = TRUE
    /\ sndNxt' = sndNxt + 1                 \* FIN occupies one sequence
    /\ state' = IF state = "Established" THEN "FinWait1" ELSE "LastAck"
    /\ UNCHANGED << sndUna, rcvNxt, finAcked, peerFin >>

\* Receive the peer's FIN.
RcvFin ==
    /\ state \in { "Established", "FinWait1", "FinWait2" }
    /\ ~peerFin
    /\ peerFin' = TRUE
    /\ rcvNxt' = rcvNxt + 1
    /\ state' = CASE state = "Established" -> "CloseWait"
                  [] state = "FinWait1"    -> "Closing"
                  [] state = "FinWait2"    -> "TimeWait"
                  [] OTHER                 -> state
    /\ UNCHANGED << sndUna, sndNxt, finSent, finAcked >>

\* Our FIN gets acknowledged, advancing the closing handshake.
FinAckProgress ==
    /\ finAcked
    /\ \/ /\ state = "FinWait1" /\ state' = "FinWait2"
       \/ /\ state = "Closing"  /\ state' = "TimeWait"
       \/ /\ state = "LastAck"  /\ state' = "Closed"
    /\ UNCHANGED << sndUna, sndNxt, rcvNxt, finSent, finAcked, peerFin >>

\* TIME-WAIT expires (2*MSL).
TimeWaitExpire ==
    /\ state = "TimeWait"
    /\ state' = "Closed"
    /\ UNCHANGED << sndUna, sndNxt, rcvNxt, finSent, finAcked, peerFin >>

\* A reset at any synchronized state tears the connection down.
RcvReset ==
    /\ Synchronized
    /\ state' = "Closed"
    /\ UNCHANGED << sndUna, sndNxt, rcvNxt, finSent, finAcked, peerFin >>

\* Terminal stutter: a Closed connection's slot is reclaimed and the model
\* idles. Without this, TLC would report the (intended) halt as a deadlock.
\* This is the standard TLA+ idiom for a machine that legitimately stops.
Terminating ==
    /\ state = "Closed"
    /\ UNCHANGED vars

Next ==
    \/ RcvSynAck \/ RcvSyn \/ RcvAckOfSyn
    \/ SendData \/ RcvAck \/ RcvData
    \/ AppClose \/ RcvFin \/ FinAckProgress
    \/ TimeWaitExpire \/ RcvReset
    \/ Terminating

\* Fairness: enough to discharge the conditional liveness properties below
\* without forcing the application to ever close (staying ESTABLISHED forever
\* is a legitimate behavior). We require only that, *once a connection has
\* begun to wind down*, the wind-down completes:
\*   - acknowledgements keep arriving (so a sent FIN is eventually acked),
\*   - the closing-handshake transitions fire,
\*   - the 2*MSL TIME-WAIT timer eventually expires.
Fairness ==
    /\ WF_vars(RcvAck)
    /\ WF_vars(FinAckProgress)
    /\ WF_vars(TimeWaitExpire)

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
(* SAFETY invariants — the TLA+ form of S-INV-* in docs/TRACEABILITY.md.   *)

TypeOK ==
    /\ state \in States
    /\ sndUna \in 0..(MaxSeq + 1)
    /\ sndNxt \in 0..(MaxSeq + 1)
    /\ sndUna =< sndNxt
    /\ rcvNxt \in 0..(MaxSeq + 1)
    /\ finSent \in BOOLEAN
    /\ finAcked \in BOOLEAN
    /\ peerFin \in BOOLEAN

\* S-INV-1: never send sequence numbers ahead of what has been produced.
Inv_UnaLeNxt == sndUna =< sndNxt

\* S-INV-2 (abstract): a FIN can only be acknowledged after it was sent.
Inv_FinAck == finAcked => finSent

\* Consistency: synchronized states have consumed the peer's SYN.
Inv_SynConsumed == Synchronized => rcvNxt >= 1

Safety ==
    /\ TypeOK
    /\ Inv_UnaLeNxt
    /\ Inv_FinAck
    /\ Inv_SynConsumed

----------------------------------------------------------------------------
(* LIVENESS — the TLA+ form of PLAN.md's liveness targets. Under weak      *)
(* fairness on Next, a connection that begins closing eventually reaches a *)
(* terminal state. (Checking this requires the actions that drive closure  *)
(* to remain enabled; this is the obligation a full proof discharges.)     *)

\* Once a connection enters TIME-WAIT, it eventually reaches CLOSED (the
\* 2*MSL timer fires). Checked under Fairness.
ClosingTerminates ==
    (state = "TimeWait") ~> (state = "Closed")

\* CLOSED is absorbing: a reclaimed connection never springs back to life.
\* (A stability property; holds because no action leaves "Closed".)
ClosedIsForever ==
    [](state = "Closed" => [](state = "Closed"))

=============================================================================
(* To check with TLC:  ./check.sh    (config in tcp_fsm.cfg)               *)
(*                                                                         *)
(* This skeleton intentionally omits: retransmission/timer dynamics, the   *)
(* RFC 5961 challenge logic, SACK, and window accounting. Those are the    *)
(* next refinements; each maps to a code region named in the traceability  *)
(* matrix.                                                                  *)
=============================================================================
