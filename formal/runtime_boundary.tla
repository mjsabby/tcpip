---------------------------- MODULE runtime_boundary ----------------------------
(***************************************************************************)
(* The stack <-> runtime timer boundary, as implemented by                 *)
(* `Stack::reconcile_conn_timers` / `sweep` (src/stack.rs) against a       *)
(* runtime that drains `poll_action`.                                      *)
(*                                                                         *)
(* Four variables capture the whole protocol for one timer key:           *)
(*   desired  - the deadline the connection currently wants (0 = none);   *)
(*              changed by protocol events (ACKs, sends, state moves).    *)
(*   emitted  - the stack's BELIEF about what the runtime knows            *)
(*              (`emitted_conn_timers`).                                   *)
(*   queue    - the bounded action queue between reconcile and drain.     *)
(*   armed    - the deadline the runtime actually has armed.              *)
(*                                                                         *)
(* `Reconcile` emits a diff when belief differs from desire; with the     *)
(* queue full the action is SHED. The constant `RecordOnShed` selects     *)
(* the implementation:                                                     *)
(*   TRUE  - the pre-fix code: record `emitted = desired` even though     *)
(*           nothing was queued (the stack lies to itself).               *)
(*   FALSE - the fixed code: leave `emitted` untouched so the diff        *)
(*           stays visible and a later reconcile retries.                 *)
(*                                                                         *)
(* With RecordOnShed = TRUE, TLC produces the stall counterexample in     *)
(* milliseconds: a state with `desired = emitted`, empty queue, and       *)
(* `armed # desired` - the runtime never learns the deadline and no       *)
(* enabled action ever fixes it (violates both QuiescentFaithful and      *)
(* Converges). With FALSE both properties hold over the full state space. *)
(*                                                                         *)
(* Fairness on Reconcile/Drain is the A-POLL-1 assumption that the        *)
(* runtime keeps polling; without it nothing converges (and the README    *)
(* says as much: a runtime that stops draining stalls the protocol).      *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
    MaxChanges,    \* protocol events eventually stop (else nothing need converge)
    QCap,          \* action queue capacity (1 suffices to expose shedding)
    RecordOnShed   \* TRUE = pre-fix behavior, FALSE = fixed behavior

NoTimer == 0
Deadlines == {1, 2}
Values == Deadlines \cup {NoTimer}

VARIABLES desired, emitted, armed, queue, changes

vars == <<desired, emitted, armed, queue, changes>>

TypeOK ==
    /\ desired \in Values
    /\ emitted \in Values
    /\ armed \in Values
    /\ changes \in 0..MaxChanges
    /\ Len(queue) <= QCap
    /\ \A i \in 1..Len(queue) : queue[i] \in Values

Init ==
    /\ desired = NoTimer
    /\ emitted = NoTimer
    /\ armed = NoTimer
    /\ queue = <<>>
    /\ changes = 0

(* A protocol event re-arms or cancels the timer's desired deadline. *)
ChangeDesired ==
    /\ changes < MaxChanges
    /\ \E d \in Values \ {desired} : desired' = d
    /\ changes' = changes + 1
    /\ UNCHANGED <<emitted, armed, queue>>

(* One reconcile pass for this key: emit the diff, or shed on a full queue.
   Queueing value v means "make armed = v"; NoTimer is a CancelTimer.     *)
Reconcile ==
    /\ emitted # desired
    /\ IF Len(queue) < QCap
       THEN /\ queue' = Append(queue, desired)
            /\ emitted' = desired
       ELSE /\ queue' = queue
            /\ emitted' = IF RecordOnShed THEN desired ELSE emitted
    /\ UNCHANGED <<desired, armed, changes>>

(* The runtime pops one action and applies it. *)
Drain ==
    /\ Len(queue) > 0
    /\ armed' = Head(queue)
    /\ queue' = Tail(queue)
    /\ UNCHANGED <<desired, emitted, changes>>

Next == ChangeDesired \/ Reconcile \/ Drain

Spec == Init /\ [][Next]_vars /\ WF_vars(Reconcile) /\ WF_vars(Drain)

(* Safety: when the stack believes it is reconciled and the queue is
   drained, the runtime's view must actually match. The pre-fix code
   reaches `desired = emitted /\ queue = <<>> /\ armed # desired`:
   a silent, permanent divergence - the wedge. *)
QuiescentFaithful ==
    (emitted = desired /\ queue = <<>>) => armed = desired

(* Liveness: once protocol events stop, the runtime eventually holds the
   desired deadline forever ("a backlog delays, never loses"). *)
Converges == <>[](armed = desired)

=================================================================================
