#!/usr/bin/env bash
# Model-check the TCP FSM and the stack<->runtime timer boundary with TLC.
#
# Requires Java and tla2tools.jar. Set TLA_TOOLS to its path, or drop
# tla2tools.jar next to this script. Download:
#   curl -sSL -o tla2tools.jar \
#     https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
set -euo pipefail
cd "$(dirname "$0")"

JAR="${TLA_TOOLS:-tla2tools.jar}"
if [[ ! -f "$JAR" ]]; then
  for c in /tmp/tla2tools.jar "$HOME/tla2tools.jar"; do
    [[ -f "$c" ]] && JAR="$c" && break
  done
fi
if [[ ! -f "$JAR" ]]; then
  echo "tla2tools.jar not found. Set TLA_TOOLS=/path/to/tla2tools.jar" >&2
  exit 1
fi

tlc() { java -XX:+UseParallelGC -jar "$JAR" "$@"; }

echo "== tcp_fsm: connection FSM (safety + liveness) =="
tlc -config tcp_fsm.cfg tcp_fsm.tla

echo
echo "== runtime_boundary: timer reconcile protocol (fixed) =="
# Quiescence (no enabled action) is the goal state here, not a deadlock.
tlc -deadlock -config runtime_boundary.cfg runtime_boundary.tla

echo
echo "== runtime_boundary: pre-fix protocol must STILL fail (negative test) =="
# The RecordOnShed=TRUE variant models the bug fixed in src/stack.rs
# (recording a timer diff as delivered when the queue shed it). TLC must
# find the QuiescentFaithful violation; if it stops finding it, the model
# no longer captures the bug class and needs attention.
if tlc -deadlock -config runtime_boundary_bug.cfg runtime_boundary.tla \
    > /tmp/runtime_boundary_bug.out 2>&1; then
  echo "ERROR: pre-fix model unexpectedly verified — counterexample vanished" >&2
  exit 1
fi
if ! grep -q "Invariant QuiescentFaithful is violated" /tmp/runtime_boundary_bug.out; then
  echo "ERROR: pre-fix model failed for the wrong reason:" >&2
  tail -20 /tmp/runtime_boundary_bug.out >&2
  exit 1
fi
echo "counterexample found, as expected (see /tmp/runtime_boundary_bug.out)"

echo
echo "ALL MODEL CHECKS PASSED"
