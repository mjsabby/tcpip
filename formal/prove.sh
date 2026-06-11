#!/usr/bin/env bash
# Theorem-proving layer (PLAN.md proof layer 2): check the Coq development.
#
#   formal/seq_arith.v — TCP sequence-number arithmetic (src/tcp/seq.rs),
#   definitions mirrored formula-for-formula (incl. the `as i32` cast,
#   modeled as two's-complement reinterpretation and characterized by
#   theorem, not assumption).
#
# Requires coqc (Debian/Ubuntu: apt install coq; proved with Coq 8.20.1).
set -euo pipefail
cd "$(dirname "$0")"

command -v coqc >/dev/null || {
  echo "coqc not found — install Coq (e.g. apt install coq)" >&2
  exit 1
}

coqc -q seq_arith.v
echo "ALL THEOREMS PROVED ($(grep -c 'Qed\.' seq_arith.v) Qed: seq_arith.v accepted by $(coqc --version | head -1))"
