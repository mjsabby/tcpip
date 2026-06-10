#!/usr/bin/env bash
# Model-check the TCP FSM with TLC.
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

exec java -XX:+UseParallelGC -jar "$JAR" -config tcp_fsm.cfg tcp_fsm.tla
