#!/usr/bin/env bash
# Build and run the on-the-wire interop harness against the live Linux kernel
# TCP stack. Requires root (TUN creation needs CAP_NET_ADMIN).
#
#   ./run.sh           # build (as the calling user) then run under sudo
#
# The harness creates a transient TUN interface (tcptun0), assigns
# 10.9.0.1/24 to the kernel side, and runs two bulk-transfer scenarios with
# the stack at 10.9.0.2. The interface disappears when the process exits.
set -euo pipefail
cd "$(dirname "$0")"

echo "building (release)..."
cargo build --release

BIN=./target/release/tun-interop
echo "running interop scenarios under sudo..."
exec sudo -n "$BIN"
