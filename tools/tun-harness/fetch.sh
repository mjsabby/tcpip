#!/usr/bin/env bash
# Worked example: download a web page from the public Internet through the
# sans-I/O stack. Sets up what the example needs from the host — IP
# forwarding and NAT for the stack's subnet — runs `fetch`, and cleans up.
#
#   sudo tools/tun-harness/fetch.sh                # GET http://www.bing.com/
#   sudo tools/tun-harness/fetch.sh example.com    # any other host
#
# Requires root (TUN creation, sysctl, nft) and Internet access.
set -euo pipefail
cd "$(dirname "$0")"

HOST="${1:-www.bing.com}"
SUBNET=10.99.0.0/24

echo "building (release)..."
cargo build --release --bin fetch

cleanup() {
    sudo -n nft delete table ip tcpfetch 2>/dev/null || true
}
trap cleanup EXIT

echo "enabling forwarding + NAT for $SUBNET..."
sudo -n sysctl -qw net.ipv4.ip_forward=1
sudo -n nft -f - <<EOF
table ip tcpfetch {
    chain post {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr $SUBNET masquerade
    }
    chain allow_forward {
        type filter hook forward priority filter; policy accept;
        ip saddr $SUBNET accept
        ip daddr $SUBNET accept
    }
}
EOF

sudo -n ./target/release/fetch "$HOST"
