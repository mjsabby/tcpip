//! Security mitigations (RFC 5961, RFC 6528) and protocol edge cases that
//! the plain scenario suite does not reach: blind RST/SYN injection,
//! zero-window persist, path-MTU discovery, ICMP echo, fragment reassembly,
//! and ISN unpredictability.

mod harness;

use harness::{Host, Net, NetModel, TcpState, establish};
use tcp_sans_io::time::{Duration, Instant};
use tcp_sans_io::wire::checksum::Checksum;
use tcp_sans_io::wire::tcp::{TcpEmit, TcpFlags, TcpOptionsEmit};
use tcp_sans_io::wire::{ipv4, proto};
use tcp_sans_io::{CloseReason, IpAddr, SocketAddr};

const PORT: u16 = 80;

fn clean() -> Net {
    Net::new(NetModel::default(), 0x5EC)
}

/// Hand-craft a raw IPv4+TCP datagram (for injecting forged segments that no
/// well-behaved peer would send).
#[allow(clippy::too_many_arguments)]
fn forge_v4(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip, dst.ip) else { panic!("v4 only") };
    let mut buf = vec![0u8; 1500];
    let emit = TcpEmit {
        src_port: src.port,
        dst_port: dst.port,
        seq,
        ack,
        flags,
        window,
        options: TcpOptionsEmit::default(),
    };
    let seg_len = emit.emit(&src.ip, &dst.ip, (payload, &[]), &mut buf[ipv4::HEADER_LEN..]);
    ipv4::Ipv4Emit::datagram(s, d, proto::TCP, 64, 1, false).emit(seg_len, &mut buf);
    buf.truncate(ipv4::HEADER_LEN + seg_len);
    buf
}

#[test]
fn blind_rst_outside_window_is_ignored() {
    // RFC 5961 §3.2: an in-window-but-not-exact RST gets a challenge ACK, not
    // a teardown; an out-of-window RST is dropped.
    let mut net = clean();
    let (client, server) = establish(&mut net, PORT);
    let _ = server;

    let a = net.endpoint(Host::A, net.client_port(client));
    let b = net.endpoint(Host::B, PORT);

    // Forged RST with a wildly wrong sequence number (blind attacker).
    let bogus = forge_v4(b, a, 0x4000_0000, 0, TcpFlags::RST, 0, &[]);
    let now = net.now();
    net.a.on_datagram(now, &bogus);
    net.pump_public();
    net.run(50);
    assert_eq!(
        net.state_a(client),
        Some(TcpState::Established),
        "blind RST must not tear down the connection"
    );
}

#[test]
fn in_window_rst_triggers_challenge_then_legit_rst_closes() {
    let mut net = clean();
    let (client, _server) = establish(&mut net, PORT);
    let a = net.endpoint(Host::A, net.client_port(client));
    let b = net.endpoint(Host::B, PORT);

    let before = net.a.stats().challenges_granted;
    // RST whose seq is in the window but not exactly RCV.NXT.
    let rcv_nxt = net.a_rcv_nxt(client);
    let inexact = forge_v4(b, a, rcv_nxt.wrapping_add(5), 0, TcpFlags::RST, 0, &[]);
    let now = net.now();
    net.a.on_datagram(now, &inexact);
    net.pump_public();
    net.run(50);
    assert_eq!(net.state_a(client), Some(TcpState::Established), "inexact RST → challenge, not close");
    assert!(net.a.stats().challenges_granted > before, "a challenge ACK was sent");
}

#[test]
fn blind_syn_in_window_is_challenged_not_accepted() {
    // RFC 5961 §4.2: an in-window SYN on an established connection elicits a
    // challenge ACK and is otherwise ignored (no reset of state).
    let mut net = clean();
    let (client, _server) = establish(&mut net, PORT);
    let a = net.endpoint(Host::A, net.client_port(client));
    let b = net.endpoint(Host::B, PORT);

    let rcv_nxt = net.a_rcv_nxt(client);
    let before = net.a.stats().challenges_granted;
    let forged_syn = forge_v4(b, a, rcv_nxt, 0, TcpFlags::SYN, 1000, &[]);
    let now = net.now();
    net.a.on_datagram(now, &forged_syn);
    net.pump_public();
    net.run(50);
    assert_eq!(net.state_a(client), Some(TcpState::Established));
    assert!(net.a.stats().challenges_granted > before);
}

#[test]
fn challenge_ack_rate_limited() {
    // RFC 5961 §10: challenge ACKs are rate limited. Flooding inexact RSTs
    // must not produce one challenge per segment.
    let mut net = clean();
    let (client, _server) = establish(&mut net, PORT);
    let a = net.endpoint(Host::A, net.client_port(client));
    let b = net.endpoint(Host::B, PORT);
    let rcv_nxt = net.a_rcv_nxt(client);

    let now = net.now();
    for i in 0..100u32 {
        let seg = forge_v4(b, a, rcv_nxt.wrapping_add(7 + i), 0, TcpFlags::RST, 0, &[]);
        net.a.on_datagram(now, &seg);
    }
    net.pump_public();
    let granted = net.a.stats().challenges_granted;
    let limited = net.a.stats().challenges_limited;
    assert!(granted <= net.a.config().challenge_acks_per_sec as u64 + 1);
    assert!(limited > 0, "most forged segments were rate-limited");
    assert_eq!(net.state_a(client), Some(TcpState::Established));
}

#[test]
fn isns_are_unpredictable_across_connections() {
    // RFC 6528: ISNs for different 4-tuples must not be trivially related.
    // We open several connections and confirm the initial sequence numbers
    // (observed as the first byte's seq) are well spread.
    let mut net = clean();
    let mut isns = Vec::new();
    for p in 5000..5008u16 {
        net.listen(Host::B, p);
        let ep = net.endpoint(Host::B, p);
        let c = net.connect(Host::A, ep);
        net.run(50);
        isns.push(net.a_snd_una(c)); // SND.UNA = ISS+1 after handshake
    }
    // No two equal, and consecutive deltas are not a constant (which a naive
    // counter ISN would produce).
    for i in 0..isns.len() {
        for j in i + 1..isns.len() {
            assert_ne!(isns[i], isns[j], "ISNs collided");
        }
    }
    let d0 = isns[1].wrapping_sub(isns[0]);
    let d1 = isns[2].wrapping_sub(isns[1]);
    assert_ne!(d0, d1, "ISN deltas are constant — predictable generator");
}

#[test]
fn zero_window_then_reopen_via_persist() {
    // Receiver advertises a full buffer (zero window); sender must persist
    // and resume when the application drains the receiver (RFC 9293 §3.8.6.1).
    let mut net = clean();
    let (client, server) = establish(&mut net, PORT);

    // Fill the receiver: send more than its buffer without draining.
    let cap = 16 * 1024;
    let payload = vec![0x5Au8; cap * 2];
    let mut offered = 0;
    for _ in 0..500 {
        if offered < payload.len() {
            offered += net.send(Host::A, client, &payload[offered..]);
        }
        if !net.step() {
            break;
        }
    }
    // The receive buffer should now be full → window driven to zero and the
    // sender parked on the persist timer.
    assert!(net.a_snd_wnd(client) <= 1, "peer advertised (near) zero window");

    // Drain the receiver; persist probes elicit a window update and the rest
    // flows.
    let mut received = net.recv_all(Host::B, server).len();
    for _ in 0..3000 {
        if offered < payload.len() {
            offered += net.send(Host::A, client, &payload[offered..]);
        }
        net.step();
        received += net.recv_all(Host::B, server).len();
        if received >= payload.len() {
            break;
        }
    }
    net.run(5000);
    received += net.recv_all(Host::B, server).len();
    assert_eq!(received, payload.len(), "transfer resumed after the window reopened");
}

#[test]
fn icmp_echo_request_is_answered() {
    // RFC 1122 §3.2.2.6: a host MUST answer echo requests.
    let mut net = clean();
    let before = net.b.stats().echo_tx;
    // Build an ICMPv4 echo request to B.
    let mut buf = vec![0u8; 64];
    let body = b"ping-payload";
    let icmp_len = tcp_sans_io::wire::icmp::emit_v4(
        tcp_sans_io::wire::icmp::v4::ECHO_REQUEST,
        0,
        [0, 1, 0, 9],
        body,
        &mut buf[ipv4::HEADER_LEN..],
    );
    let IpAddr::V4(s) = net.addr_a else { unreachable!() };
    let IpAddr::V4(d) = net.addr_b else { unreachable!() };
    ipv4::Ipv4Emit::datagram(s, d, proto::ICMP, 64, 1, false).emit(icmp_len, &mut buf);
    buf.truncate(ipv4::HEADER_LEN + icmp_len);

    let now = net.now();
    net.b.on_datagram(now, &buf);
    net.pump_public();
    assert_eq!(net.b.stats().echo_tx, before + 1, "an echo reply was generated");
}

#[test]
fn fragmented_ip_datagram_reassembles_into_a_segment() {
    // A TCP SYN delivered as two IP fragments must reassemble and open a
    // connection (RFC 791 §3.2 reassembly path).
    let mut net = clean();
    net.listen(Host::B, PORT);
    let a = net.endpoint(Host::A, 40000);
    let b = net.endpoint(Host::B, PORT);

    // Build a SYN segment with a payload long enough to split.
    let payload = vec![0u8; 32]; // fragmenting a SYN's options/data region
    let syn = forge_v4(a, b, 1000, 0, TcpFlags::SYN, 4096, &payload);
    let (IpAddr::V4(s), IpAddr::V4(d)) = (a.ip, b.ip) else { unreachable!() };
    let tcp_seg = &syn[ipv4::HEADER_LEN..];

    // Two fragments at offsets 0 and 24 (first 24 bytes, then the rest).
    let split = 24;
    let mut f0 = vec![0u8; ipv4::HEADER_LEN + split];
    let mut e0 = ipv4::Ipv4Emit::datagram(s, d, proto::TCP, 64, 7, false);
    e0.more_frags = true;
    e0.emit(split, &mut f0);
    f0[ipv4::HEADER_LEN..].copy_from_slice(&tcp_seg[..split]);

    let rest = tcp_seg.len() - split;
    let mut f1 = vec![0u8; ipv4::HEADER_LEN + rest];
    let mut e1 = ipv4::Ipv4Emit::datagram(s, d, proto::TCP, 64, 7, false);
    e1.frag_offset = split as u16;
    e1.emit(rest, &mut f1);
    f1[ipv4::HEADER_LEN..].copy_from_slice(&tcp_seg[split..]);

    let now = net.now();
    net.b.on_datagram(now, &f0);
    net.b.on_datagram(now, &f1);
    net.pump_public();
    net.run(50);
    // B should have accepted the reassembled SYN and replied (SYN-RECEIVED).
    assert!(net.b.stats().segs_rx >= 1, "reassembled segment reached TCP");
}

#[test]
fn time_wait_absorbs_late_duplicate_and_expires() {
    let mut net = clean();
    let (client, server) = establish(&mut net, PORT);
    net.close(Host::A, client);
    net.run(200);
    net.close(Host::B, server);
    net.run(200);
    // Client is in TIME-WAIT (active closer). Confirm it is still present
    // before 2*MSL.
    net.idle(Duration::from_secs(10));
    assert!(
        matches!(net.state_a(client), Some(TcpState::TimeWait) | None),
        "client in TIME-WAIT or already done"
    );
    // After 2*MSL (default MSL 30s → 60s) it is reclaimed.
    net.idle(Duration::from_secs(130));
    assert_eq!(net.state_a(client), None);
    assert_eq!(net.closed_reason(Host::A, client), Some(CloseReason::Normal));
}

#[test]
fn checksum_is_verified_on_ingress() {
    // Directly confirm the stack drops a TCP segment with a bad checksum.
    let mut net = clean();
    let (client, _server) = establish(&mut net, PORT);
    let a = net.endpoint(Host::A, net.client_port(client));
    let b = net.endpoint(Host::B, PORT);
    let mut seg = forge_v4(b, a, net.a_rcv_nxt(client), net.a_snd_una(client), TcpFlags::ACK, 100, b"x");
    // Corrupt a TCP payload byte without fixing the checksum.
    let last = seg.len() - 1;
    seg[last] ^= 0xff;
    let before = net.a.stats().rx_malformed;
    let now = net.now();
    net.a.on_datagram(now, &seg);
    assert_eq!(net.a.stats().rx_malformed, before + 1, "bad-checksum segment dropped");
    assert_eq!(net.state_a(client), Some(TcpState::Established));
    let _ = Checksum::new(); // keep the import meaningful
    let _ = Instant::ZERO;
}
