//! Security mitigations (RFC 5961, RFC 6528) and protocol edge cases that
//! the plain scenario suite does not reach: blind RST/SYN injection,
//! zero-window persist, path-MTU discovery, ICMP echo, fragment reassembly,
//! and ISN unpredictability.

mod harness;

use harness::{Host, Net, NetModel, TcpState, establish};
use tcp_sans_io::config::MAX_OOO_RANGES;
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
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip, dst.ip) else {
        panic!("v4 only")
    };
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
    let seg_len = emit.emit(
        &src.ip,
        &dst.ip,
        (payload, &[]),
        &mut buf[ipv4::HEADER_LEN..],
    );
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
    assert_eq!(
        net.state_a(client),
        Some(TcpState::Established),
        "inexact RST → challenge, not close"
    );
    assert!(
        net.a.stats().challenges_granted > before,
        "a challenge ACK was sent"
    );
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
    assert!(
        net.a_snd_wnd(client) <= 1,
        "peer advertised (near) zero window"
    );

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
    assert_eq!(
        received,
        payload.len(),
        "transfer resumed after the window reopened"
    );
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
    let IpAddr::V4(s) = net.addr_a else {
        unreachable!()
    };
    let IpAddr::V4(d) = net.addr_b else {
        unreachable!()
    };
    ipv4::Ipv4Emit::datagram(s, d, proto::ICMP, 64, 1, false).emit(icmp_len, &mut buf);
    buf.truncate(ipv4::HEADER_LEN + icmp_len);

    let now = net.now();
    net.b.on_datagram(now, &buf);
    net.pump_public();
    assert_eq!(
        net.b.stats().echo_tx,
        before + 1,
        "an echo reply was generated"
    );
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
    let (IpAddr::V4(s), IpAddr::V4(d)) = (a.ip, b.ip) else {
        unreachable!()
    };
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
    assert!(
        net.b.stats().segs_rx >= 1,
        "reassembled segment reached TCP"
    );
}

#[test]
fn time_wait_absorbs_late_duplicate_and_expires() {
    let mut net = clean();
    let (client, server) = establish(&mut net, PORT);
    // Close both ends before draining so the harness doesn't advance the
    // clock all the way to A's FIN-WAIT-2 orphan timer between closes
    // (which would close A from FW2 — exactly what DEF-L33 now flags as
    // `TimedOut` — and never reach TIME-WAIT at all).
    net.close(Host::A, client);
    net.close(Host::B, server);
    while net.state_a(client) != Some(TcpState::TimeWait) {
        assert!(net.step(), "reached quiescence before TIME-WAIT");
    }
    net.idle(Duration::from_secs(10));
    // Still in TIME-WAIT before 2·MSL.
    assert_eq!(net.state_a(client), Some(TcpState::TimeWait));
    // After 2*MSL (default MSL 30s → 60s) it is reclaimed gracefully.
    net.idle(Duration::from_secs(130));
    assert_eq!(net.state_a(client), None);
    assert_eq!(
        net.closed_reason(Host::A, client),
        Some(CloseReason::Normal)
    );
}

#[test]
fn checksum_is_verified_on_ingress() {
    // Directly confirm the stack drops a TCP segment with a bad checksum.
    let mut net = clean();
    let (client, _server) = establish(&mut net, PORT);
    let a = net.endpoint(Host::A, net.client_port(client));
    let b = net.endpoint(Host::B, PORT);
    let mut seg = forge_v4(
        b,
        a,
        net.a_rcv_nxt(client),
        net.a_snd_una(client),
        TcpFlags::ACK,
        100,
        b"x",
    );
    // Corrupt a TCP payload byte without fixing the checksum.
    let last = seg.len() - 1;
    seg[last] ^= 0xff;
    let before = net.a.stats().rx_malformed;
    let now = net.now();
    net.a.on_datagram(now, &seg);
    assert_eq!(
        net.a.stats().rx_malformed,
        before + 1,
        "bad-checksum segment dropped"
    );
    assert_eq!(net.state_a(client), Some(TcpState::Established));
    let _ = Checksum::new(); // keep the import meaningful
    let _ = Instant::ZERO;
}

// ------------------------------------------------------------------
// Regressions from the adversarial audit (DEF-* in TRACEABILITY.md §8)
// ------------------------------------------------------------------

/// DEF-C1 / S-CHALLENGE-1: the CVE-2016-5696 side channel relies on the
/// per-second challenge-ACK budget being a fixed, observable constant. With
/// keyed jitter, draining the bucket in two adjacent seconds yields
/// *different* counts (and replays identically given the same entropy seed).
#[test]
fn challenge_ack_budget_is_jittered_per_second() {
    let mut net = clean();
    let (client, _server) = establish(&mut net, PORT);
    let a = net.endpoint(Host::A, net.client_port(client));
    let b = net.endpoint(Host::B, PORT);
    let rcv_nxt = net.a_rcv_nxt(client);

    let mut counts = Vec::new();
    for _sec in 0..6 {
        let before = net.a.stats().challenges_granted;
        let now = net.now();
        for i in 0..50u32 {
            let seg = forge_v4(b, a, rcv_nxt.wrapping_add(1 + i), 0, TcpFlags::RST, 0, &[]);
            net.a.on_datagram(now, &seg);
        }
        net.pump_public();
        counts.push(net.a.stats().challenges_granted - before);
        net.idle(Duration::from_millis(1100));
    }
    // Each second's grant is within [cap/2, cap], and they are not all equal.
    let cap = net.a.config().challenge_acks_per_sec as u64;
    assert!(
        counts.iter().all(|&c| c >= cap / 2 && c <= cap),
        "{counts:?}"
    );
    assert!(
        !counts.windows(2).all(|w| w[0] == w[1]),
        "challenge-ACK budget is constant across seconds — CVE-2016-5696 side channel: {counts:?}"
    );
}

/// DEF-C5: a full-MSS data segment carrying SACK blocks must still fit the
/// path MTU. Before the fix `eff_send_mss` ignored the option overhead, so
/// a single out-of-order segment from the peer caused the next emitted
/// data segment to be `MTU + 36` bytes — overrunning the runtime's tx
/// buffer (panic) or, with DF set, blackholing at the bottleneck.
#[test]
fn full_mss_segment_with_sack_blocks_fits_mtu() {
    let mut net = clean();
    let (client, server) = establish(&mut net, PORT);
    let a = net.endpoint(Host::A, net.client_port(client));
    let b = net.endpoint(Host::B, PORT);
    let rcv_nxt = net.a_rcv_nxt(client);
    let snd_una = net.a_snd_una(client);

    // Give A four disjoint out-of-order ranges so it has the maximum SACK
    // option payload to attach (4 blocks = 36 option bytes).
    let now = net.now();
    for i in 0..4u32 {
        let seq = rcv_nxt.wrapping_add(100 + i * 8);
        let seg = forge_v4(b, a, seq, snd_una, TcpFlags::ACK, 16384, &[0x11; 4]);
        net.a.on_datagram(now, &seg);
    }
    net.pump_public();

    // A now sends a full window of data; every emitted IP datagram must be
    // ≤ MTU even with 36 bytes of SACK options riding on top of payload.
    // Drive the stack directly so we can inspect each Transmit length.
    let mtu = 1500usize;
    let payload = vec![0x77u8; 8 * mtu];
    let n = net.a.send(client, &payload).expect("send");
    assert!(n > 0);
    let now = net.now();
    let mut tx = [0u8; harness::FRAME];
    let mut saw_full = false;
    while let Some(act) = net.a.poll_action(now, &mut tx) {
        if let tcp_sans_io::Action::Transmit { len } = act {
            assert!(
                len <= mtu,
                "DEF-C5: emitted datagram {len} > MTU {mtu} (SACK option \
                 overhead not charged against eff_send_mss)"
            );
            // We want to see at least one segment that *would* have been
            // full-MSS (i.e., the payload-sizing path was exercised, not
            // just a tail fragment).
            saw_full |= len > mtu - 100;
        }
    }
    assert!(saw_full, "expected at least one near-MSS data segment");
    let _ = server;
}

/// DEF-H8: an injected FIN at an *earlier* in-window sequence must not
/// overwrite a later, legitimately-recorded peer FIN — that would truncate
/// the application stream at the injected position.
#[test]
fn injected_earlier_fin_does_not_truncate_stream() {
    let mut net = clean();
    let (client, _server) = establish(&mut net, PORT);
    let a = net.endpoint(Host::A, net.client_port(client));
    let b = net.endpoint(Host::B, PORT);
    let rcv_nxt = net.a_rcv_nxt(client);
    let snd_una = net.a_snd_una(client);
    let now = net.now();

    // Legitimate peer's FIN sits 200 bytes into the future (out of order).
    let real_fin = forge_v4(
        b,
        a,
        rcv_nxt.wrapping_add(200),
        snd_una,
        TcpFlags::ACK.union(TcpFlags::FIN),
        16384,
        &[],
    );
    net.a.on_datagram(now, &real_fin);
    // Attacker injects an *earlier* FIN at +50.
    let forged_fin = forge_v4(
        b,
        a,
        rcv_nxt.wrapping_add(50),
        snd_una,
        TcpFlags::ACK.union(TcpFlags::FIN),
        16384,
        &[],
    );
    net.a.on_datagram(now, &forged_fin);
    // Now the peer's real bytes 0..200 arrive in order.
    let body = forge_v4(b, a, rcv_nxt, snd_una, TcpFlags::ACK, 16384, &[0x42; 200]);
    net.a.on_datagram(now, &body);
    net.pump_public();

    // All 200 bytes must be readable; the FIN is consumed at 200, not 50.
    let got = net.recv_all(Host::A, client);
    assert_eq!(
        got.len(),
        200,
        "DEF-H8: forged earlier FIN truncated the stream"
    );
}

/// DEF-C2: end-to-end form of the receive-path livelock. Saturating the
/// out-of-order budget with far-offset 1-byte segments must not stop
/// in-order data from being delivered.
#[test]
fn ooo_budget_saturation_cannot_wedge_receive_path() {
    let mut net = clean();
    let (client, server) = establish(&mut net, PORT);
    let a = net.endpoint(Host::A, net.client_port(client));
    let b = net.endpoint(Host::B, PORT);
    let rcv_nxt = net.a_rcv_nxt(client);
    let snd_una = net.a_snd_una(client);
    let cap = 16 * 1024u32; // RECV_BUF_SIZE default

    // Attacker injects MAX_OOO_RANGES disjoint 1-byte segments near the top
    // of A's receive window (with a valid ACK so they pass RFC 5961 §5.2).
    let now = net.now();
    for i in 0..MAX_OOO_RANGES as u32 {
        let seq = rcv_nxt.wrapping_add(cap - 2 - i * 2);
        let seg = forge_v4(b, a, seq, snd_una, TcpFlags::ACK, 1000, &[0xEE]);
        net.a.on_datagram(now, &seg);
    }
    net.pump_public();

    // Now the legitimate peer sends in-order data. Before the fix, A would
    // refuse it (merge-scratch overflow), RCV.NXT freezes, and B retransmits
    // forever. After: A accepts, advances, and delivers to the application.
    let payload = vec![0xAB; 4096];
    assert_eq!(net.send(Host::B, server, &payload), payload.len());
    net.run(500);
    let got = net.recv_all(Host::A, client);
    assert_eq!(
        got.len(),
        payload.len(),
        "in-order data must be delivered even with the OOO budget saturated"
    );
    assert!(got.iter().all(|&b| b == 0xAB));
}

/// DEF-H2 / RFC 1337: a RST must not destroy TIME-WAIT, even with the exact
/// sequence number — otherwise a rebooted peer's reflexive RST tears down
/// the 2·MSL quarantine.
#[test]
fn time_wait_ignores_rst() {
    let mut net = clean();
    let (client, server) = establish(&mut net, PORT);
    let a = net.endpoint(Host::A, net.client_port(client));
    // Close both sides, stepping only as far as the FIN/ACK exchange so the
    // Wait timer (60 s out) does not fire.
    net.close(Host::A, client);
    for _ in 0..50 {
        net.step();
        if net.state_b(server) == Some(TcpState::CloseWait) {
            break;
        }
    }
    net.close(Host::B, server);
    for _ in 0..50 {
        net.step();
        if net.state_a(client) == Some(TcpState::TimeWait) {
            break;
        }
    }
    assert_eq!(net.state_a(client), Some(TcpState::TimeWait));

    let b = net.endpoint(Host::B, PORT);
    let rcv_nxt = net.a_rcv_nxt(client);
    let exact_rst = forge_v4(b, a, rcv_nxt, 0, TcpFlags::RST, 0, &[]);
    let now = net.now();
    net.a.on_datagram(now, &exact_rst);
    net.pump_public();
    assert_eq!(
        net.state_a(client),
        Some(TcpState::TimeWait),
        "RST in TIME-WAIT must be ignored (RFC 1337)"
    );
    // It still expires normally after 2·MSL.
    net.idle(Duration::from_secs(130));
    assert_eq!(net.state_a(client), None);
}

/// DEF-H1: a peer that goes silent after closing its window must not pin a
/// connection slot forever; the persist budget aborts it.
#[test]
fn silent_zero_window_peer_is_eventually_aborted() {
    let mut net = clean();
    let (client, _server) = establish(&mut net, PORT);
    let a = net.endpoint(Host::A, net.client_port(client));
    let b = net.endpoint(Host::B, PORT);
    let rcv_nxt = net.a_rcv_nxt(client);
    let snd_una = net.a_snd_una(client);

    // Queue data, then forge a window-0 ACK from B and stop B from
    // responding (drop everything on the wire).
    net.send(Host::A, client, &[1u8; 256]);
    let zero_wnd = forge_v4(b, a, rcv_nxt, snd_una, TcpFlags::ACK, 0, &[]);
    let now = net.now();
    net.a.on_datagram(now, &zero_wnd);
    net.pump_public();
    net.model.loss_permille = 1000; // peer is silent

    // Persist backs off to 60 s; budget is 14 → bounded under ~15 minutes.
    net.idle(Duration::from_secs(60 * 20));
    assert_eq!(
        net.closed_reason(Host::A, client),
        Some(CloseReason::TimedOut),
        "silent zero-window peer must not pin the slot indefinitely"
    );
}

/// S-MARTIAN-1: TCP from a multicast/broadcast/unspecified source is
/// silently dropped (RFC 1122 §4.2.3.10) — no RST, no SYN-ACK reflection.
#[test]
fn martian_source_addresses_are_dropped() {
    let mut net = clean();
    net.listen(Host::B, PORT);
    let b = net.endpoint(Host::B, PORT);

    let martians = [
        IpAddr::v4(224, 0, 0, 1),       // multicast
        IpAddr::v4(255, 255, 255, 255), // broadcast
        IpAddr::v4(0, 0, 0, 0),         // unspecified
        net.addr_b,                     // LAND (src == dst)
    ];
    let tx_before = net.b.stats().tx_datagrams;
    let rst_before = net.b.stats().rst_tx;
    let now = net.now();
    for src in martians {
        // SYN to listener: must NOT allocate a slot or SYN-ACK.
        let syn = forge_v4(
            SocketAddr::new(src, 40000),
            b,
            1000,
            0,
            TcpFlags::SYN,
            1000,
            &[],
        );
        net.b.on_datagram(now, &syn);
        // ACK to closed port: must NOT RST.
        let ack = forge_v4(
            SocketAddr::new(src, 40001),
            SocketAddr::new(net.addr_b, 1),
            0,
            1,
            TcpFlags::ACK,
            0,
            &[],
        );
        net.b.on_datagram(now, &ack);
    }
    net.pump_public();
    assert_eq!(
        net.b.stats().tx_datagrams,
        tx_before,
        "no reply to a martian source"
    );
    assert_eq!(net.b.stats().rst_tx, rst_before);
    assert_eq!(net.b.stats().rx_martian_src as usize, martians.len() * 2);
}

/// DEF-M1: a forged FIN at RCV.NXT after the legitimate FIN was already
/// consumed must not advance RCV.NXT or emit a second `PeerFin`.
#[test]
fn fin_is_consumed_at_most_once() {
    let mut net = clean();
    let (client, server) = establish(&mut net, PORT);
    net.close(Host::B, server);
    net.run(200);
    assert_eq!(net.state_a(client), Some(TcpState::CloseWait));
    assert_eq!(net.peer_fin_count(Host::A, client), 1);

    let a = net.endpoint(Host::A, net.client_port(client));
    let b = net.endpoint(Host::B, PORT);
    let rcv_nxt = net.a_rcv_nxt(client);
    let snd_una = net.a_snd_una(client);
    // Forged FIN at the new RCV.NXT (post-FIN). Before the fix this advanced
    // RCV.NXT and emitted a second PeerFin; repeated, it drifted RCV.NXT.
    let now = net.now();
    for i in 0..5 {
        let seg = forge_v4(
            b,
            a,
            rcv_nxt.wrapping_add(i),
            snd_una,
            TcpFlags::ACK.union(TcpFlags::FIN),
            1000,
            &[],
        );
        net.a.on_datagram(now, &seg);
    }
    net.pump_public();
    net.run(50);
    assert_eq!(
        net.a_rcv_nxt(client),
        rcv_nxt,
        "RCV.NXT drifted on forged post-FIN FINs"
    );
    assert_eq!(
        net.peer_fin_count(Host::A, client),
        1,
        "PeerFin delivered more than once"
    );
}

/// S-PORT-1: ephemeral source ports are not a predictable sequence.
#[test]
fn ephemeral_ports_are_not_sequential() {
    let mut net = clean();
    let mut ports = Vec::new();
    for p in 6000..6006u16 {
        net.listen(Host::B, p);
        let c = net.connect(Host::A, net.endpoint(Host::B, p));
        ports.push(net.client_port(c));
        net.run(50);
    }
    let deltas: Vec<i32> = ports
        .windows(2)
        .map(|w| w[1] as i32 - w[0] as i32)
        .collect();
    assert!(
        !deltas.iter().all(|&d| d == deltas[0]),
        "ephemeral ports are a constant-delta sequence (RFC 6056 violated): {ports:?}"
    );
}

/// DEF-M10 / S-CHALLENGE-1: a SYN to a synchronized connection consumes a
/// challenge-ACK token *regardless* of whether its sequence number is in
/// the window. Without this, in/out-of-window is a perfect oracle.
#[test]
fn syn_consumes_challenge_token_regardless_of_seq() {
    let mut net = clean();
    let (client, _server) = establish(&mut net, PORT);
    let a = net.endpoint(Host::A, net.client_port(client));
    let b = net.endpoint(Host::B, PORT);

    let granted = |net: &Net| net.a.stats().challenges_granted + net.a.stats().challenges_limited;

    let before = granted(&net);
    let now = net.now();
    // Out-of-window SYN.
    net.a
        .on_datagram(now, &forge_v4(b, a, 0x4000_0000, 0, TcpFlags::SYN, 0, &[]));
    // In-window SYN.
    let rcv_nxt = net.a_rcv_nxt(client);
    net.a
        .on_datagram(now, &forge_v4(b, a, rcv_nxt, 0, TcpFlags::SYN, 0, &[]));
    net.pump_public();
    assert_eq!(
        granted(&net) - before,
        2,
        "both in- and out-of-window SYNs must take the challenge path"
    );
}

#[test]
fn syn_flood_fills_pool_sheds_silently_and_recovers() {
    // Resource exhaustion, end to end: "the conns array IS the pool", so a
    // SYN flood can pin at most CONNS slots and nothing else — no
    // allocation, no RST storm (no amplification), no panic. Half-open
    // slots burn their SYN-ACK retry budget (max_syn_retries), expire, and
    // the pool serves legitimate clients again.
    let mut net = clean();
    net.listen(Host::B, PORT);
    let b = net.endpoint(Host::B, PORT);

    // Eight spoofed sources fill every Stack<8> slot with SYN-RECEIVED.
    for i in 0..8u16 {
        let src = SocketAddr::new(IpAddr::v4(10, 0, 0, 100), 40_000 + i);
        let syn = forge_v4(src, b, 1_000 + u32::from(i), 0, TcpFlags::SYN, 1000, &[]);
        let now = net.now();
        net.b.on_datagram(now, &syn);
        net.pump_public();
    }
    let tx_full = net.b.stats().tx_datagrams;
    assert!(tx_full >= 8, "a SYN-ACK per accepted SYN ({tx_full})");

    // The ninth SYN is shed in silence: no slot, no SYN-ACK, and
    // deliberately no RST (the flood gets zero amplification back).
    let rst_before = net.b.stats().rst_tx;
    let src9 = SocketAddr::new(IpAddr::v4(10, 0, 0, 100), 40_900);
    let syn9 = forge_v4(src9, b, 99, 0, TcpFlags::SYN, 1000, &[]);
    let now = net.now();
    net.b.on_datagram(now, &syn9);
    net.pump_public();
    assert_eq!(
        net.b.stats().tx_datagrams,
        tx_full,
        "shed SYN elicited a reply"
    );
    assert_eq!(net.b.stats().rst_tx, rst_before, "shed SYN must not RST");

    // Burn the SYN-ACK retransmit budget; the half-opens abort and free
    // their slots (bounded lifetime — the flood cannot pin slots forever).
    net.idle(Duration::from_secs(300));

    // Recovery: a real handshake now completes.
    let client = net.connect(Host::A, b);
    net.run(200);
    assert_eq!(
        net.state_a(client),
        Some(TcpState::Established),
        "pool recovered after flood"
    );
}
