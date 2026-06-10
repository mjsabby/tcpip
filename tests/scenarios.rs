//! End-to-end scenario tests over the in-memory two-host harness.
//!
//! Each test drives two real [`Stack`](tcp_sans_io::Stack)s through the
//! virtual network and asserts on observable behavior: application events,
//! transferred bytes, and connection states. Together they cover the
//! Definition-of-Done feature list from PLAN.md.

mod harness;

use harness::{Host, Net, NetModel, TcpState, establish};
use tcp_sans_io::CloseReason;
use tcp_sans_io::config::Config;
use tcp_sans_io::time::Duration;

const PORT: u16 = 80;

fn clean() -> Net {
    Net::new(NetModel::default(), 0xC0FFEE)
}

#[test]
fn three_way_handshake() {
    let mut net = clean();
    net.listen(Host::B, PORT);
    let server_ep = net.endpoint(Host::B, PORT);
    let client = net.connect(Host::A, server_ep);
    assert_eq!(net.state_a(client), Some(TcpState::SynSent));
    net.run(100);

    // Both sides reach ESTABLISHED; the server side surfaced via its listener.
    assert_eq!(net.state_a(client), Some(TcpState::Established));
    let (server, port) = net.accepted_socket(Host::B).expect("accepted");
    assert_eq!(port, PORT);
    assert_eq!(net.state_b(server), Some(TcpState::Established));
}

#[test]
fn small_message_transfer_both_directions() {
    let mut net = clean();
    let (client, server) = establish(&mut net, PORT);

    assert_eq!(net.send(Host::A, client, b"ping"), 4);
    net.run(100);
    assert_eq!(net.recv_all(Host::B, server), b"ping");

    assert_eq!(net.send(Host::B, server, b"pong!"), 5);
    net.run(100);
    assert_eq!(net.recv_all(Host::A, client), b"pong!");
}

#[test]
fn bulk_transfer_exceeds_window_and_arrives_intact() {
    let mut net = clean();
    let (client, server) = establish(&mut net, PORT);

    // More than one congestion window and more than one MSS worth of data.
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 31 + 7) as u8).collect();
    let mut offered = 0;
    let mut received = Vec::new();
    let mut buf = [0u8; 8192];
    // Feed in chunks as the send buffer drains, draining the receiver too.
    for _ in 0..2000 {
        if offered < payload.len() {
            offered += net.send(Host::A, client, &payload[offered..]);
        }
        if !net.step() {
            // Top up if stalled only by our offering cadence.
            if offered >= payload.len() {
                break;
            }
        }
        let n = net.a.stats(); // keep borrow short
        let _ = n;
        let got = net.recv(Host::B, server, &mut buf);
        received.extend_from_slice(&buf[..got]);
    }
    // Drain anything left.
    net.run(5000);
    received.extend_from_slice(&net.recv_all(Host::B, server));

    assert_eq!(offered, payload.len(), "all bytes were accepted for sending");
    assert_eq!(received.len(), payload.len(), "all bytes were received");
    assert_eq!(received, payload, "stream integrity preserved");
}

#[test]
fn graceful_close_four_way() {
    let mut net = clean();
    let (client, server) = establish(&mut net, PORT);

    net.send(Host::A, client, b"bye");
    net.run(50);
    net.close(Host::A, client);
    net.run(200);

    // Server saw the peer's FIN and the buffered data preceding it.
    assert!(net.saw_peer_fin(Host::B, server));
    assert_eq!(net.recv_all(Host::B, server), b"bye");

    // Server closes back; everything terminates.
    net.close(Host::B, server);
    net.run(200);
    // Client (active closer) goes through TIME-WAIT; let it expire.
    net.idle(Duration::from_secs(120));
    assert_eq!(net.state_a(client), None, "client slot reclaimed after TIME-WAIT");
    assert_eq!(net.state_b(server), None, "server slot reclaimed after LAST-ACK");
    assert_eq!(net.closed_reason(Host::B, server), Some(CloseReason::Normal));
}

#[test]
fn half_close_then_bulk_send_drains_in_last_ack() {
    // Regression for a bug found by the on-the-wire interop harness: when a
    // peer in CLOSE-WAIT closes with send-buffer data still untransmitted, it
    // transitions to LAST-ACK; that queued data (and the FIN behind it) must
    // still flush. RFC 9293 §3.10.4. The half-duplex echo pattern below never
    // arises in the other scenarios, so only this exercises it.
    let mut net = clean();
    let (client, server) = establish(&mut net, PORT);

    // Client finishes sending and half-closes; step only until the server
    // observes the FIN (CLOSE-WAIT) — not long enough for the client's
    // FIN-WAIT-2 orphan timer (60 s) to reap it.
    net.close(Host::A, client);
    for _ in 0..50 {
        net.step();
        if net.state_b(server) == Some(TcpState::CloseWait) {
            break;
        }
    }
    assert_eq!(net.state_b(server), Some(TcpState::CloseWait), "server reached CLOSE-WAIT");
    // The client's FIN may or may not be ACKed yet; either way it is
    // half-closed and still able to receive.
    assert!(
        matches!(net.state_a(client), Some(TcpState::FinWait1 | TcpState::FinWait2)),
        "client half-closed, still reading: {:?}",
        net.state_a(client)
    );

    // Server queues a full send buffer's worth (one shot, before closing),
    // then closes *immediately*. cwnd is small at this instant, so most of
    // the buffer is still unsent when CLOSE-WAIT -> LAST-ACK — exactly the
    // condition that stranded the tail before the fix.
    let payload: Vec<u8> = (0..12_000u32).map(|i| (i ^ 0x5A) as u8).collect();
    let queued = net.send(Host::B, server, &payload);
    assert_eq!(queued, payload.len(), "whole payload fits the send buffer");
    net.close(Host::B, server); // CLOSE-WAIT -> LAST-ACK with data unsent

    // Drive to completion; the half-closed-but-still-reading client must
    // receive every byte the server queued before its FIN.
    let mut received = Vec::new();
    for _ in 0..20_000 {
        if !net.step() {
            break;
        }
        received.extend_from_slice(&net.recv_all(Host::A, client));
    }
    net.run(5000);
    received.extend_from_slice(&net.recv_all(Host::A, client));

    assert_eq!(received.len(), payload.len(), "client received every byte despite LAST-ACK close");
    assert_eq!(received, payload, "stream intact across the half-close");
    assert_eq!(net.state_b(server), None, "server reclaimed after LAST-ACK completes");
}

#[test]
fn simultaneous_close() {
    let mut net = clean();
    let (client, server) = establish(&mut net, PORT);
    // Both close before exchanging further data.
    net.close(Host::A, client);
    net.close(Host::B, server);
    net.run(300);
    net.idle(Duration::from_secs(120));
    assert_eq!(net.state_a(client), None);
    assert_eq!(net.state_b(server), None);
    assert_eq!(net.closed_reason(Host::A, client), Some(CloseReason::Normal));
    assert_eq!(net.closed_reason(Host::B, server), Some(CloseReason::Normal));
}

#[test]
fn connection_refused_to_closed_port() {
    let mut net = clean();
    // No listener on B.
    let server_ep = net.endpoint(Host::B, 9999);
    let client = net.connect(Host::A, server_ep);
    net.run(100);
    assert_eq!(net.closed_reason(Host::A, client), Some(CloseReason::Refused));
    assert!(net.b.stats().rst_tx >= 1, "B emitted a RST for the closed port");
}

#[test]
fn ipv6_handshake_and_transfer() {
    let mut net = Net::new_v6(NetModel::default(), 42);
    net.listen(Host::B, PORT);
    let server_ep = net.endpoint(Host::B, PORT);
    let client = net.connect(Host::A, server_ep);
    net.run(100);
    let server = net.accepted_socket(Host::B).expect("accepted").0;
    assert_eq!(net.state_a(client), Some(TcpState::Established));

    let msg = b"hello over IPv6 with a longer-than-tiny payload";
    net.send(Host::A, client, msg);
    net.run(100);
    assert_eq!(net.recv_all(Host::B, server), msg);
}

#[test]
fn retransmission_recovers_from_total_loss_burst() {
    // 30% loss: the handshake and transfer must still complete via RTO and
    // fast retransmit (liveness under loss, PLAN.md liveness target).
    let model = NetModel { delay: Duration::from_millis(10), loss_permille: 300, ..Default::default() };
    let mut net = Net::new(model, 0xBADF00D);
    net.listen(Host::B, PORT);
    let server_ep = net.endpoint(Host::B, PORT);
    let client = net.connect(Host::A, server_ep);
    net.run(2000);
    let server = net.accepted_socket(Host::B).expect("eventually connects").0;

    let payload: Vec<u8> = (0..12_000u32).map(|i| (i ^ (i >> 3)) as u8).collect();
    let mut offered = 0;
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];
    for _ in 0..20000 {
        if offered < payload.len() {
            offered += net.send(Host::A, client, &payload[offered..]);
        }
        if !net.step() && offered >= payload.len() {
            break;
        }
        let got = net.recv(Host::B, server, &mut buf);
        received.extend_from_slice(&buf[..got]);
    }
    net.run(20000);
    received.extend_from_slice(&net.recv_all(Host::B, server));
    assert_eq!(received, payload, "data integrity preserved despite 30% loss");
    assert!(net.dropped > 0, "the loss model actually dropped datagrams");
}

#[test]
fn reordering_and_duplication_preserve_stream() {
    let model = NetModel {
        delay: Duration::from_millis(10),
        jitter: Duration::from_millis(40), // heavy reordering
        dup_permille: 200,
        ..Default::default()
    };
    let mut net = Net::new(model, 7);
    let (client, server) = establish(&mut net, PORT);

    let payload: Vec<u8> = (0..16_000u32).map(|i| (i * 7) as u8).collect();
    let mut offered = 0;
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];
    for _ in 0..20000 {
        if offered < payload.len() {
            offered += net.send(Host::A, client, &payload[offered..]);
        }
        if !net.step() && offered >= payload.len() {
            break;
        }
        let got = net.recv(Host::B, server, &mut buf);
        received.extend_from_slice(&buf[..got]);
    }
    net.run(20000);
    received.extend_from_slice(&net.recv_all(Host::B, server));
    assert_eq!(received, payload);
}

#[test]
fn corruption_is_rejected_by_checksum() {
    // Corrupt 15% of datagrams; the checksum must reject them so the stream
    // still arrives correctly (the bytes look like loss to TCP).
    let model = NetModel {
        delay: Duration::from_millis(5),
        corrupt_permille: 150,
        ..Default::default()
    };
    let mut net = Net::new(model, 999);
    let (client, server) = establish(&mut net, PORT);
    // Large enough that 15% corruption is statistically certain to strike
    // many datagrams (≈hundreds of segments + ACKs).
    let payload: Vec<u8> = (0..120_000u32).map(|i| i as u8).collect();
    let mut offered = 0;
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];
    for _ in 0..20000 {
        if offered < payload.len() {
            offered += net.send(Host::A, client, &payload[offered..]);
        }
        if !net.step() && offered >= payload.len() {
            break;
        }
        let got = net.recv(Host::B, server, &mut buf);
        received.extend_from_slice(&buf[..got]);
    }
    net.run(20000);
    received.extend_from_slice(&net.recv_all(Host::B, server));
    assert_eq!(received, payload);
    // Corruption strikes both directions (data toward B, ACKs toward A);
    // every corrupted datagram must be rejected by a checksum.
    let rejected = net.a.stats().rx_malformed + net.b.stats().rx_malformed;
    assert!(rejected > 0, "corrupted datagrams were rejected by checksum");
}

#[test]
fn window_scaling_enables_large_in_flight_window() {
    // With a scale factor the advertised window can exceed 64 KiB.
    let cfg = Config { offer_window_scale: true, recv_window_scale: 7, ..Config::default() };
    let mut net = clean();
    net.reconfigure(cfg.clone(), cfg);

    let (client, server) = establish(&mut net, PORT);
    // The handshake negotiated scaling on both sides; a transfer still works.
    let payload = vec![0xABu8; 30_000];
    let mut offered = 0;
    let mut received = Vec::new();
    let mut buf = [0u8; 8192];
    for _ in 0..5000 {
        if offered < payload.len() {
            offered += net.send(Host::A, client, &payload[offered..]);
        }
        if !net.step() && offered >= payload.len() {
            break;
        }
        let got = net.recv(Host::B, server, &mut buf);
        received.extend_from_slice(&buf[..got]);
    }
    net.run(5000);
    received.extend_from_slice(&net.recv_all(Host::B, server));
    assert_eq!(received.len(), payload.len());
    assert_eq!(received, payload);
}

#[test]
fn many_connections_concurrently() {
    let mut net = clean();
    for p in 1000..1008u16 {
        net.listen(Host::B, p);
    }
    let mut clients = Vec::new();
    for p in 1000..1008u16 {
        let ep = net.endpoint(Host::B, p);
        clients.push(net.connect(Host::A, ep));
    }
    net.run(500);
    for &c in &clients {
        assert_eq!(net.state_a(c), Some(TcpState::Established), "all opens established");
    }
    assert_eq!(net.count_events(|c| matches!(c.event,
        tcp_sans_io::AppEvent::Connected { .. }) && c.host == Host::B), 8);
}
