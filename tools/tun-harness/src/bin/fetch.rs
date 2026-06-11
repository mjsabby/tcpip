//! Worked example: download a web page from the public Internet with the
//! sans-I/O stack doing **all** of the TCP.
//!
//! The kernel's role is reduced to plumbing: it carries raw IP datagrams
//! between the stack and the Internet (TUN device + IP forwarding + NAT) and
//! resolves the host name. Every TCP segment on the connection — SYN, ISN,
//! window management, retransmission, FIN — comes from `tcp_sans_io::Stack`.
//!
//! Run via the wrapper script, which sets up forwarding/NAT and cleans up:
//!
//! ```text
//! sudo tools/tun-harness/fetch.sh                # GET http://www.bing.com/
//! sudo tools/tun-harness/fetch.sh example.com    # any other host
//! ```

use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};

use tcp_sans_io::config::Config;
use tcp_sans_io::{AppEvent, IpAddr, SocketAddr, Stack};
use tun_harness::runtime::TunRuntime;
use tun_harness::tun::Tun;

const IFNAME: &str = "tcpfetch0";
const STACK_IP: [u8; 4] = [10, 99, 0, 2]; // the stack's address; NATed by the host

fn main() {
    let host = std::env::args().nth(1).unwrap_or_else(|| "www.bing.com".into());

    // DNS is the runtime's job — the core speaks TCP/IP only.
    let remote_ip = (host.as_str(), 80u16)
        .to_socket_addrs()
        .expect("DNS resolution failed")
        .find_map(|sa| match sa {
            std::net::SocketAddr::V4(v4) => Some(v4.ip().octets()),
            _ => None,
        })
        .expect("no IPv4 address for host");
    println!(
        "{host} -> {}.{}.{}.{}",
        remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3]
    );

    // The wire: a TUN device. fetch.sh has enabled forwarding + MASQUERADE,
    // so datagrams we write here are routed to the Internet and back.
    let tun = Tun::create(IFNAME).unwrap_or_else(|e| {
        eprintln!("FATAL: cannot create TUN {IFNAME}: {e}");
        eprintln!("       run as root via tools/tun-harness/fetch.sh");
        std::process::exit(2);
    });
    tun.configure("10.99.0.1/24", 1500).expect("configure tun");

    let stack: Stack<16> = Stack::new(Config::with_addr(IpAddr::V4(STACK_IP)));
    let mut rt = TunRuntime::new(stack, tun).expect("runtime");

    // First poll answers Action::RequestEntropy (seeds RFC 6528 ISNs);
    // until then connect() would refuse with Error::NeedEntropy.
    rt.poll();

    let sock = rt
        .connect(SocketAddr::new(IpAddr::V4(remote_ip), 80))
        .expect("connect");

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: tcp-sans-io-fetch/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    let request = request.as_bytes();

    let mut established = false;
    let mut sent = 0;
    let mut response: Vec<u8> = Vec::new();
    let mut peer_fin = false;
    let mut closed_back = false;
    let mut done = false;
    let mut buf = [0u8; 16 * 1024];
    let deadline = Instant::now() + Duration::from_secs(30);

    while !done && Instant::now() < deadline {
        rt.poll(); // timers -> stack, datagrams -> stack, actions -> wire
        for ev in rt.take_events() {
            match ev {
                AppEvent::Connected { sock: s, .. } if s == sock => established = true,
                AppEvent::PeerFinReceived { sock: s } if s == sock => peer_fin = true,
                AppEvent::Closed { sock: s, reason } if s == sock => {
                    println!("connection closed ({reason:?})");
                    done = true;
                }
                _ => {}
            }
        }
        if !established {
            continue;
        }
        // Push the rest of the request as send-buffer space allows.
        if sent < request.len()
            && let Ok(n) = rt.send(sock, &request[sent..])
        {
            sent += n;
        }
        // Drain whatever has arrived.
        while let Ok(n) = rt.recv(sock, &mut buf) {
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buf[..n]);
        }
        // Server said EOF ("Connection: close"): finish the close handshake.
        if peer_fin && !closed_back {
            let _ = rt.close(sock);
            closed_back = true;
        }
    }

    if !done {
        eprintln!("FAIL: timed out with {} bytes received", response.len());
        std::process::exit(1);
    }
    let header_end = response.windows(4).position(|w| w == b"\r\n\r\n");
    let Some(header_end) = header_end else {
        eprintln!("FAIL: no HTTP header terminator in {} bytes", response.len());
        std::process::exit(1);
    };
    println!("--- response headers ---");
    println!("{}", String::from_utf8_lossy(&response[..header_end]));
    println!("--- body: {} bytes ---", response.len() - header_end - 4);

    let s = rt.stats();
    println!(
        "stats: rx_datagrams={} segs_rx={} tx_datagrams={} rx_malformed={}",
        s.rx_datagrams, s.segs_rx, s.tx_datagrams, s.rx_malformed
    );
    if !response.starts_with(b"HTTP/1.1") && !response.starts_with(b"HTTP/1.0") {
        eprintln!("FAIL: response does not look like HTTP");
        std::process::exit(1);
    }
    println!("OK");
}
