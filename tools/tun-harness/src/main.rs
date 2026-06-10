//! On-the-wire interop harness.
//!
//! Drives the `tcp-sans-io` stack against the **real Linux kernel TCP stack**
//! over a TUN device. Two scenarios, each a bulk transfer whose integrity is
//! checked end to end:
//!
//!   1. kernel `connect()` → our stack's echo server (kernel is the client);
//!   2. our stack `connect()` → a kernel echo server (kernel is the server).
//!
//! Run as root (TUN creation needs `CAP_NET_ADMIN`):
//!
//! ```text
//! cargo build --release --manifest-path tools/tun-harness/Cargo.toml
//! sudo ./tools/tun-harness/target/release/tun-interop
//! ```
//!
//! Exit code 0 on success; non-zero with a diagnostic on failure.

mod runtime;
mod tun;

use runtime::TunRuntime;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tcp_sans_io::config::Config;
use tcp_sans_io::{AppEvent, IpAddr, SocketAddr, SocketId, Stack};
use tun::Tun;

const IFNAME: &str = "tcptun0";
const STACK_IP: [u8; 4] = [10, 9, 0, 2]; // our stack's address
const KERNEL_IP: [u8; 4] = [10, 9, 0, 1]; // the kernel side / tun address
const ECHO_PORT: u16 = 9000; // our stack listens here (scenario 1)
const KSRV_PORT: u16 = 9001; // kernel listens here (scenario 2)
const PAYLOAD: usize = 128 * 1024;

fn payload() -> Vec<u8> {
    (0..PAYLOAD).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect()
}

fn new_runtime(tun: Tun) -> TunRuntime {
    let stack: Stack<16> = Stack::new(Config::with_addr(IpAddr::V4(STACK_IP)));
    TunRuntime::new(stack, tun).expect("runtime")
}

fn main() {
    let tun = match Tun::create(IFNAME) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("FATAL: cannot create TUN {IFNAME}: {e}");
            eprintln!("       run as root: sudo {}", std::env::args().next().unwrap_or_default());
            std::process::exit(2);
        }
    };
    if let Err(e) = tun.configure(&format!("{}.{}.{}.{}/24", KERNEL_IP[0], KERNEL_IP[1], KERNEL_IP[2], KERNEL_IP[3]), 1500) {
        eprintln!("FATAL: cannot configure {}: {e}", tun.name());
        std::process::exit(2);
    }
    println!("tun {} up: kernel {KERNEL_IP:?} <-> stack {STACK_IP:?}", tun.name());

    let mut rt = new_runtime(tun);
    let mut failures = 0;

    match scenario_kernel_to_stack(&mut rt) {
        Ok(()) => println!("PASS  scenario 1: kernel client -> stack echo server ({PAYLOAD} B round-trip)"),
        Err(e) => {
            println!("FAIL  scenario 1: {e}");
            failures += 1;
        }
    }
    match scenario_stack_to_kernel(&mut rt) {
        Ok(()) => println!("PASS  scenario 2: stack client -> kernel echo server ({PAYLOAD} B round-trip)"),
        Err(e) => {
            println!("FAIL  scenario 2: {e}");
            failures += 1;
        }
    }

    let s = rt.stats();
    println!(
        "stats: rx_datagrams={} segs_rx={} tx_datagrams={} rst_tx={} rx_malformed={}",
        s.rx_datagrams, s.segs_rx, s.tx_datagrams, s.rst_tx, s.rx_malformed
    );
    if failures == 0 {
        println!("ALL INTEROP SCENARIOS PASSED");
        std::process::exit(0);
    } else {
        eprintln!("{failures} scenario(s) failed");
        std::process::exit(1);
    }
}

/// Scenario 1: the kernel opens a connection to our stack's echo server and
/// streams `PAYLOAD` bytes; we echo them back; the kernel verifies.
fn scenario_kernel_to_stack(rt: &mut TunRuntime) -> Result<(), String> {
    rt.listen(ECHO_PORT).map_err(|e| format!("listen: {e:?}"))?;

    let done = Arc::new(AtomicBool::new(false));
    let data = payload();
    let (res_tx, res_rx) = mpsc::channel::<Result<usize, String>>();

    let kernel = {
        let (done, data) = (done.clone(), data.clone());
        std::thread::spawn(move || {
            let addr = format!("{}.{}.{}.{}:{ECHO_PORT}", STACK_IP[0], STACK_IP[1], STACK_IP[2], STACK_IP[3]);
            let outcome = (|| -> Result<usize, String> {
                let mut w = TcpStream::connect(&addr).map_err(|e| format!("connect: {e}"))?;
                w.set_read_timeout(Some(Duration::from_secs(20))).ok();
                let mut r = w.try_clone().map_err(|e| format!("clone: {e}"))?;
                let n = data.len();
                let reader = std::thread::spawn(move || -> Result<Vec<u8>, String> {
                    let mut got = vec![0u8; n];
                    r.read_exact(&mut got).map_err(|e| format!("read_exact: {e}"))?;
                    Ok(got)
                });
                w.write_all(&data).map_err(|e| format!("write_all: {e}"))?;
                w.shutdown(Shutdown::Write).map_err(|e| format!("shutdown: {e}"))?;
                let echoed = reader.join().expect("reader thread")?;
                match data.iter().zip(echoed.iter()).position(|(a, b)| a != b) {
                    Some(i) => Err(format!("first byte mismatch at offset {i}")),
                    None => Ok(echoed.len()),
                }
            })();
            res_tx.send(outcome).ok();
            done.store(true, Ordering::SeqCst);
        })
    };

    // Stack-side echo loop.
    let mut server: Option<SocketId> = None;
    let mut pending: Vec<u8> = Vec::new();
    let mut peer_fin = false;
    let mut buf = [0u8; 16 * 1024];
    let deadline = Instant::now() + Duration::from_secs(25);
    while !done.load(Ordering::SeqCst) && Instant::now() < deadline {
        rt.poll();
        for ev in rt.take_events() {
            match ev {
                AppEvent::Connected { sock, via_listener: Some(_) } => server = Some(sock),
                AppEvent::PeerFinReceived { sock } if Some(sock) == server => peer_fin = true,
                _ => {}
            }
        }
        if let Some(sock) = server {
            // Drain everything readable into `pending`.
            while let Ok(n) = rt.recv(sock, &mut buf) {
                if n == 0 {
                    break;
                }
                pending.extend_from_slice(&buf[..n]);
            }
            // Echo as much as the send buffer accepts.
            while !pending.is_empty() {
                match rt.send(sock, &pending) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        pending.drain(..n);
                    }
                }
            }
            if peer_fin && pending.is_empty() {
                let _ = rt.close(sock);
            }
        }
    }
    // Give the FIN exchange a moment to settle on the wire.
    rt.run_until(Duration::from_secs(3), |_| false);
    kernel.join().expect("kernel thread");

    match res_rx.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(_n)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("timed out before kernel reported a result".into()),
    }
}

/// Scenario 2: our stack opens a connection to a kernel echo server, streams
/// `PAYLOAD` bytes, half-closes, and verifies the echo it reads back.
fn scenario_stack_to_kernel(rt: &mut TunRuntime) -> Result<(), String> {
    let (ready_tx, ready_rx) = mpsc::channel::<u16>();
    let kernel = std::thread::spawn(move || {
        let bind = format!("{}.{}.{}.{}:{KSRV_PORT}", KERNEL_IP[0], KERNEL_IP[1], KERNEL_IP[2], KERNEL_IP[3]);
        let listener = TcpListener::bind(&bind).expect("kernel bind");
        ready_tx.send(KSRV_PORT).expect("ready");
        let (mut s, _) = listener.accept().expect("kernel accept");
        s.set_read_timeout(Some(Duration::from_secs(20))).ok();
        // Echo until the peer half-closes (read returns 0).
        let mut buf = [0u8; 32 * 1024];
        loop {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = s.shutdown(Shutdown::Both);
    });

    ready_rx.recv_timeout(Duration::from_secs(5)).map_err(|_| "kernel listener not ready")?;

    let remote = SocketAddr::new(IpAddr::V4(KERNEL_IP), KSRV_PORT);
    let sock = rt.connect(remote).map_err(|e| format!("connect: {e:?}"))?;

    let data = payload();
    let mut sent = 0usize;
    let mut got: Vec<u8> = Vec::new();
    let mut closed = false;
    let mut buf = [0u8; 16 * 1024];
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut established = false;

    while got.len() < data.len() && Instant::now() < deadline {
        rt.poll();
        for ev in rt.take_events() {
            if let AppEvent::Connected { sock: s, .. } = ev
                && s == sock
            {
                established = true;
            }
        }
        if established {
            // Push remaining payload as the send buffer drains.
            if sent < data.len() {
                if let Ok(n) = rt.send(sock, &data[sent..]) {
                    sent += n;
                }
            } else if !closed {
                // All data queued: half-close to signal EOF to the kernel.
                let _ = rt.close(sock);
                closed = true;
            }
            // Collect echoed bytes.
            while let Ok(n) = rt.recv(sock, &mut buf) {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
        }
    }
    rt.run_until(Duration::from_secs(3), |_| false);
    kernel.join().expect("kernel thread");

    if got.len() != data.len() {
        return Err(format!("received {} of {} bytes", got.len(), data.len()));
    }
    if got != data {
        return Err("echoed bytes did not match what was sent".into());
    }
    Ok(())
}
