//! A real (non-virtual) runtime for the sans-I/O [`Stack`]: it owns wall-clock
//! time, real timers, an entropy source, and the TUN "wire". This is the
//! reference for how to embed the protocol core in a std environment — the
//! same shape as the in-memory test harness, but against the live kernel.

use crate::tun::Tun;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::time::{Duration as StdDuration, Instant as StdInstant};
use tcp_sans_io::time::Instant;
use tcp_sans_io::{Action, AppEvent, Error, SocketAddr, SocketId, Stack, TimerKey};

/// Frame scratch (one MTU plus headroom).
const FRAME: usize = 2048;

/// Drives a `Stack` over a TUN device in real time.
pub struct TunRuntime {
    stack: Stack<16>,
    tun: Tun,
    timers: HashMap<TimerKey, StdInstant>,
    epoch: StdInstant,
    urandom: File,
    rx: [u8; FRAME],
    tx: [u8; FRAME],
    /// Application events observed, in order (drained by the caller).
    pub events: Vec<AppEvent>,
}

impl TunRuntime {
    /// Build a runtime; the stack owns `local_cidr`'s address.
    pub fn new(stack: Stack<16>, tun: Tun) -> std::io::Result<Self> {
        Ok(TunRuntime {
            stack,
            tun,
            timers: HashMap::new(),
            epoch: StdInstant::now(),
            urandom: File::open("/dev/urandom")?,
            rx: [0; FRAME],
            tx: [0; FRAME],
            events: Vec::new(),
        })
    }

    /// Logical time = wall-clock since construction, in microseconds.
    fn now(&self) -> Instant {
        Instant::from_micros(self.epoch.elapsed().as_micros() as u64)
    }

    /// One service round: fire due timers, drain inbound datagrams, and
    /// perform all pending stack actions. Returns true if any work happened.
    pub fn poll(&mut self) -> bool {
        let mut worked = false;

        // 1. Fire timers whose deadline has passed.
        let now_std = StdInstant::now();
        let due: Vec<TimerKey> =
            self.timers.iter().filter(|&(_, &t)| t <= now_std).map(|(&k, _)| k).collect();
        for key in due {
            self.timers.remove(&key);
            let now = self.now();
            self.stack.on_timer(now, key);
            worked = true;
        }

        // 2. Pull every datagram the kernel has queued on the tun.
        loop {
            match self.tun.recv(&mut self.rx) {
                Ok(Some(n)) if n > 0 => {
                    let now = self.now();
                    self.stack.on_datagram(now, &self.rx[..n]);
                    worked = true;
                }
                Ok(_) => break,
                Err(e) => {
                    eprintln!("tun read error: {e}");
                    break;
                }
            }
        }

        // 3. Drain actions.
        worked |= self.drain_actions();
        worked
    }

    fn drain_actions(&mut self) -> bool {
        let now = self.now();
        let mut worked = false;
        loop {
            let action = self.stack.poll_action(now, &mut self.tx);
            let Some(action) = action else { break };
            worked = true;
            match action {
                Action::None => {}
                Action::Transmit { len } => {
                    if let Err(e) = self.tun.send(&self.tx[..len]) {
                        eprintln!("tun write error: {e}");
                    }
                }
                Action::StartTimer { key, after } => {
                    let at = StdInstant::now() + StdDuration::from_micros(after.as_micros());
                    self.timers.insert(key, at);
                }
                Action::CancelTimer { key } => {
                    self.timers.remove(&key);
                }
                Action::RequestEntropy => {
                    let mut seed = [0u8; 16];
                    self.urandom.read_exact(&mut seed).expect("read /dev/urandom");
                    self.stack.on_entropy(seed);
                }
                Action::App(ev) => self.events.push(ev),
            }
        }
        worked
    }

    /// Run the service loop until `cond` returns true or `deadline` elapses.
    /// Sleeps briefly when idle to avoid a busy spin. Returns whether `cond`
    /// was met.
    pub fn run_until(&mut self, timeout: StdDuration, mut cond: impl FnMut(&mut Self) -> bool) -> bool {
        let deadline = StdInstant::now() + timeout;
        loop {
            let worked = self.poll();
            if cond(self) {
                return true;
            }
            if StdInstant::now() >= deadline {
                return false;
            }
            if !worked {
                std::thread::sleep(StdDuration::from_micros(500));
            }
        }
    }

    // --- thin API passthroughs ---

    pub fn listen(&mut self, port: u16) -> Result<(), Error> {
        let r = self.stack.listen(port);
        self.drain_actions();
        r
    }

    pub fn connect(&mut self, remote: SocketAddr) -> Result<SocketId, Error> {
        let now = self.now();
        let r = self.stack.connect(now, remote);
        self.drain_actions();
        r
    }

    pub fn send(&mut self, sock: SocketId, data: &[u8]) -> Result<usize, Error> {
        let r = self.stack.send(sock, data);
        self.drain_actions();
        r
    }

    pub fn recv(&mut self, sock: SocketId, out: &mut [u8]) -> Result<usize, Error> {
        self.stack.recv(sock, out)
    }

    pub fn close(&mut self, sock: SocketId) -> Result<(), Error> {
        let r = self.stack.close(sock);
        self.drain_actions();
        r
    }

    pub fn stats(&self) -> tcp_sans_io::StackStats {
        self.stack.stats()
    }

    /// Take and clear the accumulated app events.
    pub fn take_events(&mut self) -> Vec<AppEvent> {
        std::mem::take(&mut self.events)
    }
}
