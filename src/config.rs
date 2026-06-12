//! Compile-time capacities and runtime configuration.
//!
//! Capacities are `const` so worst-case memory of the whole stack is a
//! compile-time constant. Tunables that do not affect memory layout live in
//! [`Config`].

use crate::time::Duration;
use crate::types::IpAddr;
use crate::util::BoundedVec;

/// Default per-connection send buffer capacity in bytes.
///
/// This is the default for `Stack`'s `SND` const-generic parameter; a
/// deployment may pick any (preferably power-of-two) size by instantiating
/// `Stack<CONNS, SND, RCV>` explicitly. Sized for satellite/WAN
/// bandwidth-delay products while keeping the per-connection footprint
/// bounded and certifiable. With window scaling (RFC 7323) the full buffer
/// is usable as a window.
pub const SEND_BUF_SIZE: usize = 16 * 1024;
/// Default per-connection receive buffer capacity in bytes (see
/// [`SEND_BUF_SIZE`]).
pub const RECV_BUF_SIZE: usize = 16 * 1024;
/// Maximum tracked out-of-order ranges on the receive side (also bounds the
/// SACK blocks we can generate; excess out-of-order data is dropped and will
/// be retransmitted by the peer).
pub const MAX_OOO_RANGES: usize = 8;
/// Maximum tracked SACKed ranges on the send side (scoreboard).
pub const MAX_SACK_RANGES: usize = 8;
/// Concurrent IP datagrams under reassembly.
pub const REASM_SLOTS: usize = 4;
/// Maximum reassembled datagram size in bytes (larger datagrams are dropped).
pub const REASM_BUF_SIZE: usize = 4096;
/// Maximum holes tracked per datagram under reassembly (RFC 815 hole list).
pub const REASM_MAX_HOLES: usize = 8;
/// Path-MTU cache entries.
pub const PMTU_CACHE_SIZE: usize = 16;
/// Maximum simultaneous listening ports.
pub const MAX_LISTENERS: usize = 8;
/// Pending action queue capacity. The runtime contract — drain
/// [`crate::Stack::poll_action`] until `None` after every event — bounds the
/// queue depth needed per event; this is sized with ample margin.
pub const ACTION_QUEUE_SIZE: usize = 64;
/// Pending stack-generated RST/reply descriptors (e.g. RST to closed ports).
pub const CTL_QUEUE_SIZE: usize = 8;
/// Maximum local addresses assigned to the stack.
pub const MAX_LOCAL_ADDRS: usize = 4;
/// Scratch capacity for one pending ICMP echo reply payload.
pub const ECHO_BUF_SIZE: usize = 1500;

/// Runtime configuration. All defaults are RFC-conservative.
#[derive(Debug, Clone)]
pub struct Config {
    /// Local IP addresses owned by this stack (both families allowed).
    pub local_addrs: BoundedVec<IpAddr, MAX_LOCAL_ADDRS>,
    /// Interface MTU in bytes (applies to both families).
    pub mtu: u16,
    /// IPv4 TTL / IPv6 hop limit for generated datagrams.
    pub ttl: u8,
    /// Maximum Segment Lifetime; TIME-WAIT lasts `2 * msl` (RFC 9293 §3.4.1).
    pub msl: Duration,
    /// Initial retransmission timeout (RFC 6298 §2: 1 second).
    pub rto_initial: Duration,
    /// Lower bound on the RTO (RFC 6298 §2.4: SHOULD be 1 second).
    pub rto_min: Duration,
    /// Upper bound on the RTO (RFC 6298 §2.5: MAY be at least 60 seconds).
    pub rto_max: Duration,
    /// Retransmissions of a SYN / SYN-ACK before giving up.
    pub max_syn_retries: u8,
    /// Retransmissions of data / FIN before aborting (RFC 1122 R2).
    pub max_data_retries: u8,
    /// Delayed-ACK timeout (RFC 1122 §4.2.3.2: MUST be < 500 ms).
    pub delayed_ack_timeout: Duration,
    /// Enable delayed ACKs (RFC 1122 §4.2.3.2 SHOULD).
    pub delayed_ack: bool,
    /// Enable Nagle's algorithm (RFC 9293 §3.7.4 SHOULD).
    pub nagle: bool,
    /// Offer and use SACK (RFC 2018).
    pub sack: bool,
    /// Offer window scaling (RFC 7323 §2). The option is sent on SYN /
    /// SYN-ACK; sending shift 0 still enables the peer's scaling toward us.
    pub offer_window_scale: bool,
    /// Receive window scale factor to advertise (RFC 7323 §2.2, 0..=14).
    pub recv_window_scale: u8,
    /// Override the advertised MSS; `None` derives it from `mtu`.
    pub mss_override: Option<u16>,
    /// Fragment-reassembly timeout (RFC 1122 §3.3.2: 60–120 s suggested
    /// upper; we default lower to bound resource exposure).
    pub reassembly_timeout: Duration,
    /// Challenge-ACK rate limit per second (RFC 5961 §10).
    pub challenge_acks_per_sec: u8,
    /// Idle timeout in FIN-WAIT-2 with a closed local side, to bound
    /// half-closed orphan lifetime (mirrors common practice).
    pub fin_wait2_timeout: Duration,
    /// Unanswered zero-window probes before aborting the connection
    /// (RFC 9293 §3.8.3 R2; 0 = probe indefinitely per a strict reading of
    /// RFC 1122 §4.2.2.17, which lets a malicious peer pin a slot forever).
    /// "Unanswered" means the probe byte is never acknowledged; a peer that
    /// keeps ACKing with window 0 still counts as alive and resets the count.
    pub max_persist_retries: u8,
    /// Answer ICMP/ICMPv6 echo requests (RFC 1122 §3.2.2.6 MUST).
    pub answer_echo: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            local_addrs: BoundedVec::new(),
            mtu: 1500,
            ttl: 64,
            msl: Duration::from_secs(30),
            rto_initial: Duration::from_secs(1),
            rto_min: Duration::from_secs(1),
            rto_max: Duration::from_secs(60),
            max_syn_retries: 6,
            max_data_retries: 10,
            delayed_ack_timeout: Duration::from_millis(200),
            delayed_ack: true,
            nagle: true,
            sack: true,
            offer_window_scale: true,
            recv_window_scale: 0,
            mss_override: None,
            reassembly_timeout: Duration::from_secs(30),
            challenge_acks_per_sec: 10,
            fin_wait2_timeout: Duration::from_secs(60),
            max_persist_retries: 14,
            answer_echo: true,
        }
    }
}

impl Config {
    /// Configuration with one local address and defaults otherwise.
    pub fn with_addr(addr: IpAddr) -> Self {
        let mut cfg = Config::default();
        let _ = cfg.local_addrs.push(addr);
        cfg
    }

    /// True if `addr` is one of our local addresses.
    pub fn is_local(&self, addr: &IpAddr) -> bool {
        self.local_addrs.iter().any(|a| a == addr)
    }

    /// Coerce every field into its safe range, returning `true` if any
    /// field was clamped. Called by `Stack::new` so that a misconfigured
    /// deployment degrades rather than panics or stalls (DEF-L23 — closes
    /// the `cfg.mtu < floor` ICMP-triggered abort, immortal-deadline timer
    /// leaks, and zero-RTO retransmit storms). Local addresses must be
    /// unicast (a multicast/broadcast `local_addrs` entry would make the
    /// stack answer group-addressed traffic as if unicast).
    pub fn normalize(&mut self) -> bool {
        const DAY: Duration = Duration::from_secs(86_400);
        let before = Self::snapshot(self);
        self.local_addrs.retain(|a| a.is_unicast_source());
        self.mtu = self.mtu.clamp(crate::ip::IPV4_MIN_PMTU, u16::MAX);
        self.ttl = self.ttl.max(1);
        self.msl = self.msl.clamp(Duration::from_secs(1), DAY);
        self.rto_min = self.rto_min.clamp(Duration::from_millis(1), DAY);
        self.rto_max = self.rto_max.clamp(self.rto_min, DAY);
        self.rto_initial = self.rto_initial.clamp(self.rto_min, self.rto_max);
        self.delayed_ack_timeout = self
            .delayed_ack_timeout
            .clamp(Duration::from_millis(1), Duration::from_millis(500));
        self.recv_window_scale = self.recv_window_scale.min(14);
        if let Some(m) = self.mss_override {
            self.mss_override = Some(m.max(64));
        }
        self.reassembly_timeout = self.reassembly_timeout.clamp(Duration::from_secs(1), DAY);
        self.fin_wait2_timeout = self.fin_wait2_timeout.min(DAY);
        before != Self::snapshot(self)
    }

    #[allow(clippy::type_complexity)]
    fn snapshot(
        c: &Self,
    ) -> (
        usize,
        u16,
        u8,
        Duration,
        Duration,
        Duration,
        Duration,
        Duration,
        u8,
        Option<u16>,
        Duration,
        Duration,
    ) {
        (
            c.local_addrs.len(),
            c.mtu,
            c.ttl,
            c.msl,
            c.rto_initial,
            c.rto_min,
            c.rto_max,
            c.delayed_ack_timeout,
            c.recv_window_scale,
            c.mss_override,
            c.reassembly_timeout,
            c.fin_wait2_timeout,
        )
    }
}
