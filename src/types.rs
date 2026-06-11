//! Public types: addresses, handles, events, actions, errors.
//!
//! Together with the [`crate::Stack`] entry points these define the complete
//! interface of the protocol core: every input is an [`Event`] or an API call
//! (a "call event" in the formal model), every output is an [`Action`].

use crate::time::Duration;

/// An IPv4 or IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpAddr {
    /// IPv4 address, network byte order.
    V4([u8; 4]),
    /// IPv6 address, network byte order.
    V6([u8; 16]),
}

impl IpAddr {
    /// Convenience IPv4 constructor.
    pub const fn v4(a: u8, b: u8, c: u8, d: u8) -> Self {
        IpAddr::V4([a, b, c, d])
    }

    /// Convenience IPv6 constructor from 16-bit groups.
    pub const fn v6(g: [u16; 8]) -> Self {
        let mut b = [0u8; 16];
        let mut i = 0;
        while i < 8 {
            b[2 * i] = (g[i] >> 8) as u8;
            b[2 * i + 1] = g[i] as u8;
            i += 1;
        }
        IpAddr::V6(b)
    }

    /// True for [`IpAddr::V4`].
    pub const fn is_v4(&self) -> bool {
        matches!(self, IpAddr::V4(_))
    }

    /// True if both addresses are the same IP family.
    pub const fn same_family(&self, other: &IpAddr) -> bool {
        self.is_v4() == other.is_v4()
    }

    /// True if this is a unicast address valid as the *source* of a datagram
    /// the stack should respond to. Rejects multicast, broadcast, the
    /// unspecified address, and (defensively) loopback arriving from the
    /// wire. RFC 1122 §4.2.3.10: a host MUST NOT respond to TCP segments
    /// addressed from a broadcast or multicast source; we extend this to all
    /// stack-generated replies (RST, SYN-ACK, echo) so the stack cannot be
    /// used as a reflector toward such addresses (S-MARTIAN-1).
    pub fn is_unicast_source(&self) -> bool {
        match self {
            IpAddr::V4(b) => {
                b[0] != 0                     // 0.0.0.0/8 ("this network")
                    && b[0] != 127            // loopback from wire
                    && b[0] < 224             // 224.0.0.0/4 multicast, 240/4 reserved
                    && *b != [255, 255, 255, 255] // limited broadcast
            }
            IpAddr::V6(b) => {
                *b != [0; 16]                 // ::
                    && b[0] != 0xff           // ff00::/8 multicast
                    && !(b[0] == 0 && b[15] == 1 && b[1..15] == [0; 14]) // ::1
            }
        }
    }
}

impl Default for IpAddr {
    fn default() -> Self {
        IpAddr::V4([0; 4])
    }
}

/// A transport endpoint: IP address and TCP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SocketAddr {
    /// IP address.
    pub ip: IpAddr,
    /// TCP port.
    pub port: u16,
}

impl SocketAddr {
    /// Construct an endpoint.
    pub const fn new(ip: IpAddr, port: u16) -> Self {
        SocketAddr { ip, port }
    }
}

/// Opaque handle to a connection slot.
///
/// Contains a generation counter so a stale handle to a recycled slot is
/// detected instead of aliasing a new connection (ABA safety). The counter
/// is 32 bits: at one slot reuse per millisecond it takes ~50 days to wrap,
/// versus ~1 minute for a 16-bit counter — placing ABA collisions outside
/// any realistic stale-handle or stale-timer lifetime (S-GEN-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SocketId {
    pub(crate) index: u8,
    pub(crate) generation: u32,
}

/// Per-connection virtual timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerKind {
    /// Retransmission timer (RFC 6298).
    Rexmit,
    /// Zero-window persist timer (RFC 9293 §3.8.6.1).
    Persist,
    /// Delayed-ACK timer (RFC 1122 §4.2.3.2).
    DelAck,
    /// Connection lifetime timer: TIME-WAIT 2*MSL (RFC 9293 §3.4.1) and the
    /// FIN-WAIT-2 idle timeout share this slot (they are mutually exclusive).
    Wait,
}

/// Identifies a virtual timer owned by the core.
///
/// Re-arming an already-armed key reschedules it; the runtime keeps at most
/// one pending expiry per key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerKey {
    /// A per-connection timer.
    Conn {
        /// Owning connection.
        sock: SocketId,
        /// Which of the connection's timers.
        kind: TimerKind,
    },
    /// Reassembly timeout for one reassembly slot.
    Reasm {
        /// Slot index within the reassembler.
        slot: u8,
        /// Slot generation. Like [`SocketId::generation`], this lets the
        /// stack detect a stale fire for a recycled slot instead of evicting
        /// the wrong datagram (S-GEN-1).
        generation: u8,
    },
}

/// Environment events fed into the core.
///
/// API calls ([`crate::Stack::connect`], `send`, `recv`, `close`, …) are the
/// remaining inputs; a replaying runtime records those calls alongside these
/// events to reproduce a run exactly.
#[derive(Debug, Clone, Copy)]
pub enum Event<'a> {
    /// A whole IP datagram arrived from the link-layer adapter.
    DatagramReceived(&'a [u8]),
    /// A timer previously started via [`Action::StartTimer`] expired.
    TimerExpired(TimerKey),
    /// Entropy supplied in response to [`Action::RequestEntropy`].
    EntropyProvided([u8; 16]),
}

/// Notifications to the application embedded in the action stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEvent {
    /// A connection reached ESTABLISHED. `via_listener` carries the local
    /// listening port for passively accepted connections.
    Connected {
        /// The connection.
        sock: SocketId,
        /// Listening port that accepted it, if passive.
        via_listener: Option<u16>,
    },
    /// Received data became available to read.
    Readable {
        /// The connection.
        sock: SocketId,
    },
    /// Send-buffer space became available after pressure.
    Writable {
        /// The connection.
        sock: SocketId,
    },
    /// The peer finished sending (FIN received); reads will drain then EOF.
    PeerFinReceived {
        /// The connection.
        sock: SocketId,
    },
    /// The connection no longer exists; the handle is invalid after this.
    Closed {
        /// The connection.
        sock: SocketId,
        /// Why it went away.
        reason: CloseReason,
    },
}

/// Why a connection was destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Normal close handshake completed (or TIME-WAIT expired).
    Normal,
    /// The peer reset the connection.
    Reset,
    /// Active open was refused (RST in SYN-SENT).
    Refused,
    /// Retransmission limit exhausted (RFC 1122 R2) or handshake timeout.
    TimedOut,
    /// An ICMP hard error (e.g. port/protocol unreachable) aborted it.
    Unreachable,
    /// The local application aborted it.
    Aborted,
}

/// Outputs of the core, drained via [`crate::Stack::poll_action`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Action {
    /// Placeholder for fixed-capacity queue initialization; never returned
    /// by [`crate::Stack::poll_action`].
    #[default]
    None,
    /// One whole IP datagram of `len` bytes was written into the buffer
    /// passed to [`crate::Stack::poll_action`]; transmit it.
    Transmit {
        /// Datagram length in bytes.
        len: usize,
    },
    /// (Re)start virtual timer `key` to fire `after` from now.
    StartTimer {
        /// Timer identity.
        key: TimerKey,
        /// Delay from the `now` passed to `poll_action`.
        after: Duration,
    },
    /// Cancel virtual timer `key` if pending.
    CancelTimer {
        /// Timer identity.
        key: TimerKey,
    },
    /// Provide 16 bytes of entropy via [`Event::EntropyProvided`].
    /// Required before connections can be opened (RFC 6528).
    RequestEntropy,
    /// Application notification.
    App(AppEvent),
}

/// Errors returned by API calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// All connection slots are in use.
    NoSlot,
    /// Entropy has not been provided yet (answer [`Action::RequestEntropy`]).
    NeedEntropy,
    /// Unknown or stale [`SocketId`].
    NotFound,
    /// Operation invalid in the connection's current state.
    InvalidState,
    /// No buffer space (send) or table space (listen) available.
    BufferFull,
    /// The 4-tuple or listening port is already in use.
    AddrInUse,
    /// No local address of a matching family is configured.
    Unaddressable,
    /// The connection was reset or aborted; only `recv` of buffered data
    /// remains valid.
    ConnectionGone,
}

impl Error {
    /// A stable, human-readable description (available in `no_std`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Error::NoSlot => "no free connection slot",
            Error::NeedEntropy => "entropy not yet provided",
            Error::NotFound => "unknown or stale socket handle",
            Error::InvalidState => "operation invalid in current state",
            Error::BufferFull => "no buffer or table space available",
            Error::AddrInUse => "address or port already in use",
            Error::Unaddressable => "no local address of a matching family",
            Error::ConnectionGone => "connection reset or aborted",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v6_groups_encode_big_endian() {
        let IpAddr::V6(b) = IpAddr::v6([0xfc00, 0, 0, 0, 0, 0, 0, 1]) else {
            panic!()
        };
        assert_eq!(b[0], 0xfc);
        assert_eq!(b[1], 0x00);
        assert_eq!(b[15], 1);
    }

    #[test]
    fn family_checks() {
        let a = IpAddr::v4(10, 0, 0, 1);
        let b = IpAddr::v6([0xfc00, 0, 0, 0, 0, 0, 0, 1]);
        assert!(a.is_v4() && !b.is_v4());
        assert!(!a.same_family(&b));
    }

    #[test]
    fn unicast_source_filter() {
        // Valid unicast sources.
        assert!(IpAddr::v4(10, 0, 0, 1).is_unicast_source());
        assert!(IpAddr::v4(223, 255, 255, 255).is_unicast_source());
        assert!(IpAddr::v6([0xfc00, 0, 0, 0, 0, 0, 0, 1]).is_unicast_source());
        // Martians.
        assert!(!IpAddr::v4(0, 0, 0, 0).is_unicast_source());
        assert!(!IpAddr::v4(127, 0, 0, 1).is_unicast_source());
        assert!(!IpAddr::v4(224, 0, 0, 1).is_unicast_source()); // multicast
        assert!(!IpAddr::v4(255, 255, 255, 255).is_unicast_source()); // broadcast
        assert!(!IpAddr::v4(240, 0, 0, 1).is_unicast_source()); // reserved
        assert!(!IpAddr::v6([0; 8]).is_unicast_source()); // ::
        assert!(!IpAddr::v6([0, 0, 0, 0, 0, 0, 0, 1]).is_unicast_source()); // ::1
        assert!(!IpAddr::v6([0xff02, 0, 0, 0, 0, 0, 0, 1]).is_unicast_source()); // multicast
    }
}
