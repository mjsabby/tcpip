//! IP-layer state machines: fragment reassembly, egress fragmentation and
//! the path-MTU cache.
//!
//! Datagram demultiplexing itself lives in [`crate::Stack`]; this module
//! holds the stateful pieces, each a deterministic fixed-capacity machine.

pub mod frag;
pub mod pmtu;
pub mod reasm;

use crate::types::IpAddr;

/// Identifies one datagram under reassembly (RFC 791 §2.3: source,
/// destination, protocol, identification; RFC 8200 §4.5: source,
/// destination, identification).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReasmKey {
    /// Source address of the fragments.
    pub src: IpAddr,
    /// Destination address of the fragments.
    pub dst: IpAddr,
    /// Upper-layer protocol (for IPv6 this is the fragment header's
    /// next-header value from the first fragment).
    pub proto: u8,
    /// Identification field (u16 for IPv4 zero-extended to u32).
    pub ident: u32,
}

/// Practical lower bound applied to IPv4 path-MTU estimates. RFC 1191
/// permits 68, but every modern path supports 576 and flooring here bounds
/// worst-case segment counts (R-PMTU-3).
pub const IPV4_MIN_PMTU: u16 = 576;
/// IPv6 minimum link MTU (RFC 8200 §5).
pub const IPV6_MIN_PMTU: u16 = 1280;
