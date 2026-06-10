//! Wire formats: parsing and emission of protocol headers.
//!
//! Parsers take raw bytes and return typed headers plus payload slices,
//! rejecting anything malformed (every length is checked, every checksum is
//! verified before any field is acted upon). Emitters write into
//! caller-provided buffers and never allocate.

pub mod checksum;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;

/// IP protocol numbers used by this stack.
pub mod proto {
    /// ICMP (IPv4).
    pub const ICMP: u8 = 1;
    /// TCP.
    pub const TCP: u8 = 6;
    /// ICMPv6.
    pub const ICMPV6: u8 = 58;
}

/// Errors produced by wire parsers.
///
/// All of these result in the datagram being dropped (RFC 1122 §3.2.1.1:
/// silently discard malformed datagrams); they are surfaced for diagnostics
/// and test assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Buffer shorter than the structure it should contain.
    Truncated,
    /// IP version field does not match the parser.
    BadVersion,
    /// Header length field out of range.
    BadHeaderLen,
    /// Checksum verification failed.
    BadChecksum,
    /// Malformed TCP option.
    BadOption,
    /// IPv6 extension-header chain too long or malformed.
    BadExtensionHeader,
    /// A length field is inconsistent with the buffer.
    BadLength,
}

#[inline]
pub(crate) fn read_u16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

#[inline]
pub(crate) fn read_u32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

#[inline]
pub(crate) fn write_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

#[inline]
pub(crate) fn write_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}
