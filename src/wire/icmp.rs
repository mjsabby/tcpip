//! ICMPv4 (RFC 792) and ICMPv6 (RFC 4443) messages.
//!
//! Only what a host TCP stack needs: echo request/reply, destination
//! unreachable, fragmentation-needed / packet-too-big, and time exceeded.
//! Error messages carry a quote of the offending datagram which we parse to
//! locate the affected connection.

use super::checksum::{self, Checksum};
use super::{WireError, read_u16, write_u16};

/// Common minimal ICMP header length (type, code, checksum, 4 "rest" bytes).
pub const HEADER_LEN: usize = 8;

/// ICMPv4 message types and codes used by this stack.
pub mod v4 {
    /// Echo reply.
    pub const ECHO_REPLY: u8 = 0;
    /// Destination unreachable.
    pub const DEST_UNREACHABLE: u8 = 3;
    /// Echo request.
    pub const ECHO_REQUEST: u8 = 8;
    /// Time exceeded.
    pub const TIME_EXCEEDED: u8 = 11;
    /// Code: protocol unreachable (hard error, RFC 1122 §3.2.2.1).
    pub const CODE_PROTO_UNREACHABLE: u8 = 2;
    /// Code: port unreachable (hard error).
    pub const CODE_PORT_UNREACHABLE: u8 = 3;
    /// Code: fragmentation needed and DF set (RFC 1191 PMTUD signal).
    pub const CODE_FRAG_NEEDED: u8 = 4;
}

/// ICMPv6 message types used by this stack.
pub mod v6 {
    /// Destination unreachable.
    pub const DEST_UNREACHABLE: u8 = 1;
    /// Packet too big (RFC 8201 PMTUD signal).
    pub const PACKET_TOO_BIG: u8 = 2;
    /// Time exceeded.
    pub const TIME_EXCEEDED: u8 = 3;
    /// Echo request.
    pub const ECHO_REQUEST: u8 = 128;
    /// Echo reply.
    pub const ECHO_REPLY: u8 = 129;
    /// Code: port unreachable (hard error).
    pub const CODE_PORT_UNREACHABLE: u8 = 4;
}

/// A parsed ICMP message (either family; the caller knows which from the IP
/// protocol number).
#[derive(Debug, Clone, Copy)]
pub struct IcmpMessage {
    /// Message type.
    pub kind: u8,
    /// Message code.
    pub code: u8,
    /// Bytes 4..8 ("rest of header"): echo ident/seq, MTU field, unused…
    pub rest: [u8; 4],
}

impl IcmpMessage {
    /// The MTU carried in an ICMPv6 Packet Too Big message (RFC 4443 §3.2:
    /// full 32-bit field).
    pub fn mtu_v6(&self) -> u32 {
        u32::from_be_bytes(self.rest)
    }

    /// The Next-Hop MTU carried in an ICMPv4 Destination Unreachable /
    /// Fragmentation Needed message (RFC 1191 §4: low 16 bits only; bytes
    /// 4–5 are "unused"). Reading all 32 bits mis-parses any router that
    /// leaves garbage in the unused field, silently discarding a legitimate
    /// PMTU signal (DEF-M7).
    pub fn mtu_v4(&self) -> u16 {
        u16::from_be_bytes([self.rest[2], self.rest[3]])
    }
}

/// Parse an ICMPv4 message; the checksum over the whole message is verified.
/// Returns the message and its body (quote or echo payload).
pub fn parse_v4(data: &[u8]) -> Result<(IcmpMessage, &[u8]), WireError> {
    if data.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    if checksum::over(data) != 0 {
        return Err(WireError::BadChecksum);
    }
    Ok((
        IcmpMessage {
            kind: data[0],
            code: data[1],
            rest: [data[4], data[5], data[6], data[7]],
        },
        &data[HEADER_LEN..],
    ))
}

/// Parse an ICMPv6 message; the checksum includes the IPv6 pseudo-header.
pub fn parse_v6<'a>(
    data: &'a [u8],
    src: &[u8; 16],
    dst: &[u8; 16],
) -> Result<(IcmpMessage, &'a [u8]), WireError> {
    if data.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    let mut c = Checksum::new();
    c.add_pseudo_v6(src, dst, super::proto::ICMPV6, data.len() as u32);
    c.add_bytes(data);
    if c.finish() != 0 {
        return Err(WireError::BadChecksum);
    }
    Ok((
        IcmpMessage {
            kind: data[0],
            code: data[1],
            rest: [data[4], data[5], data[6], data[7]],
        },
        &data[HEADER_LEN..],
    ))
}

/// Emit an ICMPv4 message into `buf`; returns the total length.
pub fn emit_v4(kind: u8, code: u8, rest: [u8; 4], body: &[u8], buf: &mut [u8]) -> usize {
    let total = HEADER_LEN + body.len();
    buf[0] = kind;
    buf[1] = code;
    write_u16(buf, 2, 0);
    buf[4..8].copy_from_slice(&rest);
    buf[HEADER_LEN..total].copy_from_slice(body);
    let cks = checksum::over(&buf[..total]);
    write_u16(buf, 2, cks);
    total
}

/// Emit an ICMPv6 message (checksum needs the enclosing datagram's
/// addresses); returns the total length.
pub fn emit_v6(
    kind: u8,
    code: u8,
    rest: [u8; 4],
    body: &[u8],
    src: &[u8; 16],
    dst: &[u8; 16],
    buf: &mut [u8],
) -> usize {
    let total = HEADER_LEN + body.len();
    buf[0] = kind;
    buf[1] = code;
    write_u16(buf, 2, 0);
    buf[4..8].copy_from_slice(&rest);
    buf[HEADER_LEN..total].copy_from_slice(body);
    let mut c = Checksum::new();
    c.add_pseudo_v6(src, dst, super::proto::ICMPV6, total as u32);
    c.add_bytes(&buf[..total]);
    let cks = c.finish();
    write_u16(buf, 2, cks);
    total
}

/// The TCP fields a quoted datagram exposes (RFC 792 guarantees the IP
/// header plus at least 8 bytes of payload: ports and sequence number).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotedTcp {
    /// Source port of the quoted (our transmitted) segment.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number of the quoted segment.
    pub seq: u32,
}

/// Extract the quoted TCP fields from an upper-layer byte slice.
pub fn quoted_tcp(l4: &[u8]) -> Result<QuotedTcp, WireError> {
    if l4.len() < 8 {
        return Err(WireError::Truncated);
    }
    Ok(QuotedTcp {
        src_port: read_u16(l4, 0),
        dst_port: read_u16(l4, 2),
        seq: super::read_u32(l4, 4),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_round_trip() {
        let mut buf = [0u8; 64];
        let len = emit_v4(v4::ECHO_REQUEST, 0, [0, 1, 0, 2], b"payload", &mut buf);
        let (m, body) = parse_v4(&buf[..len]).unwrap();
        assert_eq!(m.kind, v4::ECHO_REQUEST);
        assert_eq!(m.rest, [0, 1, 0, 2]);
        assert_eq!(body, b"payload");
        let mut bad = buf;
        bad[4] ^= 0xff;
        assert_eq!(parse_v4(&bad[..len]).unwrap_err(), WireError::BadChecksum);
    }

    #[test]
    fn v6_round_trip_with_pseudo() {
        let s = [1u8; 16];
        let d = [2u8; 16];
        let mut buf = [0u8; 64];
        let len = emit_v6(v6::ECHO_REPLY, 0, [0; 4], b"abc", &s, &d, &mut buf);
        let (m, body) = parse_v6(&buf[..len], &s, &d).unwrap();
        assert_eq!(m.kind, v6::ECHO_REPLY);
        assert_eq!(body, b"abc");
        // Wrong pseudo-header must fail (note: swapping src/dst would NOT
        // change the sum — ones-complement addition is commutative).
        let other = [3u8; 16];
        assert!(parse_v6(&buf[..len], &other, &d).is_err());
    }

    #[test]
    fn quoted_tcp_fields() {
        let mut l4 = [0u8; 12];
        write_u16(&mut l4, 0, 8080);
        write_u16(&mut l4, 2, 443);
        l4[4..8].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        let q = quoted_tcp(&l4).unwrap();
        assert_eq!(
            q,
            QuotedTcp {
                src_port: 8080,
                dst_port: 443,
                seq: 0xdead_beef
            }
        );
        assert_eq!(quoted_tcp(&l4[..7]).unwrap_err(), WireError::Truncated);
    }

    #[test]
    fn mtu_field() {
        // RFC 1191: bytes 4–5 are unused; only 6–7 carry the MTU. A router
        // leaving garbage in the unused bytes must still be understood.
        let m = IcmpMessage {
            kind: v4::DEST_UNREACHABLE,
            code: v4::CODE_FRAG_NEEDED,
            rest: [0xAB, 0xCD, 0x05, 0xdc],
        };
        assert_eq!(m.mtu_v4(), 1500);
        assert_eq!(m.mtu_v6(), 0xABCD_05DC);
    }
}
