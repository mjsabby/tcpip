//! IPv4 header parsing and emission (RFC 791).

use super::checksum::{self, Checksum};
use super::{WireError, read_u16, write_u16};

/// Minimum (and, on egress, only) IPv4 header length.
pub const HEADER_LEN: usize = 20;

/// Flag bit: don't fragment.
const FLAG_DF: u16 = 0x4000;
/// Flag bit: more fragments.
const FLAG_MF: u16 = 0x2000;

/// A parsed IPv4 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    /// Source address.
    pub src: [u8; 4],
    /// Destination address.
    pub dst: [u8; 4],
    /// Upper-layer protocol number.
    pub proto: u8,
    /// Time to live as received.
    pub ttl: u8,
    /// Identification field (reassembly key component).
    pub ident: u16,
    /// Don't-fragment flag.
    pub dont_frag: bool,
    /// More-fragments flag.
    pub more_frags: bool,
    /// Fragment offset in bytes (already multiplied by 8).
    pub frag_offset: u16,
    /// Header length in bytes (>= 20 when options are present).
    pub header_len: u8,
    /// Total datagram length from the header.
    pub total_len: u16,
}

impl Ipv4Header {
    /// True if this datagram is a fragment (of any position).
    pub fn is_fragment(&self) -> bool {
        self.more_frags || self.frag_offset != 0
    }
}

/// Parse and validate an IPv4 datagram; returns the header and the payload.
///
/// Validates version, header length, total length and the header checksum
/// (RFC 1122 §3.2.1.2: a datagram with a bad checksum MUST be discarded).
/// IP options are length-validated and skipped: this host never acts on
/// source routes (PLAN.md: source routing disabled).
pub fn parse(data: &[u8]) -> Result<(Ipv4Header, &[u8]), WireError> {
    let header = parse_header(data, true)?;
    let hlen = header.header_len as usize;
    let total = header.total_len as usize;
    if total < hlen {
        return Err(WireError::BadLength);
    }
    if total > data.len() {
        return Err(WireError::Truncated);
    }
    // Anything past total_len is link-layer padding; ignore it.
    Ok((header, &data[hlen..total]))
}

/// Parse an IPv4 header from an ICMP error quote, where the quoted datagram
/// is intentionally truncated (RFC 792: header + first 8 payload bytes).
/// The header checksum is still verified; `total_len` is not compared with
/// the buffer. Returns the header and whatever quoted payload is present.
pub fn parse_quote(data: &[u8]) -> Result<(Ipv4Header, &[u8]), WireError> {
    let header = parse_header(data, true)?;
    Ok((header, &data[header.header_len as usize..]))
}

fn parse_header(data: &[u8], verify_checksum: bool) -> Result<Ipv4Header, WireError> {
    if data.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    if data[0] >> 4 != 4 {
        return Err(WireError::BadVersion);
    }
    let hlen = ((data[0] & 0x0f) as usize) * 4;
    if !(HEADER_LEN..=60).contains(&hlen) || hlen > data.len() {
        return Err(WireError::BadHeaderLen);
    }
    if verify_checksum && checksum::over(&data[..hlen]) != 0 {
        return Err(WireError::BadChecksum);
    }
    let flags_frag = read_u16(data, 6);
    Ok(Ipv4Header {
        src: [data[12], data[13], data[14], data[15]],
        dst: [data[16], data[17], data[18], data[19]],
        proto: data[9],
        ttl: data[8],
        ident: read_u16(data, 4),
        dont_frag: flags_frag & FLAG_DF != 0,
        more_frags: flags_frag & FLAG_MF != 0,
        frag_offset: (flags_frag & 0x1fff) * 8,
        header_len: hlen as u8,
        total_len: read_u16(data, 2),
    })
}

/// Fields for emitting an IPv4 header (always 20 bytes, no options).
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Emit {
    /// Source address.
    pub src: [u8; 4],
    /// Destination address.
    pub dst: [u8; 4],
    /// Upper-layer protocol number.
    pub proto: u8,
    /// Time to live.
    pub ttl: u8,
    /// Identification field.
    pub ident: u16,
    /// Set the DF flag (used for path MTU discovery, RFC 1191 §3).
    pub dont_frag: bool,
    /// Set the MF flag (emitting a non-final fragment).
    pub more_frags: bool,
    /// Fragment offset in bytes (must be a multiple of 8).
    pub frag_offset: u16,
}

impl Ipv4Emit {
    /// Plain unfragmented datagram fields.
    pub fn datagram(src: [u8; 4], dst: [u8; 4], proto: u8, ttl: u8, ident: u16, df: bool) -> Self {
        Ipv4Emit {
            src,
            dst,
            proto,
            ttl,
            ident,
            dont_frag: df,
            more_frags: false,
            frag_offset: 0,
        }
    }

    /// Write the 20-byte header for a payload of `payload_len` bytes into
    /// `buf[..20]` and return [`HEADER_LEN`]. The caller writes the payload
    /// at `buf[20..]`.
    pub fn emit(&self, payload_len: usize, buf: &mut [u8]) -> usize {
        debug_assert!(self.frag_offset % 8 == 0);
        let total = HEADER_LEN + payload_len;
        debug_assert!(total <= u16::MAX as usize);
        buf[0] = 0x45; // version 4, IHL 5
        buf[1] = 0; // DSCP/ECN zero
        write_u16(buf, 2, total as u16);
        write_u16(buf, 4, self.ident);
        let mut flags_frag = self.frag_offset / 8;
        if self.dont_frag {
            flags_frag |= FLAG_DF;
        }
        if self.more_frags {
            flags_frag |= FLAG_MF;
        }
        write_u16(buf, 6, flags_frag);
        buf[8] = self.ttl;
        buf[9] = self.proto;
        write_u16(buf, 10, 0);
        buf[12..16].copy_from_slice(&self.src);
        buf[16..20].copy_from_slice(&self.dst);
        let mut c = Checksum::new();
        c.add_bytes(&buf[..HEADER_LEN]);
        write_u16(buf, 10, c.finish());
        HEADER_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_parse_round_trip() {
        let mut buf = [0u8; 64];
        let emit =
            Ipv4Emit::datagram([10, 0, 0, 1], [10, 0, 0, 2], super::super::proto::TCP, 64, 7, true);
        let hl = emit.emit(4, &mut buf);
        buf[hl..hl + 4].copy_from_slice(b"abcd");
        let (h, payload) = parse(&buf[..hl + 4]).unwrap();
        assert_eq!(h.src, [10, 0, 0, 1]);
        assert_eq!(h.dst, [10, 0, 0, 2]);
        assert_eq!(h.proto, 6);
        assert_eq!(h.ttl, 64);
        assert_eq!(h.ident, 7);
        assert!(h.dont_frag && !h.more_frags && h.frag_offset == 0);
        assert!(!h.is_fragment());
        assert_eq!(payload, b"abcd");
    }

    #[test]
    fn fragment_fields_round_trip() {
        let mut buf = [0u8; 64];
        let emit = Ipv4Emit {
            src: [1, 1, 1, 1],
            dst: [2, 2, 2, 2],
            proto: 6,
            ttl: 64,
            ident: 99,
            dont_frag: false,
            more_frags: true,
            frag_offset: 24,
        };
        let hl = emit.emit(8, &mut buf);
        let (h, _) = parse(&buf[..hl + 8]).unwrap();
        assert!(h.more_frags && h.frag_offset == 24 && h.is_fragment());
    }

    #[test]
    fn rejects_malformed() {
        let mut buf = [0u8; 64];
        let emit = Ipv4Emit::datagram([1, 1, 1, 1], [2, 2, 2, 2], 6, 64, 0, false);
        let hl = emit.emit(4, &mut buf);
        let len = hl + 4;
        assert_eq!(parse(&buf[..10]), Err(WireError::Truncated));
        let mut bad = buf;
        bad[0] = 0x65; // version 6
        assert_eq!(parse(&bad[..len]), Err(WireError::BadVersion));
        let mut bad = buf;
        bad[0] = 0x44; // IHL 4 < 5
        assert_eq!(parse(&bad[..len]), Err(WireError::BadHeaderLen));
        let mut bad = buf;
        bad[8] ^= 0xff; // corrupt TTL -> checksum fails
        assert_eq!(parse(&bad[..len]), Err(WireError::BadChecksum));
        let mut bad = buf;
        bad[2] = 0;
        bad[3] = 19; // total_len < header_len (re-checksum to reach the check)
        write_u16(&mut bad, 10, 0);
        let mut c = Checksum::new();
        c.add_bytes(&bad[..20]);
        let cks = c.finish();
        write_u16(&mut bad, 10, cks);
        assert_eq!(parse(&bad[..len]), Err(WireError::BadLength));
    }
}
