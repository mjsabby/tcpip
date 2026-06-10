//! IPv6 header parsing and emission (RFC 8200).

use super::{WireError, read_u16, read_u32, write_u16};

/// Fixed IPv6 header length.
pub const HEADER_LEN: usize = 40;

/// Minimum IPv6 link MTU (RFC 8200 §5).
pub const MIN_MTU: u16 = 1280;

const NEXT_HOP_BY_HOP: u8 = 0;
const NEXT_ROUTING: u8 = 43;
const NEXT_FRAGMENT: u8 = 44;
const NEXT_DEST_OPTS: u8 = 60;
const NEXT_NO_NEXT: u8 = 59;

/// Bound on extension headers walked before declaring the chain hostile.
const MAX_EXT_HEADERS: usize = 8;

/// Fragment-header information (RFC 8200 §4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragInfo {
    /// Identification value (reassembly key component).
    pub ident: u32,
    /// Fragment offset in bytes (already multiplied by 8).
    pub offset: u16,
    /// More-fragments flag.
    pub more: bool,
    /// Next-header of the *reassembled* payload (meaningful on offset 0).
    pub next: u8,
}

/// A parsed IPv6 datagram's addressing and payload identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Header {
    /// Source address.
    pub src: [u8; 16],
    /// Destination address.
    pub dst: [u8; 16],
    /// Hop limit as received.
    pub hop_limit: u8,
    /// Upper-layer protocol of the returned payload. For a fragment this is
    /// the protocol carried *inside the fragment header* chain position; use
    /// [`FragInfo::next`] for the reassembled datagram's protocol.
    pub proto: u8,
    /// Present when a fragment header was found; the returned payload is
    /// then the fragment data, not a complete upper-layer payload.
    pub frag: Option<FragInfo>,
}

/// Parse an IPv6 datagram: fixed header plus extension-header walk.
///
/// Hop-by-hop, routing and destination-options headers are length-validated
/// and skipped without interpreting their contents — this host is not a
/// router and requests no options (deviation from RFC 8200 §4.2 option
/// action bits is documented in `docs/TRACEABILITY.md`, D-IPV6-1). A
/// fragment header terminates the walk and is reported via `frag`.
pub fn parse(data: &[u8]) -> Result<(Ipv6Header, &[u8]), WireError> {
    if data.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    if data[0] >> 4 != 6 {
        return Err(WireError::BadVersion);
    }
    let payload_len = read_u16(data, 4) as usize;
    if HEADER_LEN + payload_len > data.len() {
        return Err(WireError::Truncated);
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    dst.copy_from_slice(&data[24..40]);

    // Walk extension headers within the declared payload.
    let end = HEADER_LEN + payload_len;
    let mut next = data[6];
    let mut at = HEADER_LEN;
    let mut frag = None;
    for _ in 0..MAX_EXT_HEADERS {
        match next {
            NEXT_HOP_BY_HOP | NEXT_ROUTING | NEXT_DEST_OPTS => {
                if at + 2 > end {
                    return Err(WireError::BadExtensionHeader);
                }
                let ext_len = 8 + data[at + 1] as usize * 8;
                if at + ext_len > end {
                    return Err(WireError::BadExtensionHeader);
                }
                next = data[at];
                at += ext_len;
            }
            NEXT_FRAGMENT => {
                if at + 8 > end {
                    return Err(WireError::BadExtensionHeader);
                }
                let off_flags = read_u16(data, at + 2);
                frag = Some(FragInfo {
                    ident: read_u32(data, at + 4),
                    offset: (off_flags & !0x7) >> 3 << 3, // bytes: raw_units*8
                    more: off_flags & 0x1 != 0,
                    next: data[at],
                });
                at += 8;
                // Fragment data follows; do not walk further (any inner
                // headers belong to the reassembled datagram).
                return Ok((
                    Ipv6Header { src, dst, hop_limit: data[7], proto: data[at - 8], frag },
                    &data[at..end],
                ));
            }
            NEXT_NO_NEXT => {
                return Ok((
                    Ipv6Header { src, dst, hop_limit: data[7], proto: next, frag },
                    &data[end..end],
                ));
            }
            _ => {
                // Upper-layer protocol (TCP, ICMPv6, or something we will
                // ignore at the dispatch layer).
                return Ok((
                    Ipv6Header { src, dst, hop_limit: data[7], proto: next, frag },
                    &data[at..end],
                ));
            }
        }
    }
    Err(WireError::BadExtensionHeader)
}

/// Quoted-datagram fields: `(src, dst, next_header, rest)`.
pub type QuoteFields<'a> = ([u8; 16], [u8; 16], u8, &'a [u8]);

/// Parse the (possibly truncated) IPv6 datagram quoted inside an ICMPv6
/// error (RFC 4443 §3: as much of the offending packet as fits). Only the
/// fixed header is read; if extension headers precede the transport header
/// the caller will fail to match a connection and drop the message.
pub fn parse_quote(data: &[u8]) -> Result<QuoteFields<'_>, WireError> {
    if data.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    if data[0] >> 4 != 6 {
        return Err(WireError::BadVersion);
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    dst.copy_from_slice(&data[24..40]);
    Ok((src, dst, data[6], &data[HEADER_LEN..]))
}

/// Write a 40-byte IPv6 header for `payload_len` bytes of `next` protocol
/// into `buf[..40]`; returns [`HEADER_LEN`]. No extension headers are ever
/// emitted by this stack.
pub fn emit(
    src: &[u8; 16],
    dst: &[u8; 16],
    next: u8,
    hop_limit: u8,
    payload_len: usize,
    buf: &mut [u8],
) -> usize {
    debug_assert!(payload_len <= u16::MAX as usize);
    buf[0] = 0x60; // version 6, traffic class / flow label zero
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    write_u16(buf, 4, payload_len as u16);
    buf[6] = next;
    buf[7] = hop_limit;
    buf[8..24].copy_from_slice(src);
    buf[24..40].copy_from_slice(dst);
    HEADER_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: [u8; 16] = [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const DST: [u8; 16] = [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    #[test]
    fn emit_parse_round_trip() {
        let mut buf = [0u8; 64];
        let hl = emit(&SRC, &DST, super::super::proto::TCP, 64, 4, &mut buf);
        buf[hl..hl + 4].copy_from_slice(b"abcd");
        let (h, payload) = parse(&buf[..hl + 4]).unwrap();
        assert_eq!(h.src, SRC);
        assert_eq!(h.dst, DST);
        assert_eq!(h.proto, 6);
        assert_eq!(h.hop_limit, 64);
        assert!(h.frag.is_none());
        assert_eq!(payload, b"abcd");
    }

    #[test]
    fn walks_extension_headers() {
        let mut buf = [0u8; 80];
        emit(&SRC, &DST, NEXT_HOP_BY_HOP, 64, 8 + 4, &mut buf);
        // Hop-by-hop: next = TCP, len = 0 (8 bytes), padded options.
        buf[40] = super::super::proto::TCP;
        buf[41] = 0;
        buf[48..52].copy_from_slice(b"abcd");
        let (h, payload) = parse(&buf[..52]).unwrap();
        assert_eq!(h.proto, 6);
        assert_eq!(payload, b"abcd");
    }

    #[test]
    fn parses_fragment_header() {
        let mut buf = [0u8; 80];
        emit(&SRC, &DST, NEXT_FRAGMENT, 64, 8 + 8, &mut buf);
        buf[40] = super::super::proto::TCP; // inner next
        buf[41] = 0;
        // offset 16 bytes => raw units 2 => bits 3..15; M=1.
        write_u16(&mut buf, 42, (2 << 3) | 1);
        buf[44..48].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        buf[48..56].copy_from_slice(b"01234567");
        let (h, payload) = parse(&buf[..56]).unwrap();
        let f = h.frag.unwrap();
        assert_eq!(f.ident, 0xdead_beef);
        assert_eq!(f.offset, 16);
        assert!(f.more);
        assert_eq!(f.next, 6);
        assert_eq!(payload, b"01234567");
    }

    #[test]
    fn rejects_malformed() {
        let mut buf = [0u8; 64];
        let hl = emit(&SRC, &DST, 6, 64, 4, &mut buf);
        assert_eq!(parse(&buf[..hl - 1]), Err(WireError::Truncated));
        let mut bad = buf;
        bad[0] = 0x45;
        assert_eq!(parse(&bad[..hl + 4]), Err(WireError::BadVersion));
        // Extension header running past the payload end.
        let mut bad = [0u8; 48];
        emit(&SRC, &DST, NEXT_HOP_BY_HOP, 64, 8, &mut bad);
        bad[40] = 6;
        bad[41] = 200; // claims 1608 bytes
        assert_eq!(parse(&bad[..48]), Err(WireError::BadExtensionHeader));
    }
}
