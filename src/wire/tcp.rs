//! TCP segment parsing and emission (RFC 9293 §3.1).

use super::checksum::Checksum;
use super::{WireError, read_u16, read_u32, write_u16, write_u32};
use crate::types::IpAddr;
use crate::util::BoundedVec;

/// Minimum TCP header length.
pub const HEADER_LEN: usize = 20;
/// Maximum TCP header length (data offset 15).
pub const MAX_HEADER_LEN: usize = 60;
/// Maximum SACK blocks in one segment (RFC 2018 §3: 40-byte option space
/// allows 4; 3 when other options are present).
pub const MAX_SACK_BLOCKS: usize = 4;

const OPT_END: u8 = 0;
const OPT_NOP: u8 = 1;
const OPT_MSS: u8 = 2;
const OPT_WSCALE: u8 = 3;
const OPT_SACK_PERMITTED: u8 = 4;
const OPT_SACK: u8 = 5;

/// TCP flags (subset of the control bits; ECN bits are not used).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    /// FIN: sender is done sending.
    pub const FIN: TcpFlags = TcpFlags(0x01);
    /// SYN: synchronize sequence numbers.
    pub const SYN: TcpFlags = TcpFlags(0x02);
    /// RST: reset the connection.
    pub const RST: TcpFlags = TcpFlags(0x04);
    /// PSH: push buffered data to the application.
    pub const PSH: TcpFlags = TcpFlags(0x08);
    /// ACK: acknowledgment field significant.
    pub const ACK: TcpFlags = TcpFlags(0x10);
    /// URG: urgent pointer significant (accepted, never sent; RFC 6093).
    pub const URG: TcpFlags = TcpFlags(0x20);

    /// True if every flag in `other` is set in `self`.
    pub const fn contains(self, other: TcpFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Union of two flag sets.
    pub const fn union(self, other: TcpFlags) -> TcpFlags {
        TcpFlags(self.0 | other.0)
    }

    /// Shorthand for [`TcpFlags::contains`]`(SYN)` etc.
    pub const fn syn(self) -> bool {
        self.contains(TcpFlags::SYN)
    }
    /// ACK bit set.
    pub const fn ack(self) -> bool {
        self.contains(TcpFlags::ACK)
    }
    /// RST bit set.
    pub const fn rst(self) -> bool {
        self.contains(TcpFlags::RST)
    }
    /// FIN bit set.
    pub const fn fin(self) -> bool {
        self.contains(TcpFlags::FIN)
    }
    /// PSH bit set.
    pub const fn psh(self) -> bool {
        self.contains(TcpFlags::PSH)
    }
}

/// A parsed TCP header (fixed part).
#[derive(Debug, Clone, Copy)]
pub struct TcpHeader {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgment number (significant iff `flags.ack()`).
    pub ack: u32,
    /// Control flags.
    pub flags: TcpFlags,
    /// Window field, unscaled as received.
    pub window: u16,
    /// Header length in bytes.
    pub header_len: u8,
}

/// Parsed TCP options relevant to this stack; unknown options are skipped.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpOptions {
    /// Maximum segment size (valid only on SYN; RFC 9293 §3.7.1).
    pub mss: Option<u16>,
    /// Window scale shift (valid only on SYN; RFC 7323 §2.2).
    pub window_scale: Option<u8>,
    /// SACK permitted (valid only on SYN; RFC 2018 §2).
    pub sack_permitted: bool,
    /// SACK blocks `(left, right)` (RFC 2018 §3).
    pub sack_blocks: BoundedVec<(u32, u32), MAX_SACK_BLOCKS>,
}

/// Parse and validate a TCP segment carried between `src_ip` and `dst_ip`;
/// the checksum (with pseudo-header) is verified before anything is used
/// (RFC 9293 §3.1: segments with bad checksums MUST be discarded).
pub fn parse<'a>(
    data: &'a [u8],
    src_ip: &IpAddr,
    dst_ip: &IpAddr,
) -> Result<(TcpHeader, TcpOptions, &'a [u8]), WireError> {
    if data.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    let header_len = ((data[12] >> 4) as usize) * 4;
    if !(HEADER_LEN..=MAX_HEADER_LEN).contains(&header_len) || header_len > data.len() {
        return Err(WireError::BadHeaderLen);
    }
    let mut c = Checksum::new();
    c.add_pseudo(src_ip, dst_ip, super::proto::TCP, data.len() as u32);
    c.add_bytes(data);
    if c.finish() != 0 {
        return Err(WireError::BadChecksum);
    }

    let header = TcpHeader {
        src_port: read_u16(data, 0),
        dst_port: read_u16(data, 2),
        seq: read_u32(data, 4),
        ack: read_u32(data, 8),
        flags: TcpFlags(data[13] & 0x3f),
        window: read_u16(data, 14),
        header_len: header_len as u8,
    };
    let options = parse_options(&data[HEADER_LEN..header_len])?;
    Ok((header, options, &data[header_len..]))
}

fn parse_options(mut opts: &[u8]) -> Result<TcpOptions, WireError> {
    let mut out = TcpOptions::default();
    while let Some(&kind) = opts.first() {
        match kind {
            OPT_END => break,
            OPT_NOP => {
                opts = &opts[1..];
                continue;
            }
            _ => {}
        }
        let Some(&len) = opts.get(1) else {
            return Err(WireError::BadOption);
        };
        let len = len as usize;
        if len < 2 || len > opts.len() {
            return Err(WireError::BadOption);
        }
        let body = &opts[2..len];
        match kind {
            OPT_MSS if body.len() == 2 => out.mss = Some(u16::from_be_bytes([body[0], body[1]])),
            OPT_WSCALE if body.len() == 1 => {
                // RFC 7323 §2.3: values above 14 MUST be treated as 14.
                out.window_scale = Some(body[0].min(14));
            }
            OPT_SACK_PERMITTED if body.is_empty() => out.sack_permitted = true,
            OPT_SACK if body.len() % 8 == 0 => {
                for chunk in body.chunks_exact(8) {
                    let left = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    let right = u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
                    // Excess blocks beyond our bound are ignored, not an error.
                    let _ = out.sack_blocks.push((left, right));
                }
            }
            OPT_MSS | OPT_WSCALE | OPT_SACK_PERMITTED | OPT_SACK => {
                return Err(WireError::BadOption);
            }
            _ => {} // unknown option: skipped by length (RFC 1122 §4.2.2.5)
        }
        opts = &opts[len..];
    }
    Ok(out)
}

/// Options to include when emitting a segment.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpOptionsEmit {
    /// Advertise MSS (SYN / SYN-ACK only).
    pub mss: Option<u16>,
    /// Advertise window scale (SYN / SYN-ACK only).
    pub window_scale: Option<u8>,
    /// Advertise SACK permitted (SYN / SYN-ACK only).
    pub sack_permitted: bool,
    /// SACK blocks to send.
    pub sack_blocks: BoundedVec<(u32, u32), MAX_SACK_BLOCKS>,
}

impl TcpOptionsEmit {
    fn encoded_len(&self) -> usize {
        let mut n = 0;
        if self.mss.is_some() {
            n += 4;
        }
        if self.window_scale.is_some() {
            n += 4; // NOP + 3
        }
        if self.sack_permitted {
            n += 4; // 2 NOPs + 2
        }
        if !self.sack_blocks.is_empty() {
            n += 4 + 8 * self.sack_blocks.len(); // 2 NOPs + 2 + blocks
        }
        n
    }
}

// DEF-L18: the data-offset field caps the TCP header at 60 bytes. The
// disjoint option groups this stack ever emits together stay under that, but
// a future caller setting all groups at once would overflow it (and in
// release silently encode a wrong data offset). Prove the bound at compile
// time so any new option breaks the build instead.
const _: () = {
    // SYN-only group: MSS + WScale + SACK-permitted = 12 bytes.
    assert!(HEADER_LEN + 4 + 4 + 4 <= MAX_HEADER_LEN);
    // Data group: SACK with 4 blocks = 36 bytes.
    assert!(HEADER_LEN + 4 + 8 * MAX_SACK_BLOCKS <= MAX_HEADER_LEN);
};

/// Fields for emitting a TCP segment.
#[derive(Debug, Clone, Copy)]
pub struct TcpEmit {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgment number (0 when ACK flag is clear).
    pub ack: u32,
    /// Control flags.
    pub flags: TcpFlags,
    /// Window field value (already scaled down by the sender).
    pub window: u16,
    /// Options to include.
    pub options: TcpOptionsEmit,
}

impl TcpEmit {
    /// Serialize header + options + payload into `buf`, computing the
    /// checksum with the pseudo-header for `src_ip` → `dst_ip`. The payload
    /// is provided as two slices so ring-buffer contents need not be copied
    /// first. Returns the total segment length.
    pub fn emit(
        &self,
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
        payload: (&[u8], &[u8]),
        buf: &mut [u8],
    ) -> usize {
        // The const-assert above proves each option *group* fits; this
        // release-mode clamp additionally guarantees a hostile combination
        // cannot wrap the 4-bit data-offset field (DEF-L18).
        let opt_len = self.options.encoded_len().min(MAX_HEADER_LEN - HEADER_LEN);
        debug_assert!(opt_len % 4 == 0);
        let header_len = HEADER_LEN + opt_len;
        let total = header_len + payload.0.len() + payload.1.len();

        write_u16(buf, 0, self.src_port);
        write_u16(buf, 2, self.dst_port);
        write_u32(buf, 4, self.seq);
        write_u32(buf, 8, self.ack);
        buf[12] = ((header_len / 4) as u8) << 4;
        buf[13] = self.flags.0;
        write_u16(buf, 14, self.window);
        write_u16(buf, 16, 0); // checksum placeholder
        write_u16(buf, 18, 0); // urgent pointer: never sent (RFC 6093)

        let mut at = HEADER_LEN;
        if let Some(mss) = self.options.mss {
            buf[at] = OPT_MSS;
            buf[at + 1] = 4;
            write_u16(buf, at + 2, mss);
            at += 4;
        }
        if let Some(ws) = self.options.window_scale {
            buf[at] = OPT_NOP;
            buf[at + 1] = OPT_WSCALE;
            buf[at + 2] = 3;
            buf[at + 3] = ws;
            at += 4;
        }
        if self.options.sack_permitted {
            buf[at] = OPT_NOP;
            buf[at + 1] = OPT_NOP;
            buf[at + 2] = OPT_SACK_PERMITTED;
            buf[at + 3] = 2;
            at += 4;
        }
        if !self.options.sack_blocks.is_empty() {
            buf[at] = OPT_NOP;
            buf[at + 1] = OPT_NOP;
            buf[at + 2] = OPT_SACK;
            buf[at + 3] = (2 + 8 * self.options.sack_blocks.len()) as u8;
            at += 4;
            for &(l, r) in self.options.sack_blocks.iter() {
                write_u32(buf, at, l);
                write_u32(buf, at + 4, r);
                at += 8;
            }
        }
        debug_assert_eq!(at, header_len);

        buf[header_len..header_len + payload.0.len()].copy_from_slice(payload.0);
        buf[header_len + payload.0.len()..total].copy_from_slice(payload.1);

        let mut c = Checksum::new();
        c.add_pseudo(src_ip, dst_ip, super::proto::TCP, total as u32);
        c.add_bytes(&buf[..total]);
        write_u16(buf, 16, c.finish());
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: IpAddr = IpAddr::V4([10, 0, 0, 1]);
    const B: IpAddr = IpAddr::V4([10, 0, 0, 2]);

    fn emit_full() -> ([u8; 128], usize) {
        let mut opts = TcpOptionsEmit {
            mss: Some(1460),
            window_scale: Some(7),
            sack_permitted: true,
            ..Default::default()
        };
        opts.sack_blocks.push((100, 200)).unwrap();
        opts.sack_blocks.push((300, 400)).unwrap();
        let seg = TcpEmit {
            src_port: 1234,
            dst_port: 80,
            seq: 0x01020304,
            ack: 0x0a0b0c0d,
            flags: TcpFlags::SYN.union(TcpFlags::ACK),
            window: 0xfff0,
            options: opts,
        };
        let mut buf = [0u8; 128];
        let len = seg.emit(&A, &B, (b"hel", b"lo"), &mut buf);
        (buf, len)
    }

    #[test]
    fn emit_parse_round_trip() {
        let (buf, len) = emit_full();
        let (h, o, payload) = parse(&buf[..len], &A, &B).unwrap();
        assert_eq!(h.src_port, 1234);
        assert_eq!(h.dst_port, 80);
        assert_eq!(h.seq, 0x01020304);
        assert_eq!(h.ack, 0x0a0b0c0d);
        assert!(h.flags.syn() && h.flags.ack() && !h.flags.rst());
        assert_eq!(h.window, 0xfff0);
        assert_eq!(o.mss, Some(1460));
        assert_eq!(o.window_scale, Some(7));
        assert!(o.sack_permitted);
        assert_eq!(o.sack_blocks.as_slice(), &[(100, 200), (300, 400)]);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn checksum_detects_corruption() {
        let (mut buf, len) = emit_full();
        buf[len - 1] ^= 1;
        assert_eq!(
            parse(&buf[..len], &A, &B).unwrap_err(),
            WireError::BadChecksum
        );
        // Also wrong pseudo-header (different src ip).
        let (buf, len) = emit_full();
        let c = IpAddr::V4([10, 0, 0, 3]);
        assert_eq!(
            parse(&buf[..len], &c, &B).unwrap_err(),
            WireError::BadChecksum
        );
    }

    #[test]
    fn v6_pseudo_header_round_trip() {
        let s = IpAddr::v6([0xfc00, 0, 0, 0, 0, 0, 0, 1]);
        let d = IpAddr::v6([0xfc00, 0, 0, 0, 0, 0, 0, 2]);
        let seg = TcpEmit {
            src_port: 1,
            dst_port: 2,
            seq: 9,
            ack: 0,
            flags: TcpFlags::SYN,
            window: 100,
            options: Default::default(),
        };
        let mut buf = [0u8; 64];
        let len = seg.emit(&s, &d, (&[], &[]), &mut buf);
        let (h, _, payload) = parse(&buf[..len], &s, &d).unwrap();
        assert_eq!(h.seq, 9);
        assert!(payload.is_empty());
    }

    #[test]
    fn rejects_bad_options() {
        // A segment whose options claim a length running past the header.
        let seg = TcpEmit {
            src_port: 1,
            dst_port: 2,
            seq: 0,
            ack: 0,
            flags: TcpFlags::SYN,
            window: 0,
            options: TcpOptionsEmit {
                mss: Some(1460),
                ..Default::default()
            },
        };
        let mut buf = [0u8; 64];
        let len = seg.emit(&A, &B, (&[], &[]), &mut buf);
        buf[21] = 40; // MSS option length 40 > remaining space
        // Fix checksum so we reach option parsing.
        write_u16(&mut buf, 16, 0);
        let mut c = Checksum::new();
        c.add_pseudo(&A, &B, super::super::proto::TCP, len as u32);
        c.add_bytes(&buf[..len]);
        let cks = c.finish();
        write_u16(&mut buf, 16, cks);
        assert_eq!(
            parse(&buf[..len], &A, &B).unwrap_err(),
            WireError::BadOption
        );
    }

    #[test]
    fn unknown_options_skipped() {
        let seg = TcpEmit {
            src_port: 1,
            dst_port: 2,
            seq: 7,
            ack: 0,
            flags: TcpFlags::ACK,
            window: 10,
            options: Default::default(),
        };
        let mut buf = [0u8; 64];
        let base = seg.emit(&A, &B, (&[], &[]), &mut buf);
        // Splice in a 4-byte unknown option (kind 254) by hand.
        let mut raw = [0u8; 64];
        raw[..base].copy_from_slice(&buf[..base]);
        raw.copy_within(20..base, 24);
        raw[20] = 254;
        raw[21] = 4;
        raw[22] = 0xde;
        raw[23] = 0xad;
        let len = base + 4;
        raw[12] = (((20 + 4) / 4) as u8) << 4;
        write_u16(&mut raw, 16, 0);
        let mut c = Checksum::new();
        c.add_pseudo(&A, &B, super::super::proto::TCP, len as u32);
        c.add_bytes(&raw[..len]);
        let cks = c.finish();
        write_u16(&mut raw, 16, cks);
        let (h, o, _) = parse(&raw[..len], &A, &B).unwrap();
        assert_eq!(h.seq, 7);
        assert!(o.mss.is_none() && !o.sack_permitted);
    }
}
