//! Fixed-capacity send buffer, generic over its byte capacity.
//!
//! A byte ring holding everything from SND.UNA up to the newest byte the
//! application has written (unacknowledged + unsent). Retransmission reads
//! any range relative to SND.UNA; acknowledgment pops from the front.
//!
//! The capacity `CAP` is a const-generic parameter so each deployment fixes
//! its per-connection send window at compile time (the
//! [`crate::Stack`] threads it through). A power-of-two `CAP`
//! lets the compiler lower the ring's `% CAP` to a mask.

/// Send-side byte ring of capacity `CAP`. Offset 0 always corresponds to
/// SND.UNA.
pub struct SendBuffer<const CAP: usize> {
    buf: [u8; CAP],
    /// Ring index of offset 0 (SND.UNA).
    start: usize,
    /// Bytes stored (unacked + unsent).
    len: usize,
}

impl<const CAP: usize> Default for SendBuffer<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> SendBuffer<CAP> {
    /// An empty buffer.
    pub const fn new() -> Self {
        SendBuffer { buf: [0; CAP], start: 0, len: 0 }
    }

    /// Total capacity in bytes.
    pub const fn capacity(&self) -> usize {
        CAP
    }

    /// Bytes stored.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Free space.
    pub fn space(&self) -> usize {
        CAP - self.len
    }

    /// Append as much of `data` as fits; returns the number accepted.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.space());
        let from = (self.start + self.len) % CAP;
        let first = n.min(CAP - from);
        self.buf[from..from + first].copy_from_slice(&data[..first]);
        self.buf[..n - first].copy_from_slice(&data[first..n]);
        self.len += n;
        n
    }

    /// Drop `n` bytes from the front (they were cumulatively acknowledged).
    pub fn ack(&mut self, n: usize) {
        debug_assert!(n <= self.len);
        let n = n.min(self.len);
        self.start = (self.start + n) % CAP;
        self.len -= n;
    }

    /// Read `len` bytes at `off` (relative to SND.UNA) as up to two slices
    /// (the range may wrap the ring). Caller guarantees the range is stored.
    pub fn read(&self, off: usize, len: usize) -> (&[u8], &[u8]) {
        debug_assert!(off + len <= self.len);
        let from = (self.start + off) % CAP;
        let first = len.min(CAP - from);
        (&self.buf[from..from + first], &self.buf[..len - first])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    const CAP: usize = 64;

    fn collect<const N: usize>(buf: &SendBuffer<N>, off: usize, len: usize) -> Vec<u8> {
        let (a, b) = buf.read(off, len);
        let mut v = a.to_vec();
        v.extend_from_slice(b);
        v
    }

    #[test]
    fn write_ack_read_wraps() {
        let mut b: SendBuffer<CAP> = SendBuffer::new();
        // Fill almost everything, ack most, write again to force wrap.
        let chunk: Vec<u8> = (0..CAP - 3).map(|i| i as u8).collect();
        assert_eq!(b.write(&chunk), chunk.len());
        b.ack(CAP - 8);
        assert_eq!(b.len(), 5);
        let tail: Vec<u8> = (0..16).map(|i| 0xA0 + i as u8).collect();
        assert_eq!(b.write(&tail), 16);
        assert_eq!(b.len(), 21);
        let got = collect(&b, 5, 16);
        assert_eq!(got, tail);
        // The 5 pre-wrap bytes survive intact.
        let head = collect(&b, 0, 5);
        assert_eq!(head, chunk[chunk.len() - 5..]);
    }

    #[test]
    fn write_caps_at_capacity() {
        let mut b: SendBuffer<CAP> = SendBuffer::new();
        let big = std::vec![7u8; CAP + 100];
        assert_eq!(b.write(&big), CAP);
        assert_eq!(b.space(), 0);
        assert_eq!(b.write(&[1]), 0);
        b.ack(1);
        assert_eq!(b.write(&[9]), 1);
        assert_eq!(collect(&b, CAP - 1, 1), &[9]);
    }
}
