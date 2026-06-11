//! Shared pieces of the TUN harness: the device wrapper and the real-time
//! runtime that embeds the sans-I/O [`tcp_sans_io::Stack`]. Used by the
//! `tun-interop` test binary and the `fetch` worked example.

pub mod runtime;
pub mod tun;
