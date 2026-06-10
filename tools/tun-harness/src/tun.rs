//! Minimal TUN device: open `/dev/net/tun`, attach a named L3 interface, and
//! read/write raw IP datagrams. Everything but the one `TUNSETIFF` ioctl uses
//! std file I/O.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;

const TUNSETIFF: u64 = 0x4004_54ca; // _IOW('T', 202, int)
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000; // no 4-byte packet-info prefix: pure IP
const O_NONBLOCK: i32 = 0x800;

// SAFETY-relevant FFI: a single ioctl to bind the fd to a tun interface.
unsafe extern "C" {
    fn ioctl(fd: i32, request: u64, arg: *mut IfReq) -> i32;
}

#[repr(C)]
struct IfReq {
    name: [u8; 16],
    flags: u16,
    _pad: [u8; 22], // ifreq is 40 bytes on LP64; only name+flags matter here
}

/// An open, non-blocking TUN device carrying raw IPv4/IPv6 datagrams.
pub struct Tun {
    file: File,
    name: String,
}

impl Tun {
    /// Create (transient) tun interface `name`, non-blocking. Disappears when
    /// dropped. Requires `CAP_NET_ADMIN` (run as root).
    pub fn create(name: &str) -> io::Result<Tun> {
        assert!(name.len() < 16, "interface name too long");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_NONBLOCK)
            .open("/dev/net/tun")?;

        let mut req = IfReq { name: [0; 16], flags: IFF_TUN | IFF_NO_PI, _pad: [0; 22] };
        req.name[..name.len()].copy_from_slice(name.as_bytes());

        // SAFETY: `file` is a valid open fd for /dev/net/tun; `req` is a
        // correctly-sized, initialized `ifreq`; TUNSETIFF reads `flags` and
        // `name` and writes back the assigned `name`. The pointer is valid
        // for the duration of the call. This is the only unsafe in the crate.
        let rc = unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, &mut req) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let end = req.name.iter().position(|&b| b == 0).unwrap_or(16);
        let assigned = String::from_utf8_lossy(&req.name[..end]).into_owned();
        Ok(Tun { file, name: assigned })
    }

    /// Interface name actually assigned by the kernel.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read one datagram if available; `Ok(None)` when nothing is queued.
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self.file.read(buf) {
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write one datagram.
    pub fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        self.file.write_all(datagram)
    }

    /// Configure address, MTU, and bring the link up via `ip(8)`. Must run as
    /// root. Also disables reverse-path filtering on the interface so the
    /// kernel does not drop packets sourced from our peer address.
    pub fn configure(&self, cidr: &str, mtu: u16) -> io::Result<()> {
        ip(&["addr", "add", cidr, "dev", &self.name])?;
        ip(&["link", "set", "dev", &self.name, "mtu", &mtu.to_string()])?;
        ip(&["link", "set", "dev", &self.name, "up"])?;
        // Best-effort; ignore failures (kernel may already permit it).
        let _ = sysctl(&format!("net.ipv4.conf.{}.rp_filter=0", self.name));
        let _ = sysctl("net.ipv4.conf.all.rp_filter=0");
        Ok(())
    }
}

fn ip(args: &[&str]) -> io::Result<()> {
    let status = Command::new("ip").args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("`ip {}` failed: {status}", args.join(" "))))
    }
}

fn sysctl(kv: &str) -> io::Result<()> {
    Command::new("sysctl").arg("-w").arg(kv).status().map(|_| ())
}
