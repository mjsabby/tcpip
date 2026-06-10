# tun-harness — on-the-wire interop

Drives the `tcp-sans-io` stack against the **real Linux kernel TCP stack** over
a TUN device, to validate interoperability beyond the in-memory tests.

This is a separate crate (its own `[workspace]`) so it can use the single
`unsafe` block needed for the `TUNSETIFF` ioctl — the library it links remains
`#![forbid(unsafe_code)]`.

## Run

```sh
sudo ./run.sh
```

(Needs root for `CAP_NET_ADMIN` to create the TUN device.) It builds release,
creates a transient `tcptun0` interface (`10.9.0.1/24` on the kernel side, the
stack at `10.9.0.2`), and runs two scenarios:

1. **kernel client → stack echo server** — the kernel `connect()`s, streams
   128 KiB, half-closes; the stack echoes it back; the kernel verifies.
2. **stack client → kernel echo server** — the stack `connect()`s to a kernel
   `TcpListener`, streams 128 KiB, half-closes; verifies the echo.

Exit code 0 and `ALL INTEROP SCENARIOS PASSED` on success. The interface is
torn down automatically when the process exits.

## What it demonstrates

* The sans-I/O core embedded in a **real** std runtime (`src/runtime.rs`):
  wall-clock time, real timers keyed by `TimerKey`, `/dev/urandom` entropy, and
  the TUN "wire". This is the reference for how to host the stack in
  production — the same shape as the in-memory test harness.
* Correct behavior against an independent, battle-tested peer (Linux), under
  real timing, including window management, retransmission, and graceful
  close in both directions.

## Extending to FreeBSD / Windows

The harness logic is host-agnostic; only `tun.rs` (device open + `ip`
configuration) is Linux-specific. Porting the device layer to a BSD `tun`/utun
or a Windows TAP adapter is the remaining work to close the interop matrix.
