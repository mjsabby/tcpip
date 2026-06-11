//! # tcp-sans-io
//!
//! A verification-first, sans-I/O, deterministic TCP/IPv4/IPv6 protocol core
//! aimed at aerospace and safety-critical systems, while remaining a good
//! citizen on the public Internet.
//!
//! ## Architecture
//!
//! The entire protocol core is a deterministic state machine:
//!
//! ```text
//! (State, Event) -> (NewState, Actions)
//! ```
//!
//! The core never touches clocks, sockets, threads, allocators, or entropy
//! sources. Every external dependency is virtualized:
//!
//! * **Time** enters as an [`Instant`](time::Instant) argument on every call
//!   and as [`TimerExpired`](Event::TimerExpired) events. The core emits
//!   [`Action::StartTimer`] / [`Action::CancelTimer`].
//! * **Packets** enter as [`Event::DatagramReceived`]; the core emits
//!   transmissions by writing full IP datagrams into a caller-provided buffer
//!   from [`Stack::poll_action`].
//! * **Entropy** enters as [`Event::EntropyProvided`]; the core asks for it
//!   with [`Action::RequestEntropy`] (used for RFC 6528 initial sequence
//!   numbers).
//! * **Memory** is fixed-capacity: no heap, no allocator, `#![no_std]`.
//!
//! ## Standards implemented
//!
//! * RFC 9293 (TCP) core state machine, RFC 1122 host requirements subset
//! * RFC 791 / RFC 815 (IPv4 + fragment reassembly), RFC 8200 (IPv6)
//! * RFC 1191 / RFC 8201 (Path MTU awareness)
//! * RFC 5681 / RFC 6582 (Reno congestion control, NewReno recovery)
//! * RFC 6298 (RTT estimation and RTO)
//! * RFC 6528 (cryptographic ISN generation, SipHash-2-4)
//! * RFC 5961 (blind reset / blind injection mitigation)
//! * RFC 2018 (SACK)
//! * RFC 7323 §2 (window scaling; timestamps intentionally omitted)
//!
//! See `docs/TRACEABILITY.md` for the requirement-to-code-to-test map.
//!
//! ## What the core is *not*
//!
//! There is no link layer here: the boundary is whole IP datagrams. ARP and
//! Neighbor Discovery belong to the link-layer adapter supplied by the
//! runtime (e.g. a TUN device needs neither).

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

// The protocol core is `no_std` by default. The `std` feature lifts that
// (e.g. for the TUN host runtime); the test harness always needs `std`.
#[cfg(all(not(feature = "std"), test))]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod config;
pub mod ip;
pub mod time;
pub mod types;
pub mod util;
pub mod wire;

pub mod tcp;

mod stack;

pub use stack::{Stack, StackStats};

pub use types::{
    Action, AppEvent, CloseReason, Error, Event, IpAddr, SocketAddr, SocketId, TimerKey, TimerKind,
};
