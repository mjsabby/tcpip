//! TCP (RFC 9293) with the production-Internet baseline:
//! RFC 5681/6582 congestion control, RFC 6298 timers, RFC 6528 ISNs,
//! RFC 5961 mitigations, RFC 2018 SACK and RFC 7323 window scaling.

pub mod cc;
pub mod conn;
pub mod isn;
pub mod recvbuf;
pub mod rtt;
pub mod sack;
pub mod sendbuf;
pub mod seq;

/// TCP connection states (RFC 9293 §3.3.2).
///
/// LISTEN lives at the stack level (a listener is not a connection slot);
/// CLOSED is represented both by the absence of a connection and, fleetingly,
/// by this variant while a slot is being torn down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Active open sent a SYN, awaiting SYN-ACK.
    SynSent,
    /// SYN received (passive open or simultaneous open), SYN-ACK sent.
    SynReceived,
    /// Data transfer.
    Established,
    /// Local close requested; FIN sent, awaiting ACK (and peer's FIN).
    FinWait1,
    /// Our FIN is acknowledged; awaiting the peer's FIN.
    FinWait2,
    /// Peer's FIN received; local side may still send.
    CloseWait,
    /// Both FINs in flight; ours not yet acknowledged (simultaneous close).
    Closing,
    /// Peer closed first, then we sent FIN; awaiting its ACK.
    LastAck,
    /// Both sides done; absorbing old duplicates for 2*MSL.
    TimeWait,
    /// Torn down; the slot is about to be released.
    Closed,
}

impl State {
    /// States where sequence numbers are synchronized (RFC 9293 §3.5.2
    /// group 3).
    pub fn synchronized(self) -> bool {
        !matches!(self, State::SynSent | State::SynReceived | State::Closed)
    }

    /// States in which the application may still submit data to send.
    pub fn may_send(self) -> bool {
        matches!(
            self,
            State::SynSent | State::SynReceived | State::Established | State::CloseWait
        )
    }

    /// States in which data from the peer is still accepted.
    pub fn may_receive(self) -> bool {
        matches!(
            self,
            State::SynSent
                | State::SynReceived
                | State::Established
                | State::FinWait1
                | State::FinWait2
        )
    }
}
