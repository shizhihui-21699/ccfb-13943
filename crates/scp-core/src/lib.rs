//! SCP/1 — the shared, *non-secret* half of the protocol: framing, message
//! shapes, and the key schedule.
//!
//! The reference server, the deliberately-buggy targets, and the black-box
//! prober all build on this crate. Nothing in here enforces a state machine:
//! ordering rules live in the individual implementations, which is exactly
//! what makes them observable from the outside.

pub mod crypto;
pub mod wire;

pub use wire::{
    ClientFinish, ClientHello, ErrorCode, Frame, FrameDecoder, MsgType, ResumeOk, Sealed,
    ServerFinish, ServerHello, SessionResume, WireError, HANDSHAKE_DEADLINE_MS, IDLE_TIMEOUT_MS,
    MAX_FRAME, SUITE, TICKET_LEN, TICKET_TTL_MS, UNSUPPORTED_VERSION, VERSION,
};
