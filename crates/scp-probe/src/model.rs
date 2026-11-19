//! The **normative model**: `docs/spec.md` rendered as an executable
//! transition relation.
//!
//! This module is derived only from the published spec.  It says, for a
//! given protocol phase and an abstract input, whether the server must
//! accept it, must reject it (and with which `ERR` code), or must stay
//! silent.  The analysis stage compares what a target does against this
//! table; nothing else in the probe decides what is "right".

use scp_core::wire::ErrorCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Phase {
    Start,
    AwaitFinish,
    Established,
    /// Terminal: the server has closed; nothing may follow.
    Closed,
}

impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Phase::Start => "Start",
            Phase::AwaitFinish => "AwaitFinish",
            Phase::Established => "Established",
            Phase::Closed => "Closed",
        }
    }
}

/// One abstract input the probe can present in a given phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    ClientHelloV1,
    ClientHelloBadVersion,
    ClientFinishValid,
    ClientFinishBadMac,
    SessionResumeValid,
    SessionResumeInvalidTicket,
    SessionResumeReusedTicket,
    AppDataInSequence,
    AppDataGap,
    AppDataReplay,
    AppDataOldEpoch,
    AppDataBadMac,
    RekeyValid,
    CloseValid,
    WireUnknownType,
    WireOversize,
    ReflectedServerHello,
    IdlePastDeadline,
    IdlePastIdleTimeout,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Action::ClientHelloV1 => "CLIENT_HELLO(v1)",
            Action::ClientHelloBadVersion => "CLIENT_HELLO(bad version)",
            Action::ClientFinishValid => "CLIENT_FINISH(valid)",
            Action::ClientFinishBadMac => "CLIENT_FINISH(bad MAC)",
            Action::SessionResumeValid => "SESSION_RESUME(valid ticket)",
            Action::SessionResumeInvalidTicket => "SESSION_RESUME(forged ticket)",
            Action::SessionResumeReusedTicket => "SESSION_RESUME(reused ticket)",
            Action::AppDataInSequence => "APP_DATA(seq = expected)",
            Action::AppDataGap => "APP_DATA(seq = expected + 1)",
            Action::AppDataReplay => "APP_DATA(seq = expected - 1)",
            Action::AppDataOldEpoch => "APP_DATA(retired key epoch)",
            Action::AppDataBadMac => "APP_DATA(corrupted tag, seq = expected)",
            Action::RekeyValid => "REKEY(valid)",
            Action::CloseValid => "CLOSE(valid)",
            Action::WireUnknownType => "wire: unknown frame type",
            Action::WireOversize => "wire: body_len > 16384",
            Action::ReflectedServerHello => "wire: reflected SERVER_HELLO",
            Action::IdlePastDeadline => "idle past handshake deadline",
            Action::IdlePastIdleTimeout => "idle past idle timeout",
        }
    }

    /// Which spec rule governs the answer.  `None` for inputs the spec does
    /// not constrain (used for exploratory actions only).
    #[allow(unreachable_patterns)]
    pub fn rule(self, phase: Phase) -> &'static str {
        use Action::*;
        match (self, phase) {
            (ClientHelloV1, Phase::Start) => "R-3.2",
            (ClientHelloBadVersion, Phase::Start) => "R-3.2",
            (ClientFinishValid, Phase::Start) => "R-3.3",
            (ClientFinishBadMac, Phase::AwaitFinish) => "R-3.4",
            (ClientFinishValid, Phase::AwaitFinish) => "R-3.6",
            (ClientFinishValid, Phase::Established) => "R-3.8",
            (ClientHelloV1, Phase::AwaitFinish) => "R-3.3",
            (ClientHelloV1, Phase::Established) => "R-3.8",
            (ClientHelloBadVersion, Phase::AwaitFinish) => "R-3.3",
            (ClientHelloBadVersion, Phase::Established) => "R-3.8",
            (SessionResumeValid, Phase::Start) => "R-6.5",
            (SessionResumeValid, Phase::AwaitFinish) => "R-6.2",
            (SessionResumeValid, Phase::Established) => "R-6.2",
            (SessionResumeInvalidTicket, Phase::Start) => "R-6.3",
            (SessionResumeInvalidTicket, _) => "R-6.2",
            (SessionResumeReusedTicket, Phase::Start) => "R-6.4",
            (SessionResumeReusedTicket, _) => "R-6.2",
            (AppDataInSequence, Phase::Established) => "R-4.4",
            (AppDataGap, Phase::Established) => "R-4.3",
            (AppDataReplay, Phase::Established) => "R-4.3",
            (AppDataOldEpoch, Phase::Established) => "R-5.4",
            (AppDataBadMac, Phase::Established) => "R-4.2",
            (AppDataInSequence, Phase::Start) => "R-3.1",
            (AppDataInSequence, Phase::AwaitFinish) => "R-3.7",
            (AppDataGap, Phase::AwaitFinish) => "R-3.7",
            (AppDataReplay, Phase::AwaitFinish) => "R-3.7",
            (AppDataOldEpoch, Phase::AwaitFinish) => "R-3.7",
            (AppDataBadMac, Phase::AwaitFinish) => "R-3.7",
            (AppDataBadMac, Phase::Start) => "R-3.1",
            (RekeyValid, Phase::Established) => "R-5.1",
            (RekeyValid, Phase::Start) => "R-3.1",
            (RekeyValid, Phase::AwaitFinish) => "R-3.7",
            (CloseValid, Phase::Established) => "R-4.5",
            (CloseValid, Phase::Start) => "R-3.1",
            (CloseValid, Phase::AwaitFinish) => "R-3.7",
            (WireUnknownType, _) => "R-1.3",
            (WireOversize, _) => "R-1.2",
            (ReflectedServerHello, _) => "R-1.4",
            (IdlePastDeadline, _) => "R-7.1",
            (IdlePastIdleTimeout, Phase::Established) => "R-7.2",
            (IdlePastIdleTimeout, _) => "R-7.1",
            (_, Phase::Closed) => "R-7.3",
            // Combinations the spec does not constrain; `expect()` returns
            // None for these, so the rule string is never used in a verdict.
            (_, Phase::AwaitFinish) => "R-3.7",
            (_, Phase::Established) => "R-4.3",
            (_, Phase::Start) => "R-3.1",
        }
    }
}

/// What the spec requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// The input is legal and the server must act on it.
    Accept,
    /// The server must answer `ERR(code)` and close.
    Reject(ErrorCode),
    /// The server must close without sending anything (R-7.2 idle).
    SilentClose,
    /// Nothing may be sent; used only after `Closed`.
    Nothing,
}

impl Expect {
    pub fn describe(self) -> String {
        match self {
            Expect::Accept => "accept".into(),
            Expect::Reject(c) => format!("reject with ERR({})", c.name()),
            Expect::SilentClose => "close silently".into(),
            Expect::Nothing => "send nothing".into(),
        }
    }
}

use Action::*;
use Expect::*;
use Phase::*;

/// The spec's transition table.  Any `(phase, action)` pair not listed is
/// not constrained by the spec and is never used for a compliance verdict.
pub fn expect(phase: Phase, action: Action) -> Option<Expect> {
    use ErrorCode::*;
    Some(match (phase, action) {
        // ---- Start --------------------------------------------------------
        (Start, ClientHelloV1) => Accept,
        (Start, ClientHelloBadVersion) => Reject(BadVersion),
        (Start, ClientFinishValid) => Reject(UnexpectedMessage),
        (Start, ClientFinishBadMac) => Reject(UnexpectedMessage),
        (Start, SessionResumeValid) => Accept,
        (Start, SessionResumeInvalidTicket) => Reject(TicketInvalid),
        (Start, SessionResumeReusedTicket) => Reject(TicketInvalid),
        (Start, AppDataInSequence) => Reject(UnexpectedMessage),
        (Start, AppDataGap) => Reject(UnexpectedMessage),
        (Start, AppDataReplay) => Reject(UnexpectedMessage),
        (Start, AppDataOldEpoch) => Reject(UnexpectedMessage),
        (Start, AppDataBadMac) => Reject(UnexpectedMessage),
        (Start, RekeyValid) => Reject(UnexpectedMessage),
        (Start, CloseValid) => Reject(UnexpectedMessage),
        (Start, WireUnknownType) => Reject(DecodeError),
        (Start, WireOversize) => Reject(TooLarge),
        (Start, ReflectedServerHello) => Reject(DecodeError),
        (Start, IdlePastDeadline) => Reject(DeadlineExceeded),

        // ---- AwaitFinish --------------------------------------------------
        (AwaitFinish, ClientHelloV1) => Reject(UnexpectedMessage),
        (AwaitFinish, ClientHelloBadVersion) => Reject(UnexpectedMessage),
        (AwaitFinish, ClientFinishValid) => Accept,
        (AwaitFinish, ClientFinishBadMac) => Reject(BadMac),
        (AwaitFinish, SessionResumeValid) => Reject(UnexpectedMessage),
        (AwaitFinish, SessionResumeInvalidTicket) => Reject(UnexpectedMessage),
        (AwaitFinish, SessionResumeReusedTicket) => Reject(UnexpectedMessage),
        // R-3.7: the rule at the heart of the exercise.
        (AwaitFinish, AppDataInSequence) => Reject(UnexpectedMessage),
        (AwaitFinish, AppDataGap) => Reject(UnexpectedMessage),
        (AwaitFinish, AppDataReplay) => Reject(UnexpectedMessage),
        (AwaitFinish, AppDataOldEpoch) => Reject(UnexpectedMessage),
        (AwaitFinish, AppDataBadMac) => Reject(UnexpectedMessage),
        (AwaitFinish, RekeyValid) => Reject(UnexpectedMessage),
        (AwaitFinish, CloseValid) => Reject(UnexpectedMessage),
        (AwaitFinish, WireUnknownType) => Reject(DecodeError),
        (AwaitFinish, WireOversize) => Reject(TooLarge),
        (AwaitFinish, ReflectedServerHello) => Reject(DecodeError),
        (AwaitFinish, IdlePastDeadline) => Reject(DeadlineExceeded),

        // ---- Established --------------------------------------------------
        (Established, ClientHelloV1) => Reject(UnexpectedMessage),
        (Established, ClientHelloBadVersion) => Reject(UnexpectedMessage),
        (Established, ClientFinishValid) => Reject(UnexpectedMessage),
        (Established, SessionResumeValid) => Reject(UnexpectedMessage),
        (Established, SessionResumeInvalidTicket) => Reject(UnexpectedMessage),
        (Established, SessionResumeReusedTicket) => Reject(UnexpectedMessage),
        (Established, AppDataInSequence) => Accept,
        (Established, AppDataGap) => Reject(Replay),
        (Established, AppDataReplay) => Reject(Replay),
        (Established, AppDataOldEpoch) => Reject(BadMac),
        (Established, AppDataBadMac) => Reject(BadMac),
        (Established, RekeyValid) => Accept,
        (Established, CloseValid) => Accept,
        (Established, WireUnknownType) => Reject(DecodeError),
        (Established, WireOversize) => Reject(TooLarge),
        (Established, ReflectedServerHello) => Reject(DecodeError),
        (Established, IdlePastIdleTimeout) => SilentClose,

        // ---- Closed -------------------------------------------------------
        (Closed, _) => Nothing,

        // Unconstrained combinations (e.g. idle timeout in Start, a bad-MAC
        // finish on an established connection) are not used for verdicts.
        _ => return None,
    })
}

/// Severity of a divergence.  Accepting something the spec forbids is the
/// serious kind: it is the class of bug that caused the incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Accepted an input the spec says must be rejected. Security-relevant.
    Critical,
    /// Rejected something the spec says must be accepted (interop breakage).
    Major,
    /// Wrong error code, wrong timeout behaviour, no close after ERR, etc.
    Minor,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::Major => "major",
            Severity::Minor => "minor",
        }
    }
}

/// Classify a divergence between expected and actual.
pub fn severity_of(expected: Expect, accepted: bool, matched_code: bool) -> Option<Severity> {
    match (expected, accepted) {
        // Spec says reject / close / nothing, target accepted -> the
        // dangerous direction.
        (Reject(_) | SilentClose | Nothing, true) => Some(Severity::Critical),
        // Spec says accept, target rejected -> interop failure.
        (Accept, false) => Some(Severity::Major),
        // Contract met to first order but the error code differs: minor.
        (Reject(_), false) if !matched_code => Some(Severity::Minor),
        _ => None,
    }
}
