//! Deliberately-imperfect SCP/1 server implementations used as inspection
//! targets, plus the compliant reference that the spec was written against.
//!
//! Each implementation is a small, self-contained state machine.  The
//! faults are documented in the module header of each file so the test
//! bench's own results can be audited: a finding is a *claim* that a rule
//! was broken, and the fault catalogue is the ground truth against which
//! those claims are checked (see `scp-probe`'s self-test).

pub mod eager;
pub mod lenient_record;
pub mod reference;
pub mod sticky;

/// Which implementation a target process should serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Impl {
    /// Fully compliant; the oracle. Should produce zero findings.
    Reference,
    /// Accepts APP_DATA / REKEY / CLOSE before the handshake completes.
    Eager,
    /// Does not enforce receive-sequence (replay); ignores bad MACs.
    Lenient,
    /// Tickets reusable, retired key epochs still accepted, mid-session resume.
    Sticky,
}

impl Impl {
    pub fn name(self) -> &'static str {
        match self {
            Impl::Reference => "reference",
            Impl::Eager => "eager",
            Impl::Lenient => "lenient",
            Impl::Sticky => "sticky",
        }
    }

    /// Fault identifiers this implementation is *supposed* to exhibit.
    /// The probe's self-test asserts that every one is found and that
    /// nothing outside this set is reported.
    pub fn expected_faults(self) -> &'static [&'static str] {
        match self {
            Impl::Reference => &[],
            Impl::Eager => &["early-app-data", "early-rekey", "early-close"],
            Impl::Lenient => &["replay-accepted", "bad-mac-ignored"],
            Impl::Sticky => &["ticket-reuse", "old-epoch-accepted", "resume-mid-session"],
        }
    }
}
