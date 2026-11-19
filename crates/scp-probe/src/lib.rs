//! `scp-probe` — a black-box conformance prober for SCP/1 servers.
//!
//! Given the address of a running server it learns, purely by exchanging
//! messages, which protocol orderings the implementation actually accepts,
//! compares that against `docs/spec.md`, and emits reproduction steps for
//! every place the two disagree.

pub mod case;
pub mod client;
pub mod explore;
pub mod model;
pub mod replay;
pub mod report;

pub use explore::{explore, Budget, Report};
pub use model::{Action, Phase, Severity};
pub use report::Finding;
