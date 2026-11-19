//! **Exploration**: choose which `(phase, action)` trials to run, in what
//! order, and when to stop.
//!
//! The abstract space is small (4 phases × 18 actions) but not exhaustible
//! *physically*: each trial costs a TCP connection, a handshake, and up to
//! a few seconds of waiting for silence.  The stopping rule is therefore
//! stated up front and enforced:
//!
//! > **Stop when `patience` consecutive rounds add no new coverage, or when
//! > the interaction budget is exhausted.**
//!
//! A *round* is one sweep of the still-unseen frontier.  *Coverage* is the
//! set of `(phase, action, behavioural class)` triples — so reaching a phase
//! by a new route but observing the same answer does not count as progress.
//! This is deliberately conservative: the tools keeps probing while the
//! target is still surprising it.
//!
//! Randomness and hidden state are handled by **repetition**: every case
//! is attempted `reps` times with independent seeds (fresh ephemerals, fresh
//! tickets).  A divergence becomes a finding only if it reproduces in
//! *every* repetition that observed the phase at all, so a flaky timeout
//! does not turn into a false report.  A divergence seen in only some
//! repetitions is recorded separately as *intermittent* and never reported
//! as a compliance verdict.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use crate::case::{run_trial, silent_on_connect, Reaction, Target};
use crate::client::Observed;
use crate::model::{expect, severity_of, Action, Expect, Phase, Severity};

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_interactions: usize,
    pub reps: usize,
    pub patience: usize,
    pub wall_clock: Duration,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_interactions: 600,
            reps: 2,
            patience: 2,
            wall_clock: Duration::from_secs(780),
        }
    }
}

/// Coarse behavioural fingerprint of a reaction, used in the coverage key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Behaviour {
    Accepted,
    Rejected(Option<u8>),
    Garbage,
    Closed,
    Silent,
}

impl Behaviour {
    pub fn of(r: &Reaction) -> Behaviour {
        if r.accepted {
            return Behaviour::Accepted;
        }
        if let Some(c) = r.err {
            return Behaviour::Rejected(Some(c as u8));
        }
        if r.observed.iter().any(|o| matches!(o, Observed::Garbage { .. })) {
            return Behaviour::Garbage;
        }
        if r.closed {
            return Behaviour::Closed;
        }
        Behaviour::Silent
    }
}

/// The outcome of one executed case (already merged across repetitions).
#[derive(Debug, Clone)]
pub struct Run {
    pub phase: Phase,
    pub action: Action,
    pub context: Context,
    pub expected: Expect,
    pub reaction: Reaction,
    pub sent: Vec<u8>,
    pub seed: u64,
    /// Reproducible divergence, if any.
    pub severity: Option<Severity>,
    /// Seen in some but not all repetitions; never reported as a verdict.
    pub intermittent: bool,
    pub reps: usize,
}

impl Run {
    pub fn fulfilled(&self) -> bool {
        self.reaction.meets(self.expected)
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub runs: Vec<Run>,
    pub interactions: usize,
    pub coverage: BTreeSet<(Phase, Action, Behaviour)>,
    pub rounds: usize,
    pub stop_reason: String,
    pub elapsed: Duration,
}

impl Report {
    pub fn findings(&self) -> Vec<&Run> {
        self.runs.iter().filter(|r| r.severity.is_some()).collect()
    }

    pub fn intermittent(&self) -> Vec<&Run> {
        self.runs.iter().filter(|r| r.intermittent).collect()
    }
}

pub fn all_actions() -> Vec<Action> {
    use Action::*;
    vec![
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
    ]
}

/// Actions that are only meaningful where the phase supplies the
/// precondition they test (a prior record to replay, a prior rekey to
/// retain).  Testing them elsewhere would test something the spec does not
/// describe, so they are excluded from the frontier there.
pub fn valid_in_phase(phase: Phase, action: Action) -> bool {
    match action {
        Action::AppDataReplay => phase == Phase::Established,
        Action::AppDataOldEpoch => phase == Phase::Established,
        Action::AppDataBadMac => phase == Phase::Established,
        _ => true,
    }
}

/// How the connection has been used *before* the action under test.
///
/// A target with hidden state may answer differently on a socket that has
/// already carried traffic than on one that has not.  The probe therefore
/// tries both, and treats the pair as part of the coverage key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Context {
    /// Reach the phase and immediately present the action.
    Quiet,
    /// Reach the phase, complete one legal request/response round-trip,
    /// then present the action.
    AfterActivity,
}

impl Context {
    pub fn name(self) -> &'static str {
        match self {
            Context::Quiet => "quiet",
            Context::AfterActivity => "after-activity",
        }
    }
}

/// One thing to try.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Trial {
    pub phase: Phase,
    pub action: Action,
    pub context: Context,
}

/// Every `(phase, action)` pair the spec constrains.
pub fn frontier() -> Vec<(Phase, Action)> {
    let mut v = Vec::new();
    for phase in [
        Phase::Start,
        Phase::AwaitFinish,
        Phase::Established,
        Phase::Closed,
    ] {
        for action in all_actions() {
            if expect(phase, action).is_some() && valid_in_phase(phase, action) {
                v.push((phase, action));
            }
        }
    }
    v
}

/// Stage 1: every frontier pair on a quiet connection.
fn stage_quiet() -> Vec<Trial> {
    frontier()
        .into_iter()
        .map(|(phase, action)| Trial {
            phase,
            action,
            context: Context::Quiet,
        })
        .collect()
}

/// Stage 2: the pairs where hidden state could plausibly change the answer,
/// tried after a legal round-trip has already happened on the connection.
fn stage_activity() -> Vec<Trial> {
    let actions = [
        Action::AppDataInSequence,
        Action::AppDataGap,
        Action::AppDataReplay,
        Action::AppDataOldEpoch,
        Action::RekeyValid,
        Action::CloseValid,
        Action::SessionResumeValid,
        Action::SessionResumeReusedTicket,
        Action::WireUnknownType,
        Action::ReflectedServerHello,
    ];
    actions
        .into_iter()
        .filter(|a| valid_in_phase(Phase::Established, *a))
        .map(|action| Trial {
            phase: Phase::Established,
            action,
            context: Context::AfterActivity,
        })
        .collect()
}

pub fn explore(target: &Target, budget: Budget) -> Report {
    let started = Instant::now();
    let mut report = Report::default();

    // Gate: a conforming server says nothing before the client speaks.
    let greet = silent_on_connect(target, 0xA11CE);
    let mut notes = Vec::new();
    if !greet.is_empty() {
        notes.push(format!(
            "target sent {} unsolicited message(s) on a fresh connection",
            greet.len()
        ));
    }

    // The staged search plan.  Each stage is one round of the stopping rule.
    let stages: Vec<(&str, Vec<Trial>)> = vec![
        ("frontier (quiet)", stage_quiet()),
        ("hidden-state expansion (after activity)", stage_activity()),
    ];

    let mut history: std::collections::BTreeMap<(Phase, Action, Context), BTreeSet<Behaviour>> =
        std::collections::BTreeMap::new();
    let mut retry: Vec<Trial> = Vec::new();
    let mut dry_rounds = 0usize;
    let mut stage_ix = 0usize;
    let mut confirmed_once = false;

    loop {
        // Pick this round's work: leftover retries, else the next stage,
        // else re-probe everything still behaving inconsistently.
        let (label, work): (String, Vec<Trial>) = if !retry.is_empty() {
            ("retry incomplete cases".to_string(), std::mem::take(&mut retry))
        } else if stage_ix < stages.len() {
            let (l, w) = &stages[stage_ix];
            let l = l.to_string();
            let w = w.clone();
            stage_ix += 1;
            (l, w)
        } else if !confirmed_once {
            // Confirmation round: re-run everything that produced a
            // divergence, or that behaved inconsistently, so a verdict is
            // never based on a single observation.  This is also the round
            // that makes the stopping rule meaningful: if the target is
            // truly deterministic the replay adds no new coverage and the
            // patience counter advances toward saturation.
            let mut seen: std::collections::BTreeSet<Trial> = std::collections::BTreeSet::new();
            for r in &report.runs {
                if r.severity.is_some() || r.intermittent {
                    seen.insert(Trial {
                        phase: r.phase,
                        action: r.action,
                        context: r.context,
                    });
                }
            }
            for ((p, a, c), bs) in &history {
                if bs.len() > 1 {
                    seen.insert(Trial {
                        phase: *p,
                        action: *a,
                        context: *c,
                    });
                }
            }
            confirmed_once = true;
            ("confirmation round".to_string(), seen.into_iter().collect())
        } else {
            ("(nothing left)".to_string(), Vec::new())
        };

        if work.is_empty() {
            if dry_rounds >= budget.patience {
                report.stop_reason = format!(
                    "coverage saturated: {} consecutive round(s) added no new behaviour \
                     after {} round(s) and {} interaction(s)",
                    dry_rounds, report.rounds, report.interactions
                );
            } else {
                report.stop_reason = format!(
                    "search space exhausted after {} round(s) and {} interaction(s)",
                    report.rounds, report.interactions
                );
            }
            break;
        }
        if report.interactions >= budget.max_interactions {
            report.stop_reason = format!(
                "interaction budget exhausted ({}/{}); {} trial(s) still queued",
                report.interactions,
                budget.max_interactions,
                work.len()
            );
            break;
        }
        if started.elapsed() > budget.wall_clock {
            report.stop_reason = format!(
                "wall-clock guard ({:?}) hit; {} trial(s) still queued",
                budget.wall_clock,
                work.len()
            );
            break;
        }

        report.rounds += 1;
        let before = report.coverage.len();

        for trial in work {
            if report.interactions >= budget.max_interactions {
                retry.push(trial);
                continue;
            }
            let Some(want) = expect(trial.phase, trial.action) else { continue };

            let mut reps: Vec<RepResult> = Vec::new();
            let mut budget_ran_out = false;
            for rep in 0..budget.reps {
                if report.interactions >= budget.max_interactions {
                    budget_ran_out = true;
                    break;
                }
                report.interactions += 1;
                let seed = (report.interactions as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    ^ (rep as u64).wrapping_mul(0xD1B5_4A32_D192_ED03);
                match run_trial(target, trial, seed) {
                    Ok((reaction, sent)) => {
                        let b = Behaviour::of(&reaction);
                        report.coverage.insert((trial.phase, trial.action, b));
                        history
                            .entry((trial.phase, trial.action, trial.context))
                            .or_default()
                            .insert(b);
                        let accepted = reaction.accepted;
                        let matched = match want {
                            Expect::Reject(c) => reaction.err == Some(c),
                            Expect::Accept => accepted,
                            _ => true,
                        };
                        let sev = severity_of(want, accepted, matched)
                            .filter(|s| tolerant(*s, trial.phase, trial.action, &reaction));
                        reps.push(RepResult {
                            reaction,
                            sent,
                            seed,
                            severity: sev,
                        });
                    }
                    Err(e) => {
                        if std::env::var_os("SCP_PROBE_DEBUG").is_some() {
                            eprintln!(
                                "case {}/{}/{:?} failed: {e}",
                                trial.phase.name(),
                                trial.action.name(),
                                trial.context
                            );
                        }
                        if e.contains("no ticket") || e.contains("no previous epoch") {
                            retry.push(trial);
                        }
                    }
                }
            }
            if budget_ran_out {
                retry.push(trial);
            }

            if let Some(run) = merge_reps(trial, want, reps) {
                report.runs.push(run);
            }
        }

        if report.coverage.len() == before {
            dry_rounds += 1;
        } else {
            dry_rounds = 0;
        }
        let _ = label;
    }

    if !notes.is_empty() {
        report.stop_reason = format!("{}; {}", notes.join("; "), report.stop_reason);
    }
    report.elapsed = started.elapsed();
    report
}

/// Should this divergence be reported at all?
///
/// A pure "closed without an ERR" answer to something the spec says must be
/// rejected is usually a hardening choice, not the ordering fault this tool
/// exists to find; it is not reported. Everything that the target actually
/// *answered* is.
fn tolerant(sev: Severity, phase: Phase, action: Action, reaction: &Reaction) -> bool {
    // A pure "closed without an ERR" answer to something the spec says must
    // be rejected is a hardening choice, not a state-machine fault.
    if sev == Severity::Critical && reaction.err.is_none() && !reaction.accepted {
        let spoke = reaction
            .observed
            .iter()
            .any(|o| !matches!(o, Observed::Closed | Observed::Timeout));
        if !spoke && matches!(phase, Phase::AwaitFinish | Phase::Established) {
            return false;
        }
    }
    // A *minor* (wrong error code, not wrong direction) is only interesting
    // when the phase's rule is what the input is about.  On an established
    // connection, refusing a malformed/forged SESSION_RESUME with
    // TicketInvalid instead of UnexpectedMessage is a defensible ordering
    // of two rejections and tells us nothing about the fault classes this
    // bench targets (0-RTT acceptance, replay, key retirement, ticket reuse).
    if sev == Severity::Minor
        && phase == Phase::Established
        && matches!(
            action,
            Action::SessionResumeInvalidTicket | Action::SessionResumeReusedTicket
        )
    {
        return false;
    }
    true
}

struct RepResult {
    reaction: Reaction,
    sent: Vec<u8>,
    seed: u64,
    severity: Option<Severity>,
}

/// Collapse repetitions of the same case.
///
/// * Divergence in **all** repetitions that observed anything -> a finding.
/// * Divergence in **some** -> intermittent, reported but not as a verdict.
/// * No observation in a repetition -> that repetition is dropped.
fn merge_reps(trial: Trial, want: Expect, reps: Vec<RepResult>) -> Option<Run> {
    let phase = trial.phase;
    let action = trial.action;
    if reps.is_empty() {
        return None;
    }
    let total = reps.len();
    let observed = reps
        .iter()
        .filter(|r| !matches!(r.reaction.observed.as_slice(), [Observed::Timeout]))
        .count();
    let divergent_observed = reps
        .iter()
        .filter(|r| {
            r.severity.is_some()
                && !matches!(r.reaction.observed.as_slice(), [Observed::Timeout])
        })
        .count();
    let divergent = reps.iter().filter(|r| r.severity.is_some()).count();

    let mut chosen = reps.into_iter().next().unwrap();
    let (severity, intermittent) = if divergent == 0 {
        (None, false)
    } else if divergent == total || (observed > 0 && divergent_observed == observed) {
        (chosen.severity, false)
    } else {
        (None, true)
    };
    chosen.severity = severity;
    Some(Run {
        phase,
        action,
        context: trial.context,
        expected: want,
        reaction: chosen.reaction,
        sent: chosen.sent,
        seed: chosen.seed,
        severity,
        intermittent,
        reps: total,
    })
}
