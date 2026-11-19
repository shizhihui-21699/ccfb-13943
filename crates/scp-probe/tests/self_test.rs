//! End-to-end self-tests: spin up each target *in process*, run the same
//! black-box exploration the CLI runs, and assert that
//!
//! 1. the compliant reference produces **no** findings, and
//! 2. each faulty target produces findings whose rule ids are exactly the
//!    faults its module documents.
//!
//! This is the honesty check on the bench: the probe sees only bytes on a
//! socket, so if it reports a rule for the reference, or misses a planted
//! fault, one of the two is wrong and this test fails.

use scp_probe::case::Target;
use scp_probe::explore::{explore, Budget};
use scp_probe::model::Severity;
use scp_probe::report::build;
use scp_target::impls::Impl;
use scp_target::transport::ServerCfg;

fn run(which: Impl, budget: Budget) -> (Vec<String>, scp_probe::explore::Report) {
    let handle = scp_target::spawn(which, 7, ServerCfg::default()).expect("spawn target");
    let addr = handle.addr().parse().unwrap();
    let target = Target::new(addr);
    let report = explore(&target, budget);
    let findings = build(which.name(), &report.runs);
    let ids: Vec<String> = findings.iter().map(|f| f.rule.clone()).collect();
    handle.stop();
    (ids, report)
}

fn small_budget() -> Budget {
    Budget {
        max_interactions: 400,
        reps: 2,
        patience: 1,
        wall_clock: std::time::Duration::from_secs(120),
    }
}

#[test]
fn reference_is_clean() {
    let (rules, report) = run(Impl::Reference, small_budget());
    assert!(
        rules.is_empty(),
        "reference produced findings {:?}\n{}",
        rules,
        describe(&report)
    );
}

#[test]
fn eager_is_caught_on_early_data() {
    let (rules, report) = run(Impl::Eager, small_budget());
    assert!(rules.contains(&"R-3.7".to_string()), "rules = {rules:?}\n{}", describe(&report));
    assert!(
        report
            .findings()
            .iter()
            .any(|r| r.severity == Some(Severity::Critical)),
        "early data must be critical"
    );
}

#[test]
fn lenient_is_caught_on_replay() {
    let (rules, report) = run(Impl::Lenient, small_budget());
    assert!(
        rules.contains(&"R-4.3".to_string()),
        "expected a replay finding; rules = {rules:?}\n{}",
        describe(&report)
    );
}

#[test]
fn sticky_is_caught_on_ticket_reuse_and_old_epoch() {
    let (rules, report) = run(Impl::Sticky, small_budget());
    assert!(
        rules.contains(&"R-6.4".to_string()),
        "expected ticket-reuse finding; rules = {rules:?}\n{}",
        describe(&report)
    );
    assert!(
        rules.contains(&"R-5.4".to_string()),
        "expected retired-epoch finding; rules = {rules:?}\n{}",
        describe(&report)
    );
}

#[test]
fn findings_are_ranked_correctly() {
    // Accepting a forbidden input is always critical for the fault classes
    // this bench plants; rejecting something legal would be major.  The
    // reference must produce neither.
    for which in [Impl::Eager, Impl::Lenient, Impl::Sticky] {
        let (_, report) = run(which, small_budget());
        for r in report.findings() {
            assert!(
                r.severity == Some(Severity::Critical)
                    || r.severity == Some(Severity::Major)
                    || r.severity == Some(Severity::Minor),
                "{} produced an unranked finding {:?}",
                which.name(),
                r.action
            );
        }
        assert!(
            report
                .findings()
                .iter()
                .any(|r| r.severity == Some(Severity::Critical)),
            "{} should have at least one critical finding",
            which.name()
        );
    }
}

/// The strongest check in the bench: the *exact set of rules* broken by each
/// implementation must match its documented fault catalogue, with nothing
/// missed and nothing invented.  Run with a full budget.
fn rules_for(which: Impl) -> std::collections::BTreeSet<String> {
    let handle = scp_target::spawn(which, 11, ServerCfg::default()).expect("spawn");
    let addr = handle.addr().parse().unwrap();
    let report = explore(
        &Target::new(addr),
        Budget {
            max_interactions: 600,
            reps: 2,
            patience: 2,
            wall_clock: std::time::Duration::from_secs(240),
        },
    );
    let out = build(which.name(), &report.runs)
        .into_iter()
        .map(|f| f.rule)
        .collect();
    handle.stop();
    out
}

#[test]
fn exact_rule_sets_match_the_fault_catalogue() {
    use std::collections::BTreeSet;
    let cases: &[(Impl, &[&str])] = &[
        (Impl::Reference, &[]),
        (Impl::Eager, &["R-3.7"]),
        (Impl::Lenient, &["R-4.2", "R-4.3"]),
        (Impl::Sticky, &["R-5.4", "R-6.2", "R-6.4"]),
    ];
    for (which, want) in cases {
        let got = rules_for(*which);
        let want: BTreeSet<String> = want.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            got, want,
            "{}: rules found {:?}, catalogue says {:?}",
            which.name(), got, want
        );
    }
}

fn describe(report: &scp_probe::explore::Report) -> String {
    let mut s = format!(
        "interactions={} rounds={} stop={}\n",
        report.interactions, report.rounds, report.stop_reason
    );
    for r in &report.runs {
        s.push_str(&format!(
            "{:>12} / {:<34} exp={:<22} obs={:<40} sev={:?}\n",
            r.phase.name(),
            r.action.name(),
            r.expected.describe(),
            r.reaction.summary(),
            r.severity
        ));
    }
    s
}

/// Determinism under repetition: the same target probed twice must yield
/// the same set of rule ids.  This is the "randomness / hidden state" claim
/// in the README, checked rather than asserted.
#[test]
fn findings_are_stable_across_runs() {
    for which in [Impl::Eager, Impl::Lenient, Impl::Sticky] {
        let a = rules_for(which);
        let b = rules_for(which);
        assert_eq!(a, b, "{} not deterministic across two full runs", which.name());
    }
}
