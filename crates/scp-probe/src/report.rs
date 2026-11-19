//! Turning divergent runs into **findings**: a stable id, a severity, the
//! spec rule violated, the observed vs required behaviour, and a
//! reproduction recipe with the exact bytes and the exact protocol script.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::client::Observed;
use crate::explore::Run;
use crate::model::{Action, Phase, Severity};

#[derive(Debug, Clone)]
pub struct Finding {
    /// Stable identifier: `<impl>:<rule>:<phase>/<action>`.
    pub id: String,
    pub rule: String,
    pub severity: Severity,
    pub phase: Phase,
    pub action: Action,
    pub context: &'static str,
    pub expected: String,
    pub observed: String,
    pub detail: String,
    /// Reproduction steps as a protocol script.
    pub repro: Vec<String>,
    /// Hex of the last frame the probe sent.
    pub sent_hex: String,
    pub seed: u64,
    pub reps: usize,
}

impl Finding {
    pub fn title(&self) -> String {
        format!(
            "{} violated in {}: {} accepted/answered against spec",
            self.rule,
            self.phase.name(),
            self.action.name()
        )
    }
}

/// Build findings from a run list.  Findings with the same
/// `(rule, phase, action)` collapse into one entry even if several
/// scenarios reached it (e.g. resume-on-established reached via different
/// setups).
pub fn build(impl_name: &str, runs: &[Run]) -> Vec<Finding> {
    let mut by_key: BTreeMap<(String, Phase, Action), &Run> = BTreeMap::new();
    for r in runs {
        if let Some(sev) = r.severity {
            let key = (effective_rule(r).to_string(), r.phase, r.action);
            // A divergence seen after intervening traffic is the stronger
            // evidence (it survives hidden-state changes), so it wins ties.
            let _ = &r.context;
            by_key
                .entry(key)
                .and_modify(|prev| {
                    let prev_ctx = matches!(prev.context, crate::explore::Context::AfterActivity);
                    let this_ctx = matches!(r.context, crate::explore::Context::AfterActivity);
                    let better = (this_ctx && !prev_ctx)
                        || (this_ctx == prev_ctx
                            && sev < prev.severity.unwrap_or(Severity::Minor));
                    if better {
                        *prev = r;
                    }
                })
                .or_insert(r);
        }
    }

    by_key
        .into_iter()
        .map(|((rule, phase, action), r)| {
            let severity = r.severity.unwrap_or(Severity::Minor);
            let expected = r.expected.describe();
            let observed = r.reaction.summary();
            let interesting: Vec<String> = r
                .reaction
                .observed
                .iter()
                .filter(|o| {
                    !matches!(o, Observed::Timeout | Observed::Closed)
                })
                .map(|o| o.short())
                .collect();
            let detail = diagnose(action, phase, severity, &r.reaction.observed);
            Finding {
                id: format!(
                    "{}:{}:{}/{}",
                    impl_name,
                    rule,
                    phase.name(),
                    action_slug(action)
                ),
                rule: rule.to_string(),
                severity,
                phase,
                action,
                context: r.context.name(),
                expected,
                observed: if interesting.is_empty() {
                    observed
                } else {
                    interesting.join(" | ")
                },
                detail,
                repro: repro_steps(phase, action),
                sent_hex: hex::encode(&r.sent),
                seed: r.seed,
                reps: r.reps,
            }
        })
        .collect()
}

/// The rule a finding should cite, given what actually happened.
///
/// `Action::rule` names the rule the *input* is about.  When the target did
/// not accept the input, though, that rule is satisfied and the divergence
/// is a different one — most often "a failed record must end the
/// connection" (R-4.2/R-7.3) rather than "the retired key must not work"
/// (R-5.4).  Citing the rule the evidence actually breaks keeps the report
/// honest and keeps distinct faults from being conflated.
fn effective_rule(r: &Run) -> &'static str {
    match r.action {
        Action::AppDataOldEpoch if !r.reaction.accepted => "R-4.2",
        Action::AppDataBadMac if !r.reaction.accepted => "R-4.2",
        _ => r.action.rule(r.phase),
    }
}

fn action_slug(a: Action) -> &'static str {
    match a {
        Action::ClientHelloV1 => "client-hello",
        Action::ClientHelloBadVersion => "client-hello-bad-version",
        Action::ClientFinishValid => "client-finish",
        Action::ClientFinishBadMac => "client-finish-bad-mac",
        Action::SessionResumeValid => "resume",
        Action::SessionResumeInvalidTicket => "resume-forged-ticket",
        Action::SessionResumeReusedTicket => "resume-reused-ticket",
        Action::AppDataInSequence => "app-data",
        Action::AppDataGap => "app-data-gap",
        Action::AppDataReplay => "app-data-replay",
        Action::AppDataOldEpoch => "app-data-old-epoch",
        Action::AppDataBadMac => "app-data-bad-mac",
        Action::RekeyValid => "rekey",
        Action::CloseValid => "close",
        Action::WireUnknownType => "wire-unknown-type",
        Action::WireOversize => "wire-oversize",
        Action::ReflectedServerHello => "wire-reflected",
        Action::IdlePastDeadline => "idle-handshake-deadline",
        Action::IdlePastIdleTimeout => "idle-established-timeout",
    }
}

/// Name the fault class in one human sentence.
fn diagnose(action: Action, phase: Phase, severity: Severity, obs: &[Observed]) -> String {
    use Action::*;
    let accepted = obs.iter().any(|o| {
        matches!(
            o,
            Observed::AppData(_)
                | Observed::AppDataOldEpoch(_)
                | Observed::Rekey { .. }
                | Observed::CloseRecv
                | Observed::ServerHello { .. }
                | Observed::ServerFinish { .. }
                | Observed::ResumeOk { .. }
        )
    });
    let what = if accepted { "accepted" } else { "did not accept" };
    match action {
        AppDataInSequence | AppDataGap | AppDataReplay | AppDataOldEpoch | AppDataBadMac
            if phase == Phase::AwaitFinish && severity == Severity::Critical =>
        {
            "Server processed application-layer ciphertext before the handshake \
             finished. The epoch-0 keys are derivable from the HELLO flight alone \
             (R-3.5), so early records decrypt; the state machine is the only thing \
             that keeps 0-RTT data out (R-3.7), and it does not here."
                .into()
        }
        RekeyValid if phase == Phase::AwaitFinish => {
            "Server performed a key rotation before SERVER_FINISH. Keys in use do \
             not match the handshake transcript it has not yet completed (R-3.7/R-5.3)."
                .into()
        }
        CloseValid if phase == Phase::AwaitFinish => {
            "Server honoured a CLOSE it received before the handshake finished (R-3.7)."
                .into()
        }
        SessionResumeValid if phase == Phase::Established || phase == Phase::AwaitFinish => {
            "Server honoured SESSION_RESUME outside a connection's first frame (R-6.2)."
                .into()
        }
        SessionResumeReusedTicket => {
            "Server accepted a session ticket that had already been redeemed once (R-6.4)."
                .into()
        }
        AppDataBadMac if accepted => {
            "Server accepted a record whose AEAD tag did not verify (R-4.2).".into()
        }
        AppDataBadMac => {
            "Server did not answer ERR(BadMac) and close after a record failed \
             authentication; it ignored the frame and kept the connection open \
             (R-4.2/R-7.3)."
                .into()
        }
        AppDataGap | AppDataReplay => {
            "Server accepted a record whose seq did not equal the expected value; \
             out-of-order and duplicated records are therefore both accepted (R-4.3)."
                .into()
        }
        AppDataOldEpoch if accepted => {
            "Server accepted a record sealed under a key epoch it had already \
             rotated away from; retired keys are not destroyed (R-5.4)."
                .into()
        }
        AppDataOldEpoch => {
            "Server failed to end the connection after a record it could not \
             authenticate (a retired-epoch record). Ignoring an authentication \
             failure is itself a fault (R-4.2/R-7.3), even though the key \
             rotation requirement (R-5.4) was met."
                .into()
        }
        _ => format!(
            "Server {} an input that the spec requires it to {} (severity {}).",
            what,
            match severity {
                Severity::Critical => "reject",
                Severity::Major => "accept",
                Severity::Minor => "handle exactly",
            },
            severity.as_str()
        ),
    }
}

/// Protocol-level reproduction recipe.  Each line is one action the reader
/// can perform with the probe's `replay` mode or by hand.
pub fn repro_steps(phase: Phase, action: Action) -> Vec<String> {
    use Action::*;
    let mut v = Vec::new();
    v.push(format!("connect to the target ({})", phase.name()));
    match phase {
        Phase::Start => {}
        Phase::AwaitFinish => {
            v.push("send CLIENT_HELLO(version=1, random=Rc, eph=Ec)".into());
            v.push("read SERVER_HELLO(version=1, random=Rs, eph=Es)".into());
            v.push("derive epoch-0 keys from SHA256(HELLO flight) (spec R-3.5)".into());
        }
        Phase::Established | Phase::Closed => {
            v.push("send CLIENT_HELLO(version=1, random=Rc, eph=Ec)".into());
            v.push("read SERVER_HELLO(version=1, random=Rs, eph=Es)".into());
            if action == AppDataOldEpoch {
                v.push("send CLIENT_FINISH(verify) and read SERVER_FINISH + ticket".into());
                v.push("send REKEY(seq=0, contribution C0); read REKEY(seq=0) in epoch 1".into());
                v.push("keep the epoch-0 keys as the 'retired' set".into());
            } else {
                v.push("send CLIENT_FINISH(verify) and read SERVER_FINISH + ticket".into());
            }
        }
    }
    match action {
        ClientHelloV1 => v.push("send CLIENT_HELLO(version=1) again".into()),
        ClientHelloBadVersion => v.push("send CLIENT_HELLO(version=0x0200)".into()),
        ClientFinishValid => v.push("send CLIENT_FINISH(verify=valid)".into()),
        ClientFinishBadMac => v.push("send CLIENT_FINISH(verify=32 zero bytes)".into()),
        SessionResumeValid => v.push("send SESSION_RESUME(ticket=valid, random=Rr, eph=Er)".into()),
        SessionResumeInvalidTicket => {
            v.push("flip any bit in the ticket's sealed payload (offset 40)".into());
            v.push("send SESSION_RESUME(ticket=corrupted, random=Rr, eph=Er)".into());
        }
        SessionResumeReusedTicket => {
            v.push("first redeem the ticket on a throwaway connection".into());
            v.push("send SESSION_RESUME(same ticket again)".into());
        }
        AppDataInSequence => {
            v.push("send APP_DATA(seq=expected, ct=SEAL(key, op=0x01 'ping'))".into())
        }
        AppDataGap => v.push("send APP_DATA(seq=expected+1, ct=SEAL(...))".into()),
        AppDataReplay => v.push("send APP_DATA(seq=expected-1, ct=SEAL(...))".into()),
        AppDataOldEpoch => {
            v.push("send APP_DATA(seq=expected, ct=SEAL(epoch-0 key, op=0x01 'ping'))".into())
        }
        AppDataBadMac => {
            v.push("flip one bit in the AEAD tag of an otherwise valid APP_DATA".into())
        }
        RekeyValid => v.push("send REKEY(seq=expected, ct=SEAL(key, C1))".into()),
        CloseValid => v.push("send CLOSE(seq=expected, ct=SEAL(key, ''))".into()),
        WireUnknownType => v.push("send raw bytes: 00 00 00 02 99 00".into()),
        WireOversize => v.push("send raw length prefix 00 00 4E 20 (20000), no body".into()),
        ReflectedServerHello => v.push("send a SERVER_HELLO frame back at the server".into()),
        IdlePastDeadline => v.push("send nothing; wait 900 ms".into()),
        IdlePastIdleTimeout => v.push("send nothing; wait 3200 ms".into()),
    }
    v.push(format!("expected: {}", crate::model::expect(phase, action).map(|e| e.describe()).unwrap_or_default()));
    v
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub fn render_markdown(impl_name: &str, report: &crate::explore::Report, findings: &[Finding]) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# SCP/1 black-box report — `{impl_name}`\n");
    let _ = writeln!(
        s,
        "{} interaction(s) in {} round(s), {:.1}s. Stop reason: **{}**.",
        report.interactions,
        report.rounds,
        report.elapsed.as_secs_f64(),
        report.stop_reason
    );
    let _ = writeln!(
        s,
        "{} distinct (phase, action, behaviour) observations.\n",
        report.coverage.len()
    );

    let crit = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let major = findings.iter().filter(|f| f.severity == Severity::Major).count();
    let minor = findings.iter().filter(|f| f.severity == Severity::Minor).count();
    let _ = writeln!(
        s,
        "## Verdict\n\n**{} critical, {} major, {} minor** divergence(s).\n",
        crit, major, minor
    );

    if findings.is_empty() {
        let _ = writeln!(s, "No divergence from the spec was observed within the budget.");
        return s;
    }

    for (i, f) in findings.iter().enumerate() {
        let _ = writeln!(
            s,
            "### {}. {} in {} [{}] ({})\n",
            i + 1,
            f.action.name(),
            f.phase.name(),
            f.context,
            f.severity.as_str()
        );
        let _ = writeln!(s, "- **id**: `{}`", f.id);
        let _ = writeln!(s, "- **rule**: {}", f.rule);
        let _ = writeln!(s, "- **phase**: {}", f.phase.name());
        let _ = writeln!(s, "- **connection context**: {}", f.context);
        let _ = writeln!(s, "- **expected**: {}", f.expected);
        let _ = writeln!(s, "- **observed**: {}", f.observed);
        let _ = writeln!(
            s,
            "- **reproduced in**: {}/{} repetitions",
            f.reps, f.reps
        );
        let _ = writeln!(s, "- **why it matters**: {}\n", f.detail);
        let _ = writeln!(s, "Reproduction:");
        let _ = writeln!(s, "```");
        for step in &f.repro {
            let _ = writeln!(s, "{step}");
        }
        let _ = writeln!(s, "```");
        if !f.sent_hex.is_empty() {
            let _ = writeln!(s, "\nLast frame sent (hex):\n\n```\n{}\n```", f.sent_hex);
        }
        let _ = writeln!(s);
    }
    s
}
