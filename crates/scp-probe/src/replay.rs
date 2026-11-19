//! `replay`: re-execute one finding's case and print a trace of exactly
//! what went on the wire and what came back.
//!
//! This is the "reproduction steps" half of a finding, made mechanical: the
//! same `(phase, action)` script the prober used is re-run against the
//! target, with the transcript shown frame by frame.

use std::net::SocketAddr;

use crate::case::{run_case, Scenario, Target};
use crate::model::{expect, Action, Phase};
use crate::report::Finding;

pub fn parse_action(s: &str) -> Option<Action> {
    use Action::*;
    Some(match s {
        "client-hello" | "ClientHelloV1" => ClientHelloV1,
        "client-hello-bad-version" | "ClientHelloBadVersion" => ClientHelloBadVersion,
        "client-finish" | "ClientFinishValid" => ClientFinishValid,
        "client-finish-bad-mac" | "ClientFinishBadMac" => ClientFinishBadMac,
        "resume" | "SessionResumeValid" => SessionResumeValid,
        "resume-forged-ticket" | "SessionResumeInvalidTicket" => SessionResumeInvalidTicket,
        "resume-reused-ticket" | "SessionResumeReusedTicket" => SessionResumeReusedTicket,
        "app-data" | "AppDataInSequence" => AppDataInSequence,
        "app-data-gap" | "AppDataGap" => AppDataGap,
        "app-data-replay" | "AppDataReplay" => AppDataReplay,
        "app-data-old-epoch" | "AppDataOldEpoch" => AppDataOldEpoch,
        "app-data-bad-mac" | "AppDataBadMac" => AppDataBadMac,
        "rekey" | "RekeyValid" => RekeyValid,
        "close" | "CloseValid" => CloseValid,
        "wire-unknown-type" | "WireUnknownType" => WireUnknownType,
        "wire-oversize" | "WireOversize" => WireOversize,
        "wire-reflected" | "ReflectedServerHello" => ReflectedServerHello,
        "idle-handshake-deadline" | "IdlePastDeadline" => IdlePastDeadline,
        "idle-established-timeout" | "IdlePastIdleTimeout" => IdlePastIdleTimeout,
        _ => return None,
    })
}

pub fn parse_phase(s: &str) -> Option<Phase> {
    Some(match s {
        "Start" | "start" => Phase::Start,
        "AwaitFinish" | "await-finish" => Phase::AwaitFinish,
        "Established" | "established" => Phase::Established,
        "Closed" | "closed" => Phase::Closed,
        _ => return None,
    })
}

/// Replay a single case with a full trace.
pub fn replay(addr: SocketAddr, phase: Phase, action: Action, seed: u64) -> Result<(), String> {
    let target = Target::new(addr);
    println!("replaying {}/{} against {addr}", phase.name(), action.name());
    if let Some(e) = expect(phase, action) {
        println!("spec requires: {}", e.describe());
    }
    let (reaction, sent) = run_case(&target, phase, action, seed)?;
    println!("\nframes sent:");
    if sent.is_empty() {
        println!("  (none)");
    } else {
        println!("  {}", hex::encode(&sent));
    }
    println!("\nobserved: {}", reaction.summary());
    println!(
        "verdict: {}",
        match expect(phase, action) {
            Some(e) if reaction.meets(e) => "conforms".to_string(),
            Some(e) => format!("DIVERGES (spec requires {})", e.describe()),
            None => "not constrained".into(),
        }
    );
    Ok(())
}

/// Replay with an explicit scenario trace (used interactively).
pub fn replay_verbose(addr: SocketAddr, phase: Phase, action: Action, seed: u64) -> Result<(), String> {
    let target = Target::new(addr);
    let needs_ticket = matches!(
        action,
        Action::SessionResumeValid
            | Action::SessionResumeInvalidTicket
            | Action::SessionResumeReusedTicket
    );
    let mut sc = if needs_ticket {
        Scenario::with_ticket(&target, seed)?
    } else {
        Scenario::new(&target, seed)?
    };
    sc.reach(phase, matches!(action, Action::AppDataOldEpoch))?;
    let before = sc.session.transcript.len();
    sc.present(action)?;
    let observed = sc.collect(action);
    println!("transcript:");
    for (label, bytes) in &sc.session.transcript {
        println!("  -> {label:<34} {}", hex::encode(bytes));
    }
    let _ = before;
    println!("observed: {observed:?}");
    Ok(())
}

impl Finding {
    pub fn replay(&self, addr: SocketAddr) -> Result<(), String> {
        replay(addr, self.phase, self.action, self.seed)
    }
}
