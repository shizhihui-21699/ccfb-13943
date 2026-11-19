use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use scp_probe::case::Target;
use scp_probe::explore::Budget;

#[derive(Parser, Debug)]
#[command(
    name = "scp-probe",
    about = "Black-box SCP/1 conformance prober: learn a server's real state machine, diff it against the spec, emit reproducible findings"
)]
struct Args {
    /// Address of a running SCP/1 server, e.g. 127.0.0.1:9000.
    #[arg(long)]
    addr: String,

    /// Label for this target, used in report ids (defaults to the address).
    #[arg(long)]
    name: Option<String>,

    /// Maximum number of interactions (one TCP connection each).
    #[arg(long, default_value_t = 500)]
    max_interactions: usize,

    /// Repetitions per case (randomness / hidden-state robustness).
    #[arg(long, default_value_t = 2)]
    reps: usize,

    /// Consecutive no-new-coverage rounds before stopping.
    #[arg(long, default_value_t = 2)]
    patience: usize,

    /// Write the Markdown report here (also printed if omitted).
    #[arg(long)]
    out: Option<PathBuf>,

    /// Write findings as JSON here.
    #[arg(long)]
    json: Option<PathBuf>,

    /// Exit non-zero if any critical finding is present.
    #[arg(long, default_value_t = false)]
    fail_on_critical: bool,

    /// Instead of exploring, replay one case given by --phase/--action.
    #[arg(long)]
    replay_phase: Option<String>,

    /// Case action for --replay-phase (e.g. app-data, resume-reused-ticket).
    #[arg(long)]
    replay_action: Option<String>,

    /// Seed for the replay.
    #[arg(long, default_value_t = 0xD0D0)]
    replay_seed: u64,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let addr: SocketAddr = match args.addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("bad --addr: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(phase_s) = args.replay_phase.as_deref() {
        let Some(phase) = scp_probe::replay::parse_phase(phase_s) else {
            eprintln!("unknown --replay-phase {phase_s:?}");
            return ExitCode::FAILURE;
        };
        let Some(action_s) = args.replay_action.as_deref() else {
            eprintln!("--replay-phase needs --replay-action");
            return ExitCode::FAILURE;
        };
        let Some(action) = scp_probe::replay::parse_action(action_s) else {
            eprintln!("unknown --replay-action {action_s:?}");
            return ExitCode::FAILURE;
        };
        return match scp_probe::replay::replay_verbose(addr, phase, action, args.replay_seed) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("replay failed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    let target = Target::new(addr);
    let name = args.name.unwrap_or_else(|| args.addr.clone());
    let budget = Budget {
        max_interactions: args.max_interactions,
        reps: args.reps.max(1),
        patience: args.patience,
        wall_clock: std::time::Duration::from_secs(780),
    };

    eprintln!("scp-probe: exploring {name} at {addr}");
    let report = scp_probe::explore(&target, budget);
    let findings = scp_probe::report::build(&name, &report.runs);
    let md = scp_probe::report::render_markdown(&name, &report, &findings);
    print!("{md}");

    if let Some(p) = args.out {
        if let Err(e) = std::fs::write(&p, &md) {
            eprintln!("could not write {}: {e}", p.display());
        } else {
            eprintln!("report: {}", p.display());
        }
    }
    if let Some(p) = args.json {
        match serde_json::to_string_pretty(&findings_json(&findings)) {
            Ok(s) => {
                if let Err(e) = std::fs::write(&p, s) {
                    eprintln!("could not write {}: {e}", p.display());
                } else {
                    eprintln!("findings json: {}", p.display());
                }
            }
            Err(e) => eprintln!("json: {e}"),
        }
    }

    let critical = findings
        .iter()
        .filter(|f| f.severity == scp_probe::Severity::Critical)
        .count();
    if args.fail_on_critical && critical > 0 {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn findings_json(findings: &[scp_probe::Finding]) -> serde_json::Value {
    use serde_json::json;
    json!(
        findings
            .iter()
            .map(|f| json!({
                "id": f.id,
                "rule": f.rule,
                "severity": f.severity.as_str(),
                "phase": f.phase.name(),
                "context": f.context,
                "action": f.action.name(),
                "expected": f.expected,
                "observed": f.observed,
                "detail": f.detail,
                "repro": f.repro,
                "sent_hex": f.sent_hex,
            }))
            .collect::<Vec<_>>()
    )
}
