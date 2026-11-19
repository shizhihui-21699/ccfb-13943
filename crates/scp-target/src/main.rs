use std::process::ExitCode;

use clap::Parser;
use scp_target::impls::Impl;
use scp_target::transport::ServerCfg;

#[derive(Parser, Debug)]
#[command(
    name = "scp-target",
    about = "SCP/1 target server (one of several implementations, some faulty)"
)]
struct Args {
    /// Which implementation to serve.
    #[arg(long, value_enum, default_value_t = Impl::Reference)]
    impl_: Impl,

    /// RNG seed; the same seed plus the same message sequence reproduces a
    /// run exactly.
    #[arg(long, default_value_t = 1)]
    seed: u64,

    /// Handshake deadline in milliseconds (SPEC R-7.1 defaults to 120).
    #[arg(long)]
    handshake_deadline_ms: Option<u64>,

    /// Idle timeout in milliseconds (SPEC R-7.2 defaults to 2000).
    #[arg(long)]
    idle_timeout_ms: Option<u64>,

    /// Ticket lifetime in milliseconds.
    #[arg(long)]
    ticket_ttl_ms: Option<u64>,

    /// Largest legal frame body_len (defaults to 16384 per SPEC R-1.1).
    #[arg(long)]
    max_frame: Option<usize>,

    /// Print the chosen listen address on stdout as `ADDR=<ip:port>` and
    /// keep serving until killed.
    #[arg(long, default_value_t = true)]
    announce: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let mut cfg = ServerCfg::default();
    if let Some(v) = args.handshake_deadline_ms {
        cfg.handshake_deadline = std::time::Duration::from_millis(v);
    }
    if let Some(v) = args.idle_timeout_ms {
        cfg.idle_timeout = std::time::Duration::from_millis(v);
    }
    if let Some(v) = args.ticket_ttl_ms {
        cfg.ticket_ttl_ms = v;
    }
    if let Some(v) = args.max_frame {
        cfg.max_frame = v;
    }

    let handle = match scp_target::spawn(args.impl_, args.seed, cfg) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("bind failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if args.announce {
        println!("ADDR={}", handle.addr());
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
    eprintln!("scp-target: impl={} seed={}", args.impl_.name(), args.seed);
    loop {
        std::thread::park();
    }
}
