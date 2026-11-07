//! `vaultosd`: serves the agent API for one vault over a Unix socket. It starts locked;
//! `vaultos unlock` (or the app) unlocks it. See `docs/AGENTS.md`.

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "vaultosd",
    version,
    about = "VaultOS daemon: the agent API over a Unix socket"
)]
struct Args {
    /// The vault's folder (default: VAULTOS_DATA_DIR, else the platform's app-data folder).
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
    /// Lock after this many minutes without a successful request.
    #[arg(long, value_name = "MINUTES", value_parser = clap::value_parser!(u64).range(1..=10080))]
    idle_lock_minutes: Option<u64>,
    /// If the app owns the vault, wait for it to quit and take over (for a login service).
    #[arg(long)]
    wait: bool,
}

fn main() -> ExitCode {
    vaultos_core::hardening::harden_process();
    let args = Args::parse();
    let data_dir = match args
        .data_dir
        .map_or_else(vaultos_core::paths::default_data_dir, Ok)
    {
        Ok(d) if d.is_absolute() => d,
        Ok(_) => {
            eprintln!("vaultosd: --data-dir must be absolute");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("vaultosd: {e}");
            return ExitCode::from(2);
        }
    };
    let cfg = vaultos_daemon::server::Config {
        data_dir,
        idle_lock: args.idle_lock_minutes.map(|m| Duration::from_secs(m * 60)),
        wait_for_owner: args.wait,
        sync_repo: None,
        confirm: None,
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(8)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("vaultosd: cannot start: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(vaultos_daemon::server::run(cfg)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vaultosd: {e}");
            ExitCode::FAILURE
        }
    }
}
