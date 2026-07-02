//! C3 Unified Console Dashboard — full C2 control from one terminal.
//!
//! Two modes:
//!   Remote:  c3 --connect http://c2-server:7443 --token <admin_token>
//!   Local:   c3 --local  (spawns API server in-process)

mod api;
mod app;
mod ui;
mod tabs;

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "c3", version, about = "C3 Unified Console Dashboard")]
struct Cli {
    /// Connect to remote API server
    #[arg(long, default_value = "http://localhost:7443")]
    connect: String,

    /// Admin token for remote API
    #[arg(long)]
    token: Option<String>,

    /// Run embedded: start API server in-process
    #[arg(long, conflicts_with = "connect")]
    local: bool,

    /// Path to config directory (default: ~/.c3/)
    #[arg(long, default_value = "~/.c3")]
    config_dir: PathBuf,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let api_url = if cli.local {
        "http://127.0.0.1:7443".to_string()
    } else {
        cli.connect.clone()
    };

    let token = cli.token.unwrap_or_else(|| {
        std::env::var("C3_TOKEN").unwrap_or_default()
    });

    if token.is_empty() && !cli.local {
        eprintln!("Error: --token required for remote mode (or set C3_TOKEN env var)");
        std::process::exit(1);
    }

    let api = api::ApiClient::new(&api_url, &token);

    // Health check
    match api.whoami().await {
        Ok(role) => {
            eprintln!("Connected to {} — role: {} — hit 'q' to quit, '?' for help", api_url, role);
        }
        Err(_) => {
            eprintln!("Warning: Could not authenticate with API at {}. Starting in offline mode.", api_url);
        }
    }

    let mut dashboard = app::DashboardApp::new(api);
    dashboard.run().await.unwrap_or_else(|e| {
        eprintln!("Dashboard error: {e}");
    });
}
