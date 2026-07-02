//! Cryptographic utilities using the `ring` library.
//!
//! All cryptographic operations go through `ring` — no openssl, no native-tls.
//! This provides:
//! - Constant-time token comparison (hmac-based)
//! - Secure random token generation
//! - SHA-256 hashing with optional HMAC
//! - Bot hash generation with random padding
//! - AEAD encrypt/decrypt (ChaCha20-Poly1305 via ring)
//! - ZW transport session key derivation

use ring::digest::{digest, SHA256};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::Result;

/// Generate a cryptographically secure random hex token.
///
/// Returns a 64-character hex string (32 bytes of entropy).
/// Used for admin tokens, lints tokens, and other secrets.
pub fn generate_token() -> String {
    let rng = SystemRandom::new();
    let mut buf = [0u8; 32];
    rng.fill(&mut buf)
        .expect("SystemRandom::fill should never fail on a valid buffer");
    hex::encode(buf)
}

/// Generate a cryptographically secure random token of specified byte length.
pub fn generate_token_bytes(n_bytes: usize) -> Vec<u8> {
    let rng = SystemRandom::new();
    let mut buf = vec![0u8; n_bytes];
    rng.fill(&mut buf)
        .expect("SystemRandom::fill should never fail on a valid buffer");
    buf
}

/// Constant-time comparison of two byte slices.
///
/// Uses `ring::hmac::verify` with a fixed key for timing-attack-safe
/// comparison. This prevents byte-by-byte timing oracle attacks on
/// token validation.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // Use HMAC verification for constant-time comparison
    let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
    let tag_a = hmac::sign(&key, a);
    hmac::verify(&key, b, tag_a.as_ref()).is_ok()
}

/// Constant-time comparison for string tokens.
pub fn constant_time_str_eq(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Compute SHA-256 hash of data, returning hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let d = digest(&SHA256, data);
    hex::encode(d.as_ref())
}

/// Compute SHA-256 HMAC.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, data);
    tag.as_ref().to_vec()
}

/// BotHasher — generates padded, randomized bot hashes for heartbeat.
///
/// Each heartbeat produces a different hash even for the same bot,
/// preventing static fingerprinting. The hash format is:
/// `<random_padding>:<sha256(padding + bot_id)[:16]>`
pub struct BotHasher {
    rng: SystemRandom,
}

impl Clone for BotHasher {
    fn clone(&self) -> Self {
        // SystemRandom is just an fd — cheap to reuse
        BotHasher { rng: SystemRandom::new() }
    }
}

impl BotHasher {
    pub fn new() -> Self {
        BotHasher {
            rng: SystemRandom::new(),
        }
    }

    /// Generate a new padded hash for the given bot ID.
    ///
    /// Returns a string like `PADDING:HEXHASH` where:
    /// - PADDING is 32 random bytes in base32 (no padding)
    /// - HEXHASH is the first 16 hex chars of SHA256(padding + bot_id)
    pub fn generate_padded_hash(&self, bot_id: &str) -> String {
        let mut pad = [0u8; 16];
        let _ = self.rng.fill(&mut pad);

        let pad_b32 = data_encoding::BASE32_NOPAD.encode(&pad);

        let mut combined = Vec::with_capacity(pad.len() + bot_id.len());
        combined.extend_from_slice(&pad);
        combined.extend_from_slice(bot_id.as_bytes());

        let hash = sha256_hex(&combined);
        let short_hash = &hash[..16];

        format!("{}:{}", pad_b32, short_hash)
    }
}

impl Default for BotHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Securely compare two hex-encoded SHA-256 hashes.
pub fn secure_hash_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let a_bytes = match hex::decode(a) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let b_bytes = match hex::decode(b) {
        Ok(v) => v,
        Err(_) => return false,
    };
    constant_time_eq(&a_bytes, &b_bytes)
}

// ── AEAD Encrypt/Decrypt (ChaCha20-Poly1305) ───────────────────────────────

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

/// ZW transport session key — 32 bytes for CHACHA20_POLY1305.
pub const SESSION_KEY_LEN: usize = 32;
/// AEAD nonce length.
pub const NONCE_LEN: usize = 12;
/// AEAD tag overhead (ChaCha20-Poly1305 = 16 bytes).
pub const TAG_LEN: usize = 16;

/// Encrypt plaintext with ChaCha20-Poly1305.
///
/// Returns `ciphertext || tag` (the tag is appended by ring).
/// The nonce MUST be unique per encryption with the same key.
pub fn aead_encrypt(key: &[u8; SESSION_KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|_| crate::error::ArcticFoxError::Internal { message: "bad AEAD key".into() })?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(*nonce);

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| crate::error::ArcticFoxError::Internal { message: "AEAD encrypt failed".into() })?;

    Ok(in_out)
}

/// Decrypt ciphertext (with appended tag) using ChaCha20-Poly1305.
pub fn aead_decrypt(key: &[u8; SESSION_KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < TAG_LEN {
        return Err(crate::error::ArcticFoxError::Internal { message: "ciphertext too short".into() });
    }

    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|_| crate::error::ArcticFoxError::Internal { message: "bad AEAD key".into() })?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(*nonce);

    let mut in_out = ciphertext.to_vec();
    let _plaintext_slice = key.open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| crate::error::ArcticFoxError::Internal { message: "AEAD decrypt failed — wrong key or corrupted data".into() })?;

    // Return exactly the plaintext (open_in_place returns full buffer with zeroed tag;
    // we must truncate to plaintext length ourselves)
    let pt_len = ciphertext.len() - TAG_LEN;
    Ok(in_out[..pt_len].to_vec())
}

/// Derive a session key from a shared secret using HKDF-SHA256.
pub fn derive_session_key(shared_secret: &[u8], salt: &[u8], info: &[u8]) -> [u8; SESSION_KEY_LEN] {
    use ring::hkdf::{Salt, HKDF_SHA256, KeyType};

    struct Len(usize);
    impl KeyType for Len {
        fn len(&self) -> usize { self.0 }
    }

    let salt = Salt::new(HKDF_SHA256, salt);
    let prk = salt.extract(shared_secret);
    let mut derived = [0u8; SESSION_KEY_LEN];
    let _ = prk.expand(&[info], Len(SESSION_KEY_LEN))
        .and_then(|okm| okm.fill(&mut derived));
    derived
}

/// Generate a random nonce for AEAD.
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    let rng = SystemRandom::new();
    let _ = rng.fill(&mut nonce);
    nonce
}

/// Generate a random session key.
pub fn generate_session_key() -> [u8; SESSION_KEY_LEN] {
    let mut key = [0u8; SESSION_KEY_LEN];
    let rng = SystemRandom::new();
    let _ = rng.fill(&mut key);
    key
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_generation_is_unique() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_eq!(t1.len(), 64);
        assert_ne!(t1, t2);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hello!"));
    }

    #[test]
    fn constant_time_str_eq_works() {
        assert!(constant_time_str_eq("secret", "secret"));
        assert!(!constant_time_str_eq("secret", "wrong"));
    }

    #[test]
    fn bot_hasher_generates_unique_hashes() {
        let hasher = BotHasher::new();
        let h1 = hasher.generate_padded_hash("bot123");
        let h2 = hasher.generate_padded_hash("bot123");
        assert_ne!(h1, h2);
        assert!(h1.contains(':'));
        let parts: Vec<&str> = h1.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].len(), 16);
    }

    #[test]
    fn sha256_hex_output_length() {
        let hash = sha256_hex(b"hello");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn aead_roundtrip() {
        let key = generate_session_key();
        let nonce = generate_nonce();
        let msg = b"test-bot-ABC123";
        let ct = aead_encrypt(&key, &nonce, msg).unwrap();
        let pt = aead_decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, msg, "AEAD roundtrip failed");
    }

    #[test]
    fn aead_tampered_ciphertext_fails() {
        let key = generate_session_key();
        let nonce = generate_nonce();
        let msg = b"test-data";
        let mut ct = aead_encrypt(&key, &nonce, msg).unwrap();
        if !ct.is_empty() { ct[0] ^= 1; }
        assert!(aead_decrypt(&key, &nonce, &ct).is_err());
    }

    #[test]
    fn aead_wrong_nonce_fails() {
        let key = generate_session_key();
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        let ct = aead_encrypt(&key, &n1, b"test").unwrap();
        assert!(aead_decrypt(&key, &n2, &ct).is_err());
    }

    #[test]
    fn aead_empty_plaintext_roundtrip() {
        let key = generate_session_key();
        let nonce = generate_nonce();
        let ct = aead_encrypt(&key, &nonce, b"").unwrap();
        let pt = aead_decrypt(&key, &nonce, &ct).unwrap();
        assert!(pt.is_empty());
    }
}
