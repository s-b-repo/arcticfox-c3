//! Zero-Width Unicode Steganography Codec
//!
//! Encodes arbitrary bytes into invisible zero-width Unicode characters.
//! Uses base-4 encoding: 4 zero-width chars per byte.
//!
//! Character mapping:
//!   U+200B  Zero Width Space       = 0
//!   U+200C  Zero Width Non-Joiner  = 1
//!   U+200D  Zero Width Joiner      = 2
//!   U+FEFF  Zero Width No-Break Sp = 3

use rand::Rng;
use std::collections::HashMap;

use crate::error::{ArcticFoxError, Result};

// ── Constants ───────────────────────────────────────────────────────────────

/// The four zero-width characters used in encoding.
pub const ZW_CHARS: [char; 4] = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}'];

/// Start marker: 8 ZW chars marking payload start.
const START_MARKER: &str = "\u{200B}\u{200B}\u{200C}\u{200C}\u{200D}\u{200D}\u{FEFF}\u{FEFF}";

/// End marker: 8 ZW chars marking payload end.
const END_MARKER: &str = "\u{FEFF}\u{FEFF}\u{200D}\u{200D}\u{200C}\u{200C}\u{200B}\u{200B}";

/// Target padding size in bytes (≈1 MB of ZW chars).
pub const ZW_PAD_TARGET: usize = 1_048_576;

/// Number of ZW chars per encoded byte.
const ZW_PER_BYTE: usize = 4;

/// All ZW characters as a set for fast lookup.
lazy_static::lazy_static! {
    static ref ZW_SET: std::collections::HashSet<char> = ZW_CHARS.iter().copied().collect();
    static ref ZW_MAP: HashMap<char, u8> = ZW_CHARS.iter().enumerate()
        .map(|(i, &c)| (c, i as u8))
        .collect();
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Encode arbitrary bytes into a zero-width Unicode string.
///
/// Each input byte becomes 4 zero-width characters (base-4 encoding).
/// Returns a `String` containing only ZW characters.
///
/// # Examples
///
/// ```ignore
/// let encoded = zwcodec::encode(b"hello");
/// assert_eq!(encoded.len(), 20); // 5 bytes × 4 ZW chars
/// assert!(encoded.chars().all(|c| ZW_CHARS.contains(&c)));
/// ```
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * ZW_PER_BYTE);
    for &byte in data {
        out.push(ZW_CHARS[(byte >> 6 & 3) as usize]);
        out.push(ZW_CHARS[(byte >> 4 & 3) as usize]);
        out.push(ZW_CHARS[(byte >> 2 & 3) as usize]);
        out.push(ZW_CHARS[(byte & 3) as usize]);
    }
    out
}

/// Decode a zero-width Unicode string back into bytes.
///
/// Filters out non-ZW characters, then decodes groups of 4 ZW chars into bytes.
/// Any trailing incomplete group is silently ignored.
///
/// # Errors
///
/// Returns `TruncatedZw` if no valid ZW characters are found.
/// Returns `InvalidZwChar` if a character in the ZW set maps to an invalid value.
pub fn decode(zw_text: &str) -> Result<Vec<u8>> {
    let chars: Vec<char> = zw_text.chars().filter(|c| ZW_SET.contains(c)).collect();

    if chars.is_empty() {
        return Err(ArcticFoxError::NoPayload);
    }

    let usable = chars.len() - (chars.len() % ZW_PER_BYTE);
    if usable == 0 {
        return Err(ArcticFoxError::TruncatedZw {
            actual: chars.len(),
        });
    }

    let mut result = Vec::with_capacity(usable / ZW_PER_BYTE);

    for chunk in chars[..usable].chunks_exact(ZW_PER_BYTE) {
        let byte = (zw_val(chunk[0])? << 6)
            | (zw_val(chunk[1])? << 4)
            | (zw_val(chunk[2])? << 2)
            | zw_val(chunk[3])?;
        result.push(byte);
    }

    Ok(result)
}

/// Convert a ZW character to its numeric value (0-3).
fn zw_val(c: char) -> Result<u8> {
    ZW_MAP.get(&c).copied().ok_or_else(|| ArcticFoxError::InvalidZwChar {
        pos: 0,
        byte: c as u16,
    })
}

/// Generate random ZW padding of approximately `target_bytes` of underlying data.
///
/// This produces a string of ZW characters that, when decoded, would yield
/// roughly `target_bytes` of random data. Used for anti-analysis padding.
pub fn gen_padding(target_bytes: usize) -> String {
    let chars_needed = target_bytes * ZW_PER_BYTE;
    let mut rng = rand::thread_rng();
    let mut out = String::with_capacity(chars_needed);
    for _ in 0..chars_needed {
        let idx = rng.gen_range(0..4);
        out.push(ZW_CHARS[idx]);
    }
    out
}

/// Inject a ZW-encoded payload into a README (or any markdown text).
///
/// Strips any existing ZW characters from the input, then inserts the
/// encoded payload (with start/end markers) into the first line starting
/// with `#`. If no heading is found, appends to the last line.
///
/// When `pad` is true, appends ~1MB of random ZW noise after the end marker
/// to make extraction computationally expensive and hinder analysis.
pub fn inject(readme: &str, payload: &[u8], pad: bool) -> Result<String> {
    let clean = strip(readme);
    let mut blob = String::with_capacity(
        START_MARKER.len() + payload.len() * ZW_PER_BYTE + END_MARKER.len(),
    );
    blob.push_str(START_MARKER);
    blob.push_str(&encode(payload));
    blob.push_str(END_MARKER);

    if pad {
        blob.push_str(&gen_padding(ZW_PAD_TARGET));
    }

    let mut lines: Vec<&str> = clean.lines().collect();
    if lines.is_empty() {
        return Ok(blob);
    }

    // Find first heading line
    let heading_idx = lines.iter().position(|line| line.starts_with('#'));
    match heading_idx {
        Some(idx) => {
            lines[idx] = &lines[idx];
            // We need to rebuild the string with the injection
            let mut result = String::with_capacity(clean.len() + blob.len());
            for (i, line) in lines.iter().enumerate() {
                if i > 0 {
                    result.push('\n');
                }
                result.push_str(line);
                if i == idx {
                    result.push_str(&blob);
                }
            }
            Ok(result)
        }
        None => {
            // No heading — append to last line or create new
            if let Some(last) = lines.last_mut() {
                Ok(format!("{}\n{}{}", clean.trim_end(), *last, blob))
            } else {
                Ok(blob)
            }
        }
    }
}

/// Strip all zero-width characters from a string.
///
/// Returns the same string with all ZW characters removed.
pub fn strip(text: &str) -> String {
    text.chars().filter(|c| !ZW_SET.contains(c)).collect()
}

/// Extract and decode a ZW payload from text.
///
/// Looks for the start and end markers, extracts everything between them,
/// and decodes the ZW characters into bytes.
///
/// Returns `None` if no valid payload is found (start/end markers missing
/// or payload cannot be decoded).
pub fn extract(text: &str) -> Option<Vec<u8>> {
    let start = text.find(START_MARKER)?;
    let end = text[start + START_MARKER.len()..].find(END_MARKER)?;
    let encoded = &text[start + START_MARKER.len()..start + START_MARKER.len() + end];
    decode(encoded).ok()
}

/// Check if a string contains any ZW payload markers.
pub fn contains_payload(text: &str) -> bool {
    text.contains(START_MARKER) && text.contains(END_MARKER)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let data = b"Hello, World! This is a test payload.";
        let encoded = encode(data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_decode_empty() {
        let data = b"";
        let encoded = encode(data);
        assert!(encoded.is_empty());
        // Empty should fail with NoPayload since there are no ZW chars
        assert!(decode(&encoded).is_err());
    }

    #[test]
    fn encode_decode_binary() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn inject_and_extract() {
        let readme = "# My Project\n\nThis is a README.\n";
        let payload = b"secret commands here";
        let injected = inject(readme, payload, false).unwrap();
        let extracted = extract(&injected).unwrap();
        assert_eq!(extracted, payload);
        // Make sure the original content is preserved
        assert!(injected.contains("My Project"));
        assert!(injected.contains("README"));
    }

    #[test]
    fn inject_and_extract_with_padding() {
        let readme = "# Project\nContent\n";
        let payload = b"test";
        let injected = inject(readme, payload, true).unwrap();
        let extracted = extract(&injected).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn inject_no_heading() {
        let readme = "Just some text\nMore text\n";
        let payload = b"test";
        let injected = inject(readme, payload, false).unwrap();
        let extracted = extract(&injected);
        assert!(extracted.is_some());
    }

    #[test]
    fn inject_empty_readme() {
        let payload = b"test";
        let injected = inject("", payload, false).unwrap();
        let extracted = extract(&injected);
        assert!(extracted.is_some());
    }

    #[test]
    fn strip_removes_all_zw() {
        let text = "Normal text with some \u{200B}hidden\u{200C} chars";
        let cleaned = strip(text);
        assert_eq!(cleaned, "Normal text with some hidden chars");
    }

    #[test]
    fn decode_with_noise() {
        let payload = b"hello";
        let encoded = encode(payload);
        let noisy = format!("some text {} more text {}", encoded, "extra");
        let decoded = decode(&noisy).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn decode_truncated() {
        // Only 3 ZW chars (not divisible by 4)
        let truncated = "\u{200B}\u{200C}\u{200D}";
        assert!(decode(truncated).is_err());
    }

    #[test]
    fn extract_no_markers() {
        assert!(extract("plain text with no markers").is_none());
    }

    #[test]
    fn contains_payload_detection() {
        let readme = "# Test\n";
        let injected = inject(readme, b"data", false).unwrap();
        assert!(contains_payload(&injected));
        assert!(!contains_payload("plain text"));
    }
}
