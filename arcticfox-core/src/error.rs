//! Error types for ArcticFox C3.
//!
//! All errors in the framework funnel through `ArcticFoxError`.
//! No bare unwrap/expect outside of tests — every fallible operation
//! returns a `Result<T>`.

use std::path::PathBuf;

/// Unified error type for the ArcticFox C3 framework.
#[derive(Debug, thiserror::Error)]
pub enum ArcticFoxError {
    // ── I/O ──────────────────────────────────────────────────────────────────
    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to read file {path}: {source}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to write file {path}: {source}")]
    FileWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Atomic replace failed for {path}: {source}")]
    AtomicReplace {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    // ── Network ──────────────────────────────────────────────────────────────
    #[error("HTTP request to {url} failed: {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("HTTP {status} from {url}: {body}")]
    HttpStatus {
        url: String,
        status: u16,
        body: String,
    },

    #[error("Network timeout connecting to {url} after {duration:?}")]
    Timeout { url: String, duration: std::time::Duration },

    #[error("DNS resolution failed for {host}")]
    Dns { host: String },

    #[error("TLS error connecting to {url}: {source}")]
    Tls {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    // ── Encoding / ZW Codec ─────────────────────────────────────────────────
    #[error("No zero-width payload found in content")]
    NoPayload,

    #[error("Truncated zero-width sequence: expected multiple of 4 ZW chars, got {actual}")]
    TruncatedZw { actual: usize },

    #[error("Invalid zero-width character at position {pos}: 0x{byte:04X}")]
    InvalidZwChar { pos: usize, byte: u16 },

    #[error("No heading found in content for ZW injection")]
    NoHeadingForInjection,

    // ── JSON / Deserialization ──────────────────────────────────────────────
    #[error("JSON parse error: {source}")]
    Json {
        #[source]
        source: serde_json::Error,
    },

    #[error("JSON parse error in {context}: {source}")]
    JsonContext {
        context: String,
        #[source]
        source: serde_json::Error,
    },

    // ── Config ──────────────────────────────────────────────────────────────
    #[error("Config file not found: {path}")]
    ConfigNotFound { path: String },

    #[error("Invalid config in {path}: {message}")]
    ConfigInvalid { path: String, message: String },

    #[error("Missing required config field '{field}' in {path}")]
    ConfigMissingField { path: String, field: String },

    // ── Auth ────────────────────────────────────────────────────────────────
    #[error("Authentication failed: {reason}")]
    Auth { reason: String },

    #[error("Insufficient permissions: {required} role required")]
    Forbidden { required: String },

    #[error("Token not provided")]
    MissingToken,

    #[error("Invalid token format")]
    InvalidTokenFormat,

    // ── Repo Operations ─────────────────────────────────────────────────────
    #[error("Repo not found: {label}")]
    RepoNotFound { label: String },

    #[error("No alive repos available for push")]
    NoAliveRepos,

    #[error("Invalid repo spec '{spec}': {reason}")]
    InvalidRepoSpec { spec: String, reason: String },

    #[error("Missing API token for {platform}")]
    MissingApiToken { platform: String },

    #[error("Failed to create paste: {reason}")]
    PasteCreate { reason: String },

    // ── Agent / Execution ───────────────────────────────────────────────────
    #[error("Command execution timed out after {duration:?}")]
    CommandTimeout { duration: std::time::Duration },

    #[error("Command execution failed: {reason}")]
    CommandExec { reason: String },

    #[error("Bot persistence failed: {reason}")]
    Persistence { reason: String },

    #[error("Agent already running (pid: {pid})")]
    AlreadyRunning { pid: u32 },

    // ── Scanner ─────────────────────────────────────────────────────────────
    #[error("Scan target invalid: {reason}")]
    ScanTarget { reason: String },

    #[error("Honeypot detected at {target}: {evidence}")]
    HoneypotDetected { target: String, evidence: String },

    // ── Internal ────────────────────────────────────────────────────────────
    #[error("Internal error: {message}")]
    Internal { message: String },

    #[error("Lock poisoned: {message}")]
    LockPoisoned { message: String },
}

/// Convenience result type alias.
pub type Result<T> = std::result::Result<T, ArcticFoxError>;

// ── From impls for common conversions ──────────────────────────────────────

impl From<serde_json::Error> for ArcticFoxError {
    fn from(source: serde_json::Error) -> Self {
        ArcticFoxError::Json { source }
    }
}

impl From<std::io::Error> for ArcticFoxError {
    fn from(source: std::io::Error) -> Self {
        ArcticFoxError::Io {
            path: PathBuf::from("<unknown>"),
            source,
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

impl ArcticFoxError {
    /// Wrap an I/O error with a known path.
    pub fn io_at(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        ArcticFoxError::Io {
            path: path.into(),
            source,
        }
    }

    /// Create an HTTP error from a reqwest status response.
    pub fn http_status(url: impl Into<String>, status: u16, body: impl Into<String>) -> Self {
        ArcticFoxError::HttpStatus {
            url: url.into(),
            status,
            body: body.into(),
        }
    }

    /// Check if this error is retryable (transient).
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ArcticFoxError::Http { .. }
                | ArcticFoxError::Timeout { .. }
                | ArcticFoxError::Dns { .. }
                | ArcticFoxError::Tls { .. }
                | ArcticFoxError::Io { .. }
        )
    }

    /// Check if this error is fatal (no point retrying).
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            ArcticFoxError::Auth { .. }
                | ArcticFoxError::Forbidden { .. }
                | ArcticFoxError::ConfigInvalid { .. }
                | ArcticFoxError::ConfigMissingField { .. }
                | ArcticFoxError::LockPoisoned { .. }
        )
    }
}
