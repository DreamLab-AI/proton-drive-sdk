//! Crate-wide error model. Mirrors `js/sdk/src/errors.ts` taxonomy.

use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("network error: {0}")]
    Network(String),

    #[error("rate limited; retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("validation error: {0}")]
    Validation(String),

    #[error("integrity error: {0}")]
    Integrity(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("verification error: {0}")]
    Verification(String),

    #[error("node with same name already exists: {name}")]
    NodeWithSameNameExists { name: String },

    /// Proton API `Code` 2011 (`NOT_ENOUGH_PERMISSIONS`) — see
    /// `map_api_error` in `nodes.rs` for the wire-code taxonomy citation.
    #[error("insufficient permissions: {0}")]
    PermissionDenied(String),

    #[error("revision draft conflict")]
    RevisionDraftConflict,

    #[error("node not found: {0}")]
    NotFound(String),

    #[error("integrity check failed: {0}")]
    IntegrityCheckFailed(String),

    #[error("protocol violation: {0}")]
    ProtocolViolation(String),

    #[error("not implemented in this build: {0}")]
    NotImplemented(&'static str),

    #[error("crypto: {0}")]
    Crypto(#[from] proton_drive_crypto::CryptoError),

    #[error("cache: {0}")]
    Cache(#[from] proton_drive_cache::CacheError),

    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    pub fn is_transient(&self) -> bool {
        matches!(self, Error::Network(_) | Error::RateLimited { .. })
    }
}
