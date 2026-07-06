//! Error taxonomy for the Sync engine.
//!
//! The engine is pure and offline, so the only fallible operations are local
//! filesystem access (walking + hashing), cache persistence, and plan
//! resolution. Cache *loading* is deliberately absent from this list: a corrupt
//! or missing cache is recovered from silently (full rehash), never surfaced as
//! an error (`docs/domain-model-sync.md` §2, cache-invalidation rule).

use crate::path::RelativePath;
use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// Anything the Sync engine can fail at.
#[derive(Debug, Error)]
pub enum SyncError {
    /// A filesystem read failed while walking or hashing the local tree.
    #[error("i/o error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// Persisting the hash cache failed (serialise or write).
    #[error("failed to write hash cache to {path}: {source}")]
    CacheWrite {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// A `Conflict` op was left without a `ConflictOutcome` when resolving a
    /// plan. The engine never guesses (`docs/domain-model-sync.md` invariant 6).
    #[error("unresolved conflict at {path}: a ConflictOutcome must be supplied")]
    UnresolvedConflict { path: RelativePath },

    /// A resolution decision was supplied for a path that carries no conflict —
    /// almost always a caller mistake (stale path, typo).
    #[error("resolution supplied for {path}, which has no conflict to resolve")]
    UnexpectedDecision { path: RelativePath },
}
