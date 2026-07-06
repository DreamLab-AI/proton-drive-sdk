//! Hash-based smart-sync engine for Proton Drive — the **Sync** bounded context
//! (`docs/domain-model-sync.md`).
//!
//! This crate decides *what* to transfer between a local directory tree and a
//! Drive folder subtree; it never performs the transfer, and it contains **no
//! network, crypto, or async code**. It is a pure, offline engine over two
//! snapshots:
//!
//! * [`LocalIndex`] — built by [`Indexer`] from a directory walk, with a
//!   persistent [`HashCache`] so unchanged files are not rehashed.
//! * [`RemoteSnapshot`] — plain data fed in by the caller (WP4) after it has
//!   listed and decrypted the remote side; the engine takes no dependency on
//!   listing or client code.
//!
//! [`diff`] reconciles the two into an immutable, ordered [`SyncPlan`] of
//! [`SyncOp`]s. Conflicts are surfaced, never guessed: the host supplies a
//! [`ConflictOutcome`] per conflict and [`SyncPlan::resolve`] produces a fresh
//! `Approved` plan that supersedes the proposed one without mutating it.
//!
//! ## Content identity
//!
//! Sameness is decided by the cleartext SHA1 [`ContentHash`] — computed locally
//! from file bytes, recovered remotely from the decrypted `Common.Digests.SHA1`
//! extended attribute. Equal hashes are authoritative; size/mtime never
//! override a hash comparison (`docs/domain-model-sync.md` §1, invariant 3).
//!
//! ## Typical flow
//!
//! ```no_run
//! use proton_drive_sync::{Indexer, RemoteSnapshot, diff};
//! use std::path::Path;
//!
//! # fn demo(remote: RemoteSnapshot) -> Result<(), proton_drive_sync::SyncError> {
//! let index = Indexer::new("/home/me/Sync")
//!     .index_with_cache_file(Path::new("/home/me/.cache/pdtui/sync-hashes.json"))?;
//! let plan = diff(&index, &remote);
//! for (path, reason) in plan.conflicts() {
//!     eprintln!("conflict at {path}: {reason:?}");
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod diff;
mod error;
mod index;
mod path;
mod plan;
mod snapshot;

pub use diff::diff;
pub use error::SyncError;
pub use index::{HashCache, IndexEntry, Indexer, LocalIndex};
pub use path::{ContentHash, RelativePath};
pub use plan::{
    ConflictOutcome, ConflictReason, LocalRef, PlanState, RemoteRef, SyncOp, SyncOpKind, SyncPlan,
    SyncPlanId,
};
pub use snapshot::{RemoteEntry, RemoteSnapshot};
