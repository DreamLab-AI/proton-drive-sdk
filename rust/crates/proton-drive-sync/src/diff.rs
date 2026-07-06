//! The pure diff engine: [`diff`] compares a [`LocalIndex`] against a
//! [`RemoteSnapshot`] and produces an immutable, `Proposed` [`SyncPlan`]
//! (`docs/domain-model-sync.md` §2, invariants 1 & 3).
//!
//! The function is total and side-effect free — no I/O, no clock reads that
//! change the decision, no live re-reads of either side. It works purely from
//! the two snapshots handed in, exactly matching invariant 1 ("a `SyncOp`
//! references only nodes/paths that existed in the snapshots the plan was
//! computed from").
//!
//! ## Decision table (per path in the union of both sides)
//!
//! | local | remote | remote digest | result |
//! |-------|--------|---------------|--------|
//! | yes   | no     | —             | `Upload` |
//! | no    | yes    | —             | `Download` |
//! | yes   | yes    | absent        | `Conflict(NoRemoteDigest)` |
//! | yes   | yes    | == local      | `Skip` |
//! | yes   | yes    | != local      | `Conflict(ContentDiverged)` |
//!
//! There is no three-way merge: the engine sees only the current local and
//! current remote state, not a common base, so any two-sided divergence is a
//! genuine conflict the agent must resolve — never a silently-chosen transfer.

use crate::index::LocalIndex;
use crate::path::RelativePath;
use crate::plan::{ConflictReason, LocalRef, RemoteRef, SyncOp, SyncOpKind, SyncPlan};
use crate::snapshot::RemoteSnapshot;
use std::collections::BTreeSet;

/// Compute a plan reconciling `local` against `remote`.
///
/// The returned plan is `Proposed`, immutable, and ordered parent-before-child;
/// resolve its conflicts with [`SyncPlan::resolve`] before applying.
pub fn diff(local: &LocalIndex, remote: &RemoteSnapshot) -> SyncPlan {
    // Union of both sides' paths. A `BTreeSet` gives the stable, sorted,
    // parent-before-sibling ordering the plan requires.
    let mut paths: BTreeSet<&RelativePath> = BTreeSet::new();
    paths.extend(local.entries().map(|(p, _)| p));
    paths.extend(remote.entries().map(|(p, _)| p));

    let mut ops = Vec::with_capacity(paths.len());
    for path in &paths {
        let local_entry = local.get(path);
        let remote_entry = remote.get(path);

        let op = match (local_entry, remote_entry) {
            // Local-only → create a new remote file.
            (Some(l), None) => SyncOp {
                path: (*path).clone(),
                kind: SyncOpKind::Upload,
                local: Some(LocalRef {
                    content_hash: l.content_hash.clone(),
                    size: l.size,
                    mtime: l.mtime,
                }),
                remote: None,
                outcome: None,
            },
            // Remote-only → fetch it down. No digest comparison needed.
            (None, Some(r)) => SyncOp {
                path: (*path).clone(),
                kind: SyncOpKind::Download,
                local: None,
                remote: Some(RemoteRef {
                    node_uid: r.node_uid.clone(),
                    revision_uid: r.revision_uid.clone(),
                    content_hash: r.sha1_hex.clone(),
                }),
                outcome: None,
            },
            // Both present → compare digests.
            (Some(l), Some(r)) => {
                let local_ref = LocalRef {
                    content_hash: l.content_hash.clone(),
                    size: l.size,
                    mtime: l.mtime,
                };
                let remote_ref = RemoteRef {
                    node_uid: r.node_uid.clone(),
                    revision_uid: r.revision_uid.clone(),
                    content_hash: r.sha1_hex.clone(),
                };
                let kind = match &r.sha1_hex {
                    // No remote digest to compare → conflict, never a silent
                    // transfer (invariant 3).
                    None => SyncOpKind::Conflict(ConflictReason::NoRemoteDigest),
                    // Equal digests short-circuit all transfer (invariant 3).
                    Some(rh) if *rh == l.content_hash => SyncOpKind::Skip,
                    // Both sides carry a digest and they differ → true conflict.
                    Some(_) => SyncOpKind::Conflict(ConflictReason::ContentDiverged),
                };
                SyncOp {
                    path: (*path).clone(),
                    kind,
                    local: Some(local_ref),
                    remote: Some(remote_ref),
                    outcome: None,
                }
            }
            // The path came from the union, so at least one side has it.
            (None, None) => continue,
        };
        ops.push(op);
    }

    let dirs_to_create = compute_dirs_to_create(&ops, remote);
    SyncPlan::proposed(ops, dirs_to_create)
}

/// The remote directories that must exist before the plan's `Upload` ops run,
/// in parent-before-child order.
///
/// A remote directory is taken to already exist if any remote entry lives under
/// it. The result is therefore the ancestors of every `Upload` target *minus*
/// those already implied by the snapshot — the minimal scaffold a consumer has
/// to create. `Download` ops need no remote directory (they create *local*
/// dirs), and `UploadRevision` targets an existing node, so only `Upload` ops
/// contribute.
fn compute_dirs_to_create(ops: &[SyncOp], remote: &RemoteSnapshot) -> Vec<RelativePath> {
    // Directories already backed by a remote file.
    let mut existing: BTreeSet<RelativePath> = BTreeSet::new();
    for (path, _) in remote.entries() {
        existing.extend(path.ancestors());
    }

    let mut needed: BTreeSet<RelativePath> = BTreeSet::new();
    for op in ops {
        if op.kind == SyncOpKind::Upload {
            for ancestor in op.path.ancestors() {
                if !existing.contains(&ancestor) {
                    needed.insert(ancestor);
                }
            }
        }
    }

    // Sort parent-before-child: shallower paths (fewer segments) first, then
    // lexicographically for a fully deterministic order.
    let mut dirs: Vec<RelativePath> = needed.into_iter().collect();
    dirs.sort_by(|a, b| {
        let da = a.as_str().split('/').count();
        let db = b.as_str().split('/').count();
        da.cmp(&db).then_with(|| a.cmp(b))
    });
    dirs
}
