//! Conflict resolution: immutability, the three outcomes, and the error paths.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proton_drive_core::nodes::{NodeUid, make_node_uid};
use proton_drive_sync::{
    ConflictOutcome, ContentHash, HashCache, Indexer, LocalIndex, PlanState, RelativePath,
    RemoteEntry, RemoteSnapshot, SyncError, SyncOpKind, SyncPlan, diff,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn write(root: &Path, rel: &str, contents: &str) {
    let full = root.join(rel);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(full, contents).unwrap();
}

fn local(files: &[(&str, &str)]) -> (TempDir, LocalIndex) {
    let dir = TempDir::new().unwrap();
    for (rel, contents) in files {
        write(dir.path(), rel, contents);
    }
    let index = Indexer::new(dir.path())
        .index(&mut HashCache::empty())
        .unwrap();
    (dir, index)
}

fn uid(n: &str) -> NodeUid {
    make_node_uid("vol", n)
}

/// A plan whose single op is a `ContentDiverged` conflict at `a.txt`.
fn conflict_plan() -> (TempDir, SyncPlan) {
    let (dir, index) = local(&[("a.txt", "local wins")]);
    let snap = RemoteSnapshot::from_entries([(
        RelativePath::new("a.txt"),
        // A digest that cannot match the local content.
        RemoteEntry::new(
            uid("a"),
            "rev-a",
            Some(ContentHash::from_hex("deadbeef")),
            9,
        ),
    )]);
    let plan = diff(&index, &snap);
    assert!(matches!(plan.ops()[0].kind, SyncOpKind::Conflict(_)));
    (dir, plan)
}

fn decisions(pairs: &[(&str, ConflictOutcome)]) -> BTreeMap<RelativePath, ConflictOutcome> {
    pairs
        .iter()
        .map(|(p, o)| (RelativePath::new(p), *o))
        .collect()
}

#[test]
fn keep_local_yields_upload_revision() {
    let (_dir, plan) = conflict_plan();
    let approved = plan
        .resolve(&decisions(&[("a.txt", ConflictOutcome::KeepLocal)]))
        .unwrap();

    assert_eq!(approved.state(), PlanState::Approved);
    assert_eq!(approved.ops().len(), 1);
    let op = &approved.ops()[0];
    assert_eq!(op.kind, SyncOpKind::UploadRevision);
    assert_eq!(op.outcome, Some(ConflictOutcome::KeepLocal));
    // Both sides' evidence is preserved onto the resolved op.
    assert!(op.local.is_some());
    assert!(op.remote.is_some());
    // The new plan supersedes the original.
    assert_eq!(approved.superseded(), Some(plan.id()));
}

#[test]
fn keep_remote_yields_download() {
    let (_dir, plan) = conflict_plan();
    let approved = plan
        .resolve(&decisions(&[("a.txt", ConflictOutcome::KeepRemote)]))
        .unwrap();

    let op = &approved.ops()[0];
    assert_eq!(op.kind, SyncOpKind::Download);
    assert_eq!(op.outcome, Some(ConflictOutcome::KeepRemote));
}

#[test]
fn skip_drops_the_op() {
    let (_dir, plan) = conflict_plan();
    let approved = plan
        .resolve(&decisions(&[("a.txt", ConflictOutcome::Skip)]))
        .unwrap();

    assert!(approved.ops().is_empty(), "a skipped conflict is dropped");
    assert_eq!(approved.state(), PlanState::Approved);
    assert!(approved.is_fully_resolved());
}

#[test]
fn resolve_does_not_mutate_the_original_plan() {
    let (_dir, plan) = conflict_plan();
    let _ = plan
        .resolve(&decisions(&[("a.txt", ConflictOutcome::KeepLocal)]))
        .unwrap();

    // Original is untouched: still Proposed, still an unresolved conflict.
    assert_eq!(plan.state(), PlanState::Proposed);
    assert!(matches!(plan.ops()[0].kind, SyncOpKind::Conflict(_)));
    assert!(!plan.is_fully_resolved());
}

#[test]
fn unresolved_conflict_is_an_error() {
    let (_dir, plan) = conflict_plan();
    let err = plan.resolve(&BTreeMap::new()).unwrap_err();
    match err {
        SyncError::UnresolvedConflict { path } => assert_eq!(path, RelativePath::new("a.txt")),
        other => panic!("expected UnresolvedConflict, got {other:?}"),
    }
}

#[test]
fn decision_for_a_non_conflict_path_is_an_error() {
    let (_dir, plan) = conflict_plan();
    let err = plan
        .resolve(&decisions(&[("ghost.txt", ConflictOutcome::KeepLocal)]))
        .unwrap_err();
    match err {
        SyncError::UnexpectedDecision { path } => assert_eq!(path, RelativePath::new("ghost.txt")),
        other => panic!("expected UnexpectedDecision, got {other:?}"),
    }
}

#[test]
fn non_conflict_ops_pass_through_unchanged() {
    // Upload (local-only) + Download (remote-only) + Skip (equal) — no conflicts.
    let (_dir, index) = local(&[("up.txt", "local"), ("same.txt", "identical")]);
    let same_hash = index
        .get(&RelativePath::new("same.txt"))
        .unwrap()
        .content_hash
        .clone();
    let snap = RemoteSnapshot::from_entries([
        (
            RelativePath::new("same.txt"),
            RemoteEntry::new(uid("s"), "rev-s", Some(same_hash), 9),
        ),
        (
            RelativePath::new("down.txt"),
            RemoteEntry::new(uid("d"), "rev-d", Some(ContentHash::from_hex("ff")), 4),
        ),
    ]);
    let plan = diff(&index, &snap);
    assert!(plan.is_fully_resolved());

    let approved = plan.resolve(&BTreeMap::new()).unwrap();
    assert_eq!(approved.state(), PlanState::Approved);

    let kinds: BTreeMap<String, SyncOpKind> = approved
        .ops()
        .iter()
        .map(|o| (o.path.to_string(), o.kind))
        .collect();
    assert_eq!(kinds[&"up.txt".to_string()], SyncOpKind::Upload);
    assert_eq!(kinds[&"down.txt".to_string()], SyncOpKind::Download);
    assert_eq!(kinds[&"same.txt".to_string()], SyncOpKind::Skip);
    // dirs_to_create carries through resolution untouched.
    assert_eq!(approved.dirs_to_create(), plan.dirs_to_create());
}

#[test]
fn mixed_plan_resolves_each_conflict_independently() {
    let (_dir, index) = local(&[("keep_local.txt", "L"), ("keep_remote.txt", "R")]);
    let snap = RemoteSnapshot::from_entries([
        (
            RelativePath::new("keep_local.txt"),
            RemoteEntry::new(uid("l"), "rev-l", Some(ContentHash::from_hex("aa")), 1),
        ),
        (
            RelativePath::new("keep_remote.txt"),
            // No remote digest → NoRemoteDigest conflict.
            RemoteEntry::new(uid("r"), "rev-r", None, 1),
        ),
    ]);
    let plan = diff(&index, &snap);
    assert_eq!(plan.conflicts().count(), 2);

    let approved = plan
        .resolve(&decisions(&[
            ("keep_local.txt", ConflictOutcome::KeepLocal),
            ("keep_remote.txt", ConflictOutcome::KeepRemote),
        ]))
        .unwrap();

    let kinds: BTreeMap<String, SyncOpKind> = approved
        .ops()
        .iter()
        .map(|o| (o.path.to_string(), o.kind))
        .collect();
    assert_eq!(
        kinds[&"keep_local.txt".to_string()],
        SyncOpKind::UploadRevision
    );
    assert_eq!(kinds[&"keep_remote.txt".to_string()], SyncOpKind::Download);
    assert!(approved.is_fully_resolved());
}
