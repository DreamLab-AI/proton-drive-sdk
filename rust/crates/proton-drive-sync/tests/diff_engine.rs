//! Every branch of the diff decision table, plus ordering and dir-scaffold edges.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proton_drive_core::nodes::{NodeUid, make_node_uid};
use proton_drive_sync::{
    ConflictReason, ContentHash, HashCache, Indexer, LocalIndex, RelativePath, RemoteEntry,
    RemoteSnapshot, SyncOpKind, diff,
};
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

/// Build a `LocalIndex` from `(relative_path, contents)` pairs. The `TempDir`
/// is returned so its lifetime keeps the tree alive for the caller.
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

fn local_hash(index: &LocalIndex, rel: &str) -> ContentHash {
    index
        .get(&RelativePath::new(rel))
        .unwrap()
        .content_hash
        .clone()
}

fn uid(n: &str) -> NodeUid {
    make_node_uid("vol", n)
}

fn remote(entries: &[(&str, RemoteEntry)]) -> RemoteSnapshot {
    RemoteSnapshot::from_entries(
        entries
            .iter()
            .map(|(p, e)| (RelativePath::new(p), e.clone())),
    )
}

#[test]
fn local_only_is_upload() {
    let (_dir, index) = local(&[("a.txt", "x")]);
    let plan = diff(&index, &RemoteSnapshot::from_entries(std::iter::empty()));

    assert_eq!(plan.ops().len(), 1);
    let op = &plan.ops()[0];
    assert_eq!(op.kind, SyncOpKind::Upload);
    assert!(op.local.is_some());
    assert!(op.remote.is_none());
    assert!(op.outcome.is_none());
}

#[test]
fn remote_only_is_download() {
    let (_dir, index) = local(&[]);
    let snap = remote(&[(
        "a.txt",
        RemoteEntry::new(uid("a"), "rev-a", Some(ContentHash::from_hex("abc")), 3),
    )]);
    let plan = diff(&index, &snap);

    assert_eq!(plan.ops().len(), 1);
    let op = &plan.ops()[0];
    assert_eq!(op.kind, SyncOpKind::Download);
    assert!(op.local.is_none());
    let r = op.remote.as_ref().unwrap();
    assert_eq!(r.node_uid, uid("a"));
    assert_eq!(r.revision_uid, "rev-a");
    // Download carries the staleness token.
    assert_eq!(op.staleness_token(), Some("rev-a"));
}

#[test]
fn both_sides_equal_hash_is_skip() {
    let (_dir, index) = local(&[("a.txt", "same content")]);
    let h = local_hash(&index, "a.txt");
    let snap = remote(&[("a.txt", RemoteEntry::new(uid("a"), "rev-a", Some(h), 12))]);
    let plan = diff(&index, &snap);

    assert_eq!(plan.ops().len(), 1);
    assert_eq!(plan.ops()[0].kind, SyncOpKind::Skip);
    assert!(plan.is_fully_resolved());
}

#[test]
fn equal_hash_but_different_size_still_skips() {
    // Invariant 3: hash equality short-circuits regardless of size/mtime.
    let (_dir, index) = local(&[("a.txt", "same content")]);
    let h = local_hash(&index, "a.txt");
    let snap = remote(&[(
        "a.txt",
        RemoteEntry::new(uid("a"), "rev-a", Some(h), 999_999),
    )]);
    let plan = diff(&index, &snap);
    assert_eq!(plan.ops()[0].kind, SyncOpKind::Skip);
}

#[test]
fn both_sides_differing_hash_is_content_diverged_conflict() {
    let (_dir, index) = local(&[("a.txt", "local content")]);
    let h = local_hash(&index, "a.txt");
    // Flip the last hex char to guarantee a full-string mismatch that still
    // shares a long common prefix (proves we compare the whole digest).
    let mut chars: Vec<char> = h.as_str().chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
    let divergent = ContentHash::from_hex(chars.into_iter().collect::<String>());

    let snap = remote(&[(
        "a.txt",
        RemoteEntry::new(uid("a"), "rev-a", Some(divergent), 13),
    )]);
    let plan = diff(&index, &snap);

    assert_eq!(
        plan.ops()[0].kind,
        SyncOpKind::Conflict(ConflictReason::ContentDiverged)
    );
    assert!(plan.ops()[0].local.is_some());
    assert!(plan.ops()[0].remote.is_some());
    assert!(!plan.is_fully_resolved());
}

#[test]
fn missing_remote_digest_is_no_remote_digest_conflict() {
    let (_dir, index) = local(&[("a.txt", "local content")]);
    let snap = remote(&[("a.txt", RemoteEntry::new(uid("a"), "rev-a", None, 13))]);
    let plan = diff(&index, &snap);

    assert_eq!(
        plan.ops()[0].kind,
        SyncOpKind::Conflict(ConflictReason::NoRemoteDigest)
    );
}

#[test]
fn empty_both_sides_is_empty_plan() {
    let (_dir, index) = local(&[]);
    let plan = diff(&index, &RemoteSnapshot::from_entries(std::iter::empty()));
    assert!(plan.ops().is_empty());
    assert!(plan.dirs_to_create().is_empty());
    assert!(plan.is_fully_resolved());
    assert_eq!(plan.conflicts().count(), 0);
}

#[test]
fn ops_are_ordered_parents_before_children() {
    let (_dir, index) = local(&[
        ("z/last.txt", "z"),
        ("a/first.txt", "a"),
        ("a/deep/mid.txt", "m"),
        ("top.txt", "t"),
    ]);
    let plan = diff(&index, &RemoteSnapshot::from_entries(std::iter::empty()));
    let ordered: Vec<String> = plan.ops().iter().map(|o| o.path.to_string()).collect();
    assert_eq!(
        ordered,
        vec!["a/deep/mid.txt", "a/first.txt", "top.txt", "z/last.txt"]
    );
}

#[test]
fn dirs_to_create_lists_missing_upload_ancestors_in_order() {
    let (_dir, index) = local(&[("a/b/c.txt", "deep")]);
    let plan = diff(&index, &RemoteSnapshot::from_entries(std::iter::empty()));
    let dirs: Vec<String> = plan
        .dirs_to_create()
        .iter()
        .map(|d| d.to_string())
        .collect();
    assert_eq!(dirs, vec!["a", "a/b"]);
}

#[test]
fn dirs_to_create_excludes_dirs_already_backed_by_remote_files() {
    let (_dir, index) = local(&[("a/b/new.txt", "new")]);
    // A remote file under `a/` means `a` already exists remotely; only `a/b`
    // needs creating for the upload.
    let snap = remote(&[(
        "a/existing.txt",
        RemoteEntry::new(uid("e"), "rev-e", Some(ContentHash::from_hex("ff")), 1),
    )]);
    let plan = diff(&index, &snap);

    // `a/existing.txt` is remote-only → Download; `a/b/new.txt` → Upload.
    let dirs: Vec<String> = plan
        .dirs_to_create()
        .iter()
        .map(|d| d.to_string())
        .collect();
    assert_eq!(dirs, vec!["a/b"]);
}

#[test]
fn download_ops_contribute_no_remote_dirs() {
    let (_dir, index) = local(&[]);
    let snap = remote(&[(
        "deep/nested/remote.txt",
        RemoteEntry::new(uid("r"), "rev-r", Some(ContentHash::from_hex("ab")), 4),
    )]);
    let plan = diff(&index, &snap);
    assert_eq!(plan.ops()[0].kind, SyncOpKind::Download);
    assert!(
        plan.dirs_to_create().is_empty(),
        "downloads create local dirs, never remote ones"
    );
}

#[test]
fn upload_op_has_no_staleness_token() {
    let (_dir, index) = local(&[("a.txt", "x")]);
    let plan = diff(&index, &RemoteSnapshot::from_entries(std::iter::empty()));
    assert_eq!(plan.ops()[0].staleness_token(), None);
}
