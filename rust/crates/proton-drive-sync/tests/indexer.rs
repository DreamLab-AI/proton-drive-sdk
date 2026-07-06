//! Indexer + hash-cache behaviour against real temporary directory trees.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proton_drive_sync::{HashCache, Indexer, RelativePath};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// SHA1 of `hello` — the reference digest the indexer must reproduce.
const SHA1_HELLO: &str = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
/// An obviously-wrong 40-hex-char sentinel we plant in the cache to prove a hit.
const SENTINEL: &str = "0000000000000000000000000000000000000000";

fn write(root: &Path, rel: &str, contents: &str) {
    let full = root.join(rel);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(full, contents).unwrap();
}

fn paths(index: &proton_drive_sync::LocalIndex) -> Vec<String> {
    index.entries().map(|(p, _)| p.to_string()).collect()
}

#[test]
fn indexes_nested_tree_deterministically_and_ignores_empty_dirs() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "a.txt", "top");
    write(dir.path(), "sub/b.txt", "nested");
    write(dir.path(), "sub/deep/c.txt", "deeper");
    fs::create_dir_all(dir.path().join("empty")).unwrap();
    fs::create_dir_all(dir.path().join("sub/also_empty")).unwrap();

    let index = Indexer::new(dir.path())
        .index(&mut HashCache::empty())
        .unwrap();

    // Files only, sorted, empty directories contribute nothing.
    assert_eq!(paths(&index), vec!["a.txt", "sub/b.txt", "sub/deep/c.txt"]);
    assert_eq!(index.len(), 3);
    assert!(!index.is_empty());
}

#[test]
fn hashes_file_content_correctly() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "greeting.txt", "hello");

    let index = Indexer::new(dir.path())
        .index(&mut HashCache::empty())
        .unwrap();

    let entry = index.get(&RelativePath::new("greeting.txt")).unwrap();
    assert_eq!(entry.content_hash.as_str(), SHA1_HELLO);
    assert_eq!(entry.size, 5);
}

#[test]
fn empty_tree_produces_empty_index() {
    let dir = TempDir::new().unwrap();
    let index = Indexer::new(dir.path())
        .index(&mut HashCache::empty())
        .unwrap();
    assert!(index.is_empty());
    assert_eq!(index.len(), 0);
}

#[test]
fn cache_hit_reuses_stored_digest_without_rehashing() {
    let dir = TempDir::new().unwrap();
    let cache_path = dir.path().join("hashes.json");
    write(dir.path(), "greeting.txt", "hello");

    // First pass computes and persists the true digest.
    let first = Indexer::new(dir.path())
        .index_with_cache_file(&cache_path)
        .unwrap();
    assert_eq!(
        first
            .get(&RelativePath::new("greeting.txt"))
            .unwrap()
            .content_hash
            .as_str(),
        SHA1_HELLO
    );

    // Poison the cached digest but leave (size, mtime) untouched.
    let mut cache_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&cache_path).unwrap()).unwrap();
    cache_json["records"]["greeting.txt"]["sha1"] = serde_json::json!(SENTINEL);
    fs::write(&cache_path, serde_json::to_vec(&cache_json).unwrap()).unwrap();

    // Second pass must trust the cache (matching size+mtime) → returns sentinel.
    let second = Indexer::new(dir.path())
        .index_with_cache_file(&cache_path)
        .unwrap();
    assert_eq!(
        second
            .get(&RelativePath::new("greeting.txt"))
            .unwrap()
            .content_hash
            .as_str(),
        SENTINEL,
        "matching size+mtime should reuse the cached digest, not rehash"
    );
}

#[test]
fn cache_miss_on_content_change_forces_rehash() {
    let dir = TempDir::new().unwrap();
    let cache_path = dir.path().join("hashes.json");
    write(dir.path(), "greeting.txt", "hello");

    Indexer::new(dir.path())
        .index_with_cache_file(&cache_path)
        .unwrap();

    // Poison the cache, then change the file's size so the cache key mismatches.
    let mut cache_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&cache_path).unwrap()).unwrap();
    cache_json["records"]["greeting.txt"]["sha1"] = serde_json::json!(SENTINEL);
    fs::write(&cache_path, serde_json::to_vec(&cache_json).unwrap()).unwrap();
    write(dir.path(), "greeting.txt", "hello world");

    let reindex = Indexer::new(dir.path())
        .index_with_cache_file(&cache_path)
        .unwrap();
    let hash = reindex
        .get(&RelativePath::new("greeting.txt"))
        .unwrap()
        .content_hash
        .clone();
    assert_ne!(hash.as_str(), SENTINEL, "changed size must force a rehash");
    // Real SHA1 of "hello world".
    assert_eq!(hash.as_str(), "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
}

#[test]
fn corrupt_cache_falls_back_to_full_rehash_without_error() {
    let dir = TempDir::new().unwrap();
    let cache_path = dir.path().join("hashes.json");
    write(dir.path(), "greeting.txt", "hello");
    fs::write(&cache_path, b"{ this is not valid json").unwrap();

    let index = Indexer::new(dir.path())
        .index_with_cache_file(&cache_path)
        .expect("a corrupt cache must never be an error");
    assert_eq!(
        index
            .get(&RelativePath::new("greeting.txt"))
            .unwrap()
            .content_hash
            .as_str(),
        SHA1_HELLO
    );
}

#[test]
fn missing_cache_is_not_an_error() {
    let dir = TempDir::new().unwrap();
    let cache_path = dir.path().join("does-not-exist.json");
    write(dir.path(), "greeting.txt", "hello");

    let index = Indexer::new(dir.path())
        .index_with_cache_file(&cache_path)
        .expect("a missing cache must never be an error");
    assert_eq!(index.len(), 1);
    // And it should now have been created.
    assert!(cache_path.exists());
}

#[test]
fn cache_serde_round_trips() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "a.txt", "one");
    write(dir.path(), "sub/b.txt", "two");

    let mut cache = HashCache::empty();
    Indexer::new(dir.path()).index(&mut cache).unwrap();

    let json = serde_json::to_string(&cache).unwrap();
    let back: HashCache = serde_json::from_str(&json).unwrap();
    assert_eq!(cache, back);
}

#[test]
fn cache_prunes_vanished_paths() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), "keep.txt", "keep");
    write(dir.path(), "remove.txt", "remove");

    let mut cache = HashCache::empty();
    Indexer::new(dir.path()).index(&mut cache).unwrap();
    let json = serde_json::to_string(&cache).unwrap();
    assert!(json.contains("remove.txt"));

    fs::remove_file(dir.path().join("remove.txt")).unwrap();
    Indexer::new(dir.path()).index(&mut cache).unwrap();
    let json = serde_json::to_string(&cache).unwrap();
    assert!(
        !json.contains("remove.txt"),
        "deleted paths must be pruned from the cache"
    );
    assert!(json.contains("keep.txt"));
}

#[cfg(unix)]
#[test]
fn symlinks_are_skipped() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    write(dir.path(), "real.txt", "real");
    symlink(dir.path().join("real.txt"), dir.path().join("link.txt")).unwrap();
    // Also a symlinked directory, which must not be traversed.
    fs::create_dir_all(dir.path().join("realdir")).unwrap();
    write(dir.path(), "realdir/inside.txt", "inside");
    symlink(dir.path().join("realdir"), dir.path().join("linkdir")).unwrap();

    let index = Indexer::new(dir.path())
        .index(&mut HashCache::empty())
        .unwrap();

    assert_eq!(paths(&index), vec!["real.txt", "realdir/inside.txt"]);
}
