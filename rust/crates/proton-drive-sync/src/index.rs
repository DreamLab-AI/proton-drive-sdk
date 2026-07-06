//! The local side of a diff: a [`LocalIndex`] built by walking a directory tree
//! and hashing every file (`docs/domain-model-sync.md` §2, *LocalIndex*).
//!
//! Two design points carry the domain rules:
//!
//! * **Deterministic walk.** Directories are read, sorted by name, and
//!   descended in order, so the resulting `BTreeMap<RelativePath, IndexEntry>`
//!   is identical across runs and platforms. Symlinks are skipped entirely —
//!   the engine indexes real file content only, and following links risks
//!   cycles and escapes from the sync root.
//!
//! * **Trust-but-verify hashing.** SHA1 over a large file is the expensive part,
//!   so a JSON [`HashCache`] records `(size, mtime) -> sha1`. On re-index, an
//!   entry whose live `(size, mtime)` still matches the cache reuses the stored
//!   digest; any change forces a rehash. A missing or corrupt cache is not an
//!   error — it simply means every file is rehashed this pass.

use crate::error::SyncError;
use crate::path::{ContentHash, RelativePath};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Read buffer for streaming SHA1 — large enough to amortise syscall overhead
/// on big files without holding whole files in memory.
const HASH_CHUNK_BYTES: usize = 128 * 1024;

/// One local file's state, keyed by [`RelativePath`] within a [`LocalIndex`].
///
/// The digest is always present: the indexer hashes every file it emits (the
/// domain's `Option<ContentHash>` "not yet hashed" state never escapes this
/// module). `size`/`mtime` are the exact values the digest was computed for and
/// are the cache-validity key on the next pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub path: RelativePath,
    pub content_hash: ContentHash,
    pub size: u64,
    pub mtime: SystemTime,
}

/// All indexed files under one local root, keyed by relative path.
#[derive(Debug, Clone)]
pub struct LocalIndex {
    root: PathBuf,
    entries: BTreeMap<RelativePath, IndexEntry>,
    generated_at: SystemTime,
}

impl LocalIndex {
    /// The directory tree this index was built from.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// When the index was produced.
    pub fn generated_at(&self) -> SystemTime {
        self.generated_at
    }

    /// Look up one entry by path.
    pub fn get(&self, path: &RelativePath) -> Option<&IndexEntry> {
        self.entries.get(path)
    }

    /// Iterate entries in deterministic (path-sorted) order.
    pub fn entries(&self) -> impl Iterator<Item = (&RelativePath, &IndexEntry)> {
        self.entries.iter()
    }

    /// Number of indexed files.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when the tree held no regular files.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One cache record: the `(size, mtime)` the digest was computed for, plus the
/// digest. `mtime` is split into whole seconds + sub-second nanos relative to
/// the unix epoch so the JSON form is stable and exactly comparable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CacheRecord {
    size: u64,
    mtime_secs: i64,
    mtime_nanos: u32,
    sha1: String,
}

/// Persistent `(size, mtime) -> sha1` cache, keyed by relative path.
///
/// Load with [`HashCache::load`] (infallible — corrupt/missing yields an empty
/// cache), consume it through [`crate::Indexer::index`], then persist the
/// refreshed cache with [`HashCache::save`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashCache {
    records: BTreeMap<String, CacheRecord>,
}

impl HashCache {
    /// An empty cache — every file will be hashed.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Load a cache from a JSON file. A missing file, an unreadable file, or a
    /// corrupt/unparseable file all yield an empty cache rather than an error:
    /// a bad cache must never block indexing, only cost a full rehash.
    pub fn load(path: &Path) -> Self {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|err| {
                tracing::warn!(
                    cache = %path.display(),
                    %err,
                    "hash cache unparseable — falling back to full rehash"
                );
                Self::empty()
            }),
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        cache = %path.display(),
                        %err,
                        "hash cache unreadable — falling back to full rehash"
                    );
                }
                Self::empty()
            }
        }
    }

    /// Persist the cache to a JSON file. Unlike loading, a save failure *is*
    /// surfaced — the caller decides whether a non-durable cache is acceptable.
    pub fn save(&self, path: &Path) -> Result<(), SyncError> {
        let json = serde_json::to_vec_pretty(self).map_err(|err| SyncError::CacheWrite {
            path: path.to_path_buf(),
            source: std::io::Error::other(err),
        })?;
        fs::write(path, json).map_err(|source| SyncError::CacheWrite {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Return the cached digest for `path` iff the record's `(size, mtime)`
    /// still matches the live file — the trust-but-verify check.
    fn get_valid(&self, path: &RelativePath, size: u64, mtime: SystemTime) -> Option<ContentHash> {
        let record = self.records.get(path.as_str())?;
        let (secs, nanos) = split_mtime(mtime);
        if record.size == size && record.mtime_secs == secs && record.mtime_nanos == nanos {
            Some(ContentHash::from_hex(&record.sha1))
        } else {
            None
        }
    }

    /// Record (or refresh) the digest for `path`.
    fn put(&mut self, path: &RelativePath, size: u64, mtime: SystemTime, hash: &ContentHash) {
        let (mtime_secs, mtime_nanos) = split_mtime(mtime);
        self.records.insert(
            path.as_str().to_owned(),
            CacheRecord {
                size,
                mtime_secs,
                mtime_nanos,
                sha1: hash.as_str().to_owned(),
            },
        );
    }

    /// Drop any record whose path is not in `live` — keeps the cache from
    /// growing without bound as files are deleted.
    fn retain_live(&mut self, live: &BTreeMap<RelativePath, IndexEntry>) {
        self.records
            .retain(|k, _| live.contains_key(&RelativePath::new(k)));
    }
}

/// Recursive local indexer over one directory root.
///
/// The indexer holds no filesystem handles and no hidden state; call
/// [`Indexer::index`] with a [`HashCache`] to walk + hash, or the convenience
/// [`Indexer::index_with_cache_file`] to load/save the cache around it.
#[derive(Debug, Clone)]
pub struct Indexer {
    root: PathBuf,
}

impl Indexer {
    /// Create an indexer rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Walk the tree, hashing files (reusing valid cache entries), and build a
    /// [`LocalIndex`]. `cache` is updated in place with fresh digests and
    /// pruned of vanished paths; the caller persists it afterwards.
    pub fn index(&self, cache: &mut HashCache) -> Result<LocalIndex, SyncError> {
        let mut entries = BTreeMap::new();
        self.walk(&self.root, cache, &mut entries)?;
        cache.retain_live(&entries);
        Ok(LocalIndex {
            root: self.root.clone(),
            entries,
            generated_at: SystemTime::now(),
        })
    }

    /// Convenience: load the cache from `cache_path`, index, then best-effort
    /// persist the refreshed cache back. A save failure is logged, not
    /// propagated — the freshly built index is always returned. Callers that
    /// need durable-cache guarantees should use [`Indexer::index`] +
    /// [`HashCache::save`] directly.
    pub fn index_with_cache_file(&self, cache_path: &Path) -> Result<LocalIndex, SyncError> {
        let mut cache = HashCache::load(cache_path);
        let index = self.index(&mut cache)?;
        if let Err(err) = cache.save(cache_path) {
            tracing::warn!(
                cache = %cache_path.display(),
                %err,
                "failed to persist hash cache — next index will rehash"
            );
        }
        Ok(index)
    }

    /// Depth-first, name-sorted walk. Directories recurse; regular files are
    /// hashed; symlinks and other non-regular entries are skipped.
    fn walk(
        &self,
        dir: &Path,
        cache: &mut HashCache,
        out: &mut BTreeMap<RelativePath, IndexEntry>,
    ) -> Result<(), SyncError> {
        let mut children: Vec<PathBuf> = Vec::new();
        let read_dir = fs::read_dir(dir).map_err(|source| SyncError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        for entry in read_dir {
            let entry = entry.map_err(|source| SyncError::Io {
                path: dir.to_path_buf(),
                source,
            })?;
            children.push(entry.path());
        }
        // Deterministic ordering regardless of the OS's readdir order.
        children.sort();

        for child in children {
            // `symlink_metadata` does not follow links, so a symlink reports as
            // a symlink here and is skipped rather than traversed.
            let meta = fs::symlink_metadata(&child).map_err(|source| SyncError::Io {
                path: child.clone(),
                source,
            })?;
            let file_type = meta.file_type();
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                self.walk(&child, cache, out)?;
            } else if file_type.is_file() {
                let rel = self.relative_of(&child);
                let size = meta.len();
                let mtime = meta.modified().map_err(|source| SyncError::Io {
                    path: child.clone(),
                    source,
                })?;
                let content_hash = match cache.get_valid(&rel, size, mtime) {
                    Some(hit) => hit,
                    None => {
                        let hashed = hash_file(&child)?;
                        cache.put(&rel, size, mtime, &hashed);
                        hashed
                    }
                };
                out.insert(
                    rel.clone(),
                    IndexEntry {
                        path: rel,
                        content_hash,
                        size,
                        mtime,
                    },
                );
            }
            // Anything else (fifo, socket, device) is silently ignored.
        }
        Ok(())
    }

    /// Path of `child` relative to the root, normalised to a [`RelativePath`].
    fn relative_of(&self, child: &Path) -> RelativePath {
        match child.strip_prefix(&self.root) {
            Ok(rel) => RelativePath::from_relative_fs(rel),
            // A child produced by walking `root` is always under it; this arm
            // only fires on a pathological root and degrades gracefully.
            Err(_) => RelativePath::from_relative_fs(child),
        }
    }
}

/// Stream a file through SHA1 in fixed-size chunks and return the lower-case
/// hex digest.
fn hash_file(path: &Path) -> Result<ContentHash, SyncError> {
    let file = File::open(path).map_err(|source| SyncError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha1::new();
    let mut buf = vec![0u8; HASH_CHUNK_BYTES];
    loop {
        let n = reader.read(&mut buf).map_err(|source| SyncError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(ContentHash::from_hex(hex_lower(&hasher.finalize())))
}

/// Split a `SystemTime` into floored whole seconds + sub-second nanos relative
/// to the unix epoch, handling pre-epoch times without panicking.
///
/// `nanos` always counts *forward* from `secs` (i.e. `secs` is the floor), so a
/// pre-epoch instant and its mirror-image post-epoch instant never collapse to
/// the same `(secs, nanos)` pair. The naive `(-secs, subsec_nanos)` encoding
/// did collide — e.g. 0.3 s before and 0.3 s after the epoch both mapped to
/// `(0, 300_000_000)`, letting a `HashCache` record validate against the wrong
/// mtime and return a stale digest for a changed file.
fn split_mtime(t: SystemTime) -> (i64, u32) {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            // `e.duration()` is the absolute distance *before* the epoch. Floor
            // it: -0.3 s → (-1, 700_000_000), distinct from +0.3 s →
            // (0, 300_000_000); a whole-second pre-epoch time keeps nanos 0.
            let d = e.duration();
            let secs = d.as_secs() as i64;
            let nanos = d.subsec_nanos();
            if nanos == 0 {
                (-secs, 0)
            } else {
                (-secs - 1, 1_000_000_000 - nanos)
            }
        }
    }
}

/// Lower-case hex encoding without pulling in a formatting dependency.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn split_mtime_pre_and_post_epoch_do_not_collide() {
        // The exact regression: 0.3 s before and 0.3 s after the epoch must not
        // encode to the same (secs, nanos), or a HashCache record validates
        // against the wrong mtime and returns a stale digest for a changed file.
        let before = split_mtime(SystemTime::UNIX_EPOCH - Duration::from_millis(300));
        let after = split_mtime(SystemTime::UNIX_EPOCH + Duration::from_millis(300));
        assert_ne!(before, after);
        assert_eq!(before, (-1, 700_000_000));
        assert_eq!(after, (0, 300_000_000));
    }

    #[test]
    fn split_mtime_whole_second_pre_epoch_keeps_zero_nanos() {
        assert_eq!(
            split_mtime(SystemTime::UNIX_EPOCH - Duration::from_secs(5)),
            (-5, 0)
        );
    }

    #[test]
    fn split_mtime_is_monotonic_across_the_epoch() {
        // Ordering the (secs, nanos) tuples must agree with time ordering.
        let times = [
            SystemTime::UNIX_EPOCH - Duration::from_millis(1500),
            SystemTime::UNIX_EPOCH - Duration::from_millis(300),
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH + Duration::from_millis(300),
            SystemTime::UNIX_EPOCH + Duration::from_millis(1500),
        ];
        let encoded: Vec<(i64, u32)> = times.iter().copied().map(split_mtime).collect();
        let mut sorted = encoded.clone();
        sorted.sort();
        assert_eq!(
            encoded, sorted,
            "encoding must preserve chronological order"
        );
    }
}
