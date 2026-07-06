//! Value objects shared across the Sync bounded context.
//!
//! Two newtypes carry the domain's ubiquitous language into the type system:
//! [`RelativePath`] is the aggregate key that ties a local file to its remote
//! counterpart, and [`ContentHash`] is the cleartext SHA1 digest that decides
//! whether two sides hold the same content (see `docs/domain-model-sync.md`
//! §3). Both serialise transparently as their inner string, so a
//! `BTreeMap<RelativePath, _>` round-trips through JSON with plain string keys.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Component, Path};

/// A file's path relative to a sync root, normalised to forward slashes.
///
/// The normalisation is deliberate: it is the *identity* by which a local
/// [`crate::IndexEntry`] and a remote [`crate::RemoteEntry`] are matched, so it
/// must be byte-for-byte identical on both sides regardless of the host OS's
/// native separator. `Ord` gives a deterministic, parent-before-sibling walk
/// order for free (a `BTreeMap` keyed on this yields stable plans).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RelativePath(String);

impl RelativePath {
    /// Build a `RelativePath` from an already-normalised forward-slash string.
    ///
    /// Leading/trailing slashes are trimmed and empty segments collapsed so
    /// that `"a//b/"` and `"a/b"` are the same identity.
    pub fn new(raw: impl AsRef<str>) -> Self {
        let cleaned: Vec<&str> = raw
            .as_ref()
            .split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect();
        Self(cleaned.join("/"))
    }

    /// Derive a `RelativePath` from a filesystem path taken *relative to* a sync
    /// root (i.e. already `strip_prefix`ed). Each path component becomes one
    /// forward-slash segment; `.` and `..` components are dropped defensively
    /// (the indexer never emits them, but a caller-supplied path might).
    pub fn from_relative_fs(path: &Path) -> Self {
        let segments: Vec<String> = path
            .components()
            .filter_map(|c| match c {
                Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        Self(segments.join("/"))
    }

    /// The normalised string form (forward-slash separated, no leading slash).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `true` for the root itself (empty relative path).
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// The parent path, or `None` for a top-level entry / the root.
    pub fn parent(&self) -> Option<RelativePath> {
        self.0
            .rsplit_once('/')
            .map(|(head, _)| RelativePath(head.to_owned()))
            .filter(|p| !p.0.is_empty())
    }

    /// Every ancestor directory from the top-level segment down to the direct
    /// parent, in parent-before-child order. `"a/b/c.txt"` yields `["a",
    /// "a/b"]`; a top-level file yields an empty vec.
    pub fn ancestors(&self) -> Vec<RelativePath> {
        let mut out = Vec::new();
        let segments: Vec<&str> = self.0.split('/').filter(|s| !s.is_empty()).collect();
        // The last segment is the entry itself, so stop one short of it.
        for end in 1..segments.len() {
            out.push(RelativePath(segments[..end].join("/")));
        }
        out
    }
}

impl fmt::Display for RelativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The cleartext SHA1 digest that decides content identity.
///
/// Locally it is computed directly from file bytes; remotely it is recovered
/// from the decrypted `Common.Digests.SHA1` extended attribute. Identical
/// hashes on both sides are authoritative — no size/mtime tie-break is needed
/// once a hash exists for both (`docs/domain-model-sync.md` §1, invariant 3).
/// Stored lower-case hex.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContentHash(String);

impl ContentHash {
    /// Wrap a hex digest string, normalising to lower case so that digests from
    /// different sources (local hasher vs. decrypted xattr) compare equal.
    pub fn from_hex(hex: impl AsRef<str>) -> Self {
        Self(hex.as_ref().to_ascii_lowercase())
    }

    /// The lower-case hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn relative_path_normalises_slashes() {
        assert_eq!(RelativePath::new("a//b/").as_str(), "a/b");
        assert_eq!(RelativePath::new("/a/./b").as_str(), "a/b");
        assert_eq!(RelativePath::new("").as_str(), "");
    }

    #[test]
    fn from_relative_fs_drops_dot_components() {
        let p = PathBuf::from("sub").join("deep").join("file.txt");
        assert_eq!(
            RelativePath::from_relative_fs(&p).as_str(),
            "sub/deep/file.txt"
        );
    }

    #[test]
    fn ancestors_are_parent_before_child() {
        let p = RelativePath::new("a/b/c/file.txt");
        let anc: Vec<String> = p.ancestors().iter().map(|a| a.to_string()).collect();
        assert_eq!(anc, vec!["a", "a/b", "a/b/c"]);
    }

    #[test]
    fn top_level_file_has_no_ancestors_and_no_parent() {
        let p = RelativePath::new("file.txt");
        assert!(p.ancestors().is_empty());
        assert_eq!(p.parent(), None);
    }

    #[test]
    fn parent_of_nested_path() {
        let p = RelativePath::new("a/b/c.txt");
        assert_eq!(p.parent(), Some(RelativePath::new("a/b")));
    }

    #[test]
    fn content_hash_is_case_insensitive() {
        assert_eq!(
            ContentHash::from_hex("ABCDEF"),
            ContentHash::from_hex("abcdef")
        );
    }
}
