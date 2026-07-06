//! The remote side of a diff: a point-in-time projection of a Drive folder
//! subtree, keyed by relative path (`docs/domain-model-sync.md` §2,
//! *RemoteSnapshot*).
//!
//! This module is deliberately free of any listing/network code. WP4 fetches
//! nodes through `ProtonDriveClient`, decrypts the `Common.Digests.SHA1` xattr,
//! and feeds the results in through [`RemoteSnapshot::from_entries`]; the Sync
//! engine only ever sees the resulting plain data. Because the snapshot is the
//! last-known-remote-state checkpoint WP4 persists between planning cycles, the
//! whole structure is `serde`-serialisable.
//!
//! `NodeUid` (from `proton-drive-core`) is not itself `serde`-derivable and is
//! owned by another crate, so it is (de)serialised here through a local
//! [`serde(remote)`] mirror rather than by modifying the upstream type.

use crate::path::{ContentHash, RelativePath};
use proton_drive_core::nodes::NodeUid;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One remote file's state, keyed by [`RelativePath`] within a [`RemoteSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteEntry {
    /// Stable Drive handle for the node.
    #[serde(with = "node_uid_serde")]
    pub node_uid: NodeUid,
    /// The active revision's uid at snapshot time. This is the per-op staleness
    /// token: at apply time WP4 re-reads the node's active revision and refuses
    /// the op if it no longer matches (`docs/domain-model-sync.md` invariant 2).
    pub revision_uid: String,
    /// Cleartext SHA1 recovered from the decrypted xattr, or `None` when the
    /// xattr is absent/unparseable. `None` forces a conflict rather than a
    /// silent transfer (`docs/domain-model-sync.md` invariant 3).
    pub sha1_hex: Option<ContentHash>,
    /// File size in bytes as reported by the active revision.
    pub size: u64,
}

impl RemoteEntry {
    /// Construct a remote entry. `sha1_hex` is `None` when no cleartext digest
    /// could be recovered from the node's extended attributes.
    pub fn new(
        node_uid: NodeUid,
        revision_uid: impl Into<String>,
        sha1_hex: Option<ContentHash>,
        size: u64,
    ) -> Self {
        Self {
            node_uid,
            revision_uid: revision_uid.into(),
            sha1_hex,
            size,
        }
    }
}

/// A read-only projection of a Drive folder subtree, keyed by relative path.
///
/// A snapshot is never mutated by apply — apply changes Drive state via
/// Transfer, and a fresh snapshot is retaken for the next planning cycle. The
/// [`stale`](Self::is_stale) flag records that an unconsumed `DriveEvent` has
/// invalidated the projection; a stale snapshot must be retaken before it is
/// used as diff input (`docs/domain-model-sync.md` §5). Enforcing that guard is
/// the planning tool's job (WP4) — the pure [`crate::diff`] function itself is
/// infallible and does not inspect the flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSnapshot {
    /// The volume this subtree lives on, if known to the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_id: Option<String>,
    /// The subtree root this snapshot covers, if known to the caller.
    #[serde(
        default,
        with = "opt_node_uid_serde",
        skip_serializing_if = "Option::is_none"
    )]
    pub folder: Option<NodeUid>,
    /// When the snapshot was taken (unix epoch seconds), if recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taken_at_unix: Option<u64>,
    /// Set once an unconsumed `DriveEvent` invalidates the projection.
    #[serde(default)]
    stale: bool,
    entries: BTreeMap<RelativePath, RemoteEntry>,
}

impl RemoteSnapshot {
    /// Build a snapshot from an iterator of `(path, entry)` pairs. This is the
    /// only ingestion path: it takes no dependency on listing/client code, so
    /// the caller (WP4) owns the fetch+decrypt and simply hands over the result.
    pub fn from_entries<I>(entries: I) -> Self
    where
        I: IntoIterator<Item = (RelativePath, RemoteEntry)>,
    {
        Self {
            volume_id: None,
            folder: None,
            taken_at_unix: None,
            stale: false,
            entries: entries.into_iter().collect(),
        }
    }

    /// Attach the volume id this snapshot covers (builder style).
    #[must_use]
    pub fn with_volume(mut self, volume_id: impl Into<String>) -> Self {
        self.volume_id = Some(volume_id.into());
        self
    }

    /// Attach the subtree-root node this snapshot covers (builder style).
    #[must_use]
    pub fn with_folder(mut self, folder: NodeUid) -> Self {
        self.folder = Some(folder);
        self
    }

    /// Record when the snapshot was taken, as unix epoch seconds (builder style).
    #[must_use]
    pub fn taken_at_unix(mut self, secs: u64) -> Self {
        self.taken_at_unix = Some(secs);
        self
    }

    /// Look up the remote entry for a path, if present.
    pub fn get(&self, path: &RelativePath) -> Option<&RemoteEntry> {
        self.entries.get(path)
    }

    /// Iterate entries in deterministic (path-sorted) order.
    pub fn entries(&self) -> impl Iterator<Item = (&RelativePath, &RemoteEntry)> {
        self.entries.iter()
    }

    /// Number of files in the snapshot.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when the snapshot covers no files.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether an unconsumed event has invalidated this snapshot.
    pub fn is_stale(&self) -> bool {
        self.stale
    }

    /// Mark the snapshot stale. WP4 calls this when a scoped `DriveEvent`
    /// arrives; a stale snapshot must be retaken before the next plan.
    pub fn mark_stale(&mut self) {
        self.stale = true;
    }
}

/// `serde(remote)` mirror of `NodeUid` — the upstream type lives in
/// `proton-drive-core` and carries no `serde` derives, so it is (de)serialised
/// field-by-field here without touching the other crate.
#[derive(Serialize, Deserialize)]
#[serde(remote = "NodeUid")]
struct NodeUidRepr {
    volume_id: String,
    node_id: String,
}

/// Adapter for a bare `NodeUid` field (`#[serde(with = "node_uid_serde")]`).
mod node_uid_serde {
    use super::{NodeUid, NodeUidRepr};
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &NodeUid, s: S) -> Result<S::Ok, S::Error> {
        NodeUidRepr::serialize(v, s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<NodeUid, D::Error> {
        NodeUidRepr::deserialize(d)
    }
}

/// Adapter for an `Option<NodeUid>` field.
mod opt_node_uid_serde {
    use super::{NodeUid, NodeUidRepr};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &Option<NodeUid>, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wrap<'a>(#[serde(with = "NodeUidRepr")] &'a NodeUid);
        v.as_ref().map(Wrap).serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<NodeUid>, D::Error> {
        #[derive(Deserialize)]
        struct Wrap(#[serde(with = "NodeUidRepr")] NodeUid);
        Ok(Option::<Wrap>::deserialize(d)?.map(|Wrap(n)| n))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use proton_drive_core::nodes::make_node_uid;

    fn uid(v: &str, n: &str) -> NodeUid {
        make_node_uid(v, n)
    }

    #[test]
    fn from_entries_collects_and_sorts() {
        let snap = RemoteSnapshot::from_entries([
            (
                RelativePath::new("z.txt"),
                RemoteEntry::new(uid("vol", "z"), "rev-z", None, 1),
            ),
            (
                RelativePath::new("a.txt"),
                RemoteEntry::new(uid("vol", "a"), "rev-a", None, 2),
            ),
        ]);
        let paths: Vec<String> = snap.entries().map(|(p, _)| p.to_string()).collect();
        assert_eq!(paths, vec!["a.txt", "z.txt"]);
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn stale_flag_defaults_false_and_flips() {
        let mut snap = RemoteSnapshot::from_entries(std::iter::empty());
        assert!(!snap.is_stale());
        snap.mark_stale();
        assert!(snap.is_stale());
    }

    #[test]
    fn serde_round_trip_preserves_entries_and_metadata() {
        let snap = RemoteSnapshot::from_entries([
            (
                RelativePath::new("dir/a.txt"),
                RemoteEntry::new(
                    uid("vol-1", "node-a"),
                    "rev-1",
                    Some(ContentHash::from_hex("deadbeef")),
                    42,
                ),
            ),
            (
                RelativePath::new("b.txt"),
                RemoteEntry::new(uid("vol-1", "node-b"), "rev-2", None, 7),
            ),
        ])
        .with_volume("vol-1")
        .with_folder(uid("vol-1", "root"))
        .taken_at_unix(1_700_000_000);

        let json = serde_json::to_string(&snap).expect("serialise");
        let back: RemoteSnapshot = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(snap, back);

        // Node uid survives the mirror round-trip intact.
        let a = back.get(&RelativePath::new("dir/a.txt")).expect("entry a");
        assert_eq!(a.node_uid, uid("vol-1", "node-a"));
        assert_eq!(a.sha1_hex, Some(ContentHash::from_hex("deadbeef")));
        assert_eq!(back.folder, Some(uid("vol-1", "root")));
        assert_eq!(back.volume_id.as_deref(), Some("vol-1"));
        assert_eq!(back.taken_at_unix, Some(1_700_000_000));
    }
}
