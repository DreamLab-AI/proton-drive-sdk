//! Pure glue between the MCP tool surface and the SDK / sync-engine types.
//!
//! Everything here is offline and side-effect free — no live client, no
//! network, no filesystem beyond what a caller hands in — so it is unit-tested
//! directly. The live tool bodies (`tools.rs`) call these helpers to resolve
//! path segments, validate remote digests, bridge nodes into the sync engine,
//! parse agent decisions, and shape results.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use proton_drive::{NodeUid, make_node_uid};
use proton_drive_sync::{ConflictOutcome, ContentHash, RemoteEntry, SyncPlan};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// NodeUid wire form
// ---------------------------------------------------------------------------

/// Wire form of a [`NodeUid`] — an explicit two-field object rather than a
/// single delimited string, so a uid round-trips through JSON unambiguously
/// (Proton link/volume ids are opaque and may contain delimiter characters).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NodeUidDto {
    pub volume_id: String,
    pub node_id: String,
}

impl NodeUidDto {
    /// Reconstruct the domain [`NodeUid`].
    pub fn to_node_uid(&self) -> NodeUid {
        make_node_uid(&self.volume_id, &self.node_id)
    }
}

impl From<&NodeUid> for NodeUidDto {
    fn from(u: &NodeUid) -> Self {
        Self {
            volume_id: u.volume_id.clone(),
            node_id: u.node_id.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Path-segment resolution (the pure half; the live walk lives in tools.rs)
// ---------------------------------------------------------------------------

/// Split a `'/'`-separated logical path into non-empty segments. `""`, `"/"`,
/// and `"//"` all denote the My Files root and yield an empty vec. Case is
/// preserved — segment matching against decrypted node names is case-sensitive.
pub fn split_path_segments(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .map(str::to_owned)
        .collect()
}

/// Find the index of the first child whose name equals `segment` exactly
/// (case-sensitive). `None` is the "missing path segment" case — the live
/// walker turns it into an `invalid_params` error naming the missing segment.
pub fn match_segment<'a>(names: impl IntoIterator<Item = &'a str>, segment: &str) -> Option<usize> {
    names.into_iter().position(|n| n == segment)
}

// ---------------------------------------------------------------------------
// Remote digest validation + RemoteEntry bridge
// ---------------------------------------------------------------------------

/// Validate a claimed remote SHA1 hex digest, returning a [`ContentHash`] only
/// for a well-formed 40-character hex string (any case).
///
/// Anything else — absent, the wrong length (e.g. a truncated 39-char digest),
/// or non-hex — yields `None`, which the diff engine turns into a
/// `NoRemoteDigest` conflict rather than a silent (mis)comparison. A malformed
/// digest must never masquerade as content identity: a 39-char value can never
/// equal a real 40-char local SHA1, so trusting it would fabricate a spurious
/// `ContentDiverged` where the honest answer is "no usable digest, agent
/// decides" (`docs/domain-model-sync.md` invariant 3).
pub fn parse_remote_sha1(claimed: Option<&str>) -> Option<ContentHash> {
    let s = claimed?;
    if s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(ContentHash::from_hex(s))
    } else {
        None
    }
}

/// Bridge one remote file node into the sync engine's [`RemoteEntry`]. The
/// claimed SHA1 is validated (see [`parse_remote_sha1`]) before it is trusted
/// as content identity; the active revision uid becomes the staleness token.
pub fn to_remote_entry(
    uid: &NodeUid,
    revision_uid: &str,
    claimed_sha1: Option<&str>,
    size: u64,
) -> RemoteEntry {
    RemoteEntry::new(
        uid.clone(),
        revision_uid.to_owned(),
        parse_remote_sha1(claimed_sha1),
        size,
    )
}

// ---------------------------------------------------------------------------
// Conflict-decision parsing
// ---------------------------------------------------------------------------

/// Parse an agent-supplied conflict decision string into a [`ConflictOutcome`].
/// Accepts exactly `keep_local` | `keep_remote` | `skip` — the same snake_case
/// vocabulary the engine serialises, so the tool contract and the domain type
/// cannot drift.
pub fn parse_decision(raw: &str) -> Result<ConflictOutcome, String> {
    match raw {
        "keep_local" => Ok(ConflictOutcome::KeepLocal),
        "keep_remote" => Ok(ConflictOutcome::KeepRemote),
        "skip" => Ok(ConflictOutcome::Skip),
        other => Err(format!(
            "unknown decision '{other}' (expected keep_local | keep_remote | skip)"
        )),
    }
}

// ---------------------------------------------------------------------------
// sync_apply per-op result shape
// ---------------------------------------------------------------------------

/// One applied op's outcome, as returned by `sync_apply`. `result` is `"ok"`
/// or `"error"`; `error` carries the message on failure. `uid`/`revision_uid`
/// are populated for a successful upload / revision where the new node was
/// located. Every field beyond `path`/`op`/`result` is omitted when absent so
/// the JSON stays terse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpResult {
    pub path: String,
    pub op: String,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<NodeUidDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_uid: Option<String>,
}

impl OpResult {
    /// A successful op with no node to report (skip, download).
    pub fn ok(path: impl Into<String>, op: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            op: op.into(),
            result: "ok".to_owned(),
            error: None,
            uid: None,
            revision_uid: None,
        }
    }

    /// A failed op carrying the reason. One op failing never aborts the rest —
    /// this is captured and reported, not propagated.
    pub fn err(path: impl Into<String>, op: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            op: op.into(),
            result: "error".to_owned(),
            error: Some(message.into()),
            uid: None,
            revision_uid: None,
        }
    }

    /// Attach the located node uid + active revision uid to a successful op.
    #[must_use]
    pub fn with_node(mut self, uid: &NodeUid, revision_uid: Option<String>) -> Self {
        self.uid = Some(NodeUidDto::from(uid));
        self.revision_uid = revision_uid;
        self
    }
}

// ---------------------------------------------------------------------------
// Plan store
// ---------------------------------------------------------------------------

/// A stored plan plus the context `sync_apply` needs to execute it: the remote
/// subtree root the plan was computed against, and the local root its ops read
/// from. Kept together so an applied op can map a relative path to both a live
/// remote parent and a local file.
#[derive(Debug, Clone)]
pub struct StoredPlan {
    pub plan: SyncPlan,
    pub remote_root: NodeUid,
    pub local_root: PathBuf,
}

/// Process-lifetime store of proposed plans keyed by plan id (ADR-0013). In
/// memory only — a fresh `pdtui mcp` process starts empty (ADR-0003); a
/// long-running agent session amortises across many tool calls against one
/// process.
#[derive(Default)]
pub struct PlanStore {
    plans: Mutex<HashMap<String, StoredPlan>>,
}

impl PlanStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a stored plan, returning its id (the plan's own uuid).
    pub fn insert(&self, stored: StoredPlan) -> String {
        let id = stored.plan.id().as_str().to_owned();
        self.lock().insert(id.clone(), stored);
        id
    }

    /// Fetch a clone of the stored plan by id.
    pub fn get(&self, id: &str) -> Option<StoredPlan> {
        self.lock().get(id).cloned()
    }

    /// Remove and return a stored plan by id — the "consume" half of the store
    /// lifecycle. `sync_apply` deliberately does *not* consume (a plan is
    /// re-appliable per invariant 4), so this is currently exercised only by the
    /// store's own tests; retained as the completing half of the API.
    #[allow(dead_code)]
    pub fn remove(&self, id: &str) -> Option<StoredPlan> {
        self.lock().remove(id)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, StoredPlan>> {
        // A poisoned lock only means a prior holder panicked mid-update; the
        // map itself is still consistent to read/replace, and this is a
        // single-process personal-use tool — recover rather than propagate a
        // panic (workspace-wide `panic`/`unwrap` deny).
        self.plans.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

// ---------------------------------------------------------------------------
// Small pure helpers shared by the live tool bodies
// ---------------------------------------------------------------------------

/// Lower-case hex encoding, without pulling in a formatting dependency.
pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Whole seconds since the unix epoch (0 for pre-epoch times), for JSON mtime.
pub fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Join a sync-engine relative path (forward-slash) onto a local root,
/// component by component so it is correct regardless of the host separator.
pub fn rel_to_local(local_root: &Path, rel: &str) -> PathBuf {
    rel.split('/')
        .filter(|s| !s.is_empty())
        .fold(local_root.to_path_buf(), |acc, seg| acc.join(seg))
}

/// The final segment of a forward-slash relative path (the file/dir name).
pub fn last_segment(rel: &str) -> &str {
    rel.rsplit('/').next().unwrap_or(rel)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use proton_drive_sync::{HashCache, Indexer, RelativePath, RemoteSnapshot, diff};

    // ── path segments ────────────────────────────────────────────────────────

    #[test]
    fn split_path_segments_root_forms_are_empty() {
        assert!(split_path_segments("").is_empty());
        assert!(split_path_segments("/").is_empty());
        assert!(split_path_segments("//").is_empty());
    }

    #[test]
    fn split_path_segments_nested_and_trims() {
        assert_eq!(split_path_segments("a"), vec!["a"]);
        assert_eq!(split_path_segments("a/b/c"), vec!["a", "b", "c"]);
        assert_eq!(split_path_segments("/a//b/"), vec!["a", "b"]);
        assert_eq!(split_path_segments("./a/./b"), vec!["a", "b"]);
    }

    #[test]
    fn match_segment_found_missing_and_empty() {
        let names = ["alpha", "beta", "gamma"];
        assert_eq!(match_segment(names.iter().copied(), "beta"), Some(1));
        assert_eq!(match_segment(names.iter().copied(), "delta"), None);
        assert_eq!(match_segment(std::iter::empty(), "beta"), None);
        // Case-sensitive: "Beta" != "beta".
        assert_eq!(match_segment(names.iter().copied(), "Beta"), None);
    }

    // ── remote digest validation ─────────────────────────────────────────────

    #[test]
    fn parse_remote_sha1_accepts_only_well_formed_40_hex() {
        let valid = "da39a3ee5e6b4b0d3255bfef95601890afd80709"; // 40 chars
        assert_eq!(
            parse_remote_sha1(Some(valid)),
            Some(ContentHash::from_hex(valid))
        );
        // 39 chars — a truncated digest must be rejected, not trusted.
        assert_eq!(parse_remote_sha1(Some(&valid[..39])), None);
        // 41 chars.
        assert_eq!(parse_remote_sha1(Some(&format!("{valid}0")),), None);
        // Non-hex character in an otherwise 40-long string.
        let non_hex = "g".repeat(40);
        assert_eq!(parse_remote_sha1(Some(&non_hex)), None);
        // Absent.
        assert_eq!(parse_remote_sha1(None), None);
    }

    #[test]
    fn parse_remote_sha1_normalises_case() {
        let upper = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
        let lower = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        assert_eq!(
            parse_remote_sha1(Some(upper)),
            Some(ContentHash::from_hex(lower)),
            "an upper-case 40-hex digest must compare equal to its lower-case form"
        );
    }

    #[test]
    fn to_remote_entry_bridges_and_gates_bad_digest() {
        let uid = make_node_uid("vol", "node");
        let good = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

        let e = to_remote_entry(&uid, "rev-1", Some(good), 42);
        assert_eq!(e.node_uid, uid);
        assert_eq!(e.revision_uid, "rev-1");
        assert_eq!(e.size, 42);
        assert_eq!(e.sha1_hex, Some(ContentHash::from_hex(good)));

        // A 39-char digest is dropped to None → the diff engine will raise a
        // NoRemoteDigest conflict rather than trust it.
        let bad = to_remote_entry(&uid, "rev-2", Some(&good[..39]), 7);
        assert_eq!(bad.sha1_hex, None);
        assert_eq!(bad.revision_uid, "rev-2");
    }

    // ── decision parsing ─────────────────────────────────────────────────────

    #[test]
    fn parse_decision_accepts_the_three_outcomes() {
        assert_eq!(parse_decision("keep_local"), Ok(ConflictOutcome::KeepLocal));
        assert_eq!(
            parse_decision("keep_remote"),
            Ok(ConflictOutcome::KeepRemote)
        );
        assert_eq!(parse_decision("skip"), Ok(ConflictOutcome::Skip));
        assert!(parse_decision("overwrite").is_err());
        assert!(parse_decision("KeepLocal").is_err());
    }

    // ── OpResult serialization shape ─────────────────────────────────────────

    #[test]
    fn op_result_ok_shape_omits_absent_fields() {
        let r = OpResult::ok("a/b.txt", "download");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["path"], "a/b.txt");
        assert_eq!(v["op"], "download");
        assert_eq!(v["result"], "ok");
        assert!(v.get("error").is_none(), "error omitted when absent: {v}");
        assert!(v.get("uid").is_none());
        assert!(v.get("revision_uid").is_none());
    }

    #[test]
    fn op_result_err_shape_carries_message() {
        let r = OpResult::err("x.bin", "upload", "boom");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["result"], "error");
        assert_eq!(v["error"], "boom");
    }

    #[test]
    fn op_result_with_node_attaches_uid_and_revision() {
        let uid = make_node_uid("vol", "node");
        let r = OpResult::ok("f", "upload").with_node(&uid, Some("rev-9".to_owned()));
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["uid"]["volume_id"], "vol");
        assert_eq!(v["uid"]["node_id"], "node");
        assert_eq!(v["revision_uid"], "rev-9");
    }

    // ── plan store ───────────────────────────────────────────────────────────

    /// Build a real (Proposed) plan without a live client: an empty local index
    /// diffed against a one-file remote snapshot yields a single Download op.
    fn sample_stored_plan() -> StoredPlan {
        let dir = tempfile::tempdir().expect("tempdir");
        let index = Indexer::new(dir.path())
            .index(&mut HashCache::empty())
            .expect("index empty dir");
        let remote = RemoteSnapshot::from_entries([(
            RelativePath::new("only.txt"),
            RemoteEntry::new(make_node_uid("vol", "node"), "rev-1", None, 5),
        )]);
        let plan = diff(&index, &remote);
        StoredPlan {
            plan,
            remote_root: make_node_uid("vol", "root"),
            local_root: dir.path().to_path_buf(),
        }
    }

    #[test]
    fn plan_store_insert_get_remove() {
        let store = PlanStore::new();

        let stored = sample_stored_plan();
        let plan_id = stored.plan.id().as_str().to_owned();
        let ops_len = stored.plan.ops().len();

        let id = store.insert(stored);
        assert_eq!(id, plan_id, "insert returns the plan's own id");

        let got = store.get(&id).expect("plan present after insert");
        assert_eq!(got.plan.ops().len(), ops_len);
        assert_eq!(got.plan.id().as_str(), plan_id);
        assert_eq!(got.remote_root, make_node_uid("vol", "root"));

        assert!(store.get("no-such-plan").is_none());

        let removed = store.remove(&id).expect("remove returns the plan");
        assert_eq!(removed.plan.id().as_str(), plan_id);
        assert!(store.get(&id).is_none(), "plan gone after remove");
        assert!(store.remove(&id).is_none(), "double remove is None");
    }

    // ── small helpers ────────────────────────────────────────────────────────

    #[test]
    fn hex_lower_encodes() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    #[test]
    fn rel_to_local_joins_componentwise() {
        let root = Path::new("/tmp/root");
        assert_eq!(
            rel_to_local(root, "a/b/c.txt"),
            root.join("a").join("b").join("c.txt")
        );
        assert_eq!(rel_to_local(root, "top.txt"), root.join("top.txt"));
    }

    #[test]
    fn last_segment_of_relative_path() {
        assert_eq!(last_segment("a/b/c.txt"), "c.txt");
        assert_eq!(last_segment("top"), "top");
    }
}
