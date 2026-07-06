//! The [`SyncPlan`] aggregate and its ops (`docs/domain-model-sync.md` §2,
//! *SyncPlan* / *SyncOp* / *ConflictOutcome*).
//!
//! A plan is **immutable once issued**. [`crate::diff`] emits a `Proposed`
//! plan; [`SyncPlan::resolve`] does not edit it in place but *supersedes* it,
//! returning a fresh `Approved` plan built from the caller's
//! [`ConflictOutcome`] decisions. The engine never manufactures a
//! `ConflictOutcome` itself (invariant 6): an unresolved conflict is an error,
//! not a guess.
//!
//! Ordering is significant and stable: ops are sorted parent-before-child so a
//! consumer (WP4) can apply them top-down, and [`SyncPlan::dirs_to_create`]
//! lists the remote directories that must exist before the `Upload` ops run.

use crate::error::SyncError;
use crate::path::{ContentHash, RelativePath};
use proton_drive_core::nodes::NodeUid;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Opaque plan identifier (UUIDv7 — time-ordered, so plans sort by issue time).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SyncPlanId(String);

impl SyncPlanId {
    /// The canonical 8-4-4-4-12 hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Mint a fresh time-ordered id.
    fn generate() -> Self {
        Self(uuid_v7())
    }
}

impl std::fmt::Display for SyncPlanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lifecycle state of a plan (`docs/domain-model-sync.md` §2).
///
/// `Applied` is set by the executor (WP4) once a plan's ops have run; the
/// engine only ever produces `Proposed` (from [`crate::diff`]) and `Approved`
/// (from [`SyncPlan::resolve`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanState {
    Proposed,
    Approved,
    Applied,
    Superseded,
}

/// Why a path was flagged as a conflict rather than transferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictReason {
    /// Both sides carry a digest and they differ — the engine cannot know which
    /// side is authoritative without a decision.
    ContentDiverged,
    /// The remote side has no recoverable digest (xattr absent/unparseable), so
    /// no safe comparison is possible. Never a silent transfer (invariant 3).
    NoRemoteDigest,
}

/// The action a plan proposes for one path.
///
/// [`crate::diff`] emits `Upload`, `Download`, `Skip`, or `Conflict`.
/// [`SyncPlan::resolve`] turns a resolved `Conflict` into `UploadRevision`
/// (keep local — new revision of the existing node) or `Download` (keep remote).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOpKind {
    /// Local file with no remote counterpart — create a new remote file.
    Upload,
    /// Local content wins over an existing remote node — upload a new revision.
    UploadRevision,
    /// Remote file to fetch (either remote-only, or a resolved keep-remote).
    Download,
    /// Both sides already hold identical content — nothing to do.
    Skip,
    /// Both sides changed (or the remote digest is missing); awaits a decision.
    Conflict(ConflictReason),
}

/// Snapshot-time facts about the local file (never re-read live).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRef {
    pub content_hash: ContentHash,
    pub size: u64,
    pub mtime: SystemTime,
}

/// Snapshot-time facts about the remote file, including the staleness token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRef {
    pub node_uid: NodeUid,
    /// Active revision uid at snapshot time — the token WP4 compares against
    /// live state before applying, to fail safe on a concurrent remote change
    /// (invariant 2).
    pub revision_uid: String,
    pub content_hash: Option<ContentHash>,
}

/// One planned action against one path. Identity is position + `path` within
/// the owning [`SyncPlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOp {
    pub path: RelativePath,
    pub kind: SyncOpKind,
    /// Present whenever a local file is involved (`Upload`, `UploadRevision`,
    /// `Skip`, `Conflict`); `None` for a pure `Download`.
    pub local: Option<LocalRef>,
    /// Present whenever a remote file is involved (`Download`, `UploadRevision`,
    /// `Skip`, `Conflict`); `None` for a pure `Upload`.
    pub remote: Option<RemoteRef>,
    /// The decision that resolved a conflict, recorded on the resulting op for
    /// audit. `None` on unresolved and non-conflict ops. Maps to the domain's
    /// `SyncOp.conflict` field.
    pub outcome: Option<ConflictOutcome>,
}

impl SyncOp {
    /// `true` while this op still needs a [`ConflictOutcome`] before the plan
    /// can be approved.
    pub fn is_unresolved_conflict(&self) -> bool {
        matches!(self.kind, SyncOpKind::Conflict(_))
    }

    /// The per-op staleness token (the remote active-revision uid), if this op
    /// targets an existing remote node.
    pub fn staleness_token(&self) -> Option<&str> {
        self.remote.as_ref().map(|r| r.revision_uid.as_str())
    }
}

/// The agent's decision resolving one conflict (`docs/domain-model-sync.md` §2).
/// Always supplied by the host — the engine never picks one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictOutcome {
    /// Local content wins → the resolved op becomes an `UploadRevision`.
    KeepLocal,
    /// Remote content wins → the resolved op becomes a `Download`.
    KeepRemote,
    /// Leave both sides untouched → the op is dropped from the approved set.
    Skip,
}

/// The immutable, ordered set of ops computed from one local/remote pair.
#[derive(Debug, Clone)]
pub struct SyncPlan {
    id: SyncPlanId,
    state: PlanState,
    ops: Vec<SyncOp>,
    /// Remote directories that must exist before the `Upload` ops run, in
    /// parent-before-child order. Chosen over inline `mkdir` ops so a consumer
    /// can create the whole scaffold up front, idempotently.
    dirs_to_create: Vec<RelativePath>,
    issued_at: SystemTime,
    /// The plan this one supersedes, set when produced by [`SyncPlan::resolve`].
    superseded: Option<SyncPlanId>,
}

impl SyncPlan {
    /// Construct a `Proposed` plan. Used by [`crate::diff`]; `ops` are assumed
    /// already sorted parent-before-child.
    pub(crate) fn proposed(ops: Vec<SyncOp>, dirs_to_create: Vec<RelativePath>) -> Self {
        Self {
            id: SyncPlanId::generate(),
            state: PlanState::Proposed,
            ops,
            dirs_to_create,
            issued_at: SystemTime::now(),
            superseded: None,
        }
    }

    /// The plan's identifier.
    pub fn id(&self) -> &SyncPlanId {
        &self.id
    }

    /// The plan's lifecycle state.
    pub fn state(&self) -> PlanState {
        self.state
    }

    /// The ordered ops.
    pub fn ops(&self) -> &[SyncOp] {
        &self.ops
    }

    /// Remote directories to create before applying, parent-before-child.
    pub fn dirs_to_create(&self) -> &[RelativePath] {
        &self.dirs_to_create
    }

    /// When the plan was issued.
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// The id of the plan this one supersedes, if any.
    pub fn superseded(&self) -> Option<&SyncPlanId> {
        self.superseded.as_ref()
    }

    /// Every path currently flagged as an unresolved conflict, with its reason.
    pub fn conflicts(&self) -> impl Iterator<Item = (&RelativePath, ConflictReason)> {
        self.ops.iter().filter_map(|op| match op.kind {
            SyncOpKind::Conflict(reason) => Some((&op.path, reason)),
            _ => None,
        })
    }

    /// `true` when no op still awaits a decision.
    pub fn is_fully_resolved(&self) -> bool {
        !self.ops.iter().any(SyncOp::is_unresolved_conflict)
    }

    /// Resolve every conflict with the supplied decisions and return a new,
    /// `Approved` plan that **supersedes** this one — this plan is left
    /// untouched (immutability, invariant 5).
    ///
    /// Resolution rules (`docs/domain-model-sync.md` §2):
    /// * `KeepLocal`  → the op becomes `UploadRevision` (new revision of the
    ///   existing remote node).
    /// * `KeepRemote` → the op becomes `Download`.
    /// * `Skip`       → the op is dropped from the approved set.
    ///
    /// Non-conflict ops (`Upload`/`Download`/`Skip`) pass through unchanged and
    /// in the same relative order. Errors:
    /// * [`SyncError::UnresolvedConflict`] — a conflict has no decision.
    /// * [`SyncError::UnexpectedDecision`] — a decision names a non-conflict path.
    pub fn resolve(
        &self,
        decisions: &BTreeMap<RelativePath, ConflictOutcome>,
    ) -> Result<SyncPlan, SyncError> {
        // Reject decisions that do not correspond to a conflict — catches stale
        // paths and typos rather than silently ignoring them.
        for path in decisions.keys() {
            let is_conflict = self
                .ops
                .iter()
                .any(|op| &op.path == path && op.is_unresolved_conflict());
            if !is_conflict {
                return Err(SyncError::UnexpectedDecision { path: path.clone() });
            }
        }

        let mut approved = Vec::with_capacity(self.ops.len());
        for op in &self.ops {
            match op.kind {
                SyncOpKind::Conflict(_) => {
                    let outcome =
                        decisions
                            .get(&op.path)
                            .ok_or_else(|| SyncError::UnresolvedConflict {
                                path: op.path.clone(),
                            })?;
                    match outcome {
                        ConflictOutcome::KeepLocal => approved.push(SyncOp {
                            kind: SyncOpKind::UploadRevision,
                            outcome: Some(ConflictOutcome::KeepLocal),
                            ..op.clone()
                        }),
                        ConflictOutcome::KeepRemote => approved.push(SyncOp {
                            kind: SyncOpKind::Download,
                            outcome: Some(ConflictOutcome::KeepRemote),
                            ..op.clone()
                        }),
                        ConflictOutcome::Skip => { /* dropped from the approved set */ }
                    }
                }
                _ => approved.push(op.clone()),
            }
        }

        Ok(SyncPlan {
            id: SyncPlanId::generate(),
            state: PlanState::Approved,
            ops: approved,
            dirs_to_create: self.dirs_to_create.clone(),
            issued_at: SystemTime::now(),
            superseded: Some(self.id.clone()),
        })
    }
}

/// Format 16 bytes as a canonical 8-4-4-4-12 lower-case hex UUID string.
fn format_uuid(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(36);
    for (i, &b) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Generate a UUIDv7 string: 48-bit unix-millis timestamp, version 7, variant
/// 10, remaining bits random. Time-ordered so plan ids sort by issue time.
fn uuid_v7() -> String {
    use rand::RngCore;
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut bytes = [0u8; 16];
    bytes[0] = (ts_ms >> 40) as u8;
    bytes[1] = (ts_ms >> 32) as u8;
    bytes[2] = (ts_ms >> 24) as u8;
    bytes[3] = (ts_ms >> 16) as u8;
    bytes[4] = (ts_ms >> 8) as u8;
    bytes[5] = ts_ms as u8;
    rand::thread_rng().fill_bytes(&mut bytes[6..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70; // version 7
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10
    format_uuid(&bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn uuid_v7_has_version_and_variant_nibbles() {
        let id = uuid_v7();
        assert_eq!(id.len(), 36);
        let bytes: Vec<char> = id.chars().filter(|c| *c != '-').collect();
        // 13th hex nibble (index 12) is the version → '7'.
        assert_eq!(bytes[12], '7');
        // 17th hex nibble (index 16) is the variant → one of 8,9,a,b.
        assert!(['8', '9', 'a', 'b'].contains(&bytes[16]));
    }

    #[test]
    fn plan_ids_are_unique() {
        let a = SyncPlanId::generate();
        let b = SyncPlanId::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn conflict_outcome_serde_is_snake_case() {
        let json = serde_json::to_string(&ConflictOutcome::KeepLocal).expect("serialise");
        assert_eq!(json, "\"keep_local\"");
        let back: ConflictOutcome = serde_json::from_str("\"keep_remote\"").expect("deserialise");
        assert_eq!(back, ConflictOutcome::KeepRemote);
    }
}
