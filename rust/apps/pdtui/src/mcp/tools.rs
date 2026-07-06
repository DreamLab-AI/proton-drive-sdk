//! Live tool implementations for the `pdtui mcp` surface.
//!
//! Each `pub async fn` here backs one `#[tool]` on [`DriveMcpServer`]
//! (`server.rs`) and returns a `serde_json::Value` (or an [`McpError`]) that the
//! server wraps into a `CallToolResult`. The tool semantics follow
//! `docs/PRD-mcp-agentic-sync.md` §6.2 and the plan/apply safety model in
//! `docs/adr/0013-mcp-server-surface.md`:
//!
//! * reads (`drive_list`, `local_index`) never mutate;
//! * `sync_plan` is a pure dry-run over two snapshots and stores the result;
//! * `sync_apply` executes only the ops of the named plan, re-checking remote
//!   revisions before an overwrite and never resolving a conflict itself;
//! * `events_poll` is an on-demand drain of the sanctioned Events API — never a
//!   background timer (`CLAUDE.md` no-ad-hoc-polling guardrail).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt as _;
use serde_json::{Value, json};

use proton_drive::{
    DriveEvent, DriveListener, MaybeNode, Node, NodeEventKind, NodeType, NodeUid,
    ProtonDriveClient, UploadMetadata,
};
use proton_drive_core::events::{drain_volume_events, fetch_latest_event_id};
use proton_drive_core::{DownloadStats, RevisionXAttr};
use proton_drive_sync::{
    ConflictOutcome, ConflictReason, HashCache, Indexer, LocalIndex, LocalRef, RelativePath,
    RemoteRef, RemoteSnapshot, SyncOp, SyncOpKind, SyncPlan, diff,
};

use crate::mcp::bridge::{self, NodeUidDto, StoredPlan};
use crate::mcp::server::{DriveMcpServer, map_sdk_err, mcp_bad_params, mcp_err};

/// Page size for folder-children listings. 150 is Proton's typical max page and
/// matches the client's own `iter_folder_children` constant.
const LIST_PAGE_SIZE: u32 = 150;

/// Cap on the number of `local_index` entries echoed back in the response. The
/// full index still feeds `sync_plan`; only the echo is truncated.
const LOCAL_INDEX_ECHO_CAP: usize = 1000;

/// Hard cap on remote nodes visited during a single `sync_plan` subtree walk.
/// A backstop against a cyclic/oversized remote folder graph — the walk fails
/// loudly past this rather than flooding requests or exhausting memory.
const MAX_REMOTE_NODES: usize = 100_000;

// ===========================================================================
// drive_list
// ===========================================================================

pub async fn drive_list(
    server: &DriveMcpServer,
    p: crate::mcp::server::DriveListParams,
) -> Result<Value, McpErrorAlias> {
    let folder = resolve_path(server, &p.path).await?;
    let children = server
        .client()
        .fetch_folder_children(&folder, LIST_PAGE_SIZE)
        .await
        .map_err(|e| map_sdk_err("drive_list", e))?;

    let live: Vec<&Node> = children
        .iter()
        .filter_map(|c| match c {
            MaybeNode::Node(n) if !n.trashed => Some(&**n),
            _ => None,
        })
        .collect();

    // Optional, opt-in digest fetch: one bounded-concurrency round trip per file
    // (the listing endpoint carries no XAttr — see `fetch_revision_xattrs`).
    let mut sha1_by_uid: HashMap<NodeUid, String> = HashMap::new();
    if p.include_digest {
        let pairs: Vec<(NodeUid, String)> = live
            .iter()
            .filter_map(|n| {
                if matches!(n.node_type, NodeType::File) {
                    n.active_revision
                        .as_ref()
                        .map(|r| (n.uid.clone(), r.uid.clone()))
                } else {
                    None
                }
            })
            .collect();
        for (uid, xattr) in fetch_digests(server.client_arc(), pairs).await {
            if let Some(sha1) = xattr.content_sha1 {
                sha1_by_uid.insert(uid, sha1);
            }
        }
    }

    let items: Vec<Value> = live
        .iter()
        .map(|n| {
            let kind = match n.node_type {
                NodeType::File => "file",
                NodeType::Folder => "folder",
                NodeType::Album => "album",
            };
            let mut obj = json!({
                "uid": NodeUidDto::from(&n.uid),
                "name": n.name,
                "kind": kind,
                "size": n.size_bytes,
                "mtime": bridge::unix_secs(n.modified_at),
            });
            if let Some(sha1) = sha1_by_uid.get(&n.uid) {
                obj["sha1"] = json!(sha1);
            }
            obj
        })
        .collect();

    Ok(json!({
        "path": p.path,
        "uid": NodeUidDto::from(&folder),
        "count": items.len(),
        "children": items,
    }))
}

// ===========================================================================
// drive_download
// ===========================================================================

pub async fn drive_download(
    server: &DriveMcpServer,
    p: crate::mcp::server::DriveDownloadParams,
) -> Result<Value, McpErrorAlias> {
    p.uid.validate().map_err(mcp_bad_params)?;
    let uid = p.uid.to_node_uid();
    let dest = PathBuf::from(&p.local_path);
    if dest.exists() && !p.overwrite {
        return Err(mcp_bad_params(format!(
            "{} already exists (pass overwrite:true to replace)",
            dest.display()
        )));
    }
    let stats = download_file(server, &uid, &dest).await.map_err(mcp_err)?;
    let sha1 = sha1_hex_of_file(&dest).await.map_err(mcp_err)?;
    Ok(json!({
        "bytes": stats.bytes,
        "sha1": sha1,
        "signature_verified": stats.signature_verified,
    }))
}

// ===========================================================================
// drive_upload
// ===========================================================================

pub async fn drive_upload(
    server: &DriveMcpServer,
    p: crate::mcp::server::DriveUploadParams,
) -> Result<Value, McpErrorAlias> {
    let parent = resolve_path(server, &p.remote_parent_path).await?;
    let local_file = PathBuf::from(&p.local_path);
    let name = match &p.name {
        Some(n) => n.clone(),
        None => local_file
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .ok_or_else(|| {
                mcp_bad_params(format!("cannot derive a name from '{}'", p.local_path))
            })?,
    };

    let (meta, sha1) = build_upload_meta(&local_file)
        .await
        .map_err(mcp_bad_params)?;

    // New file first. On a name collision the existing file is only touched when
    // the caller explicitly opts in (`allow_revision_on_conflict`): otherwise a
    // create silently replacing an unrelated file is a data-safety hole, so the
    // default is to fail and let the caller decide. The collision is detected
    // via the SDK's own 2500 → `NodeWithSameNameExists` mapping.
    let created_revision = match run_upload(
        server,
        UploadTarget::New {
            parent: &parent,
            name: &name,
        },
        &local_file,
        meta.clone(),
    )
    .await
    {
        Ok(()) => false,
        Err(proton_drive::Error::NodeWithSameNameExists { .. }) => {
            if !p.allow_revision_on_conflict {
                return Err(mcp_bad_params(format!(
                    "a file named '{name}' already exists under '{}'. Refusing to overwrite it. \
                     Re-call with allow_revision_on_conflict=true to upload a new revision of the \
                     existing file, or choose a different name.",
                    p.remote_parent_path
                )));
            }
            let existing = resolve_child(server, &parent, &name, false)
                .await
                .map_err(|e| map_sdk_err("locate existing node", e))?;
            let (node_uid, _) = existing.ok_or_else(|| {
                mcp_err(format!(
                    "name '{name}' collides under the parent but the existing file could not be located"
                ))
            })?;
            run_upload(
                server,
                UploadTarget::Revision { node: &node_uid },
                &local_file,
                meta.clone(),
            )
            .await
            .map_err(|e| map_sdk_err("revision upload", e))?;
            true
        }
        Err(e) => return Err(map_sdk_err("upload", e)),
    };

    // Re-list to report the resulting node uid + active revision uid.
    let located = resolve_child(server, &parent, &name, false)
        .await
        .map_err(|e| map_sdk_err("locate uploaded node", e))?;
    let (uid_json, rev_json) = match located {
        Some((uid, rev)) => (json!(NodeUidDto::from(&uid)), json!(rev)),
        None => (Value::Null, Value::Null),
    };

    Ok(json!({
        "uid": uid_json,
        "revision_uid": rev_json,
        "sha1": sha1,
        "created_revision": created_revision,
    }))
}

// ===========================================================================
// drive_mkdir
// ===========================================================================

pub async fn drive_mkdir(
    server: &DriveMcpServer,
    p: crate::mcp::server::DriveMkdirParams,
) -> Result<Value, McpErrorAlias> {
    let parent = resolve_path(server, &p.parent_path).await?;
    let uid = server
        .client()
        .create_folder(&parent, &p.name)
        .await
        .map_err(|e| map_sdk_err("create_folder", e))?;
    Ok(json!({ "uid": NodeUidDto::from(&uid) }))
}

// ===========================================================================
// local_index
// ===========================================================================

pub async fn local_index(
    _server: &DriveMcpServer,
    p: crate::mcp::server::LocalIndexParams,
) -> Result<Value, McpErrorAlias> {
    let root = PathBuf::from(&p.root);
    let index = build_local_index(root, p.cache_file.clone())
        .await
        .map_err(mcp_err)?;

    let count = index.len();
    let entries: Vec<Value> = index
        .entries()
        .take(LOCAL_INDEX_ECHO_CAP)
        .map(|(path, e)| {
            json!({
                "path": path.as_str(),
                "sha1": e.content_hash.as_str(),
                "size": e.size,
                "mtime": bridge::unix_secs(e.mtime),
            })
        })
        .collect();

    Ok(json!({
        "root": index.root().display().to_string(),
        "count": count,
        "truncated": count > LOCAL_INDEX_ECHO_CAP,
        "entries": entries,
    }))
}

// ===========================================================================
// sync_plan
// ===========================================================================

pub async fn sync_plan(
    server: &DriveMcpServer,
    p: crate::mcp::server::SyncPlanParams,
) -> Result<Value, McpErrorAlias> {
    let local_root = PathBuf::from(&p.local_root);
    let index = build_local_index(local_root.clone(), p.cache_file.clone())
        .await
        .map_err(mcp_err)?;

    let remote_root = resolve_path(server, &p.remote_folder).await?;
    let files = collect_remote_files(server, &remote_root).await?;

    // On-demand digest fetch for the whole remote subtree (bounded concurrency
    // inside the SDK). A malformed/absent digest becomes a NoRemoteDigest
    // conflict, never a silent transfer (`bridge::to_remote_entry`).
    let pairs: Vec<(NodeUid, String)> = files
        .iter()
        .map(|f| (f.uid.clone(), f.revision_uid.clone()))
        .collect();
    let xattrs = fetch_digests(server.client_arc(), pairs).await;

    let entries = files.iter().map(|f| {
        let sha1 = xattrs.get(&f.uid).and_then(|x| x.content_sha1.as_deref());
        (
            RelativePath::new(&f.rel),
            bridge::to_remote_entry(&f.uid, &f.revision_uid, sha1, f.size),
        )
    });
    let snapshot = RemoteSnapshot::from_entries(entries)
        .with_folder(remote_root.clone())
        .with_volume(server.volume_id().to_owned())
        .taken_at_unix(bridge::unix_secs(std::time::SystemTime::now()));

    let plan = diff(&index, &snapshot);
    let plan_id = plan.id().as_str().to_owned();
    let checkpoint = persist_checkpoint(server, &plan_id, &snapshot);
    let response = plan_response(&plan, checkpoint.as_deref());

    // Store the plan plus the context sync_apply needs to execute it.
    server.plans().insert(StoredPlan {
        plan,
        remote_root,
        local_root,
    });

    Ok(response)
}

// ===========================================================================
// sync_apply
// ===========================================================================

pub async fn sync_apply(
    server: &DriveMcpServer,
    p: crate::mcp::server::SyncApplyParams,
) -> Result<Value, McpErrorAlias> {
    let stored = server.plans().get(&p.plan_id).ok_or_else(|| {
        mcp_bad_params(format!(
            "no plan with id '{}' (call sync_plan first; plans are held per-process)",
            p.plan_id
        ))
    })?;

    // Parse the decision map, then resolve the plan. `resolve` rejects both an
    // unresolved conflict and a decision naming a non-conflict path — those come
    // back as invalid_params, never a silent guess.
    let mut decisions: BTreeMap<RelativePath, ConflictOutcome> = BTreeMap::new();
    for (path, raw) in &p.decisions {
        let outcome = bridge::parse_decision(raw).map_err(mcp_bad_params)?;
        decisions.insert(RelativePath::new(path), outcome);
    }
    let approved = stored
        .plan
        .resolve(&decisions)
        .map_err(|e| mcp_bad_params(format!("{e}")))?;

    let results = apply_approved(server, &approved, &stored.remote_root, &stored.local_root).await;

    Ok(json!({
        "plan_id": p.plan_id,
        "applied": results.len(),
        "results": results,
    }))
}

// ===========================================================================
// events_poll
// ===========================================================================

pub async fn events_poll(
    server: &DriveMcpServer,
    p: crate::mcp::server::EventsPollParams,
) -> Result<Value, McpErrorAlias> {
    // Validate agent-supplied ids before they reach a `format!`ed API URL path.
    // The default volume id comes from the trusted session, so only a
    // caller-provided override needs checking.
    if let Some(v) = &p.volume_id {
        bridge::validate_opaque_id("volume_id", v).map_err(mcp_bad_params)?;
    }
    if let Some(since) = &p.since_event_id {
        bridge::validate_opaque_id("since_event_id", since).map_err(mcp_bad_params)?;
    }
    let volume_id = p
        .volume_id
        .clone()
        .unwrap_or_else(|| server.volume_id().to_owned());

    match &p.since_event_id {
        None => {
            // No cursor: return the current latest event id as the anchor to
            // resume from on the next call. No events are drained.
            let latest = fetch_latest_event_id(server.http(), &volume_id)
                .await
                .map_err(|e| map_sdk_err("events_poll (latest)", e))?;
            Ok(json!({
                "volume_id": volume_id,
                "next_anchor": latest,
                "events": [],
            }))
        }
        Some(since) => {
            let collector = CollectingListener::default();
            let outcome = drain_volume_events(server.http(), &volume_id, &collector, since.clone())
                .await
                .map_err(|e| map_sdk_err("events_poll (drain)", e))?;
            Ok(json!({
                "volume_id": volume_id,
                "next_anchor": outcome.cursor,
                "refreshed": outcome.refreshed,
                "events": collector.take(),
            }))
        }
    }
}

// ===========================================================================
// Path resolution + child lookup
// ===========================================================================

/// Walk a logical `'/'`-separated path from the My Files root to a folder
/// [`NodeUid`], matching each segment against decrypted child folder names
/// (case-sensitive). `""`/`"/"` resolves to the root itself.
async fn resolve_path(server: &DriveMcpServer, path: &str) -> Result<NodeUid, McpErrorAlias> {
    let segments = bridge::split_path_segments(path);
    let mut current = server.root_uid().clone();
    for seg in &segments {
        let children = server
            .client()
            .fetch_folder_children(&current, LIST_PAGE_SIZE)
            .await
            .map_err(|e| map_sdk_err("resolve path", e))?;

        let mut names: Vec<&str> = Vec::new();
        let mut uids: Vec<&NodeUid> = Vec::new();
        for child in &children {
            if let MaybeNode::Node(n) = child
                && !n.trashed
                && matches!(n.node_type, NodeType::Folder)
            {
                names.push(n.name.as_str());
                uids.push(&n.uid);
            }
        }
        let idx = bridge::match_segment(names.iter().copied(), seg).ok_or_else(|| {
            mcp_bad_params(format!(
                "folder path segment '{seg}' not found under '{path}'"
            ))
        })?;
        current = uids
            .get(idx)
            .map(|u| (*u).clone())
            .ok_or_else(|| mcp_err("internal: resolved segment index out of range"))?;
    }
    Ok(current)
}

/// Resolve an existing remote folder addressed by a sync-engine relative path,
/// walking `start` down one folder segment at a time. Returns `None` if any
/// segment is absent (the folder does not exist remotely) — distinct from an
/// `Err`, which is a transport/listing failure.
///
/// Sync's `dirs_to_create` deliberately omits directories that already back a
/// remote file, so an `Upload` op targeting a pre-existing folder has no entry
/// in the freshly-created `dir_uids` map; this recovers that folder's uid.
async fn resolve_existing_dir(
    server: &DriveMcpServer,
    start: &NodeUid,
    rel: &RelativePath,
) -> Result<Option<NodeUid>, McpErrorAlias> {
    let mut current = start.clone();
    for seg in rel.as_str().split('/').filter(|s| !s.is_empty()) {
        let children = server
            .client()
            .fetch_folder_children(&current, LIST_PAGE_SIZE)
            .await
            .map_err(|e| map_sdk_err("sync_apply (resolve existing dir)", e))?;
        let mut found: Option<NodeUid> = None;
        for child in &children {
            if let MaybeNode::Node(n) = child
                && !n.trashed
                && matches!(n.node_type, NodeType::Folder)
                && n.has_decrypted_name()
                && n.name == seg
            {
                found = Some(n.uid.clone());
                break;
            }
        }
        match found {
            Some(uid) => current = uid,
            None => return Ok(None),
        }
    }
    Ok(Some(current))
}

/// Find a non-trashed child of `parent` named `name`. `want_folder` selects
/// Folder vs File exactly (Albums never match). Returns the uid and, for a file,
/// its active revision uid.
async fn resolve_child(
    server: &DriveMcpServer,
    parent: &NodeUid,
    name: &str,
    want_folder: bool,
) -> Result<Option<(NodeUid, Option<String>)>, proton_drive::Error> {
    let children = server
        .client()
        .fetch_folder_children(parent, LIST_PAGE_SIZE)
        .await?;
    for child in &children {
        if let MaybeNode::Node(n) = child {
            if n.trashed || n.name != name {
                continue;
            }
            let matches_kind = if want_folder {
                matches!(n.node_type, NodeType::Folder)
            } else {
                matches!(n.node_type, NodeType::File)
            };
            if matches_kind {
                let rev = n.active_revision.as_ref().map(|r| r.uid.clone());
                return Ok(Some((n.uid.clone(), rev)));
            }
        }
    }
    Ok(None)
}

// ===========================================================================
// Remote subtree walk
// ===========================================================================

/// One remote file discovered while walking a folder subtree.
struct RemoteFile {
    rel: String,
    uid: NodeUid,
    revision_uid: String,
    size: u64,
}

/// Recursively list `root`'s subtree, collecting every non-trashed file keyed by
/// its path relative to `root`. Uses an explicit stack (no async recursion).
/// Descends real folders only; photo albums are outside Sync's scope.
async fn collect_remote_files(
    server: &DriveMcpServer,
    root: &NodeUid,
) -> Result<Vec<RemoteFile>, McpErrorAlias> {
    let mut out = Vec::new();
    let mut stack: Vec<(NodeUid, String)> = vec![(root.clone(), String::new())];
    // Cycle + size guards: the remote folder graph is untrusted input. A folder
    // that is (transitively) its own ancestor — a malformed server response or a
    // future multi-parent feature — would otherwise loop forever, flooding
    // requests and growing `out`/`stack` without bound. `visited` breaks cycles;
    // MAX_REMOTE_NODES caps the walk and fails loudly rather than exhausting.
    let mut visited: std::collections::HashSet<NodeUid> = std::collections::HashSet::new();
    visited.insert(root.clone());
    let mut seen_count: usize = 0;
    while let Some((folder, prefix)) = stack.pop() {
        let children = server
            .client()
            .fetch_folder_children(&folder, LIST_PAGE_SIZE)
            .await
            .map_err(|e| map_sdk_err("sync_plan (list remote)", e))?;
        for child in &children {
            if let MaybeNode::Node(n) = child {
                if n.trashed {
                    continue;
                }
                seen_count += 1;
                if seen_count > MAX_REMOTE_NODES {
                    return Err(mcp_err(format!(
                        "remote subtree exceeds {MAX_REMOTE_NODES} nodes — refusing to walk further \
                         (cyclic folder graph or a tree too large to sync in one plan)"
                    )));
                }
                // A node whose name failed to decrypt carries a synthetic
                // placeholder, and a name containing a path separator or a
                // `.`/`..` segment is not a valid sync identity — folding either
                // into the tree would fork or misplace the identity (a transient
                // decrypt failure would masquerade as a distinct remote file).
                // Skip and report to stderr; the transport stays on stdout.
                if !n.has_decrypted_name() || !bridge::is_safe_name_segment(&n.name) {
                    // Skipping a FOLDER drops its entire subtree from the
                    // snapshot, so any local counterparts diff as local-only and
                    // would re-upload as duplicates. Say so, not just "one node".
                    let scope = if matches!(n.node_type, NodeType::Folder) {
                        " (and its entire subtree)"
                    } else {
                        ""
                    };
                    eprintln!(
                        "sync_plan: skipping remote node {}{scope} — name is not a usable sync identity ('{}')",
                        n.uid.node_id, n.name
                    );
                    continue;
                }
                let rel = if prefix.is_empty() {
                    n.name.clone()
                } else {
                    format!("{prefix}/{}", n.name)
                };
                match n.node_type {
                    // Descend a folder only the first time it is seen; a repeat
                    // uid is a cycle and is skipped (reported to stderr).
                    NodeType::Folder => {
                        if visited.insert(n.uid.clone()) {
                            stack.push((n.uid.clone(), rel));
                        } else {
                            eprintln!(
                                "sync_plan: skipping already-visited remote folder {} — cyclic graph",
                                n.uid.node_id
                            );
                        }
                    }
                    NodeType::File => {
                        if let Some(rev) = n.active_revision.as_ref().map(|r| r.uid.clone()) {
                            out.push(RemoteFile {
                                rel,
                                uid: n.uid.clone(),
                                revision_uid: rev,
                                size: n.size_bytes.unwrap_or(0),
                            });
                        }
                    }
                    NodeType::Album => {}
                }
            }
        }
    }
    Ok(out)
}

// ===========================================================================
// Plan response serialization
// ===========================================================================

fn plan_response(plan: &SyncPlan, checkpoint: Option<&str>) -> Value {
    let ops: Vec<Value> = plan.ops().iter().map(op_to_json).collect();
    let conflicts: Vec<Value> = plan
        .ops()
        .iter()
        .filter_map(|op| match op.kind {
            SyncOpKind::Conflict(reason) => Some(json!({
                "path": op.path.to_string(),
                "reason": conflict_reason_str(reason),
                "local": op.local.as_ref().map(local_ref_json),
                "remote": op.remote.as_ref().map(remote_ref_json),
            })),
            _ => None,
        })
        .collect();
    let dirs: Vec<String> = plan
        .dirs_to_create()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    json!({
        "plan_id": plan.id().as_str(),
        "summary": summary_counts(plan),
        "ops": ops,
        "conflicts": conflicts,
        "dirs_to_create": dirs,
        "checkpoint": checkpoint,
    })
}

fn summary_counts(plan: &SyncPlan) -> Value {
    let (mut upload, mut upload_revision, mut download, mut skip, mut conflict) = (0, 0, 0, 0, 0);
    for op in plan.ops() {
        match op.kind {
            SyncOpKind::Upload => upload += 1,
            SyncOpKind::UploadRevision => upload_revision += 1,
            SyncOpKind::Download => download += 1,
            SyncOpKind::Skip => skip += 1,
            SyncOpKind::Conflict(_) => conflict += 1,
        }
    }
    json!({
        "upload": upload,
        "upload_revision": upload_revision,
        "download": download,
        "skip": skip,
        "conflict": conflict,
    })
}

fn op_to_json(op: &SyncOp) -> Value {
    let mut obj = json!({
        "path": op.path.to_string(),
        "op": op_kind_str(op.kind),
    });
    if let Some(l) = &op.local {
        obj["local"] = local_ref_json(l);
    }
    if let Some(r) = &op.remote {
        obj["remote"] = remote_ref_json(r);
    }
    if let SyncOpKind::Conflict(reason) = op.kind {
        obj["reason"] = json!(conflict_reason_str(reason));
    }
    obj
}

fn local_ref_json(l: &LocalRef) -> Value {
    json!({
        "sha1": l.content_hash.as_str(),
        "size": l.size,
        "mtime": bridge::unix_secs(l.mtime),
    })
}

fn remote_ref_json(r: &RemoteRef) -> Value {
    json!({
        "uid": NodeUidDto::from(&r.node_uid),
        "revision_uid": r.revision_uid,
        "sha1": r.content_hash.as_ref().map(|c| c.as_str()),
    })
}

fn op_kind_str(kind: SyncOpKind) -> &'static str {
    match kind {
        SyncOpKind::Upload => "upload",
        SyncOpKind::UploadRevision => "upload_revision",
        SyncOpKind::Download => "download",
        SyncOpKind::Skip => "skip",
        SyncOpKind::Conflict(_) => "conflict",
    }
}

fn conflict_reason_str(reason: ConflictReason) -> &'static str {
    match reason {
        ConflictReason::ContentDiverged => "content_diverged",
        ConflictReason::NoRemoteDigest => "no_remote_digest",
    }
}

/// Best-effort persist of the remote-snapshot checkpoint. A write failure is
/// logged (to stderr, never stdout) and reported as an absent checkpoint, not a
/// tool failure — the plan is already usable from the in-memory store.
fn persist_checkpoint(
    server: &DriveMcpServer,
    plan_id: &str,
    snapshot: &RemoteSnapshot,
) -> Option<String> {
    let dir = server.checkpoint_dir();
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::warn!("checkpoint dir {}: {e}", dir.display());
        return None;
    }
    let path = dir.join(format!("{plan_id}.json"));
    match serde_json::to_vec_pretty(snapshot) {
        Ok(bytes) => match std::fs::write(&path, bytes) {
            Ok(()) => Some(path.display().to_string()),
            Err(e) => {
                tracing::warn!("checkpoint write {}: {e}", path.display());
                None
            }
        },
        Err(e) => {
            tracing::warn!("checkpoint serialise: {e}");
            None
        }
    }
}

// ===========================================================================
// Apply
// ===========================================================================

async fn apply_approved(
    server: &DriveMcpServer,
    approved: &SyncPlan,
    remote_root: &NodeUid,
    local_root: &Path,
) -> Vec<bridge::OpResult> {
    // 1. Create the remote directory scaffold first, parent-before-child, so
    //    upload targets have a live parent. Idempotent: an already-existing dir
    //    is resolved rather than treated as a failure (invariant 4).
    let mut dir_uids: HashMap<RelativePath, NodeUid> = HashMap::new();
    let mut results: Vec<bridge::OpResult> = Vec::new();
    for dir in approved.dirs_to_create() {
        let parent = match dir.parent() {
            None => Some(remote_root.clone()),
            // A new dir's parent may itself be new (in dir_uids) or a
            // pre-existing remote folder (never in dir_uids, because
            // dirs_to_create omits already-backed dirs) — resolve the latter by
            // walking, so scaffolding e.g. "a/b" with "a" already remote works.
            Some(p) => match dir_uids.get(&p).cloned() {
                Some(uid) => Some(uid),
                None => resolve_existing_dir(server, remote_root, &p)
                    .await
                    .ok()
                    .flatten(),
            },
        };
        let Some(parent) = parent else {
            results.push(bridge::OpResult::err(
                dir.to_string(),
                "mkdir",
                "parent directory could not be created or resolved",
            ));
            continue;
        };
        let name = bridge::last_segment(dir.as_str());
        match server.client().create_folder(&parent, name).await {
            Ok(uid) => {
                dir_uids.insert(dir.clone(), uid);
            }
            Err(proton_drive::Error::NodeWithSameNameExists { .. }) => {
                match resolve_child(server, &parent, name, true).await {
                    Ok(Some((uid, _))) => {
                        dir_uids.insert(dir.clone(), uid);
                    }
                    Ok(None) => results.push(bridge::OpResult::err(
                        dir.to_string(),
                        "mkdir",
                        "name exists but the folder could not be located",
                    )),
                    Err(e) => results.push(bridge::OpResult::err(
                        dir.to_string(),
                        "mkdir",
                        format!("resolve existing folder: {e}"),
                    )),
                }
            }
            Err(e) => results.push(bridge::OpResult::err(
                dir.to_string(),
                "mkdir",
                format!("create_folder: {e}"),
            )),
        }
    }

    // 1b. Resolve parents of Upload ops that live in *pre-existing* remote
    //     folders. dirs_to_create omits dirs already backed by a remote file, so
    //     their uids are absent from dir_uids; without this an Upload into any
    //     non-empty remote folder would fail with "remote parent not available".
    //     Done sequentially before the concurrent phase so the resolution walk
    //     is not repeated per-op and dir_uids can stay an immutable shared ref.
    let mut parents_needed: Vec<RelativePath> = approved
        .ops()
        .iter()
        .filter(|op| matches!(op.kind, SyncOpKind::Upload))
        .filter_map(|op| op.path.parent())
        .filter(|p| !dir_uids.contains_key(p))
        .collect();
    parents_needed.sort();
    parents_needed.dedup();
    for parent in parents_needed {
        // Left absent on None/Err → the Upload op reports a clear per-op error
        // rather than the whole apply failing.
        if let Ok(Some(uid)) = resolve_existing_dir(server, remote_root, &parent).await {
            dir_uids.insert(parent, uid);
        }
    }

    // 2. Apply file ops with bounded concurrency. Ops target distinct paths, so
    //    running them in parallel is safe; each captures its own outcome and one
    //    failure never aborts the rest. The op futures are built eagerly into a
    //    Vec (rather than via a lazy `StreamExt::map`) to sidestep a rustc
    //    higher-ranked-lifetime false-negative that otherwise blocks proving the
    //    `Send` bound rmcp requires (#102211).
    let dir_uids = &dir_uids;
    let op_futures: Vec<_> = approved
        .ops()
        .iter()
        .enumerate()
        .map(|(i, op)| async move {
            (
                i,
                exec_op(server, op, remote_root, local_root, dir_uids).await,
            )
        })
        .collect();
    let mut indexed: Vec<(usize, bridge::OpResult)> = futures::stream::iter(op_futures)
        .buffer_unordered(server.max_parallel())
        .collect()
        .await;
    indexed.sort_by_key(|(i, _)| *i);
    results.extend(indexed.into_iter().map(|(_, r)| r));
    results
}

async fn exec_op(
    server: &DriveMcpServer,
    op: &SyncOp,
    remote_root: &NodeUid,
    local_root: &Path,
    dir_uids: &HashMap<RelativePath, NodeUid>,
) -> bridge::OpResult {
    let path_str = op.path.to_string();
    match op.kind {
        SyncOpKind::Skip => bridge::OpResult::ok(path_str, "skip"),

        SyncOpKind::Upload => {
            let parent = match op.path.parent() {
                None => Some(remote_root.clone()),
                Some(p) => dir_uids.get(&p).cloned(),
            };
            let Some(parent) = parent else {
                return bridge::OpResult::err(
                    path_str,
                    "upload",
                    "remote parent directory not available",
                );
            };
            let name = bridge::last_segment(op.path.as_str());
            let local_file = bridge::rel_to_local(local_root, op.path.as_str());
            exec_upload_new(server, &parent, name, &local_file, path_str).await
        }

        SyncOpKind::UploadRevision => {
            let Some(remote) = &op.remote else {
                return bridge::OpResult::err(
                    path_str,
                    "upload_revision",
                    "internal: revision op has no remote ref",
                );
            };
            // Staleness check (invariant 2): re-read the node's active revision
            // and refuse the overwrite if it moved since the plan was computed.
            match current_revision_uid(server, &remote.node_uid).await {
                Ok(current) => {
                    if current.as_deref() != Some(remote.revision_uid.as_str()) {
                        return bridge::OpResult::err(
                            path_str,
                            "upload_revision",
                            format!(
                                "stale: remote active revision is {current:?}, plan expected {} — refusing to overwrite",
                                remote.revision_uid
                            ),
                        );
                    }
                }
                Err(msg) => {
                    return bridge::OpResult::err(
                        path_str,
                        "upload_revision",
                        format!("staleness check: {msg}"),
                    );
                }
            }
            let local_file = bridge::rel_to_local(local_root, op.path.as_str());
            // Thread the plan's revision uid to the server as CurrentRevisionID
            // so its guard rejects the draft if the active revision moved after
            // the plan was computed — closing the window between the staleness
            // re-read above and the draft POST that the re-read alone leaves open.
            match upload_file(
                server,
                UploadTarget::Revision {
                    node: &remote.node_uid,
                },
                &local_file,
                Some(remote.revision_uid.clone()),
            )
            .await
            {
                // Attach the (existing) node uid for the audit trail; the new
                // revision uid would cost an extra fetch, so it is left absent.
                Ok(()) => bridge::OpResult::ok(path_str, "upload_revision")
                    .with_node(&remote.node_uid, None),
                Err(msg) => bridge::OpResult::err(path_str, "upload_revision", msg),
            }
        }

        SyncOpKind::Download => {
            let Some(remote) = &op.remote else {
                return bridge::OpResult::err(
                    path_str,
                    "download",
                    "internal: download op has no remote ref",
                );
            };
            let dest = bridge::rel_to_local(local_root, op.path.as_str());
            // Local staleness guard, symmetric to UploadRevision's remote guard:
            // a Download truncates `dest`, so refuse if the on-disk file no
            // longer matches what the plan decided against (post-plan local
            // edits, or a file that appeared where the plan expected none).
            match &op.local {
                Some(local) => match sha1_hex_of_file(&dest).await {
                    // Unchanged since the plan → safe to overwrite.
                    Ok(cur) if cur == local.content_hash.as_str() => {}
                    Ok(_) => {
                        return bridge::OpResult::err(
                            path_str,
                            "download",
                            "local file changed since the plan was computed — refusing to overwrite (re-plan)",
                        );
                    }
                    // Missing/unreadable now: nothing on disk to lose, proceed.
                    Err(_) => {}
                },
                None => {
                    if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
                        return bridge::OpResult::err(
                            path_str,
                            "download",
                            "a local file appeared at this path since the plan — refusing to overwrite (re-plan)",
                        );
                    }
                }
            }
            match download_file(server, &remote.node_uid, &dest).await {
                Ok(_) => bridge::OpResult::ok(path_str, "download"),
                Err(msg) => bridge::OpResult::err(path_str, "download", msg),
            }
        }

        SyncOpKind::Conflict(_) => bridge::OpResult::err(
            path_str,
            "conflict",
            "unresolved conflict reached apply — supply a decision or it is rejected",
        ),
    }
}

async fn current_revision_uid(
    server: &DriveMcpServer,
    uid: &NodeUid,
) -> Result<Option<String>, String> {
    match server.client().node(uid).await {
        Ok(MaybeNode::Node(n)) => Ok(n.active_revision.map(|r| r.uid)),
        Ok(_) => Ok(None),
        Err(e) => Err(format!("re-fetch node: {e}")),
    }
}

// ===========================================================================
// Transfer helpers
// ===========================================================================

/// Fetch content digests for a set of `(node, active-revision)` pairs.
///
/// Plain passthrough to the SDK's best-effort batch fetch (bounded
/// concurrency, missing entries omitted, never errors).
async fn fetch_digests(
    client: Arc<ProtonDriveClient>,
    pairs: Vec<(NodeUid, String)>,
) -> HashMap<NodeUid, RevisionXAttr> {
    client.fetch_revision_xattrs(&pairs).await
}

enum UploadTarget<'a> {
    New { parent: &'a NodeUid, name: &'a str },
    Revision { node: &'a NodeUid },
}

/// Build upload metadata from a local file: size, mtime, media type, and the
/// locally-computed SHA1 (which the SDK verifies after streaming).
async fn build_upload_meta(local_file: &Path) -> Result<(UploadMetadata, String), String> {
    let md = tokio::fs::metadata(local_file)
        .await
        .map_err(|e| format!("stat {}: {e}", local_file.display()))?;
    if !md.is_file() {
        return Err(format!("{} is not a regular file", local_file.display()));
    }
    let size = md.len();
    if size == 0 {
        return Err(format!(
            "cannot upload empty file {} (the SDK requires size > 0)",
            local_file.display()
        ));
    }
    let modification_time = md.modified().ok();
    let sha1 = sha1_hex_of_file(local_file).await?;
    let meta = UploadMetadata {
        media_type: guess_media_type(local_file),
        expected_size: size,
        expected_sha1_hex: Some(sha1.clone()),
        modification_time,
        additional_metadata_json: None,
        override_existing_draft_by_other_client: false,
        expected_current_revision_id: None,
    };
    Ok((meta, sha1))
}

/// Stream a local file to a new node or a new revision, preserving the SDK error
/// variant so the caller can detect a name collision.
async fn run_upload(
    server: &DriveMcpServer,
    target: UploadTarget<'_>,
    local_file: &Path,
    meta: UploadMetadata,
) -> Result<(), proton_drive::Error> {
    let stream = open_stream(local_file)
        .await
        .map_err(proton_drive::Error::Internal)?;
    let (tx, _rx) = tokio::sync::watch::channel::<u64>(0);
    let uploader = match target {
        UploadTarget::New { parent, name } => {
            server.client().file_uploader(parent, name, meta).await?
        }
        UploadTarget::Revision { node } => server.client().revision_uploader(node, meta).await?,
    };
    uploader.upload_from_stream(stream, tx).await?;
    Ok(())
}

/// Execute a sync `Upload` op (new file) with idempotent re-apply semantics.
///
/// A stored plan may be re-applied after a partial apply (the plan store does
/// not consume plans — domain invariant 4). So a name collision here is not
/// automatically a failure: if the remote file's digest can be fetched and
/// already equals the local file's, the upload happened on a prior run and the
/// op reports success. Any other outcome — different remote content, or a
/// digest that could not be fetched right now — is reported as an error rather
/// than an overwrite; it is fail-safe and self-heals on a fresh sync_plan. It
/// never auto-overwrites, matching the plan/apply safety contract.
async fn exec_upload_new(
    server: &DriveMcpServer,
    parent: &NodeUid,
    name: &str,
    local_file: &Path,
    path_str: String,
) -> bridge::OpResult {
    let (meta, local_sha1) = match build_upload_meta(local_file).await {
        Ok(v) => v,
        Err(msg) => return bridge::OpResult::err(path_str, "upload", msg),
    };
    match run_upload(server, UploadTarget::New { parent, name }, local_file, meta).await {
        Ok(()) => bridge::OpResult::ok(path_str, "upload"),
        Err(proton_drive::Error::NodeWithSameNameExists { .. }) => {
            // Locate the colliding remote file and compare content by digest.
            let existing = match resolve_child(server, parent, name, false).await {
                Ok(Some((uid, Some(rev)))) => Some((uid, rev)),
                Ok(_) => None,
                Err(e) => {
                    return bridge::OpResult::err(
                        path_str,
                        "upload",
                        format!("name collision, and locating the existing file failed: {e}"),
                    );
                }
            };
            let Some((uid, rev)) = existing else {
                return bridge::OpResult::err(
                    path_str,
                    "upload",
                    "name already exists remotely but the existing file could not be located",
                );
            };
            let digests = fetch_digests(server.client_arc(), vec![(uid.clone(), rev)]).await;
            match digests.get(&uid).and_then(|x| x.content_sha1.as_deref()) {
                Some(remote_sha1) if remote_sha1 == local_sha1 => {
                    // Same content already present → this op succeeded on a
                    // prior apply. Idempotent success, not an overwrite.
                    bridge::OpResult::ok(path_str, "upload").with_node(&uid, None)
                }
                _ => bridge::OpResult::err(
                    path_str,
                    "upload",
                    "a different file already exists remotely at this name — refusing to overwrite (re-plan)",
                ),
            }
        }
        Err(e) => bridge::OpResult::err(path_str, "upload", e.to_string()),
    }
}

/// Upload wrapper returning a plain message on failure (for per-op results).
async fn upload_file(
    server: &DriveMcpServer,
    target: UploadTarget<'_>,
    local_file: &Path,
    expected_current_revision_id: Option<String>,
) -> Result<(), String> {
    let (mut meta, _sha1) = build_upload_meta(local_file).await?;
    // Carry the plan's revision token to the server for a revision upload so
    // its optimistic-concurrency guard fires on the plan-time revision, not a
    // fresh read (closes the between-reads race the local staleness check
    // cannot). `None` for a new-file upload.
    meta.expected_current_revision_id = expected_current_revision_id;
    run_upload(server, target, local_file, meta)
        .await
        .map_err(|e| e.to_string())
}

/// Download `uid` to `dest`, creating parent dirs, returning the download stats.
async fn download_file(
    server: &DriveMcpServer,
    uid: &NodeUid,
    dest: &Path,
) -> Result<DownloadStats, String> {
    if let Some(parent) = dest.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    let file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| format!("create {}: {e}", dest.display()))?;
    let downloader = server
        .client()
        .file_downloader(uid)
        .await
        .map_err(|e| format!("file_downloader: {e}"))?;
    downloader
        .download_to_writer(file)
        .await
        .map_err(|e| format!("download: {e}"))
}

async fn open_stream(path: &Path) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, String> {
    let f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    Ok(Box::new(f))
}

/// Stream a file through SHA1 on the blocking pool, returning lower-case hex.
async fn sha1_hex_of_file(path: &Path) -> Result<String, String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<String, String> {
        use sha1::{Digest, Sha1};
        use std::io::Read as _;
        let mut f =
            std::fs::File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
        let mut hasher = Sha1::new();
        let mut buf = vec![0u8; 128 * 1024];
        loop {
            let n = f
                .read(&mut buf)
                .map_err(|e| format!("read {}: {e}", path.display()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(bridge::hex_lower(&hasher.finalize()))
    })
    .await
    .map_err(|e| format!("hash task join: {e}"))?
}

/// Build a [`LocalIndex`] on the blocking pool (the walk + hashing is sync I/O).
async fn build_local_index(
    root: PathBuf,
    cache_file: Option<String>,
) -> Result<LocalIndex, String> {
    tokio::task::spawn_blocking(move || {
        let indexer = Indexer::new(&root);
        match cache_file {
            Some(cf) => indexer.index_with_cache_file(Path::new(&cf)),
            None => indexer.index(&mut HashCache::empty()),
        }
    })
    .await
    .map_err(|e| format!("index task join: {e}"))?
    .map_err(|e| e.to_string())
}

/// Minimal extension → media-type guess; defaults to octet-stream.
fn guess_media_type(path: &Path) -> String {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mt = match ext.as_str() {
        "txt" | "md" | "log" | "csv" => "text/plain",
        "json" => "application/json",
        "html" | "htm" => "text/html",
        "xml" => "application/xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        _ => "application/octet-stream",
    };
    mt.to_owned()
}

// ===========================================================================
// Events collector
// ===========================================================================

/// A [`DriveListener`] that captures each drained event as JSON, for the
/// single-shot `events_poll` drain (no timer, no background subscription).
#[derive(Default)]
struct CollectingListener {
    events: std::sync::Mutex<Vec<Value>>,
}

impl CollectingListener {
    fn take(&self) -> Vec<Value> {
        std::mem::take(
            &mut *self
                .events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

#[async_trait]
impl DriveListener for CollectingListener {
    async fn on_event(&self, event: DriveEvent) {
        let v = event_to_json(&event);
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(v);
    }
}

fn event_to_json(e: &DriveEvent) -> Value {
    match e {
        DriveEvent::Node(n) => json!({
            "type": "node",
            "kind": node_kind_str(n.kind),
            "uid": NodeUidDto::from(&n.uid),
            "parent_uid": n.parent_uid.as_ref().map(NodeUidDto::from),
            "is_shared": n.is_shared,
            "event_id": n.event_id,
        }),
        DriveEvent::TreeRefresh(t) => json!({
            "type": "tree_refresh",
            "root": NodeUidDto::from(&t.root),
            "new_event_id": t.new_event_id,
        }),
        DriveEvent::TreeRemoval(t) => json!({
            "type": "tree_removal",
            "root": NodeUidDto::from(&t.root),
        }),
        DriveEvent::FastForward(f) => json!({
            "type": "fast_forward",
            "new_event_id": f.new_event_id,
        }),
        DriveEvent::SharedWithMeUpdated => json!({ "type": "shared_with_me_updated" }),
    }
}

fn node_kind_str(kind: NodeEventKind) -> &'static str {
    match kind {
        NodeEventKind::Created => "created",
        NodeEventKind::Updated => "updated",
        NodeEventKind::Trashed => "trashed",
        NodeEventKind::Restored => "restored",
        NodeEventKind::Deleted => "deleted",
        NodeEventKind::Renamed => "renamed",
    }
}

// Local alias so the long `rmcp::ErrorData` return type reads cleanly and stays
// consistent with `server.rs`'s `McpError`.
type McpErrorAlias = rmcp::ErrorData;
