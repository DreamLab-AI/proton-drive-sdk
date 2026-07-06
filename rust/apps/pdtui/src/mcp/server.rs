//! The `rmcp` server handler: state, tool catalogue wiring, and the thin
//! `#[tool]` methods that delegate to [`crate::mcp::tools`].
//!
//! The tool *semantics* live in `tools.rs`; this module owns only the MCP
//! surface — the `ToolRouter`, the parameter schemas, and the mapping of each
//! tool's JSON result / `McpError` into an `rmcp` [`CallToolResult`]. Mirrors
//! the `#[tool_router]`/`#[tool_handler]` pattern from the rmcp 2.1 docs
//! (`handler::server::router::tool`).

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerInfo};
use rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use proton_drive::{NodeUid, ProtonDriveClient, ProtonDriveHttpClient};

use crate::mcp::bridge::{NodeUidDto, PlanStore};
use crate::mcp::tools;

// ---------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------

/// Immutable, shared server context. Held behind an `Arc` so cloning the
/// handler (rmcp clones it per request) is cheap.
pub(crate) struct Inner {
    pub(crate) client: Arc<ProtonDriveClient>,
    /// The session-aware transport, kept so `events_poll` can drive the Events
    /// API directly (the client owns no public events-drain entry point).
    pub(crate) http: Arc<dyn ProtonDriveHttpClient>,
    /// My Files root (share-scoped `NodeUid`, per the listing endpoints).
    pub(crate) root_uid: NodeUid,
    /// The true volume id for the My Files volume (resolved once at startup),
    /// used as the default target for `events_poll`.
    pub(crate) volume_id: String,
    /// Directory the remote-snapshot checkpoints are persisted under.
    pub(crate) checkpoint_dir: PathBuf,
    /// Shared per-account transfer-concurrency cap (`ProtonDriveConfig`, default 3).
    pub(crate) max_parallel_transfers: usize,
}

/// MCP handler for the Proton Drive tool surface. `Clone` (via `Arc`s) because
/// rmcp's service loop clones the handler per request context.
#[derive(Clone)]
pub struct DriveMcpServer {
    tool_router: ToolRouter<DriveMcpServer>,
    inner: Arc<Inner>,
    plans: Arc<PlanStore>,
}

impl DriveMcpServer {
    /// Assemble the server from the bootstrapped session/client context.
    pub(crate) fn new(
        client: Arc<ProtonDriveClient>,
        http: Arc<dyn ProtonDriveHttpClient>,
        root_uid: NodeUid,
        volume_id: String,
        checkpoint_dir: PathBuf,
        max_parallel_transfers: usize,
    ) -> Self {
        Self {
            tool_router: Self::tool_router(),
            inner: Arc::new(Inner {
                client,
                http,
                root_uid,
                volume_id,
                checkpoint_dir,
                max_parallel_transfers,
            }),
            plans: Arc::new(PlanStore::new()),
        }
    }

    // ── accessors used by the tool bodies (same crate module tree) ───────────

    pub(crate) fn client(&self) -> &ProtonDriveClient {
        self.inner.client.as_ref()
    }
    /// A cloned client handle, for driving a not-`Send`-provable SDK future on a
    /// blocking thread (see `tools::fetch_digests`).
    pub(crate) fn client_arc(&self) -> Arc<ProtonDriveClient> {
        Arc::clone(&self.inner.client)
    }
    pub(crate) fn http(&self) -> &Arc<dyn ProtonDriveHttpClient> {
        &self.inner.http
    }
    pub(crate) fn root_uid(&self) -> &NodeUid {
        &self.inner.root_uid
    }
    pub(crate) fn volume_id(&self) -> &str {
        &self.inner.volume_id
    }
    pub(crate) fn plans(&self) -> &PlanStore {
        &self.plans
    }
    pub(crate) fn checkpoint_dir(&self) -> &Path {
        &self.inner.checkpoint_dir
    }
    pub(crate) fn max_parallel(&self) -> usize {
        self.inner.max_parallel_transfers.max(1)
    }
}

// ---------------------------------------------------------------------------
// Error + result helpers
// ---------------------------------------------------------------------------

/// Build an internal-error `McpError` with a plain message.
pub(crate) fn mcp_err(message: impl Into<Cow<'static, str>>) -> McpError {
    McpError::internal_error(message, None)
}

/// Build an invalid-params `McpError` (bad path, bad decision, etc.).
pub(crate) fn mcp_bad_params(message: impl Into<Cow<'static, str>>) -> McpError {
    McpError::invalid_params(message, None)
}

/// Map an SDK [`proton_drive::Error`] into an `McpError`, tagged with the
/// operation that produced it.
pub(crate) fn map_sdk_err(context: &str, e: proton_drive::Error) -> McpError {
    match e {
        proton_drive::Error::Validation(_) | proton_drive::Error::NotFound(_) => {
            mcp_bad_params(format!("{context}: {e}"))
        }
        other => mcp_err(format!("{context}: {other}")),
    }
}

/// Wrap a tool's JSON value as a single text content block (pretty-printed so a
/// human reading the transcript can follow it; agents parse it either way).
fn ok_json(value: Value) -> CallToolResult {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    CallToolResult::success(vec![ContentBlock::text(text)])
}

// ---------------------------------------------------------------------------
// Tool parameter schemas
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct DriveListParams {
    /// Logical path from the My Files root, `'/'`-separated and case-sensitive.
    /// `""` or `"/"` is the root itself.
    pub path: String,
    /// When true, additionally fetch + decrypt each file child's content SHA1
    /// (one extra request per file, bounded concurrency). Off by default —
    /// listing is cheap, digests are not.
    #[serde(default)]
    pub include_digest: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct DriveDownloadParams {
    /// The node to download, as returned by `drive_list`.
    pub uid: NodeUidDto,
    /// Local filesystem path to write the verified plaintext to.
    pub local_path: String,
    /// Refuse to clobber an existing file unless this is set.
    #[serde(default)]
    pub overwrite: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct DriveUploadParams {
    /// Local file to upload.
    pub local_path: String,
    /// Logical path of the remote parent folder (`""`/`"/"` = root).
    pub remote_parent_path: String,
    /// Remote name; defaults to the local file's basename.
    #[serde(default)]
    pub name: Option<String>,
    /// If the name already exists remotely: when `false` (default) the upload
    /// fails rather than touch the existing file; when `true` a new revision of
    /// the existing node is uploaded (replacing its active content). Off by
    /// default so a create can never silently overwrite an unrelated file.
    #[serde(default)]
    pub allow_revision_on_conflict: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct DriveMkdirParams {
    /// Logical path of the parent folder (`""`/`"/"` = root).
    pub parent_path: String,
    /// New folder name.
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct LocalIndexParams {
    /// Local directory tree to index.
    pub root: String,
    /// Optional JSON hash-cache file to reuse/refresh (`(size,mtime)->sha1`).
    #[serde(default)]
    pub cache_file: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SyncPlanParams {
    /// Local directory root.
    pub local_root: String,
    /// Logical path of the remote folder to reconcile against (`""`/`"/"` = root).
    pub remote_folder: String,
    /// Optional JSON hash-cache file for the local index.
    #[serde(default)]
    pub cache_file: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SyncApplyParams {
    /// Id of a plan previously returned by `sync_plan`.
    pub plan_id: String,
    /// Per-path conflict decisions: `keep_local` | `keep_remote` | `skip`. A
    /// conflict left undecided causes the whole apply to be rejected, not
    /// silently resolved.
    #[serde(default)]
    pub decisions: HashMap<String, String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct EventsPollParams {
    /// Volume to poll; defaults to the My Files volume.
    #[serde(default)]
    pub volume_id: Option<String>,
    /// Resume cursor from a prior call. Omit to just fetch the current latest
    /// event id as an anchor (no events drained).
    #[serde(default)]
    pub since_event_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Tool catalogue
// ---------------------------------------------------------------------------

#[tool_router]
impl DriveMcpServer {
    #[tool(
        name = "drive_list",
        description = "List a Proton Drive folder's children by logical path from the My Files \
                       root. Returns [{uid, name, kind, size, mtime, sha1?}]. Content SHA1 is \
                       only included when include_digest=true (one extra request per file)."
    )]
    async fn drive_list(
        &self,
        Parameters(p): Parameters<DriveListParams>,
    ) -> Result<CallToolResult, McpError> {
        Ok(ok_json(tools::drive_list(self, p).await?))
    }

    #[tool(
        name = "drive_download",
        description = "Download a file node to a local path, verifying blocks + manifest. \
                       Refuses to overwrite an existing file unless overwrite=true. Returns \
                       {bytes, sha1, signature_verified}."
    )]
    async fn drive_download(
        &self,
        Parameters(p): Parameters<DriveDownloadParams>,
    ) -> Result<CallToolResult, McpError> {
        Ok(ok_json(tools::drive_download(self, p).await?))
    }

    #[tool(
        name = "drive_upload",
        description = "Upload a local file into a remote folder (by logical path). If a file of \
                       that name already exists it uploads a new revision rather than failing. \
                       Returns {uid, revision_uid, sha1, created_revision}."
    )]
    async fn drive_upload(
        &self,
        Parameters(p): Parameters<DriveUploadParams>,
    ) -> Result<CallToolResult, McpError> {
        Ok(ok_json(tools::drive_upload(self, p).await?))
    }

    #[tool(
        name = "drive_mkdir",
        description = "Create a folder under a parent (by logical path). An existing name \
                       surfaces AlreadyExists rather than silently succeeding. Returns {uid}."
    )]
    async fn drive_mkdir(
        &self,
        Parameters(p): Parameters<DriveMkdirParams>,
    ) -> Result<CallToolResult, McpError> {
        Ok(ok_json(tools::drive_mkdir(self, p).await?))
    }

    #[tool(
        name = "local_index",
        description = "Walk a local directory tree and hash every file (reusing a (size,mtime) \
                       cache when given). Returns {root, count, truncated, entries:[{path, sha1, \
                       size, mtime}]} with the echoed entry list capped."
    )]
    async fn local_index(
        &self,
        Parameters(p): Parameters<LocalIndexParams>,
    ) -> Result<CallToolResult, McpError> {
        Ok(ok_json(tools::local_index(self, p).await?))
    }

    #[tool(
        name = "sync_plan",
        description = "Compute a side-effect-free sync plan reconciling a local root against a \
                       remote folder by content SHA1. Stores the plan and persists a remote \
                       snapshot checkpoint. Returns {plan_id, summary, ops, conflicts, \
                       dirs_to_create}. A hash divergence or a missing remote digest is an \
                       undecided conflict, never a silent transfer."
    )]
    async fn sync_plan(
        &self,
        Parameters(p): Parameters<SyncPlanParams>,
    ) -> Result<CallToolResult, McpError> {
        Ok(ok_json(tools::sync_plan(self, p).await?))
    }

    #[tool(
        name = "sync_apply",
        description = "Execute a stored plan after resolving its conflicts with per-path \
                       decisions (keep_local|keep_remote|skip). Creates needed remote dirs \
                       first, then applies each op; an UploadRevision re-checks the remote \
                       revision and fails safe if it moved. One op failing never aborts the \
                       rest. Returns {plan_id, results:[{path, op, result, ...}]}."
    )]
    async fn sync_apply(
        &self,
        Parameters(p): Parameters<SyncApplyParams>,
    ) -> Result<CallToolResult, McpError> {
        Ok(ok_json(tools::sync_apply(self, p).await?))
    }

    #[tool(
        name = "events_poll",
        description = "On-demand poll of the Proton Drive Events API (never a background timer). \
                       With no since_event_id, returns the current latest event id as an anchor. \
                       With one, drains events once and returns {events, next_anchor}."
    )]
    async fn events_poll(
        &self,
        Parameters(p): Parameters<EventsPollParams>,
    ) -> Result<CallToolResult, McpError> {
        Ok(ok_json(tools::events_poll(self, p).await?))
    }
}

// ---------------------------------------------------------------------------
// ServerHandler
// ---------------------------------------------------------------------------

// Point the generated `call_tool`/`list_tools` at our stored router rather than
// rebuilding it per call (the macro default is `Self::tool_router()`).
#[tool_handler(router = self.tool_router.clone())]
impl ServerHandler for DriveMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "pdtui-proton-drive",
                proton_drive::VERSION,
            ))
            .with_instructions(
                "Proton Drive control for agents (personal use, unaudited). Read tools \
                 (drive_list, local_index) are safe; sync_plan is a pure dry-run; sync_apply \
                 executes only the ops in the named plan, never resolving a conflict for you. \
                 Paths are '/'-separated from the My Files root and case-sensitive."
                    .to_owned(),
            )
    }
}
