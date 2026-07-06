//! Transfer aggregate — domain-model-mvp.md §Transfer.
//!
//! Each `Transfer` models a single in-flight file movement (upload or
//! download).  State flows monotonically:
//!
//!   `Pending` → `Running` → `Completed`
//!                         ↘ `CompletedUnverified` (downloads only)
//!                         ↘ `Failed(String)`
//!   (`Cancelled` is accepted from any non-terminal state.)
//!
//! Progress is driven by three watch channels:
//! - `progress_rx`: `u64` bytes_done, sent by the upload/download task.
//! - `total_rx`: `Option<u64>` bytes_total, set once known (uploads set it
//!   immediately after `stat`ing the local file; downloads set it from the
//!   remote revision's XAttr-declared plaintext size — `Common.Size`, *not*
//!   the raw `Revision.Size` on the wire, which is the ciphertext/block size
//!   and does not equal the plaintext length — via
//!   `FileDownloader::claimed_size`, mirroring the C# SDK's `ClaimedSize`
//!   (cs/v0.15.0 "Report extended attributes size for download progress
//!   instead of revision size"). It stays `None` when the XAttr is missing
//!   or undecryptable (legacy revisions, best-effort — see `claimed_size`'s
//!   own doc comment).
//! - `outcome_rx`: `Option<Result<TransferOutcome, String>>` — `None` while
//!   running, `Some(Ok(outcome))` on success, `Some(Err(msg))` on failure.
//!
//! All three channels are polled by `Transfer::poll`, called from
//! `App::tick` every 100 ms so the TUI stays responsive.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::watch;

use proton_drive::{NodeUid, UploadMetadata};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Direction of a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Upload,
    Download,
}

/// Snapshot of bytes transferred.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransferProgress {
    pub bytes_done: u64,
    /// `None` until the file size is known.
    pub bytes_total: Option<u64>,
}

impl TransferProgress {
    /// A value in `0.0..=1.0` suitable for a ratatui `Gauge`.
    pub fn fraction(&self) -> f64 {
        match self.bytes_total {
            Some(total) if total > 0 => (self.bytes_done as f64 / total as f64).min(1.0),
            Some(_) => 1.0,
            None => 0.0,
        }
    }
}

/// State of a transfer.  Terminal states are `Completed`,
/// `CompletedUnverified`, `Cancelled`, and `Failed`.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Pending and Cancelled wired in M7 / cancel action
pub enum TransferState {
    Pending,
    Running,
    Completed,
    /// A download completed and every block's ciphertext hash matched, but
    /// the manifest signature could not be verified against the signer's
    /// known keys (e.g. an address key that has since been rotated out) —
    /// data is intact, authenticity is unconfirmed. Mirrors
    /// `proton_drive_core::download::DownloadStats::signature_verified ==
    /// false`. Never set for uploads (no equivalent check exists there).
    CompletedUnverified,
    Cancelled,
    Failed(String),
}

impl TransferState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TransferState::Completed
                | TransferState::CompletedUnverified
                | TransferState::Cancelled
                | TransferState::Failed(_)
        )
    }
}

/// Outcome carried by the outcome channel on a successful transfer.
/// `signature_verified` is only meaningful for downloads — the manifest
/// authenticity check (`DownloadStats::signature_verified`); uploads set it
/// to `None` since no equivalent check exists on that path.
#[derive(Debug, Clone, Copy)]
pub struct TransferOutcome {
    pub signature_verified: Option<bool>,
}

/// An in-flight (or finished) transfer.
pub struct Transfer {
    /// Human-readable label — usually the file name.
    pub label: String,
    pub direction: TransferDirection,
    /// Target node uid (destination for upload, source for download).
    /// Stored for future status display / retry; not yet read in this MVP.
    #[allow(dead_code)]
    pub node_uid: NodeUid,
    pub state: TransferState,
    pub progress: TransferProgress,
    /// Watch receiver driven by the spawned task (bytes done).
    progress_rx: watch::Receiver<u64>,
    /// Watch receiver for the total size, once known (uploads only; `None`
    /// forever for downloads).
    total_rx: watch::Receiver<Option<u64>>,
    /// Outcome receiver — `None` while running, `Some` when the task ends.
    outcome_rx: watch::Receiver<Option<Result<TransferOutcome, String>>>,
    /// Cancellation token — exposed for future cancel-action binding (M7).
    #[allow(dead_code)]
    cancel: Arc<tokio_util::sync::CancellationToken>,
}

impl Transfer {
    /// Advance the state machine by polling the watch channels.
    /// Called from `App::tick` every ~100 ms.
    ///
    /// Returns `true` when any visible state changed (signals a redraw).
    pub fn poll(&mut self) -> bool {
        if self.state.is_terminal() {
            return false;
        }

        let bytes_now = *self.progress_rx.borrow();
        let bytes_changed = bytes_now != self.progress.bytes_done;
        if bytes_changed {
            self.progress.bytes_done = bytes_now;
            self.state = TransferState::Running;
        }

        let total_now = *self.total_rx.borrow();
        let total_changed = total_now != self.progress.bytes_total;
        if total_changed {
            self.progress.bytes_total = total_now;
        }

        // Check for task completion.
        let outcome = self.outcome_rx.borrow().clone();
        match outcome {
            None => bytes_changed || total_changed,
            Some(Ok(outcome)) => {
                self.state = match outcome.signature_verified {
                    Some(false) => TransferState::CompletedUnverified,
                    _ => TransferState::Completed,
                };
                true
            }
            Some(Err(msg)) => {
                self.state = TransferState::Failed(msg);
                true
            }
        }
    }

    /// Cancel an in-flight transfer.  No-op if already terminal.
    #[allow(dead_code)] // wired to a key action in M7
    pub fn cancel(&mut self) {
        if !self.state.is_terminal() {
            self.cancel.cancel();
            self.state = TransferState::Cancelled;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Spawn helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn an upload transfer.
///
/// Opens `local_path` as a `tokio::fs::File`, constructs a `FileUploader`
/// for `parent_uid` (the current remote folder), and calls
/// `upload_from_stream`.
pub fn spawn_upload(
    client: Arc<proton_drive::ProtonDriveClient>,
    local_path: PathBuf,
    parent_uid: NodeUid,
) -> Transfer {
    let cancel = Arc::new(tokio_util::sync::CancellationToken::new());
    let (progress_tx, progress_rx) = watch::channel::<u64>(0);
    let (total_tx, total_rx) = watch::channel::<Option<u64>>(None);
    let (outcome_tx, outcome_rx) = watch::channel::<Option<Result<TransferOutcome, String>>>(None);

    let file_name = local_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());

    let label = file_name.clone();
    let uid_for_transfer = parent_uid.clone();
    let cancel_clone = cancel.clone();

    tokio::spawn(async move {
        let result = do_upload(
            client,
            local_path,
            parent_uid,
            file_name,
            progress_tx,
            total_tx,
            cancel_clone,
        )
        .await;
        let _ = outcome_tx.send(Some(result));
    });

    Transfer {
        label,
        direction: TransferDirection::Upload,
        node_uid: uid_for_transfer,
        state: TransferState::Running,
        progress: TransferProgress::default(),
        progress_rx,
        total_rx,
        outcome_rx,
        cancel,
    }
}

/// Spawn a download transfer.
///
/// Constructs a `FileDownloader` for `node_uid` and streams decrypted
/// plaintext into a new file at `dest_dir / node_name`.
pub fn spawn_download(
    client: Arc<proton_drive::ProtonDriveClient>,
    node_uid: NodeUid,
    node_name: String,
    dest_dir: PathBuf,
) -> Transfer {
    let cancel = Arc::new(tokio_util::sync::CancellationToken::new());
    let (progress_tx, progress_rx) = watch::channel::<u64>(0);
    // Set from the revision's XAttr-declared plaintext size once
    // `do_download` fetches it (best-effort — see `claimed_size`); stays
    // `None` for legacy revisions with no decryptable XAttr.
    let (total_tx, total_rx) = watch::channel::<Option<u64>>(None);
    let (outcome_tx, outcome_rx) = watch::channel::<Option<Result<TransferOutcome, String>>>(None);

    let label = node_name.clone();
    let uid_for_transfer = node_uid.clone();
    let cancel_clone = cancel.clone();

    tokio::spawn(async move {
        let result = do_download(
            client,
            node_uid,
            node_name,
            dest_dir,
            progress_tx,
            total_tx,
            cancel_clone,
        )
        .await;
        let _ = outcome_tx.send(Some(result));
    });

    Transfer {
        label,
        direction: TransferDirection::Download,
        node_uid: uid_for_transfer,
        state: TransferState::Running,
        progress: TransferProgress::default(),
        progress_rx,
        total_rx,
        outcome_rx,
        cancel,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private task bodies
// ─────────────────────────────────────────────────────────────────────────────

async fn do_upload(
    client: Arc<proton_drive::ProtonDriveClient>,
    local_path: PathBuf,
    parent_uid: NodeUid,
    file_name: String,
    progress_tx: watch::Sender<u64>,
    total_tx: watch::Sender<Option<u64>>,
    cancel: Arc<tokio_util::sync::CancellationToken>,
) -> Result<TransferOutcome, String> {
    if cancel.is_cancelled() {
        return Err("upload cancelled before start".into());
    }

    let metadata = tokio::fs::metadata(&local_path)
        .await
        .map_err(|e| format!("stat {}: {e}", local_path.display()))?;

    let file_size = metadata.len();
    if file_size == 0 {
        return Err("upload: file is empty (server requires expected_size > 0)".into());
    }

    // The gauge needs a known total to render a fraction/percentage instead
    // of staying inert for the whole transfer — set it as soon as it's known,
    // well before the byte-count updates start arriving from the uploader.
    let _ = total_tx.send(Some(file_size));

    let media_type = media_type_from_path(&local_path);
    let modification_time = metadata.modified().ok();

    let upload_meta = UploadMetadata {
        media_type,
        expected_size: file_size,
        expected_sha1_hex: None,
        modification_time,
        additional_metadata_json: None,
        override_existing_draft_by_other_client: false,
        expected_current_revision_id: None,
    };

    let uploader = client
        .file_uploader(&parent_uid, &file_name, upload_meta)
        .await
        .map_err(|e| format!("file_uploader: {e}"))?;

    let file = tokio::fs::File::open(&local_path)
        .await
        .map_err(|e| format!("open {}: {e}", local_path.display()))?;

    let stream: Box<dyn tokio::io::AsyncRead + Send + Unpin> = Box::new(file);

    if cancel.is_cancelled() {
        return Err("upload cancelled".into());
    }

    let _controller = uploader
        .upload_from_stream(stream, progress_tx)
        .await
        .map_err(|e| format!("upload_from_stream: {e}"))?;

    Ok(TransferOutcome {
        signature_verified: None,
    })
}

async fn do_download(
    client: Arc<proton_drive::ProtonDriveClient>,
    node_uid: NodeUid,
    node_name: String,
    dest_dir: PathBuf,
    progress_tx: watch::Sender<u64>,
    total_tx: watch::Sender<Option<u64>>,
    cancel: Arc<tokio_util::sync::CancellationToken>,
) -> Result<TransferOutcome, String> {
    if cancel.is_cancelled() {
        return Err("download cancelled before start".into());
    }

    let downloader = client
        .file_downloader(&node_uid)
        .await
        .map_err(|e| format!("file_downloader: {e}"))?;

    // Best-effort progress total, sourced from the revision's XAttr-declared
    // plaintext size (`Common.Size`), *not* the raw `Revision.Size` on the
    // wire (ciphertext/block size — mirrors the C# SDK's `ClaimedSize`,
    // cs/v0.15.0). A fetch/decrypt failure here (legacy revision with no
    // XAttr, transient error, ...) only means the gauge stays indeterminate;
    // it must never fail the download itself.
    match downloader.claimed_size().await {
        Ok(size) => {
            let _ = total_tx.send(size);
        }
        Err(e) => {
            tracing::debug!("claimed_size: {e} — progress total stays unknown");
        }
    }

    // `node_name` is the decrypted remote node name — plaintext chosen by
    // whoever created/shared the node, never trustworthy as a raw path
    // component (CWE-22). Sanitize before joining onto the local destination
    // directory so a malicious/crafted name can never escape `dest_dir` or
    // resolve to an absolute path.
    let safe_name = sanitize_download_name(&node_name);
    let dest_path = dest_dir.join(&safe_name);

    let _ = progress_tx.send(0);

    if cancel.is_cancelled() {
        return Err("download cancelled".into());
    }

    // `download_to_path` owns the destination file's lifecycle: it
    // creates/truncates `dest_path`, and removes it again on any failure so a
    // partial/failed download never leaves a truncated same-named file behind
    // (B6).
    let stats = downloader
        .download_to_path(&dest_path)
        .await
        .map_err(|e| format!("download_to_path: {e}"))?;

    let _ = progress_tx.send(stats.bytes);

    Ok(TransferOutcome {
        signature_verified: Some(stats.signature_verified),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Sanitize a decrypted remote node name before it is joined onto a local
/// destination directory (CWE-22 path-traversal / absolute-path-escape
/// hardening). Node names are plaintext chosen by whoever created or shared
/// the node — including, in principle, a malicious share — and must never be
/// trusted as a raw path component.
///
/// - Strips path-separator characters (`/` and `\`, the latter covers
///   Windows-style names too) so the result can never introduce additional
///   path segments — `dest_dir.join(&sanitized)` always yields exactly one
///   more component under `dest_dir`, never more, never fewer.
/// - Strips control characters (`0x00`-`0x1F`, `0x7F`), meaningless in
///   filenames and liable to confuse terminals/filesystems.
/// - After stripping, rejects the result being exactly `.` or `..` (the only
///   component values a filesystem treats specially even without
///   separators) by substituting a fixed placeholder — a name that merely
///   *contains* dots (including a leading dot: dotfiles like `.gitignore`
///   are legitimate and left untouched) is just an ordinary filename once
///   separators are gone, so it is never rewritten.
/// - Falls back to the same placeholder if stripping leaves nothing at all.
///
/// The output is always a single, safe path *component*: joining it onto
/// `dest_dir` can never escape `dest_dir` and can never become an absolute
/// path, regardless of what the original decrypted name contained.
fn sanitize_download_name(name: &str) -> String {
    const PLACEHOLDER: &str = "_unnamed_download";

    let stripped: String = name
        .chars()
        .filter(|c| *c != '/' && *c != '\\' && !c.is_control())
        .collect();

    match stripped.as_str() {
        "" | "." | ".." => PLACEHOLDER.to_owned(),
        _ => stripped,
    }
}

fn media_type_from_path(path: &std::path::Path) -> String {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "txt" | "md" | "rs" | "toml" | "json" | "yaml" | "yml" | "csv" | "log" => {
            "text/plain".into()
        }
        "html" | "htm" => "text/html".into(),
        "css" => "text/css".into(),
        "js" | "mjs" => "text/javascript".into(),
        "png" => "image/png".into(),
        "jpg" | "jpeg" => "image/jpeg".into(),
        "gif" => "image/gif".into(),
        "svg" => "image/svg+xml".into(),
        "pdf" => "application/pdf".into(),
        "zip" => "application/zip".into(),
        _ => "application/octet-stream".into(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A `Transfer` plus the sender halves of its progress/total/outcome
    /// channels, kept alive by tests so the receivers inside the `Transfer`
    /// stay open.
    type TransferHarness = (
        Transfer,
        watch::Sender<u64>,
        watch::Sender<Option<u64>>,
        watch::Sender<Option<Result<TransferOutcome, String>>>,
    );

    fn make_transfer(direction: TransferDirection, state: TransferState) -> TransferHarness {
        let (progress_tx, progress_rx) = watch::channel::<u64>(0);
        let (total_tx, total_rx) = watch::channel::<Option<u64>>(None);
        let (outcome_tx, outcome_rx) =
            watch::channel::<Option<Result<TransferOutcome, String>>>(None);
        let cancel = Arc::new(tokio_util::sync::CancellationToken::new());
        let t = Transfer {
            label: "test".into(),
            direction,
            node_uid: NodeUid {
                volume_id: "v".into(),
                node_id: "n".into(),
            },
            state,
            progress: TransferProgress::default(),
            progress_rx,
            total_rx,
            outcome_rx,
            cancel,
        };
        (t, progress_tx, total_tx, outcome_tx)
    }

    // ── TransferProgress ─────────────────────────────────────────────────────

    #[test]
    fn fraction_no_total_is_zero() {
        let p = TransferProgress {
            bytes_done: 500,
            bytes_total: None,
        };
        assert_eq!(p.fraction(), 0.0);
    }

    #[test]
    fn fraction_zero_total_is_one() {
        let p = TransferProgress {
            bytes_done: 0,
            bytes_total: Some(0),
        };
        assert_eq!(p.fraction(), 1.0);
    }

    #[test]
    fn fraction_half() {
        let p = TransferProgress {
            bytes_done: 50,
            bytes_total: Some(100),
        };
        assert!((p.fraction() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn fraction_caps_at_one() {
        let p = TransferProgress {
            bytes_done: 200,
            bytes_total: Some(100),
        };
        assert_eq!(p.fraction(), 1.0);
    }

    // ── TransferState ─────────────────────────────────────────────────────────

    #[test]
    fn terminal_states_are_terminal() {
        assert!(TransferState::Completed.is_terminal());
        assert!(TransferState::CompletedUnverified.is_terminal());
        assert!(TransferState::Cancelled.is_terminal());
        assert!(TransferState::Failed("oops".into()).is_terminal());
    }

    #[test]
    fn non_terminal_states_are_not_terminal() {
        assert!(!TransferState::Pending.is_terminal());
        assert!(!TransferState::Running.is_terminal());
    }

    // ── Transfer::cancel ─────────────────────────────────────────────────────

    #[test]
    fn cancel_sets_cancelled_state() {
        let (mut t, _, _, _) = make_transfer(TransferDirection::Upload, TransferState::Running);
        let token = t.cancel.clone();
        t.cancel();
        assert!(matches!(t.state, TransferState::Cancelled));
        assert!(token.is_cancelled());
    }

    #[test]
    fn cancel_on_completed_is_noop() {
        let (mut t, _, _, _) = make_transfer(TransferDirection::Download, TransferState::Completed);
        let token = t.cancel.clone();
        t.cancel();
        assert!(matches!(t.state, TransferState::Completed));
        assert!(!token.is_cancelled());
    }

    // ── Transfer::poll ────────────────────────────────────────────────────────

    #[test]
    fn poll_terminal_returns_false() {
        let (mut t, _, _, _) = make_transfer(TransferDirection::Upload, TransferState::Completed);
        assert!(!t.poll());
    }

    #[test]
    fn poll_progress_update_returns_true() {
        let (mut t, progress_tx, _, _) =
            make_transfer(TransferDirection::Upload, TransferState::Running);
        progress_tx.send(1024).unwrap();
        let changed = t.poll();
        assert!(changed);
        assert_eq!(t.progress.bytes_done, 1024);
    }

    #[test]
    fn poll_no_change_returns_false() {
        let (mut t, _progress_tx, _total_tx, _outcome_tx) =
            make_transfer(TransferDirection::Upload, TransferState::Running);
        // bytes_done starts at 0 and the channel also sends 0 — no change.
        let changed = t.poll();
        assert!(!changed);
    }

    #[test]
    fn poll_total_update_returns_true_and_sets_bytes_total() {
        let (mut t, _, total_tx, _) =
            make_transfer(TransferDirection::Upload, TransferState::Running);
        total_tx.send(Some(4096)).unwrap();
        let changed = t.poll();
        assert!(changed, "a newly-known total must trigger a redraw");
        assert_eq!(t.progress.bytes_total, Some(4096));
    }

    #[test]
    fn poll_success_outcome_transitions_completed() {
        let (mut t, _, _, outcome_tx) =
            make_transfer(TransferDirection::Upload, TransferState::Running);
        outcome_tx
            .send(Some(Ok(TransferOutcome {
                signature_verified: None,
            })))
            .unwrap();
        t.poll();
        assert!(matches!(t.state, TransferState::Completed));
    }

    #[test]
    fn poll_verified_download_outcome_transitions_completed() {
        let (mut t, _, _, outcome_tx) =
            make_transfer(TransferDirection::Download, TransferState::Running);
        outcome_tx
            .send(Some(Ok(TransferOutcome {
                signature_verified: Some(true),
            })))
            .unwrap();
        t.poll();
        assert!(matches!(t.state, TransferState::Completed));
    }

    #[test]
    fn poll_unverified_download_outcome_transitions_completed_unverified() {
        let (mut t, _, _, outcome_tx) =
            make_transfer(TransferDirection::Download, TransferState::Running);
        outcome_tx
            .send(Some(Ok(TransferOutcome {
                signature_verified: Some(false),
            })))
            .unwrap();
        t.poll();
        assert!(
            matches!(t.state, TransferState::CompletedUnverified),
            "got: {:?}",
            t.state
        );
    }

    #[test]
    fn poll_error_outcome_captures_message() {
        let (mut t, _, _, outcome_tx) =
            make_transfer(TransferDirection::Download, TransferState::Running);
        outcome_tx
            .send(Some(Err("something went wrong".into())))
            .unwrap();
        t.poll();
        assert!(
            matches!(&t.state, TransferState::Failed(msg) if msg.contains("something went wrong")),
            "got: {:?}",
            t.state
        );
    }

    // ── media_type_from_path ─────────────────────────────────────────────────

    #[test]
    fn media_type_txt() {
        let p = std::path::Path::new("notes.txt");
        assert_eq!(media_type_from_path(p), "text/plain");
    }

    #[test]
    fn media_type_png() {
        let p = std::path::Path::new("logo.PNG"); // uppercase extension
        assert_eq!(media_type_from_path(p), "image/png");
    }

    #[test]
    fn media_type_unknown() {
        let p = std::path::Path::new("binary.bin");
        assert_eq!(media_type_from_path(p), "application/octet-stream");
    }

    #[test]
    fn media_type_no_extension() {
        let p = std::path::Path::new("Makefile");
        assert_eq!(media_type_from_path(p), "application/octet-stream");
    }

    // ── sanitize_download_name ───────────────────────────────────────────────

    #[test]
    fn sanitize_benign_name_is_unchanged() {
        assert_eq!(sanitize_download_name("photo.jpg"), "photo.jpg");
    }

    #[test]
    fn sanitize_leading_dot_is_allowed() {
        // Dotfiles are legitimate names — only the bare "." and ".." tokens
        // are special-cased.
        assert_eq!(sanitize_download_name(".hidden-file"), ".hidden-file");
    }

    #[test]
    fn sanitize_strips_path_separators_and_cannot_traverse() {
        let dest_dir = std::path::PathBuf::from("/tmp/downloads");
        let sanitized = sanitize_download_name("../../etc/passwd");

        assert!(
            !sanitized.contains('/') && !sanitized.contains('\\'),
            "sanitized name must contain no path separators: {sanitized:?}"
        );
        let joined = dest_dir.join(&sanitized);
        assert_eq!(
            joined.parent(),
            Some(dest_dir.as_path()),
            "joined path must live directly inside dest_dir, never escape it"
        );
    }

    #[test]
    fn sanitize_rejects_absolute_path() {
        let dest_dir = std::path::PathBuf::from("/tmp/downloads");
        let sanitized = sanitize_download_name("/etc/passwd");

        assert!(
            !std::path::Path::new(&sanitized).is_absolute(),
            "sanitized name must not be absolute: {sanitized:?}"
        );
        let joined = dest_dir.join(&sanitized);
        assert_eq!(joined.parent(), Some(dest_dir.as_path()));
    }

    #[test]
    fn sanitize_rejects_bare_parent_component() {
        let sanitized = sanitize_download_name("..");
        assert_ne!(sanitized, "..");
        assert_ne!(sanitized, ".");
        assert!(!sanitized.is_empty());
    }

    #[test]
    fn sanitize_rejects_bare_current_component() {
        let sanitized = sanitize_download_name(".");
        assert_ne!(sanitized, ".");
        assert!(!sanitized.is_empty());
    }

    #[test]
    fn sanitize_empty_name_falls_back_to_placeholder() {
        // A name that is nothing but separators strips down to empty.
        let sanitized = sanitize_download_name("///");
        assert!(!sanitized.is_empty());
        assert!(!sanitized.contains('/'));
    }

    #[test]
    fn sanitize_strips_control_characters() {
        let sanitized = sanitize_download_name("bad\u{0000}name\u{0007}.txt");
        assert_eq!(sanitized, "badname.txt");
    }
}
