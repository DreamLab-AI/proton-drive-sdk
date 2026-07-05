//! Session lifecycle and token refresh (ADR-0010).
//!
//! # Overview
//!
//! [`SessionManager`] owns the `(uid, access_token, refresh_token,
//! key_password, expiry)` tuple behind a `tokio::sync::RwLock`. HTTP requests
//! read a snapshot atomically (many readers, one writer). A background
//! `tokio::task` refreshes proactively at `expires_at - 60 s`. HTTP 401
//! responses trigger a single forced refresh followed by one retry (see
//! `http.rs`).
//!
//! # Persistence
//!
//! | Secret | Storage |
//! |---|---|
//! | `refresh_token` + `key_password` | OS keyring when a native backend is compiled in and reachable (kernel keyutils session keyring on Linux, Keychain on macOS, Credential Manager on Windows), **falling back to a 0600 `session.secret.json` file** whenever the keyring write/read fails (no session keyring, headless host, keyring feature not compiled) |
//! | `access_token` + `expires_at` | `session.json` (mode 0600) |
//!
//! The keyring write is always best-effort: the 0600 secret file is written
//! unconditionally on every login/refresh and is the store `from_keyring`
//! falls back to reading from, so it is the persistence path actually
//! exercised whenever no native backend is reachable — not merely a rare
//! contingency (ADR-0007, personal use only).
//!
//! On logout (or a confirmed-dead refresh, see [`SessionManagerError::SessionExpired`]):
//! keyring entry deleted (best-effort), `session.secret.json` deleted,
//! `session.json` truncated.
//!
//! # Backward compatibility
//!
//! The original [`Session`] struct is retained for `probe.rs` and `app.rs`
//! which use it as a lightweight bearer-token container.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex as StdMutex, PoisonError, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::FutureExt as _;
use futures::future::{BoxFuture, Shared};
use proton_drive::{
    ProtonDriveHttpClient,
    http::{HttpMethod, JsonRequest},
};
use proton_drive_api::{
    auth::{RefreshRequest, RefreshResponse},
    common::{self, ResponseEnvelope},
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ---------------------------------------------------------------------------
// Public error type
// ---------------------------------------------------------------------------

/// Errors produced by [`SessionManager`] operations.
#[derive(Debug, thiserror::Error)]
pub enum SessionManagerError {
    /// The access token could not be refreshed (server returned 401 or 422).
    /// The caller should prompt the user to log in again.
    #[error("session expired - please log in again")]
    SessionExpired,

    #[error("keyring: {0}")]
    Keyring(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("http: {0}")]
    Http(proton_drive::Error),

    #[error("no session stored in keyring for uid {0}")]
    NoKeyring(String),

    /// Surfaced to a caller that coalesced onto another in-flight
    /// `force_refresh` (see [`SessionManager::force_refresh`]) whose refresh
    /// failed for a reason other than [`SessionManagerError::SessionExpired`].
    #[error("refresh failed: {0}")]
    Refresh(String),
}

// ---------------------------------------------------------------------------
// Legacy Session struct (backward compat for probe.rs / app.rs)
// ---------------------------------------------------------------------------

/// Minimal session loaded from `$XDG_CONFIG_HOME/pdtui/session.json`.
///
/// Used by the `probe` subcommand and the pre-MG manual-bearer path.
/// New code should use [`SessionManager`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    #[serde(rename = "AccessToken")]
    pub access_token: String,
    #[serde(rename = "UID")]
    pub uid: String,
    #[serde(default = "default_app_version")]
    pub app_version: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
}

fn default_app_version() -> String {
    format!("external-drive-pdtui@{}-stable", env!("CARGO_PKG_VERSION"))
}

fn default_base_url() -> String {
    "https://drive.proton.me/api".to_owned()
}

/// Errors from the legacy [`Session::load`] path.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("no session file at {0}")]
    NotFound(PathBuf),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] serde_json::Error),
}

// Per-thread temp directory that session persistence is redirected to under
// `cfg(test)`, so unit tests never touch the developer's real session files
// *and* never race each other over the same file.
//
// This is `thread_local!`, not a single process-wide static: `cargo test`'s
// default harness runs many test functions truly concurrently on different
// OS threads (each `#[tokio::test]`'s `current_thread` runtime executes
// entirely on the one worker thread libtest assigned it), and both
// `session::tests` (this module) and `http::tests` (a different module in
// the same crate, out of this work package's remit to modify) drive
// `do_refresh`, which reads/writes/deletes these files. A single shared path
// was previously keyed only by process ID — every concurrently-running test
// thread in the process shared the exact same `session.json` /
// `session.secret.json`, so one test's `delete_secret_file`/
// `truncate_session_file`/`create_dir_all`+`write` sequence could race
// another's and intermittently fail with a spurious I/O error (observed:
// `session_aware_401_once_then_200` failing with "No such file or directory"
// under concurrent test execution). Keying by thread ID as well gives every
// concurrently-running test its own directory. The random suffix
// additionally guards against PID reuse colliding with an unrelated
// concurrent process sharing the same `$TMPDIR` (this environment runs
// multiple worktree checkouts against a shared temp directory).
#[cfg(test)]
thread_local! {
    static TEST_CONFIG_DIR: PathBuf = {
        use rand::Rng as _;
        let nonce: u64 = rand::thread_rng().r#gen();
        let dir = std::env::temp_dir().join(format!(
            "pdtui-test-{}-{:?}-{nonce:x}",
            std::process::id(),
            std::thread::current().id(),
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir
    };
}

impl Session {
    pub fn config_path() -> PathBuf {
        // In test builds, redirect all session persistence to a per-thread
        // temp directory. Unit tests exercise `do_refresh`/`from_login`, which
        // write the session + secret files; without this redirect they would
        // clobber the developer's real `~/.config/pdtui/` session (and race
        // each other — see `TEST_CONFIG_DIR` docs).
        #[cfg(test)]
        {
            TEST_CONFIG_DIR.with(|dir| dir.join("session.json"))
        }
        #[cfg(not(test))]
        {
            let base = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    let home = std::env::var_os("HOME").unwrap_or_default();
                    PathBuf::from(home).join(".config")
                });
            base.join("pdtui").join("session.json")
        }
    }

    /// Path to the 0600 secret-fallback file holding `refresh_token` +
    /// `key_password`. Written unconditionally on every login/refresh and
    /// read whenever the OS keyring has no entry — this is the persistence
    /// path that actually runs on any host with no reachable native
    /// keyutils/Keychain/Credential-Manager backend (headless containers
    /// with no session keyring, or a build with no keyring platform feature
    /// enabled). Personal-use only (ADR-0007).
    pub fn secret_path() -> PathBuf {
        let mut p = Self::config_path();
        p.set_file_name("session.secret.json");
        p
    }

    pub fn load() -> Result<Self, SessionError> {
        let path = Self::config_path();
        if !path.exists() {
            return Err(SessionError::NotFound(path));
        }
        let bytes = std::fs::read(&path)?;
        let s = serde_json::from_slice::<Session>(&bytes)?;
        Ok(s)
    }

    pub fn auth_headers(&self) -> Vec<(String, String)> {
        vec![
            (
                "Authorization".to_owned(),
                format!("Bearer {}", self.access_token),
            ),
            ("x-pm-uid".to_owned(), self.uid.clone()),
        ]
    }
}

// ---------------------------------------------------------------------------
// Persistent session JSON (access_token + expiry, mode 0600)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct SessionFile {
    #[serde(rename = "UID")]
    uid: String,
    #[serde(rename = "AccessToken")]
    access_token: String,
    /// Unix timestamp (seconds) when the access token expires.
    ///
    /// `#[serde(default)]` (-> `0`, i.e. already-expired) so a minimal,
    /// hand-authored `session.json` — such as the one
    /// `scripts/configure-session.sh` writes for the 2FA/`pdtui probe`
    /// workaround, which only ever contains `AccessToken` + `UID` — still
    /// deserializes instead of hard-failing with "missing field ExpiresAt".
    /// Treating the missing field as already-expired is the safe default: it
    /// makes `SessionManager::from_keyring` attempt an immediate refresh
    /// rather than silently trusting an unknown expiry. See
    /// `session_file_tolerates_missing_expires_at` below for the exact
    /// script-output shape this must accept.
    #[serde(rename = "ExpiresAt", default)]
    expires_at_unix: u64,
    #[serde(default = "default_app_version")]
    app_version: String,
    #[serde(default = "default_base_url")]
    base_url: String,
}

// ---------------------------------------------------------------------------
// Keyring helpers
// ---------------------------------------------------------------------------

const KEYRING_SERVICE: &str = "pdtui-proton-drive";

#[derive(Serialize, Deserialize)]
struct KeyringPayload {
    uid: String,
    refresh_token: String,
    key_password: String,
}

fn keyring_entry(uid: &str) -> Result<keyring::Entry, SessionManagerError> {
    keyring::Entry::new(KEYRING_SERVICE, uid)
        .map_err(|e| SessionManagerError::Keyring(e.to_string()))
}

pub(crate) fn save_keyring(
    uid: &str,
    refresh_token: &str,
    key_password: &str,
) -> Result<(), SessionManagerError> {
    // Serialize the same `KeyringPayload` struct that `load_keyring` parses, so
    // the write and read schemas cannot drift (the prior bug: a second writer
    // persisted `{uid, refresh_token}` with no `key_password`, which
    // `load_keyring` then failed to resume).
    let payload = KeyringPayload {
        uid: uid.to_owned(),
        refresh_token: refresh_token.to_owned(),
        key_password: key_password.to_owned(),
    };
    let json = serde_json::to_string(&payload)?;
    keyring_entry(uid)?
        .set_password(&json)
        .map_err(|e| SessionManagerError::Keyring(e.to_string()))
}

pub(crate) fn delete_keyring(uid: &str) -> Result<(), SessionManagerError> {
    match keyring_entry(uid)?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(SessionManagerError::Keyring(e.to_string())),
    }
}

fn load_keyring(uid: &str) -> Result<KeyringPayload, SessionManagerError> {
    let raw = keyring_entry(uid)?.get_password().map_err(|e| match e {
        keyring::Error::NoEntry => SessionManagerError::NoKeyring(uid.to_owned()),
        other => SessionManagerError::Keyring(other.to_string()),
    })?;
    serde_json::from_str(&raw).map_err(SessionManagerError::Json)
}

// ---------------------------------------------------------------------------
// Secret-file fallback (0600) — for environments with no usable OS secret
// store. The same `KeyringPayload` schema is reused so the two stores cannot
// drift. ADR-0007: personal use only.
// ---------------------------------------------------------------------------

pub(crate) fn save_secret_file(
    uid: &str,
    refresh_token: &str,
    key_password: &str,
) -> Result<(), SessionManagerError> {
    let payload = KeyringPayload {
        uid: uid.to_owned(),
        refresh_token: refresh_token.to_owned(),
        key_password: key_password.to_owned(),
    };
    let json = serde_json::to_string(&payload)?;
    let path = Session::secret_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, json.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn load_secret_file(uid: &str) -> Result<KeyringPayload, SessionManagerError> {
    let path = Session::secret_path();
    if !path.exists() {
        return Err(SessionManagerError::NoKeyring(uid.to_owned()));
    }
    let raw = std::fs::read(&path)?;
    let payload: KeyringPayload = serde_json::from_slice(&raw)?;
    if payload.uid != uid {
        return Err(SessionManagerError::NoKeyring(uid.to_owned()));
    }
    Ok(payload)
}

pub(crate) fn delete_secret_file() -> Result<(), SessionManagerError> {
    let path = Session::secret_path();
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(SessionManagerError::Io(e)),
    }
}

// ---------------------------------------------------------------------------
// session.json helpers
// ---------------------------------------------------------------------------

pub(crate) fn write_session_file(
    uid: &str,
    access_token: &str,
    expires_at: Instant,
) -> Result<(), SessionManagerError> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let secs_remaining = expires_at
        .saturating_duration_since(Instant::now())
        .as_secs();
    let expires_at_unix = now_unix.saturating_add(secs_remaining);

    let sf = SessionFile {
        uid: uid.to_owned(),
        access_token: access_token.to_owned(),
        expires_at_unix,
        app_version: default_app_version(),
        base_url: default_base_url(),
    };
    let json = serde_json::to_string_pretty(&sf)?;
    let path = Session::config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, json.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn truncate_session_file() -> Result<(), SessionManagerError> {
    let path = Session::config_path();
    if path.exists() {
        std::fs::write(&path, b"")?;
    }
    Ok(())
}

fn load_session_file() -> Result<SessionFile, SessionManagerError> {
    let path = Session::config_path();
    let bytes = std::fs::read(&path)?;
    serde_json::from_slice(&bytes).map_err(SessionManagerError::Json)
}

// ---------------------------------------------------------------------------
// Server-supplied ExpiresIn (optional, deprecated-but-present on the wire)
// ---------------------------------------------------------------------------

/// Minimal local view of a `/core/v4/auth` or `/core/v4/auth/refresh` JSON
/// body used solely to sniff the optional `ExpiresIn` (seconds) field.
/// `proton_drive_api::auth::{AuthResponse, RefreshResponse}` do not carry it,
/// so rather than extending those shared DTOs (outside this work package's
/// `rust/apps/pdtui`-only remit) it is parsed directly from the raw body
/// here. Unknown/extra top-level keys are ignored by serde by default.
#[derive(Deserialize)]
struct ExpiresInHint {
    #[serde(rename = "ExpiresIn", default)]
    expires_in: Option<u64>,
}

/// Extract a positive `ExpiresIn` (seconds) from a raw JSON response body, if
/// present. Returns `None` on parse failure, a missing field, or a
/// non-positive value (treated the same as absent).
pub(crate) fn extract_expires_in_secs(body: &[u8]) -> Option<u64> {
    serde_json::from_slice::<ExpiresInHint>(body)
        .ok()
        .and_then(|hint| hint.expires_in)
        .filter(|secs| *secs > 0)
}

// ---------------------------------------------------------------------------
// SessionState
// ---------------------------------------------------------------------------

/// Secret state for one authenticated session.
///
/// All secret fields use `Zeroizing<String>`; `ZeroizeOnDrop` wipes heap
/// storage on drop (ADR-0011).
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SessionState {
    pub(crate) uid: String,
    pub(crate) access_token: Zeroizing<String>,
    pub(crate) refresh_token: Zeroizing<String>,
    pub(crate) key_password: Zeroizing<String>,
    // Instant holds no secret material.
    #[zeroize(skip)]
    pub(crate) expires_at: Instant,
}

// ---------------------------------------------------------------------------
// Refresh (shared by proactive + reactive paths)
// ---------------------------------------------------------------------------

/// Issue `POST /core/v4/auth/refresh` and atomically replace session state.
///
/// Returns [`SessionManagerError::SessionExpired`] on 401 or 422, scrubbing
/// all three persistence layers (keyring entry, 0600 secret file,
/// `session.json`) so the caller can detect the need to re-login and a
/// confirmed-dead session cannot be silently resumed by a later
/// `from_keyring()` call (mirrors [`SessionManager::logout`]).
///
/// `pub(crate)` so `http.rs` tests can drive it directly.
pub(crate) async fn do_refresh(
    state: &mut SessionState,
    http: &dyn ProtonDriveHttpClient,
) -> Result<(), SessionManagerError> {
    let body = serde_json::to_vec(&RefreshRequest {
        response_type: "token".to_owned(),
        grant_type: "refresh_token".to_owned(),
        refresh_token: state.refresh_token.as_str().to_owned(),
        redirect_uri: "https://protonmail.com".to_owned(),
    })?;

    let req = JsonRequest {
        method: HttpMethod::Post,
        path: "/core/v4/auth/refresh".to_owned(),
        query: vec![],
        headers: vec![("x-pm-uid".to_owned(), state.uid.clone())],
        body: Some(body),
    };

    let resp = http
        .request_json(req)
        .await
        .map_err(SessionManagerError::Http)?;

    if resp.status == 401 || resp.status == 422 {
        warn!(status = resp.status, "refresh rejected - session expired");
        // Scrub every persistence layer, not just the (best-effort) keyring
        // entry: the 0600 secret file and session.json are what actually
        // survive process exit (see module docs), so leaving them untouched
        // would let a later `from_keyring()` call resume with tokens the
        // server has already rejected.
        let _ = delete_keyring(&state.uid); // best-effort
        if let Err(e) = delete_secret_file() {
            warn!("failed to delete secret file after session expiry: {e}");
        }
        if let Err(e) = truncate_session_file() {
            warn!("failed to truncate session.json after session expiry: {e}");
        }
        return Err(SessionManagerError::SessionExpired);
    }

    let env: ResponseEnvelope<RefreshResponse> =
        serde_json::from_slice(&resp.body).map_err(SessionManagerError::Json)?;

    if env.code != common::CODE_OK {
        return Err(SessionManagerError::Http(proton_drive::Error::Internal(
            format!(
                "refresh endpoint returned code {}: {}",
                env.code,
                env.error.unwrap_or_default()
            ),
        )));
    }

    let new_token = env.inner;
    // Honour the server-supplied `ExpiresIn` (seconds) when present.
    // reference/client/js/src/internal/apiService/coreTypes.ts documents
    // `ExpiresIn?: number` (deprecated but present, e.g. on the
    // `/core/v4/auth/refresh` 200 response) — `proton-drive-api`'s
    // `RefreshResponse` DTO doesn't carry it (outside this work package's
    // remit to extend), so it's sniffed directly from the raw body here.
    // Fall back to the previous conservative 30-minute guess only when the
    // field is absent or non-positive.
    let expires_in_secs = extract_expires_in_secs(&resp.body).unwrap_or(30 * 60);
    let expires_at = Instant::now() + Duration::from_secs(expires_in_secs);

    // Persist before updating in-memory state. Keyring is best-effort (it may
    // be an in-memory backend on headless hosts); the 0600 secret file is the
    // authoritative fallback and must stay in sync with the rotated token.
    if let Err(e) = save_keyring(
        &state.uid,
        &new_token.refresh_token,
        state.key_password.as_str(),
    ) {
        warn!("keyring update on refresh failed ({e}); updating secret-file fallback");
    }
    save_secret_file(
        &state.uid,
        &new_token.refresh_token,
        state.key_password.as_str(),
    )?;
    write_session_file(&state.uid, &new_token.access_token, expires_at)?;

    *state.access_token = new_token.access_token;
    *state.refresh_token = new_token.refresh_token;
    state.expires_at = expires_at;

    debug!("token refresh succeeded");
    Ok(())
}

// ---------------------------------------------------------------------------
// Proactive background refresh loop
// ---------------------------------------------------------------------------

/// Runs inside a `tokio::spawn`. Sleeps until `expires_at - 60 s`, refreshes,
/// then loops. Exits permanently on `SessionExpired`.
///
/// `pub(crate)` so integration tests can spawn it directly.
pub(crate) async fn proactive_refresh_loop(
    inner: Arc<RwLock<SessionState>>,
    http: Arc<dyn ProtonDriveHttpClient>,
) {
    loop {
        let sleep_duration = {
            let guard = inner.read().await;
            let advance = Duration::from_secs(60);
            guard
                .expires_at
                .saturating_duration_since(Instant::now() + advance)
        };
        // Floor at 1 s to avoid a busy-loop when token is nearly expired.
        let sleep_duration = sleep_duration.max(Duration::from_secs(1));
        debug!(
            secs = sleep_duration.as_secs(),
            "proactive refresh sleeping"
        );
        tokio::time::sleep(sleep_duration).await;

        let mut guard = inner.write().await;
        match do_refresh(&mut guard, &*http).await {
            Ok(()) => debug!("proactive refresh succeeded"),
            Err(SessionManagerError::SessionExpired) => {
                warn!("proactive refresh: session expired; background task exiting");
                return;
            }
            Err(e) => {
                warn!("proactive refresh transient error (will retry): {e}");
                drop(guard);
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------

/// Cloneable projection of a `do_refresh` outcome, used as the `Output` of
/// the [`Shared`] future that coalesces concurrent [`SessionManager::force_refresh`]
/// callers (`SessionManagerError` itself can't be `Clone`: several variants
/// wrap non-`Clone` types like [`std::io::Error`]).
#[derive(Clone)]
enum SharedRefreshOutcome {
    Ok,
    SessionExpired,
    Other(Arc<str>),
}

impl From<&SessionManagerError> for SharedRefreshOutcome {
    fn from(e: &SessionManagerError) -> Self {
        match e {
            SessionManagerError::SessionExpired => SharedRefreshOutcome::SessionExpired,
            other => SharedRefreshOutcome::Other(Arc::from(other.to_string())),
        }
    }
}

/// A single in-flight [`SessionManager::force_refresh`] refresh: the [`Shared`]
/// future every coalescing caller awaits, alongside a [`Weak`] handle to the
/// `SessionState` it belongs to (see [`REFRESH_COALESCE`] docs).
type InFlightRefresh = (
    Weak<RwLock<SessionState>>,
    Shared<BoxFuture<'static, SharedRefreshOutcome>>,
);

/// Single-flight registry coalescing concurrent [`SessionManager::force_refresh`]
/// callers into one in-flight `/core/v4/auth/refresh` request each, keyed by
/// the identity (pointer address) of the session's `Arc<RwLock<SessionState>>`.
/// A global static is used rather than a field on `SessionManager`/
/// `SessionState` because both types are constructed via bare struct
/// literals in `http.rs`'s test module, which this work package is not
/// permitted to touch.
///
/// The map value also carries a [`Weak`] handle to the same `SessionState`
/// so a lookup can confirm the entry really belongs to *this* live session,
/// not a stale entry whose key happens to collide with a freed-and-reused
/// address (the allocator can reuse an address once every strong `Arc` to
/// it, including one held by an abandoned/never-driven-to-completion
/// coalescing future, is gone). Without this check a collision could hand a
/// caller someone else's in-flight refresh outcome.
static REFRESH_COALESCE: LazyLock<StdMutex<HashMap<usize, InFlightRefresh>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

/// Owns the session tuple, drives proactive refresh, and exposes auth headers.
///
/// Construct via [`SessionManager::from_login`] or
/// [`SessionManager::from_keyring`].
pub struct SessionManager {
    pub(crate) inner: Arc<RwLock<SessionState>>,
    pub(crate) http: Arc<dyn ProtonDriveHttpClient>,
    /// Background refresh task. Aborted on drop.
    pub(crate) _refresh_task: JoinHandle<()>,
}

impl SessionManager {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Build a `SessionManager` from freshly-obtained credentials.
    ///
    /// Persists `refresh_token + key_password` to the OS keyring
    /// (best-effort — see module docs) and unconditionally to the 0600
    /// `session.secret.json` fallback, and `access_token + expiry` to
    /// `session.json`.
    ///
    /// Pass `expires_in_secs = 1800` if the server does not return an expiry.
    pub async fn from_login(
        http: Arc<dyn ProtonDriveHttpClient>,
        uid: String,
        access_token: Zeroizing<String>,
        refresh_token: Zeroizing<String>,
        key_password: Zeroizing<String>,
        expires_in_secs: u64,
    ) -> Result<Self, SessionManagerError> {
        let expires_at = Instant::now() + Duration::from_secs(expires_in_secs);
        // Best-effort keyring write: even with a native backend compiled in,
        // the write fails whenever there is no reachable session keyring
        // (headless host) or no keyring platform feature was compiled in.
        // The 0600 secret file below is the authoritative fallback
        // `from_keyring` reads from in that case (ADR-0007).
        if let Err(e) = save_keyring(&uid, refresh_token.as_str(), key_password.as_str()) {
            warn!("keyring write failed ({e}); relying on 0600 secret-file fallback");
        }
        save_secret_file(&uid, refresh_token.as_str(), key_password.as_str())?;
        write_session_file(&uid, access_token.as_str(), expires_at)?;
        let state = SessionState {
            uid,
            access_token,
            refresh_token,
            key_password,
            expires_at,
        };
        Ok(Self::build(state, http))
    }

    /// Resume a session by loading `access_token` + expiry from
    /// `session.json` and `refresh_token` + `key_password` from the OS
    /// keyring, falling back to the 0600 secret file (see module docs).
    pub async fn from_keyring(
        http: Arc<dyn ProtonDriveHttpClient>,
    ) -> Result<Self, SessionManagerError> {
        let sf = load_session_file()?;
        // Prefer the OS keyring; fall back to the 0600 secret file whenever
        // the keyring has no entry — the normal case whenever there is no
        // reachable native keyutils/Keychain/Credential-Manager backend
        // (headless host with no session keyring, or a build with no
        // keyring platform feature compiled in), not merely a rare edge case.
        let kp = match load_keyring(&sf.uid) {
            Ok(kp) => kp,
            Err(SessionManagerError::NoKeyring(_)) => load_secret_file(&sf.uid)?,
            Err(e) => return Err(e),
        };

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let secs_remaining = sf.expires_at_unix.saturating_sub(now_unix);
        let expires_at = Instant::now() + Duration::from_secs(secs_remaining);

        let state = SessionState {
            uid: sf.uid,
            access_token: Zeroizing::new(sf.access_token),
            refresh_token: Zeroizing::new(kp.refresh_token),
            key_password: Zeroizing::new(kp.key_password),
            expires_at,
        };
        Ok(Self::build(state, http))
    }

    fn build(state: SessionState, http: Arc<dyn ProtonDriveHttpClient>) -> Self {
        let inner = Arc::new(RwLock::new(state));
        let task_inner = Arc::clone(&inner);
        let task_http = Arc::clone(&http);
        let _refresh_task = tokio::spawn(async move {
            proactive_refresh_loop(task_inner, task_http).await;
        });
        Self {
            inner,
            http,
            _refresh_task,
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Return auth headers for one request (snapshot, no refresh).
    pub async fn auth_headers(&self) -> Vec<(String, String)> {
        let guard = self.inner.read().await;
        vec![
            (
                "Authorization".to_owned(),
                format!("Bearer {}", guard.access_token.as_str()),
            ),
            ("x-pm-uid".to_owned(), guard.uid.clone()),
        ]
    }

    /// Force-refresh the access token (called on 401).
    ///
    /// Concurrent callers on the same session are coalesced into a single
    /// in-flight `/core/v4/auth/refresh` request: if a refresh is already
    /// running when this is called, the caller awaits that refresh's result
    /// instead of issuing a second one (parallel transfers that all 401
    /// around the same moment must not each rotate the single-use refresh
    /// token — see the WP5 audit finding on concurrent-401 coalescing).
    ///
    /// Returns [`SessionManagerError::SessionExpired`] if the server rejects
    /// the refresh, after clearing the keyring.
    pub async fn force_refresh(&self) -> Result<(), SessionManagerError> {
        // Keyed by the `Arc<RwLock<SessionState>>` pointer identity so this
        // manager's in-flight refresh is (ordinarily) never confused with
        // another manager's; verified below via `Weak::upgrade` +
        // `Arc::ptr_eq` against `self.inner` so an address collision with a
        // stale entry can never be mistaken for a live match (see
        // `REFRESH_COALESCE` docs).
        let key = Arc::as_ptr(&self.inner) as usize;

        let shared = {
            let mut inflight = REFRESH_COALESCE
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let existing = inflight.get(&key).and_then(|(weak, shared)| {
                weak.upgrade()
                    .filter(|arc| Arc::ptr_eq(arc, &self.inner))
                    .map(|_| shared.clone())
            });
            if let Some(shared) = existing {
                debug!("force_refresh: coalescing onto an in-flight refresh");
                shared
            } else {
                let state = Arc::clone(&self.inner);
                let http = Arc::clone(&self.http);
                let fut: BoxFuture<'static, SharedRefreshOutcome> = Box::pin(async move {
                    debug!("force_refresh: acquiring write lock");
                    let mut guard = state.write().await;
                    let result = do_refresh(&mut guard, &*http).await;
                    drop(guard);
                    // Remove our own entry now that the refresh has
                    // completed (before the outcome becomes observable to
                    // any awaiter — see `REFRESH_COALESCE` docs), so a later,
                    // non-concurrent 401 starts a fresh single-flight group
                    // instead of replaying this cached result forever.
                    REFRESH_COALESCE
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&key);
                    match &result {
                        Ok(()) => SharedRefreshOutcome::Ok,
                        Err(e) => SharedRefreshOutcome::from(e),
                    }
                });
                let shared = fut.shared();
                inflight.insert(key, (Arc::downgrade(&self.inner), shared.clone()));
                shared
            }
        };

        match shared.await {
            SharedRefreshOutcome::Ok => Ok(()),
            SharedRefreshOutcome::SessionExpired => Err(SessionManagerError::SessionExpired),
            SharedRefreshOutcome::Other(msg) => Err(SessionManagerError::Refresh(msg.to_string())),
        }
    }

    /// Return the key password for unlocking the user's PGP private key.
    pub async fn key_password(&self) -> Zeroizing<String> {
        let guard = self.inner.read().await;
        guard.key_password.clone()
    }

    /// Delete the keyring entry (best-effort), delete the 0600 secret file,
    /// truncate `session.json`, and consume `self`.
    pub async fn logout(self) -> Result<(), SessionManagerError> {
        let uid = {
            let guard = self.inner.read().await;
            guard.uid.clone()
        };
        // Best-effort, like everywhere else the keyring is touched: a native
        // backend may be compiled in but unreachable (no session keyring on
        // a headless host), and that must not prevent scrubbing the
        // authoritative secret file + session.json below.
        if let Err(e) = delete_keyring(&uid) {
            warn!("keyring delete on logout failed ({e}); scrubbing secret-file fallback anyway");
        }
        delete_secret_file()?;
        truncate_session_file()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use bytes::Bytes;
    use proton_drive::{
        Result as DriveResult,
        http::{BlobRequest, JsonResponse},
    };
    use tokio::time::sleep;

    // -----------------------------------------------------------------------
    // Mock HTTP client
    // -----------------------------------------------------------------------

    pub(super) struct MockHttp {
        pub(super) responses: std::sync::Mutex<std::collections::VecDeque<(u16, String)>>,
        pub(super) call_count: AtomicUsize,
    }

    impl MockHttp {
        pub(super) fn new(responses: Vec<(u16, &str)>) -> Self {
            Self {
                responses: std::sync::Mutex::new(
                    responses
                        .into_iter()
                        .map(|(s, b)| (s, b.to_owned()))
                        .collect(),
                ),
                call_count: AtomicUsize::new(0),
            }
        }

        pub(super) fn calls(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ProtonDriveHttpClient for MockHttp {
        async fn request_json(&self, _req: JsonRequest) -> DriveResult<JsonResponse> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            let (status, body) = self.responses.lock().unwrap().pop_front().unwrap_or((
                200,
                r#"{"Code":1000,"UID":"u1","AccessToken":"new","RefreshToken":"newr"}"#.to_owned(),
            ));
            Ok(JsonResponse {
                status,
                headers: vec![],
                body: Bytes::from(body.into_bytes()),
            })
        }

        async fn request_blob(&self, _req: BlobRequest) -> DriveResult<JsonResponse> {
            Ok(JsonResponse {
                status: 200,
                headers: vec![],
                body: Bytes::new(),
            })
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    pub(super) fn make_state(expires_in_secs: u64) -> SessionState {
        SessionState {
            uid: "u1".to_owned(),
            access_token: Zeroizing::new("old_access".to_owned()),
            refresh_token: Zeroizing::new("old_refresh".to_owned()),
            key_password: Zeroizing::new("$2y$10$fakekeypassword".to_owned()),
            expires_at: Instant::now() + Duration::from_secs(expires_in_secs),
        }
    }

    fn success_refresh_body() -> &'static str {
        r#"{"Code":1000,"UID":"u1","AccessToken":"new_access","RefreshToken":"new_refresh"}"#
    }

    // -----------------------------------------------------------------------
    // Unit: do_refresh returns SessionExpired on 401
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn refresh_401_returns_session_expired() {
        let http = MockHttp::new(vec![(401, r#"{"Code":401,"Error":"Unauthorized"}"#)]);
        let mut state = make_state(1800);
        let result = do_refresh(&mut state, &http).await;
        assert!(
            matches!(result, Err(SessionManagerError::SessionExpired)),
            "expected SessionExpired, got: {result:?}"
        );
        assert_eq!(http.calls(), 1);
    }

    // -----------------------------------------------------------------------
    // Unit (ADR-0010 quality gate): mock refresh returns 422; assert
    // SessionExpired and keyring cleared.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn refresh_422_session_expired_and_keyring_cleared() {
        let http = MockHttp::new(vec![(422, r#"{"Code":422,"Error":"Unprocessable"}"#)]);
        let mut state = make_state(1800);

        let result = do_refresh(&mut state, &http).await;

        assert!(
            matches!(result, Err(SessionManagerError::SessionExpired)),
            "422 must produce SessionExpired, got: {result:?}"
        );

        // delete_keyring is called internally; verify it does not panic when
        // there is no keyring entry (NoEntry is silently swallowed).
        let _ = delete_keyring("u1");
    }

    // -----------------------------------------------------------------------
    // Unit: successful refresh updates tokens
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn refresh_200_updates_state() {
        let http = MockHttp::new(vec![(200, success_refresh_body())]);
        let mut state = make_state(1800);
        do_refresh(&mut state, &http)
            .await
            .expect("refresh should succeed");
        assert_eq!(state.access_token.as_str(), "new_access");
        assert_eq!(state.refresh_token.as_str(), "new_refresh");
    }

    // -----------------------------------------------------------------------
    // Unit (ADR-0010 quality gate): mock HTTP returns 401 once then 200;
    // assert exactly one refresh happened and the retry succeeded.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn reactive_refresh_401_once_then_200() {
        let http = Arc::new(MockHttp::new(vec![
            (401, r#"{"Code":401,"Error":"Unauthorized"}"#),
            (200, success_refresh_body()),
        ]));

        let inner = Arc::new(RwLock::new(make_state(1800)));

        // First call -> 401 -> SessionExpired.
        {
            let mut guard = inner.write().await;
            let r = do_refresh(&mut guard, &*http).await;
            assert!(
                matches!(r, Err(SessionManagerError::SessionExpired)),
                "first refresh must fail with SessionExpired"
            );
        }
        assert_eq!(http.calls(), 1, "exactly one HTTP call for first attempt");

        // Re-install a valid refresh token to model re-login.
        {
            let mut guard = inner.write().await;
            *guard.refresh_token = "fresh_token".to_owned();
        }

        // Second call -> 200 -> success.
        {
            let mut guard = inner.write().await;
            let r = do_refresh(&mut guard, &*http).await;
            assert!(r.is_ok(), "second refresh must succeed");
            assert_eq!(guard.access_token.as_str(), "new_access");
        }
        assert_eq!(http.calls(), 2, "exactly two HTTP calls total");
    }

    // -----------------------------------------------------------------------
    // Unit: auth_headers returns correct snapshot
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn auth_headers_snapshot() {
        let http = Arc::new(MockHttp::new(vec![])) as Arc<dyn ProtonDriveHttpClient>;
        let state = make_state(1800);
        let inner = Arc::new(RwLock::new(state));
        let task_inner = Arc::clone(&inner);
        let handle = tokio::spawn(proactive_refresh_loop(task_inner, Arc::clone(&http)));

        let mgr = SessionManager {
            inner,
            http,
            _refresh_task: handle,
        };

        let headers = mgr.auth_headers().await;
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v == "Bearer old_access"),
            "Authorization header mismatch: {headers:?}"
        );
        assert!(
            headers.iter().any(|(k, v)| k == "x-pm-uid" && v == "u1"),
            "x-pm-uid header missing: {headers:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Integration (ADR-0010 quality gate): spawn SessionManager with a short
    // expiry, sleep past it, observe proactive refresh fired.
    //
    // Marked #[ignore] because it is timing-sensitive.
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "timing-sensitive - run manually with --ignored"]
    async fn proactive_refresh_fires_before_expiry() {
        // Token expires in 2 s; the loop wakes after max(expiry - 60, 1) = 1 s.
        let http = Arc::new(MockHttp::new(vec![
            (200, success_refresh_body()),
            (200, success_refresh_body()),
        ]));
        let inner = Arc::new(RwLock::new(make_state(2)));

        let task_inner = Arc::clone(&inner);
        let task_http = Arc::clone(&http) as Arc<dyn ProtonDriveHttpClient>;
        let handle = tokio::spawn(proactive_refresh_loop(task_inner, task_http));

        sleep(Duration::from_secs(3)).await;

        let token = {
            let guard = inner.read().await;
            guard.access_token.as_str().to_owned()
        };
        handle.abort();

        assert_eq!(token, "new_access", "token should be refreshed");
        assert!(http.calls() >= 1, "expected at least one refresh HTTP call");
    }

    // -----------------------------------------------------------------------
    // Backward-compat: legacy Session struct
    // -----------------------------------------------------------------------

    #[test]
    fn parses_minimal_session() {
        let json = r#"{"AccessToken": "tok", "UID": "u"}"#;
        let s: Session = serde_json::from_str(json).unwrap();
        assert_eq!(s.access_token, "tok");
        assert_eq!(s.uid, "u");
        assert_eq!(s.base_url, "https://drive.proton.me/api");
        assert!(s.app_version.starts_with("external-drive-pdtui@"));
    }

    #[test]
    fn auth_headers_include_bearer_and_uid() {
        let s = Session {
            access_token: "abc".into(),
            uid: "u1".into(),
            app_version: "x".into(),
            base_url: "x".into(),
        };
        let h = s.auth_headers();
        assert!(
            h.iter()
                .any(|(k, v)| k == "Authorization" && v == "Bearer abc")
        );
        assert!(h.iter().any(|(k, v)| k == "x-pm-uid" && v == "u1"));
    }

    // -----------------------------------------------------------------------
    // Persistence schema contract (regression for the login→pickup bug).
    //
    // The bug was a schema split: a CLI-login writer persisted a keyring entry
    // with no `key_password` and a `session.json` with no `ExpiresAt`, which
    // `from_keyring` could not resume. Both writers are now unified through
    // `save_keyring` / `write_session_file`. These tests pin the exact JSON
    // shapes that `load_keyring` / `load_session_file` must round-trip.
    // -----------------------------------------------------------------------

    #[test]
    fn keyring_payload_round_trips_with_key_password() {
        let payload = KeyringPayload {
            uid: "uid-123".to_owned(),
            refresh_token: "refresh-abc".to_owned(),
            key_password: "$2y$10$exampleexampleexample".to_owned(),
        };
        let json = serde_json::to_string(&payload).expect("serialize");
        // The resume path (`load_keyring`) parses exactly this shape.
        let back: KeyringPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.uid, "uid-123");
        assert_eq!(back.refresh_token, "refresh-abc");
        assert_eq!(
            back.key_password, "$2y$10$exampleexampleexample",
            "key_password must survive the keyring round-trip — its absence was the login pickup bug"
        );
    }

    #[test]
    fn session_file_carries_expiry_for_resume() {
        let sf = SessionFile {
            uid: "uid-123".to_owned(),
            access_token: "access-xyz".to_owned(),
            expires_at_unix: 1_900_000_000,
            app_version: default_app_version(),
            base_url: default_base_url(),
        };
        let json = serde_json::to_string(&sf).expect("serialize");
        assert!(
            json.contains("\"ExpiresAt\""),
            "session.json must include ExpiresAt so from_keyring can compute remaining lifetime: {json}"
        );
        let back: SessionFile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.uid, "uid-123");
        assert_eq!(back.access_token, "access-xyz");
        assert_eq!(back.expires_at_unix, 1_900_000_000);
    }

    // -----------------------------------------------------------------------
    // 2FA workaround (`scripts/configure-session.sh`) <-> `SessionFile`
    // deserializer agreement.
    //
    // The script only ever writes `{"AccessToken": ..., "UID": ...}` (it
    // cannot obtain `refresh_token`/`key_password` without a full SRP
    // exchange). Before this fix, `SessionFile::expires_at_unix` had no
    // `#[serde(default)]`, so `load_session_file` hard-failed with "missing
    // field ExpiresAt" on exactly this shape instead of surfacing a clean
    // "no session in keyring" error further down the resume path.
    // -----------------------------------------------------------------------

    #[test]
    fn session_file_tolerates_missing_expires_at() {
        // This literal must stay byte-for-byte in sync with the JSON heredoc
        // `scripts/configure-session.sh` writes to session.json.
        let script_output = r#"{
  "AccessToken": "captured-access-token",
  "UID": "captured-uid"
}"#;
        let sf: SessionFile = serde_json::from_str(script_output)
            .expect("SessionFile must deserialize the script's minimal output, not hard-fail");
        assert_eq!(sf.uid, "captured-uid");
        assert_eq!(sf.access_token, "captured-access-token");
        assert_eq!(
            sf.expires_at_unix, 0,
            "a missing ExpiresAt must default to 0 (already-expired), not panic or silently trust an unknown expiry"
        );
        // Defaults for the other back-compat fields still apply too.
        assert_eq!(sf.base_url, "https://drive.proton.me/api");
        assert!(sf.app_version.starts_with("external-drive-pdtui@"));
    }

    // -----------------------------------------------------------------------
    // SessionExpired scrubs every persistence layer, not just the keyring.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_expired_scrubs_secret_file_and_session_json() {
        // Arrange: a prior successful login/refresh left both files behind.
        save_secret_file("u1", "dead_refresh", "dead_key_password").expect("write secret file");
        write_session_file(
            "u1",
            "dead_access",
            Instant::now() + Duration::from_secs(1800),
        )
        .expect("write session file");
        assert!(
            Session::secret_path().exists(),
            "precondition: secret file must exist before the expiry"
        );
        assert!(
            Session::config_path().exists(),
            "precondition: session.json must exist before the expiry"
        );

        let http = MockHttp::new(vec![(401, r#"{"Code":401,"Error":"Unauthorized"}"#)]);
        let mut state = make_state(1800);
        let result = do_refresh(&mut state, &http).await;
        assert!(
            matches!(result, Err(SessionManagerError::SessionExpired)),
            "expected SessionExpired, got: {result:?}"
        );

        assert!(
            !Session::secret_path().exists(),
            "the 0600 secret file must be deleted on SessionExpired, mirroring logout()"
        );
        let remaining = std::fs::read(Session::config_path())
            .expect("session.json must still exist (truncated), not deleted");
        assert!(
            remaining.is_empty(),
            "session.json must be truncated on SessionExpired, not left with dead tokens"
        );
    }

    // -----------------------------------------------------------------------
    // Concurrent 401s coalesce into a single in-flight refresh.
    // -----------------------------------------------------------------------

    /// Mock transport that introduces a small delay before replying, so every
    /// concurrently-spawned caller is guaranteed to have joined the same
    /// single-flight group before the (one) refresh resolves.
    struct SlowMockHttp {
        call_count: AtomicUsize,
        delay: Duration,
    }

    impl SlowMockHttp {
        fn new(delay: Duration) -> Self {
            Self {
                call_count: AtomicUsize::new(0),
                delay,
            }
        }

        fn calls(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ProtonDriveHttpClient for SlowMockHttp {
        async fn request_json(&self, _req: JsonRequest) -> DriveResult<JsonResponse> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            sleep(self.delay).await;
            Ok(JsonResponse {
                status: 200,
                headers: vec![],
                body: Bytes::from(success_refresh_body().as_bytes().to_vec()),
            })
        }

        async fn request_blob(&self, _req: BlobRequest) -> DriveResult<JsonResponse> {
            Ok(JsonResponse {
                status: 200,
                headers: vec![],
                body: Bytes::new(),
            })
        }
    }

    #[tokio::test]
    async fn concurrent_401s_coalesce_into_single_refresh() {
        let http = Arc::new(SlowMockHttp::new(Duration::from_millis(100)));
        let manager = Arc::new(SessionManager::build(
            make_state(1800),
            Arc::clone(&http) as Arc<dyn ProtonDriveHttpClient>,
        ));

        const N: usize = 8;
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let mgr = Arc::clone(&manager);
            handles.push(tokio::spawn(async move { mgr.force_refresh().await }));
        }

        for handle in handles {
            let result = handle.await.expect("refresh task panicked");
            assert!(
                result.is_ok(),
                "every coalesced caller must observe a successful refresh: {result:?}"
            );
        }

        assert_eq!(
            http.calls(),
            1,
            "{N} concurrent 401-triggered refreshes must coalesce into exactly one HTTP call"
        );
    }

    // -----------------------------------------------------------------------
    // Server-supplied ExpiresIn is honoured; 30 min is only the fallback.
    // -----------------------------------------------------------------------

    #[test]
    fn extract_expires_in_secs_reads_positive_value() {
        let body =
            br#"{"Code":1000,"UID":"u1","AccessToken":"a","RefreshToken":"r","ExpiresIn":600}"#;
        assert_eq!(extract_expires_in_secs(body), Some(600));
    }

    #[test]
    fn extract_expires_in_secs_ignores_absent_or_non_positive() {
        let absent = br#"{"Code":1000,"UID":"u1","AccessToken":"a","RefreshToken":"r"}"#;
        assert_eq!(extract_expires_in_secs(absent), None);

        let zero =
            br#"{"Code":1000,"UID":"u1","AccessToken":"a","RefreshToken":"r","ExpiresIn":0}"#;
        assert_eq!(extract_expires_in_secs(zero), None);
    }

    #[tokio::test]
    async fn refresh_honours_server_expires_in() {
        let body = r#"{"Code":1000,"UID":"u1","AccessToken":"new_access","RefreshToken":"new_refresh","ExpiresIn":90}"#;
        let http = MockHttp::new(vec![(200, body)]);
        let mut state = make_state(1800);

        do_refresh(&mut state, &http)
            .await
            .expect("refresh should succeed");

        let remaining = state.expires_at.saturating_duration_since(Instant::now());
        assert!(
            remaining <= Duration::from_secs(90) && remaining > Duration::from_secs(60),
            "expires_at should reflect the server's ExpiresIn=90s, not the 30-minute fallback: {remaining:?}"
        );
    }

    #[tokio::test]
    async fn refresh_falls_back_to_thirty_minutes_without_expires_in() {
        let http = MockHttp::new(vec![(200, success_refresh_body())]);
        let mut state = make_state(1800);

        do_refresh(&mut state, &http)
            .await
            .expect("refresh should succeed");

        let remaining = state.expires_at.saturating_duration_since(Instant::now());
        assert!(
            remaining > Duration::from_secs(29 * 60),
            "with no ExpiresIn field, the 30-minute fallback must still apply: {remaining:?}"
        );
    }
}
