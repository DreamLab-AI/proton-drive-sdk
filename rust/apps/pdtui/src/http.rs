//! `reqwest`-backed `ProtonDriveHttpClient` with retry/backoff middleware.
//!
//! Implements the operational requirements from `README.md`:
//! - `x-pm-appversion` injected on every request
//! - retry `5xx` responses with exponential backoff + jitter
//! - retry connection-level network errors and request timeouts with their
//!   own bounded attempt counts and fixed delays, matching the JS
//!   reference's `MAX_NETWORK_ERROR_RETRY_ATTEMPTS` /
//!   `MAX_TIMEOUT_ERROR_RETRY_ATTEMPTS` split (jitter is layered on top of
//!   the matched delay; see `send_with_retry`)
//! - retry `429` responses, honouring `Retry-After`, up to a bounded budget
//!   before surfacing `Error::RateLimited` (mirrors the JS reference's
//!   transparent-retry rate-limit handling; see `send_with_retry`)
//! - never proxy endpoints (constructor pins the base URL)
//!
//! # Session-aware wrapper (ADR-0010)
//!
//! [`SessionAwareHttpClient`] wraps any [`ProtonDriveHttpClient`] and injects
//! auth headers (`Authorization` + `x-pm-uid`) from a [`SessionManager`] on
//! every JSON (metadata) request. On a `401` response it calls
//! [`SessionManager::force_refresh`] once and retries the original request
//! exactly once. If the refresh itself fails with
//! [`SessionManagerError::SessionExpired`] that error is converted to
//! `Error::Internal` so the TUI can surface a re-login prompt.
//!
//! Blob (storage) requests are deliberately **not** given the API session's
//! `Authorization` / `x-pm-uid` headers: storage endpoints (absolute
//! BareURLs, often on a different host than the API base, e.g.
//! `upload.proton.me`) authenticate with the caller-supplied
//! `pm-storage-token` header only. This matches the JS reference's
//! `makeStorageRequest`, which sends only `pm-storage-token`, `Language` and
//! `x-pm-drive-sdk-version` (reference/client/js/src/internal/apiService/apiService.ts:233-253)
//! -- never the API bearer. Sending the full-scope session bearer to a
//! separate storage host would widen the blast radius of that token far
//! beyond its intended use.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use proton_drive::{
    Error, ProtonDriveHttpClient, Result,
    http::{BlobRequest, HttpMethod, JsonRequest, JsonResponse},
};
use rand::Rng as _;
use reqwest::Client;
use tracing::{debug, warn};

use crate::session::{SessionManager, SessionManagerError};

/// Default retry delay (seconds) for a `429` response with no `Retry-After`
/// header. Matches the JS reference's `DEFAULT_429_RETRY_DELAY_SECONDS`
/// (reference/client/js/src/internal/apiService/apiService.ts:77).
const DEFAULT_429_RETRY_DELAY_SECS: u64 = 10;

/// Bounded number of `429` retries per request before giving up and
/// surfacing `Error::RateLimited`.
///
/// The JS reference instead retries `429`s indefinitely per-request, only
/// refusing to send further requests once a *global*, cross-request rolling
/// count of consecutive `429`s exceeds `TOO_MANY_SUBSEQUENT_429_ERRORS` (50)
/// within a 60s window
/// (reference/client/js/src/internal/apiService/apiService.ts:35,303-306,408-414).
/// We cap retries per-request instead of threading cross-request state
/// through the transport, trading a little fidelity for a deterministic,
/// easily-tested budget while still transparently absorbing the common case
/// of a handful of rate-limit responses instead of failing the whole
/// operation on the first one.
const MAX_RATE_LIMIT_ATTEMPTS: u32 = 5;

/// Bounded number of retry attempts for a connection-level *network* error
/// (DNS failure, connection refused/reset -- reqwest's `is_connect()`).
/// Matches the JS reference's `MAX_NETWORK_ERROR_RETRY_ATTEMPTS`
/// (reference/client/js/src/internal/apiService/apiService.ts:30). js/v0.15.2
/// ("Retry network errors more times and with bigger delay",
/// `reference/client/js/CHANGELOG.md`) bumped both this count and
/// [`NETWORK_ERROR_RETRY_DELAY_SECS`] upstream; wp2 vendored v0.15.2 but never
/// ported the change -- this aligns with the *current* (v0.19-pinned) values.
const NETWORK_ERROR_MAX_ATTEMPTS: u32 = 3;

/// Fixed delay (seconds) between network-error retries. Matches the JS
/// reference's `NETWORK_ERROR_RETRY_DELAY_SECONDS`
/// (reference/client/js/src/internal/apiService/apiService.ts:67,333-336).
const NETWORK_ERROR_RETRY_DELAY_SECS: u64 = 5;

/// Bounded number of retry attempts for a request *timeout* specifically
/// (reqwest's `is_timeout()`), distinct upstream from a network/connect
/// failure. Matches the JS reference's `MAX_TIMEOUT_ERROR_RETRY_ATTEMPTS`
/// (reference/client/js/src/internal/apiService/apiService.ts:25).
const TIMEOUT_ERROR_MAX_ATTEMPTS: u32 = 3;

/// Fixed delay (seconds) between request-timeout retries. Matches the JS
/// reference's `SERVER_ERROR_RETRY_DELAY_SECONDS`, which is reused for
/// `TimeoutError` retries
/// (reference/client/js/src/internal/apiService/apiService.ts:62,327-329).
const TIMEOUT_ERROR_RETRY_DELAY_SECS: u64 = 1;

// ---------------------------------------------------------------------------
// ReqwestHttpClient -- bare transport layer, no auth injection
// ---------------------------------------------------------------------------

pub struct ReqwestHttpClient {
    base_url: String,
    app_version: String,
    client: Client,
    max_attempts: u32,
    /// Defaults to [`NETWORK_ERROR_RETRY_DELAY_SECS`] * 1000; only ever
    /// overridden by tests (via [`Self::with_test_delays_ms`]) so retry-count
    /// behaviour can be asserted without a real multi-second wait.
    network_error_delay_ms: u64,
    /// Defaults to [`TIMEOUT_ERROR_RETRY_DELAY_SECS`] * 1000; see
    /// `network_error_delay_ms`.
    timeout_error_delay_ms: u64,
}

impl ReqwestHttpClient {
    pub fn new(base_url: impl Into<String>, app_version: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(8)
            .user_agent("pdtui/0.0.1")
            .build()
            .map_err(|e| Error::Internal(format!("reqwest builder: {e}")))?;
        Ok(Self {
            base_url: base_url.into(),
            app_version: app_version.into(),
            client,
            max_attempts: 5,
            network_error_delay_ms: NETWORK_ERROR_RETRY_DELAY_SECS * 1000,
            timeout_error_delay_ms: TIMEOUT_ERROR_RETRY_DELAY_SECS * 1000,
        })
    }

    /// Test-only seam: shrink the network/timeout-error retry delays from
    /// several seconds down to a few milliseconds so retry-COUNT behaviour
    /// (as opposed to the delay duration itself, which is a one-line constant
    /// change reviewed against `reference/client/js`) can be asserted quickly
    /// and deterministically.
    #[cfg(test)]
    fn with_test_delays_ms(mut self, network_ms: u64, timeout_ms: u64) -> Self {
        self.network_error_delay_ms = network_ms;
        self.timeout_error_delay_ms = timeout_ms;
        self
    }

    /// Test-only seam: rebuild the inner `reqwest::Client` with a much
    /// shorter overall request timeout, so a server that never responds
    /// triggers `is_timeout()` in milliseconds instead of the production
    /// 60s. Falls back to leaving the existing client untouched if the
    /// builder somehow fails (it never has in practice for a timeout-only
    /// change) rather than panicking in test code.
    #[cfg(test)]
    fn with_test_request_timeout_ms(mut self, ms: u64) -> Self {
        if let Ok(c) = Client::builder()
            .timeout(Duration::from_millis(ms))
            .pool_max_idle_per_host(8)
            .user_agent("pdtui/0.0.1")
            .build()
        {
            self.client = c;
        }
        self
    }

    fn method(m: HttpMethod) -> reqwest::Method {
        match m {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Patch => reqwest::Method::PATCH,
        }
    }

    async fn send_with_retry(
        &self,
        build: impl Fn() -> reqwest::RequestBuilder,
    ) -> Result<JsonResponse> {
        let mut delay_ms: u64 = 250;
        let mut rate_limit_attempts: u32 = 0;
        let mut attempt: u32 = 1;
        let mut network_error_attempts: u32 = 0;
        let mut timeout_error_attempts: u32 = 0;
        loop {
            let req = build()
                .header("x-pm-appversion", &self.app_version)
                .header("accept", "application/json");
            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.as_u16() == 429 {
                        let retry_after = Self::parse_retry_after_secs(resp.headers());
                        if rate_limit_attempts < MAX_RATE_LIMIT_ATTEMPTS {
                            rate_limit_attempts += 1;
                            warn!(
                                rate_limit_attempts,
                                retry_after, "rate limited (429); retrying after Retry-After"
                            );
                            tokio::time::sleep(Duration::from_secs(retry_after)).await;
                            continue;
                        }
                        warn!(retry_after, "rate limit retry budget exhausted; giving up");
                        return Err(Error::RateLimited {
                            retry_after_secs: retry_after,
                        });
                    }
                    let headers: Vec<(String, String)> = resp
                        .headers()
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_owned()))
                        .collect();
                    let bytes = resp
                        .bytes()
                        .await
                        .map_err(|e| Error::Network(format!("body read: {e}")))?;
                    if status.is_server_error() && attempt < self.max_attempts {
                        warn!(attempt, %status, "server error; retrying");
                        Self::sleep_with_jitter(delay_ms).await;
                        delay_ms = (delay_ms * 2).min(8_000);
                        attempt += 1;
                        continue;
                    }
                    return Ok(JsonResponse {
                        status: status.as_u16(),
                        headers,
                        body: bytes,
                    });
                }
                // The JS reference distinguishes a connection-level "network
                // error" (`isNetworkError` -- DNS failure, connection
                // refused/reset) from a request `TimeoutError`, retrying each
                // with its own bounded attempt count and fixed delay rather
                // than the 5xx path's shared exponential-backoff budget
                // (apiService.ts:23-30,62,67,327-336). reqwest's
                // `is_connect()`/`is_timeout()` map onto that same split, so
                // mirror it here instead of folding both into
                // `self.max_attempts`.
                Err(e) if e.is_connect() => {
                    // `network_error_attempts` is 0-based (retries issued so
                    // far), mirroring JS's `attempt`: retry while
                    // `attempt + 1 < MAX_NETWORK_ERROR_RETRY_ATTEMPTS`, i.e.
                    // while fewer than `NETWORK_ERROR_MAX_ATTEMPTS` total
                    // attempts have been made (apiService.ts:333-336).
                    if network_error_attempts + 1 < NETWORK_ERROR_MAX_ATTEMPTS {
                        network_error_attempts += 1;
                        warn!(
                            attempt = network_error_attempts,
                            error = %e,
                            "network error; retrying"
                        );
                        Self::sleep_with_jitter(self.network_error_delay_ms).await;
                    } else {
                        return Err(Error::Network(format!(
                            "network error after {} attempts: {e}",
                            network_error_attempts + 1
                        )));
                    }
                }
                Err(e) if e.is_timeout() => {
                    // Same 0-based counting as above, mirroring JS's
                    // `attempt + 1 < MAX_TIMEOUT_ERROR_RETRY_ATTEMPTS`
                    // (apiService.ts:327-330).
                    if timeout_error_attempts + 1 < TIMEOUT_ERROR_MAX_ATTEMPTS {
                        timeout_error_attempts += 1;
                        debug!(
                            attempt = timeout_error_attempts,
                            error = %e,
                            "timeout error; retrying"
                        );
                        Self::sleep_with_jitter(self.timeout_error_delay_ms).await;
                    } else {
                        return Err(Error::Network(format!(
                            "timeout error after {} attempts: {e}",
                            timeout_error_attempts + 1
                        )));
                    }
                }
                Err(e) => {
                    // The JS reference retries once on *any* other exception
                    // before giving up, in addition to its dedicated
                    // timeout/network branches (apiService.ts:339-343,
                    // `GENERAL_RETRY_DELAY_SECONDS`). Mirror that single
                    // fallback retry for transport errors that are neither a
                    // timeout nor a connect failure (e.g. a mid-stream body
                    // error), instead of failing on the first occurrence.
                    if attempt == 1 {
                        debug!(error = %e, "transport error; retrying once");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        attempt += 1;
                    } else {
                        return Err(Error::Network(e.to_string()));
                    }
                }
            }
        }
    }

    async fn sleep_with_jitter(base_ms: u64) {
        let jitter: u64 = rand::thread_rng().gen_range(0..(base_ms / 2 + 1));
        tokio::time::sleep(Duration::from_millis(base_ms + jitter)).await;
    }

    /// Parse the `Retry-After` header (seconds) from a `429` response,
    /// falling back to [`DEFAULT_429_RETRY_DELAY_SECS`] when absent or
    /// unparseable. Pulled out as a pure function so the "with" and
    /// "without a header" cases are unit-testable without any networking.
    fn parse_retry_after_secs(headers: &reqwest::header::HeaderMap) -> u64 {
        headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_429_RETRY_DELAY_SECS)
    }
}

#[async_trait]
impl ProtonDriveHttpClient for ReqwestHttpClient {
    async fn request_json(&self, req: JsonRequest) -> Result<JsonResponse> {
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            req.path.trim_start_matches('/')
        );
        self.send_with_retry(|| {
            let mut rb = self.client.request(Self::method(req.method), &url);
            for (k, v) in &req.query {
                rb = rb.query(&[(k.as_str(), v.as_str())]);
            }
            for (k, v) in &req.headers {
                rb = rb.header(k, v);
            }
            if let Some(body) = &req.body {
                rb = rb
                    .header("content-type", "application/json")
                    .body(body.clone());
            }
            rb
        })
        .await
    }

    async fn request_blob(&self, req: BlobRequest) -> Result<JsonResponse> {
        // Block tokens carry an absolute, server-issued BareURL
        // (e.g. https://upload.proton.me/block/...). These are opaque blobs;
        // never rewrite them or prepend the API base_url. Only relative paths
        // are joined against base_url.
        //
        // We attach `Authorization: Bearer {token}` to this request, so a
        // plaintext http:// BareURL would leak the bearer token. Reject it.
        let url = if req.path.starts_with("https://") {
            req.path.clone()
        } else if req.path.starts_with("http://") {
            return Err(Error::Validation(format!(
                "refusing to send bearer token to non-https BareURL: {}",
                req.path
            )));
        } else {
            format!(
                "{}/{}",
                self.base_url.trim_end_matches('/'),
                req.path.trim_start_matches('/')
            )
        };
        let body: Bytes = req.body.clone();
        let headers = req.headers.clone();
        self.send_with_retry(|| {
            let mut rb = self.client.request(Self::method(req.method), &url);
            for (k, v) in &req.query {
                rb = rb.query(&[(k.as_str(), v.as_str())]);
            }
            for (k, v) in &headers {
                rb = rb.header(k, v);
            }
            rb.body(body.clone())
        })
        .await
    }
}

// ---------------------------------------------------------------------------
// SessionAwareHttpClient -- auth injection + 401-retry (ADR-0010)
// ---------------------------------------------------------------------------

/// Wraps any [`ProtonDriveHttpClient`] with session-aware auth injection.
///
/// On a `401` response the client calls [`SessionManager::force_refresh`] once
/// and retries the original request. If the refresh itself fails with
/// [`SessionManagerError::SessionExpired`], the error is converted to
/// `Error::Internal("session expired -- please log in again")`.
pub struct SessionAwareHttpClient {
    inner: Arc<dyn ProtonDriveHttpClient>,
    session: Arc<SessionManager>,
}

impl SessionAwareHttpClient {
    /// Wrap a transport client with session-aware auth injection.
    pub fn new(inner: Arc<dyn ProtonDriveHttpClient>, session: Arc<SessionManager>) -> Self {
        Self { inner, session }
    }

    /// Prepend session auth headers to `req.headers`, preserving any
    /// caller-supplied overrides.
    async fn with_auth_headers(&self, mut req: JsonRequest) -> JsonRequest {
        let mut auth = self.session.auth_headers().await;
        // Caller headers appended last so they can override auth headers.
        auth.append(&mut req.headers);
        req.headers = auth;
        req
    }
}

#[async_trait]
impl ProtonDriveHttpClient for SessionAwareHttpClient {
    async fn request_json(&self, req: JsonRequest) -> Result<JsonResponse> {
        let authed = self.with_auth_headers(req.clone()).await;
        let resp = self.inner.request_json(authed).await?;

        if resp.status != 401 {
            return Ok(resp);
        }

        debug!("401 received; attempting token refresh");
        match self.session.force_refresh().await {
            Ok(()) => {
                debug!("refresh succeeded; retrying original request");
                let authed_retry = self.with_auth_headers(req).await;
                self.inner.request_json(authed_retry).await
            }
            Err(SessionManagerError::SessionExpired) => {
                warn!("refresh returned SessionExpired; propagating to caller");
                Err(Error::Internal(
                    "session expired -- please log in again".to_owned(),
                ))
            }
            Err(e) => Err(Error::Internal(format!("refresh failed: {e}"))),
        }
    }

    async fn request_blob(&self, req: BlobRequest) -> Result<JsonResponse> {
        // Storage (blob) requests hit absolute BareURLs -- often on a
        // different host than the API base -- and authenticate with the
        // caller-supplied `pm-storage-token` header only. Do NOT prepend the
        // API session's `Authorization` bearer or `x-pm-uid`: that would leak
        // a full-scope, longer-lived credential to a separate storage host
        // that was never designed to receive it (see module docs and
        // reference/client/js/src/internal/apiService/apiService.ts:233-253
        // `makeStorageRequest`, which sends only `pm-storage-token`,
        // `Language` and `x-pm-drive-sdk-version`).
        let retry_req = BlobRequest {
            method: req.method,
            path: req.path.clone(),
            query: req.query.clone(),
            headers: req.headers.clone(),
            body: req.body.clone(),
        };
        let resp = self.inner.request_blob(req).await?;

        if resp.status != 401 {
            return Ok(resp);
        }

        debug!("401 on blob; attempting token refresh before retrying");
        match self.session.force_refresh().await {
            Ok(()) => self.inner.request_blob(retry_req).await,
            Err(SessionManagerError::SessionExpired) => Err(Error::Internal(
                "session expired -- please log in again".to_owned(),
            )),
            Err(e) => Err(Error::Internal(format!("refresh failed: {e}"))),
        }
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
    use std::time::Instant;

    use zeroize::Zeroizing;

    use crate::session::{SessionState, do_refresh, proactive_refresh_loop};

    // -----------------------------------------------------------------------
    // Minimal mock transport
    // -----------------------------------------------------------------------

    struct SequentialMock {
        responses: std::sync::Mutex<std::collections::VecDeque<(u16, &'static str)>>,
        calls: AtomicUsize,
    }

    impl SequentialMock {
        fn new(seq: Vec<(u16, &'static str)>) -> Self {
            Self {
                responses: std::sync::Mutex::new(seq.into()),
                calls: AtomicUsize::new(0),
            }
        }

        #[allow(dead_code)]
        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ProtonDriveHttpClient for SequentialMock {
        async fn request_json(&self, _req: JsonRequest) -> Result<JsonResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (status, body) = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or((200, r#"{"ok":true}"#));
            Ok(JsonResponse {
                status,
                headers: vec![],
                body: Bytes::from(body),
            })
        }

        async fn request_blob(&self, _req: BlobRequest) -> Result<JsonResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (status, body) = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or((200, ""));
            Ok(JsonResponse {
                status,
                headers: vec![],
                body: Bytes::from(body),
            })
        }
    }

    /// Records the headers it receives on `request_blob` so tests can assert
    /// on exactly what was sent, without a real network hop.
    struct HeaderCapturingMock {
        captured_blob_headers: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl HeaderCapturingMock {
        fn new() -> Self {
            Self {
                captured_blob_headers: std::sync::Mutex::new(vec![]),
            }
        }
    }

    #[async_trait]
    impl ProtonDriveHttpClient for HeaderCapturingMock {
        async fn request_json(&self, _req: JsonRequest) -> Result<JsonResponse> {
            Ok(JsonResponse {
                status: 200,
                headers: vec![],
                body: Bytes::from(r#"{"ok":true}"#),
            })
        }

        async fn request_blob(&self, req: BlobRequest) -> Result<JsonResponse> {
            *self.captured_blob_headers.lock().unwrap() = req.headers.clone();
            Ok(JsonResponse {
                status: 200,
                headers: vec![],
                body: Bytes::new(),
            })
        }
    }

    // -----------------------------------------------------------------------
    // Helper: build a SessionManager backed by a SequentialMock without
    // touching the keyring or filesystem.
    // -----------------------------------------------------------------------

    fn make_manager(mock: Arc<SequentialMock>) -> SessionManager {
        let state = SessionState {
            uid: "u1".to_owned(),
            access_token: Zeroizing::new("old_access".to_owned()),
            refresh_token: Zeroizing::new("old_refresh".to_owned()),
            key_password: Zeroizing::new("$2y$10$fake".to_owned()),
            expires_at: Instant::now() + std::time::Duration::from_secs(1800),
        };
        let inner = Arc::new(tokio::sync::RwLock::new(state));
        let task_inner = Arc::clone(&inner);
        let task_http = Arc::clone(&mock) as Arc<dyn ProtonDriveHttpClient>;
        let handle = tokio::spawn(proactive_refresh_loop(task_inner, task_http));
        SessionManager {
            inner,
            http: mock as Arc<dyn ProtonDriveHttpClient>,
            _refresh_task: handle,
        }
    }

    // -----------------------------------------------------------------------
    // Unit (ADR-0010 quality gate): mock HTTP returns 401 once then 200;
    // assert exactly one refresh happened and the retry succeeded.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_aware_401_once_then_200() {
        // Transport returns: 401 (first request), 200 refresh, 200 retry.
        let transport = Arc::new(SequentialMock::new(vec![
            (401, r#"{"Code":401,"Error":"Unauthorized"}"#),
            (
                200,
                r#"{"Code":1000,"UID":"u1","AccessToken":"new_access","RefreshToken":"new_refresh"}"#,
            ),
            (200, r#"{"Code":1000,"ok":true}"#),
        ]));

        let manager = Arc::new(make_manager(Arc::clone(&transport)));
        let client = SessionAwareHttpClient::new(
            Arc::clone(&transport) as Arc<dyn ProtonDriveHttpClient>,
            Arc::clone(&manager),
        );

        let req = JsonRequest {
            method: HttpMethod::Get,
            path: "/test".to_owned(),
            query: vec![],
            headers: vec![],
            body: None,
        };
        // Call 1: 401 -> triggers refresh (call 2) -> retry (call 3) -> 200.
        let resp = client
            .request_json(req)
            .await
            .expect("request should succeed");
        assert_eq!(resp.status, 200, "retry after refresh should return 200");
        assert_eq!(
            transport.calls.load(Ordering::SeqCst),
            3,
            "expected 3 transport calls: original + refresh + retry"
        );
    }

    // -----------------------------------------------------------------------
    // Unit (ADR-0010 quality gate): mock refresh returns 422 -> SessionExpired
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn refresh_422_propagates_session_expired_error() {
        let http = Arc::new(SequentialMock::new(vec![(
            422,
            r#"{"Code":422,"Error":"Unprocessable"}"#,
        )]));

        let state = SessionState {
            uid: "u1".to_owned(),
            access_token: Zeroizing::new("tok".to_owned()),
            refresh_token: Zeroizing::new("ref".to_owned()),
            key_password: Zeroizing::new("kp".to_owned()),
            expires_at: Instant::now() + std::time::Duration::from_secs(10),
        };
        let inner = Arc::new(tokio::sync::RwLock::new(state));
        let mut guard = inner.write().await;
        let result = do_refresh(&mut guard, &*http).await;
        assert!(
            matches!(
                result,
                Err(crate::session::SessionManagerError::SessionExpired)
            ),
            "422 should produce SessionExpired, got: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Credential-leak regression: SessionAwareHttpClient::request_blob must
    // never carry the API session's Authorization / x-pm-uid headers.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_aware_request_blob_never_leaks_session_auth_headers() {
        let capturing = Arc::new(HeaderCapturingMock::new());
        // Separate, unrelated transport backing the SessionManager's own
        // background refresh loop -- never hit in this test since the blob
        // response is 200, not 401.
        let session_transport = Arc::new(SequentialMock::new(vec![]));
        let manager = Arc::new(make_manager(session_transport));

        let client = SessionAwareHttpClient::new(
            Arc::clone(&capturing) as Arc<dyn ProtonDriveHttpClient>,
            manager,
        );

        let req = BlobRequest {
            method: HttpMethod::Post,
            path: "https://storage.example.com/block/abc".to_owned(),
            query: vec![],
            headers: vec![("pm-storage-token".to_owned(), "storage-tok-123".to_owned())],
            body: Bytes::new(),
        };

        let resp = client
            .request_blob(req)
            .await
            .expect("blob request should succeed");
        assert_eq!(resp.status, 200);

        let captured = capturing.captured_blob_headers.lock().unwrap();
        let has_header = |name: &str| captured.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
        assert!(
            !has_header("authorization"),
            "blob request must never carry the API session Authorization header, got: {captured:?}"
        );
        assert!(
            !has_header("x-pm-uid"),
            "blob request must never carry the API session x-pm-uid header, got: {captured:?}"
        );
        assert!(
            has_header("pm-storage-token"),
            "blob request should still carry the caller-supplied pm-storage-token, got: {captured:?}"
        );
    }

    // -----------------------------------------------------------------------
    // ReqwestHttpClient retry/backoff tests, via a minimal hand-rolled
    // HTTP/1.1 mock server -- no live network, no keyring, no extra
    // mock-HTTP-server dependency.
    // -----------------------------------------------------------------------

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// One scripted response: (status, extra headers, body).
    type ScriptedResponse = (u16, Vec<(&'static str, String)>, &'static str);

    /// A single-purpose HTTP/1.1 server: every accepted TCP connection is
    /// treated as exactly one request/response (`Connection: close`), served
    /// from a FIFO script. Requests are drained but not parsed -- these
    /// tests only exercise `ReqwestHttpClient`'s status-code branching.
    struct MockServer {
        addr: std::net::SocketAddr,
        calls: Arc<AtomicUsize>,
    }

    impl MockServer {
        async fn start(script: Vec<ScriptedResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind mock listener");
            let addr = listener.local_addr().expect("mock listener local addr");
            let script = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::from(
                script,
            )));
            let calls = Arc::new(AtomicUsize::new(0));
            let task_calls = Arc::clone(&calls);
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let script = Arc::clone(&script);
                    let calls = Arc::clone(&task_calls);
                    tokio::spawn(async move {
                        let mut buf = [0u8; 8192];
                        // Best-effort drain of the request; these small test
                        // payloads arrive in a single read over loopback.
                        let _ = stream.read(&mut buf).await;
                        calls.fetch_add(1, Ordering::SeqCst);
                        let next = script.lock().unwrap().pop_front();
                        let (status, headers, body) = next.unwrap_or((200, vec![], ""));
                        let mut out = format!(
                            "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: {len}\r\n",
                            reason = reason_phrase(status),
                            len = body.len(),
                        );
                        for (k, v) in &headers {
                            out.push_str(&format!("{k}: {v}\r\n"));
                        }
                        out.push_str("\r\n");
                        out.push_str(body);
                        let _ = stream.write_all(out.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
            Self { addr, calls }
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    fn reason_phrase(status: u16) -> &'static str {
        match status {
            200 => "OK",
            400 => "Bad Request",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "Unknown",
        }
    }

    fn get_request() -> JsonRequest {
        JsonRequest {
            method: HttpMethod::Get,
            path: "/test".to_owned(),
            query: vec![],
            headers: vec![],
            body: None,
        }
    }

    #[tokio::test]
    async fn http_429_honours_retry_after_header_then_succeeds() {
        let server = MockServer::start(vec![
            (429, vec![("Retry-After", "0".to_owned())], ""),
            (200, vec![], r#"{"ok":true}"#),
        ])
        .await;
        let client = ReqwestHttpClient::new(server.base_url(), "test@0.0.0-stable")
            .expect("build ReqwestHttpClient");

        let resp = client
            .request_json(get_request())
            .await
            .expect("429 should be transparently retried and then succeed");

        assert_eq!(resp.status, 200);
        assert_eq!(server.call_count(), 2, "expected initial attempt + 1 retry");
    }

    // `parse_retry_after_secs` is a pure function precisely so the
    // with/without-header cases can be asserted deterministically, without
    // a real (or paused-clock) multi-second sleep. Mixing tokio's paused
    // virtual clock with real loopback sockets in the same test proved
    // unreliable (the mock server observed extra connections), so the
    // *value* is unit-tested here and the *retry behaviour* is exercised
    // end-to-end below using `Retry-After: 0` to keep those tests fast.
    #[test]
    fn parse_retry_after_secs_defaults_when_header_absent() {
        let headers = reqwest::header::HeaderMap::new();
        assert_eq!(
            ReqwestHttpClient::parse_retry_after_secs(&headers),
            DEFAULT_429_RETRY_DELAY_SECS
        );
    }

    #[test]
    fn parse_retry_after_secs_honours_header_when_present() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("retry-after", "42".parse().expect("valid header value"));
        assert_eq!(ReqwestHttpClient::parse_retry_after_secs(&headers), 42);
    }

    #[tokio::test]
    async fn http_429_exhausts_retry_budget_then_returns_rate_limited() {
        let script: Vec<ScriptedResponse> = (0..=MAX_RATE_LIMIT_ATTEMPTS)
            .map(|_| (429, vec![("Retry-After", "0".to_owned())], ""))
            .collect();
        let expected_calls = script.len();
        let server = MockServer::start(script).await;
        let client = ReqwestHttpClient::new(server.base_url(), "test@0.0.0-stable")
            .expect("build ReqwestHttpClient");

        let err = client
            .request_json(get_request())
            .await
            .expect_err("rate limit retry budget should eventually be exhausted");

        match err {
            Error::RateLimited { retry_after_secs } => assert_eq!(retry_after_secs, 0),
            other => panic!("expected Error::RateLimited, got: {other:?}"),
        }
        assert_eq!(
            server.call_count(),
            expected_calls,
            "expected exactly the initial attempt plus MAX_RATE_LIMIT_ATTEMPTS retries"
        );
    }

    #[tokio::test]
    async fn http_5xx_retries_once_then_succeeds() {
        let server =
            MockServer::start(vec![(500, vec![], ""), (200, vec![], r#"{"ok":true}"#)]).await;
        let client = ReqwestHttpClient::new(server.base_url(), "test@0.0.0-stable")
            .expect("build ReqwestHttpClient");

        let resp = client
            .request_json(get_request())
            .await
            .expect("5xx should be retried with backoff and then succeed");

        assert_eq!(resp.status, 200);
        assert_eq!(server.call_count(), 2, "expected initial attempt + 1 retry");
    }

    #[tokio::test]
    async fn http_4xx_is_not_retried() {
        let server = MockServer::start(vec![
            (400, vec![], r#"{"Code":400,"Error":"bad request"}"#),
            (200, vec![], r#"{"ok":true}"#), // must never be consumed
        ])
        .await;
        let client = ReqwestHttpClient::new(server.base_url(), "test@0.0.0-stable")
            .expect("build ReqwestHttpClient");

        let resp = client
            .request_json(get_request())
            .await
            .expect("4xx should be surfaced directly, not retried");

        assert_eq!(resp.status, 400);
        assert_eq!(
            server.call_count(),
            1,
            "a 4xx must not trigger any retry attempts"
        );
    }

    // -----------------------------------------------------------------------
    // Network-error / timeout-error retry alignment (js/v0.15.2 "Retry
    // network errors more times and with bigger delay",
    // `reference/client/js/CHANGELOG.md`; constants verified against the
    // current v0.19 pin in `apiService.ts`). Delays are overridden to a few
    // milliseconds via `with_test_delays_ms` so the attempt COUNT can be
    // asserted without a real multi-second wait.
    // -----------------------------------------------------------------------

    #[test]
    fn network_and_timeout_retry_constants_match_js_reference() {
        // reference/client/js/src/internal/apiService/apiService.ts:25,30,62,67
        assert_eq!(NETWORK_ERROR_MAX_ATTEMPTS, 3);
        assert_eq!(NETWORK_ERROR_RETRY_DELAY_SECS, 5);
        assert_eq!(TIMEOUT_ERROR_MAX_ATTEMPTS, 3);
        assert_eq!(TIMEOUT_ERROR_RETRY_DELAY_SECS, 1);
    }

    #[tokio::test]
    async fn network_error_exhausts_retry_budget_then_fails() {
        // Bind to grab a free loopback port, then drop the listener
        // immediately: nothing is listening on the port, so connecting to it
        // fails at the TCP layer (connection refused), which reqwest
        // surfaces via `is_connect()`.
        let addr = {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind throwaway listener");
            listener.local_addr().expect("listener local addr")
        };

        let client = ReqwestHttpClient::new(format!("http://{addr}"), "test@0.0.0-stable")
            .expect("build ReqwestHttpClient")
            .with_test_delays_ms(1, 1);

        let start = Instant::now();
        let err = client
            .request_json(get_request())
            .await
            .expect_err("connection-refused should exhaust the network-error retry budget");
        let elapsed = start.elapsed();

        match err {
            Error::Network(msg) => assert!(
                msg.contains("network error after 3 attempts"),
                "expected exactly NETWORK_ERROR_MAX_ATTEMPTS (3) attempts, got: {msg}"
            ),
            other => panic!("expected Error::Network, got: {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(2),
            "elapsed {elapsed:?} suggests the real (multi-second) retry delay leaked through instead of the test override"
        );
    }

    #[tokio::test]
    async fn timeout_error_exhausts_retry_budget_then_fails() {
        // Server accepts every connection but never writes a response, so
        // every attempt hits the client's own request timeout (`is_timeout()`).
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener local addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let _ = stream.read(&mut buf).await; // drain, never respond
                    // Hold the connection open past the client's own timeout
                    // instead of closing it, so the failure is a genuine
                    // request timeout rather than a reset/EOF.
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                });
            }
        });

        let client = ReqwestHttpClient::new(format!("http://{addr}"), "test@0.0.0-stable")
            .expect("build ReqwestHttpClient")
            .with_test_delays_ms(1, 1)
            .with_test_request_timeout_ms(50);

        let start = Instant::now();
        let err = client
            .request_json(get_request())
            .await
            .expect_err("a server that never responds should exhaust the timeout retry budget");
        let elapsed = start.elapsed();

        match err {
            Error::Network(msg) => assert!(
                msg.contains("timeout error after 3 attempts"),
                "expected exactly TIMEOUT_ERROR_MAX_ATTEMPTS (3) attempts, got: {msg}"
            ),
            other => panic!("expected Error::Network, got: {other:?}"),
        }
        assert!(
            elapsed < Duration::from_secs(2),
            "elapsed {elapsed:?} suggests the real (multi-second) retry delay leaked through instead of the test override"
        );
    }
}
