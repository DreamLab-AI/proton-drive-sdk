//! M3 SRP authentication against Proton's /core/v4/auth endpoints.
//!
//! Flow: auth/info → SRP exchange (via proton-drive-crypto) → auth →
//! verify server proof → fetch key salts → derive mailbox password.
//!
//! Tokens are persisted via [`SessionManager::from_login`], which writes to
//! the OS keyring when a native backend is reachable (the kernel keyutils
//! session keyring on Linux, Keychain on macOS, Credential Manager on
//! Windows) and unconditionally to a 0600 secret file as the fallback
//! actually exercised whenever no such backend is reachable (see
//! `session.rs` module docs). A session.json is also written so the
//! existing manual-bearer path keeps working without any changes.

use std::io::{self, Write as _};
use std::sync::Arc;

use base64::Engine as _;
use proton_drive::{
    ProtonDriveHttpClient, RpgpCrypto, SrpModule,
    http::{HttpMethod, JsonRequest},
};
use proton_drive_api::{
    auth::{
        AuthInfoRequest, AuthInfoResponse, AuthRequest, AuthResponse, KeySaltsResponse,
        TwoFactorRequest, TwoFactorResponse,
    },
    common::{self, ResponseEnvelope},
};
use proton_drive_crypto::CryptoError;
use serde::Serialize;
use serde::de::DeserializeOwned;
use subtle::ConstantTimeEq as _;
use tracing::debug;
use zeroize::Zeroizing;

use crate::session::{SessionManager, SessionManagerError};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("http: {0}")]
    Http(proton_drive::Error),
    #[error("api error {code}: {message}")]
    Api { code: u32, message: String },
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("server proof mismatch — possible MITM")]
    ServerProofMismatch,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("no non-empty key salt in /keys/salts response")]
    NoKeySalt,
    #[error("2FA code rejected (API error {code}): {message}")]
    SecondFactorRejected { code: u32, message: String },
    #[error("session: {0}")]
    Session(#[from] SessionManagerError),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// Validated credentials after a successful SRP exchange.
///
/// `access_token`, `refresh_token`, and `key_password` are wrapped in
/// `Zeroizing` so their heap storage is wiped on drop (ADR-0011).
#[allow(dead_code)] // user_id + key_password consumed in M7 TUI wiring
pub struct Credentials {
    pub username: String,
    pub uid: String,
    pub user_id: String,
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    /// 31-char bcrypt hash portion — passphrase for unlocking the user's PGP key.
    pub key_password: Zeroizing<String>,
    /// Access-token lifetime in seconds. Taken from the server's `ExpiresIn`
    /// field on `/core/v4/auth` when present (reference/client/js coreTypes.ts
    /// documents it, deprecated but present); otherwise the previous
    /// conservative 30-minute default.
    pub expires_in_secs: u64,
}

/// Result of the SRP phase of login.
///
/// Accounts without a second factor complete in one step; accounts with TOTP
/// 2FA come back as [`NeedsSecondFactor`](LoginOutcome::NeedsSecondFactor)
/// and must submit a code via [`PendingLogin::submit_totp`] before the
/// session is usable.
pub enum LoginOutcome {
    Complete(Credentials),
    NeedsSecondFactor(PendingLogin),
}

/// An SRP-authenticated session whose access token is still
/// `twofactor`-scoped: the server accepted the password proof but is waiting
/// for the account's second factor.
///
/// Sequencing mirrors the C# account SDK (`ProtonApiSession` →
/// `ApplySecondFactorCodeAsync` → `ApplyDataPasswordAsync`): submit the code
/// with the freshly issued bearer token, then run the same key-salt →
/// key-password tail a non-2FA login runs immediately. The account password
/// is retained (zeroized on drop) because that tail still needs it — 2FA has
/// no effect on key-password derivation.
pub struct PendingLogin {
    username: String,
    uid: String,
    user_id: String,
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    password: Zeroizing<String>,
    expires_in_secs: u64,
}

impl PendingLogin {
    /// The account this pending login belongs to (for UI labels).
    pub fn username(&self) -> &str {
        &self.username
    }

    fn bearer_headers(&self) -> Vec<(String, String)> {
        vec![
            (
                "Authorization".to_owned(),
                format!("Bearer {}", self.access_token.as_str()),
            ),
            ("x-pm-uid".to_owned(), self.uid.clone()),
        ]
    }

    /// Submit a TOTP (or recovery) code via `POST /core/v4/auth/2fa`, then
    /// finish the login. A code the server rejects surfaces as
    /// [`AuthError::SecondFactorRejected`]; the pending state stays valid for
    /// another attempt (until the server invalidates the session after
    /// repeated failures, which surfaces as a non-`SecondFactorRejected`
    /// error).
    pub async fn submit_totp(
        &self,
        http: &dyn ProtonDriveHttpClient,
        code: &str,
    ) -> Result<Credentials, AuthError> {
        debug!("POST auth/2fa");
        let result: Result<TwoFactorResponse, AuthError> = api_post(
            http,
            "/core/v4/auth/2fa",
            &TwoFactorRequest {
                two_factor_code: code.trim().to_owned(),
            },
            &self.bearer_headers(),
        )
        .await;
        match result {
            // Success grants the session full scope in place — same tokens.
            // Upstream reads back the granted `Scopes`; this port doesn't
            // track scopes, so the envelope code is the whole signal.
            Ok(_) => self.finish(http).await,
            Err(AuthError::Api { code, message }) => {
                Err(AuthError::SecondFactorRejected { code, message })
            }
            Err(e) => Err(e),
        }
    }

    /// Key-salt fetch + key-password derivation — the tail shared by the
    /// no-2FA path and the post-2FA path.
    async fn finish(&self, http: &dyn ProtonDriveHttpClient) -> Result<Credentials, AuthError> {
        debug!("GET keys/salts");
        let salts: KeySaltsResponse =
            api_get(http, "/core/v4/keys/salts", &self.bearer_headers()).await?;

        let key_salt_b64 = salts
            .key_salts
            .into_iter()
            .find(|s| !s.key_salt.is_empty())
            .map(|s| s.key_salt)
            .ok_or(AuthError::NoKeySalt)?;

        let salt_bytes = base64::engine::general_purpose::STANDARD.decode(&key_salt_b64)?;
        let crypto = RpgpCrypto::new();
        let key_password = crypto
            .compute_key_password(
                self.password.as_str(),
                &base64::engine::general_purpose::STANDARD.encode(&salt_bytes),
            )
            .await?;

        Ok(Credentials {
            username: self.username.clone(),
            uid: self.uid.clone(),
            user_id: self.user_id.clone(),
            access_token: self.access_token.clone(),
            refresh_token: self.refresh_token.clone(),
            key_password: Zeroizing::new(key_password),
            expires_in_secs: self.expires_in_secs,
        })
    }
}

/// Perform the SRP login flow. Returns either validated credentials or a
/// [`PendingLogin`] awaiting the account's TOTP second factor.
pub async fn login(
    http: &dyn ProtonDriveHttpClient,
    username: &str,
    password: &str,
) -> Result<LoginOutcome, AuthError> {
    debug!(%username, "POST auth/info");
    let info: AuthInfoResponse = api_post(
        http,
        "/core/v4/auth/info",
        &AuthInfoRequest {
            username: username.to_owned(),
        },
        &[],
    )
    .await?;

    debug!(srp_version = info.version, "running SRP exchange");
    let crypto = RpgpCrypto::new();
    let exchange = crypto
        .get_srp(
            info.version,
            &info.modulus,
            &info.server_ephemeral,
            &info.salt,
            password,
        )
        .await?;

    debug!("POST auth");
    let auth_body = api_post_bytes(
        http,
        "/core/v4/auth",
        &AuthRequest {
            username: username.to_owned(),
            client_ephemeral: exchange.client_ephemeral.clone(),
            client_proof: exchange.client_proof.clone(),
            srp_session: info.srp_session,
        },
        &[],
    )
    .await?;
    let auth_resp: AuthResponse = parse_envelope(&auth_body)?;
    // Honour the server-supplied ExpiresIn (seconds) when present, falling
    // back to the same conservative 30-minute default the refresh path uses.
    let expires_in_secs = crate::session::extract_expires_in_secs(&auth_body).unwrap_or(30 * 60);

    // Constant-time comparison to avoid timing side-channel (ADR-0011).
    let proofs_match: bool = auth_resp
        .server_proof
        .as_bytes()
        .ct_eq(exchange.expected_server_proof.as_bytes())
        .into();
    if !proofs_match {
        return Err(AuthError::ServerProofMismatch);
    }

    let second_factor_needed = auth_resp.two_factor.enabled != 0;
    let pending = PendingLogin {
        username: username.to_owned(),
        uid: auth_resp.uid,
        user_id: auth_resp.user_id,
        access_token: Zeroizing::new(auth_resp.access_token),
        refresh_token: Zeroizing::new(auth_resp.refresh_token),
        password: Zeroizing::new(password.to_owned()),
        expires_in_secs,
    };

    if second_factor_needed {
        debug!("2FA enabled — session is twofactor-scoped until a code validates");
        return Ok(LoginOutcome::NeedsSecondFactor(pending));
    }

    Ok(LoginOutcome::Complete(pending.finish(http).await?))
}

/// Prompt for credentials interactively, run the full auth flow, and persist
/// the session through [`SessionManager::from_login`] — the single source of
/// truth for the keyring (uid-keyed, with `key_password`) and `session.json`
/// (with expiry). This is the same persistence path the TUI uses, so a session
/// created here can later be resumed via [`SessionManager::from_keyring`].
pub async fn login_interactive(base_url: &str, app_version: &str) -> Result<(), AuthError> {
    let username = prompt("Email: ")?;
    // Wrapped in `Zeroizing` like every other secret in this module (ADR-0011)
    // so the mailbox password's heap buffer is wiped on drop rather than
    // merely freed; `login()` still takes `&str` (see `password.as_str()`
    // below), matching the convention already used by the TUI's login form.
    let password: Zeroizing<String> =
        Zeroizing::new(rpassword::prompt_password("Password: ").map_err(AuthError::Io)?);

    let http: Arc<dyn ProtonDriveHttpClient> = Arc::new(
        crate::http::ReqwestHttpClient::new(base_url, app_version).map_err(AuthError::Http)?,
    );

    eprintln!("Authenticating…");
    let creds = match login(&*http, &username, password.as_str()).await? {
        LoginOutcome::Complete(creds) => creds,
        LoginOutcome::NeedsSecondFactor(pending) => {
            let code = prompt("2FA code: ")?;
            eprintln!("Validating second factor…");
            pending.submit_totp(&*http, &code).await?
        }
    };
    let username = creds.username.clone();

    SessionManager::from_login(
        Arc::clone(&http),
        creds.uid,
        creds.access_token,
        creds.refresh_token,
        creds.key_password,
        creds.expires_in_secs,
    )
    .await?;

    eprintln!("✓ session persisted (keyring + session.json)");
    eprintln!("✓ logged in as {username}");
    Ok(())
}

fn prompt(label: &str) -> Result<String, AuthError> {
    print!("{label}");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_owned())
}

/// POST `path` and return the raw response body, before envelope parsing.
///
/// Split out from [`api_post`] so callers that need to sniff an optional
/// field the typed DTO doesn't carry (e.g. `login`'s `ExpiresIn` sniff) can
/// do so without issuing a second HTTP request.
async fn api_post_bytes<Req>(
    http: &dyn ProtonDriveHttpClient,
    path: &str,
    body: &Req,
    extra_headers: &[(String, String)],
) -> Result<bytes::Bytes, AuthError>
where
    Req: Serialize,
{
    let body_bytes = serde_json::to_vec(body)?;
    let req = JsonRequest {
        method: HttpMethod::Post,
        path: path.to_owned(),
        query: vec![],
        headers: extra_headers.to_vec(),
        body: Some(body_bytes),
    };
    let resp = http.request_json(req).await.map_err(AuthError::Http)?;
    Ok(resp.body)
}

async fn api_post<Req, Resp>(
    http: &dyn ProtonDriveHttpClient,
    path: &str,
    body: &Req,
    extra_headers: &[(String, String)],
) -> Result<Resp, AuthError>
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let body_bytes = api_post_bytes(http, path, body, extra_headers).await?;
    parse_envelope(&body_bytes)
}

async fn api_get<Resp>(
    http: &dyn ProtonDriveHttpClient,
    path: &str,
    extra_headers: &[(String, String)],
) -> Result<Resp, AuthError>
where
    Resp: DeserializeOwned,
{
    let req = JsonRequest {
        method: HttpMethod::Get,
        path: path.to_owned(),
        query: vec![],
        headers: extra_headers.to_vec(),
        body: None,
    };
    let resp = http.request_json(req).await.map_err(AuthError::Http)?;
    parse_envelope(&resp.body)
}

fn parse_envelope<Resp: DeserializeOwned>(body: &[u8]) -> Result<Resp, AuthError> {
    let env: ResponseEnvelope<Resp> = serde_json::from_slice(body)?;
    if env.code != common::CODE_OK {
        return Err(AuthError::Api {
            code: env.code,
            message: env.error.unwrap_or_else(|| "unknown API error".into()),
        });
    }
    Ok(env.inner)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    // -----------------------------------------------------------------------
    // PendingLogin::submit_totp against a loopback mock server. Unlike the
    // response-script-only mock in `http.rs`, this one captures each raw
    // request so the tests can assert the 2FA wire shape (path, body,
    // bearer/uid headers) — the part of the flow no live test has proven yet.
    // -----------------------------------------------------------------------

    struct CapturingMockServer {
        addr: std::net::SocketAddr,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl CapturingMockServer {
        async fn start(script: Vec<(u16, &'static str)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
            let addr = listener.local_addr().expect("mock addr");
            let script = Arc::new(Mutex::new(VecDeque::from(script)));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let task_requests = Arc::clone(&requests);
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let script = Arc::clone(&script);
                    let requests = Arc::clone(&task_requests);
                    tokio::spawn(async move {
                        let raw = read_http_request(&mut stream).await;
                        requests.lock().unwrap().push(raw);
                        let (status, body) =
                            script.lock().unwrap().pop_front().unwrap_or((200, "{}"));
                        let out = format!(
                            "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Length: {len}\r\n\r\n{body}",
                            len = body.len(),
                        );
                        let _ = stream.write_all(out.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
            Self { addr, requests }
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    /// Read one HTTP/1.1 request fully: headers, then `Content-Length` body
    /// bytes. A single `read()` is not enough here — reqwest may flush
    /// headers and body separately, and these tests assert on the body.
    async fn read_http_request(stream: &mut TcpStream) -> String {
        let mut data: Vec<u8> = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if let Some(header_end) = data
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
            {
                let headers = String::from_utf8_lossy(&data[..header_end]).to_lowercase();
                let content_length = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if data.len() >= header_end + content_length {
                    return String::from_utf8_lossy(&data).into_owned();
                }
            }
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return String::from_utf8_lossy(&data).into_owned(),
                Ok(n) => data.extend_from_slice(&buf[..n]),
            }
        }
    }

    fn test_pending() -> PendingLogin {
        PendingLogin {
            username: "alice@proton.me".to_owned(),
            uid: "uid-1".to_owned(),
            user_id: "user-1".to_owned(),
            access_token: Zeroizing::new("access-tok".to_owned()),
            refresh_token: Zeroizing::new("refresh-tok".to_owned()),
            password: Zeroizing::new("hunter2".to_owned()),
            expires_in_secs: 1800,
        }
    }

    #[tokio::test]
    async fn submit_totp_posts_code_then_finishes_login() {
        let server = CapturingMockServer::start(vec![
            (200, r#"{"Code":1000,"Scopes":["full","drive"]}"#),
            // 16-byte salt (base64) — enough for the bcrypt key-password
            // derivation to run for real.
            (
                200,
                r#"{"Code":1000,"KeySalts":[{"ID":"k1","KeySalt":"AQEBAQEBAQEBAQEBAQEBAQ=="}]}"#,
            ),
        ])
        .await;
        let http = crate::http::ReqwestHttpClient::new(server.base_url(), "test@0.0.0-stable")
            .expect("build client");

        let creds = test_pending()
            .submit_totp(&http, " 123456 ")
            .await
            .expect("2FA login should complete");

        assert_eq!(creds.uid, "uid-1");
        assert_eq!(creds.username, "alice@proton.me");
        assert_eq!(creds.expires_in_secs, 1800);
        assert!(
            !creds.key_password.is_empty(),
            "key password must be derived after 2FA, same as a non-2FA login"
        );

        let reqs = server.requests();
        assert_eq!(reqs.len(), 2, "exactly 2fa POST then key-salts GET");
        assert!(
            reqs[0].starts_with("POST /core/v4/auth/2fa"),
            "first request must be the 2fa submission: {}",
            &reqs[0]
        );
        assert!(
            reqs[0].contains(r#"{"TwoFactorCode":"123456"}"#),
            "code must be trimmed and sent as TwoFactorCode: {}",
            &reqs[0]
        );
        let first_lower = reqs[0].to_lowercase();
        assert!(
            first_lower.contains("authorization: bearer access-tok"),
            "2fa call must carry the twofactor-scoped bearer token"
        );
        assert!(
            first_lower.contains("x-pm-uid: uid-1"),
            "2fa call must carry the session UID header"
        );
        assert!(reqs[1].starts_with("GET /core/v4/keys/salts"));
    }

    #[tokio::test]
    async fn submit_totp_rejected_code_surfaces_distinct_error_and_stops() {
        let server = CapturingMockServer::start(vec![(
            422,
            r#"{"Code":12060,"Error":"Incorrect login credentials. Please try again"}"#,
        )])
        .await;
        let http = crate::http::ReqwestHttpClient::new(server.base_url(), "test@0.0.0-stable")
            .expect("build client");

        // No `expect_err`: `Credentials` deliberately lacks `Debug` (it
        // carries key material), so unpack by hand.
        let err = match test_pending().submit_totp(&http, "000000").await {
            Ok(_) => panic!("a rejected code must fail"),
            Err(e) => e,
        };

        match err {
            AuthError::SecondFactorRejected { code, message } => {
                assert_eq!(code, 12060);
                assert!(message.contains("Incorrect"), "message: {message}");
            }
            other => panic!("expected SecondFactorRejected, got: {other}"),
        }
        assert_eq!(
            server.requests().len(),
            1,
            "a rejected code must not proceed to key salts"
        );
    }
}
