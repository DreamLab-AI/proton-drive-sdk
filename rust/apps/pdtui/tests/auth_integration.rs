//! Live SRP login integration test.
//!
//! Marked `#[ignore]` — skipped by default so CI doesn't need credentials.
//!
//! Run:
//!   PDTUI_TEST_EMAIL=you@proton.me \
//!   PDTUI_TEST_PASSWORD=yourpassword \
//!   cargo test -p pdtui --test auth_integration -- --ignored --nocapture
//!
//! If the account has TOTP 2FA enabled, also set PDTUI_TEST_TOTP to a
//! freshly generated code (it expires within ~30 s, so set it just before
//! running).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use pdtui::auth;
use pdtui::http::ReqwestHttpClient;

const BASE_URL: &str = "https://drive.proton.me/api";
const APP_VERSION: &str = "external-drive-pdtui@0.0.1-stable";

#[tokio::test]
#[ignore = "requires PDTUI_TEST_EMAIL + PDTUI_TEST_PASSWORD"]
async fn live_srp_login_succeeds() {
    let email = std::env::var("PDTUI_TEST_EMAIL").expect("set PDTUI_TEST_EMAIL to run this test");
    let password =
        std::env::var("PDTUI_TEST_PASSWORD").expect("set PDTUI_TEST_PASSWORD to run this test");

    let http = ReqwestHttpClient::new(BASE_URL, APP_VERSION).expect("http client init");
    let outcome = auth::login(&http, &email, &password)
        .await
        .expect("SRP login failed");
    let creds = match outcome {
        auth::LoginOutcome::Complete(creds) => creds,
        auth::LoginOutcome::NeedsSecondFactor(pending) => {
            let code = std::env::var("PDTUI_TEST_TOTP").expect(
                "account has 2FA enabled — set PDTUI_TEST_TOTP to a fresh code to run this test",
            );
            pending
                .submit_totp(&http, &code)
                .await
                .expect("2FA validation failed (stale code?)")
        }
    };

    assert!(!creds.uid.is_empty(), "uid is empty");
    assert!(!creds.access_token.is_empty(), "access_token is empty");
    assert!(!creds.refresh_token.is_empty(), "refresh_token is empty");
    assert!(
        creds.key_password.starts_with("$2y$10"),
        "key_password should be a bcrypt hash, got prefix: {:?}",
        &creds.key_password[..creds.key_password.len().min(10)]
    );

    // Masked output — safe to print in --nocapture mode.
    let tok = &creds.access_token;
    println!("✓ uid           : {}", creds.uid);
    println!(
        "✓ access_token  : {}…{}",
        &tok[..6.min(tok.len())],
        &tok[tok.len().saturating_sub(4)..]
    );
    println!("✓ key_password  : {}…", &creds.key_password[..7]);
}
