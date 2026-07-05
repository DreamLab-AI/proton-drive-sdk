# Plan — TOTP 2FA in native Rust SRP login

Date: 2026-07-05. Baseline: `main` @ `bb3ea1d` (post v0.19 alignment).
Status: **implemented same day** (steps 1–8 below all landed; kept as the
design record). What remains is the live validation described at the bottom —
no code path here has been proven against a real 2FA-enabled account yet.

Implementation summary: `LoginOutcome::{Complete, NeedsSecondFactor}` +
`PendingLogin::submit_totp` in `rust/apps/pdtui/src/auth.rs` (shared
`finish()` tail for the salts → key-password derivation), `TwoFactorRequest`/
`TwoFactorResponse` DTOs in `proton-drive-api::auth`,
`Screen::{SecondFactor, SubmittingSecondFactor}` + code-entry overlay in the
TUI (`app.rs`/`ui.rs`), `2FA code:` prompt in `pdtui login`,
`AuthError::SecondFactorRejected` (retry keeps the SRP-authenticated pending
state), and capturing-mock-server tests asserting the exact wire shape.

## Where we are

The SRP login flow is fully native Rust (`rust/apps/pdtui/src/auth.rs`):
`/core/v4/auth/info` → SRP exchange (`proton-srp` 0.8.2 via
`RpgpCrypto::get_srp`) → `POST /core/v4/auth` → constant-time server-proof
check → `/core/v4/keys/salts` → `compute_key_password`.

2FA is already *detected*: `AuthResponse.two_factor` deserializes the `2FA`
field (`TwoFactor { enabled: u32 }`,
`rust/crates/proton-drive-api/src/lib.rs`), and `login()` bails at
`auth.rs:141` with `AuthError::TwoFactorRequired`, pointing at the
`scripts/configure-session.sh` workaround (probe-only bearer capture).

## The gap is one endpoint call

Between "server proof verified" and "fetch key salts":

```
POST /core/v4/auth/2fa
Authorization: Bearer <access token from the /auth response>   (twofactor-scoped)
x-pm-uid: <UID from the /auth response>

{"TwoFactorCode": "<6-digit code>"}
```

On envelope `Code == 1000` the session gains full scope; continue to
`/core/v4/keys/salts` exactly as today. **2FA does not touch key-password
derivation** — once this lands, the full encrypted TUI/list/upload/download
path works behind TOTP, and the current error message's claim to the contrary
becomes obsolete.

### Wire truth (vendored reference @ `f249616`)

- `reference/incubating/account/cs/src/Proton.Drive.Sdk.Account/Api/Authentication/SecondFactorValidationRequest.cs`
  — body shape (`TwoFactorCode`).
- `.../AuthenticationApiClient.cs` — `ValidateSecondFactorAsync`, route
  `auth/v4/2fa` (same endpoint family as our `/core/v4/auth`); response is
  `ScopesResponse` (we only need the envelope code).
- `.../ProtonApiSession.cs` (~lines 141–150 and `ApplySecondFactorCodeAsync`
  ~line 275) — sequencing: auth → if `2FA.Enabled` submit code → then key
  salts / data password.
- `reference/client/js/src/internal/apiService/coreTypes.ts:4121` — OpenAPI
  route `/core/{_version}/auth/2fa`, "Submit second factor."

## Implementation steps

1. **DTO** (`proton-drive-api::auth`): `TwoFactorRequest` with
   `#[serde(rename = "TwoFactorCode")] two_factor_code: String`. Response
   needs no new DTO (envelope-only; upstream reads back `Scopes`, which we
   don't track).
2. **`auth.rs::login`**: replace the bail with a continuation. Preferred
   shape: split into begin/continue —
   `LoginOutcome::{Complete(Credentials), NeedsSecondFactor(PendingLogin)}`
   where `PendingLogin` holds the http handle, bearer headers, and everything
   needed to resume; `PendingLogin::submit_totp(code)` posts
   `/core/v4/auth/2fa` then runs the existing salts → key-password tail.
   (A code-provider callback is the simpler alternative but awkward for the
   TUI.)
3. **`login_interactive`**: on `NeedsSecondFactor`, prompt `2FA code: ` via
   the existing `prompt()` helper.
4. **TUI login form** (referenced at `auth.rs:192`): add a code-entry step.
5. **Error taxonomy**: new `AuthError::SecondFactorRejected { code, message }`
   for a rejected code (exact API error code to be confirmed live; Proton
   clients suggest ~8002).
6. **Tests** (loopback mock-server pattern already in pdtui `http.rs` /
   `session.rs` tests): accepted-code path (Enabled=1 → 2fa POST → salts),
   rejected-code path, and Enabled=0 regression (no 2fa call made).
7. **Cleanup**: retire/update the `TwoFactorRequired` error text, the
   `configure-session.sh` header comment ("fails today if your account has
   2FA"), and `docs/PRD-MVP-completion.md:32`.
8. **Gate** (from `rust/`): `cargo fmt --all && cargo clippy --workspace
   --all-targets -- -D warnings && cargo test --workspace`.

## Scope and validation

- **TOTP only.** Upstream's own incubating account SDK collapses
  `2FA.Enabled` to a bool and supports code submission only — no
  FIDO2/WebAuthn. A hardware-key-only second factor is out of scope here too.
- **Live validation** needs a TOTP-enabled account: `pdtui login` →
  `pdtui mvp`. Unit/mock coverage alone leaves the rejected-code error number
  unverified.
