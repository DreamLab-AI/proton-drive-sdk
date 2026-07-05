# PRD — MVP Completion (log in → list → upload → download)

**Status:** historical planning document — the milestones below (MA–MH) all
shipped; kept for the sequencing rationale and mesh-agent file assignments.
For **current** state, read `docs/IMPLEMENTATION-STATUS.md` and
`docs/audit-2026-07-05.md` instead — in particular, the "Out of scope for
MVP" events-sync line below is stale: M6 (events consumer + `pdtui` wiring)
shipped after this PRD was written. Supersedes M2-M7 of
`PRD-rust-port-and-tui.md` for sequencing.
**Date opened:** 2026-05-28.
**Acceptance:** the user can run `pdtui` against their own Proton Drive account, navigate the remote pane via SRP login, upload a small (<10 MiB) file, and download it back byte-identical.

## Where we are

Live SRP login confirmed end-to-end (`apps/pdtui/tests/auth_integration.rs` passes against real account). Crypto primitives (encrypt/decrypt/sign/verify, key gen, session-key roundtrip) self-consistent in rpgp. HTTP middleware proven via probe diff vs Node `fetch` (3/3 endpoints match). What remains is:

1. **Wire-format validation** — every rpgp ciphertext we produce must round-trip against a JS-SDK-encoded counterpart before we trust it.
2. **Listing path** — `my_files_root`, `iter_folder_children` need real implementations (currently `Error::NotImplemented`).
3. **Block-upload protocol** — ~5,900 LoC of JS to port.
4. **Block-download protocol** — ~2,900 LoC of JS to port.
5. **Token refresh + session hardening** — no refresh path; secrets live in plaintext heap.
6. **TUI wiring** — `transfer.rs` is a 19-line stub.

## Out of scope for MVP

- Photos, sharing, public links (`internal/sharingPublic/`, `internal/photos/`)
- Trash, restore, move/rename, copy
- ~~Events-driven sync (`internal/events/` — DTOs in place, no consumer wired)~~ — **shipped since this PRD was written**: see M6 in `docs/IMPLEMENTATION-STATUS.md`
- AEAD-GCM / SEIPDv2 (per ADR-0006 — rejected at boundary)
- Thumbnail generation/upload
- Resumable upload, parallel block upload >4 in flight, retry orchestration
- ~~2FA login (returns `TwoFactorRequired` cleanly — fix-forward when needed)~~ — **shipped since this PRD was written**: TOTP codes are submitted via `POST /core/v4/auth/2fa` in both `pdtui login` and the TUI login flow (see `docs/plan-2fa-totp.md`). FIDO2/security-key second factor remains out of scope (upstream's account SDK doesn't support it either).

## Milestones

| M | Goal | Acceptance | Est. |
|---|---|---|---|
| **MA** | **Security hardening** | All credential types zeroize on drop; `subtle::ConstantTimeEq` on server-proof; PKESK subkey selection filters `is_encryption_key()`. Live SRP still passes. | 3h |
| **MB** | **Wire-format validation harness** | `tests/fixtures/` contains JS-encoded SEIPDv1 message + matching public key. Rust round-trips: decrypt → re-encrypt → JS decrypts ours. Fixture committed. | 4h |
| **MC** | **Node DTOs + listing** | `proton-drive-api::nodes` ports `Link`, `Revision`, `FileBlock`, `ShareKey`. `proton-drive-core::client::{my_files_root, node, iter_folder_children}` return real data, name-decrypted via share key. Live integration test lists user's root. | 9h |
| **MD** | **Block-upload protocol** | `FileUploader::upload_from_stream` works for files <16 MiB single-revision: create node → request revision → chunk to 4 MiB blocks → encrypt+sign each → request block tokens → PUT to block URLs → commit revision. Live test uploads `tests/fixtures/small.txt`. | 14h |
| **ME** | **Block-download protocol** | `FileDownloader::download_to_writer` reverses MD: fetch active revision → GET each block URL → decrypt + verify each → write to stream. Round-trip byte-identical. | 8h |
| **MF** | **TUI wiring** | Remote pane populates from `iter_folder_children`. F2 (download) and F3 (upload) launch `Transfer` tasks with progress reporting. Cancellation via Esc. | 5h |
| **MG** | **Token refresh** | Background task refreshes access token via `/core/v4/auth/refresh` before expiry; persists to keyring. Stale-token 401 triggers single retry after refresh. | 3h |
| **MH** | **Docs refresh + handoff** | `IMPLEMENTATION-STATUS.md` updated to reflect actual state. `HANDOFF.md` notes "MVP shipped — these are the gaps". | 1h |

**Total:** ~47h focused. Dependencies: MA + MB independent; MC unblocks MD/ME; MD+ME unblock MF; MG independent.

## Sequencing for parallel agent execution

```
Wave 1 (parallel):  MA  MB  MC
Wave 2 (parallel):  MD  ME       (depend on MC)
Wave 3:             MF           (depends on MD + ME)
Wave 4:             MG  MH       (independent of above; can start any time)
```

## Quality gates per merge

- `cargo clippy --workspace --all-targets -- -D warnings` green
- `cargo fmt --all --check` green
- `cargo test --workspace` all passing
- New code touching crypto/auth has at least one negative-path test
- No `unwrap`/`expect`/`panic` outside `#[cfg(test)]` (workspace lints enforce)
- Secret types implement `ZeroizeOnDrop` (ADR-0011)

## Risks

- **SEIPDv1 wire-format mismatch.** Pure rpgp self-consistency does not prove Proton interop. Mitigation: MB blocks all upload/download merges.
- **Block-upload protocol drift.** JS implements verifier feedback (`blockVerifier.ts`) and digest cross-check — easy to silently skip and lose data integrity. Mitigation: port the verifier loop, not just the happy path.
- **rpgp signature ordering inside SEIPD.** JS SDK uses a specific OnePassSignature → Literal → Signature packet ordering. rpgp's `MessageBuilder` may emit differently. MB harness catches.
- **Token expiry mid-upload.** A 16 MiB upload over a slow link can outlast a token. MG must land before MVP demo, or upload retries will spuriously 401 on the commit step.
- **Concurrent agent edits.** Mesh agents working on `proton-drive-api/src/lib.rs` simultaneously will collide. Mitigation: agent assignments below are file-disjoint.

## Mesh agent assignments (file-disjoint)

| Agent | Files owned (write) | Reads (no write) |
|---|---|---|
| **MA-zeroize** | `crates/proton-drive-crypto/src/lib.rs` (struct annotations), `apps/pdtui/src/auth.rs` (Credentials, LoginForm), `apps/pdtui/src/app.rs` (LoginForm shape) | — |
| **MB-fixture** | `tests/fixtures/`, `crates/proton-drive-crypto/tests/wire_format.rs` (new file) | `crates/proton-drive-crypto/src/lib.rs` |
| **MC-listing** | `crates/proton-drive-api/src/nodes.rs` (new file extracted from `lib.rs`), `crates/proton-drive-core/src/client.rs`, `crates/proton-drive-core/src/nodes.rs` | `client/js/src/internal/nodes/` |
| **MD-upload** | `crates/proton-drive-core/src/upload.rs`, `crates/proton-drive-api/src/upload.rs` (new file extracted) | `client/js/src/internal/upload/` |
| **ME-download** | `crates/proton-drive-core/src/download.rs`, `crates/proton-drive-api/src/download.rs` (new file extracted) | `client/js/src/internal/download/` |
| **MF-tui** | `apps/pdtui/src/transfer.rs`, `apps/pdtui/src/panes.rs`, `apps/pdtui/src/app.rs` (transfer wiring only — not LoginForm), `apps/pdtui/src/ui.rs` | — |
| **MG-refresh** | `apps/pdtui/src/auth.rs` (refresh fn only — not Credentials), `apps/pdtui/src/session.rs` | — |

**Coordination rules:** every agent reads this PRD + the relevant ADR before touching files. On completion an agent commits with `git commit -m "Mx-<slug>: <summary>"` and pushes. Conflicts on shared files (`auth.rs`, `app.rs`) are resolved by sequencing — MA → MG → MF.

## What MVP does NOT prove

- That this code is safe to use against arbitrary Proton accounts (assume your own only).
- That uploads survive a network drop mid-block (no resume).
- That the SDK is API-stable. Internal types may churn freely.

## What MVP DOES prove

- The Rust port can talk to the real Proton API end-to-end with real crypto.
- The block protocol is understood well enough to debug failures.
- The TUI is a usable test harness for further SDK development.
