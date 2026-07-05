# Implementation Status — MVP upload/download + auth

Date: 2026-07-05. Branch: `audit/gap-fill` (post gap-fill, pre-merge to `main`).

Supersedes the 2026-05-28 snapshot. Between that snapshot and this one, a
seven-agent audit mesh (`wp1`–`wp9`) reviewed the codebase against the JS SDK
reference and landed fix packages for every **CONFIRMED** finding it judged
worth acting on. See [`audit-2026-07-05.md`](./audit-2026-07-05.md) for the
full audit summary (38 confirmed findings, fix-per-package breakdown, and what
was deliberately deferred). This file documents the resulting *state*, not the
audit process itself.

Every M0–M7 milestone has a real implementation (no `NotImplemented` on the
happy path), including M6 (events), which was DTOs-only at the previous
snapshot and is now a fully wired, tested consumer reaching into `pdtui`'s UI.

## Milestone state

| M | Goal | State | Evidence |
|---|---|---|---|
| M0 | Workspace + CI + traits | Done | `cargo check/clippy/fmt/test/doc` green; deny-lints active |
| M1 | JSON API DTOs | Done | serde round-trip tests; happy-path subset for list/upload/download/events |
| M2 | Crypto (rpgp 0.16/0.19) | Done | `decrypt_session_key`, `encrypt_and_sign`, `decrypt_and_verify`, manifest sign/verify, `generate_passphrase` (`Zeroizing<String>`), explicit SEIPDv2/AEAD rejection guard (`reject_seipd_v2`, see ADR-0006); validated by JS-encoded wire fixtures incl. a compressed-payload fixture |
| M3 | HTTP + SRP auth | Done | `ReqwestHttpClient` (retry/backoff/jitter/`x-pm-appversion`, 429 + `Retry-After` honoured); SRP login via `proton-srp` 0.8.2; `SessionManager` proactive + reactive refresh (ADR-0010), single-flight-coalesced concurrent refresh, real OS-keyring backend |
| M4 | Upload block protocol | Done (one known interop gap) | create file (HMAC-SHA256 name hash) → request revision → 4 MiB chunk → encrypt+sign → block tokens → PUT BareURL → commit; draft cleanup (`DeleteDraft`) on failure. See blockers below (upload into a **nested, non-root** folder is still unresolved) |
| M5 | Download block protocol | Done (interop gaps closed) | get revision (paginated) → decrypt content key → per-block GET/hash/decrypt-verify → stream → manifest verify (post-delivery) → XAttr size/SHA1/mtime cross-check. See blockers below |
| M6 | Events | Done — SDK consumer + pdtui UI wired | `proton-drive-core::events::{drain_volume_events, spawn_volume_event_loop}` is a real background poll/backoff loop (Fibonacci, JS-faithful ~30s cadence); `ProtonDriveClient::subscribe_drive_events` exposes it publicly; `apps/pdtui/src/events_bridge.rs` subscribes it into the remote pane's staleness flag, with graceful degradation to manual/pull-on-focus refresh if the subscription fails to establish |
| M7 | pdtui TUI | Done | local + remote panes, F3-upload/F2-download, progress gauge, live remote-pane refresh on drive events, `signature_verified` surfaced in the UI, `PdtuiAccount` key-unlock bootstrap, session persistence |

## Test gate (end state, re-run 2026-07-05 on `audit/gap-fill`)

- `cargo fmt --all --check` — clean
- `cargo clippy --workspace --all-targets -- -D warnings` — clean, **zero warnings**
- `cargo test --workspace` — **192 passing, 0 failing, 6 ignored**
  - Ignored (all require external state, by design): live `auth_integration`
    (needs a real account), `wire_rust_encrypted_decryptable_by_node` (needs
    `node`+`openpgp` npm), one timing-sensitive `session.rs` test (manual
    `--ignored` run only), one live-credentials `account.rs` test, one
    live-credentials `download.rs` round-trip test.
  - Do not hard-code this number in prose elsewhere without re-running the
    gate — it has drifted before. Prefer "all tests pass" in docs that aren't
    the primary status snapshot.
- Wire-format fixtures (ADR-0012): JS→Rust decrypt+verify, tamper rejection,
  wrong-signer rejection, and compressed-payload (`compress: true`) decrypt
  all pass.

## Known blockers / gaps

| # | Item | Where | State |
|---|---|---|---|
| B1 | Name hash | `upload.rs` (`resolve_parent_context` + name-hash computation) | **Fixed.** `HMAC-SHA256(parent_hash_key, name_bytes)`, with `parent_hash_key` decrypted from the parent's `FolderProperties.NodeHashKey`. |
| B2 | Nested-folder key derivation | download/listing: `client.rs::resolve_node_key_via_chain`; upload: `upload.rs::resolve_parent_context` | **Split state.** Download and folder-listing walk the full parent chain and work at any depth (live-verified against a 646 MB nested file). **Upload does not**: `resolve_parent_context`'s own doc comment states it is "only correct when `parent.node_id` is the share root" — uploading into a nested (non-root) folder will derive the wrong `NodeHashKey`/parent node key. This is a real, current, deliberately-deferred gap (see `audit-2026-07-05.md`), not yet fixed by any wp1–wp9 package. |
| B3 | XAttr modification-time / size / SHA1 | `download.rs::verify_xattr` | **Fixed.** Modification time is decrypted and returned in `DownloadStats`. Size and SHA1 mismatches are logged at `error` level but are **deliberately non-fatal**, matching the JS SDK's own fallback behaviour (JS never asserts assembled size against `XAttr.Common.Size` either — see ADR-0009 correction). |
| ~~B4~~ | ~~Recovered passphrases held as plain `Vec<u8>`~~ | ~~`account.rs`, `download.rs`~~ | **Fixed** — wrapped in `Zeroizing`, as before. |
| B5 | Detached per-block `enc_signature` fetched but not independently verified | `download.rs` | **Not a bug — JS-faithful by design**, and now says so explicitly in code: the JS reference has no code path that decrypts or verifies the per-block detached signature either; only the manifest signature over block hashes establishes per-revision authenticity, and the SHA-256 hash check guards data integrity per block. |
| B6 | Download partial-write leaves a truncated file on mid-stream failure | `download.rs` | **Fixed.** A mid-stream block failure now removes the partial file via `tokio::fs::remove_file`, covered by dedicated tests. |
| ~~B7~~ | ~~Dead `decrypt_node_key` public stub returns `NotImplemented`~~ | — | **Fixed — deleted.** No symbol named `decrypt_node_key` remains anywhere in the tree; `decrypt_node_private_key` is the only path. |
| B8 (new) | Core node-read/list operations use `@deprecated`-marked legacy v1 share-scoped endpoints (`/drive/shares/{shareID}/links/{linkID}`, `/drive/shares/{shareID}/folders/{linkID}/children`) instead of the v2 volume-scoped, cursor-paginated endpoints (`/drive/v2/volumes/{volumeID}/folders/{linkID}/children` + batched `POST /drive/v2/volumes/{volumeID}/links`) that `reference/client/js/src/internal/nodes/apiService.ts` actually uses in production | `client.rs`: `node`, `fetch_folder_children`, `resolve_node_key_via_chain`, `file_downloader` | **Known gap, deliberately deferred.** Functions correctly today (proven by the live round-trip); the risk is Proton removing the deprecated routes without notice. Migrating requires new DTOs (`LinkIDs`/`More`/`AnchorID` cursor shape vs. the current flat `Links[]`/page-index `GetChildrenResponse`) and is out of scope for this docs pass. See `audit-2026-07-05.md`. |

## Fixed by the wp1–wp9 gap-fill mesh (2026-07-05)

See `audit-2026-07-05.md` for the full per-package breakdown. Highlights not
already covered by the B-table above:

- Error taxonomy: 2500 now maps to `AlreadyExists` (name collision), 2011 to a
  new `PermissionDenied` variant (previously both were mis-mapped).
- HTTP transport stopped leaking `Authorization: Bearer` / `x-pm-uid` onto
  storage `BareURL`s (blocks live on a different host than the API).
- Block-list fetch is paginated (JS `PageSize`/`FromBlockIndex`); large
  revisions no longer silently truncate.
- Filename sanitisation closes a path-traversal gap.
- `NodePassphraseSignature` and `ContentKeyPacketSignature` are now verified
  JS-faithfully (non-fatally, matching JS's own non-fatal authorship checks).
- Upload progress gauge fixed (previously stuck/incorrect).
- Session hardening: real OS-keyring backend (file fallback retained),
  `SessionExpired` now wipes the 0600 secret file and `session.json` (not
  just the keyring entry), concurrent-401 refreshes coalesce into a single
  in-flight request, interactive-login password wrapped in `Zeroizing`,
  server `ExpiresIn` honoured.
- Crypto: decompress-before-verify so JS `compress: true` XAttr payloads
  verify; `EncryptOptions.compress` wired; `Zeroizing` at the
  `generate_passphrase` trait boundary; redacted `Debug` on key material;
  explicit `reject_seipd_v2` guard (ADR-0006).
- `pdtui`: `subscribe_drive_events` wired into the remote pane via
  `events_bridge.rs` (M6, see milestone table above), with graceful
  degradation to pull-on-focus if the subscription can't be established.

## What's deliberately not done

- Full OpenAPI surface — only list/upload/download/events DTOs. Mechanical to extend.
- Migrating off the deprecated v1 share-scoped node/list endpoints to the v2
  volume-scoped ones (B8 above) — functions today, deferred pending live
  re-validation of the fix packages above.
- SEIPDv2 / AEAD — rejected by ADR-0006, deferred to M2.5.
- SQLite cache — in-memory only, ADR-0003.
- Uploading into nested (non-root-parent) folders (B2, upload half).

## Honest verdict

The MVP was **code-complete and unit/wire-verified end-to-end** as of the last
live-account round-trip (SRP login → list → upload → byte-identical download,
including a 646 MB nested-file download). The wp1–wp9 mesh then found and
fixed 38 confirmed defects across error handling, transport, crypto, upload,
download, auth/session, and pdtui's event wiring — all unit/wire-tested, none
yet re-validated against a live account since landing. **Before trusting this
state end-to-end, re-run the live round-trip** (`pdtui mvp`) to confirm the
fix packages didn't regress the happy path; nothing in the wp1–wp9 diffs
touched the core protocol shape, but that is an assumption, not a proof, until
someone runs it against production again.

Remaining known gaps are all deliberately scoped out or deferred, not
oversights: nested-folder **upload** (B2 upload-half), the v1→v2 endpoint
migration (B8), SEIPDv2/AEAD (ADR-0006), and B5's non-verification of
per-block detached signatures (JS-faithful by design). None of these block the
MVP's stated scope (SRP login → list → upload/download at the My Files root
and nested reads).
