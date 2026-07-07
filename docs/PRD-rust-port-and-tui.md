# PRD: Rust port of Proton Drive SDK + `pdtui` two-pane TUI

| | |
|---|---|
| Status | Draft v1 |
| Date | 2026-05-27 |
| Owner | DreamLab AI (John O'Hare) |
| Reference impl | `js/sdk/` @ v0.15.2 (most mature: 394 commits, 42K LoC, recent feature work in photos/events/public-link decryption) |
| Distribution | **None.** Personal use against the owner's Proton Drive account only. No npm/crates.io/binary release. |
| Out of scope | C#/kt/swift parity, non-Proton remotes, server side, auth/login UI, public distribution |

---

## 1. Problem & Motivation

The Proton Drive SDK ships as TypeScript (npm) and C# (with kt/swift bindings). There is no Rust client. We want:

1. A **Rust crate** (`proton-drive`) usable from terminal tools, daemons, and embedded Linux clients without dragging in Node or .NET runtimes.
2. A **tmux-friendly TUI** (`pdtui`): two-pane (local FS / Proton Drive remote) Midnight-Commander-style browser focused on **upload and download only** for v1.

Rationale for picking JS as the reference port source: it is the more mature and feature-rich of the two independent implementations (394 vs 258 commits, v0.15.2 vs v0.14.5, ~2× LoC, more recent edge-case fixes around photos drafts, public-link decryption, retry policy, CLI integration).

## 2. Goals (v1)

- G1. Publish `proton-drive` crate that authenticates against Proton, lists `/My Files`, uploads a file, downloads a file, and processes events, with **on-the-wire and cryptographic parity** to the JS SDK so existing accounts remain interoperable.
- G2. Use **pure-Rust OpenPGP** (`rpgp`) as the crypto backend. Behind a trait so it can be swapped if/when Proton's late-2026/early-2027 crypto migration forces it. No cgo, no Go runtime, no licence-tainted linkage.
- G3. Ship `pdtui`: single static binary, ratatui-based, two panes, keyboard-first, runs cleanly inside tmux.
- G4. Honour Proton's operational rules: `x-pm-appversion`, official endpoints only, event-based sync, shared-with-first-party rate limits.

## 3. Non-Goals (v1)

- Sharing, public links, bookmarks, invitations, devices, photos. (Crate scaffolds the modules; clients are stubbed.)
- Trash management beyond "do not show trashed nodes" in the UI.
- Sync daemon, conflict resolution, FUSE mount.
- Windows-specific TUI polish (target Linux/macOS; Windows best-effort via crossterm).
- Auth/login flows: host wires in an `Account` impl exactly as the JS SDK requires.

## 4. Users & Use Cases

| User | Use case |
|---|---|
| Linux power user on Proton Drive | Browse + upload/download from a tmux split without leaving the terminal |
| Researcher / data engineer | Scripted Rust binary to push artefacts into Drive over SSH |
| Proton SDK team (downstream) | Have a reference Rust impl to validate the upcoming crypto migration |

Anti-user: any commercial third-party app, explicitly disallowed by Proton's [usage guidelines](../README.md#usage-guidelines-for-personal-projects) until GA.

## 5. Reference: what we are porting

From `client/js/src/`:

- **Public surface** (`interface/index.ts`, 1,170 LoC across 16 files): types only, no business logic. Mirror to `proton_drive::interface`.
- **Construction contract**: `{ httpClient, entitiesCache, cryptoCache, account, openPGPCryptoModule, srpModule, telemetry?, featureFlagProvider?, latestEventIdProvider? }`.
- **Client entry points**: `ProtonDriveClient`, `ProtonDrivePhotosClient`, `ProtonDrivePublicLinkClient`. v1 ports `ProtonDriveClient` only.
- **Core methods needed for TUI** (subset of 30+ on the JS client):
  - `getMyFilesRootFolder()`, `getNode(uid)`, `iterateFolderChildren(uid, filters, signal)`
  - `getFileDownloader(uid, signal)` → `FileDownloader::downloadToStream(...)`
  - `getFileUploader(parentUid, name, metadata, ...)` → `FileUploader::uploadFromStream(...)`
  - `getAvailableName(parentUid, name)` for conflict-safe naming
  - `subscribeToDriveEvents(callback)` to refresh remote pane on external changes
- **Wire format**: protobuf schemas live in `cs/sdk/src/protos/`; reuse those `.proto` files (do not re-derive from the JS layer).
- **Operational**: `x-pm-appversion`, retry/backoff (see `Retry network errors more times` commit), event-based refresh (no polling).

## 6. Architecture: `proton-drive` crate

### 6.1 Workspace layout

```
rust/
├─ Cargo.toml                       # workspace
├─ crates/
│  ├─ proton-drive/                 # public crate, re-exports the rest
│  ├─ proton-drive-core/            # client, nodes, events, transfer
│  ├─ proton-drive-api/             # HTTP DTOs + protobuf (generated)
│  ├─ proton-drive-crypto/          # OpenPgpCrypto trait + rpgp impl
│  ├─ proton-drive-cache/           # ProtonDriveCache trait + memory impl
│  ├─ proton-drive-sync/            # local↔remote hash-based sync engine (domain-model-sync.md)
│  └─ proton-drive-telemetry/       # Telemetry trait + null impl
└─ apps/
   └─ pdtui/                        # the TUI binary
```

Rationale: mirrors the JS module split (`internal/{nodes,events,upload,download}`, `cache/`, `crypto/`, `interface/`) so reviewers can map a Rust file to its JS sibling 1:1.

### 6.2 Public API shape

```rust
pub struct ProtonDriveClient { /* ... */ }

pub struct ProtonDriveClientOptions {
    pub http_client: Arc<dyn ProtonDriveHttpClient>,
    pub entities_cache: Arc<dyn ProtonDriveCache<String>>,
    pub crypto_cache: Arc<dyn ProtonDriveCache<CachedCryptoMaterial>>,
    pub account: Arc<dyn ProtonDriveAccount>,
    pub openpgp: Arc<dyn OpenPgpCrypto>,
    pub srp: Arc<dyn SrpModule>,
    pub config: ProtonDriveConfig,           // default: official endpoints
    pub telemetry: Option<Arc<dyn Telemetry>>,
    pub feature_flags: Option<Arc<dyn FeatureFlagProvider>>,
}

impl ProtonDriveClient {
    pub async fn my_files_root(&self) -> Result<MaybeNode>;
    pub async fn node(&self, uid: &NodeUid) -> Result<MaybeNode>;
    pub fn iter_folder_children<'a>(
        &'a self,
        parent: &NodeUid,
        filter: FolderChildrenFilter,
    ) -> impl Stream<Item = Result<MaybeNode>> + 'a;

    pub async fn file_downloader(&self, uid: &NodeUid) -> Result<FileDownloader>;
    pub async fn file_uploader(
        &self,
        parent: &NodeUid,
        name: &str,
        meta: UploadMetadata,
    ) -> Result<FileUploader>;

    pub async fn subscribe_drive_events(
        &self,
        cb: Box<dyn DriveListener>,
    ) -> Result<EventSubscription>;
}
```

Transfer objects expose `tokio::io::AsyncRead` / `AsyncWrite` rather than the JS `ReadableStream`/`WritableStream`. Progress is a `tokio::sync::watch::Receiver<u64>`. Cancellation is `tokio_util::sync::CancellationToken`, not `AbortSignal`.

### 6.3 Crypto seam

`OpenPgpCrypto` is a trait, identical role to JS `crypto/interface.ts`. v1 implementation: **`rpgp`** (pure Rust, MIT/Apache-2.0 dual-licensed, compatible with our MIT use). No cgo, no GopenPGP, no Go runtime; cross-compiles trivially, no licence interaction concerns.

**What we need from rpgp** (from auditing `client/js/src/crypto/openPGPCrypto.ts`):
- Curve25519 keys (ECDH + EdDSA), Proton's default
- SEIPDv1 symmetric encryption, the path used when feature-flag-gated AEAD is off
- Detached + inline signatures, multi-recipient session-key encryption, password-encrypted session keys
- Critical signature notations (`signatureContext`), RFC 9580
- SEIPDv2 / AEAD-GCM: **opt-in** via Proton's per-key `enableAeadWithEncryptionKeys` flag; v1 keeps this **disabled** (matches `NullFeatureFlagProvider` default)

This gating is the key insight: Proton itself runs SEIPDv1 by default and opts keys into SEIPDv2 only when the recipient advertises it. v1 of the Rust port can therefore stay on the well-trodden SEIPDv1 path and defer SEIPDv2 to **M2.5**, a separate sub-milestone after we have AEAD-on JS fixtures to validate against. If `rpgp`'s AEAD path has gaps then, fork it, file upstream, or carry a local patch.

The trait is also **the** insulation layer for the late-2026/early-2027 cryptographic migration (likely SEIPDv2 + v6 keys becoming mandatory). PRD-level requirement: the crate stays compilable across the migration by swapping the impl behind the trait.

**Validation**: every milestone runs an interop fixture suite (§11), JS-upload/Rust-download and inverse, over Proton's actual byte output. Diverge anywhere, halt and fix before progressing.

### 6.4 Cache

`ProtonDriveCache<T>` trait + an **in-memory** impl using `dashmap`. This is sufficient for v1 because:

- Single-user, single-session TUI: no cross-process sharing to coordinate.
- Upload/download flow doesn't benefit from persisted metadata; each session re-fetches the folder being browsed (cheap; event-based refresh after first list).
- No offline-mode requirement.
- Avoids a `rusqlite` dep, schema-migration tooling, and a class of "stale cache vs server truth" bugs.

**SQLite is deferred** unless one of these triggers fires:
- Folder listings >5k entries feel slow on cold start (event refresh isn't enough).
- We add a sync daemon / background watcher (out of v1 scope).
- We want browse-without-network for already-visited folders.

If we ever pull it forward, port the C# SDK's schema directly (`cs/sdk/src/Proton.Drive.Sdk/Caching/`) rather than designing new: they've already solved encrypted-blob storage, eviction, and migration there.

### 6.5 HTTP client

`ProtonDriveHttpClient` trait is host-injected (mirrors JS). Default convenience impl in `apps/pdtui` only: `reqwest` with cookie store, `rustls`, and a `tower` middleware stack for retry/backoff matching the JS policy (`Retry network errors more times and with bigger delay`: exponential, jitter, 5 attempts). `x-pm-appversion = external-drive-pdtui@{semver}-{channel}` set at the middleware layer; not user-overridable.

### 6.6 Async runtime

`tokio` multi-threaded. No `async-std`, no blocking. Streams via `tokio_stream`.

### 6.7 Error model

One crate-level `Error` enum with `thiserror`. Mirrors the JS error taxonomy (`errors.ts`): `NetworkError`, `IntegrityError`, `DecryptionError`, `VerificationError`, `ValidationError`, `NodeWithSameNameExistsError`, `RevisionDraftConflictError`, `RateLimitedError`, etc. Public API returns `Result<T, proton_drive::Error>`; no `anyhow` in the public surface.

## 7. Architecture: `pdtui`

### 7.1 Layout

```
┌─ pdtui  v0.1.0 ─ user@example.com ──────────── /My Files ─┐
│ ┌─ LOCAL ────────────────┐ ┌─ REMOTE ───────────────────┐ │
│ │ /home/dev/projects     │ │ /My Files/Photos           │ │
│ │ ..                     │ │ ..                         │ │
│ │ docs/                  │ │ trip-2026/                 │ │
│ │ notes.md      2.1 KiB  │ │ IMG_0042.jpg     3.2 MiB   │ │
│ │ data.csv     14.3 MiB  │ │ IMG_0043.jpg     2.9 MiB   │ │
│ │ > video.mp4 412.0 MiB  │ │ ▶ video.mp4    412.0 MiB ↑ │ │
│ └────────────────────────┘ └────────────────────────────┘ │
│ ↑ video.mp4  73%  18.2 MiB/s  eta 9s        2 queued      │
│ F2 upload  F3 download  F5 refresh  Tab switch  q quit    │
└───────────────────────────────────────────────────────────┘
```

### 7.2 Tech stack

- **ratatui** for layout/widgets, **crossterm** for I/O (works inside tmux; honours `TERM`, mouse-capture toggle).
- **tokio** runtime shared with the SDK.
- **notify** crate to watch the local pane's cwd.
- **Config** at `$XDG_CONFIG_HOME/pdtui/config.toml`: keymap, default panes, endpoint override (locked to Proton domain).
- **Logs** at `$XDG_STATE_HOME/pdtui/pdtui.log` (tracing-appender, rotated). UI never writes to stdout/stderr.

### 7.3 tmux-readiness checklist

- Detect `TMUX` env; fall back to `XTerm-256` colour if not 24-bit-capable.
- Avoid alternate-screen-flicker on pane resize (`crossterm::event::Event::Resize` → debounced redraw).
- Bracketed paste enabled.
- Mouse opt-in (`m` toggles) so tmux's own mouse mode still works.
- No bell/title escapes that tmux's `monitor-activity` would spuriously trigger.
- Exit cleanly on `SIGWINCH` and `SIGTERM`; restore cursor and screen.

### 7.4 Keymap (v1)

| Key | Action |
|---|---|
| `Tab` / `Shift+Tab` | Switch active pane |
| `↑ ↓` / `j k` | Move cursor |
| `Enter` / `l` | Descend into folder |
| `Backspace` / `h` | Parent folder |
| `Space` | Select / deselect (multi-select) |
| `F2` / `u` | Upload selected (local → remote, into remote pane's cwd) |
| `F3` / `d` | Download selected (remote → local, into local pane's cwd) |
| `F5` / `r` | Refresh active pane |
| `/` | Filter current pane by substring |
| `g` / `G` | Top / bottom |
| `?` | Help overlay |
| `q` / `Ctrl+C` | Quit (prompts if transfers active) |

### 7.5 Transfer queue

- Bounded `tokio::sync::Semaphore` (default 3 parallel transfers, matching the conservative side of the JS SDK's parallelism guard).
- Per-transfer task owns a `FileUploader` / `FileDownloader`, reports progress to a `watch` channel.
- Status bar aggregates: bytes/s, ETA, active/queued/failed counts.
- Resume on UI restart is a v1.1 goal; v1 cancels all on quit after confirmation.
- Integrity: SDK enforces SHA1 / size verification on upload (JS `UploadMetadata.expectedSha1`); pdtui computes locally before queueing.

### 7.6 Auth (TUI scope only)

`pdtui` is **not** the SDK: it needs a concrete `Account` impl. v1 uses the same flow Proton's reference Linux CLI uses: device-code-style login against `account.proton.me`, persisted refresh token in OS keyring (`secret-service` on Linux, Keychain on macOS). If keyring unavailable, fall back to encrypted file in `$XDG_DATA_HOME/pdtui/session` (passphrase prompt on launch).

This is the **only** code path in pdtui that talks outside the SDK trait surface; it is isolated in `apps/pdtui/src/auth.rs` so the SDK crate stays auth-free.

## 8. Milestones

| M | Deliverable | Acceptance |
|---|---|---|
| M0 | Workspace + CI scaffold | `cargo build` + `cargo clippy --all -- -D warnings` green; GH Actions matrix linux/macos |
| M1 | `proton-drive-api`: protobuf codegen + DTOs | Round-trip equality with JS-emitted bytes for 10 captured fixtures |
| M2 | `proton-drive-crypto`: `OpenPgpCrypto` trait + `rpgp` SEIPDv1 path | Decrypts JS-uploaded SEIPDv1 fixture; encrypts roundtrip verified by JS; Curve25519 + signature context exercised |
| M2.5 | SEIPDv2 / AEAD-GCM path (deferrable) | Validate against JS fixtures with `enableAeadWithEncryptionKeys: true`; only needed before the late-2026 migration forces it |
| M3 | `proton-drive-core`: auth-injected client, `my_files_root`, `iter_folder_children` | `pdtui` skeleton lists remote root |
| M4 | Upload (`FileUploader` + stream) | 1 GB file uploads, JS SDK can download and verify SHA1 |
| M5 | Download (`FileDownloader` + stream) | Inverse of M4 |
| M6 | Events subscription | Renaming a node from the web UI refreshes the pane within one event-loop tick, with **no ad hoc polling of node/listing endpoints outside the official Events API**. *(Reconciled 2026-07-05: the original "within 5s without polling" wording didn't survive contact with upstream. The JS SDK's own event loop is itself a ~30s-interval poll against the Events endpoint with Fibonacci backoff, since Proton Drive has no push/websocket transport. The Rust port mirrors that cadence exactly (`spawn_volume_event_loop`, `POLL_INTERVAL_SECS = 30`). "Without polling" means without the client re-listing/re-fetching nodes on its own timer, not a sub-5s push guarantee neither SDK provides.)* |
| M7 | `pdtui` v0.1.0 release | All keymap entries work, tmux smoke test passes, single static binary < 15 MB stripped |

Target cadence: 2 weeks per M, with M0/M1 in flight together. Total ~14 weeks single-engineer to M7.

## 9. Risks & Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| `rpgp` diverges from Proton's OpenPGP packet expectations on a real fixture | High | Interop fixture suite at every milestone; if blocking, fork `rpgp` locally rather than switching to cgo |
| **Late-2026/early-2027 crypto migration** breaks wire format mid-port | High | All crypto behind trait; pin work to JS SDK version; allocate buffer between M6 and M7 to absorb the migration. Personal-use scope means we can stop and rebase rather than ship broken |
| OpenAPI DTOs drift (JS regenerates from `api/openapi-*.json` outside this repo) | Med | Vendor a copy of the OpenAPI files at port time; track diffs |
| Rate limiting from over-eager event polling | Med | Use event subscription exclusively. The event loop's own interval poll against the Events endpoint (JS-faithful cadence, see M6 above) is sanctioned; assert in tests that `getNode`/`iterateFolderChildren` (the *node/listing* endpoints) are never called on a timer, only on focus-change or in response to a dispatched `DriveEvent` |
| tmux + crossterm mouse/paste edge cases | Low | Manual test matrix in M7 (tmux 3.4, alacritty, kitty, wezterm) |
| Scope creep into sharing/photos | Med | Stubbed modules return `Error::NotImplemented`; PRD explicit in §3 |

## 10. Open Questions

_None blocking v1._ The two earlier candidates resolved:

- **Rate-limiting risk**: Proton's README sanctions `external-drive-{name}@…` as the third-party identifier and applies the same per-session/per-user limits as first-party. Trip-wires are spoofing, polling, and recursive traversal, all of which the SDK contract already prevents. No special blocking for third-party SDKs.
- **`rpgp` packet coverage**: Proton's JS SDK runs SEIPDv1 by default and feature-flag-gates SEIPDv2/AEAD per-key. v1 ships SEIPDv1-only (well-supported in `rpgp` for years); SEIPDv2 deferred to M2.5 and validated against AEAD-on JS fixtures before promotion. Crypto-refresh migration in 2026/2027 will force SEIPDv2 + v6 keys eventually, handled by the trait seam.

## 11. Acceptance Criteria (gate to "v1 done")

- `cargo test -p proton-drive` exercises upload/download against a recorded HTTP fixture; passes on linux + macos in CI.
- Interop test: a file uploaded with `proton-drive` is downloadable and verifies in the JS SDK, and vice versa, for 5 representative fixtures (small text, 1 GB binary, UTF-8-named file, deeply-nested path, file with thumbnail).
- `pdtui` runs in a tmux pane for 30 minutes uploading/downloading without redraw artefacts, leaks, or unhandled tokio task panics.
- Zero `unwrap`/`expect`/`panic!` on the public crate API surface (clippy lint enforced).
- `x-pm-appversion` header verified on every outbound request via integration test.

---

**Next step on approval:** spin up the workspace skeleton (M0) and vendor the protobufs + OpenAPI files from `cs/sdk/src/protos/` and the (external) `api/openapi-*.json`.
