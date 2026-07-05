# Rust Port — Handoff to Linux Workstation

You're picking up the Rust port of the Proton Drive SDK + `pdtui` TUI on the user's Linux machine, where they have access to their live Proton Drive account.

**Read these first, in order:**

1. [`docs/PRD-rust-port-and-tui.md`](docs/PRD-rust-port-and-tui.md) — Product requirements, milestones M0–M7, risks
2. [`docs/adr/README.md`](docs/adr/README.md) — Architecture decisions (port source, crypto choice, scope)
3. [`docs/domain-model.md`](docs/domain-model.md) — Bounded contexts, ubiquitous language, aggregate→module map
4. [`docs/IMPLEMENTATION-STATUS.md`](docs/IMPLEMENTATION-STATUS.md) — **What's done, what's stubbed, what needs live validation**

## TL;DR — where things stand (2026-07-05)

All M0–M7 milestones are implemented and the full crypto-backed transfer path
was **live-validated** against the real Proton API: SRP login → list → upload →
byte-identical download, including nested files via parent-chain node-key
derivation. The live blockers B1 (HMAC name hash) and B2 (nested **download**)
are resolved. Since that live validation, a seven-agent audit mesh (`wp1`–`wp9`)
reviewed the codebase against the JS SDK reference, confirmed 38 findings, and
landed fix packages for all of them — see
[`docs/audit-2026-07-05.md`](docs/audit-2026-07-05.md) for the summary and
`docs/IMPLEMENTATION-STATUS.md` for the resulting per-milestone state. **The
live round-trip has not been re-run since those fixes landed** — treat the
table below as "unit/wire-tested," not "freshly live-proven," until someone
re-runs `pdtui mvp` against a real account.

| Layer | State | Trustable? |
|---|---|---|
| Workspace + traits + error model | Complete | Yes |
| JSON DTOs (list/upload/download/events) | Complete (happy-path subset) | Yes — roundtripped live pre-audit |
| `ReqwestHttpClient` (retry/backoff/headers, 429+`Retry-After`) | Complete | Yes — live API pre-audit; unit-tested post-audit |
| Crypto — encrypt/decrypt/sign/verify | Complete | Yes — JS-encoded wire fixtures + tamper/wrong-signer rejection |
| SRP auth (`proton-srp` 0.8.2) | Complete | Yes — live login pre-audit |
| `SessionManager` refresh (ADR-0010) | Complete | Yes — unit-tested; single-flight coalescing added post-audit |
| Upload block protocol | Complete for share-root parents; **nested-folder upload still unresolved** (`upload.rs::resolve_parent_context` only derives the correct parent hash key when the parent is the share root) | Root-parent case: yes, live byte-identical round-trip pre-audit. Nested-parent case: no — known gap, see `docs/IMPLEMENTATION-STATUS.md` B2 |
| Download block protocol | Complete | Yes — root + nested (646 MB verified); manifest verified after write |
| Events subscription | **Done — SDK consumer wired into pdtui's remote pane** (`events_bridge.rs`), graceful fallback to pull-on-focus if subscription fails | Yes — unit-tested; not yet re-proven live post-wiring |
| `pdtui` local + remote panes | Complete | Yes — remote pane wired to real `PdtuiAccount`, now with live-event-driven refresh |

## Integrity / signature model (current behaviour)

Download mirrors the JS SDK: blocks are guarded by their SHA-256 ciphertext
hash; the manifest signature is verified **after** the data is delivered. A
*missing* manifest signature aborts before any byte is written; a
*present-but-unverifiable* one (signer key rotated out of the account) delivers
the bytes and reports `DownloadStats.signature_verified = false` rather than
discarding a file the official client would still download. The root round-trip
asserts `signature_verified == true` against our own freshly-signed revision.

**Never commit real account secrets** — `.gitignore` excludes `rust/.env`,
`rust/fixtures/auth/*`, and generic credential patterns. pdtui's live session
lives in the OS keyring, not a file.

## Recommended order on the Linux box

1. Run the gate (from `rust/`): `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.
2. `pdtui login` (SRP is live; session → OS keyring), then `pdtui mvp` for the headless list→upload→download→byte-compare acceptance check. **This is the re-validation the wp1–wp9 fix packages still need** — nothing in this repo has confirmed live behaviour since they landed.
3. Boot interactive `pdtui`, confirm the remote pane lists MyFiles root, and confirm the live-event bridge refreshes it on a remote change (rename a node from the web UI; the pane should update within the poll cadence, ~30s, without a manual refresh — see `docs/IMPLEMENTATION-STATUS.md` M6).
4. Remaining known gaps per `docs/IMPLEMENTATION-STATUS.md`: B2 upload-half (nested-folder upload), B8 (v1→v2 endpoint migration, deferred).
5. M6 events consumer is done (SDK + pdtui wiring); nothing left here beyond re-validating it live per step 3.

## How to talk to the agents on the Linux machine

This handoff doc is the entry point. Reference it from any new agent invocation:

```
Read HANDOFF.md, then docs/IMPLEMENTATION-STATUS.md.
The current task is: <thing you want>
The constraint is: <verifiable, no fabrication; ask for fixtures if needed>
```

Skills/agents already wired into the user's setup:
- `claude-code-guide` for Claude Code itself
- `agentic-qe` (broken in container, working on host — try it on Linux)
- ruflo / ruvector swarm tools (`mcp__ruvector__*`)

DTOs are JSON, not protobuf (see Guardrails below). M0–M7 are implemented
(originally landed on `rust-port`, since restructured onto `main` with
upstream SDKs moved under `reference/`; see `git log`: MB–MH waves, then the
`audit/gap-fill` mesh `wp1`–`wp9`). Remaining work is the B2 (upload-half) and
B8 gaps in `docs/IMPLEMENTATION-STATUS.md`, plus live re-validation of the
wp1–wp9 fixes — not new milestones. See `docs/audit-2026-07-05.md`.

## Guardrails worth keeping

- `unwrap_used`/`expect_used`/`panic` are **denied workspace-wide**. Tests opt out with `#[allow(...)]` on the test module.
- `cargo fmt --check` is part of CI. Run `cargo fmt --all` before committing.
- The crypto trait seam is non-negotiable — direct `pgp::*` references outside `proton-drive-crypto` are a bug.
- The DTOs are JSON. The `reference/client/cs/src/protos/` file is the C-ABI marshalling source for kt/swift and the build-time wire-type codegen source for `proton-drive-api` (`build.rs`).
- No *ad hoc* polling of node/listing state outside the official Events API. The event-loop consumer itself (`spawn_volume_event_loop`) legitimately polls the Events endpoint on an interval with Fibonacci backoff — that mirrors the JS SDK's own `eventManager.ts` exactly (Proton Drive has no push/websocket transport for events) and is not a guardrail violation. What the PRD invariant forbids is a client re-listing folders or re-fetching nodes on a timer instead of reacting to the Events feed.
- `x-pm-appversion = external-drive-pdtui@{semver}-stable`. Never spoof a first-party header. The middleware enforces this; don't bypass.
- Personal use only. No publishing to crates.io, no binary releases, no fork-promotion. See ADR-0007.
