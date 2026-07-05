# Rust Port — Handoff to Linux Workstation

You're picking up the Rust port of the Proton Drive SDK + `pdtui` TUI on the user's Linux machine, where they have access to their live Proton Drive account.

**Read these first, in order:**

1. [`docs/PRD-rust-port-and-tui.md`](docs/PRD-rust-port-and-tui.md) — Product requirements, milestones M0–M7, risks
2. [`docs/adr/README.md`](docs/adr/README.md) — Architecture decisions (port source, crypto choice, scope)
3. [`docs/domain-model.md`](docs/domain-model.md) — Bounded contexts, ubiquitous language, aggregate→module map
4. [`docs/IMPLEMENTATION-STATUS.md`](docs/IMPLEMENTATION-STATUS.md) — **What's done, what's stubbed, what needs live validation**

## TL;DR — where things stand (2026-05-29)

All M0–M7 milestones are implemented and the full crypto-backed transfer path is
**live-validated** against the real Proton API: SRP login → list → upload →
byte-identical download, including nested files via parent-chain node-key
derivation. The live blockers B1 (HMAC name hash) and B2 (nested download) are
resolved. Full detail in `docs/IMPLEMENTATION-STATUS.md`.

| Layer | State | Trustable? |
|---|---|---|
| Workspace + traits + error model | Complete | Yes |
| JSON DTOs (list/upload/download/events) | Complete (happy-path subset) | Yes — roundtrips live |
| `ReqwestHttpClient` (retry/backoff/headers) | Complete | Yes — live API |
| Crypto — encrypt/decrypt/sign/verify | Complete | Yes — JS-encoded wire fixtures + tamper/wrong-signer rejection |
| SRP auth (`proton-srp` 0.8.2) | Complete | Yes — live login |
| `SessionManager` refresh (ADR-0010) | Complete | Yes — unit-tested |
| Upload block protocol | Complete | Yes — live byte-identical round-trip |
| Download block protocol | Complete | Yes — root + nested; manifest verified after write |
| Events subscription | DTOs only | n/a — pull-on-focus for MVP |
| `pdtui` local + remote panes | Complete | Yes — remote pane wired to real `PdtuiAccount` |

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
2. `pdtui login` (SRP is live; session → OS keyring), then `pdtui mvp` for the headless list→upload→download→byte-compare acceptance check.
3. Boot interactive `pdtui`, confirm the remote pane lists MyFiles root.
4. Remaining polish per `docs/IMPLEMENTATION-STATUS.md`: B3 (XAttr mtime edge cases), B6 (partial-write cleanup on download error).
5. M6 events consumer if live sync is wanted post-MVP.

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

DTOs are JSON, not protobuf (see Guardrails below). M0–M7 are implemented and
committed on `rust-port` (see `git log`: MB–MH waves). Remaining work is the
B1–B7 live-interop blockers in `docs/IMPLEMENTATION-STATUS.md`, not new
milestones — the agent mesh + QE pass that produced this state is complete.

## Guardrails worth keeping

- `unwrap_used`/`expect_used`/`panic` are **denied workspace-wide**. Tests opt out with `#[allow(...)]` on the test module.
- `cargo fmt --check` is part of CI. Run `cargo fmt --all` before committing.
- The crypto trait seam is non-negotiable — direct `pgp::*` references outside `proton-drive-crypto` are a bug.
- The DTOs are JSON. The `reference/client/cs/src/protos/` file is the C-ABI marshalling source for kt/swift and the build-time wire-type codegen source for `proton-drive-api` (`build.rs`).
- No polling. The PRD invariants say "event subscription is the only sync mechanism" — keep it that way.
- `x-pm-appversion = external-drive-pdtui@{semver}-stable`. Never spoof a first-party header. The middleware enforces this; don't bypass.
- Personal use only. No publishing to crates.io, no binary releases, no fork-promotion. See ADR-0007.
