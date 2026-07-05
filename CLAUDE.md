# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

A **Rust implementation of the Proton Drive SDK plus `pdtui`** (a two-pane
terminal file browser), built for personal use against the owner's own Proton
Drive account. The Rust project under [`rust/`](./rust/) is the primary
codebase. The upstream native SDKs (TypeScript, C#, Kotlin, Swift) that the port
follows for wire-format fidelity live under [`reference/`](./reference/) and are
read-only reference, not the focus of work here.

Status: working MVP, **unaudited**. The full crypto-backed transfer path is
live-validated (SRP login → list → upload → byte-identical download), including
nested files and large real-world content. Always disclaim the unaudited status
honestly; never claim audit-grade security.

## Repository Layout

| Path | Contents |
|---|---|
| `rust/` | The project — Cargo workspace (edition 2024). SDK crates `proton-drive-*` + the `pdtui` app under `rust/apps/pdtui/`. |
| `docs/` | PRDs, domain model, ADRs (`docs/adr/`) for the port. |
| `tests/fixtures/wire/` | Cross-language wire-format fixtures; consumed by `rust/crates/proton-drive-crypto/tests/wire_format.rs` via a repo-root-relative path (`../../../tests/fixtures/wire`). **Do not move.** |
| `scripts/` | Dev tooling: `setup.sh` (gate), `configure-session.sh`, `run-probes.sh`, `js-probe.mjs` (JS cross-check). |
| `reference/` | Vendored upstream Proton SDKs monorepo — `reference/client/{js,cs}`, `reference/incubating/client/{kt,swift}`. Wire-format source of truth. See `reference/VENDORED.md` for the pinned commit and layout mapping. |

## Build & Test (the Rust project)

All commands run from `rust/`.

```bash
cargo build --release -p pdtui     # build the TUI/CLI binary
cargo test --workspace             # unit + wire-fixture tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all                    # (CI runs --check)

./target/release/pdtui login       # live SRP login → OS keyring
./target/release/pdtui mvp         # headless live round-trip acceptance test
./target/release/pdtui             # interactive two-pane browser
```

Quality gate (run before committing):
`cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`

The `proton-drive-api` crate runs **build-time protobuf codegen** from
`reference/client/cs/src/protos/` (see `rust/crates/proton-drive-api/build.rs`).
Moving `reference/client/cs` requires updating that path.

### Rust guardrails (non-negotiable)
- `unwrap_used` / `expect_used` / `panic` are **denied workspace-wide** for
  runtime code. Test modules opt out with `#[allow(...)]`; the `build.rs` opts
  out because a build script *should* abort loudly.
- The crypto trait seam is the only boundary that may touch `pgp::*` — direct
  `pgp` references outside `proton-drive-crypto` are a bug.
- DTOs are JSON, not protobuf. The `reference/client/cs/src/protos/` file exists for
  C-ABI marshalling to kt/swift and as the Rust wire-type codegen source only.
- No polling. Event subscription is the only sync mechanism.

## Operational constraints (apply to any Proton Drive client, including pdtui)
- `x-pm-appversion` is `external-drive-pdtui@{semver}-stable`. Never spoof a
  first-party header.
- All HTTP must hit official Proton endpoints — no proxying.
- Rate limits are shared with first-party clients; respect caching, backoff,
  parallelism limits.
- A breaking cryptographic-model migration is targeted late-2026/early-2027.
- Personal use only — no publishing to crates.io, no binary releases (ADR-0007).

## Reference SDKs (`reference/`, read-only context)

Independent upstream implementations the port mirrors. Touch only when checking
wire-format ground truth; the JS SDK is the primary behavioural reference for
the Rust port (see ADR-0001).

- **TypeScript** — `reference/client/js/`. Entry `ProtonDriveClient`
  (`protonDriveClient.ts`); only `src/index.ts` re-exports are public API,
  `internal/` mirrors domain concerns (`nodes/`, `upload/`, `download/`,
  `events/`, `apiService/`). Crypto + cache + account are host-injected.
  Changelog `reference/client/js/CHANGELOG.md`.
- **C#** — `reference/client/cs/`. `Proton.Sdk` (base) + `Proton.Drive.Sdk`
  (Drive). `*.CExports` produce the C ABI for kt/swift. Changelog
  `reference/client/cs/CHANGELOG.md` (source of truth for kt/swift).
- **Kotlin / Swift** — `reference/incubating/client/kt/`,
  `reference/incubating/client/swift/ProtonDriveSDK/`. Bindings over the C#
  AOT native library; no business logic of their own.
- **CLI** — `reference/cli/`, new since the previous vendored snapshot; not
  used by this port.
