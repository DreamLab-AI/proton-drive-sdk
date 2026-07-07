# ADR-0001: Port from the TypeScript SDK, not the C# SDK

| | |
|---|---|
| Status | Accepted |
| Date | 2026-05-27 |
| Context tag | workspace-wide |

## Context
Two independent reference implementations exist: `js/sdk/` (TS) and `cs/sdk/` (C#). Each is a full from-scratch implementation of Drive business logic. Kotlin and Swift wrap C# via the C ABI and are not candidates as a port source.

Quantitative comparison at port time:

| | JS | C# |
|---|---|---|
| Commits touching the tree | 394 | 258 |
| LoC (excluding generated types) | ~42,859 | ~21,293 |
| Latest version | 0.15.2 (2026-05-19) | 0.14.5 (2026-05-18) |
| Recent feature work | photos drafts, public-link decryption, CLI events, retry policy | mostly bug fixes and telemetry detail |

## Decision
The Rust port uses **TypeScript SDK v0.15.2** as the reference. Where the C# SDK has solved an adjacent problem we will not re-derive (notably: protobuf schemas in `cs/sdk/src/protos/`, the SQLite cache schema if pulled forward), reuse the C# artefact directly.

## Consequences
- File-to-file mapping is `client/js/src/internal/{nodes,events,upload,download}/*` → `rust/crates/proton-drive-core/src/{nodes,events,upload,download}.rs`. Reviewers map by sibling.
- Async model translates 1:1: JS `AsyncGenerator` → Rust `Stream`, `AbortSignal` → `CancellationToken`, `ReadableStream` → `AsyncRead`.
- We inherit the JS public-interface taxonomy and error names: easier to cross-reference, harder to invent our own.
- C# crypto choices (BouncyCastle vs PGPCore vs whatever) do **not** constrain us.

## Alternatives considered
- **C# as source**, rejected: fewer commits, smaller surface, less recent feature work, AOT/native-library complexity bleeds into the port design.
- **Derive from protobuf schemas alone**, rejected: protobuf covers wire format but not the encryption lifecycle, key caching, or event subscription patterns that make the SDK behave correctly.
