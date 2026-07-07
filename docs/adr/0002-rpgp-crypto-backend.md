# ADR-0002: Use `rpgp` (pure Rust) as the OpenPGP crypto backend

| | |
|---|---|
| Status | Accepted |
| Date | 2026-05-27 |
| Context tag | `proton-drive-crypto` |
| Related | ADR-0006 (SEIPDv1 default) |

## Context
The SDK's crypto layer must perform: Curve25519 key generation, multi-recipient session-key encryption, SEIPDv1 symmetric encryption (default), SEIPDv2/AEAD-GCM (feature-flag-gated), detached and inline signatures, critical signature notations (`signatureContext`), password-encrypted session keys, and armoured/binary I/O. The full required surface is captured in `client/js/src/crypto/interface.ts`.

Proton's first-party clients use **GopenPGP** (Go). Wrapping it from Rust requires cgo bindings, a Go runtime, cross-compile toolchains per target triple, and inherits whatever licence terms the Go side imposes.

This is a **personal-use project against the project owner's own Proton Drive account**. There are no external users to maintain byte-equivalence with: only the project owner's own account, also accessed via official clients.

## Decision
Implement `OpenPgpCrypto` over **`rpgp`** (pure Rust, MIT/Apache-2.0). No cgo. No Go runtime. No GopenPGP wrapper.

Keep the trait seam so the impl can be swapped without touching call sites if `rpgp` ever proves inadequate.

## Consequences
- Cross-compiles trivially. Single static binary.
- Licence is clean (MIT/Apache-2.0 compatible with our MIT use).
- We carry risk that `rpgp` packet emission diverges from what Proton's servers or peer clients expect. Mitigated by an **interop fixture suite** run at every milestone (upload from JS / download with Rust, and inverse).
- If `rpgp` lags on a feature Proton requires (notably across the 2026/2027 crypto-refresh migration), we fork locally, file upstream, or temporarily swap impls.
- We do **not** bind to `@protontech/crypto` (the JS wrapper): irrelevant in Rust.

## Alternatives considered
- **GopenPGP via cgo**, rejected: build complexity, licence surface, no benefit for personal scope, defeats "pure Rust" goal.
- **sequoia-openpgp**, rejected for v1: heavier API, GPL2/LGPL2 implications worth avoiding even at personal scope, more opinionated about workflow than `rpgp`.
- **Hand-rolled OpenPGP**, rejected: insane.
