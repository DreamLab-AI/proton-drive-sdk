# ADR-0005: Host-injected dependencies via traits (mirror JS construction contract)

| | |
|---|---|
| Status | Accepted |
| Date | 2026-05-27 |
| Context tag | `proton-drive` public API |

## Context
The JS SDK requires the host to inject everything not part of Drive business logic: HTTP client, two caches, account/address resolver, OpenPGP module, SRP module, telemetry, feature flags, latest-event-id provider. This deliberately omits authentication, session management, and user-address resolution from the SDK surface.

A Rust port has the same boundary problem and the same answer.

## Decision
The crate `proton-drive` exports **traits** for each injection seam. `ProtonDriveClient::new` takes a struct of `Arc<dyn Trait>` mirrors. No globals. No `tokio::sync::OnceCell`. No re-exporting `reqwest` as a public dep.

Trait list (one-to-one with JS `ProtonDriveClientContructorParameters`):
- `ProtonDriveHttpClient`
- `ProtonDriveCache<T>` (instantiated twice: entities, crypto)
- `ProtonDriveAccount`
- `OpenPgpCrypto`
- `SrpModule`
- `Telemetry` (optional)
- `FeatureFlagProvider` (optional)
- `LatestEventIdProvider` (optional)

Default implementations live in **separate crates** and are not required by the SDK crate itself:
- `proton-drive-crypto` provides `RpgpCrypto: OpenPgpCrypto`
- `proton-drive-cache` provides `MemoryCache: ProtonDriveCache<T>`
- `apps/pdtui` provides `ReqwestHttpClient` and `KeyringAccount` for our own use only

## Consequences
- The core crate has zero non-essential deps. Anyone can plug in their own HTTP/cache/crypto without forking.
- Auth stays out of `proton-drive`. `pdtui` is responsible for producing a configured `ProtonDriveAccount`.
- Mocking for tests is trivial: implement the trait.
- Two caches must be wired explicitly; we cannot collapse them into one because the JS SDK distinguishes their lifecycle semantics (crypto cache can be wiped without invalidating metadata).

## Alternatives considered
- **Single `Client` struct with concrete deps**, rejected: ties the SDK to specific HTTP/crypto choices, contradicts the JS contract.
- **Cargo features for swappable impls**, rejected: feature-flag combinatorics ugly; trait injection scales better.
- **Builder pattern with optional fields and panic on missing**, rejected: prefer typed compile-time enforcement via the options struct.
