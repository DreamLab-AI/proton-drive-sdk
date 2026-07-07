# ADR-0006: SEIPDv1 by default; SEIPDv2/AEAD-GCM deferred to M2.5

| | |
|---|---|
| Status | Accepted |
| Date | 2026-05-27 |
| Context tag | `proton-drive-crypto` |
| Related | ADR-0002 |

## Context
Proton's JS SDK (`openPGPCrypto.ts`) takes an `enableAeadWithEncryptionKeys` option on every encryption call and passes `ignoreSEIPDv2FeatureFlag: !options.enableAeadWithEncryptionKeys` to the underlying crypto. The default `FeatureFlagProvider` (`NullFeatureFlagProvider`) returns no flags, so the runtime path is SEIPDv1 unless the host opts in per-key.

The late-2026/early-2027 Proton crypto migration is expected to make SEIPDv2 + v6 keys mandatory.

## Decision
The Rust crypto impl ships **SEIPDv1 only** in v1. The `OpenPgpCrypto` trait carries the same `enable_aead_with_encryption_keys` option but `proton-drive-crypto::RpgpCrypto` ignores it during M2 and may emit an error if set.

**Enforced explicitly, added 2026-07-05 (`docs/audit-2026-07-05.md`):** this
was originally an incidental consequence of the decrypt path only ever
constructing a `PlainSessionKey::V3_4`, which is not a typed, testable
guarantee — a future change that fed a V6 session key through the same path
would have silently stopped rejecting SEIPDv2. `proton-drive-crypto` now has
a dedicated `reject_seipd_v2` guard (`crates/proton-drive-crypto/src/lib.rs`)
that parses the packet stream and inspects each `SymEncryptedProtectedData`
packet's own version tag directly, returning `CryptoError::AeadNotSupported`
for anything but version 1, called explicitly from the decrypt entry point
before rpgp's own (incidental) rejection would otherwise fire.

SEIPDv2 / AEAD-GCM lands in **M2.5** as a separate sub-milestone, gated by:
1. JS-emitted AEAD fixtures available for interop validation.
2. `rpgp` AEAD-GCM path tested against those fixtures.

## Consequences
- M2 ships faster: SEIPDv1 is well-trodden in `rpgp`.
- We can interoperate with **today's** Proton Drive (server happily accepts SEIPDv1 from properly identified clients).
- Reading messages encrypted by AEAD-enabled peers will fail in v1; acceptable for single-user personal use until M2.5.
- When the 2026/2027 migration arrives, M2.5 becomes mandatory; the trait seam lets us swap without ripping out call sites.

## Alternatives considered
- **AEAD from day one**, rejected: doubles the M2 surface area and `rpgp` AEAD coverage needs fixture validation we don't have yet.
- **Skip SEIPDv1 entirely**, rejected: server still serves SEIPDv1 for legacy keys; we'd fail to read existing account content.
