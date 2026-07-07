# ADR-0012: Wire-format validation via JS-encoded fixtures

**Status:** accepted, 2026-05-28.
**Context milestone:** MB.
**Driver:** audit `[HIGH]` finding: pure rpgp self-roundtrip proves nothing about Proton interop.

## Decision

Before any upload/download merge is allowed (gates MD and ME), commit a small set of **JS-encoded fixtures** to `tests/fixtures/wire/`. The Rust crypto layer is validated against these as the source of truth.

## Fixture set

1. **Encrypted-and-signed message** (`seipdv1_signed.bin` + `seipdv1_signed.meta.json`):
   - Plaintext: 256 bytes random (committed as `seipdv1_signed.plaintext.bin`).
   - Encrypted by OpenPGP.js using SEIPDv1, AES-256, with PKESK to one Ed25519+X25519 key (committed `key_pub.asc`).
   - Signed by a separate Ed25519 key (committed `signer_pub.asc`).
   - Rust must: decrypt → byte-equal plaintext; verify → `VerificationStatus::Ok`.

2. **Re-encryption round-trip** (no committed output, produced by the test):
   - Rust encrypts the plaintext with the same session key + signing key.
   - A small Node script `tests/fixtures/wire/decrypt_with_openpgpjs.mjs` ingests Rust's ciphertext and decrypts using OpenPGP.js. Test passes if Node returns the same plaintext.

3. **Tampered ciphertext** (`seipdv1_tampered.bin`):
   - Same as #1 but with one byte of the SEIPD body flipped.
   - Rust must return `Error::IntegrityCheckFailed` (or rpgp's equivalent), NOT silently decrypt to garbage.

4. **Wrong-signer signature** (`seipdv1_wrong_signer.bin`):
   - Signature swapped for one made by a different key.
   - Rust must return `VerificationStatus::SignatureWrongSigner`.

5. **SRP test vector** (deferred to MA if simple, else MB):
   - `proton-srp` crate ships RFC vectors. Plumb one into a unit test in `proton-drive-crypto` to lock down the SRP wiring.

## Fixture generation

A one-shot Node script `tests/fixtures/wire/generate.mjs` produces fixtures #1, #3, #4 from `key_pub.asc` + `signer_priv.asc`. Committed alongside the fixtures so they are reproducible. The signer's private key is committed because it signs only test data, explicitly **NOT** any production key. README in `tests/fixtures/wire/` makes this loud.

## What this catches

| Failure mode | Caught by |
|---|---|
| rpgp emits packets in wrong order (e.g., OnePassSig after Literal) | #1: Rust decrypts JS-encoded message |
| rpgp encodes SEIPD with non-canonical packet framing JS rejects | #2: JS decrypts Rust-encoded message |
| rpgp silently strips MDC/integrity bits on tamper | #3 |
| Signature verification accepts unrelated keys | #4 |
| SRP modulus/exponent endian-swap | RFC vector |

## What this does NOT catch

- Format drift introduced by a future rpgp upgrade: re-run the harness in CI on rpgp version bumps, and pin rpgp in `Cargo.toml`. <!-- slop-ignore: "harness" = the literal tests/fixtures/wire/ test harness, not figurative -->
- Server-side validation that doesn't match the OpenPGP standard exactly (Proton has been known to be strict on certain subpackets): only live integration testing finds these.
- Performance regressions: out of scope.

## Quality gates

- Workspace gains a `wire-format` test target in `proton-drive-crypto/tests/wire_format.rs`.
- CI runs the test as part of `cargo test --workspace`.
- Generation script `generate.mjs` runs as a `cargo xtask wire-regen` (informational; not in CI).

## Costs

- Adds a Node toolchain dependency for fixture regeneration (one-shot, not CI). Acceptable: Node is already required for `js-probe.mjs`.
- Adds ~3 KB of fixture data to the repo. Acceptable.

## References

- Audit finding (deep code-quality review, `[HIGH]` "encrypt_and_sign double-wraps…")
- OpenPGP.js docs on SEIPDv1 emission
- rpgp `MessageBuilder` source for actual packet ordering
