# Wire-format validation fixtures

## WARNING: TEST-ONLY KEYS — NEVER USE IN PRODUCTION

The PGP keys committed here (`key_pub.asc`, `key_priv.asc`, `signer_pub.asc`,
`signer_priv.asc`) are **test fixtures generated once by `generate.mjs` and
committed to the repository**.

- They are NOT used in any Proton Drive account.
- They are NOT deployed anywhere.
- `key_priv.asc` uses an **EMPTY passphrase** — intentionally, for test
  simplicity. Never do this with any real key.
- They can be regenerated at any time by running `generate.mjs` again.
  The fixtures are re-committed after regeneration. Old fixtures are invalid
  and must be replaced in full.
- The private keys are committed **only** because they sign test data and have
  zero operational value — auditors: treat these like public test vectors.

## Purpose

These fixtures prove that the Rust `proton-drive-crypto` crate can decrypt and
verify messages produced by OpenPGP.js (the JS SDK's crypto layer), and vice
versa.  A pure Rust self-roundtrip would only prove internal consistency, not
interoperability with the actual Proton wire format.  Implements ADR-0012.

## Files

| File | Description |
|------|-------------|
| `key_pub.asc` | Ed25519+X25519 public key (encryption target) |
| `key_priv.asc` | Corresponding private key (EMPTY passphrase — TEST ONLY) |
| `signer_pub.asc` | Ed25519 signing public key |
| `signer_priv.asc` | Ed25519 signing private key (EMPTY passphrase — TEST ONLY) |
| `seipdv1_signed.plaintext.bin` | 256 bytes deterministic plaintext (seed: fixed string) |
| `seipdv1_signed.bin` | OpenPGP.js-encrypted+signed SEIPDv1 ciphertext |
| `seipdv1_signed.meta.json` | Metadata: key fingerprints, plaintext SHA-256 |
| `seipdv1_tampered.bin` | `seipdv1_signed.bin` with one SEIPD-body byte flipped |
| `seipdv1_wrong_signer.bin` | Re-signed with a throwaway key not in `signer_pub.asc` |
| `seipdv1_signed_compressed.bin` | Encrypted+signed with ZIP compression on the inner literal — the shape JS produces for ExtendedAttributes (`compress: true`, see `driveCrypto.ts` `encryptExtendedAttributes`). Same keys and plaintext as `seipdv1_signed.bin`. |
| `seipdv1_signed_compressed.meta.json` | Metadata for the compressed fixture (same plaintext SHA-256 as `seipdv1_signed.meta.json`) |
| `generate.mjs` | Script to regenerate all of the above |

## Regenerating

```bash
cd tests/fixtures/wire
npm i openpgp          # one-time install, not in any package.json
node generate.mjs
git add .
git commit -m "chore: regenerate wire fixtures"
```

Requires: Node >= 18 and the `openpgp` npm package (v6+).

## CI notes

The Rust integration tests in `rust/crates/proton-drive-crypto/tests/wire_format.rs`
load these fixtures at test time. They are checked into the repository so CI
needs no Node toolchain to run them.

The JS-decrypts-Rust roundtrip test (`#[ignore = "requires node + openpgp npm"]`)
is skipped in CI and must be run manually with `cargo test -- --ignored`.
