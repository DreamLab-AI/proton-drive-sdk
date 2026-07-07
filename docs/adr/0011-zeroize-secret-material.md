# ADR-0011: Zeroize all credential and key material on drop

**Status:** accepted, 2026-05-28.
**Context milestone:** MA.
**Driver:** code-quality audit `[HIGH]` finding: secrets remain in heap after drop, observable by post-mortem RAM inspection or by stale pages making it to swap.

## Decision

All types holding credential or key material implement `ZeroizeOnDrop` (via the `zeroize` crate, derive-feature). The convention:

- `String` holding a secret → `Zeroizing<String>`
- `Vec<u8>` holding a secret → `Zeroizing<Vec<u8>>`
- A struct whose fields are all secret → `#[derive(ZeroizeOnDrop)]` plus `#[derive(Zeroize)]` so manual zeroing on `clear()` is available
- Public-key material is **not** zeroized (public).
- `PrivateKey.armored` is **not** zeroized because rpgp's armour format wraps the key material as encoded text, and the passphrase that decrypts it is the real secret; we zeroize `passphrase` instead.

## Types affected

| Type | Crate | Change |
|---|---|---|
| `Credentials` | `apps/pdtui/src/auth.rs` | `Zeroizing<String>` on access_token / refresh_token / key_password / uid stays plain |
| `PrivateKey.passphrase` | `proton-drive-crypto` | `Zeroizing<String>` |
| `SessionKey.data` | `proton-drive-crypto` | `Zeroizing<Vec<u8>>` |
| `LoginForm.password` | `apps/pdtui/src/app.rs` | `Zeroizing<String>` |
| `SrpExchange.client_proof`, `expected_server_proof`, `client_ephemeral` | `proton-drive-crypto` | leave plain: public over the wire after use, not worth the complexity |
| `SessionState` (new) | `apps/pdtui/src/session.rs` | derive `ZeroizeOnDrop`; individual `Zeroizing<…>` fields |

## What is NOT done

- `subtle::ConstantTimeEq` on the server-proof comparison (`apps/pdtui/src/auth.rs:109`): a separate concern (timing-side-channel hygiene). Doing it here too because the cost is one line and the audit flagged it: change `expected != actual` to `expected.as_bytes().ct_eq(actual.as_bytes()).into()`.
- Memory-locking (`mlock`) to keep pages out of swap. Linux desktop scope; we accept the swap risk for personal use.
- Stack-allocated secrets: rpgp owns its own buffers internally; we trust them not to leak.

## Quality gates

- Add `zeroize = { version = "1.8", features = ["zeroize_derive", "derive"] }` and `subtle = "2.6"` to the workspace.
- Existing tests must still pass: zeroize is invisible at the type level for `Zeroizing<T>` because it derefs to `&T`.
- **`proton-drive-crypto/tests/zeroize_smoke.rs` (proposed above) was never implemented, caveat added 2026-07-05, see `docs/audit-2026-07-05.md`.** Verifying a zeroed buffer by "raw-pointer inspection" of memory the type system considers already dropped is inherently `unsafe` Rust (there is no safe API to read a stack/heap slot after its owning value's lifetime ends). Every crate in this workspace, including `proton-drive-crypto` where this test would live, carries `#![forbid(unsafe_code)]` at the crate root, and that blanket "no unsafe anywhere in this codebase" posture is a deliberate project-wide invariant, not an accident: introducing the one `unsafe` block this smoke test needs (even opt-in, behind a feature flag, in a test-only file) would puncture that invariant for the one crate where the crypto trait seam makes it matter most. We chose not to. Zeroization correctness for `Zeroizing<T>`/`ZeroizeOnDrop` therefore rests on trusting the upstream `zeroize` crate's own test suite and its use of volatile writes (see "What this does and does not protect against" below), not a local, repo-owned verification test. If this is ever revisited, it would need to live in its own separate, clearly-`unsafe`-scoped crate outside the `proton-drive-*` workspace member set, not inside `proton-drive-crypto`.

## What this does and does not protect against

| Threat | Mitigated? |
|---|---|
| Core dump / post-mortem RAM dump after process exit | Yes, for the protected fields |
| Swap-out of secret page during long idle | Partially: Linux may have already paged it; `mlock` would be needed |
| Hostile process with same UID reading our memory | No: root or same-UID attackers have ptrace |
| Coredump *during* a request while secrets are live | No: cannot mitigate |
| Compiler reordering / DCE of the zeroize call | No: `zeroize` crate uses volatile writes specifically to defeat this |

## References

- Audit finding: code-quality review of `fdc9db7`, `[HIGH]` "No zeroize on credential material"
- `zeroize` crate documentation
