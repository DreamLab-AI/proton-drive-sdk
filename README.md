# Proton Drive SDK — Rust port + `pdtui`

A Rust implementation of the Proton Drive SDK, plus **`pdtui`**, a two-pane
terminal file browser, built for personal use against your own Proton Drive
account.

> **Status: working MVP — unaudited.** The full crypto-backed transfer path is
> live-validated end to end (SRP login → list → upload → byte-identical
> download), including nested files and large real-world content. It has **not**
> had an independent security audit. Use it against your own account only. This
> project is **not affiliated with or endorsed by Proton AG.**

The upstream native SDKs (TypeScript, C#, Kotlin, Swift) that this port follows
for wire-format fidelity live under [`reference/`](./reference/) and remain the
authoritative source for those languages.

![pdtui (right) listing the same MVP round-trip files that the official Proton Drive web UI (left) shows — proof of a live upload/download against the real API.](rust/docs/pdtui-mvp-roundtrip.png)

`pdtui` (right) beside the official Proton Drive web UI (left): the same
`pdtui-mvp-*.txt` files appear in both panes, uploaded and downloaded
byte-identically through the live Proton API.

## What works (live-validated)

| Capability | State |
|---|---|
| SRP login + session resume (OS keyring) | Live |
| List folder children (decrypts names, sizes, types) | Live |
| Upload to the My Files root — wire-faithful armored protocol, HMAC name hash, XAttr | Live, byte-identical round-trip |
| Upload into a **nested** (non-root-parent) folder | **Known gap** — parent hash-key resolution only handles a share-root parent; not yet fixed |
| Download — block fetch, SHA-256 integrity, manifest verification | Live |
| Nested files — parent-chain node-key derivation for **listing/download** (depth ≥ 3) | Live (646 MB real file verified) |
| Signature-issue tolerance — rotated-out signer keys | Delivers data, flags `signature_verified=false` (matches the official client) |
| Event subscription | Live — background poll/backoff loop drives pdtui's remote pane; falls back to pull-on-focus if the subscription can't be established |

Integrity model mirrors the JS SDK: blocks are guarded by their SHA-256
ciphertext hash; the manifest signature is verified **after** the data is
delivered. A *missing* manifest signature aborts before any byte is written; a
*present-but-unverifiable* one (e.g. the signer's key was rotated out of the
account) delivers the data and reports `signature_verified = false` rather than
discarding a file the official client would still download.

A mesh audit found and fixed 38 issues across the areas above since the last
live round-trip; see [`docs/audit-2026-07-05.md`](docs/audit-2026-07-05.md)
for what changed and what's still deliberately deferred, and
[`docs/IMPLEMENTATION-STATUS.md`](docs/IMPLEMENTATION-STATUS.md) for the
current milestone-by-milestone state. The fixes are unit/wire-tested but not
yet re-proven against a live account.

## Quick start

```bash
cd rust
cargo build --release -p pdtui

# Log in with your real Proton credentials (SRP is live; session → OS keyring).
./target/release/pdtui login

# Headless end-to-end acceptance check (list → upload → download → byte-compare).
./target/release/pdtui mvp

# Interactive two-pane browser (local | remote).
./target/release/pdtui
```

Set `PDTUI_LOG=info` (or `debug`) for structured logs.

## Repository layout

| Path | Contents |
|---|---|
| [`rust/`](./rust/) | The project — Cargo workspace: SDK crates (`proton-drive-*`) + the `pdtui` app |
| [`docs/`](./docs/) | PRDs, domain model, and [ADRs](./docs/adr/README.md) for the port |
| [`tests/`](./tests/) | Cross-language wire-format fixtures consumed by the crypto tests |
| [`scripts/`](./scripts/) | Dev tooling — session config, JS cross-check probes |
| [`reference/`](./reference/) | Vendored upstream Proton SDKs monorepo (JS / C# / Kotlin / Swift) — wire-format source of truth. See [`reference/VENDORED.md`](./reference/VENDORED.md) for the pinned commit |
| [`HANDOFF.md`](./HANDOFF.md) | Engineering handoff and current status |

The Rust API crate generates its cross-language wire types at build time from
the protobuf in [`reference/client/cs/src/protos/`](./reference/client/cs/src/protos/).

## Operational requirements

These apply to **any** client of Proton Drive, including this one. Rate limits
are shared with first-party clients.

- **Identify honestly.** The client sets `x-pm-appversion` as
  `external-drive-pdtui@{semver}-stable`. Never spoof a first-party header.
- **Official endpoints only.** All HTTP hits the official Proton Drive domain;
  no proxying.
- **Event-based sync.** No ad hoc polling of node/listing state or recursive
  tree traversal. The event-loop consumer's own interval poll against the
  official Events endpoint (mirroring the JS SDK's `eventManager.ts` — Proton
  Drive has no push transport) is the one sanctioned exception.
- **No Proton branding.** This is an unofficial, third-party tool.

A breaking cryptographic-model migration is targeted by Proton for late
2026/early 2027; clients implementing only the current model will not
interoperate after it lands.

## Reference implementations

The upstream native SDKs under [`reference/`](./reference/):

- **TypeScript** — [`reference/client/js/`](./reference/client/js/) ([changelog](./reference/client/js/CHANGELOG.md)), published as [`@protontech/drive-sdk`](https://www.npmjs.com/package/@protontech/drive-sdk).
- **C#** — [`reference/client/cs/`](./reference/client/cs/) ([changelog](./reference/client/cs/CHANGELOG.md)).
- **Kotlin** & **Swift** — bindings wrapping the C# SDK ([`reference/incubating/client/kt/`](./reference/incubating/client/kt/), [`reference/incubating/client/swift/ProtonDriveSDK/`](./reference/incubating/client/swift/ProtonDriveSDK/)).

## License

MIT — see [LICENSE.md](./LICENSE.md). The MIT license governs the source in this
repository only; access to Proton's hosted services remains subject to Proton's
separate terms of service and operational policies.

Upstream SDK code under `reference/` is Copyright (c) 2026 Proton AG.
