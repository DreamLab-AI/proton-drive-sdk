# Vendored upstream snapshot

This directory is a **read-only vendored snapshot** of the upstream
[ProtonDriveApps/sdk](https://github.com/ProtonDriveApps/sdk) monorepo. It is
consumed by the Rust port for wire-format ground truth (build-time protobuf
codegen, JSON DTO shapes, event semantics) and as the primary behavioural
reference (see `docs/adr/` ADR-0001). Nothing under `reference/` is built or
installed as part of this repo's own build — `npm install` / dotnet restore /
gradle sync are intentionally never run here.

## Provenance

| Field | Value |
|---|---|
| Upstream repository | `https://github.com/ProtonDriveApps/sdk` |
| Pinned commit | `f24961619f849271a013926609b4a889bb57a877` |
| Commit date | 2026-06-30 (`fix(client-js): allow report of file/folder inside a direct shared folder`) |
| Vendoring date | 2026-07-05 |
| TS/JS SDK version (CHANGELOG top entry at pin) | `js/v0.19.0` (2026-06-25) — upstream `main` had advanced to `js/v0.19.1` by 2026-07-05, a few commits ahead of this pin on the JS side |
| C# SDK version (CHANGELOG top entry at pin) | `cs/v0.19.0` (2026-06-30) |

The tarball was fetched via `gh api repos/ProtonDriveApps/sdk/tarball/<sha>`
(a GitHub codeload export — no `.git` metadata is present in this snapshot).

## Layout change: previous snapshot vs. this one

The previous vendored snapshot (`js/v0.15.2`, `cs/v0.14.5`) used a flat
`reference/{js,cs,kt,swift}` layout. Upstream restructured its own tree between
then and this pin (see `chore: move JS & C# into sdk-client` / `chore: move
Kotlin & Swift bindings into incubating` in `client/cs/CHANGELOG.md`). This
vendoring mirrors upstream's current layout **verbatim** — no repackaging:

| Old path (pre-2026-07-05) | New path (this snapshot) |
|---|---|
| `reference/js/sdk/` | `reference/client/js/` |
| `reference/cs/sdk/` | `reference/client/cs/` |
| `reference/cs/headers/` | `reference/client/cs/headers/` |
| `reference/kt/` | `reference/incubating/client/kt/` |
| `reference/swift/` | `reference/incubating/client/swift/` |
| *(did not exist)* | `reference/cli/` — new upstream CLI package |
| *(did not exist)* | `reference/incubating/account/{cs,js}/` — new incubating account-linking SDKs |
| *(did not exist)* | `reference/config/{cs,js}/` — new shared lint/build config |
| *(did not exist)* | `reference/js/cli/` — stray upstream placeholder dir (`README.md` only) present at this pin; not a duplicate of `reference/client/js/` |

Root-level upstream files (`README.md`, `LICENSE.md`, `SECURITY.md`,
`Proton.Drive.Sdk.slnx`, `nuget.config`, `.editorconfig`, `.gitignore`) are
vendored as-is at `reference/`.

## Protobuf source relocation

The two-file proto layout (`proton.sdk.proto` imported by
`proton.drive.sdk.proto`) was merged upstream into a **single file**,
`proton.drive.sdk.proto`, now entirely under `package proton.drive.sdk;` with
no `proton.sdk` package remaining. New location:

```
reference/client/cs/src/protos/proton.drive.sdk.proto
```

(previously `reference/cs/sdk/src/protos/{proton.sdk.proto,proton.drive.sdk.proto}`).

`rust/crates/proton-drive-api/build.rs` and `src/lib.rs` were updated
accordingly — see their own comments for detail. `cs/v0.18.1` additionally
"aligned upload and download error enums with proto order" upstream
(`DownloadError`/`UploadError` gained a trailing `*_VALIDATION_ERROR` variant);
this is additive to the generated Rust enums and required no changes to our
hand-written JSON DTOs, which are a separate, unaffected wire path.

## What is NOT here

`tests/fixtures/wire/` (cross-language wire-format fixtures consumed by
`rust/crates/proton-drive-crypto/tests/wire_format.rs`) lives outside
`reference/` at the repo root and is untouched by this vendoring.
