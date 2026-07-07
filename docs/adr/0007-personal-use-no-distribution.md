# ADR-0007: Personal-use scope, no distribution channels

| | |
|---|---|
| Status | Accepted |
| Date | 2026-05-27 |
| Context tag | workspace-wide |

## Context
The project owner wants a Rust SDK + TUI for their **own** Proton Drive account. Proton's Operational Requirements (root `README.md`) permit non-commercial personal projects under specified conditions. There is no plan to publish to crates.io, GitHub releases, package managers, or to onboard other users.

## Decision
- Crate is **not** published to crates.io.
- `pdtui` binary is **not** released. Built and run from source by the project owner.
- `x-pm-appversion` follows Proton's mandated pattern: `external-drive-pdtui@{semver}-stable`. Honest identification, never spoofed.
- No CI publishing step. No homebrew tap. No AppImage.
- Licence remains MIT (matches upstream SDK).

## Consequences
- Tight scope. We can drop features Proton's first-party clients have to ship (multi-user, internationalisation polish, accessibility hardening, telemetry to Proton).
- No backward-compat obligation. Breaking changes between commits are fine.
- The 2026/2027 crypto migration is a "we'll fix it when we hit it" risk, not a release-blocking obligation.
- If a future user appears we re-open scope; document it then with a superseding ADR.
- We must not publish or share built binaries, since rate-limit policy says version-specific blocks are possible and we don't want our identifier associated with traffic we don't control.

## Alternatives considered
- **Publish for general use**, rejected: Proton explicitly disallows commercial third-party use until GA; even non-commercial publishing brings support and migration obligations.
- **Open-source on GitHub but no binary release**: possible later; not in scope today.
