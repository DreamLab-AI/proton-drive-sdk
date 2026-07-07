# Architecture Decision Records

| ID | Title | Status |
|---|---|---|
| [0001](0001-port-from-js-sdk.md) | Port from the TypeScript SDK, not the C# SDK | Accepted |
| [0002](0002-rpgp-crypto-backend.md) | Use `rpgp` (pure Rust) as the OpenPGP backend | Accepted |
| [0003](0003-in-memory-cache-defer-sqlite.md) | In-memory cache for v1, SQLite deferred behind explicit triggers | Accepted |
| [0004](0004-tui-stack-ratatui.md) | TUI on ratatui + crossterm + tokio | Accepted |
| [0005](0005-trait-injected-dependencies.md) | Host-injected dependencies via traits | Accepted |
| [0006](0006-seipdv1-default-aead-deferred.md) | SEIPDv1 by default; SEIPDv2 deferred to M2.5 | Accepted |
| [0007](0007-personal-use-no-distribution.md) | Personal-use scope, no distribution channels | Accepted |
| [0008](0008-block-upload-protocol.md) | Block-upload protocol (port JS happy path verbatim) | Accepted |
| [0009](0009-block-download-protocol.md) | Block-download protocol (port JS happy path) | Accepted |
| [0010](0010-session-lifecycle-and-refresh.md) | Session lifecycle and token refresh | Accepted |
| [0011](0011-zeroize-secret-material.md) | Zeroize all credential and key material on drop | Accepted |
| [0012](0012-wire-format-validation.md) | Wire-format validation via JS-encoded fixtures | Accepted |
| [0013](0013-mcp-server-surface.md) | MCP server surface (`pdtui mcp`) | Accepted |

New ADRs: copy [`0000-template.md`](0000-template.md) and bump the number.
