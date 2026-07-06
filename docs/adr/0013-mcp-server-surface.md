# ADR-0013: MCP server surface (`pdtui mcp`)

| | |
|---|---|
| Status | Accepted |
| Date | 2026-07-06 |
| Context tag | `apps/pdtui` |

## Context
An AI agent needs to browse and mutate the owner's Proton Drive on their behalf —
list nodes, plan a local↔remote sync, and execute approved changes — without the
agent shelling out to `pdtui` subcommands and scraping stdout. The Model Context
Protocol (MCP) is the established way to expose that surface to agent hosts
(Claude Code, Claude Desktop, and others) as typed tools over a well-known
transport.

`pdtui` already owns session bootstrap (SRP login, OS keyring, `session.json`,
the `login`/`mvp`/`probe`/`logout`/`where` subcommands in
`rust/apps/pdtui/src/main.rs`) and the live SDK client. Adding agent control
needs to reuse that, not duplicate it. It also needs to respect the repo's
no-ad-hoc-polling guardrail: remote-change detection must ride the Events API
event loop (`spawn_volume_event_loop` in
`rust/crates/proton-drive-core/src/{client,events}.rs`), not a new timer that
re-lists folders.

The mutation surface is the sharper risk: an MCP client is a semi-autonomous
agent, not a human confirming each keystroke in the TUI. Giving it direct
write access to `sync_apply`-style operations without a review step would let
a misbehaving or misprompted agent silently delete or overwrite real files.

## Decision
Add a `pdtui mcp` subcommand that serves MCP over stdio using the `rmcp`
crate v2.1.0 (the official Rust MCP SDK; tokio-based, fits the workspace's
edition 2024 / async-std-free stack). It reuses `pdtui`'s existing keyring
session bootstrap unchanged — no new authentication surface, no new
credential store.

A new `proton-drive-sync` crate holds the local indexer and diff engine: pure
computation, no network calls, so it can be unit-tested without a live
session and reused by both `pdtui mcp` and any future interactive sync UI.

Mutating operations follow a **plan/apply split**:
- `sync_plan` is a pure dry-run — it diffs the local index against the current
  remote state and returns a proposed set of operations (upload,
  upload-revision, download, skip, conflict) with no side effects. There is no
  `delete` op: mirror deletes are a non-goal.
- `sync_apply` executes only the specific operations the agent has approved
  from that plan — it does not recompute or re-derive changes, and it does
  not silently expand scope beyond what was approved.
- Conflicts (e.g. both sides changed since the last sync point) are reported
  as an explicit undecided state in the plan, not auto-resolved by either
  "last write wins" or "remote wins" defaults. The agent (or the human
  behind it) must choose.

Remote-change detection for the sync engine's "last known remote state"
consumes the existing Events API loop; the MCP surface adds no new polling
path, per the guardrail in `CLAUDE.md`.

`rmcp` is added as a dependency of `pdtui` only — it does not become a
dependency of any `proton-drive-*` SDK crate.

## Consequences
- `pdtui` gains a second headless entry point (alongside `probe`/`mvp`) whose
  correctness matters as much as the interactive TUI's; it inherits the
  project's overall unaudited status (see root `README`/`CLAUDE.md`
  disclaimer) — an MCP client is one more caller that can trigger the
  live crypto-backed transfer path.
- MCP clients can mutate the Drive. The plan/apply split bounds this: nothing
  is written without a plan the agent has already seen and selected from, and
  conflicts cannot be resolved without an explicit decision.
- `proton-drive-sync` is pure and network-free, so its diff logic is testable
  in isolation from session state and from the live API.
- `rmcp` joins the workspace dependency graph, scoped to `apps/pdtui`; SDK
  crates (`proton-drive`, `proton-drive-core`, `proton-drive-api`,
  `proton-drive-crypto`, `proton-drive-cache`) remain untouched by MCP
  concerns.
- Follow-on work — **partially addressed.** `sync_plan` now persists a
  remote-snapshot checkpoint (the serde `RemoteSnapshot` written to
  `$XDG_CONFIG_HOME/pdtui/mcp-checkpoints/{plan_id}.json`), but nothing yet
  reads it back: each `sync_plan` rebuilds the remote side from a fresh live
  walk. Consuming the checkpoint as a diff baseline across restarts —
  baseline-aware / three-way diff — remains deferred; sequencing tracked
  outside this ADR.

## Alternatives considered
- **Separate `pdmcp` binary crate** — rejected: at personal-use, single-user
  scale (ADR-0007) a second binary buys no real isolation, only a second
  copy of session bootstrap to keep in sync with `pdtui`.
- **HTTP/SSE transport** — rejected: stdio needs no listening socket and
  matches the single-user, locally-invoked agent model this project targets;
  HTTP/SSE would add a network-facing attack surface for no benefit here.
- **Embed agent control into the TUI event loop** — rejected: couples an
  interactive, human-paced UI loop to a headless automation lifecycle with
  different timing, error-handling, and lifecycle needs; kept as a separate
  subcommand instead, mirroring how `probe` and `mvp` are already separate
  from the TUI.
