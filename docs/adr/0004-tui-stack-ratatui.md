# ADR-0004: TUI on ratatui + crossterm + tokio

| | |
|---|---|
| Status | Accepted |
| Date | 2026-05-27 |
| Context tag | `apps/pdtui` |

## Context
Two-pane Midnight-Commander-style browser. Must run inside tmux, on a normal Linux terminal, and on macOS. Single static binary preferred. Async transfer queue runs alongside UI rendering.

## Decision
- **ratatui** for layout/widgets.
- **crossterm** for terminal I/O (cross-platform; tmux-friendly; handles raw mode, alt screen, mouse, bracketed paste).
- **tokio** multi-threaded runtime shared with the SDK.
- **tokio-stream** for SDK pagination streams.
- **tracing** + `tracing-appender` for logs to `$XDG_STATE_HOME/pdtui/pdtui.log` (UI never writes stdout/stderr).
- **notify** for local-pane file-watching.

## Consequences
- Same runtime drives the SDK and the UI: no bridging.
- Crossterm's TTY handling is well-tested under tmux; alt screen + mouse opt-in keeps tmux's own mouse mode functional.
- Single dependency footprint: ratatui+crossterm pulls in no native C libs.
- Windows is best-effort (crossterm supports it but we don't validate).

## Alternatives considered
- **tui-rs (the predecessor)**, rejected: deprecated; ratatui is the maintained fork.
- **Cursive**, rejected: heavier widget abstraction, more opinionated about event loops, less ergonomic with tokio.
- **termion**, rejected: Unix-only and lower-level than we need.
- **Iced TUI / Bubbletea-equivalent**: none mature enough in Rust.
