# ADR-0003: In-memory cache for v1, SQLite deferred behind explicit triggers

| | |
|---|---|
| Status | Accepted |
| Date | 2026-05-27 |
| Context tag | `proton-drive-cache` |

## Context
The JS SDK ships `MemoryCache` and lets hosts inject persistent variants. The C# SDK has a SQLite-backed cache (`cs/sdk/src/Proton.Drive.Sdk/Caching/`) covering encrypted-blob storage, eviction, and schema migration. Both implement the same `ProtonDriveCache<T>` contract.

For our use case:
- Single user, single session TUI
- Two caches required by the SDK: `entitiesCache` (metadata) and `cryptoCache` (key material)
- Browse + upload + download: none of which benefits structurally from cross-session persistence
- Event-based refresh keeps visited folders fresh without re-fetching

## Decision
Implement `ProtonDriveCache<T>` over `dashmap` (in-memory, thread-safe). No persistence in v1.

Pull SQLite forward only if **one** of these triggers fires:
1. Folder listings >5k entries feel sluggish on cold start.
2. A background watcher / sync daemon enters scope.
3. Offline browsing of visited folders becomes a requirement.

When pulled forward, port the C# schema directly. Do not design fresh.

## Consequences
- No `rusqlite` dependency. No schema migration tooling. No "stale cache vs server truth" failure mode.
- Cold-start latency for every session: browse hits the API for the first folder listing. Acceptable for personal interactive use.
- Crypto material is rebuilt per session: keys decrypted from address-key passphrases each launch.

## Alternatives considered
- **SQLite from day one**, rejected: complexity ahead of need, three triggers for revisiting documented.
- **sled / redb**, rejected: SQLite is the C# choice and porting their schema later is the planned path.
- **File-based per-key cache**, rejected: indexing and eviction would be reinvented.
