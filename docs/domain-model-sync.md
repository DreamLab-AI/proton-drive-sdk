# Domain model — Sync bounded context

Supplements `domain-model.md`. Adds a new bounded context, **Sync**, for
hash-based smart sync between a local directory tree and Proton Drive. Sync is
exposed to agents over MCP (`pdtui`'s MCP surface, not a new server): tools
compute a plan, an agent inspects/approves it, and a separate tool applies it.
The engine never guesses on the agent's behalf.

## 1. Bounded context and context map

```
┌──────────────────────────────────────────────────────────────────────┐
│                        ProtonDriveClient (root)                      │
├─────────────┬─────────────┬──────────────┬───────────────┬──────────┤
│  Identity   │   Nodes &   │   Transfer   │   Events &    │  Crypto  │
│  (support)  │   Folders   │   (core)     │     Sync      │ (support)│
│             │   (core)    │              │    (core)     │          │
└─────────────┴──────┬──────┴──────────────┴───────────────┴──────────┘
                      │ upstream
                      │ (conformist)
                      ▼
              ┌───────────────┐        MCP tools        ┌───────────┐
              │     Sync      │◀────────────────────────│   Agent   │
              │    (core)     │────────────────────────▶│ (external)│
              └───────────────┘   plan / apply / result  └───────────┘
```

Sync is a **new core context**, not a subordinate of Transfer: it decides
*what* to transfer, Transfer still decides *how*. The relationship to Nodes &
Folders is **upstream/downstream, conformist** — Sync consumes `Node`,
`NodeUid`, and `Revision` exactly as Nodes & Folders defines them and adds no
translation layer, because there is no risk of the upstream model changing
independently (both live in this port). Sync does *not* have a conformist
relationship with Transfer: it issues `SyncOp`s that a caller maps onto
existing `UploadJob`/`DownloadJob` aggregates one at a time, but the mapping
is the caller's job, not Sync's.

**Content identity** is the cleartext SHA1 digest carried in
`Common.Digests.SHA1` of the file's (encrypted) extended attributes — see
`rust/crates/proton-drive-core/src/upload.rs` `build_xattr_json` (around line
1180), which sets `Digests: {"SHA1": sha1_hex}` inside the `Common` object
that is itself encrypted before being attached to a Revision. Remotely the
digest is recovered by decrypting and parsing that xattr; locally it is
computed directly from file bytes. Both sides therefore agree on the same
hash algorithm and the same input (plaintext), so a match is authoritative:
identical `ContentHash` on both sides means the content is unchanged, full
stop, no size/mtime tie-break needed once hashes exist for both sides.

Agents reach Sync only through MCP tool calls (`sync_plan` then `sync_apply`);
Sync exposes no other public entry point. There is no separate `sync_resolve`
tool — conflict resolution folds into `sync_apply`'s `decisions` argument (a
`path → keep_local|keep_remote|skip` map). This mirrors the **Open Host
Service** pattern the JS SDK already uses at its own public surface
(`ProtonDriveClient`) — a small, deliberately-shaped API, not the internal
aggregate surface.

## 2. Aggregates, entities, value objects

### LocalIndex (aggregate root)

```
LocalIndex
├── root: PathBuf                        // local directory tree root
├── entries: Map<RelativePath, IndexEntry>
└── generated_at: DateTime<Utc>
```

```
IndexEntry (entity, keyed by RelativePath within LocalIndex)
├── path: RelativePath
├── content_hash: ContentHash            // always present on an emitted entry
├── size: u64
└── mtime: SystemTime
```

Cache-invalidation rule: a re-index reuses a previously-computed digest **only**
while the file's live `(size, mtime)` pair still matches the value the digest
was recorded for. That `(size, mtime) → sha1` validity check lives in a
separate `HashCache` (in-memory, or the optional on-disk `cache_file`), not on
`IndexEntry` — an emitted `IndexEntry` always carries a concrete
`content_hash`. Any `(size, mtime)` change forces a re-hash before the entry
participates in planning. This is the same "trust but verify cheaply first"
pattern the JS SDK uses nowhere else in this codebase, so it is Sync's own
invention and documented here rather than mirrored from upstream.

### RemoteSnapshot (aggregate root)

```
RemoteSnapshot
├── volume_id: String
├── folder: NodeUid                      // subtree root this snapshot covers
├── entries: Map<RelativePath, RemoteEntry>
├── taken_at: DateTime<Utc>
└── stale: bool                          // see §5, Domain events consumed
```

```
RemoteEntry (entity, keyed by RelativePath within RemoteSnapshot)
├── node: NodeUid
├── revision: Revision                   // from proton-drive-core::nodes — active revision only
└── content_hash: Option<ContentHash>     // recovered from decrypted xattr; None if xattr absent/unparseable
```

A `RemoteSnapshot` is a read-only projection over `Node`/`Revision` (Nodes &
Folders), scoped to one folder subtree. It is not itself mutated by apply —
apply mutates Drive state via Transfer, and a fresh `RemoteSnapshot` is
retaken (or the stale one is repaired) for the next planning cycle.

### SyncPlan (aggregate root)

```
SyncPlan
├── id: SyncPlanId                       // uuid v7
├── computed_from: (LocalIndex snapshot ref, RemoteSnapshot snapshot ref)
├── ops: Vec<SyncOp>                     // ordered; order is significant (§4)
├── issued_at: DateTime<Utc>
└── state: Proposed | Approved | Applied | Superseded
```

```
SyncOp (entity, ordered within SyncPlan; identity = position + target path)
├── path: RelativePath
├── kind: Upload | UploadRevision | Download | Skip | Conflict
├── local_ref: Option<(ContentHash, size, mtime)>          // snapshot-time facts, not live re-reads; `local` in code
├── remote_ref: Option<(NodeUid, RevisionId, ContentHash)> // `remote` in code
└── conflict: Option<ConflictOutcome>    // set on the resolved op after resolution; `outcome` in code
```

A `SyncPlan` is **immutable once issued.** Resolving a `Conflict` op does not
mutate the plan in place: it produces a new, approved op-set (a fresh
`SyncPlan` in `Approved` state referencing the same `computed_from` snapshots
plus the caller's `ConflictOutcome` choices). This mirrors the "Draft →
Active, never mutate in place" shape already used for `Revision` in
`domain-model-mvp.md` — plans are versioned forward, not edited.

### ConflictOutcome (value object)

```
ConflictOutcome = KeepLocal | KeepRemote | Skip
```

A pure decision value, always supplied by the agent through `sync_apply`'s
per-path `decisions` map (there is no separate resolve tool). The Sync engine
never picks a `ConflictOutcome` itself — it can detect that both sides carry a
digest and diverge (a true conflict) but resolution authority stops there. This
is the same boundary as `ProtonDriveAccount`/`AddressProvider` in
`domain-model.md` §1.1: the host (here, the agent) supplies a decision the
engine cannot manufacture.

## 3. Ubiquitous language

| Term | Meaning | Anti-name |
|---|---|---|
| **ContentHash** | Cleartext SHA1 digest identifying file content, from `Common.Digests.SHA1` (remote, decrypted) or computed locally | "checksum", "fingerprint" |
| **IndexEntry** | One file's local state: path, `ContentHash`, size, mtime | "record", "row" |
| **LocalIndex** | The aggregate of all `IndexEntry` records under one local root | "manifest", "tree" |
| **RemoteSnapshot** | A point-in-time projection of a Drive folder subtree, keyed by relative path | "listing", "cache" |
| **SyncOp** | One planned action against one path: Upload, UploadRevision, Download, Skip, Conflict | "action", "task" |
| **Plan** (`SyncPlan`) | The immutable, ordered set of `SyncOp`s computed from one `LocalIndex`/`RemoteSnapshot` pair | "diff", "changeset" |
| **Apply** | Executing an `Approved` plan's ops against Transfer/Nodes, one op at a time | "run", "execute", "sync" (bare) |
| **Conflict** | A `SyncOp` kind where both sides changed since the last common state | "clash" |
| **ConflictOutcome** | The agent's decision resolving one `Conflict`: KeepLocal, KeepRemote, Skip | "resolution", "verdict" |
| **Snapshot** | Either `LocalIndex` or `RemoteSnapshot` — a frozen view a plan is computed *from* | "state", "view" |
| **Staleness** | A `RemoteSnapshot` flag set by an unconsumed Drive event; forces re-snapshot before planning proceeds | "dirty", "expired" |

## 4. Invariants

1. **A `SyncOp` references only nodes/paths that existed in the snapshots the
   plan was computed from.** Ops are not re-validated against live state at
   plan-computation time — only at apply time (invariant 2).
2. **Staleness is detected at apply time via revision-uid mismatch, and an op
   fails safe rather than overwriting.** Immediately before applying a
   `Download`/`Upload`/`UploadRevision` op, Sync re-fetches the target node's
   active `Revision.uid` (or its absence, for a planned create) and compares
   it against `remote_ref`'s captured `RevisionId`. A mismatch means the
   remote changed after the snapshot was taken; the op fails with a
   distinguishable error rather than silently overwriting newer remote
   content. This is deliberately symmetric with `domain-model-mvp.md`'s
   `Transfer` invariant that a second concurrent write to the same target
   fails fast rather than corrupting state.
3. **Hash equality short-circuits all transfer.** If both `local_ref` and
   `remote_ref` carry a `ContentHash` and they are equal, the planner emits
   `Skip` — never `Upload`/`Download`/`UploadRevision` — regardless of
   differing size/mtime metadata (mtime is not content identity; see §1).
4. **Apply is idempotent per op.** Re-applying an already-`Applied` plan (or
   retrying a single op after a transient failure) must not produce a
   duplicate node, a duplicate revision, or a double-download; each op's
   apply step first checks whether its target already matches the intended
   post-state (by `ContentHash`, per invariant 3) and reduces to `Skip` if so.
5. **A `SyncPlan` in `Approved` state supersedes, never mutates, its
   `Proposed` predecessor.** Resolving conflicts creates a new `Approved`
   `SyncPlan` whose `superseded` field points at the original's id; the
   original is left untouched — still `Proposed`, never edited in place.
   Supersession is recorded on the *new* plan's `superseded` link, not by
   mutating the old plan's state: as landed, the engine does not transition the
   predecessor to `Superseded`, nor set `Applied` after apply. `PlanState::`
   `Superseded`/`Applied` are defined but not yet assigned by the engine.
6. **`ConflictOutcome` is only ever set by the agent.** The engine may detect
   and surface a conflict; it never defaults, guesses, or auto-resolves one.

## 5. Domain events consumed

Sync does not raise its own Drive-facing events; it **consumes** the
existing `DriveEvent` stream (`proton-drive-core::events`, see
`domain-model.md` §1.4) as a staleness signal for `RemoteSnapshot`:

> **Status (v1, as landed): intended, not yet wired into the MCP surface.**
> This staleness mechanism is defined and unit-tested on `RemoteSnapshot`
> (`mark_stale`/`is_stale`), but the MCP flow does not use it: each `sync_plan`
> call rebuilds the remote side from a fresh live walk rather than holding a
> long-lived `RemoteSnapshot` that a `DriveEvent` could mark stale, so
> `mark_stale` is exercised only in tests today. The operative safety guard on
> the MCP path is instead the apply-time revision-uid re-check (invariant 2),
> not snapshot staleness. The `events_poll` tool exposes the raw event drain to
> the agent, which can re-plan on its own initiative. The table below describes
> the intended wiring for when a persisted/long-lived snapshot lands.

| DriveEvent | Effect on `RemoteSnapshot` |
|---|---|
| `NodeEvent { kind: Created \| Updated \| Renamed \| Trashed \| Restored \| Deleted, .. }` scoped under the snapshot's `folder` | marks `RemoteSnapshot.stale = true` |
| `TreeRefresh` | marks `stale = true` unconditionally (full-resync signal upstream) |
| `TreeRemoval` scoped under `folder` | marks `stale = true` |
| `FastForward`, `SharedWithMeUpdated` | ignored — outside Sync's scope (no subtree ambiguity, or not a Sync-relevant subtree) |

A stale `RemoteSnapshot` is not usable as `computed_from` input for a new
`SyncPlan`: the planning tool must retake the snapshot first. This keeps
Sync's own "no ad hoc polling" guarantee — see `CLAUDE.md`'s Rust guardrails
— intact: staleness comes from the sanctioned event subscription, never from
a timer re-listing the folder.

## 6. What's out of scope (v1)

- Bidirectional continuous watch (inotify/FSEvents on the local side). v1
  computes a `LocalIndex` on demand per MCP call; it does not watch the
  filesystem.
- Move/rename detection across paths (a file moved locally is seen as a
  delete + create pair, not a `SyncOp::Rename`). May be added once
  `ContentHash`-based move detection is validated against real usage.
- Partial-plan apply resumption beyond per-op idempotency (invariant 4) — no
  separate "resume a half-applied plan" aggregate exists yet; the caller
  re-applies the same `Approved` plan and idempotency (invariant 4) makes
  that safe.
