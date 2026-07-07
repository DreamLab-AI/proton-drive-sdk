# PRD: MCP server surface + hash-based agentic sync for `pdtui`

| | |
|---|---|
| Status | Draft v1 |
| Date | 2026-07-06 |
| Owner | DreamLab AI (John O'Hare) |
| Builds on | `PRD-rust-port-and-tui.md` (M0–M7, shipped) and `PRD-MVP-completion.md` (MA–MH, shipped); see `docs/IMPLEMENTATION-STATUS.md` for current state. This PRD adds a new surface on top; it does not reopen either. |
| Distribution | **None.** Personal use only (ADR-0007). The MCP server is a child process an agent's own tooling launches over stdio: never a listening network socket, never packaged or published. |
| Out of scope | Mirror deletes, move/rename propagation, multi-account, sharing/photos/public-links (already out of scope upstream), any form of distribution. |

---

## 1. Problem & Motivation

`pdtui` today is a human-driven, keystroke-first two-pane browser: `Tab`/`F2`/`F3`
and friends (`PRD-rust-port-and-tui.md` §7.4). There is no way for an agent
(Claude Code or any other MCP-speaking tool) to drive Proton Drive
programmatically: list what's on Drive, decide what needs uploading or
downloading, or reconcile a local project directory against a remote folder
without a human sitting at the TUI issuing keystrokes.

Meanwhile the SDK already computes everything a sync algorithm needs to
establish per-file identity: a SHA1 digest and modification time, carried in
each revision's encrypted `XAttr` blob (`decrypt_xattr_json`,
`rust/crates/proton-drive-core/src/download.rs:577-631`), but only ever
decrypts it as a post-download integrity cross-check
(`verify_xattr`/`claimed_size`). It is never exposed as something a *listing*
can return, and there is no path at all today for uploading a new revision of
an *existing* file, only brand-new files
(`upload.rs::ProtonFileUploader`, `CreateFileRequest` at
`rust/crates/proton-drive-core/src/upload.rs:354`).

This PRD adds an MCP server surface to `pdtui` so an agent can: inspect both
sides of the local/remote boundary, compute a sync plan by comparing content
hashes, and apply exactly the operations it explicitly approves: no silent
mutation, no ambient timers, no client behaviour beyond what the existing SDK
already does honestly.

## 2. Goals (v1)

- **G1.** A new `pdtui mcp` subcommand serves MCP over stdio via the `rmcp`
  crate (v2.1.0), sitting alongside the existing `login`/`mvp`/`probe`/
  `logout`/`where` dispatch in `apps/pdtui/src/main.rs:46-65`. It reuses the
  same keyring-backed `Session`/`SessionManager` bootstrap that `pdtui login`
  already establishes (`apps/pdtui/src/session.rs`): no parallel auth path,
  no new credential store.
- **G2.** Read tools (`drive_list`, `local_index`) let an agent build an
  accurate picture of both sides without any client-side polling beyond what
  `events_poll` already rides on the sanctioned Events API
  (`spawn_volume_event_loop`, `rust/crates/proton-drive-core/src/events.rs`).
  No re-listing timers, per the workspace-wide rule in `CLAUDE.md`.
- **G3.** A pure `sync_plan` turns two listings into a diff (upload / download
  / skip / conflict) with **zero side effects**: callable repeatedly, safe to
  call speculatively, safe to throw away.
- **G4.** `sync_apply` executes only the operations the caller explicitly
  names: never "apply the whole plan" implicitly, never anything the agent
  didn't ask for by ID.
- **G5.** Minimal, additive SDK extensions to support the above: surface SHA1
  + mtime on listed nodes (WP1) and add an upload-new-revision path for
  existing files (WP2). Neither changes an existing public method's
  signature or behaviour.

## 3. Non-Goals (v1)

- **Mirror deletes.** A file removed from one side is never removed from the
  other, automatically or even as a suggested op; `sync_apply` has no delete
  operation at all in v1.
- **Move/rename propagation.** A rename surfaces as a delete-shaped gap plus
  an add-shaped gap in a naive path/name diff; v1 does not attempt to detect
  or special-case this. It is the agent's problem if it cares.
- **Multi-account.** One keyring session per `pdtui mcp` process, exactly as
  today.
- **Any distribution of the MCP server.** ADR-0007 governs: this is a local
  stdio child process, launched by the agent's own tooling, never a listening
  network service, never packaged or published anywhere.
- **Working around known SDK gaps.** Nested-folder upload is only as good as
  the underlying SDK today (B2 in `IMPLEMENTATION-STATUS.md`). This PRD does
  not silently patch around it; see Risks (§10).
- **Recursive whole-tree sync in one call.** `sync_plan`/`sync_apply` operate
  over one local root ↔ one remote folder pairing per call. Recursing into
  subfolders is the agent's loop to drive (call again per subfolder), not a
  v1 built-in.
- **Auto-resolving conflicts.** A hash-differ case is always returned
  `undecided`; the tool surface never guesses which side wins.

## 4. Users & Use Cases

| User | Use case |
|---|---|
| Coding agent (Claude Code or similar) mid-session | Push a local build artefact or scratch file to Drive without shelling out to a human-driven TUI |
| Coding agent doing project sync | Compare a local repo checkout against its mirror folder on Drive, upload what changed, flag anything that diverged on both sides |
| Long-running agent session | Poll `events_poll` between turns to notice a change made from another device before re-running `sync_plan` |
| Personal use, scripted | The owner's own automation (cron-free, agent-invoked) reconciling a photos-export or notes folder into Drive on demand |

Anti-user: same as upstream, no third-party distribution, no multi-tenant
service (ADR-0007).

### User stories

1. **Upload with verification.** *As an agent*, I call `drive_upload(local_path,
   remote_parent_path)` to push a new file, then `drive_list` the parent to
   confirm the new node's SHA1 matches what I computed locally before telling
   the user it's done.
2. **Directed sync.** *As an agent*, I call `sync_plan("~/projects/foo",
   "/My Files/Projects/foo")` and get back a `plan_id` and three ops: two
   `upload` (new local files), one `skip` (hash-equal). With no conflicts I
   call `sync_apply(plan_id)` with an empty `decisions` map; it runs that
   plan's ops: the two uploads happen, the skip is a no-op. Nothing outside
   that stored plan can be touched.
3. **Conflict surfaced, not resolved.** *As an agent*, `sync_plan` reports one
   `conflict` entry (same path, different hash on each side). I read both files
   (`drive_download` + local read), decide which side is authoritative, and
   call `sync_apply(plan_id, decisions={path: keep_local})` (or `keep_remote`);
   the engine turns that decision into an `upload_revision` (or `download`),
   never both, never automatically. An undecided conflict makes the whole
   apply fail rather than pick a side.
4. **Staleness check before acting.** *As a long-running agent*, I hold a
   `next_anchor` from a previous `events_poll` call. Before trusting a
   `sync_plan` result I call `events_poll(since_event_id=anchor)`; if it
   reports a change under the folder I'm about to sync, I re-run `drive_list`
   first rather than acting on a stale remote listing.
5. **New project folder.** *As an agent* setting up a new remote mirror, I
   call `drive_mkdir(parent_path, "new-project")` once, then upload into it.
   No separate out-of-band step required.
6. **Revise an existing file.** *As an agent* that edited a file already on
   Drive, I call `drive_upload` again against the same remote path. By default
   the tool refuses (a name collision is a hard error, never a silent
   overwrite), so I re-call with `allow_revision_on_conflict: true` to upload a
   new revision of the existing node (`created_revision: true` in the result).

## 5. Reference: what exists today vs what this PRD adds

| Capability | Current state | Delta needed |
|---|---|---|
| Node listing | `client.rs::{my_files_root, node, fetch_folder_children}` return `Node` (`nodes.rs`) with `size_bytes`, `modified_at`, no digest. | **WP1**: attach SHA1 + XAttr mtime, opt-in per call (see §6.2, §9). |
| Remote content hash | Only ever decrypted inside `FileDownloader::decrypt_xattr_json` (`download.rs:577-631`), which needs the node's private key already resolved as part of an in-flight download session. | **WP1** extracts a standalone "fetch + decrypt this revision's XAttr" path callable from a listing context, not just a download. |
| New-file upload | `upload.rs::ProtonFileUploader` implements `CreateFileRequest` → chunk → commit (ADR-0008). No `CreateDraftRevisionRequest`/response DTO anywhere in `proton-drive-api`, no client method to request a revision on an *existing* node. | **WP2**: new DTOs + `POST /drive/v2/volumes/{volumeId}/files/{nodeId}/revisions` (JS reference: `manager.ts::createDraftRevision`, `apiService.ts:137-150`), reusing the *existing* node key + content-key-packet session key rather than generating fresh ones. |
| Folder creation | Not implemented anywhere in the Rust port. Confirmed absent: `audit-2026-07-05.md` notes `createFolder` is out of scope for the shipped MVP. | **New, small surface** (folded into WP2 or WP4, see §8): `POST /drive/v2/volumes/{volumeID}/folders` with `{ParentLinkID, NodeKey, NodeHashKey, NodePassphrase, NodePassphraseSignature, SignatureEmail, Name, Hash, XAttr?}` (JS reference: `nodesManagement.ts:357-390`, `apiService.ts:498-535`). Reuses the same node-key-generation + HMAC name-hash helper `CreateFile` already uses (`upload.rs`, name-hash fn at `upload.rs:81-113`): no content key, no blocks, no revision/commit steps, materially smaller than file upload. |
| Path → `NodeUid` resolution | Does not exist. The TUI navigates one `iter_folder_children` level at a time via a `cwd` stack (`apps/pdtui/src/panes.rs`). | **New, small**: segment-walk from `my_files_root`, matching child name at each level (name uniqueness per folder is already server-enforced: `NodeWithSameNameExists`, `nodes.rs::map_api_error`). Session-scoped memo only, no new persistence layer. |
| Events | `spawn_volume_event_loop` + `ProtonDriveClient::subscribe_drive_events` are already public and wired into `pdtui`'s remote pane (`events_bridge.rs`, M6). | **Reuse as-is.** `events_poll` is a thin adapter over the existing subscription, not a new poller. |
| Local hashing | `pdtui`'s upload path already computes SHA1 client-side before queueing (`PRD-rust-port-and-tui.md` §7.5). | **WP3** generalises this into a directory-walking indexer with a (path, size, mtime) → sha1 cache, independent of any single upload. |

## 6. Architecture

### 6.1 Process & transport

`pdtui mcp` is a new arm of the existing subcommand dispatch
(`apps/pdtui/src/main.rs:46`): `Some("mcp") => run_mcp().await`. It:

1. Loads the existing keyring session via `SessionManager::from_keyring`
   exactly as `pdtui mvp` already does; if no session exists, it exits with an
   error telling the operator to run `pdtui login` first. The MCP server is
   never itself a login surface.
2. Constructs the same `ProtonDriveClient` the rest of the app uses (shared
   `proton-drive-core` construction path, not a bespoke one).
3. Serves MCP over **stdio only** via `rmcp`: no HTTP/SSE transport, no
   listening socket, matching the ADR-0007 constraint that this never becomes
   a network-reachable service.
4. Sets `x-pm-appversion` exactly as every other `pdtui` code path does
   (`external-drive-pdtui@{semver}-stable`); the MCP server is not a
   separate client identity.

### 6.2 Tool catalogue

All paths are logical `'/'`-separated paths from the My Files root (case-
sensitive), not uids. The one uid that crosses the boundary is `drive_download`'s
`uid`, which is the `{volume_id, node_id}` object a `drive_list` child carries.

| Tool | Args | Returns | Side effects |
|---|---|---|---|
| `drive_list` | `path: string`, `include_digest: bool = false` | `{path, uid, count, children: [{uid, name, kind, size, mtime, sha1?}]}`: `kind` is the string `"file"`/`"folder"`/`"album"`; `sha1` present only when `include_digest`. | None (read-only). |
| `drive_download` | `uid: {volume_id, node_id}` (the object from `drive_list`), `local_path: string`, `overwrite: bool = false` | `{bytes, sha1, signature_verified}` | Writes `local_path`; refuses to clobber an existing file unless `overwrite`. |
| `drive_upload` | `local_path: string`, `remote_parent_path: string`, `name?: string`, `allow_revision_on_conflict: bool = false` | `{uid, revision_uid, sha1, created_revision}` | Creates a new node; a name collision fails by default (see below). |
| `drive_mkdir` | `parent_path: string`, `name: string` | `{uid}` | Creates a folder node. |
| `local_index` | `root: string`, `cache_file?: string` | `{root, count, truncated, entries: [{path, sha1, size, mtime}]}`: the echoed `entries` list is capped at 1000; `count` is the full total. | None (read-only; may read/refresh the hash cache, §6.3). |
| `sync_plan` | `local_root: string`, `remote_folder: string`, `cache_file?: string` | `{plan_id, summary, ops, conflicts, dirs_to_create, checkpoint}` | None to drive/local content, pure function of two listings (G3); stores the plan in-process and writes a best-effort snapshot checkpoint (§6.4). |
| `sync_apply` | `plan_id: string`, `decisions: {path → keep_local\|keep_remote\|skip}` | `{plan_id, applied, results: [{path, op, result, error?, uid?, revision_uid?}]}` | Executes the stored plan's full op set; `decisions` only resolve its conflicts. |
| `events_poll` | `since_event_id?: string`, `volume_id?: string` | `{volume_id, next_anchor, events}` (plus `refreshed` when draining) | None: on-demand drain of the Events API; no new polling loop (§6.1, G2). |

**`drive_list`'s `include_digest` flag exists because digest is not free.**
WP1's SHA1/mtime come from decrypting each file's `XAttr`, which lives only on
the per-revision detail response
(`GET drive/v2/volumes/{volumeId}/files/{linkID}/revisions/{revisionID}`,
`proton-drive-api::download::RevisionWithBlocks`), **not** on the folder-
children listing response (`proton-drive-api::nodes::Revision`, which has no
`XAttr` field at all). Turning digest on for every file in a listing is an
extra HTTP round trip *per file*, not a batched call. Default `drive_list`
calls stay cheap (name/size/mtime/type only, already on the listing
response); `include_digest: true` is opt-in, and `sync_plan` is the one
caller that always sets it for the remote side, bounded to a small
concurrency limit (reuse the existing default-3 `Semaphore` convention from
the transfer queue, `PRD-rust-port-and-tui.md` §7.5) rather than serial N+1
or unbounded-parallel fetches, to respect the shared per-account rate limits
`CLAUDE.md` requires every Proton Drive client to honour.

**`drive_upload` never silently overwrites on a name collision.** It first
attempts the existing `CreateFile` path (`upload.rs`); if the API returns
`AlreadyExists` (error code 2500, `nodes.rs::map_api_error`) for that name
under that parent, the default (`allow_revision_on_conflict: false`) is to
**fail with a hard error** ("Refusing to overwrite it"), leaving the existing
file untouched, so a create can never clobber an unrelated file the agent
didn't mean to. Only when the caller re-invokes with
`allow_revision_on_conflict: true` does it resolve the existing node and upload
a **new revision** via WP2's create-draft-revision path; the result then
carries `created_revision: true`. This is a deliberate reversal of an earlier
"overwrite, not duplicate" default in favour of failing safe.

### 6.3 Sync engine internals (WP3)

`local_index` walks a local directory tree and, for each file, looks up
`(size, mtime)` for that relative path in a hash cache before recomputing SHA1:
if size and mtime are unchanged since the last index of that path, the
cached hash is reused (the same trick `git`/`rsync` use to avoid rehashing
unchanged files).

**The cache defaults to in-memory, keyed per relative path by
`(size, mtime) → sha1`, scoped to the `pdtui mcp` process's lifetime**,
consistent with ADR-0003 (in-memory cache, SQLite deferred behind explicit
triggers). A long-running agent session that keeps one `pdtui mcp` process
alive across many tool calls amortises the hashing cost; a fresh process
re-hashes from scratch on first `local_index` call. As a lightweight, opt-in
exception, both `local_index` and `sync_plan` accept an optional `cache_file`
parameter: a JSON file the walk reads a `(size, mtime) → sha1` cache from and
rewrites, so a fresh process can reuse a prior run's digests without standing
up the SQLite store ADR-0003 still defers. It is a plain JSON side-file, not a
database; it carries no cross-process invalidation machinery beyond the
`(size, mtime)` validity check each entry already makes. If large local trees
or short-lived MCP processes *without* a `cache_file` make hashing a real
bottleneck, revisit ADR-0003's triggers explicitly. This PRD does not pull
SQLite forward on its own authority.

`sync_plan` is a pure function: `diff(local_index(local_root),
drive_list(remote_folder, include_digest=true))` by matching relative path.
For each path:

- Only-local → `upload`.
- Only-remote → `download`.
- Both sides, hashes equal → `skip`.
- Both sides, hashes differ → `conflict`, returned **undecided**: the agent
  resolves it, this function never picks a side.

No hidden state, no implicit baseline/"last known good" tracking in v1: a
hash-differ case is always a conflict, even if one side's mtime is obviously
newer. (A future v2 could add a recorded-baseline three-way merge; explicitly
deferred here, see §11.)

### 6.4 The plan/apply safety model

This is the load-bearing design constraint of the whole feature:

- **`sync_plan` has no side effects on drive or local file content.** It can
  be called any number of times, discarded, or used only to inform a decision
  the agent makes some other way. Nothing about calling it changes local or
  remote content. (It does store the plan in-process under its `plan_id` and
  write a best-effort remote-snapshot checkpoint side-file: neither touches
  drive or local file state; see ADR-0013.)
- **`sync_apply` approves a plan by reference, not by restating ops.** The
  caller passes the `plan_id` of a plan `sync_plan` already returned; the
  server looks up that stored plan and applies **its full op set**. Per-path
  control is limited to the `decisions` map, which only resolves that plan's
  conflicts (`keep_local` → `upload_revision`, `keep_remote` → `download`,
  `skip` → drop). The caller cannot smuggle in an op the plan never produced,
  because it names no ops at all; it names a plan. An `UploadRevision`
  re-reads the remote active revision and fails safe if it moved since the
  plan was computed; one op failing never aborts the rest.
- **Every mutation is auditable.** `drive_upload`, `drive_download`,
  `drive_mkdir`, and each op inside `sync_apply` return enough detail (uid,
  revision uid, sha1) to log what happened, not just what was
  requested.
- **Conflicts are never auto-resolved anywhere in the stack**: not in
  `sync_plan` (a hash-differ or missing-remote-digest path is returned
  `conflict`, undecided), not in `sync_apply` (an unresolved conflict, meaning
  one with no matching entry in `decisions`, or a `decisions` key naming a
  non-conflict path, makes the **whole apply** fail with `invalid_params`
  rather than guessing a direction).
- **Idempotency where it costs nothing:** `skip` ops run as no-ops;
  `drive_mkdir` on an already-existing name surfaces the same `AlreadyExists`
  the API already returns rather than silently succeeding; the agent decides
  whether that's fine. Re-applying a stored plan after a partial apply is
  safe: an `Upload` whose target already carries identical content reports
  idempotent success rather than a duplicate or an overwrite.

## 7. Constraints

- `x-pm-appversion` unchanged and non-overridable: the MCP server is not a
  new client identity (§6.1).
- No ad hoc polling of node/listing endpoints outside the Events API; the
  workspace-wide rule in `CLAUDE.md` applies to `events_poll` exactly as it
  does to the TUI's own event consumer. `events_poll` must not become a
  disguised re-list-on-timer.
- All HTTP hits official Proton endpoints only. No proxying, same as every
  other `pdtui` code path.
- Rate limits are shared with first-party clients; WP1's digest-fetch
  concurrency (§6.2) and any batching in WP3's remote-side listing must
  respect this, not just work "in the common case".
- Personal use only, unaudited (ADR-0007, root `CLAUDE.md`). This PRD does
  not change that status: the MCP server is one more local code path against
  the owner's own account, not a step toward distribution.
- No breaking change to `ProtonDriveClient`'s existing public API: WP1/WP2
  are additive (new optional parameters, new methods), not modifications of
  `my_files_root`/`iter_folder_children`/`file_downloader`/`file_uploader`'s
  existing signatures.

## 8. Phased delivery

| WP | Deliverable | Depends on | Notes / gotchas found during this research pass |
|---|---|---|---|
| **WP1** | Surface SHA1 digest + XAttr mtime on listed nodes | — | Not free (§6.2): must be opt-in per listing call, not eagerly attached to every `Node`. Extract the XAttr-fetch-and-decrypt logic out of `download.rs`'s download-session context into something callable given just a `NodeUid` + resolved node key. |
| **WP2** | Upload-new-revision flow for existing files | WP1 (reuses the same node-key resolution path) | New DTOs + `POST .../files/{nodeId}/revisions` (JS: `manager.ts::createDraftRevision`). Reuses the **existing** node key and content-key-packet session key, does not generate fresh node crypto material, unlike `CreateFile`. **Known gap this intersects:** `resolve_parent_context` (`upload.rs`) is only correct when the parent is the share root (B2, `IMPLEMENTATION-STATUS.md`); this affects revision uploads into nested folders exactly as it affects new-file uploads into nested folders. Recommend WP2 either fixes B2's upload half as part of this package (it's already touching the same code path) or the PRD explicitly scopes `drive_upload`/`sync_apply` uploads to root-level and single-level-nested remote folders until B2 lands. Do not ship silently broken nested uploads. `drive_mkdir` (folder creation, §5) is small enough to fold into this package rather than standing up a fifth WP. |
| **WP3** | Sync engine: local indexer + diff/plan | none; independent of WP1/WP2, can start in parallel | Pure, testable, no I/O side effects beyond reading local files and calling `drive_list`. Hash-cache scope decision is explicit, not implicit (§6.3). |
| **WP4** | MCP server (`pdtui mcp` subcommand, tool wiring) | WP1, WP2, WP3 | Wires the tool catalogue (§6.2) onto `rmcp`. Reuses `session.rs` bootstrap unchanged (§6.1). `events_poll` reuses `subscribe_drive_events` unchanged. |

## 9. Acceptance Criteria

- `pdtui mcp` starts, serves the tool catalogue in §6.2 over stdio, and exits
  cleanly on stdin close / `SIGTERM`.
- `drive_list` without `include_digest` costs no more HTTP round trips than
  today's `iter_folder_children`; with `include_digest: true` it is
  bounded-concurrency, not serial-per-file and not unbounded-parallel.
- **Extended headless round-trip** (extends the existing `pdtui mvp` shape,
  `docs/PRD-MVP-completion.md`): upload a file → modify it locally → call
  `sync_plan` and confirm it reports exactly one `conflict` op
  (`content_diverged`) for that path (the file now exists, and differs, on
  both sides), everything else `skip` → call `sync_apply(plan_id,
  decisions={path: keep_local})` and confirm that path resolves to an
  `upload_revision` → re-run `local_index` and `drive_list(include_digest=true)`
  on both sides and confirm the SHA1s converge. (For a plain `upload` instead,
  use a brand-new local file with no remote counterpart.)
- `sync_apply` only ever executes the ops of the stored plan named by
  `plan_id`; a `decisions` key that does not name one of that plan's conflicts
  is rejected with `invalid_params`, never silently ignored.
- A hash-differ case round-trips as `conflict` (`content_diverged`) through
  `sync_plan` and, if `sync_apply(plan_id)` is called without a `decisions`
  entry for it, the whole apply is rejected (`invalid_params`) rather than
  silently resolved.
- `drive_upload` against an already-existing remote name fails by default
  (never a silent overwrite); re-called with `allow_revision_on_conflict:
  true` it creates a new revision (WP2 path, `created_revision: true` in the
  result), not a duplicate node.
- `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` all green, per the repo-standard quality gate.
- No `unwrap`/`expect`/`panic!` introduced outside `#[cfg(test)]`: same
  workspace-wide lint as everything else in this repo.

## 10. Risks & Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| WP1's per-file XAttr fetch is an unbounded N+1 against a large remote folder | Med | Opt-in `include_digest`, bounded concurrency reusing the existing transfer-queue semaphore convention (§6.2): not this PRD's job to invent a new concurrency primitive. |
| Nested-folder upload is broken today (B2) and WP2's revision-upload path shares the same parent-key-resolution code | High | Flagged explicitly in §8 as a WP2-adjacent decision point: fix B2's upload half as part of WP2, or scope `drive_upload`/`sync_apply` to root/shallow-nested remote folders until it's fixed. Do not ship a tool that silently corrupts nested uploads. |
| An agent calls `sync_apply` with a stale plan (remote changed between `sync_plan` and `sync_apply`) | Med | `events_poll` exists precisely so an agent can check staleness before applying (user story 4, §4). `sync_apply` itself doesn't re-validate the plan against current remote state before executing; v1 relies on the agent's own discipline plus the underlying upload/download error paths (e.g. a real hash mismatch surfaces as the existing `Integrity`/`AlreadyExists` errors) rather than a new optimistic-concurrency check. Revisit if this proves insufficient in practice. |
| Deprecated v1 share-scoped list/node endpoints (B8) could be retired upstream without notice | Med (pre-existing, not introduced by this PRD) | Unchanged from `IMPLEMENTATION-STATUS.md`; WP1/WP4 build on the same `client.rs` methods already using these endpoints; migrating to v2 endpoints is out of scope here, tracked separately. |
| MCP tool surface becomes a de facto second API that drifts from the TUI's own behaviour | Low | Both share the same `proton-drive-core`/`ProtonDriveClient` construction path (§6.1); the MCP server is a new *caller*, not a parallel implementation. |
| Personal-use/unaudited status gets glossed over once there's a slicker agent-facing surface | Med | Restated explicitly in §3, §7, and this PRD's header: an MCP surface makes misuse easier to automate accidentally, so the honesty obligation is if anything higher, not lower, than the interactive TUI's. |

## 11. Open Questions

- **Three-way merge / recorded baseline for conflict resolution.** v1 treats
  any hash-differ as an undecided conflict, even when one side is obviously
  newer. A future version could record a "last synced hash" per path to
  distinguish "both changed since last sync" (real conflict) from "only one
  side changed since last sync" (safe fast-forward). Deferred: not blocking
  v1, and adding it changes `sync_plan`'s purity guarantee (it would need to
  read/write a baseline store), which deserves its own design pass rather
  than folding in here.
- **Where B2 (nested-folder upload) gets fixed.** §8 flags this as a WP2
  decision point rather than resolving it; whoever picks up WP2 should
  decide and record that decision (a short ADR update, not a new PRD) before
  `drive_upload`/`sync_apply` ship claiming nested-folder support.
- **`local_index`/hash-cache persistence.** §6.3 defaults to in-memory,
  process-lifetime scope (consistent with ADR-0003), with an optional
  `cache_file` JSON side-file as a lightweight opt-in for cross-process digest
  reuse. Promoting that to the full SQLite store (with proper cross-process
  invalidation) remains an ADR-0003-trigger conversation, not something to
  quietly work around inside WP3.
