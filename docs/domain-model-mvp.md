# Domain model — MVP addendum

Supplements `domain-model.md` with the aggregates that matter for upload/download. Same bounded contexts; this file adds detail on the **Transfer** context that was a placeholder before.

## New / refined aggregates

### Transfer (aggregate root)

A single user-initiated file movement (upload or download), one revision in scope. Owns the block stream.

```
Transfer
├── id: TransferId               (uuid v7)
├── direction: Upload | Download
├── node: NodeUid                (target if upload, source if download)
├── stream: AsyncRead | AsyncWrite (caller-supplied; not persisted)
├── state: Pending | Running | Completed | Cancelled | Failed(Error)
├── progress: TransferProgress { bytes_done, bytes_total, blocks_done, blocks_total }
└── manifest: Option<ManifestSignature> (set once during commit/verify)
```

Invariants:
- A Transfer moves through states monotonically. `Failed` and `Cancelled` are terminal.
- `progress.bytes_done ≤ progress.bytes_total` always.
- A Transfer holds an exclusive lock on its target `NodeUid` for the duration. Two concurrent uploads to the same parent with the same name → second one fails fast at the node-creation step (server-enforced; we just propagate).

### Block (value object)

```
Block {
  index: u32,                 // 0-based within revision
  ciphertext: Bytes,          // SEIPDv1, includes inline signature
  enc_signature: Bytes,       // detached sig encrypted to encryption key
  hash: [u8; 32],             // sha256(ciphertext)
  size: u32,                  // 1..=4_194_304 (4 MiB)
}
```

Blocks are content-addressable by `(NodeUid, RevisionId, index)`. Server rejects size > 4 MiB. We chunk at exactly 4 MiB except the last.

### Revision (entity inside Node aggregate)

```
Revision {
  id: RevisionId,
  state: Draft | Active | Superseded,
  block_count: u32,
  size_bytes: u64,
  content_key_packet: Bytes,  // PKESK wrapping the session key
  content_key_signature: Bytes,
  manifest_signature: Bytes,  // signs SHA256 chain of block hashes
  xattr: Option<Bytes>,       // encrypted modification time, digests
  signature_address: Address,
  created_at: DateTime<Utc>,
}
```

State machine: Draft → Active (on commit) → Superseded (by a later upload to the same node). Draft revisions older than 24h are reaped server-side; we don't track them.

### Node (already in domain-model.md — extending)

For MVP we need three flavours discriminated by `Link.Type`:
- `Folder` — has children, no revisions
- `File` — has an active revision
- `Album` (photos) — **out of scope**, ignore

The TS field `Link.MIMEType` distinguishes File subtypes (text, image, …). MVP treats them all the same.

## Cross-context flows

### Upload (Transfer → Crypto → Nodes → Blocks)

```
TUI                Transfer            Crypto            Client (Nodes)     Server
 │ F3 ─────upload_request(stream)──→ ▶ │                  │                  │
 │                  │ generate session_key ─────────────→ │                  │
 │                  │ encrypt node-key + content-key-packet                  │
 │                  │ post-node ─────────────────────────→ POST .../files ──→│
 │                  │ ←──── node + revision_id                               │
 │                  │ for each block i in stream:                            │
 │                  │   encrypt+sign(block_i, session_key) → ciphertext_i    │
 │                  │   sha256(ciphertext_i) → hash_i                        │
 │                  │   encrypt(sign(block_i)) → encsig_i                    │
 │                  │ request-blocks ────────────────────→ POST .../blocks ─→│
 │                  │ ←──── [{ token, bare_url }] × N                        │
 │                  │ for each block: PUT bare_url ─────────────────────────→│
 │                  │ commit-revision ───────────────────→ PUT .../revision →│
 │                  │ ←──── active revision                                  │
 │ ←── completed ───┤                  │                  │                  │
```

### Download (Transfer ← Crypto ← Nodes ← Blocks)

```
TUI                Transfer            Crypto            Client (Nodes)     Server
 │ F2 ────download_request(node) ───→ │                  │                  │
 │                  │ get-revision ──────────────────────→ GET .../revision →│
 │                  │ ←──── { blocks[], content_key, manifest_sig, xattr }  │
 │                  │ decrypt content_key with node key ←─ Crypto           │
 │                  │ abort if manifest_sig is ABSENT (presence-only gate)   │
 │                  │ for each block (in order):                             │
 │                  │   GET bare_url ───────────────────────────────────────→│
 │                  │   assert hash matches                                  │
 │                  │   decrypt (no per-block sig check — see ADR-0009)      │
 │                  │   write to async stream                                │
 │                  │ verify manifest signature over all block hashes        │
 │                  │   (present-but-invalid → signature_verified=false,     │
 │                  │    data already delivered; matches JS)                 │
 │ ←── completed ───┤                  │                  │                  │
```

## Anti-corruption boundaries (additions)

- **Server-issued URLs are opaque.** The `bare_url` for a block is treated as a blob; we don't parse, normalise or rewrite it. If Proton changes its CDN routing, we follow.
- **`Hash` is sha256 of ciphertext, not plaintext.** Be precise — JS calls it `Hash` everywhere and the naming is ambiguous. In Rust we use `ciphertext_hash` in field names where possible.
- **`SignatureAddress` is an Address ID + Address Email + first signing key fingerprint.** Resolve from the local Account context; the API returns only the address ID, we map back via the host-provided `AddressProvider`.

## Invariants enforced in code (not just docs)

| Invariant | Where |
|---|---|
| Block size ≤ 4 MiB | `proton-drive-core::upload::chunk_stream` returns error on overflow |
| Block count fits in u32 | `Revision::new` rejects > u32::MAX blocks |
| File size ≤ 16 MiB for MVP | `FileUploader::upload_from_stream` checks `size_hint`; if `None`, accumulates and checks before commit |
| Active revisions have at least one block | enforced by server, propagated as `Error::ProtocolViolation` if violated |
| Block hash matches between client and server | per-block check after PUT response |
| Manifest signature *presence* gates download | a **missing** manifest signature aborts before any block is fetched; the cryptographic verification itself runs **after** all blocks are delivered (needs the full block-hash list), matching the JS SDK — see ADR-0009 |
| Per-block ciphertext hash verifies on fetch | `sha256(ciphertext)` checked against the server-supplied `Hash` before decrypt; one mismatched block fails the transfer. Per-block *signatures* are deliberately never checked — see ADR-0009 / IMPLEMENTATION-STATUS.md B5 |

## What's still informal (no aggregate yet)

- **Cache invalidation.** MemoryCache has no TTL. Upload invalidates by re-inserting the new Node, but cached folder listings get stale. TUI focus-change on the remote pane still triggers a fresh `iter_folder_children` as a fallback; a live drive-event now also marks the pane stale (see below). Real cache coherence is a post-MVP concern.
- **Events.** A real consumer landed (`proton-drive-core::events::{drain_volume_events, spawn_volume_event_loop}`, exposed as `ProtonDriveClient::subscribe_drive_events`), and `pdtui` wires it into the remote pane (`apps/pdtui/src/events_bridge.rs`): a relevant drive event (node create/update/trash/restore/delete/rename, tree refresh, tree removal) flips a staleness flag the app checks once per redraw tick. Subscription failure degrades gracefully to the original pull-on-focus behaviour rather than erroring.
