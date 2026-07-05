# ADR-0009: Block-download protocol — port JS happy path

**Status:** accepted, 2026-05-28. **Verification order corrected, 2026-07-05**
(see `docs/audit-2026-07-05.md`) — the original text below described a
verify-before-fetch protocol that was never what shipped or what JS actually
does; §"The protocol" and the quality gates are rewritten to match the real,
JS-faithful "deliver-then-flag" design.
**Context milestone:** ME.
**Depends on:** ADR-0008 (block-upload symmetry), ADR-0011 (zeroize), ADR-0012 (wire-format validation).

## Decision

Port `client/js/src/internal/download/` happy path 1:1 into `proton-drive-core::download`. Sequential block fetch, per-block ciphertext-hash check, write to async stream, then manifest-signature verification. Seekable/parallel download deferred.

## The protocol (as derived from the JS SDK and matching `download_to_writer`, `crates/proton-drive-core/src/download.rs`)

```
1. Client: GET /drive/v2/volumes/{volumeID}/files/{linkID}/revisions/{revisionID}
   (paginated by PageSize/FromBlockIndex; a single unpaginated GET can
   silently truncate a large revision)
   → returns: { Revision: { ID, State, Blocks: [{ Index, BareURL, Token,
                            EncSignature, Hash, Size }], ManifestSignature,
                            ContentKeyPacket, XAttr, SignatureAddress } }
   (Active revision id obtained from the Link's ActiveRevision field, fetched
   via GET /drive/shares/{shareID}/links/{linkID}.)

2. Client: presence-only gate — if ManifestSignature is absent, abort
   immediately (`Error::Verification`) before fetching or decrypting any
   block. A revision with *no* signature at all has no integrity guarantee
   to fall back on. (This is the only pre-fetch abort condition; a signature
   that is *present* is not cryptographically checked until step 5.)

3. Client: derive content session key from ContentKeyPacket using the
   node's private key. ContentKeyPacketSignature is verified against
   `[node_key, ...address_keys]`, but **non-fatally** — a missing or
   unverifiable signature only degrades an authorship claim (mirrors JS
   `contentKeyPacketAuthor`); it never aborts the download.

4. Client: for each block in ascending Index order:
     a. GET BareURL with Authorization: Bearer Token → ciphertext_i
     b. assert sha256(ciphertext_i) == Block.Hash, else abort with
        `Error::IntegrityCheckFailed` — this per-block ciphertext-hash check
        is the one fatal *data*-integrity gate in the per-block loop.
     c. decrypt ciphertext_i with the session key. **No per-block signature
        check is performed** — `EncSignature`/detached block signatures are
        never fetched or verified, deliberately matching the JS reference,
        which has no such check either (see ADR-0009 note in
        `docs/audit-2026-07-05.md` and IMPLEMENTATION-STATUS.md B5).
     d. write plaintext_i to caller-supplied AsyncWrite

5. Client: only *after* every block has been fetched, hash-checked,
   decrypted and written (and the writer flushed), verify ManifestSignature
   over the concatenated block hashes in ascending Index order. No signature
   context is used (matches JS `signManifest`/`verifyManifest` — see
   ADR-0008). The outcome is **non-fatal**: a present-but-invalid or
   wrong-signer signature does not discard the already-delivered bytes; it
   is surfaced to the caller as `DownloadStats::signature_verified = false`
   (and in `pdtui`'s UI), exactly like the official client. Verification
   necessarily runs after the fetch loop because it needs the full ordered
   set of block hashes, which only exists once every block has been seen.

6. Client: XAttr cross-check (best-effort, non-fatal) — decrypt the
   Common.ModificationTime/Size/Digests.SHA1 XAttr payload and compare
   against the assembled bytes. A mismatch is logged at `error` level but
   does **not** fail the download (see "Implementation constraints" below).
```

## Implementation constraints

- **Concurrency: 1 block at a time** (matches MD).
- **No retry mid-block:** transient HTTP errors during a block GET fail the whole download. MVP user can re-invoke. Retries belong to a later "robust transfer" milestone.
- **No range requests:** full block, full file. No seek.
- **XAttr size/SHA1 mismatch is deliberately non-fatal.** Corrected 2026-07-05:
  this ADR previously claimed "the JS SDK does verify the assembled size
  matches XAttr.Common.Size; we should too" — that is false. Neither
  `reference/client/js`'s `fileDownloader.ts` (which uses the claimed size only
  for progress reporting) nor the Rust port asserts on a size/SHA1 mismatch;
  `verify_xattr` (`download.rs`) logs a warning and still returns the decrypted
  modification time. Only a **missing** ManifestSignature is a hard abort; a
  size/SHA1/ModificationTime XAttr disagreement never is.
- **Update 2026-07-05 (wp/c2-resilience, cs/v0.15.0 alignment):** the
  "claimed size only for progress reporting" use noted just above is now
  itself ported — `FileDownloader::claimed_size()` decrypts the XAttr
  independently (a single extra revision-page fetch) and returns
  `Common.Size`, which `pdtui`'s transfer layer uses as the download's
  progress-gauge total, mirroring the C# SDK's `RevisionOperations.
  GetClaimedSizeAsync`/`DownloadState.ClaimedSize`. This is *not* the
  size/SHA1 cross-check described above (still non-fatal, unchanged) — it's
  a separate, best-effort read of the same field for UI purposes only.

## What is NOT ported

- `seekableStream.ts` — random-access download
- `blockIndex.ts` — block-skip optimisation
- Thumbnail download (`thumbnailDownloader.ts`)
- `queue.ts` parallel orchestration
- Telemetry

## Rust API shape

```rust
// crates/proton-drive-core/src/download.rs
pub struct FileDownloader { /* http, crypto, account */ }

impl FileDownloader {
    pub async fn download_to_writer(
        &self,
        node: NodeUid,
        writer: impl AsyncWrite + Unpin,
    ) -> Result<DownloadStats, Error> {
        // Resolves active revision, then drives the fetch→verify protocol
        // described above (presence-gate → fetch/hash/decrypt/write all
        // blocks → manifest-signature verify → XAttr cross-check).
    }
}

pub struct DownloadStats {
    pub bytes: u64,
    pub blocks: u32,
    pub last_modification_time: Option<DateTime<Utc>>,
    pub signature_verified: bool,
}
```

## Quality gates specific to this milestone

- **Round-trip test (gates merge):** upload `tests/fixtures/small.txt` via MD, immediately download via ME, assert plaintext bytes match.
- **Negative-path tests required (see `download.rs` test names in parens):**
  - Tampered block (flip one byte in `tests/fixtures/tampered_block.bin`) → `Error::IntegrityCheckFailed`
  - Missing ManifestSignature → abort before any block is fetched, `Error::Verification` (`missing_manifest_signature_aborts`)
  - Present-but-wrong-signer ManifestSignature → download still completes, `DownloadStats::signature_verified == false` (`manifest_wrong_signer_delivers_data_unverified`) — **not** an abort; see the corrected protocol above
  - Server returns 404 on revision lookup → `Error::NotFound`

## References

- `client/js/src/internal/download/fileDownloader.ts`
- `client/js/src/internal/download/apiService.ts`
- `client/js/src/internal/download/cryptoService.ts`
- `client/js/src/internal/download/controller.ts`
