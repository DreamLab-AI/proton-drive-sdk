# ADR-0008: Block-upload protocol — port JS happy path verbatim

**Status:** accepted, 2026-05-28.
**Context milestone:** MD.

## Decision

Port `client/js/src/internal/upload/` happy path 1:1 into `proton-drive-core::upload`. No optimisation, no architectural reinterpretation. Files <16 MiB only for MVP; large-file streaming + thumbnails + photo-specific paths are out-of-scope.

## The protocol (as derived from the JS SDK)

```
1. Client: POST /drive/v2/volumes/{volumeID}/files
   body: { ParentLinkID, Name (encrypted+signed), Hash (sha256 of name),
           MIMEType, NodeKey (PGP), NodePassphrase, NodePassphraseSignature,
           ContentKeyPacket, ContentKeyPacketSignature, SignatureAddress }
   → returns: { File: { ID, RevisionID } }

2. Client: chunks file into 4 MiB blocks. For each block index i:
     a. session_key = ContentKey (derived from ContentKeyPacket)
     b. ciphertext_i = encrypt_and_sign(block_i, session_key, [], address_priv, opts)
     c. hash_i = sha256(ciphertext_i)
     d. encsig_i = encrypt_session_key(sign(block_i, address_priv, "block-signature"),
                                        [address_pub])

3. Client: POST /drive/v2/volumes/{volumeID}/files/{linkID}/revisions/{revisionID}/blocks
   body: { BlockList: [{ Index, Size, Hash, EncSignature, Verifier }] }
   → returns: { UploadLinks: [{ Token, BareURL }], ThumbnailLink? }
   (the Verifier is a server-issued token used in step 4 to detect tampering)

4. Client: for each block, PUT ciphertext_i to BareURL with Authorization: Bearer Token
   The server runs `blockVerifier.ts` semantics: hash check + signature check.

5. Client: PUT /drive/v2/volumes/{volumeID}/files/{linkID}/revisions/{revisionID}
   body: { State: 1 (Active), ManifestSignature, XAttr, BlockList: [{ Index, Hash, Size, Token }] }
   → returns: { Revision: { ID, State, CreateTime, ... } }
```

## Implementation constraints

- **Concurrency: 1 block at a time.** JS does up to 4 parallel; MVP serialises. Reduce by changing one constant later.
- **Manifest signature:** binary signature over concatenated block hashes in order. Uses the address signing key. **No signature context** — corrected 2026-07-05: the JS reference's `signManifest()` (`client/js/src/crypto/driveCrypto.ts`) calls `signArmored(manifest, signingKey)` with no context argument at all, and `upload.rs` signs the manifest the same way (`self.openpgp.sign(&manifest_payload, &address_priv, "")`, with an explicit code comment citing this). This ADR previously claimed a `"drive.file.manifest"` context that was never real; do not resurrect it.
- **XAttr:** JSON `{ Common: { ModificationTime, Size, Digests: { SHA1: hex } } }` encrypted with node key + signed. Optional `ModificationTime` (already supported by the JS SDK).
- **Content key vs node key:**
  - **Node key** encrypts the metadata (name, xattr). Generated per-node.
  - **Content key** (the `ContentKey` session key embedded in `ContentKeyPacket`) encrypts the file blocks. Same session key for all blocks of a revision. Wrapped in PKESK to the node key.

## What is NOT ported in this ADR

- Thumbnail upload (`thumbnailUploader` paths)
- Photos block protocol (`photos/`)
- Resumable / multi-part / parallel-block upload
- Verifier retry loop on hash mismatch
- Telemetry (`upload/telemetry.ts`) — track later

## Rust API shape

```rust
// crates/proton-drive-core/src/upload.rs
pub struct FileUploader { /* http, crypto, account */ }

impl FileUploader {
    pub async fn upload_from_stream(
        &self,
        parent: NodeUid,
        metadata: UploadMetadata,
        stream: impl AsyncRead + Unpin,
    ) -> Result<Node, Error> { /* implements 5-step protocol */ }
}

pub struct UploadMetadata {
    pub name: String,
    pub mime_type: String,
    pub modification_time: Option<DateTime<Utc>>,
    pub size_hint: Option<u64>, // for XAttr; if absent, computed during upload
}
```

## Quality gates specific to this milestone

- **Negative-path tests required:**
  - Block hash mismatch → server rejects with 422 → uploader returns `Error::IntegrityCheckFailed`
  - Token expired mid-upload → retry once after refresh (MG); fail otherwise
  - Server returns fewer `UploadLinks` than requested blocks → `Error::ProtocolViolation`
- **Live test:** uploads `tests/fixtures/small.txt` (32 KiB random bytes) to `MyFiles/.test-pdtui/`. Asserts revision is active and reachable.
- **Cleanup:** test files go under a `.test-pdtui/` folder; user is responsible for periodic purge.

## References

- `client/js/src/internal/upload/fileUploader.ts` — top-level driver
- `client/js/src/internal/upload/apiService.ts` — endpoint shapes
- `client/js/src/internal/upload/cryptoService.ts` — block encryption / encsig
- `client/js/src/internal/upload/blockVerifier.ts` — server-side feedback handling
- `client/js/src/internal/upload/digests.ts` — SHA1 digest assembly for XAttr
