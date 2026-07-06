//! Block-download protocol. Ports `client/js/src/internal/download/` happy path.
//!
//! Implements ADR-0009: sequential block fetch, SHA-256 ciphertext integrity
//! check, per-revision manifest signature verification, per-block decryption,
//! and XAttr size/digest cross-check.
//!
//! Out of scope (ADR-0009 §"What is NOT ported"):
//! - Seekable / parallel download
//! - Thumbnail download
//! - Retry orchestration
//! - Telemetry

use std::sync::Arc;

use base64::Engine as _;
use sha1::Digest as Sha1Digest;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::http::{BlobRequest, HttpMethod, JsonRequest, ProtonDriveHttpClient};
use crate::nodes::NodeUid;
use proton_drive_api::common::{CODE_OK, ResponseEnvelope};
use proton_drive_api::download::{BlockResponse, GetRevisionResponse, RevisionWithBlocks};
use proton_drive_api::nodes::GetLinkResponse;
use proton_drive_api::shares::GetShareResponse;
use proton_drive_crypto::{OpenPgpCrypto, PrivateKey, PublicKey, VerificationStatus};

/// Blocks-per-page for the revision-blocks GET, matching the JS reference's
/// `BLOCKS_PAGE_SIZE` (`client/js/src/internal/download/apiService.ts`). The
/// server paginates this endpoint; a request without `PageSize`/
/// `FromBlockIndex` risks a silently truncated `Blocks` array on revisions
/// with more blocks than a single page.
const BLOCKS_PAGE_SIZE: u32 = 20;

// ── public types ──────────────────────────────────────────────────────────────

/// Statistics returned after a successful download.
#[derive(Debug, Clone)]
pub struct DownloadStats {
    /// Total plaintext bytes written to the writer.
    pub bytes: u64,
    /// Number of blocks fetched and decrypted.
    pub blocks: u32,
    /// Modification time from the XAttr (if present, decryptable, and
    /// parsed as one of the accepted formats — see
    /// [`crate::xattr::modification_time`]).
    pub last_modification_time: Option<std::time::SystemTime>,
    /// Set when `Common.ModificationTime` was present in the (decrypted)
    /// XAttr JSON but was not a value we could parse into a time — e.g. the
    /// wrong JSON type, or a string that isn't one of the accepted date
    /// formats. This is a **per-node degradation, never a download failure**:
    /// mirrors cs `DtoToMetadataConverter` recording a
    /// `ExtendedAttributesDeserializationError` against the node while still
    /// returning everything else that decrypted successfully
    /// (`reference/client/cs/src/Proton.Drive.Sdk/Nodes/DtoToMetadataConverter.cs`).
    /// The message shows the shape of what was actually in the JSON with
    /// digits redacted (`0`→`#`), mirroring cs
    /// `Iso8601DateTimeResultJsonConverter`'s `redactedValue` — enough to
    /// diagnose the format, not enough to leak the exact claimed timestamp
    /// into logs.
    pub modification_time_error: Option<String>,
    /// Whether the revision's manifest signature verified against the signer's
    /// keys. `false` means the data was delivered intact (every block matched
    /// its SHA-256 hash) but its **authenticity** could not be confirmed — e.g.
    /// the file was signed by an address key that has since been rotated out and
    /// is no longer published. This mirrors the JS SDK's
    /// `isDownloadCompleteWithSignatureIssues()`: bytes are still delivered, the
    /// signature failure is surfaced for the caller to act on, never silently
    /// swallowed. A *missing* manifest signature, by contrast, is a hard error.
    pub signature_verified: bool,
}

// ── FileDownloader ────────────────────────────────────────────────────────────

/// Drives the 8-step block-download protocol (ADR-0009).
///
/// Constructed via `ProtonDriveClient::file_downloader`. Caller supplies:
/// - The node to download (must be a file).
/// - A `share_id` that resolves to the volume (because `NodeUid.volume_id`
///   holds the share ID after MC's listing — see FIXME below).
pub struct FileDownloader {
    /// HTTP client supplied by the host.
    pub(crate) http: Arc<dyn ProtonDriveHttpClient>,
    /// Crypto module.
    pub(crate) crypto: Arc<dyn OpenPgpCrypto>,
    /// The node being downloaded (already fetched by the client).
    pub(crate) node_uid: NodeUid,
    /// True volume ID (translated from share via `GET drive/shares/{id}`).
    pub(crate) volume_id: String,
    /// Share ID — kept for future retry/debug paths; not yet used in download proper.
    #[allow(dead_code)]
    pub(crate) share_id: String,
    /// Revision ID fetched from the active revision of the node.
    pub(crate) revision_id: String,
    /// Node's private key (decrypted from NodePassphrase using the share key).
    /// For MVP, only root-level files are supported (parent IS the share root).
    pub(crate) node_private_key: PrivateKey,
    /// Public keys for the address that signed this revision's content
    /// (current + rotated-out). Empty when the revision has no signer address;
    /// verification then falls back to the node's own public key. A revision
    /// can be signed by a key the address has since replaced, so the whole set
    /// is carried (JS `getRevisionVerificationKeys` → `account.getPublicKeys`).
    pub(crate) signature_address_pubs: Vec<proton_drive_crypto::PublicKey>,
    /// ContentKeyPacket from the file link's `FileProperties` (base64 PKESK
    /// wrapping the content session key to the node key). The revision endpoint
    /// does not return it — it lives on the node, like JS `base64ContentKeyPacket`.
    pub(crate) content_key_packet: Option<String>,
    /// Armored detached signature over the ContentKeyPacket's decrypted
    /// session key, from the file link's `FileProperties` (falls back to the
    /// revision's own field if the link doesn't carry one — same fallback
    /// shape as `content_key_packet`). `None` when absent (legacy nodes).
    pub(crate) content_key_packet_signature: Option<String>,
    /// Verification keys for the ContentKeyPacketSignature: JS
    /// `decryptContentKeyPacket` verifies against `[nodeKey, ...
    /// keyVerificationKeys]`, where `keyVerificationKeys` comes from the
    /// node's own `SignatureEmail` (`Link.signature_email`) — which can differ
    /// from the revision's signer. The node's own key is added automatically
    /// in `download_to_writer`; this field carries only the resolved address
    /// key set (empty when the node has no signer address).
    pub(crate) content_key_verification_pubs: Vec<proton_drive_crypto::PublicKey>,
}

impl FileDownloader {
    /// Execute the full download protocol writing decrypted plaintext to `writer`.
    ///
    /// Order mirrors the JS SDK's `fileDownloader` (ADR-0009): blocks are
    /// fetched, hash-checked, decrypted, and written *first*, then the manifest
    /// signature is verified over the collected block hashes. The per-block
    /// SHA-256 hash check is the fatal data-integrity gate; block payloads
    /// themselves are not signature-verified (JS deliberately omits this — see
    /// `fetch_and_decrypt_block`). The manifest signature establishes
    /// *authenticity*: a missing signature is a hard error, but a present
    /// signature that fails to verify is reported via
    /// [`DownloadStats::signature_verified`] rather than discarding the data the
    /// caller already received.
    ///
    /// Steps:
    /// 1. `GET .../revisions/{id}` — fetch blocks (paginated) + manifest + content key
    /// 2. Decrypt content session key from `ContentKeyPacket`, non-fatally
    ///    verifying `ContentKeyPacketSignature`
    /// 3. For each block: fetch → SHA-256 hash check → decrypt → write
    /// 4. Verify manifest signature (over the block hashes) → `signature_verified`
    /// 5. XAttr cross-check (size + SHA1); missing XAttr is warned, not fatal
    pub async fn download_to_writer(
        self,
        mut writer: impl AsyncWrite + Unpin + Send,
    ) -> Result<DownloadStats> {
        // ── Step 1: fetch revision, paginating the Blocks array ──────────────
        // Mirrors JS `iterateRevisionBlocks`: the endpoint is paginated by
        // `PageSize`/`FromBlockIndex`, and the server may cap `Blocks` per
        // response even when those params are omitted — a single unpaginated
        // GET risks silently truncating revisions with more blocks than one
        // page. The first page carries the top-level fields (manifest
        // signature, content key packet, XAttr); JS only reads those from the
        // first page too, since they are constant across pages.
        let mut revision = self.fetch_revision_page(1).await?;

        if revision.blocks.is_empty() {
            // Server guarantees active revisions have at least one block.
            return Err(Error::Internal(
                "protocol violation: active revision has no blocks".into(),
            ));
        }

        let mut all_blocks = std::mem::take(&mut revision.blocks);
        // `all_blocks` is non-empty here (checked above), so `.last()` always
        // succeeds; the fallback is unreachable defensive code.
        let mut from_block_index = all_blocks.last().map(|b| b.index + 1).unwrap_or(1);

        loop {
            // JS keeps requesting the next page as long as the previous page
            // returned at least one block — even a short final page (fewer
            // than PageSize) — stopping only once a page returns zero blocks.
            let page = self.fetch_revision_page(from_block_index).await?;
            if page.blocks.is_empty() {
                break;
            }
            from_block_index = page
                .blocks
                .last()
                .map(|b| b.index + 1)
                .unwrap_or(from_block_index + 1);
            all_blocks.extend(page.blocks);
        }

        revision.blocks = all_blocks;

        // A *missing* manifest signature means there is no integrity guarantee
        // at all — abort before any block is fetched or decrypted (no plaintext
        // must reach the writer). JS cryptoService.verifyManifest throws
        // IntegrityError ("Missing integrity signature") for this case. The
        // cryptographic verification itself needs the block hashes and so runs
        // after the writes (Step 4); only this cheap presence gate is hoisted.
        if revision.manifest_signature.is_none() {
            return Err(Error::Verification(
                "revision has no ManifestSignature — integrity check failed".into(),
            ));
        }

        // ── Step 2: decrypt content session key ──────────────────────────────
        // The ContentKeyPacket lives on the node (file link's FileProperties),
        // not the revision (JS `base64ContentKeyPacket`). Prefer the node's;
        // fall back to the revision for legacy shapes.
        let content_key_packet = self
            .content_key_packet
            .as_deref()
            .or(revision.content_key_packet.as_deref())
            .ok_or_else(|| Error::Internal("missing ContentKeyPacket".into()))?;

        // The packet is base64 (BinaryString) on the wire; older callers may
        // pass armored input — the crypto layer dearmors transparently.
        let ckp_bytes = base64::engine::general_purpose::STANDARD
            .decode(content_key_packet)
            .unwrap_or_else(|_| content_key_packet.as_bytes().to_vec());

        let session_key = self
            .crypto
            .decrypt_session_key(&ckp_bytes, std::slice::from_ref(&self.node_private_key))
            .await
            .map_err(|e| Error::Decryption(format!("content session key: {e}")))?;

        // ContentKeyPacketSignature: verified non-fatally against
        // `[node_key, ...address_keys]`, mirroring JS `decryptContentKeyPacket`
        // -> `decryptAndVerifySessionKey(base64ContentKeyPacket,
        // armoredContentKeyPacketSignature, key, [key, ...keyVerificationKeys])`
        // (`reference/client/js/src/internal/nodes/cryptoService.ts:517-534`). The
        // signature covers the *decrypted session key bytes*, not the
        // ciphertext packet. A present-but-invalid or missing signature never
        // aborts the download — like JS's non-fatal `contentKeyPacketAuthor`,
        // this only degrades an authorship claim; the manifest signature
        // (Step 4) and per-block SHA-256 hash checks (Step 3) remain the
        // fatal integrity/authenticity gates.
        let content_key_packet_signature = self
            .content_key_packet_signature
            .as_deref()
            .or(revision.content_key_packet_signature.as_deref());
        if let Some(ckp_sig_armored) = content_key_packet_signature {
            let node_pub = self.crypto.public_key(&self.node_private_key).await?;
            let mut verification_keys =
                Vec::with_capacity(1 + self.content_key_verification_pubs.len());
            verification_keys.push(node_pub);
            verification_keys.extend(self.content_key_verification_pubs.iter().cloned());

            let sig_bytes = base64::engine::general_purpose::STANDARD
                .decode(ckp_sig_armored)
                .unwrap_or_else(|_| ckp_sig_armored.as_bytes().to_vec());

            match self
                .crypto
                .verify(&session_key.data, &sig_bytes, &verification_keys)
                .await
            {
                Ok(VerificationStatus::Ok) => {}
                Ok(other) => {
                    tracing::warn!(
                        node = %self.node_uid.node_id,
                        status = ?other,
                        "ContentKeyPacketSignature present but unverifiable — content key \
                         still used (non-fatal, mirrors JS contentKeyPacketAuthor)"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        node = %self.node_uid.node_id,
                        "ContentKeyPacketSignature verify error: {e} — treated as \
                         unverified (non-fatal)"
                    );
                }
            }
        } else {
            tracing::debug!(
                node = %self.node_uid.node_id,
                "no ContentKeyPacketSignature present — skipping content-key \
                 authorship check (legacy node)"
            );
        }

        let mut sorted_blocks = revision.blocks.clone();
        sorted_blocks.sort_by_key(|b| b.index);

        // ── Step 3: per-block fetch → SHA-256 hash check → decrypt → write ───
        let mut total_bytes: u64 = 0;
        let mut total_blocks: u32 = 0;
        let mut sha1_hasher = sha1::Sha1::new();

        for block in &sorted_blocks {
            let plaintext = self.fetch_and_decrypt_block(block, &session_key).await?;

            sha1_hasher.update(&plaintext);
            total_bytes += plaintext.len() as u64;
            total_blocks += 1;

            writer
                .write_all(&plaintext)
                .await
                .map_err(|e| Error::Internal(format!("write error: {e}")))?;
        }

        writer
            .flush()
            .await
            .map_err(|e| Error::Internal(format!("flush error: {e}")))?;

        // ── Step 4: verify manifest signature over the block hashes ──────────
        // Done after the data is delivered, like JS `fileDownloader`. A missing
        // signature is fatal; a present-but-unverifiable signature surfaces as
        // signature_verified=false (the bytes are intact per the hash checks).
        let manifest_sig_armored = revision.manifest_signature.as_deref();
        let signature_verified = self
            .verify_manifest(&sorted_blocks, manifest_sig_armored)
            .await?;

        // ── Step 5 (XAttr) ────────────────────────────────────────────────────
        // A garbage/unparseable ModificationTime is a per-node degradation,
        // never a download failure — the bytes above are already written and
        // hash-verified regardless of what `verify_xattr` finds here.
        let xattr_mtime = self
            .verify_xattr(
                revision.x_attr.as_deref(),
                total_bytes,
                &sha1_hasher.finalize(),
            )
            .await;

        Ok(DownloadStats {
            bytes: total_bytes,
            blocks: total_blocks,
            last_modification_time: xattr_mtime.time,
            modification_time_error: xattr_mtime.error,
            signature_verified,
        })
    }

    /// Execute the full download protocol writing decrypted plaintext to a
    /// file at `path`. Convenience wrapper over [`Self::download_to_writer`]
    /// that owns the destination file's lifecycle: it creates/truncates
    /// `path`, and on *any* failure from the protocol (bad block, missing or
    /// unverifiable manifest signature check, network error, …) removes the
    /// file it just opened, so a failed download never leaves a truncated,
    /// same-named file masquerading as a complete one at the caller's
    /// destination (B6). Only the file this call itself
    /// created/truncated is ever touched — a caller whose own setup fails
    /// before reaching this method (e.g. `file_downloader` construction)
    /// never had `path` opened in the first place, so nothing here runs.
    pub async fn download_to_path(self, path: &std::path::Path) -> Result<DownloadStats> {
        let file = tokio::fs::File::create(path)
            .await
            .map_err(|e| Error::Internal(format!("create {}: {e}", path.display())))?;

        match self.download_to_writer(file).await {
            Ok(stats) => Ok(stats),
            Err(err) => {
                if let Err(remove_err) = tokio::fs::remove_file(path).await {
                    tracing::warn!(
                        path = %path.display(),
                        "failed to remove partial download after error: {remove_err}"
                    );
                }
                Err(err)
            }
        }
    }

    /// Best-effort peek at the file's *claimed* plaintext size, decrypted
    /// from the revision's `XAttr` (`Common.Size`) — **not** `Revision.Size`,
    /// which is the ciphertext/block size on the wire and does not equal the
    /// plaintext length (encryption overhead, padding).
    ///
    /// Mirrors the C# SDK's `RevisionOperations.GetClaimedSizeAsync`
    /// (cs/v0.15.0 "Report extended attributes size for download progress
    /// instead of revision size";
    /// `client/cs/src/Proton.Drive.Sdk/Nodes/RevisionOperations.cs:68-78`),
    /// whose result (`DownloadState.ClaimedSize`) is threaded into the
    /// download progress callback's total instead of the revision's raw byte
    /// count (`RevisionReader.cs:59`,
    /// `downloaded => onProgress(downloaded, _state.ClaimedSize)`).
    ///
    /// Callers are expected to invoke this *before* `download_to_writer`/
    /// `download_to_path` to learn the total up front for a progress bar;
    /// it performs its own single-page revision fetch rather than
    /// restructuring the main download protocol to plumb a callback through,
    /// so it costs one extra (cheap, metadata-only) GET. Returns `Ok(None)`
    /// whenever the size can't be determined (missing XAttr, undecryptable,
    /// or malformed) rather than failing outright — a progress total is a UX
    /// nicety, not a correctness gate, matching `verify_xattr`'s existing
    /// best-effort treatment of the same field.
    pub async fn claimed_size(&self) -> Result<Option<u64>> {
        let revision = self.fetch_revision_page(1).await?;
        let Some(xattr_armored) = revision.x_attr.as_deref() else {
            return Ok(None);
        };
        Ok(crate::xattr::decrypt_xattr_json(
            &self.crypto,
            &self.node_private_key,
            &self.node_uid.node_id,
            xattr_armored,
        )
        .await
        .as_ref()
        .and_then(crate::xattr::size))
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Fetch one page of the revision's blocks, starting at `from_block_index`
    /// (1-based). Mirrors JS `iterateRevisionBlocks`'s
    /// `?PageSize=20&FromBlockIndex=N` query — the endpoint is paginated, and
    /// omitting these params risks the server silently capping `Blocks`.
    async fn fetch_revision_page(&self, from_block_index: u32) -> Result<RevisionWithBlocks> {
        // GET drive/v2/volumes/{VolumeID}/files/{linkID}/revisions/{revisionID}
        let path = format!(
            "/drive/v2/volumes/{}/files/{}/revisions/{}",
            self.volume_id, self.node_uid.node_id, self.revision_id,
        );
        let req = JsonRequest {
            method: HttpMethod::Get,
            path,
            query: vec![
                ("PageSize".to_owned(), BLOCKS_PAGE_SIZE.to_string()),
                ("FromBlockIndex".to_owned(), from_block_index.to_string()),
            ],
            headers: vec![],
            body: None,
        };
        let resp = self.http.request_json(req).await?;
        let env: ResponseEnvelope<GetRevisionResponse> = serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Internal(format!("revision JSON: {e}")))?;
        if env.code != CODE_OK {
            let msg = env
                .error
                .unwrap_or_else(|| format!("API error {}", env.code));
            return Err(if env.code == 2501 {
                Error::NotFound(msg)
            } else {
                Error::Internal(msg)
            });
        }
        Ok(env.inner.revision)
    }

    /// Verify the revision's manifest signature over the concatenated block
    /// hashes. Returns `Ok(true)` when the signature verifies, `Ok(false)` when
    /// a signature is present but cannot be verified against the signer's keys
    /// (authenticity unconfirmed — caller surfaces this via
    /// `DownloadStats::signature_verified`), and `Err` when the signature is
    /// *missing* (a hard integrity failure, matching JS `verifyManifest`'s
    /// `IntegrityError("Missing integrity signature")`).
    async fn verify_manifest(
        &self,
        sorted_blocks: &[BlockResponse],
        manifest_sig_armored: Option<&str>,
    ) -> Result<bool> {
        // Missing manifest signature is an integrity failure, not a legacy
        // tolerance. JS cryptoService.verifyManifest throws IntegrityError
        // ("Missing integrity signature") when armoredManifestSignature is absent.
        let Some(manifest_sig) = manifest_sig_armored else {
            return Err(Error::Verification(
                "revision has no ManifestSignature — integrity check failed".into(),
            ));
        };

        // manifest_payload = raw SHA-256 bytes of each block hash, concatenated
        // in ascending Index order.  Each block.hash is base64-encoded SHA-256
        // of the ciphertext.
        let mut manifest_payload: Vec<u8> = Vec::with_capacity(sorted_blocks.len() * 32);
        for block in sorted_blocks {
            let hash_bytes = base64::engine::general_purpose::STANDARD
                .decode(&block.hash)
                .map_err(|e| Error::Internal(format!("block hash base64: {e}")))?;
            manifest_payload.extend_from_slice(&hash_bytes);
        }

        // ManifestSignature is armored (`-----BEGIN PGP SIGNATURE-----`) on the
        // wire; older callers may pass base64 binary. `verify` dearmors armored
        // input, so try base64 first then fall back to the raw bytes.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(manifest_sig)
            .unwrap_or_else(|_| manifest_sig.as_bytes().to_vec());

        // Verification keys: the signer address's full public key set when
        // known (current + rotated-out — the revision may be signed by an old
        // key), otherwise fall back to the node's own public key. JS
        // getRevisionVerificationKeys returns `[nodeKey]` when no signer email
        // is present — it never skips verification.
        let verification_keys: Vec<proton_drive_crypto::PublicKey> =
            if self.signature_address_pubs.is_empty() {
                vec![self.crypto.public_key(&self.node_private_key).await?]
            } else {
                self.signature_address_pubs.clone()
            };

        let status = self
            .crypto
            .verify(&manifest_payload, &sig_bytes, &verification_keys)
            .await?;

        // A valid signature confirms authenticity. Anything else (no matching
        // signer / invalid) means the signature is present but unverifiable —
        // the bytes are still intact (every block matched its SHA-256 hash), so
        // we report rather than discard, mirroring JS's
        // isDownloadCompleteWithSignatureIssues. A *missing* signature was
        // already rejected above as a hard integrity failure.
        match status {
            VerificationStatus::Ok => Ok(true),
            other => {
                tracing::warn!(
                    node = %self.node_uid.node_id,
                    status = ?other,
                    "manifest signature present but unverifiable — data delivered, \
                     authenticity unconfirmed (signer key may have been rotated out)"
                );
                Ok(false)
            }
        }
    }

    async fn fetch_and_decrypt_block(
        &self,
        block: &BlockResponse,
        session_key: &proton_drive_crypto::SessionKey,
    ) -> Result<Vec<u8>> {
        // Step 3a: GET BareURL. Storage endpoints authenticate with the
        // `pm-storage-token` header, not the API bearer (JS `makeStorageRequest`).
        let req = BlobRequest {
            method: HttpMethod::Get,
            path: block.bare_url.clone(),
            query: vec![],
            headers: vec![("pm-storage-token".to_owned(), block.token.clone())],
            body: bytes::Bytes::new(),
        };
        let resp = self.http.request_blob(req).await?;
        let ciphertext = resp.body.to_vec();

        // Step 3b: assert sha256(ciphertext) == block.Hash. This is the fatal
        // data-integrity gate — a mismatch means the bytes are corrupt/tampered.
        let actual_hash = sha2::Sha256::digest(&ciphertext);
        let actual_hash_b64 = base64::engine::general_purpose::STANDARD.encode(actual_hash);
        if actual_hash_b64 != block.hash {
            return Err(Error::Integrity(format!(
                "block {} ciphertext hash mismatch: expected={} got={}",
                block.index, block.hash, actual_hash_b64
            )));
        }

        // Step 3c: decrypt. Block payloads are NOT signature-verified: JS
        // `decryptBlock` decrypts with the content session key and passes no
        // verification keys ("We do not verify signatures on blocks ... Any
        // issue on the blocks should be considered serious integrity issue").
        // Authenticity is established by the manifest signature; the SHA-256
        // hash check above guards data integrity.
        //
        // `block.encrypted_signature` (`EncSignature` on the wire, a per-block
        // detached signature) is deliberately never read here — this is
        // JS-faithful, not an oversight: the JS reference has no code path
        // that decrypts or verifies it either (only the manifest signature
        // over the block hashes, checked in `verify_manifest`, establishes
        // per-revision authenticity). It is only ever fetched because the
        // wire response includes it.
        let (plaintext, _sig_status) = self
            .crypto
            .decrypt_and_verify(&ciphertext, session_key, &[])
            .await
            .map_err(|e| Error::Decryption(format!("block {}: {e}", block.index)))?;

        Ok(plaintext)
    }

    /// Attempt to cross-check the assembled file against XAttr metadata.
    ///
    /// XAttr decryption is best-effort for MVP: if absent or undecryptable,
    /// we warn and return an empty result (JS does the same fallback).
    ///
    /// When present, we verify:
    /// - `Common.Size` matches `total_bytes`
    /// - `Common.Digests.SHA1` matches `sha1_digest`
    /// - `Common.ModificationTime`, if present, parses as one of the accepted
    ///   date formats (see [`crate::xattr::modification_time`]); an unparseable
    ///   value is reported via [`crate::xattr::XAttrModificationTime::error`]
    ///   but never aborts the download — mirrors cs `DtoToMetadataConverter`
    ///   treating a modification-time parse failure as a per-node degradation,
    ///   not a fatal error.
    ///
    /// Decryption + parsing live in [`crate::xattr`], shared with the
    /// listing/fetch path; this method adds only the download-specific
    /// cross-checks that compare the claimed values against the bytes actually
    /// downloaded.
    async fn verify_xattr(
        &self,
        xattr_armored: Option<&str>,
        total_bytes: u64,
        sha1_digest: &[u8],
    ) -> crate::xattr::XAttrModificationTime {
        let Some(xattr_raw) = xattr_armored else {
            tracing::debug!(
                node_id = %self.node_uid.node_id,
                "no XAttr on revision — skipping XAttr cross-check (legacy revision)"
            );
            return crate::xattr::XAttrModificationTime::default();
        };

        let Some(xattr) = crate::xattr::decrypt_xattr_json(
            &self.crypto,
            &self.node_private_key,
            &self.node_uid.node_id,
            xattr_raw,
        )
        .await
        else {
            return crate::xattr::XAttrModificationTime::default();
        };

        // Verify size.
        if let Some(claimed_size) = crate::xattr::size(&xattr) {
            if claimed_size != total_bytes {
                tracing::error!(
                    node_id = %self.node_uid.node_id,
                    "XAttr size mismatch: claimed={claimed_size} actual={total_bytes}"
                );
                // We log but do not abort — consistent with JS fallback.
            }
        }

        // Verify SHA1.
        if let Some(claimed_sha1) = crate::xattr::content_sha1(&xattr) {
            let actual_sha1_hex = hex::encode(sha1_digest);
            if claimed_sha1 != actual_sha1_hex {
                tracing::error!(
                    node_id = %self.node_uid.node_id,
                    "XAttr SHA1 mismatch: claimed={claimed_sha1} actual={actual_sha1_hex}"
                );
            }
        }

        // Extract modification time (per-node degradation on parse failure,
        // never a download error — the error is logged here, then surfaced via
        // the returned struct for the caller's DownloadStats).
        let mtime = crate::xattr::modification_time(&xattr);
        if let Some(err) = &mtime.error {
            tracing::warn!(node_id = %self.node_uid.node_id, "{err}");
        }
        mtime
    }
}

// ── factory helpers (used by ProtonDriveClient) ───────────────────────────────

/// Context gathered during `file_downloader()` construction.
pub struct FileDownloaderContext {
    /// The resolved true volume ID (from the share lookup).
    pub volume_id: String,
    pub share_id: String,
    pub revision_id: String,
    pub node_private_key: PrivateKey,
    pub signature_address_pubs: Vec<proton_drive_crypto::PublicKey>,
}

/// Resolve the volume ID from a share ID.
///
/// `NodeUid.volume_id` from MC's listing holds a **share ID**, not a volume ID.
/// This function translates it via `GET drive/shares/{shareID}`.
///
/// FIXME: NodeUid naming — see MC commit f6b29b1
pub async fn resolve_volume_id(
    http: &Arc<dyn ProtonDriveHttpClient>,
    share_id: &str,
) -> Result<String> {
    let path = format!("/drive/shares/{share_id}");
    let req = JsonRequest {
        method: HttpMethod::Get,
        path,
        query: vec![],
        headers: vec![],
        body: None,
    };
    let resp = http.request_json(req).await?;
    let env: ResponseEnvelope<GetShareResponse> = serde_json::from_slice(&resp.body)
        .map_err(|e| Error::Internal(format!("share JSON: {e}")))?;
    if env.code != CODE_OK {
        let msg = env
            .error
            .unwrap_or_else(|| format!("API error {}", env.code));
        return Err(Error::NotFound(msg));
    }
    Ok(env.inner.share.volume_id)
}

/// Resolve the active revision ID from a link.
pub async fn resolve_active_revision(
    http: &Arc<dyn ProtonDriveHttpClient>,
    share_id: &str,
    link_id: &str,
) -> Result<(String, Option<String>)> {
    // GET drive/shares/{shareID}/links/{linkID}
    let path = format!("/drive/shares/{share_id}/links/{link_id}");
    let req = JsonRequest {
        method: HttpMethod::Get,
        path,
        query: vec![],
        headers: vec![],
        body: None,
    };
    let resp = http.request_json(req).await?;
    let env: ResponseEnvelope<GetLinkResponse> = serde_json::from_slice(&resp.body)
        .map_err(|e| Error::Internal(format!("link JSON: {e}")))?;
    if env.code != CODE_OK {
        let msg = env
            .error
            .unwrap_or_else(|| format!("API error {}", env.code));
        return Err(Error::NotFound(msg));
    }
    let link = env.inner.link;
    let revision_id = link
        .file_properties
        .as_ref()
        .and_then(|fp| fp.active_revision.as_ref())
        .map(|rev| rev.id.clone())
        .ok_or_else(|| Error::NotFound("no active revision on link".into()))?;

    let signature_email = link
        .file_properties
        .and_then(|fp| fp.active_revision.and_then(|r| r.signature_email));

    Ok((revision_id, signature_email))
}

/// Verify a detached signature over already-decrypted plaintext, non-fatally.
/// Never returns `Err` for a verification failure — only for a hard crypto
/// error, which is itself downgraded to a logged, unverified result here so
/// callers (node/share passphrase unlock) never abort key derivation over a
/// signature problem. Mirrors JS's non-fatal `verified`/`verificationErrors`
/// handling (e.g. `driveCrypto.decryptKey`, which "doesn't throw in case of
/// verification issue").
///
/// `armored_signature` empty means "no signature was supplied at all", which
/// JS treats as a verification error too (`decryptArmoredAndVerifyDetached`:
/// "Signature is missing") rather than skipping the check outright.
async fn verify_detached_non_fatal(
    crypto: &Arc<dyn OpenPgpCrypto>,
    data: &[u8],
    armored_signature: &str,
    verification_keys: &[PublicKey],
) -> VerificationStatus {
    if armored_signature.trim().is_empty() {
        return VerificationStatus::NoSignature;
    }
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(armored_signature)
        .unwrap_or_else(|_| armored_signature.as_bytes().to_vec());

    match crypto.verify(data, &sig_bytes, verification_keys).await {
        Ok(status) => status,
        Err(e) => {
            tracing::warn!("passphrase signature verify error: {e} — treated as unverified");
            VerificationStatus::SignatureInvalid
        }
    }
}

/// Full node key decryption: decrypt passphrase from NodePassphrase, then
/// unlock the NodeKey armored private key with that passphrase.
///
/// `parent_key` is the node's *immediate* parent key: the share key for the
/// share root node, or the parent **node** key for any nested node. Callers
/// walk the parent chain (see `ProtonDriveClient::resolve_node_key_via_chain`)
/// to assemble the right `parent_key` for nested nodes.
///
/// `node_passphrase_signature_armored` (`NodePassphraseSignature` on the wire)
/// is verified against `verification_keys` — the signer address's public keys
/// when the node has a `SignatureEmail`, else the caller's parent-key
/// fallback (JS `decryptNode`'s `keyVerificationKeys`) — non-fatally, exactly
/// like JS `cryptoService.decryptKey` ->
/// `driveCrypto.decryptKey(armoredKey, armoredNodePassphrase,
/// armoredNodePassphraseSignature, [parentKey], verificationKeys)`
/// (`reference/client/js/src/internal/nodes/cryptoService.ts:307-338`): a
/// present-but-invalid or missing signature never aborts key derivation, it
/// is only surfaced as an authorship result via the returned
/// [`VerificationStatus`] (mirrors JS's non-fatal `keyAuthor`).
pub async fn decrypt_node_private_key(
    crypto: &Arc<dyn OpenPgpCrypto>,
    node_key_armored: &str,
    node_passphrase_encrypted_b64: &str,
    node_passphrase_signature_armored: &str,
    parent_key: &PrivateKey,
    verification_keys: &[PublicKey],
) -> Result<(PrivateKey, VerificationStatus)> {
    // Decrypt the node passphrase by using parent key to unwrap PKESK.
    // NodePassphrase is an armored PGPMessage on the wire; older callers may
    // pass base64-encoded binary. Try base64 first, else use the raw bytes —
    // the crypto layer dearmors armored input transparently.
    let ckp_bytes = base64::engine::general_purpose::STANDARD
        .decode(node_passphrase_encrypted_b64)
        .unwrap_or_else(|_| node_passphrase_encrypted_b64.as_bytes().to_vec());

    let passphrase_session_key = crypto
        .decrypt_session_key(&ckp_bytes, std::slice::from_ref(parent_key))
        .await
        .map_err(|e| Error::Decryption(format!("node passphrase session key: {e}")))?;

    // NodePassphrase itself carries no embedded signature — NodePassphraseSignature
    // is a separate *detached* signature (a distinct wire field), so the
    // decrypt here uses no verification keys; the detached signature is
    // checked separately below (mirrors JS's `decryptArmoredAndVerifyDetached`
    // split between decrypting `armoredPassphrase` and verifying
    // `armoredPassphraseSignature` against the resulting plaintext).
    let (passphrase_bytes, _) = crypto
        .decrypt_and_verify(&ckp_bytes, &passphrase_session_key, &[])
        .await
        .map_err(|e| Error::Decryption(format!("node passphrase plaintext: {e}")))?;

    // Secret material: wipe the heap buffer on drop (ADR-0011).
    let passphrase = Zeroizing::new(passphrase_bytes);

    let verified = verify_detached_non_fatal(
        crypto,
        &passphrase,
        node_passphrase_signature_armored,
        verification_keys,
    )
    .await;

    let passphrase_str = std::str::from_utf8(&passphrase)
        .map_err(|e| Error::Internal(format!("passphrase utf-8: {e}")))?;

    let node_priv = crypto
        .decrypt_key(node_key_armored, passphrase_str)
        .await
        .map_err(|e| Error::Decryption(format!("node key unlock: {e}")))?;

    Ok((node_priv, verified))
}

/// Decrypt the share key using the user's address private key.
///
/// `share_passphrase_signature_armored` (`PassphraseSignature` on the wire) is
/// verified non-fatally against `verification_keys` (the share creator's
/// address public keys), mirroring JS `SharesCryptoService.decryptRootShare`
/// -> `driveCrypto.decryptKey(..., addressPublicKeys)`
/// (`reference/client/js/src/internal/shares/cryptoService.ts:75-103`): a
/// present-but-invalid or missing signature never aborts share-key
/// derivation, only degrades the returned [`VerificationStatus`].
pub async fn decrypt_share_key(
    crypto: &Arc<dyn OpenPgpCrypto>,
    share_key_armored: &str,
    share_passphrase_encrypted_b64: &str,
    share_passphrase_signature_armored: &str,
    address_key: &PrivateKey,
    verification_keys: &[PublicKey],
) -> Result<(PrivateKey, VerificationStatus)> {
    // Share Passphrase is an armored PGPMessage on the wire; older callers may
    // pass base64-encoded binary. Try base64 first, else use the raw bytes.
    let pp_bytes = base64::engine::general_purpose::STANDARD
        .decode(share_passphrase_encrypted_b64)
        .unwrap_or_else(|_| share_passphrase_encrypted_b64.as_bytes().to_vec());

    let pp_session_key = crypto
        .decrypt_session_key(&pp_bytes, std::slice::from_ref(address_key))
        .await
        .map_err(|e| Error::Decryption(format!("share passphrase session key: {e}")))?;

    // Same decrypt/verify split as `decrypt_node_private_key`: the passphrase
    // message carries no embedded signature; PassphraseSignature is detached
    // and checked separately below.
    let (pp_bytes_plain, _) = crypto
        .decrypt_and_verify(&pp_bytes, &pp_session_key, &[])
        .await
        .map_err(|e| Error::Decryption(format!("share passphrase plaintext: {e}")))?;

    // Secret material: wipe the heap buffer on drop (ADR-0011).
    let passphrase = Zeroizing::new(pp_bytes_plain);

    let verified = verify_detached_non_fatal(
        crypto,
        &passphrase,
        share_passphrase_signature_armored,
        verification_keys,
    )
    .await;

    let passphrase_str = std::str::from_utf8(&passphrase)
        .map_err(|e| Error::Internal(format!("share passphrase utf-8: {e}")))?;

    let share_priv = crypto
        .decrypt_key(share_key_armored, passphrase_str)
        .await
        .map_err(|e| Error::Decryption(format!("share key unlock: {e}")))?;

    Ok((share_priv, verified))
}

/// Decrypt an armored node name with the parent node's private key.
///
/// The node `Name` is an armored PGP MESSAGE (PKESK to the parent node key +
/// SEIPD), signed by the address key. JS `decryptNodeName` →
/// `decryptArmoredAndVerify(name, [parentKey], verificationKeys)`; verification
/// failures are non-fatal (the caller reads `verified` separately), so we
/// decrypt without verification keys here.
pub async fn decrypt_node_name(
    crypto: &Arc<dyn OpenPgpCrypto>,
    armored_name: &str,
    parent_key: &PrivateKey,
) -> Result<String> {
    let name_bytes = armored_name.as_bytes();
    let session_key = crypto
        .decrypt_session_key(name_bytes, std::slice::from_ref(parent_key))
        .await
        .map_err(|e| Error::Decryption(format!("node name session key: {e}")))?;
    let (plaintext, _) = crypto
        .decrypt_and_verify(name_bytes, &session_key, &[])
        .await
        .map_err(|e| Error::Decryption(format!("node name plaintext: {e}")))?;
    String::from_utf8(plaintext).map_err(|e| Error::Internal(format!("node name utf-8: {e}")))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::http::{BlobRequest, JsonRequest, JsonResponse};
    use bytes::Bytes;
    use proton_drive_api::download::{BlockResponse, RevisionWithBlocks};
    use proton_drive_crypto::{
        ArmorKind, EncryptOptions, OpenPgpCrypto, PrivateKey, PublicKey, RpgpCrypto, armor,
    };

    // ── mock HTTP client for protocol tests ───────────────────────────────────

    /// HTTP responses keyed by path prefix. `request_json` serves each key's
    /// bodies in order across successive matching calls (the last body
    /// repeats once the list is exhausted), which lets the pagination tests
    /// simulate distinct pages of the same `revisions/{id}` path; `add`
    /// registers a single fixed response served on every call, unaffected.
    struct MockHttpClient {
        responses: std::collections::HashMap<String, Vec<Bytes>>,
        calls: std::sync::Mutex<std::collections::HashMap<String, usize>>,
    }

    impl MockHttpClient {
        fn new() -> Self {
            Self {
                responses: Default::default(),
                calls: Default::default(),
            }
        }
        /// Register a single fixed response served on every matching call.
        fn add(&mut self, path: impl Into<String>, body: impl Into<Bytes>) {
            self.responses.insert(path.into(), vec![body.into()]);
        }
        /// Register a sequence of responses served in order on successive
        /// calls to the same matching path (used to simulate paginated GETs).
        fn add_sequence(&mut self, path: impl Into<String>, bodies: Vec<Bytes>) {
            self.responses.insert(path.into(), bodies);
        }
    }

    #[async_trait::async_trait]
    impl ProtonDriveHttpClient for MockHttpClient {
        async fn request_json(&self, req: JsonRequest) -> Result<JsonResponse> {
            let Some((key, bodies)) = self
                .responses
                .iter()
                .find(|(k, _)| req.path.contains(k.as_str()))
            else {
                return Ok(JsonResponse {
                    status: 200,
                    headers: vec![],
                    body: Bytes::from(r#"{"Code":2501,"Error":"not found"}"#.to_owned()),
                });
            };
            let mut calls = self.calls.lock().unwrap();
            let idx = calls.entry(key.clone()).or_insert(0);
            let body = bodies
                .get(*idx)
                .or_else(|| bodies.last())
                .cloned()
                .unwrap_or_default();
            *idx += 1;
            Ok(JsonResponse {
                status: 200,
                headers: vec![],
                body,
            })
        }

        async fn request_blob(&self, req: BlobRequest) -> Result<JsonResponse> {
            let body = self
                .responses
                .iter()
                .find(|(k, _)| req.path.contains(k.as_str()))
                .and_then(|(_, v)| v.first().cloned())
                .ok_or_else(|| Error::NotFound(format!("mock: no response for {}", req.path)))?;
            Ok(JsonResponse {
                status: 200,
                headers: vec![],
                body,
            })
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    async fn make_crypto_material(passphrase: &str) -> (RpgpCrypto, PrivateKey, PublicKey) {
        let crypto = RpgpCrypto::new();
        let (priv_key, pub_armored) = crypto
            .generate_key(passphrase, EncryptOptions::default())
            .await
            .unwrap();
        let pub_key = PublicKey {
            armored: pub_armored,
            fingerprint_hex: priv_key.fingerprint_hex.clone(),
        };
        (crypto, priv_key, pub_key)
    }

    fn block_hash_b64(ciphertext: &[u8]) -> String {
        use sha2::Digest;
        let h = sha2::Sha256::digest(ciphertext);
        base64::engine::general_purpose::STANDARD.encode(h)
    }

    /// A "no more blocks" continuation page, registered as the *second* mock
    /// response for `revisions/{id}` so the paginating download loop
    /// terminates after the first (real) page — mirroring the real server's
    /// final empty-`Blocks` page. Field values other than `Blocks` are
    /// irrelevant: `download_to_writer` only reads `revision.blocks` from
    /// pages after the first.
    fn empty_continuation_page(revision_id: &str) -> String {
        serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": revision_id, "State": null,
                "Blocks": [],
                "ManifestSignature": null, "ContentKeyPacket": null,
                "ContentKeyPacketSignature": null, "XAttr": null, "SignatureEmail": null,
            }
        })
        .to_string()
    }

    // ── protocol unit tests ───────────────────────────────────────────────────

    /// Happy-path protocol test: single block, no XAttr, weak (no-signature) manifest.
    #[tokio::test]
    async fn download_single_block_happy_path() {
        // We use sign_key for both signing and as the "node key" that holds the
        // content session key, to avoid needing a separate node key roundtrip in tests.
        let (crypto, sign_key, sign_pub) = make_crypto_material("sign-pass").await;
        let crypto = Arc::new(crypto);

        let plaintext = b"hello proton drive download";

        // Generate session key and encrypt the block.
        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();

        // Block ciphertext: PKESK+SEIPD combined.
        // We include sign_pub as an encryption key so the block is PKESK+SEIPD.
        // In the real protocol, blocks are bare SEIPD (session key comes from
        // ContentKeyPacket separately). We use PKESK+SEIPD here because rpgp's
        // decrypt_with_session_key requires a Message::Encrypted variant which
        // needs at least one PKESK to be parsed correctly by Message::from_bytes.
        // NOTE: this is a known crypto-layer limitation; the production path
        // works because the real JS SDK uses a different decryptBlock primitive.
        let ciphertext = crypto
            .encrypt_and_sign(
                plaintext,
                &session_key,
                std::slice::from_ref(&sign_pub),
                &sign_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();

        let ciphertext_hash = block_hash_b64(&ciphertext);

        // ContentKeyPacket: separate PKESK wrapping the same session key.
        let ckp_bytes = crypto
            .encrypt_session_key(&session_key, std::slice::from_ref(&sign_pub))
            .await
            .unwrap();
        let ckp_b64 = base64::engine::general_purpose::STANDARD.encode(&ckp_bytes);

        // Build a manifest signature over the single block hash bytes.
        let hash_bytes = base64::engine::general_purpose::STANDARD
            .decode(&ciphertext_hash)
            .unwrap();
        // No signature context — matches production manifest signing (JS
        // signManifest → signArmored uses no context).
        let manifest_sig_bytes = crypto.sign(&hash_bytes, &sign_key, "").await.unwrap();
        let manifest_sig_b64 =
            base64::engine::general_purpose::STANDARD.encode(&manifest_sig_bytes);

        // Assemble mock HTTP responses.
        let revision = RevisionWithBlocks {
            id: "rev-1".into(),
            state: Some(1),
            blocks: vec![BlockResponse {
                index: 1,
                bare_url: "https://cdn.proton.me/block-1".into(),
                token: "tok-abc".into(),
                hash: ciphertext_hash.clone(),
                encrypted_signature: None,
                size: ciphertext.len() as u64,
            }],
            manifest_signature: Some(manifest_sig_b64),
            content_key_packet: Some(ckp_b64),
            content_key_packet_signature: None,
            x_attr: None,
            signature_email: None,
        };
        let revision_json = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": revision.id,
                "State": revision.state,
                "Blocks": [{
                    "Index": 1,
                    "BareURL": "https://cdn.proton.me/block-1",
                    "Token": "tok-abc",
                    "Hash": ciphertext_hash,
                    "EncryptedSignature": null,
                    "Size": ciphertext.len() as u64,
                }],
                "ManifestSignature": revision.manifest_signature,
                "ContentKeyPacket": revision.content_key_packet,
                "ContentKeyPacketSignature": null,
                "XAttr": null,
                "SignatureEmail": null,
            }
        })
        .to_string();

        let block_url_key = "block-1";
        let mut mock = MockHttpClient::new();
        mock.add_sequence(
            "revisions/rev-1",
            vec![
                Bytes::from(revision_json),
                Bytes::from(empty_continuation_page("rev-1")),
            ],
        );
        mock.add(block_url_key, Bytes::from(ciphertext.clone()));

        let downloader = FileDownloader {
            http: Arc::new(mock),
            crypto: crypto.clone(),
            node_uid: NodeUid {
                volume_id: "vol-1".into(),
                node_id: "link-1".into(),
            },
            volume_id: "vol-1".into(),
            share_id: "share-1".into(),
            revision_id: "rev-1".into(),
            // We encrypted the session key to sign_key so use sign_key as node_private_key.
            node_private_key: sign_key,
            signature_address_pubs: vec![sign_pub],
            content_key_packet: None,
            content_key_packet_signature: None,
            content_key_verification_pubs: Vec::new(),
        };

        let mut output = Vec::new();
        let stats = downloader.download_to_writer(&mut output).await.unwrap();

        assert_eq!(output, plaintext);
        assert_eq!(stats.bytes, plaintext.len() as u64);
        assert_eq!(stats.blocks, 1);
        assert!(
            stats.signature_verified,
            "manifest signed by the resolved verification key must verify"
        );
    }

    // -----------------------------------------------------------------------
    // cs/v0.15.0 "Report extended attributes size for download progress
    // instead of revision size"
    // (`client/cs/src/Proton.Drive.Sdk/Nodes/RevisionOperations.cs:68-78`).
    // -----------------------------------------------------------------------

    /// `claimed_size` must read `Common.Size` from the decrypted XAttr, via a
    /// single up-front revision fetch independent of the main block-download
    /// loop.
    #[tokio::test]
    async fn claimed_size_reads_xattr_common_size() {
        let (crypto, node_key, node_pub) = make_crypto_material("claimed-size-pass").await;
        let crypto = Arc::new(crypto);

        // A deliberately implausible declared size that cannot be confused
        // with any block/ciphertext length in this test, proving the value
        // returned genuinely comes from the XAttr and nowhere else (e.g. not
        // `Revision.Size`, which this wire shape doesn't even carry).
        const CLAIMED_SIZE: u64 = 123_456_789;

        let xattr_json = serde_json::json!({ "Common": { "Size": CLAIMED_SIZE } }).to_string();
        let xattr_session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let xattr_ciphertext = crypto
            .encrypt_and_sign(
                xattr_json.as_bytes(),
                &xattr_session_key,
                std::slice::from_ref(&node_pub),
                &node_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let xattr_armored = armor(&xattr_ciphertext, ArmorKind::Message);

        let revision_json = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "rev-claimed-size", "State": 1, "Blocks": [],
                "ManifestSignature": null, "ContentKeyPacket": null,
                "ContentKeyPacketSignature": null, "XAttr": xattr_armored,
                "SignatureEmail": null,
            }
        })
        .to_string();

        let mut mock = MockHttpClient::new();
        mock.add("revisions/rev-claimed-size", Bytes::from(revision_json));

        let downloader = FileDownloader {
            http: Arc::new(mock),
            crypto: crypto.clone(),
            node_uid: NodeUid {
                volume_id: "vol-1".into(),
                node_id: "link-1".into(),
            },
            volume_id: "vol-1".into(),
            share_id: "share-1".into(),
            revision_id: "rev-claimed-size".into(),
            node_private_key: node_key,
            signature_address_pubs: vec![node_pub],
            content_key_packet: None,
            content_key_packet_signature: None,
            content_key_verification_pubs: Vec::new(),
        };

        let claimed = downloader.claimed_size().await.unwrap();
        assert_eq!(
            claimed,
            Some(CLAIMED_SIZE),
            "claimed_size must read Common.Size from the decrypted XAttr"
        );
    }

    /// A legacy revision with no XAttr must yield `Ok(None)`, not fail —
    /// matching `verify_xattr`'s existing best-effort treatment of a missing
    /// XAttr, since a progress total is a UX nicety, not a correctness gate.
    #[tokio::test]
    async fn claimed_size_is_none_when_xattr_absent() {
        let (crypto, node_key, node_pub) = make_crypto_material("no-xattr-pass").await;
        let crypto = Arc::new(crypto);

        let revision_json = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "rev-no-xattr", "State": 1, "Blocks": [],
                "ManifestSignature": null, "ContentKeyPacket": null,
                "ContentKeyPacketSignature": null, "XAttr": null,
                "SignatureEmail": null,
            }
        })
        .to_string();

        let mut mock = MockHttpClient::new();
        mock.add("revisions/rev-no-xattr", Bytes::from(revision_json));

        let downloader = FileDownloader {
            http: Arc::new(mock),
            crypto: crypto.clone(),
            node_uid: NodeUid {
                volume_id: "vol-1".into(),
                node_id: "link-1".into(),
            },
            volume_id: "vol-1".into(),
            share_id: "share-1".into(),
            revision_id: "rev-no-xattr".into(),
            node_private_key: node_key,
            signature_address_pubs: vec![node_pub],
            content_key_packet: None,
            content_key_packet_signature: None,
            content_key_verification_pubs: Vec::new(),
        };

        let claimed = downloader.claimed_size().await.unwrap();
        assert_eq!(
            claimed, None,
            "a legacy revision with no XAttr must yield None, not fail the download"
        );
    }

    /// JS-faithful soft failure: a manifest signed by a key the downloader
    /// cannot resolve (e.g. the signer's key was rotated out of the account)
    /// must still deliver the byte-identical data — the SHA-256 hash checks
    /// already proved block integrity — while reporting
    /// `signature_verified == false`. This mirrors JS's
    /// `isDownloadCompleteWithSignatureIssues`: the official client downloads
    /// such files rather than discarding them.
    #[tokio::test]
    async fn manifest_wrong_signer_delivers_data_unverified() {
        // node key (decrypts the block / content key); a *different* key signs
        // the manifest, standing in for a since-rotated signer key.
        let (crypto, node_key, node_pub) = make_crypto_material("node-pass").await;
        let crypto = Arc::new(crypto);
        let (_c2, other_key, _other_pub) = make_crypto_material("other-pass").await;

        let plaintext = b"data signed by a rotated-out key";
        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let ciphertext = crypto
            .encrypt_and_sign(
                plaintext,
                &session_key,
                std::slice::from_ref(&node_pub),
                &node_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let hash = block_hash_b64(&ciphertext);
        let ckp_bytes = crypto
            .encrypt_session_key(&session_key, std::slice::from_ref(&node_pub))
            .await
            .unwrap();
        let ckp_b64 = base64::engine::general_purpose::STANDARD.encode(&ckp_bytes);

        // Manifest signed by `other_key`, which is NOT in signature_address_pubs
        // and is NOT the node key — so verification cannot succeed.
        let hash_bytes = base64::engine::general_purpose::STANDARD
            .decode(&hash)
            .unwrap();
        let manifest_sig = crypto.sign(&hash_bytes, &other_key, "").await.unwrap();
        let manifest_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&manifest_sig);

        let revision_json = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "rev-1", "State": 1,
                "Blocks": [{"Index": 1, "BareURL": "https://cdn/block", "Token": "t",
                             "Hash": hash, "EncryptedSignature": null,
                             "Size": ciphertext.len() as u64}],
                "ManifestSignature": manifest_sig_b64, "ContentKeyPacket": ckp_b64,
                "ContentKeyPacketSignature": null, "XAttr": null, "SignatureEmail": null,
            }
        })
        .to_string();

        let mut mock = MockHttpClient::new();
        mock.add_sequence(
            "revisions/rev-1",
            vec![
                Bytes::from(revision_json),
                Bytes::from(empty_continuation_page("rev-1")),
            ],
        );
        mock.add("cdn/block", Bytes::from(ciphertext));

        let downloader = FileDownloader {
            http: Arc::new(mock),
            crypto,
            node_uid: NodeUid {
                volume_id: "v".into(),
                node_id: "l".into(),
            },
            volume_id: "v".into(),
            share_id: "s".into(),
            revision_id: "rev-1".into(),
            node_private_key: node_key,
            // node_pub here would verify the block but NOT the manifest (signed
            // by other_key); leaving it empty forces node-key fallback, which
            // also fails to verify other_key's signature.
            signature_address_pubs: Vec::new(),
            content_key_packet: None,
            content_key_packet_signature: None,
            content_key_verification_pubs: Vec::new(),
        };

        let mut out = Vec::new();
        let stats = downloader.download_to_writer(&mut out).await.unwrap();
        assert_eq!(out, plaintext, "data must be delivered byte-identical");
        assert_eq!(stats.blocks, 1);
        assert!(
            !stats.signature_verified,
            "manifest signed by an unresolvable key must report signature_verified=false"
        );
    }

    /// Tampered block: SHA-256 hash mismatch → `Error::Integrity`.
    #[tokio::test]
    async fn tampered_block_fails_integrity_check() {
        let (crypto, sign_key, sign_pub) = make_crypto_material("sign-pass").await;
        let crypto = Arc::new(crypto);

        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();

        let ciphertext = crypto
            .encrypt_and_sign(
                b"real data",
                &session_key,
                &[],
                &sign_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();

        // Use correct hash but serve tampered bytes.
        let correct_hash = block_hash_b64(&ciphertext);
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xff; // flip one byte

        let ckp_bytes = crypto
            .encrypt_session_key(&session_key, std::slice::from_ref(&sign_pub))
            .await
            .unwrap();
        let ckp_b64 = base64::engine::general_purpose::STANDARD.encode(&ckp_bytes);

        // Valid manifest signature over the *correct* hash, so manifest
        // verification passes and we reach the per-block hash check, which
        // fails on the tampered bytes.
        let correct_hash_bytes = base64::engine::general_purpose::STANDARD
            .decode(&correct_hash)
            .unwrap();
        let manifest_sig = crypto
            .sign(&correct_hash_bytes, &sign_key, "")
            .await
            .unwrap();
        let manifest_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&manifest_sig);

        let revision_json = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "rev-1", "State": 1,
                "Blocks": [{"Index": 1, "BareURL": "https://cdn/block", "Token": "t",
                             "Hash": correct_hash, "EncryptedSignature": null,
                             "Size": tampered.len() as u64}],
                "ManifestSignature": manifest_sig_b64, "ContentKeyPacket": ckp_b64,
                "ContentKeyPacketSignature": null, "XAttr": null, "SignatureEmail": null,
            }
        })
        .to_string();

        let mut mock = MockHttpClient::new();
        mock.add_sequence(
            "revisions/rev-1",
            vec![
                Bytes::from(revision_json),
                Bytes::from(empty_continuation_page("rev-1")),
            ],
        );
        mock.add("cdn/block", Bytes::from(tampered));

        let downloader = FileDownloader {
            http: Arc::new(mock),
            crypto: crypto.clone(),
            node_uid: NodeUid {
                volume_id: "v".into(),
                node_id: "l".into(),
            },
            volume_id: "v".into(),
            share_id: "s".into(),
            revision_id: "rev-1".into(),
            node_private_key: sign_key,
            signature_address_pubs: vec![sign_pub],
            content_key_packet: None,
            content_key_packet_signature: None,
            content_key_verification_pubs: Vec::new(),
        };

        let mut out = Vec::new();
        let err = downloader.download_to_writer(&mut out).await.unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "expected Integrity, got {err:?}"
        );
    }

    /// Server returns 404 on revision lookup → `Error::NotFound`.
    #[tokio::test]
    async fn revision_not_found_returns_error() {
        let (crypto, sign_key, sign_pub) = make_crypto_material("p").await;
        let crypto = Arc::new(crypto);

        // No entry added → mock returns 404 envelope.
        let mock = MockHttpClient::new();

        let downloader = FileDownloader {
            http: Arc::new(mock),
            crypto,
            node_uid: NodeUid {
                volume_id: "v".into(),
                node_id: "l".into(),
            },
            volume_id: "v".into(),
            share_id: "s".into(),
            revision_id: "rev-missing".into(),
            node_private_key: sign_key,
            signature_address_pubs: vec![sign_pub],
            content_key_packet: None,
            content_key_packet_signature: None,
            content_key_verification_pubs: Vec::new(),
        };

        let mut out = Vec::new();
        let err = downloader.download_to_writer(&mut out).await.unwrap_err();
        assert!(
            matches!(err, Error::NotFound(_) | Error::Internal(_)),
            "expected NotFound or Internal, got {err:?}"
        );
    }

    /// Security: a revision with no ManifestSignature must abort the download
    /// (JS throws IntegrityError "Missing integrity signature"). The block must
    /// never be decrypted.
    #[tokio::test]
    async fn missing_manifest_signature_aborts() {
        let (crypto, sign_key, sign_pub) = make_crypto_material("p").await;
        let crypto = Arc::new(crypto);

        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let ciphertext = crypto
            .encrypt_and_sign(
                b"secret",
                &session_key,
                std::slice::from_ref(&sign_pub),
                &sign_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let hash = block_hash_b64(&ciphertext);
        let ckp_bytes = crypto
            .encrypt_session_key(&session_key, std::slice::from_ref(&sign_pub))
            .await
            .unwrap();
        let ckp_b64 = base64::engine::general_purpose::STANDARD.encode(&ckp_bytes);

        let revision_json = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "rev-1", "State": 1,
                "Blocks": [{"Index": 1, "BareURL": "https://cdn/block", "Token": "t",
                             "Hash": hash, "EncryptedSignature": null,
                             "Size": ciphertext.len() as u64}],
                "ManifestSignature": null, "ContentKeyPacket": ckp_b64,
                "ContentKeyPacketSignature": null, "XAttr": null, "SignatureEmail": null,
            }
        })
        .to_string();

        let mut mock = MockHttpClient::new();
        mock.add_sequence(
            "revisions/rev-1",
            vec![
                Bytes::from(revision_json),
                Bytes::from(empty_continuation_page("rev-1")),
            ],
        );
        mock.add("cdn/block", Bytes::from(ciphertext));

        let downloader = FileDownloader {
            http: Arc::new(mock),
            crypto,
            node_uid: NodeUid {
                volume_id: "v".into(),
                node_id: "l".into(),
            },
            volume_id: "v".into(),
            share_id: "s".into(),
            revision_id: "rev-1".into(),
            node_private_key: sign_key,
            signature_address_pubs: vec![sign_pub],
            content_key_packet: None,
            content_key_packet_signature: None,
            content_key_verification_pubs: Vec::new(),
        };

        let mut out = Vec::new();
        let err = downloader.download_to_writer(&mut out).await.unwrap_err();
        assert!(
            matches!(err, Error::Verification(_)),
            "expected Verification, got {err:?}"
        );
        assert!(out.is_empty(), "no plaintext must be written on abort");
    }

    /// Security: when no signer address public key is available, manifest
    /// verification falls back to the node's own public key (JS
    /// getRevisionVerificationKeys → `[nodeKey]`) rather than skipping.
    #[tokio::test]
    async fn manifest_verifies_with_node_key_fallback() {
        let (crypto, node_key, node_pub) = make_crypto_material("node-pass").await;
        let crypto = Arc::new(crypto);

        let plaintext = b"fallback verification path";
        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let ciphertext = crypto
            .encrypt_and_sign(
                plaintext,
                &session_key,
                std::slice::from_ref(&node_pub),
                &node_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let hash = block_hash_b64(&ciphertext);
        let ckp_bytes = crypto
            .encrypt_session_key(&session_key, std::slice::from_ref(&node_pub))
            .await
            .unwrap();
        let ckp_b64 = base64::engine::general_purpose::STANDARD.encode(&ckp_bytes);

        // Manifest signed by the node key — the only key the downloader can
        // fall back to, since signature_address_pubs is empty.
        let hash_bytes = base64::engine::general_purpose::STANDARD
            .decode(&hash)
            .unwrap();
        let manifest_sig = crypto.sign(&hash_bytes, &node_key, "").await.unwrap();
        let manifest_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&manifest_sig);

        let revision_json = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "rev-1", "State": 1,
                "Blocks": [{"Index": 1, "BareURL": "https://cdn/block", "Token": "t",
                             "Hash": hash, "EncryptedSignature": null,
                             "Size": ciphertext.len() as u64}],
                "ManifestSignature": manifest_sig_b64, "ContentKeyPacket": ckp_b64,
                "ContentKeyPacketSignature": null, "XAttr": null, "SignatureEmail": null,
            }
        })
        .to_string();

        let mut mock = MockHttpClient::new();
        mock.add_sequence(
            "revisions/rev-1",
            vec![
                Bytes::from(revision_json),
                Bytes::from(empty_continuation_page("rev-1")),
            ],
        );
        mock.add("cdn/block", Bytes::from(ciphertext));

        let downloader = FileDownloader {
            http: Arc::new(mock),
            crypto,
            node_uid: NodeUid {
                volume_id: "v".into(),
                node_id: "l".into(),
            },
            volume_id: "v".into(),
            share_id: "s".into(),
            revision_id: "rev-1".into(),
            node_private_key: node_key,
            signature_address_pubs: Vec::new(),
            content_key_packet: None,
            content_key_packet_signature: None,
            content_key_verification_pubs: Vec::new(),
        };

        let mut out = Vec::new();
        let stats = downloader.download_to_writer(&mut out).await.unwrap();
        assert_eq!(out, plaintext);
        assert_eq!(stats.blocks, 1);
    }

    /// A revision whose blocks span multiple pages must be assembled in full,
    /// not just from the first page. Mirrors JS `iterateRevisionBlocks`: page
    /// 1 returns blocks 1-2 (simulating a short page), page 2 returns block
    /// 3, page 3 returns zero blocks (the terminating page).
    #[tokio::test]
    async fn download_paginates_across_multiple_block_pages() {
        let (crypto, sign_key, sign_pub) = make_crypto_material("sign-pass").await;
        let crypto = Arc::new(crypto);

        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();

        let mut plaintexts = Vec::new();
        let mut ciphertexts = Vec::new();
        let mut hashes = Vec::new();
        for i in 0..3u8 {
            let pt = format!("block-{i}-data").into_bytes();
            let ct = crypto
                .encrypt_and_sign(&pt, &session_key, &[], &sign_key, EncryptOptions::default())
                .await
                .unwrap();
            hashes.push(block_hash_b64(&ct));
            plaintexts.push(pt);
            ciphertexts.push(ct);
        }

        let ckp_bytes = crypto
            .encrypt_session_key(&session_key, std::slice::from_ref(&sign_pub))
            .await
            .unwrap();
        let ckp_b64 = base64::engine::general_purpose::STANDARD.encode(&ckp_bytes);

        // manifest payload = concatenated raw hash bytes across ALL
        // blocks/pages, in ascending index order.
        let mut manifest_payload = Vec::new();
        for h in &hashes {
            manifest_payload.extend(base64::engine::general_purpose::STANDARD.decode(h).unwrap());
        }
        let manifest_sig = crypto.sign(&manifest_payload, &sign_key, "").await.unwrap();
        let manifest_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&manifest_sig);

        fn block_json(index: u32, url: &str, hash: &str, size: u64) -> serde_json::Value {
            serde_json::json!({
                "Index": index, "BareURL": url, "Token": format!("tok-{index}"),
                "Hash": hash, "EncryptedSignature": null, "Size": size,
            })
        }

        let page1 = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "rev-1", "State": 1,
                "Blocks": [
                    block_json(1, "https://cdn/block-1", &hashes[0], ciphertexts[0].len() as u64),
                    block_json(2, "https://cdn/block-2", &hashes[1], ciphertexts[1].len() as u64),
                ],
                "ManifestSignature": manifest_sig_b64, "ContentKeyPacket": ckp_b64,
                "ContentKeyPacketSignature": null, "XAttr": null, "SignatureEmail": null,
            }
        })
        .to_string();

        let page2 = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "rev-1", "State": 1,
                "Blocks": [
                    block_json(3, "https://cdn/block-3", &hashes[2], ciphertexts[2].len() as u64),
                ],
                "ManifestSignature": manifest_sig_b64, "ContentKeyPacket": ckp_b64,
                "ContentKeyPacketSignature": null, "XAttr": null, "SignatureEmail": null,
            }
        })
        .to_string();

        let page3 = empty_continuation_page("rev-1");

        let mut mock = MockHttpClient::new();
        mock.add_sequence(
            "revisions/rev-1",
            vec![Bytes::from(page1), Bytes::from(page2), Bytes::from(page3)],
        );
        mock.add("cdn/block-1", Bytes::from(ciphertexts[0].clone()));
        mock.add("cdn/block-2", Bytes::from(ciphertexts[1].clone()));
        mock.add("cdn/block-3", Bytes::from(ciphertexts[2].clone()));

        let downloader = FileDownloader {
            http: Arc::new(mock),
            crypto: crypto.clone(),
            node_uid: NodeUid {
                volume_id: "v".into(),
                node_id: "l".into(),
            },
            volume_id: "v".into(),
            share_id: "s".into(),
            revision_id: "rev-1".into(),
            node_private_key: sign_key,
            signature_address_pubs: vec![sign_pub],
            content_key_packet: None,
            content_key_packet_signature: None,
            content_key_verification_pubs: Vec::new(),
        };

        let mut out = Vec::new();
        let stats = downloader.download_to_writer(&mut out).await.unwrap();

        let expected: Vec<u8> = plaintexts.concat();
        assert_eq!(
            out, expected,
            "blocks from every page must be assembled, in order"
        );
        assert_eq!(
            stats.blocks, 3,
            "must fetch blocks across all pages, not just the first"
        );
        assert!(stats.signature_verified);
    }

    /// Shared fixture for the mid-stream-failure tests below: a 3-block
    /// revision where block 2's declared hash doesn't match the (tampered)
    /// bytes actually served, while blocks 1 and 3 are valid. Returns the
    /// crypto/http/key material needed to construct a fresh `FileDownloader`
    /// per test (each is consumed by value by `download_to_writer`/
    /// `download_to_path`).
    async fn mid_stream_tampered_fixture() -> (
        Arc<dyn OpenPgpCrypto>,
        Arc<dyn ProtonDriveHttpClient>,
        PrivateKey,
        Vec<PublicKey>,
    ) {
        let (crypto, sign_key, sign_pub) = make_crypto_material("sign-pass").await;
        let crypto: Arc<dyn OpenPgpCrypto> = Arc::new(crypto);

        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();

        let good1 = crypto
            .encrypt_and_sign(
                b"block-one-ok",
                &session_key,
                &[],
                &sign_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let good2_real = crypto
            .encrypt_and_sign(
                b"block-two-real",
                &session_key,
                &[],
                &sign_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let good3 = crypto
            .encrypt_and_sign(
                b"block-three-ok",
                &session_key,
                &[],
                &sign_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();

        let hash1 = block_hash_b64(&good1);
        // Server declares block 2's hash as the *untampered* ciphertext's
        // hash, but serves tampered bytes — the fatal ciphertext-integrity
        // gate (Step 3b) must catch this.
        let hash2 = block_hash_b64(&good2_real);
        let hash3 = block_hash_b64(&good3);

        let mut tampered2 = good2_real.clone();
        tampered2[0] ^= 0xff;

        let ckp_bytes = crypto
            .encrypt_session_key(&session_key, std::slice::from_ref(&sign_pub))
            .await
            .unwrap();
        let ckp_b64 = base64::engine::general_purpose::STANDARD.encode(&ckp_bytes);

        let mut manifest_payload = Vec::new();
        for h in [&hash1, &hash2, &hash3] {
            manifest_payload.extend(base64::engine::general_purpose::STANDARD.decode(h).unwrap());
        }
        let manifest_sig = crypto.sign(&manifest_payload, &sign_key, "").await.unwrap();
        let manifest_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&manifest_sig);

        let revision_json = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "rev-1", "State": 1,
                "Blocks": [
                    {"Index": 1, "BareURL": "https://cdn/block-1", "Token": "t1",
                     "Hash": hash1, "EncryptedSignature": null, "Size": good1.len() as u64},
                    {"Index": 2, "BareURL": "https://cdn/block-2", "Token": "t2",
                     "Hash": hash2, "EncryptedSignature": null, "Size": tampered2.len() as u64},
                    {"Index": 3, "BareURL": "https://cdn/block-3", "Token": "t3",
                     "Hash": hash3, "EncryptedSignature": null, "Size": good3.len() as u64},
                ],
                "ManifestSignature": manifest_sig_b64, "ContentKeyPacket": ckp_b64,
                "ContentKeyPacketSignature": null, "XAttr": null, "SignatureEmail": null,
            }
        })
        .to_string();

        let mut mock = MockHttpClient::new();
        mock.add_sequence(
            "revisions/rev-1",
            vec![
                Bytes::from(revision_json),
                Bytes::from(empty_continuation_page("rev-1")),
            ],
        );
        mock.add("cdn/block-1", Bytes::from(good1));
        mock.add("cdn/block-2", Bytes::from(tampered2));
        mock.add("cdn/block-3", Bytes::from(good3));

        let http: Arc<dyn ProtonDriveHttpClient> = Arc::new(mock);
        (crypto, http, sign_key, vec![sign_pub])
    }

    fn build_downloader(
        http: Arc<dyn ProtonDriveHttpClient>,
        crypto: Arc<dyn OpenPgpCrypto>,
        node_private_key: PrivateKey,
        signature_address_pubs: Vec<PublicKey>,
    ) -> FileDownloader {
        FileDownloader {
            http,
            crypto,
            node_uid: NodeUid {
                volume_id: "v".into(),
                node_id: "l".into(),
            },
            volume_id: "v".into(),
            share_id: "s".into(),
            revision_id: "rev-1".into(),
            node_private_key,
            signature_address_pubs,
            content_key_packet: None,
            content_key_packet_signature: None,
            content_key_verification_pubs: Vec::new(),
        }
    }

    /// B6 (partial-write half): a failure on block 2 (of 3) must leave the
    /// writer holding exactly block 1's already-written plaintext — proving
    /// the streaming writer really does deliver a truncated prefix mid-stream
    /// on failure, not nothing at all.
    #[tokio::test]
    async fn mid_stream_block_failure_writer_already_has_earlier_blocks() {
        let (crypto, http, node_key, sig_pubs) = mid_stream_tampered_fixture().await;
        let downloader = build_downloader(http, crypto, node_key, sig_pubs);

        let mut out = Vec::new();
        let err = downloader.download_to_writer(&mut out).await.unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "expected Integrity, got {err:?}"
        );
        assert_eq!(
            out, b"block-one-ok",
            "block 1's plaintext must already be written before block 2 fails"
        );
    }

    /// B6 (cleanup half): the same mid-stream failure, but through
    /// `download_to_path` — the partially-written destination file must be
    /// removed, not left behind as a truncated same-named file.
    #[tokio::test]
    async fn mid_stream_block_failure_removes_partial_file() {
        let (crypto, http, node_key, sig_pubs) = mid_stream_tampered_fixture().await;
        let downloader = build_downloader(http, crypto, node_key, sig_pubs);

        let dest = std::env::temp_dir().join(format!(
            "pdtui-test-midfail-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = tokio::fs::remove_file(&dest).await;

        let err = downloader.download_to_path(&dest).await.unwrap_err();
        assert!(
            matches!(err, Error::Integrity(_)),
            "expected Integrity, got {err:?}"
        );
        assert!(
            tokio::fs::metadata(&dest).await.is_err(),
            "partial file left after mid-stream failure must be removed"
        );
    }

    /// `download_to_path` happy path: file is created and holds the exact
    /// decrypted bytes.
    #[tokio::test]
    async fn download_to_path_writes_file_on_success() {
        let (crypto, sign_key, sign_pub) = make_crypto_material("sign-pass").await;
        let crypto = Arc::new(crypto);

        let plaintext = b"download_to_path happy path";
        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let ciphertext = crypto
            .encrypt_and_sign(
                plaintext,
                &session_key,
                std::slice::from_ref(&sign_pub),
                &sign_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let hash = block_hash_b64(&ciphertext);
        let ckp_bytes = crypto
            .encrypt_session_key(&session_key, std::slice::from_ref(&sign_pub))
            .await
            .unwrap();
        let ckp_b64 = base64::engine::general_purpose::STANDARD.encode(&ckp_bytes);
        let hash_bytes = base64::engine::general_purpose::STANDARD
            .decode(&hash)
            .unwrap();
        let manifest_sig = crypto.sign(&hash_bytes, &sign_key, "").await.unwrap();
        let manifest_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&manifest_sig);

        let revision_json = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "rev-1", "State": 1,
                "Blocks": [{"Index": 1, "BareURL": "https://cdn/block", "Token": "t",
                             "Hash": hash, "EncryptedSignature": null,
                             "Size": ciphertext.len() as u64}],
                "ManifestSignature": manifest_sig_b64, "ContentKeyPacket": ckp_b64,
                "ContentKeyPacketSignature": null, "XAttr": null, "SignatureEmail": null,
            }
        })
        .to_string();

        let mut mock = MockHttpClient::new();
        mock.add_sequence(
            "revisions/rev-1",
            vec![
                Bytes::from(revision_json),
                Bytes::from(empty_continuation_page("rev-1")),
            ],
        );
        mock.add("cdn/block", Bytes::from(ciphertext));

        let downloader = build_downloader(Arc::new(mock), crypto, sign_key, vec![sign_pub]);

        let dest = std::env::temp_dir().join(format!(
            "pdtui-test-ok-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = tokio::fs::remove_file(&dest).await;

        let stats = downloader.download_to_path(&dest).await.unwrap();
        let content = tokio::fs::read(&dest).await.unwrap();
        assert_eq!(content, plaintext);
        assert_eq!(stats.bytes, plaintext.len() as u64);
        let _ = tokio::fs::remove_file(&dest).await;
    }

    /// ContentKeyPacketSignature verification is non-fatal: a signature that
    /// cannot be resolved to any known key must never abort the download —
    /// only the manifest signature and per-block hash checks are fatal gates.
    #[tokio::test]
    async fn content_key_packet_signature_failure_is_non_fatal() {
        let (crypto, sign_key, sign_pub) = make_crypto_material("sign-pass").await;
        let crypto = Arc::new(crypto);
        let (_c2, other_key, _other_pub) = make_crypto_material("other-pass").await;

        let plaintext = b"ckp signature is only a soft check";
        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let ciphertext = crypto
            .encrypt_and_sign(
                plaintext,
                &session_key,
                std::slice::from_ref(&sign_pub),
                &sign_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let hash = block_hash_b64(&ciphertext);
        let ckp_bytes = crypto
            .encrypt_session_key(&session_key, std::slice::from_ref(&sign_pub))
            .await
            .unwrap();
        let ckp_b64 = base64::engine::general_purpose::STANDARD.encode(&ckp_bytes);
        let hash_bytes = base64::engine::general_purpose::STANDARD
            .decode(&hash)
            .unwrap();
        let manifest_sig = crypto.sign(&hash_bytes, &sign_key, "").await.unwrap();
        let manifest_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&manifest_sig);

        // ContentKeyPacketSignature signed by a key that is neither the node
        // key nor in `content_key_verification_pubs` — cannot verify.
        let ckp_sig = crypto
            .sign(&session_key.data, &other_key, "")
            .await
            .unwrap();
        let ckp_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&ckp_sig);

        let revision_json = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "rev-1", "State": 1,
                "Blocks": [{"Index": 1, "BareURL": "https://cdn/block", "Token": "t",
                             "Hash": hash, "EncryptedSignature": null,
                             "Size": ciphertext.len() as u64}],
                "ManifestSignature": manifest_sig_b64, "ContentKeyPacket": ckp_b64,
                "ContentKeyPacketSignature": null, "XAttr": null, "SignatureEmail": null,
            }
        })
        .to_string();

        let mut mock = MockHttpClient::new();
        mock.add_sequence(
            "revisions/rev-1",
            vec![
                Bytes::from(revision_json),
                Bytes::from(empty_continuation_page("rev-1")),
            ],
        );
        mock.add("cdn/block", Bytes::from(ciphertext));

        let mut downloader = build_downloader(Arc::new(mock), crypto, sign_key, vec![sign_pub]);
        downloader.content_key_packet_signature = Some(ckp_sig_b64);
        // Left empty: nothing resolves the wrong signer, so the check must
        // fail — and the download must still succeed regardless.

        let mut out = Vec::new();
        let stats = downloader.download_to_writer(&mut out).await.unwrap();
        assert_eq!(
            out, plaintext,
            "an unverifiable CKP signature must never block delivery"
        );
        assert!(
            stats.signature_verified,
            "manifest signature is unaffected by CKP signature outcome"
        );
    }

    // ── node/share passphrase signature verification tests ────────────────────

    /// `decrypt_node_private_key` verifies `NodePassphraseSignature` against
    /// the supplied verification keys and reports `VerificationStatus::Ok`
    /// when it resolves, mirroring JS `decryptKey`.
    #[tokio::test]
    async fn decrypt_node_private_key_verifies_passphrase_signature() {
        let (crypto, parent_key, _parent_pub) = make_crypto_material("parent-pass").await;
        let crypto: Arc<dyn OpenPgpCrypto> = Arc::new(crypto);
        let parent_pub = crypto.public_key(&parent_key).await.unwrap();

        let (signer_priv, signer_pub_armored) = crypto
            .generate_key("signer-pass", EncryptOptions::default())
            .await
            .unwrap();
        let signer_pub = PublicKey {
            armored: signer_pub_armored,
            fingerprint_hex: signer_priv.fingerprint_hex.clone(),
        };

        let node_unlock_passphrase = b"node-unlock-pass";
        let (node_priv, _) = crypto
            .generate_key("node-unlock-pass", EncryptOptions::default())
            .await
            .unwrap();

        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let passphrase_message = crypto
            .encrypt(
                node_unlock_passphrase,
                &session_key,
                std::slice::from_ref(&parent_pub),
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let passphrase_b64 = base64::engine::general_purpose::STANDARD.encode(&passphrase_message);

        let sig_bytes = crypto
            .sign(node_unlock_passphrase, &signer_priv, "")
            .await
            .unwrap();
        let sig_armored = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        let (unlocked, status) = decrypt_node_private_key(
            &crypto,
            &node_priv.armored,
            &passphrase_b64,
            &sig_armored,
            &parent_key,
            &[signer_pub],
        )
        .await
        .unwrap();

        assert_eq!(status, VerificationStatus::Ok);
        assert_eq!(unlocked.fingerprint_hex, node_priv.fingerprint_hex);
    }

    /// A `NodePassphraseSignature` that cannot be resolved to any known key
    /// (e.g. account lookup failed, or the signer key was rotated out) must
    /// never abort node-key derivation — only degrade the reported
    /// `VerificationStatus`, exactly like JS's non-fatal `keyAuthor`.
    #[tokio::test]
    async fn decrypt_node_private_key_never_aborts_on_bad_signature() {
        let (crypto, parent_key, _parent_pub) = make_crypto_material("parent-pass").await;
        let crypto: Arc<dyn OpenPgpCrypto> = Arc::new(crypto);
        let parent_pub = crypto.public_key(&parent_key).await.unwrap();

        let (other_priv, _) = crypto
            .generate_key("other-pass", EncryptOptions::default())
            .await
            .unwrap();

        let node_unlock_passphrase = b"node-unlock-pass-2";
        let (node_priv, _) = crypto
            .generate_key("node-unlock-pass-2", EncryptOptions::default())
            .await
            .unwrap();

        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let passphrase_message = crypto
            .encrypt(
                node_unlock_passphrase,
                &session_key,
                std::slice::from_ref(&parent_pub),
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let passphrase_b64 = base64::engine::general_purpose::STANDARD.encode(&passphrase_message);

        // Signed by `other_priv`, which is NOT among the verification keys
        // passed below — simulates an unresolvable/rotated-out signer.
        let sig_bytes = crypto
            .sign(node_unlock_passphrase, &other_priv, "")
            .await
            .unwrap();
        let sig_armored = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        let (unlocked, status) = decrypt_node_private_key(
            &crypto,
            &node_priv.armored,
            &passphrase_b64,
            &sig_armored,
            &parent_key,
            &[],
        )
        .await
        .unwrap();

        assert_eq!(
            unlocked.fingerprint_hex, node_priv.fingerprint_hex,
            "key must still unlock despite an unverifiable signature"
        );
        assert_ne!(status, VerificationStatus::Ok);
    }

    /// An empty `NodePassphraseSignature` (no signature supplied at all) is
    /// reported as `NoSignature`, not an abort — mirrors JS treating a
    /// missing `armoredPassphraseSignature` as a (non-fatal) verification
    /// error rather than skipping the check.
    #[tokio::test]
    async fn decrypt_node_private_key_missing_signature_is_non_fatal() {
        let (crypto, parent_key, _parent_pub) = make_crypto_material("parent-pass").await;
        let crypto: Arc<dyn OpenPgpCrypto> = Arc::new(crypto);
        let parent_pub = crypto.public_key(&parent_key).await.unwrap();

        let node_unlock_passphrase = b"node-unlock-pass-3";
        let (node_priv, _) = crypto
            .generate_key("node-unlock-pass-3", EncryptOptions::default())
            .await
            .unwrap();

        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let passphrase_message = crypto
            .encrypt(
                node_unlock_passphrase,
                &session_key,
                std::slice::from_ref(&parent_pub),
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let passphrase_b64 = base64::engine::general_purpose::STANDARD.encode(&passphrase_message);

        let (unlocked, status) = decrypt_node_private_key(
            &crypto,
            &node_priv.armored,
            &passphrase_b64,
            "",
            &parent_key,
            &[],
        )
        .await
        .unwrap();

        assert_eq!(unlocked.fingerprint_hex, node_priv.fingerprint_hex);
        assert_eq!(status, VerificationStatus::NoSignature);
    }

    /// `decrypt_share_key` mirrors the same non-fatal verification contract
    /// as `decrypt_node_private_key` for the share's own `PassphraseSignature`.
    #[tokio::test]
    async fn decrypt_share_key_never_aborts_on_bad_signature() {
        let (crypto, address_key, _address_pub) = make_crypto_material("address-pass").await;
        let crypto: Arc<dyn OpenPgpCrypto> = Arc::new(crypto);
        let address_pub = crypto.public_key(&address_key).await.unwrap();

        let (other_priv, _) = crypto
            .generate_key("other-pass", EncryptOptions::default())
            .await
            .unwrap();

        let share_unlock_passphrase = b"share-unlock-pass";
        let (share_priv, _) = crypto
            .generate_key("share-unlock-pass", EncryptOptions::default())
            .await
            .unwrap();

        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let passphrase_message = crypto
            .encrypt(
                share_unlock_passphrase,
                &session_key,
                std::slice::from_ref(&address_pub),
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let passphrase_b64 = base64::engine::general_purpose::STANDARD.encode(&passphrase_message);

        let sig_bytes = crypto
            .sign(share_unlock_passphrase, &other_priv, "")
            .await
            .unwrap();
        let sig_armored = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        let (unlocked, status) = decrypt_share_key(
            &crypto,
            &share_priv.armored,
            &passphrase_b64,
            &sig_armored,
            &address_key,
            &[],
        )
        .await
        .unwrap();

        assert_eq!(
            unlocked.fingerprint_hex, share_priv.fingerprint_hex,
            "share key must still unlock despite an unverifiable signature"
        );
        assert_ne!(status, VerificationStatus::Ok);
    }

    /// Out-of-order block delivery must not corrupt assembly or
    /// verification: `download_to_writer` sorts blocks by `Index` before
    /// both writing plaintext and hashing the manifest payload (lines
    /// 263-264), so a server that returns blocks in descending order must
    /// still assemble correctly and verify against a manifest signed over
    /// the ascending-order concatenation.
    #[tokio::test]
    async fn download_sorts_out_of_order_blocks_before_verifying_manifest() {
        let (crypto, sign_key, sign_pub) = make_crypto_material("sign-pass").await;
        let crypto = Arc::new(crypto);

        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();

        let ct1 = crypto
            .encrypt_and_sign(
                b"first-half-",
                &session_key,
                &[],
                &sign_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let ct2 = crypto
            .encrypt_and_sign(
                b"second-half",
                &session_key,
                &[],
                &sign_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let hash1 = block_hash_b64(&ct1);
        let hash2 = block_hash_b64(&ct2);

        let ckp_bytes = crypto
            .encrypt_session_key(&session_key, std::slice::from_ref(&sign_pub))
            .await
            .unwrap();
        let ckp_b64 = base64::engine::general_purpose::STANDARD.encode(&ckp_bytes);

        // Manifest signed over the ASCENDING-index concatenation
        // (hash1 || hash2) — the order `download_to_writer` must reconstruct
        // regardless of the delivery order below.
        let mut manifest_payload = Vec::new();
        manifest_payload.extend(
            base64::engine::general_purpose::STANDARD
                .decode(&hash1)
                .unwrap(),
        );
        manifest_payload.extend(
            base64::engine::general_purpose::STANDARD
                .decode(&hash2)
                .unwrap(),
        );
        let manifest_sig = crypto.sign(&manifest_payload, &sign_key, "").await.unwrap();
        let manifest_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&manifest_sig);

        // Server lists block 2 BEFORE block 1 — out-of-order delivery.
        let revision_json = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "rev-1", "State": 1,
                "Blocks": [
                    {"Index": 2, "BareURL": "https://cdn/block-2", "Token": "t2",
                     "Hash": hash2, "EncryptedSignature": null, "Size": ct2.len() as u64},
                    {"Index": 1, "BareURL": "https://cdn/block-1", "Token": "t1",
                     "Hash": hash1, "EncryptedSignature": null, "Size": ct1.len() as u64},
                ],
                "ManifestSignature": manifest_sig_b64, "ContentKeyPacket": ckp_b64,
                "ContentKeyPacketSignature": null, "XAttr": null, "SignatureEmail": null,
            }
        })
        .to_string();

        let mut mock = MockHttpClient::new();
        mock.add_sequence(
            "revisions/rev-1",
            vec![
                Bytes::from(revision_json),
                Bytes::from(empty_continuation_page("rev-1")),
            ],
        );
        mock.add("cdn/block-1", Bytes::from(ct1));
        mock.add("cdn/block-2", Bytes::from(ct2));

        let downloader = build_downloader(Arc::new(mock), crypto, sign_key, vec![sign_pub]);

        let mut out = Vec::new();
        let stats = downloader.download_to_writer(&mut out).await.unwrap();

        assert_eq!(
            out, b"first-half-second-half",
            "plaintext must be assembled in ascending Index order, not delivery order"
        );
        assert!(
            stats.signature_verified,
            "manifest signed over the ascending-order concatenation must verify \
             even though the server delivered blocks out of order"
        );
    }

    /// Companion to the test above: proves the ascending-index sort is load
    /// bearing, not incidental. Calls the private `verify_manifest` directly
    /// with blocks left in descending (delivery) order — bypassing
    /// `download_to_writer`'s `sort_by_key` — against a manifest signed over
    /// the ascending concatenation. If a future regression ever dropped that
    /// sort call, this is exactly the failure an out-of-order server
    /// response would produce: a real, validly-signed manifest reported as
    /// unverified.
    #[tokio::test]
    async fn verify_manifest_fails_without_the_index_sort() {
        let (crypto, sign_key, sign_pub) = make_crypto_material("sign-pass").await;
        let crypto = Arc::new(crypto);

        let hash1 = block_hash_b64(b"block-one-ciphertext-stand-in");
        let hash2 = block_hash_b64(b"block-two-ciphertext-stand-in");

        let block1 = BlockResponse {
            index: 1,
            bare_url: "unused-1".into(),
            token: "t1".into(),
            hash: hash1.clone(),
            encrypted_signature: None,
            size: 0,
        };
        let block2 = BlockResponse {
            index: 2,
            bare_url: "unused-2".into(),
            token: "t2".into(),
            hash: hash2.clone(),
            encrypted_signature: None,
            size: 0,
        };

        // Manifest signed over the ASCENDING concatenation (hash1 || hash2)
        // — the only order a genuine server-signed manifest could have been
        // produced over (the upload side always hashes in index order).
        let mut ascending_payload = Vec::new();
        ascending_payload.extend(
            base64::engine::general_purpose::STANDARD
                .decode(&hash1)
                .unwrap(),
        );
        ascending_payload.extend(
            base64::engine::general_purpose::STANDARD
                .decode(&hash2)
                .unwrap(),
        );
        let manifest_sig = crypto
            .sign(&ascending_payload, &sign_key, "")
            .await
            .unwrap();
        let manifest_sig_b64 = base64::engine::general_purpose::STANDARD.encode(&manifest_sig);

        let downloader = build_downloader(
            Arc::new(MockHttpClient::new()),
            crypto,
            sign_key,
            vec![sign_pub],
        );

        // Descending (unsorted) order — what `download_to_writer` would pass
        // to `verify_manifest` if its `sort_by_key(|b| b.index)` call were
        // ever removed.
        let unsorted = vec![block2, block1];
        let verified = downloader
            .verify_manifest(&unsorted, Some(&manifest_sig_b64))
            .await
            .unwrap();

        assert!(
            !verified,
            "a manifest signed over the ascending-index concatenation must fail \
             to verify against a descending-order payload — proving the \
             production sort-before-hash step is load-bearing"
        );
    }

    // ── in-process upload→download round trip (real crypto, no network) ─────
    // Supersedes the permanent `unimplemented!()` stub this test used to be:
    // MD (block-upload) landed long ago (see `docs/IMPLEMENTATION-STATUS.md`)
    // but the stub was never wired up. Rather than requiring live
    // credentials, this builds a tiny stateful fake Proton Drive server
    // (`InProcessServer`) that BOTH `ProtonFileUploader` (upload.rs) and
    // `FileDownloader` (this file) talk to over the same
    // `ProtonDriveHttpClient` seam, using real `RpgpCrypto` throughout (not
    // the `upload.rs` unit tests' `FakeCrypto` stub, which only round-trips
    // a "FAKE_ENC:" marker). This proves the upload path's wire output —
    // encrypted node key/passphrase, content key packet, block ciphertext +
    // manifest signature, XAttr — is genuinely decryptable by the download
    // path, not just independently mocked on each side.

    const ROUNDTRIP_FILE_LINK_ID: &str = "roundtrip-file-link";
    const ROUNDTRIP_FILE_REVISION_ID: &str = "roundtrip-file-rev";

    /// Fields captured from the real `CreateFileRequest` POST body so they
    /// can be served back on the subsequent `GET .../links/{id}` calls
    /// during download — mirroring what the real server would persist.
    struct RoundtripCapturedFile {
        name: String,
        hash: String,
        node_key: String,
        node_passphrase: String,
        node_passphrase_signature: String,
        content_key_packet: String,
        content_key_packet_signature: String,
        signature_address: String,
    }

    /// Fields captured from the real `CommitRevisionRequest` PUT body.
    struct RoundtripCapturedCommit {
        manifest_signature: String,
        signature_address: String,
        x_attr: String,
    }

    struct RoundtripBlockMeta {
        index: u32,
        bare_url: String,
        token: String,
    }

    /// Extract the raw ciphertext from `put_block`'s multipart/form-data
    /// body (a single "Block" part): locates the blank line ending the part
    /// headers and the trailing `--boundary` marker, rather than hardcoding
    /// upload.rs's private boundary constant.
    fn extract_multipart_block(body: &[u8]) -> Vec<u8> {
        let header_end = body
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| i + 4)
            .unwrap_or(0);
        let after_headers = &body[header_end..];
        match after_headers.windows(4).rposition(|w| w == b"\r\n--") {
            Some(idx) => after_headers[..idx].to_vec(),
            None => after_headers.to_vec(),
        }
    }

    /// A tiny stateful in-process fake of the Proton Drive HTTP API,
    /// sufficient to drive one file through the real upload protocol
    /// (`upload.rs`) and then the real download protocol (this file)
    /// against the *same* backing state. Unlike the crate's other mocks
    /// (`MockHttpClient` above, `FakeHttpClient` in `upload.rs`), this one
    /// actually persists what each write call sends so the corresponding
    /// read calls can serve it back — a real server's job, minimally
    /// reimplemented for the test.
    struct InProcessServer {
        share_id: String,
        root_link_id: String,
        volume_id: String,
        /// Pre-built canned response bodies for the share and the My Files
        /// root folder — fixed for the whole test, not captured from a write.
        share_json: String,
        root_link_json: String,
        file: std::sync::Mutex<Option<RoundtripCapturedFile>>,
        blocks_meta: std::sync::Mutex<Vec<RoundtripBlockMeta>>,
        block_bytes: std::sync::Mutex<std::collections::HashMap<String, Bytes>>,
        commit: std::sync::Mutex<Option<RoundtripCapturedCommit>>,
    }

    impl InProcessServer {
        fn new(
            share_id: impl Into<String>,
            root_link_id: impl Into<String>,
            volume_id: impl Into<String>,
            share_json: String,
            root_link_json: String,
        ) -> Self {
            Self {
                share_id: share_id.into(),
                root_link_id: root_link_id.into(),
                volume_id: volume_id.into(),
                share_json,
                root_link_json,
                file: std::sync::Mutex::new(None),
                blocks_meta: std::sync::Mutex::new(Vec::new()),
                block_bytes: std::sync::Mutex::new(std::collections::HashMap::new()),
                commit: std::sync::Mutex::new(None),
            }
        }

        fn capture_create_file(&self, body: &[u8]) -> Result<()> {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "PascalCase")]
            struct Probe {
                name: String,
                hash: String,
                node_key: String,
                node_passphrase: String,
                node_passphrase_signature: String,
                content_key_packet: String,
                content_key_packet_signature: String,
                signature_address: String,
            }
            let probe: Probe = serde_json::from_slice(body)
                .map_err(|e| Error::Internal(format!("capture create-file body: {e}")))?;
            *self.file.lock().unwrap() = Some(RoundtripCapturedFile {
                name: probe.name,
                hash: probe.hash,
                node_key: probe.node_key,
                node_passphrase: probe.node_passphrase,
                node_passphrase_signature: probe.node_passphrase_signature,
                content_key_packet: probe.content_key_packet,
                content_key_packet_signature: probe.content_key_packet_signature,
                signature_address: probe.signature_address,
            });
            Ok(())
        }

        fn capture_commit(&self, body: &[u8]) -> Result<()> {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "PascalCase")]
            struct Probe {
                manifest_signature: String,
                signature_address: String,
                #[serde(rename = "XAttr")]
                x_attr: String,
            }
            let probe: Probe = serde_json::from_slice(body)
                .map_err(|e| Error::Internal(format!("capture commit body: {e}")))?;
            *self.commit.lock().unwrap() = Some(RoundtripCapturedCommit {
                manifest_signature: probe.manifest_signature,
                signature_address: probe.signature_address,
                x_attr: probe.x_attr,
            });
            Ok(())
        }

        fn handle_request_blocks(&self, body: &[u8]) -> Result<String> {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "PascalCase")]
            struct EntryProbe {
                index: u32,
            }
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "PascalCase")]
            struct Probe {
                block_list: Vec<EntryProbe>,
            }
            let probe: Probe = serde_json::from_slice(body)
                .map_err(|e| Error::Internal(format!("capture request-blocks body: {e}")))?;

            let mut meta = self.blocks_meta.lock().unwrap();
            let mut links = Vec::new();
            for entry in &probe.block_list {
                let bare_url = format!("https://upload.proton.me/block/{}", entry.index);
                let token = format!("blk-tok-{}", entry.index);
                meta.push(RoundtripBlockMeta {
                    index: entry.index,
                    bare_url: bare_url.clone(),
                    token: token.clone(),
                });
                links.push(serde_json::json!({
                    "Index": entry.index, "BareURL": bare_url, "Token": token,
                }));
            }
            Ok(serde_json::json!({"Code": 1000, "UploadLinks": links}).to_string())
        }

        fn file_link_json(&self) -> String {
            let file = self.file.lock().unwrap();
            let file = file
                .as_ref()
                .expect("create-file must be captured before the file link is fetched");
            let commit = self.commit.lock().unwrap();
            let signature_email = commit.as_ref().map(|c| c.signature_address.clone());
            serde_json::json!({
                "Code": 1000,
                "Link": {
                    "LinkID": ROUNDTRIP_FILE_LINK_ID,
                    "ParentLinkID": self.root_link_id,
                    "Type": 2,
                    "Name": file.name,
                    "NameSignatureEmail": null,
                    "Hash": file.hash,
                    "MIMEType": "text/plain",
                    "State": 1,
                    "Size": 0,
                    "CreateTime": 0,
                    "ModifyTime": 0,
                    "Trashed": null,
                    "NodeKey": file.node_key,
                    "NodePassphrase": file.node_passphrase,
                    "NodePassphraseSignature": file.node_passphrase_signature,
                    "SignatureEmail": file.signature_address,
                    "FileProperties": {
                        "ContentKeyPacket": file.content_key_packet,
                        "ContentKeyPacketSignature": file.content_key_packet_signature,
                        "ActiveRevision": {
                            "ID": ROUNDTRIP_FILE_REVISION_ID,
                            "State": 1,
                            "CreateTime": 0,
                            "Size": 0,
                            "ManifestSignature": null,
                            "SignatureEmail": signature_email,
                        },
                    },
                    "FolderProperties": null,
                }
            })
            .to_string()
        }

        fn revision_page_json(&self, query: &[(String, String)]) -> String {
            let from_block_index: u32 = query
                .iter()
                .find(|(k, _)| k == "FromBlockIndex")
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(1);

            let meta = self.blocks_meta.lock().unwrap();
            let bytes_map = self.block_bytes.lock().unwrap();
            let commit = self.commit.lock().unwrap();

            let blocks: Vec<serde_json::Value> = meta
                .iter()
                .filter(|b| b.index >= from_block_index)
                .map(|b| {
                    let ct = bytes_map.get(&b.bare_url).cloned().unwrap_or_default();
                    serde_json::json!({
                        "Index": b.index,
                        "BareURL": b.bare_url,
                        "Token": b.token,
                        "Hash": block_hash_b64(&ct),
                        "EncryptedSignature": null,
                        "Size": ct.len() as u64,
                    })
                })
                .collect();

            let (manifest_signature, x_attr, signature_email) = match &*commit {
                Some(c) => (
                    Some(c.manifest_signature.clone()),
                    Some(c.x_attr.clone()),
                    Some(c.signature_address.clone()),
                ),
                None => (None, None, None),
            };

            serde_json::json!({
                "Code": 1000,
                "Revision": {
                    "ID": ROUNDTRIP_FILE_REVISION_ID,
                    "State": 1,
                    "Blocks": blocks,
                    "ManifestSignature": manifest_signature,
                    "ContentKeyPacket": null,
                    "ContentKeyPacketSignature": null,
                    "XAttr": x_attr,
                    "SignatureEmail": signature_email,
                }
            })
            .to_string()
        }
    }

    #[async_trait::async_trait]
    impl ProtonDriveHttpClient for InProcessServer {
        async fn request_json(&self, req: JsonRequest) -> Result<JsonResponse> {
            fn ok(body: String) -> JsonResponse {
                JsonResponse {
                    status: 200,
                    headers: vec![],
                    body: Bytes::from(body),
                }
            }

            let share_path = format!("/drive/shares/{}", self.share_id);
            let root_link_path = format!(
                "/drive/shares/{}/links/{}",
                self.share_id, self.root_link_id
            );
            let file_link_path = format!(
                "/drive/shares/{}/links/{}",
                self.share_id, ROUNDTRIP_FILE_LINK_ID
            );
            let create_file_path = format!("/drive/v2/volumes/{}/files", self.volume_id);
            let revision_path = format!(
                "/drive/v2/volumes/{}/files/{}/revisions/{}",
                self.volume_id, ROUNDTRIP_FILE_LINK_ID, ROUNDTRIP_FILE_REVISION_ID
            );

            if req.method == HttpMethod::Get && req.path == share_path {
                return Ok(ok(self.share_json.clone()));
            }
            if req.method == HttpMethod::Get && req.path == root_link_path {
                return Ok(ok(self.root_link_json.clone()));
            }
            if req.method == HttpMethod::Get && req.path == file_link_path {
                return Ok(ok(self.file_link_json()));
            }
            if req.method == HttpMethod::Post && req.path == create_file_path {
                self.capture_create_file(req.body.as_deref().unwrap_or_default())?;
                return Ok(ok(serde_json::json!({
                    "Code": 1000,
                    "File": {"ID": ROUNDTRIP_FILE_LINK_ID, "RevisionID": ROUNDTRIP_FILE_REVISION_ID},
                })
                .to_string()));
            }
            if req.method == HttpMethod::Get && req.path.ends_with("/verification") {
                return Ok(ok(serde_json::json!({
                    "Code": 1000,
                    "VerificationCode": base64::engine::general_purpose::STANDARD.encode([0xAAu8; 64]),
                    "ContentKeyPacket": base64::engine::general_purpose::STANDARD.encode(b"unused"),
                })
                .to_string()));
            }
            if req.method == HttpMethod::Post && req.path == "/drive/blocks" {
                return Ok(ok(
                    self.handle_request_blocks(req.body.as_deref().unwrap_or_default())?
                ));
            }
            if req.method == HttpMethod::Put && req.path == revision_path {
                self.capture_commit(req.body.as_deref().unwrap_or_default())?;
                return Ok(ok(serde_json::json!({"Code": 1000}).to_string()));
            }
            if req.method == HttpMethod::Get && req.path == revision_path {
                return Ok(ok(self.revision_page_json(&req.query)));
            }

            Err(Error::Internal(format!(
                "InProcessServer: unhandled request {:?} {}",
                req.method, req.path
            )))
        }

        async fn request_blob(&self, req: BlobRequest) -> Result<JsonResponse> {
            match req.method {
                HttpMethod::Post => {
                    let ciphertext = extract_multipart_block(&req.body);
                    self.block_bytes
                        .lock()
                        .unwrap()
                        .insert(req.path.clone(), Bytes::from(ciphertext));
                    Ok(JsonResponse {
                        status: 200,
                        headers: vec![],
                        body: Bytes::from_static(b"{}"),
                    })
                }
                HttpMethod::Get => {
                    let body = self
                        .block_bytes
                        .lock()
                        .unwrap()
                        .get(&req.path)
                        .cloned()
                        .ok_or_else(|| {
                            Error::NotFound(format!("InProcessServer: no block at {}", req.path))
                        })?;
                    Ok(JsonResponse {
                        status: 200,
                        headers: vec![],
                        body,
                    })
                }
                other => Err(Error::Internal(format!(
                    "InProcessServer: unexpected blob method {other:?}"
                ))),
            }
        }
    }

    /// Host account backed by real keys (not `upload.rs`'s `FakeAccount`
    /// literal placeholder strings) — the downloader genuinely decrypts and
    /// verifies against these.
    struct RoundtripAccount {
        email: String,
        address_priv: PrivateKey,
        address_pub: PublicKey,
    }

    #[async_trait::async_trait]
    impl crate::account::ProtonDriveAccount for RoundtripAccount {
        fn user_id(&self) -> &str {
            "roundtrip-user"
        }

        fn primary_email(&self) -> &str {
            &self.email
        }

        async fn address_private_key(&self, _email: &str) -> Result<PrivateKey> {
            Ok(self.address_priv.clone())
        }

        async fn address_public_keys(&self, _email: &str) -> Result<Vec<PublicKey>> {
            Ok(vec![self.address_pub.clone()])
        }

        async fn address_id(&self, _email: &str) -> Result<String> {
            Ok("roundtrip-address-id".into())
        }

        async fn key_password(&self) -> Result<String> {
            Ok("unused".into())
        }
    }

    /// Round-trip test: upload a file through the real `ProtonFileUploader`
    /// protocol, then download it through the real `FileDownloader`
    /// protocol, both driven by the same in-process fake server and real
    /// `RpgpCrypto` — no live credentials, no `unimplemented!()`.
    #[tokio::test]
    async fn round_trip_upload_download_byte_identical() {
        use crate::account::ProtonDriveAccount;
        use crate::client::{ProtonDriveClient, ProtonDriveClientOptions};
        use crate::config::ProtonDriveConfig;
        use crate::nodes::make_node_uid;
        use crate::upload::{FileUploader, ProtonFileUploader, UploadMetadata};
        use tokio::io::AsyncRead;

        let crypto = Arc::new(RpgpCrypto::new());

        // ── real key hierarchy: address → share → My Files root folder ───────
        let (address_priv, address_pub_armored) = crypto
            .generate_key("address-pass", EncryptOptions::default())
            .await
            .unwrap();
        let address_pub = PublicKey {
            armored: address_pub_armored,
            fingerprint_hex: address_priv.fingerprint_hex.clone(),
        };

        let (share_priv, share_pub_armored) = crypto
            .generate_key("share-pass", EncryptOptions::default())
            .await
            .unwrap();
        let share_pub = PublicKey {
            armored: share_pub_armored,
            fingerprint_hex: share_priv.fingerprint_hex.clone(),
        };

        let (root_priv, root_pub_armored) = crypto
            .generate_key("root-pass", EncryptOptions::default())
            .await
            .unwrap();
        let root_pub = PublicKey {
            armored: root_pub_armored,
            fingerprint_hex: root_priv.fingerprint_hex.clone(),
        };

        // Share's own passphrase is encrypted to the ADDRESS key
        // (`decrypt_share_key`'s contract).
        let share_pp_session = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let share_pp_msg = crypto
            .encrypt(
                b"share-pass",
                &share_pp_session,
                std::slice::from_ref(&address_pub),
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let share_passphrase_b64 = base64::engine::general_purpose::STANDARD.encode(&share_pp_msg);

        // The My Files root folder's own NodePassphrase is encrypted
        // directly to the SHARE key — only the share root gets this
        // treatment; every other node's passphrase is encrypted to its
        // *parent node* key.
        let root_pp_session = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let root_pp_msg = crypto
            .encrypt(
                b"root-pass",
                &root_pp_session,
                std::slice::from_ref(&share_pub),
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let root_passphrase_b64 = base64::engine::general_purpose::STANDARD.encode(&root_pp_msg);

        // Root folder's NodeHashKey: encrypted to its OWN public key (a
        // folder locks its child-name HMAC key to itself), armored — this
        // field is dearmored directly on the wire, not base64
        // (`ProtonFileUploader::resolve_parent_context`).
        let hash_key_session = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let hash_key_msg = crypto
            .encrypt(
                b"roundtrip-hash-key-material",
                &hash_key_session,
                std::slice::from_ref(&root_pub),
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let hash_key_armored = armor(&hash_key_msg, ArmorKind::Message);

        let share_id = "share-1";
        let root_link_id = "root-link";
        let volume_id = "vol-1";
        let address_email = "roundtrip@proton.me";

        let share_json = serde_json::json!({
            "Code": 1000,
            "ShareID": share_id, "VolumeID": volume_id, "LinkID": root_link_id, "Type": 1,
            "Key": share_priv.armored, "Passphrase": share_passphrase_b64,
            "PassphraseSignature": "", "AddressID": "addr-1",
        })
        .to_string();

        let root_link_json = serde_json::json!({
            "Code": 1000,
            "Link": {
                "LinkID": root_link_id, "ParentLinkID": null, "Type": 1, "Name": "root",
                "NameSignatureEmail": null, "Hash": null, "MIMEType": null, "State": 1,
                "Size": 0, "CreateTime": 0, "ModifyTime": 0, "Trashed": null,
                "NodeKey": root_priv.armored, "NodePassphrase": root_passphrase_b64,
                "NodePassphraseSignature": "", "SignatureEmail": null,
                "FileProperties": null,
                "FolderProperties": {"NodeHashKey": hash_key_armored},
            }
        })
        .to_string();

        let server = Arc::new(InProcessServer::new(
            share_id,
            root_link_id,
            volume_id,
            share_json,
            root_link_json,
        ));

        let account: Arc<dyn ProtonDriveAccount> = Arc::new(RoundtripAccount {
            email: address_email.to_owned(),
            address_priv,
            address_pub,
        });

        let content = b"round-trip upload-then-download content, byte-identical end to end";

        let uploader = ProtonFileUploader {
            http: server.clone() as Arc<dyn ProtonDriveHttpClient>,
            openpgp: Arc::clone(&crypto) as Arc<dyn OpenPgpCrypto>,
            account: account.clone(),
            parent: make_node_uid(share_id, root_link_id),
            name: "roundtrip.txt".into(),
            metadata: UploadMetadata {
                media_type: "text/plain".into(),
                expected_size: content.len() as u64,
                expected_sha1_hex: None,
                modification_time: None,
                additional_metadata_json: None,
                override_existing_draft_by_other_client: false,
                expected_current_revision_id: None,
            },
            telemetry: None,
        };

        let (progress_tx, _progress_rx) = tokio::sync::watch::channel(0u64);
        let stream: Box<dyn AsyncRead + Send + Unpin> =
            Box::new(std::io::Cursor::new(content.to_vec()));
        uploader
            .upload_from_stream(stream, progress_tx)
            .await
            .unwrap();

        // ── download the just-uploaded file through the same server ──────────
        let client = ProtonDriveClient::new(ProtonDriveClientOptions {
            http_client: server as Arc<dyn ProtonDriveHttpClient>,
            entities_cache: Arc::new(proton_drive_cache::MemoryCache::<String>::new()),
            crypto_cache: Arc::new(proton_drive_cache::MemoryCache::<
                crate::nodes::CachedCryptoMaterial,
            >::new()),
            account,
            openpgp: Arc::clone(&crypto) as Arc<dyn OpenPgpCrypto>,
            srp: crypto as Arc<dyn proton_drive_crypto::SrpModule>,
            config: ProtonDriveConfig::default(),
            telemetry: None,
            latest_event_id: None,
        });

        let uid = make_node_uid(share_id, ROUNDTRIP_FILE_LINK_ID);

        // `claimed_size` (cs/v0.15.0 XAttr-sourced progress total) against a
        // *real* uploaded file, decrypted with the genuine crypto stack —
        // not just the lighter `MockHttpClient` unit tests above. A second,
        // independent `file_downloader()` call, since `claimed_size` is
        // meant to be queried before the consuming `download_to_writer`/
        // `download_to_path` call takes ownership of its `FileDownloader`.
        let size_probe = client.file_downloader(&uid).await.unwrap();
        assert_eq!(
            size_probe.claimed_size().await.unwrap(),
            Some(content.len() as u64),
            "claimed_size should report the real uploaded file's XAttr-declared size"
        );

        let downloader = client.file_downloader(&uid).await.unwrap();
        let mut out = Vec::new();
        let stats = downloader.download_to_writer(&mut out).await.unwrap();

        assert_eq!(
            out,
            content.to_vec(),
            "downloaded bytes must be byte-identical to the uploaded content"
        );
        assert_eq!(stats.bytes, content.len() as u64);
        assert_eq!(stats.blocks, 1);
        assert!(
            stats.signature_verified,
            "manifest must verify: it was signed by the same address key the \
             downloader resolves via the file's SignatureEmail"
        );
    }

    // ── XAttr ModificationTime: per-node degradation (end-to-end) ────────────
    //
    // The accepted-format matrix for the underlying parser now lives with the
    // parser itself in `crate::xattr` (`parse_modification_time_tests`); the
    // end-to-end behavioural guarantee (download still succeeds when the value
    // is garbage) is covered below via `download_with_xattr_common`.

    /// Builds a single-block revision whose XAttr is
    /// `{"Common": <xattr_common_json>}`, downloads it end to end (real
    /// crypto, mocked HTTP), and returns the resulting `DownloadStats`.
    /// Asserts along the way that the download itself always succeeds and
    /// delivers the plaintext byte-identically — the whole point of the
    /// per-node-degradation contract this section tests is that a bad
    /// `Common.ModificationTime` never prevents that.
    async fn download_with_xattr_common(xattr_common_json: serde_json::Value) -> DownloadStats {
        let (crypto, sign_key, sign_pub) = make_crypto_material("xattr-mtime-pass").await;
        let crypto = Arc::new(crypto);

        let plaintext = b"xattr modification-time test content";

        let session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let ciphertext = crypto
            .encrypt_and_sign(
                plaintext,
                &session_key,
                std::slice::from_ref(&sign_pub),
                &sign_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let ciphertext_hash = block_hash_b64(&ciphertext);

        let ckp_bytes = crypto
            .encrypt_session_key(&session_key, std::slice::from_ref(&sign_pub))
            .await
            .unwrap();
        let ckp_b64 = base64::engine::general_purpose::STANDARD.encode(&ckp_bytes);

        let hash_bytes = base64::engine::general_purpose::STANDARD
            .decode(&ciphertext_hash)
            .unwrap();
        let manifest_sig_bytes = crypto.sign(&hash_bytes, &sign_key, "").await.unwrap();
        let manifest_sig_b64 =
            base64::engine::general_purpose::STANDARD.encode(&manifest_sig_bytes);

        // XAttr encrypted to the node key and signed by the same key —
        // mirrors production shape closely enough for this cross-check
        // (`encrypt_and_sign` on write, `decrypt_and_verify` on read).
        let xattr_json = serde_json::json!({ "Common": xattr_common_json }).to_string();
        let xattr_session_key = crypto
            .generate_session_key(&[], EncryptOptions::default())
            .await
            .unwrap();
        let xattr_ciphertext = crypto
            .encrypt_and_sign(
                xattr_json.as_bytes(),
                &xattr_session_key,
                std::slice::from_ref(&sign_pub),
                &sign_key,
                EncryptOptions::default(),
            )
            .await
            .unwrap();
        let xattr_armored = armor(&xattr_ciphertext, ArmorKind::Message);

        let revision_json = serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "rev-1",
                "State": 1,
                "Blocks": [{
                    "Index": 1,
                    "BareURL": "https://cdn.proton.me/block-1",
                    "Token": "tok-abc",
                    "Hash": ciphertext_hash,
                    "EncryptedSignature": null,
                    "Size": ciphertext.len() as u64,
                }],
                "ManifestSignature": manifest_sig_b64,
                "ContentKeyPacket": ckp_b64,
                "ContentKeyPacketSignature": null,
                "XAttr": xattr_armored,
                "SignatureEmail": null,
            }
        })
        .to_string();

        let mut mock = MockHttpClient::new();
        mock.add_sequence(
            "revisions/rev-1",
            vec![
                Bytes::from(revision_json),
                Bytes::from(empty_continuation_page("rev-1")),
            ],
        );
        mock.add("block-1", Bytes::from(ciphertext.clone()));

        let downloader = FileDownloader {
            http: Arc::new(mock),
            crypto: crypto.clone(),
            node_uid: NodeUid {
                volume_id: "vol-1".into(),
                node_id: "link-1".into(),
            },
            volume_id: "vol-1".into(),
            share_id: "share-1".into(),
            revision_id: "rev-1".into(),
            node_private_key: sign_key,
            signature_address_pubs: vec![sign_pub],
            content_key_packet: None,
            content_key_packet_signature: None,
            content_key_verification_pubs: Vec::new(),
        };

        let mut output = Vec::new();
        let stats = downloader
            .download_to_writer(&mut output)
            .await
            .expect("download must succeed even with a degraded XAttr ModificationTime");
        assert_eq!(
            output, plaintext,
            "bytes must still be delivered intact regardless of XAttr ModificationTime validity"
        );
        stats
    }

    #[tokio::test]
    async fn xattr_with_no_modification_time_field_downloads_cleanly() {
        let stats = download_with_xattr_common(serde_json::json!({})).await;
        assert!(stats.last_modification_time.is_none());
        assert!(stats.modification_time_error.is_none());
    }

    #[tokio::test]
    async fn xattr_modification_time_js_millisecond_format_round_trips() {
        let stats = download_with_xattr_common(serde_json::json!({
            "ModificationTime": "2023-11-14T22:13:20.000Z"
        }))
        .await;
        assert_eq!(
            stats.last_modification_time,
            Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000))
        );
        assert!(stats.modification_time_error.is_none());
    }

    #[tokio::test]
    async fn xattr_modification_time_cs_seven_digit_fraction_round_trips() {
        let stats = download_with_xattr_common(serde_json::json!({
            "ModificationTime": "2023-11-14T22:13:20.1234567Z"
        }))
        .await;
        assert!(stats.modification_time_error.is_none());
        let expected = std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(1_700_000_000)
            + std::time::Duration::from_nanos(123_456_700);
        assert_eq!(stats.last_modification_time, Some(expected));
    }

    #[tokio::test]
    async fn xattr_modification_time_no_fraction_round_trips() {
        let stats = download_with_xattr_common(serde_json::json!({
            "ModificationTime": "2023-11-14T22:13:20Z"
        }))
        .await;
        assert!(stats.modification_time_error.is_none());
        assert_eq!(
            stats.last_modification_time,
            Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000))
        );
    }

    #[tokio::test]
    async fn xattr_modification_time_numeric_offset_round_trips() {
        let stats = download_with_xattr_common(serde_json::json!({
            "ModificationTime": "2023-11-14T23:13:20+01:00"
        }))
        .await;
        assert!(stats.modification_time_error.is_none());
        assert_eq!(
            stats.last_modification_time,
            Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000))
        );
    }

    /// The regression test for the actual bug: before this fix,
    /// `Common.ModificationTime` was read with `.as_i64()`, which can never
    /// match the string upstream actually writes — every real
    /// ModificationTime was silently dropped. A garbage value must still
    /// degrade gracefully rather than aborting the download, mirroring cs
    /// `DtoToMetadataConverter`'s per-node
    /// `ExtendedAttributesDeserializationError` handling.
    #[tokio::test]
    async fn xattr_garbage_modification_time_degrades_without_failing_download() {
        let stats = download_with_xattr_common(serde_json::json!({
            "ModificationTime": "13/45/2023 not-a-real-date"
        }))
        .await;
        assert!(stats.last_modification_time.is_none());
        let err = stats
            .modification_time_error
            .expect("a garbage mtime must be reported, not silently dropped");
        assert!(err.contains("ModificationTime"));
        // Digits are redacted — the raw claimed value never appears verbatim.
        assert!(!err.contains("13/45/2023"));
        assert!(err.contains("##/##/####"));
    }

    /// A `ModificationTime` present with the wrong JSON type (a number
    /// instead of an ISO-8601 string) is exactly as invalid as a garbage
    /// string, and must degrade the same way — matching cs's explicit
    /// `JsonTokenType.String` check in `Iso8601DateTimeResultJsonConverter`.
    #[tokio::test]
    async fn xattr_modification_time_wrong_json_type_degrades_without_failing_download() {
        let stats = download_with_xattr_common(serde_json::json!({
            "ModificationTime": 1_700_000_000
        }))
        .await;
        assert!(stats.last_modification_time.is_none());
        assert!(stats.modification_time_error.is_some());
    }
}
