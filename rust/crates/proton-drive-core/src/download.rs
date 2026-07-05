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
use proton_drive_api::download::{BlockResponse, GetRevisionResponse};
use proton_drive_api::nodes::GetLinkResponse;
use proton_drive_api::shares::GetShareResponse;
use proton_drive_crypto::{OpenPgpCrypto, PrivateKey, VerificationStatus};

// ── public types ──────────────────────────────────────────────────────────────

/// Statistics returned after a successful download.
#[derive(Debug, Clone)]
pub struct DownloadStats {
    /// Total plaintext bytes written to the writer.
    pub bytes: u64,
    /// Number of blocks fetched and decrypted.
    pub blocks: u32,
    /// Modification time from the XAttr (if present and decryptable).
    pub last_modification_time: Option<std::time::SystemTime>,
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
    /// 1. `GET .../revisions/{id}` — fetch blocks + manifest + content key
    /// 2. Decrypt content session key from `ContentKeyPacket`
    /// 3. For each block: fetch → SHA-256 hash check → decrypt → write
    /// 4. Verify manifest signature (over the block hashes) → `signature_verified`
    /// 5. XAttr cross-check (size + SHA1); missing XAttr is warned, not fatal
    pub async fn download_to_writer(
        self,
        mut writer: impl AsyncWrite + Unpin + Send,
    ) -> Result<DownloadStats> {
        // ── Step 1: fetch revision ───────────────────────────────────────────
        let revision = self.fetch_revision().await?;

        if revision.blocks.is_empty() {
            // Server guarantees active revisions have at least one block.
            return Err(Error::Internal(
                "protocol violation: active revision has no blocks".into(),
            ));
        }

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

        // ContentKeyPacketSignature is intentionally not verified here. JS
        // `getContentKeyPacketSessionKey` decrypts with empty verification keys
        // (`decryptAndVerifySessionKey(..., nodeKey, [])`); download integrity is
        // guaranteed by the manifest signature and the SHA-256 ciphertext hash
        // checks below.

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
        let last_modification_time = self
            .verify_xattr(
                revision.x_attr.as_deref(),
                total_bytes,
                &sha1_hasher.finalize(),
            )
            .await;

        Ok(DownloadStats {
            bytes: total_bytes,
            blocks: total_blocks,
            last_modification_time,
            signature_verified,
        })
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    async fn fetch_revision(&self) -> Result<proton_drive_api::download::RevisionWithBlocks> {
        // GET drive/v2/volumes/{VolumeID}/files/{linkID}/revisions/{revisionID}
        let path = format!(
            "/drive/v2/volumes/{}/files/{}/revisions/{}",
            self.volume_id, self.node_uid.node_id, self.revision_id,
        );
        let req = JsonRequest {
            method: HttpMethod::Get,
            path,
            query: vec![],
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
    /// we warn and return `None` (JS does the same fallback).
    ///
    /// When present, we verify:
    /// - `Common.Size` matches `total_bytes`
    /// - `Common.Digests.SHA1` matches `sha1_digest`
    async fn verify_xattr(
        &self,
        xattr_armored: Option<&str>,
        total_bytes: u64,
        sha1_digest: &[u8],
    ) -> Option<std::time::SystemTime> {
        let Some(xattr_raw) = xattr_armored else {
            tracing::debug!(
                node_id = %self.node_uid.node_id,
                "no XAttr on revision — skipping XAttr cross-check (legacy revision)"
            );
            return None;
        };

        // XAttr is an armored PGP message (`armoredExtendedAttributes`):
        // encrypted to the node key, signed by the address key. Decrypt the
        // session key with the node key, then the message body; verification is
        // best-effort (empty keys → no signature check), mirroring JS where a
        // failed XAttr decrypt is non-fatal.
        let xattr_bytes = xattr_raw.as_bytes();
        let session_key = match self
            .crypto
            .decrypt_session_key(xattr_bytes, std::slice::from_ref(&self.node_private_key))
            .await
        {
            Ok(sk) => sk,
            Err(e) => {
                tracing::warn!(
                    node_id = %self.node_uid.node_id,
                    "XAttr session-key decrypt failed: {e} — skipping cross-check"
                );
                return None;
            }
        };

        let plaintext = match self
            .crypto
            .decrypt_and_verify(xattr_bytes, &session_key, &[])
            .await
        {
            Ok((pt, _)) => pt,
            Err(e) => {
                tracing::warn!(
                    node_id = %self.node_uid.node_id,
                    "XAttr decrypt failed: {e} — skipping cross-check"
                );
                return None;
            }
        };

        let json_str = match std::str::from_utf8(&plaintext) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    node_id = %self.node_uid.node_id,
                    "XAttr plaintext not UTF-8: {e}"
                );
                return None;
            }
        };

        let xattr: serde_json::Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    node_id = %self.node_uid.node_id,
                    "XAttr JSON parse failed: {e}"
                );
                return None;
            }
        };

        // Verify size.
        if let Some(claimed_size) = xattr["Common"]["Size"].as_u64() {
            if claimed_size != total_bytes {
                tracing::error!(
                    node_id = %self.node_uid.node_id,
                    "XAttr size mismatch: claimed={claimed_size} actual={total_bytes}"
                );
                // We log but do not abort — consistent with JS fallback.
            }
        }

        // Verify SHA1.
        if let Some(claimed_sha1) = xattr["Common"]["Digests"]["SHA1"].as_str() {
            let actual_sha1_hex = hex::encode(sha1_digest);
            if claimed_sha1 != actual_sha1_hex {
                tracing::error!(
                    node_id = %self.node_uid.node_id,
                    "XAttr SHA1 mismatch: claimed={claimed_sha1} actual={actual_sha1_hex}"
                );
            }
        }

        // Extract modification time.
        xattr["Common"]["ModificationTime"].as_i64().map(|ts| {
            if ts >= 0 {
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(ts as u64)
            } else {
                std::time::UNIX_EPOCH
            }
        })
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

/// Full node key decryption: decrypt passphrase from NodePassphrase, then
/// unlock the NodeKey armored private key with that passphrase.
///
/// `parent_key` is the node's *immediate* parent key: the share key for the
/// share root node, or the parent **node** key for any nested node. Callers
/// walk the parent chain (see `ProtonDriveClient::resolve_node_key_via_chain`)
/// to assemble the right `parent_key` for nested nodes.
pub async fn decrypt_node_private_key(
    crypto: &Arc<dyn OpenPgpCrypto>,
    node_key_armored: &str,
    node_passphrase_encrypted_b64: &str,
    parent_key: &PrivateKey,
) -> Result<PrivateKey> {
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

    let (passphrase_bytes, _) = crypto
        .decrypt_and_verify(&ckp_bytes, &passphrase_session_key, &[])
        .await
        .map_err(|e| Error::Decryption(format!("node passphrase plaintext: {e}")))?;

    // Secret material: wipe the heap buffer on drop (ADR-0011).
    let passphrase = Zeroizing::new(passphrase_bytes);
    let passphrase_str = std::str::from_utf8(&passphrase)
        .map_err(|e| Error::Internal(format!("passphrase utf-8: {e}")))?;

    let node_priv = crypto
        .decrypt_key(node_key_armored, passphrase_str)
        .await
        .map_err(|e| Error::Decryption(format!("node key unlock: {e}")))?;

    Ok(node_priv)
}

/// Decrypt the share key using the user's address private key.
pub async fn decrypt_share_key(
    crypto: &Arc<dyn OpenPgpCrypto>,
    share_key_armored: &str,
    share_passphrase_encrypted_b64: &str,
    address_key: &PrivateKey,
) -> Result<PrivateKey> {
    // Share Passphrase is an armored PGPMessage on the wire; older callers may
    // pass base64-encoded binary. Try base64 first, else use the raw bytes.
    let pp_bytes = base64::engine::general_purpose::STANDARD
        .decode(share_passphrase_encrypted_b64)
        .unwrap_or_else(|_| share_passphrase_encrypted_b64.as_bytes().to_vec());

    let pp_session_key = crypto
        .decrypt_session_key(&pp_bytes, std::slice::from_ref(address_key))
        .await
        .map_err(|e| Error::Decryption(format!("share passphrase session key: {e}")))?;

    let (pp_bytes_plain, _) = crypto
        .decrypt_and_verify(&pp_bytes, &pp_session_key, &[])
        .await
        .map_err(|e| Error::Decryption(format!("share passphrase plaintext: {e}")))?;

    // Secret material: wipe the heap buffer on drop (ADR-0011).
    let passphrase = Zeroizing::new(pp_bytes_plain);
    let passphrase_str = std::str::from_utf8(&passphrase)
        .map_err(|e| Error::Internal(format!("share passphrase utf-8: {e}")))?;

    let share_priv = crypto
        .decrypt_key(share_key_armored, passphrase_str)
        .await
        .map_err(|e| Error::Decryption(format!("share key unlock: {e}")))?;

    Ok(share_priv)
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
    use proton_drive_crypto::{EncryptOptions, OpenPgpCrypto, PrivateKey, PublicKey, RpgpCrypto};

    // ── mock HTTP client for protocol tests ───────────────────────────────────

    /// HTTP responses keyed by path prefix.
    struct MockHttpClient {
        /// (path_prefix, response_body)
        responses: std::collections::HashMap<String, Bytes>,
    }

    impl MockHttpClient {
        fn new() -> Self {
            Self {
                responses: Default::default(),
            }
        }
        fn add(&mut self, path: impl Into<String>, body: impl Into<Bytes>) {
            self.responses.insert(path.into(), body.into());
        }
    }

    #[async_trait::async_trait]
    impl ProtonDriveHttpClient for MockHttpClient {
        async fn request_json(&self, req: JsonRequest) -> Result<JsonResponse> {
            let body = self
                .responses
                .iter()
                .find(|(k, _)| req.path.contains(k.as_str()))
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| Bytes::from(r#"{"Code":2501,"Error":"not found"}"#.to_owned()));
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
                .map(|(_, v)| v.clone())
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
        mock.add("revisions/rev-1", Bytes::from(revision_json));
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
        mock.add("revisions/rev-1", Bytes::from(revision_json));
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
        mock.add("revisions/rev-1", Bytes::from(revision_json));
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
        mock.add("revisions/rev-1", Bytes::from(revision_json));
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
        mock.add("revisions/rev-1", Bytes::from(revision_json));
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
        };

        let mut out = Vec::new();
        let stats = downloader.download_to_writer(&mut out).await.unwrap();
        assert_eq!(out, plaintext);
        assert_eq!(stats.blocks, 1);
    }

    /// Round-trip test (gated `#[ignore]` — requires live credentials).
    ///
    /// Upload `tests/fixtures/small.txt` via MD's FileUploader, then download
    /// via ME's FileDownloader, assert plaintext bytes are byte-identical.
    ///
    /// Skipped without live credentials: set `PROTON_TEST_CREDENTIALS` env var.
    #[tokio::test]
    #[ignore = "requires live Proton credentials — set PROTON_TEST_CREDENTIALS"]
    async fn round_trip_upload_download_byte_identical() {
        // This test is intentionally left as a stub pending live integration.
        // When MD (block-upload) lands, wire:
        //   1. Build ProtonDriveClient with real reqwest + credentials.
        //   2. Upload tests/fixtures/small.txt via client.file_uploader(...).upload_from_stream.
        //   3. Download the resulting node via client.file_downloader(...).download_to_writer.
        //   4. assert_eq!(downloaded_bytes, original_bytes).
        unimplemented!("round-trip test stub — wire after MD lands");
    }
}
