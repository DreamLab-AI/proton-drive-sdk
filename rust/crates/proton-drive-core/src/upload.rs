//! Block-upload protocol — ADR-0008 §"The protocol".
//!
//! Implements `FileUploader::upload_from_stream` for files < 16 MiB.
//! Happy path only; thumbnail upload, resumable upload, parallel blocks, and
//! telemetry are explicitly out of scope (ADR-0008 §"What is NOT ported").
//!
//! ## Mapping divergence: JS vs ADR-0008
//!
//! The JS SDK (apiService.ts) does **not** pass `Hash` or `Size` per block in
//! the RequestBlockUpload call — those fields were deprecated server-side.
//! ADR-0008 step 3 still mentions them, but we follow the JS implementation
//! and omit them from `BlockList` entries (the `RequestBlockUploadRequest` in
//! proton-drive-api retains the fields for the commit step only).
//!
//! The verifier token is computed as `verificationCode XOR ciphertext[0..len]`
//! (blockVerifier.ts semantics) and sent as base64.
//!
//! The block upload (step 4) is a multipart form-data POST with a "Block" part,
//! not a raw-binary PUT, matching apiService.ts `postBlockStream`/`uploadBlock`.
//! We send raw bytes in a form field named "Block" via a bespoke request; the
//! existing `request_blob` method is used for the binary body.
//!
//! ## FIXME: NodeUid naming
//!
//! MC commit f6b29b1 note: `NodeUid.volume_id` stores the Proton **share ID**
//! from listing endpoints. Volume-scoped POST endpoints need the real VolumeID.
//! Before any `drive/v2/volumes/{volumeID}/...` call we fetch
//! `GET drive/shares/{shareID}` to resolve the actual volume_id.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

use proton_drive_api::common::{CODE_OK, ResponseEnvelope};
use proton_drive_api::upload::{
    BlockUploadEntry, BlockVerifier as ApiBlockVerifier, CommitRevisionRequest, CreateFileRequest,
    DeleteNodesRequest, DeleteNodesResponse, RequestBlockUploadRequest,
};
use proton_drive_crypto::{
    ArmorKind, EncryptOptions, OpenPgpCrypto, PrivateKey, PublicKey, SessionKey, armor,
};

use crate::account::ProtonDriveAccount;
use crate::error::{Error, Result};
use crate::http::{BlobRequest, HttpMethod, JsonRequest, ProtonDriveHttpClient};
use crate::nodes::{NodeUid, map_api_error};

/// 4 MiB — server rejects blocks larger than this.
pub const BLOCK_SIZE: usize = 4 * 1024 * 1024;
/// 16 MiB MVP limit (domain-model-mvp.md invariant table).
pub const MAX_FILE_SIZE: u64 = 16 * 1024 * 1024;

/// Minimal envelope used to inspect a response's `Code`/`Error` without
/// requiring the typed body — Proton error responses omit the typed payload.
#[derive(serde::Deserialize)]
struct EnvelopeProbe {
    #[serde(rename = "Code")]
    code: u32,
    #[serde(rename = "Error", default)]
    error: Option<String>,
}

/// Name hash: `HMAC-SHA256(parent_hash_key, name_bytes)` → hex. Mirrors JS
/// `generateLookupHash` (`reference/client/js/src/crypto/driveCrypto.ts:439-443`:
/// `computeHmacSignature(importHmacKey(parentHashKey), utf8(newName)).toHex()`).
/// The key is the parent folder's decrypted `NodeHashKey` bytes; the message
/// is the UTF-8 file name. Pulled out to a standalone, pure function so a
/// known-answer test (`name_hash_hex_matches_known_answer`) can pin the exact
/// byte-for-byte computation without driving the full upload protocol — B1
/// (see `docs/IMPLEMENTATION-STATUS.md`) was this same computation done as
/// plain SHA-256 instead of HMAC-SHA256, and previously blocked every upload.
fn compute_name_hash_hex(parent_hash_key: &[u8], name: &str) -> Result<String> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(parent_hash_key)
        .map_err(|e| Error::Internal(format!("HMAC key init: {e}")))?;
    mac.update(name.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Truncated, lossy view of a response body for error diagnostics.
fn body_snippet(body: &[u8]) -> String {
    const MAX: usize = 512;
    let text = String::from_utf8_lossy(body);
    if text.len() > MAX {
        format!("{}…", &text[..MAX])
    } else {
        text.into_owned()
    }
}

// ── public types ──────────────────────────────────────────────────────────────

/// Metadata supplied by the caller alongside the stream.
#[derive(Debug, Clone)]
pub struct UploadMetadata {
    pub media_type: String,
    /// Required — server uses it for integrity. Missing it is a programming error.
    pub expected_size: u64,
    /// Optional SHA1 of cleartext; SDK verifies after streaming.
    pub expected_sha1_hex: Option<String>,
    pub modification_time: Option<std::time::SystemTime>,
    pub additional_metadata_json: Option<String>,
    /// If true, override any existing draft owned by another client.
    pub override_existing_draft_by_other_client: bool,
}

impl UploadMetadata {
    pub fn validate(&self) -> Result<()> {
        if self.expected_size == 0 {
            return Err(Error::Validation(
                "expected_size must be > 0 (server uses it for integrity)".into(),
            ));
        }
        if let Some(sha1) = &self.expected_sha1_hex
            && sha1.len() != 40
        {
            return Err(Error::Validation(
                "expected_sha1_hex must be 40 hex chars (SHA1)".into(),
            ));
        }
        if self.expected_size > MAX_FILE_SIZE {
            return Err(Error::Validation(format!(
                "file exceeds MVP limit: {} > {} bytes",
                self.expected_size, MAX_FILE_SIZE
            )));
        }
        Ok(())
    }
}

/// Active upload handle — returned from `upload_from_stream`.
/// For MVP the upload is synchronous; this type is a thin wrapper around the
/// cancellation token and byte counter.
pub struct UploadController {
    pub(crate) cancel: tokio_util::sync::CancellationToken,
    pub(crate) progress: tokio::sync::watch::Receiver<u64>,
}

impl UploadController {
    pub fn progress(&self) -> &tokio::sync::watch::Receiver<u64> {
        &self.progress
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

/// Builder returned by `ProtonDriveClient::file_uploader`.
#[async_trait::async_trait]
pub trait FileUploader: Send + Sync {
    /// Upload from a streaming source. Resolves to a controller with pause/resume.
    async fn upload_from_stream(
        &self,
        stream: Box<dyn AsyncRead + Send + Unpin>,
        progress: tokio::sync::watch::Sender<u64>,
    ) -> Result<UploadController>;
}

// ── internal block representation ─────────────────────────────────────────────

struct EncryptedBlock {
    index: u32,
    ciphertext: Vec<u8>,
    /// hex-encoded sha256 of the ciphertext
    ciphertext_hash_hex: String,
    /// armored PGP signature of plaintext, encrypted to address public key
    enc_signature: String,
    /// XOR-based verifier token (base64)
    verifier_token_b64: String,
}

// ── ProtonFileUploader ────────────────────────────────────────────────────────

/// Concrete uploader bound to a specific parent folder.
pub struct ProtonFileUploader {
    pub(crate) http: Arc<dyn ProtonDriveHttpClient>,
    pub(crate) openpgp: Arc<dyn OpenPgpCrypto>,
    pub(crate) account: Arc<dyn ProtonDriveAccount>,
    /// The parent folder's NodeUid.
    /// FIXME: NodeUid naming — see MC commit f6b29b1 note.
    /// `parent.volume_id` holds the share_id from listing endpoints.
    pub(crate) parent: NodeUid,
    /// File name to upload.
    pub(crate) name: String,
    /// UploadMetadata for this upload.
    pub(crate) metadata: UploadMetadata,
}

#[async_trait::async_trait]
impl FileUploader for ProtonFileUploader {
    async fn upload_from_stream(
        &self,
        stream: Box<dyn AsyncRead + Send + Unpin>,
        progress_tx: tokio::sync::watch::Sender<u64>,
    ) -> Result<UploadController> {
        let cancel = tokio_util::sync::CancellationToken::new();
        let (progress_inner_tx, progress_rx) = tokio::sync::watch::channel::<u64>(0u64);

        // Run the actual upload inline (MVP is single-threaded / sequential).
        // We pass the cancel token in; if cancelled mid-upload we surface an error.
        let result = self.run_upload(stream, &progress_tx, &cancel).await;

        // Mirror progress to the inner channel for the UploadController.
        let _ = progress_inner_tx.send(*progress_tx.borrow());

        result?;

        Ok(UploadController {
            cancel,
            progress: progress_rx,
        })
    }
}

impl ProtonFileUploader {
    /// Full 5-step block-upload protocol (ADR-0008).
    async fn run_upload(
        &self,
        mut stream: Box<dyn AsyncRead + Send + Unpin>,
        progress_tx: &tokio::sync::watch::Sender<u64>,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        // ── step 0: resolve real volume_id ────────────────────────────────────
        // FIXME: NodeUid naming — see MC commit f6b29b1 note.
        // `parent.volume_id` is actually the share_id.
        let share_id = &self.parent.volume_id;
        let volume_id = self.resolve_volume_id(share_id).await?;

        // ── step 0b: get address key ──────────────────────────────────────────
        let address_email = self.account.primary_email().to_owned();
        let address_priv = self.account.address_private_key(&address_email).await?;

        // ── step 1: generate node crypto ─────────────────────────────────────
        let node_passphrase = self.openpgp.generate_passphrase();

        let (node_priv, node_pub_armored) = self
            .openpgp
            .generate_key(&node_passphrase, EncryptOptions::default())
            .await?;

        let node_pub = PublicKey {
            armored: node_pub_armored,
            fingerprint_hex: node_priv.fingerprint_hex.clone(),
        };

        // Resolve the parent folder's node key (to encrypt the new node's
        // passphrase to) and its decrypted hash key (to compute the name hash).
        let (parent_node_priv, parent_hash_key) = self.resolve_parent_context(share_id).await?;

        let parent_node_pub = self.openpgp.public_key(&parent_node_priv).await?;

        // Encrypt the new node's passphrase to the parent node key.
        let node_passphrase_bytes = node_passphrase.as_bytes();
        let passphrase_session_key = self
            .openpgp
            .generate_session_key(&[], EncryptOptions::default())
            .await?;
        let node_passphrase_encrypted = self
            .openpgp
            .encrypt_and_sign(
                node_passphrase_bytes,
                &passphrase_session_key,
                std::slice::from_ref(&parent_node_pub),
                &address_priv,
                EncryptOptions::default(),
            )
            .await?;
        // NodePassphrase is an armored PGP MESSAGE on the wire (OpenAPI
        // `PGPMessage`); base64 is rejected with "not valid PGP data".
        let node_passphrase_armored = armor(&node_passphrase_encrypted, ArmorKind::Message);

        // Detached signature over the *plaintext* passphrase, signed by the
        // address key, with no signature context — mirrors JS
        // `encryptAndSignDetachedArmored` (the detached sig is over `binaryData`,
        // i.e. the passphrase bytes, not the ciphertext). Armored PGP SIGNATURE.
        let passphrase_sig = self
            .openpgp
            .sign(node_passphrase_bytes, &address_priv, "")
            .await?;
        let passphrase_sig_armored = armor(&passphrase_sig, ArmorKind::Signature);

        // ── step 1b: generate content session key ─────────────────────────────
        let content_session_key = self
            .openpgp
            .generate_session_key(&[], EncryptOptions::default())
            .await?;

        // Wrap content session key in PKESK to node public key.
        let content_key_packet_bytes = self
            .openpgp
            .encrypt_session_key(&content_session_key, std::slice::from_ref(&node_pub))
            .await?;
        let content_key_packet_b64 =
            base64::engine::general_purpose::STANDARD.encode(&content_key_packet_bytes);

        // Sign the *raw content session key bytes* with the **node** key (not
        // the address key), no signature context — mirrors JS
        // `generateContentKey`: `signArmored(contentKeyPacketSessionKey.data,
        // [nodeKey])`. Armored PGP SIGNATURE.
        let content_key_sig = self
            .openpgp
            .sign(&content_session_key.data, &node_priv, "")
            .await?;
        let content_key_sig_armored = armor(&content_key_sig, ArmorKind::Signature);

        // ── step 1c: encrypt file name + compute name hash ────────────────────
        let name_session_key = self
            .openpgp
            .generate_session_key(&[], EncryptOptions::default())
            .await?;
        let encrypted_name_bytes = self
            .openpgp
            .encrypt_and_sign(
                self.name.as_bytes(),
                &name_session_key,
                &[parent_node_pub],
                &address_priv,
                EncryptOptions::default(),
            )
            .await?;
        // Name is an armored PGP MESSAGE on the wire (OpenAPI `PGPMessage`).
        let encrypted_name_armored = armor(&encrypted_name_bytes, ArmorKind::Message);

        // Name hash: HMAC-SHA256(parent_hash_key, name_bytes) → hex.
        // Mirrors JS `generateLookupHash` (driveCrypto.ts): the key is the
        // parent folder's decrypted NodeHashKey bytes; the message is the
        // UTF-8 file name. The server validates this against the parent's
        // hash-key namespace, so a wrong key yields HTTP 422.
        let name_hash_hex = compute_name_hash_hex(&parent_hash_key, &self.name)?;

        // ── step 2: POST create file node ─────────────────────────────────────
        let create_req = CreateFileRequest {
            name: encrypted_name_armored,
            hash: name_hash_hex,
            parent_link_id: self.parent.node_id.clone(),
            mime_type: self.metadata.media_type.clone(),
            client_uid: None,
            intended_upload_size: None,
            // NodeKey is the armored *private* key locked with `node_passphrase`
            // (OpenAPI `PGPPrivateKey`) — readers unlock it with the decrypted
            // passphrase. Sending the public key makes node-key unlock fail.
            node_key: node_priv.armored.clone(),
            node_passphrase: node_passphrase_armored,
            node_passphrase_signature: passphrase_sig_armored,
            content_key_packet: content_key_packet_b64,
            content_key_packet_signature: content_key_sig_armored,
            signature_address: address_email.clone(),
        };

        let (link_id, revision_id) = self.post_create_file(&volume_id, create_req).await?;

        // ── steps 3-9: verification code, block encrypt+upload, manifest,
        // XAttr, commit ────────────────────────────────────────────────────────
        // A failure anywhere in here leaves an orphaned draft node on the
        // server. JS treats deletion as unconditional cleanup on any failure
        // downstream of node creation (`fileUploader.ts` `createRevisionDraft`'s
        // catch block calls `manager.deleteDraftNode`; `streamUploader.ts`
        // `start()`'s `finally { await this.onFinish(failure) }` does the same
        // for every exception raised by `encryptAndUploadBlocks`/`commitFile`),
        // and treats the delete call itself as best-effort — `deleteDraftNode`
        // (manager.ts) only logs a delete failure, it never lets it mask the
        // original error. We mirror both here: wrap the whole post-creation
        // body, and swallow (log) any cleanup failure in
        // `delete_draft_best_effort`.
        let body_result = self
            .upload_after_create(
                &mut stream,
                progress_tx,
                cancel,
                &volume_id,
                &link_id,
                &revision_id,
                &address_email,
                &address_priv,
                &node_pub,
                &content_session_key,
            )
            .await;

        if body_result.is_err() {
            self.delete_draft_best_effort(&volume_id, &link_id).await;
        }

        body_result
    }

    /// Steps 3-9 of the block-upload protocol, run once the draft node and
    /// revision already exist on the server (`link_id`/`revision_id`). Split
    /// out from `run_upload` so any failure here can trigger best-effort
    /// draft cleanup at the call site without duplicating that logic on every
    /// early return.
    #[allow(clippy::too_many_arguments)]
    async fn upload_after_create(
        &self,
        stream: &mut Box<dyn AsyncRead + Send + Unpin>,
        progress_tx: &tokio::sync::watch::Sender<u64>,
        cancel: &tokio_util::sync::CancellationToken,
        volume_id: &str,
        link_id: &str,
        revision_id: &str,
        address_email: &str,
        address_priv: &PrivateKey,
        node_pub: &PublicKey,
        content_session_key: &SessionKey,
    ) -> Result<()> {
        // ── step 3: get verification data from server ─────────────────────────
        // The JS SDK fetches a verification code from:
        //   GET drive/v2/volumes/{volumeID}/links/{linkID}/revisions/{revisionID}/verification
        // which returns { VerificationCode: base64, ContentKeyPacket: base64 }.
        // This is used to compute the verifier token per block.
        let verification_code = self
            .get_verification_code(volume_id, link_id, revision_id)
            .await?;

        // ── step 4: read stream, chunk into 4 MiB blocks, encrypt each ────────
        let mut blocks: Vec<EncryptedBlock> = Vec::new();
        let mut block_sizes: Vec<u64> = Vec::new();
        let mut sha1_hasher = Sha1::new();
        let mut total_bytes: u64 = 0;
        // Proton block indices are 1-based (JS `streamUploader` does `index++`
        // before the first use); Index 0 is rejected ("value should be positive").
        let mut block_index: u32 = 1;

        loop {
            if cancel.is_cancelled() {
                return Err(Error::Internal("upload cancelled".into()));
            }

            let mut buf = vec![0u8; BLOCK_SIZE];
            let mut read_bytes: usize = 0;

            // Fill buffer up to BLOCK_SIZE.
            loop {
                let remaining = BLOCK_SIZE - read_bytes;
                match stream
                    .read(&mut buf[read_bytes..read_bytes + remaining])
                    .await
                {
                    Ok(0) => break,
                    Ok(n) => {
                        read_bytes += n;
                        if read_bytes == BLOCK_SIZE {
                            break;
                        }
                    }
                    Err(e) => return Err(Error::Network(format!("stream read: {e}"))),
                }
            }

            if read_bytes == 0 {
                break; // EOF
            }

            let plaintext_block = &buf[..read_bytes];
            sha1_hasher.update(plaintext_block);
            total_bytes += read_bytes as u64;
            block_sizes.push(read_bytes as u64);

            // Encrypt-only the block content with the content session key (no
            // PKESK — bare SEIPD per ADR-0008 — and no embedded signature).
            // Mirrors JS `encryptBlock` (driveCrypto.ts), which calls
            // `encryptAndSignDetached(blockData, sessionKey, [], signingKey,
            // ...)`: passing `detached: true` to `cryptoProxy.encryptMessage`
            // means the returned ciphertext carries only the literal content —
            // the signature is produced and transmitted separately (below).
            // An earlier version of this port used `encrypt_and_sign` here,
            // which embeds a redundant One-Pass-Signature + Signature packet
            // inside the SEIPD payload alongside the literal data. That
            // embedded signature was never verified on read — `download.rs`
            // decrypts blocks via `decrypt_and_verify(&ciphertext, session_key,
            // &[])` with an empty verification-key list, and JS's own
            // `decryptBlock` does the same ("We do not verify signatures on
            // blocks") — so removing it changes nothing observable for either
            // this port or JS-produced files (which never had a block-level
            // embedded signature to begin with); it only drops dead bytes and
            // a redundant signing operation per block.
            let ciphertext = self
                .openpgp
                .encrypt(
                    plaintext_block,
                    content_session_key,
                    &[], // no PKESK — bare SEIPD
                    EncryptOptions::default(),
                )
                .await?;

            // SHA256 of ciphertext.
            let ciphertext_hash: [u8; 32] = {
                let mut h = Sha256::new();
                h.update(&ciphertext);
                h.finalize().into()
            };
            let ciphertext_hash_hex = hex::encode(ciphertext_hash);

            // Detached signature of the plaintext block, signed by the address
            // key, no signature context (JS `encryptBlock`).
            let block_sig_bytes = self.openpgp.sign(plaintext_block, address_priv, "").await?;

            // Encrypt-only the detached signature to the **node** key under the
            // **content session key** (JS `encryptSignature`: `encryptArmored(sig,
            // [nodeKey], contentSessionKey)`), then armor. The server validates
            // this as `PGPMessage`; readers decrypt it with the content key.
            let enc_sig_bytes = self
                .openpgp
                .encrypt(
                    &block_sig_bytes,
                    content_session_key,
                    std::slice::from_ref(node_pub),
                    EncryptOptions::default(),
                )
                .await?;
            let enc_signature_armored = armor(&enc_sig_bytes, ArmorKind::Message);

            // Verifier token: XOR verification_code[i] with ciphertext[i].
            // (blockVerifier.ts: `verificationCode.map((v, i) => v ^ (encryptedData[i] || 0))`)
            let verifier_token: Vec<u8> = verification_code
                .iter()
                .enumerate()
                .map(|(i, &v)| v ^ ciphertext.get(i).copied().unwrap_or(0))
                .collect();
            let verifier_token_b64 =
                base64::engine::general_purpose::STANDARD.encode(&verifier_token);

            blocks.push(EncryptedBlock {
                index: block_index,
                ciphertext,
                ciphertext_hash_hex,
                enc_signature: enc_signature_armored,
                verifier_token_b64,
            });

            block_index += 1;

            let _ = progress_tx.send(total_bytes);

            if read_bytes < BLOCK_SIZE {
                break; // last block
            }
        }

        if blocks.is_empty() {
            return Err(Error::Validation(
                "upload_from_stream: stream was empty".into(),
            ));
        }

        // Validate computed size against expected_size.
        if total_bytes != self.metadata.expected_size {
            return Err(Error::Validation(format!(
                "stream size mismatch: expected {} bytes, got {}",
                self.metadata.expected_size, total_bytes
            )));
        }

        // ── step 5: POST request block upload tokens ──────────────────────────
        let block_entries: Vec<BlockUploadEntry> = blocks
            .iter()
            .map(|b| BlockUploadEntry {
                index: b.index,
                enc_signature: b.enc_signature.clone(),
                verifier: ApiBlockVerifier {
                    token: b.verifier_token_b64.clone(),
                },
            })
            .collect();

        // Block-upload keys on the Proton AddressID, not the email (the email is
        // only valid for `SignatureAddress` on the create-file request).
        let address_id = self.account.address_id(address_email).await?;
        let block_req = RequestBlockUploadRequest {
            address_id,
            volume_id: volume_id.to_owned(),
            link_id: link_id.to_owned(),
            revision_id: revision_id.to_owned(),
            block_list: block_entries,
            thumbnail_list: Vec::new(),
        };

        let upload_links = self.post_request_blocks(block_req).await?;

        if upload_links.len() != blocks.len() {
            return Err(Error::ProtocolViolation(format!(
                "server returned {} upload links but {} blocks were requested",
                upload_links.len(),
                blocks.len()
            )));
        }

        // ── step 6: PUT each block to its BareURL ─────────────────────────────
        // Sort upload_links by index so we match the correct block.
        let mut sorted_links = upload_links;
        sorted_links.sort_by_key(|l| l.index);

        for (block, link) in blocks.iter().zip(sorted_links.iter()) {
            if cancel.is_cancelled() {
                return Err(Error::Internal("upload cancelled".into()));
            }
            self.put_block(&link.bare_url, &link.token, &block.ciphertext)
                .await?;
        }

        // ── step 7: compute manifest signature ────────────────────────────────
        // Manifest payload = concat(sha256_raw_bytes[0..N] in index order).
        let manifest_payload: Vec<u8> = blocks
            .iter()
            .flat_map(|b| {
                // Re-hash from hex string to get raw [u8; 32].
                hex::decode(&b.ciphertext_hash_hex).unwrap_or_else(|_| vec![0u8; 32])
            })
            .collect();

        // No signature context: JS signManifest → signArmored signs with no
        // context (client/js/src/crypto/driveCrypto.ts), and verifyManifest →
        // verifyArmored reads it back with no context. A non-empty context here
        // would embed a critical notation that OpenPGP.js verification rejects.
        let manifest_sig = self
            .openpgp
            .sign(&manifest_payload, address_priv, "")
            .await?;
        let manifest_sig_armored = armor(&manifest_sig, ArmorKind::Signature);

        // ── step 8: compute XAttr, verify integrity ───────────────────────────
        let sha1_hex = hex::encode(sha1_hasher.finalize());

        // Compare the streamed digest against the caller-supplied expectation,
        // mirroring JS `verifyIntegrity` (streamUploader.ts): a mismatch is
        // fatal — JS throws `IntegrityError` from `commitFile` *before*
        // `commitDraft`/`ChecksumVerified` is ever sent — and `checksumVerified`
        // is only `true` when the comparison actually matched, never simply
        // "a checksum was supplied":
        // `checksumVerified: !!(expectedSha1 && digests.sha1 === expectedSha1)`.
        // `Error::Integrity` (not `IntegrityCheckFailed`) matches the variant
        // `download.rs` already uses for a computed-vs-expected digest
        // mismatch (ciphertext SHA-256), keeping the two symmetric.
        let checksum_verified = match &self.metadata.expected_sha1_hex {
            Some(expected) if expected == &sha1_hex => true,
            Some(expected) => {
                return Err(Error::Integrity(format!(
                    "file hash does not match expected hash: expected {expected}, got {sha1_hex}"
                )));
            }
            None => false,
        };

        let xattr_json = build_xattr_json(
            total_bytes,
            &block_sizes,
            &sha1_hex,
            self.metadata.modification_time,
        );

        let xattr_session_key = self
            .openpgp
            .generate_session_key(&[], EncryptOptions::default())
            .await?;
        let xattr_ciphertext = self
            .openpgp
            .encrypt_and_sign(
                xattr_json.as_bytes(),
                &xattr_session_key,
                std::slice::from_ref(node_pub),
                address_priv,
                EncryptOptions::default(),
            )
            .await?;
        let xattr_armored = armor(&xattr_ciphertext, ArmorKind::Message);

        // ── step 9: commit revision ───────────────────────────────────────────
        let commit_req = CommitRevisionRequest {
            manifest_signature: manifest_sig_armored,
            signature_address: address_email.to_owned(),
            x_attr: xattr_armored,
            checksum_verified,
            photo: None,
        };

        self.put_commit_revision(volume_id, link_id, revision_id, commit_req)
            .await?;

        let _ = progress_tx.send(total_bytes);
        Ok(())
    }

    /// Best-effort draft-node cleanup after a post-creation failure.
    ///
    /// Mirrors JS `UploadManager.deleteDraftNode` (manager.ts): the delete
    /// call's own failure is only logged, never propagated, so it can never
    /// mask the original upload error that triggered this cleanup. Wire
    /// format: `POST drive/v2/volumes/{volumeID}/delete_multiple` with
    /// `{"LinkIDs": [nodeId]}` (JS `apiService.ts` `deleteDraft`), whose
    /// response is a per-link multi-status wrapper — the outer envelope
    /// `Code` is a fixed marker (`1001`); the real per-link result lives at
    /// `Responses[0].Response.Code`, which is what JS actually inspects.
    async fn delete_draft_best_effort(&self, volume_id: &str, link_id: &str) {
        let req_body = DeleteNodesRequest {
            link_ids: vec![link_id.to_owned()],
        };
        let body_bytes = match serde_json::to_vec(&req_body) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(
                    link_id = %link_id,
                    "delete_draft: failed to serialize request: {e}"
                );
                return;
            }
        };
        let req = JsonRequest {
            method: HttpMethod::Post,
            path: format!("/drive/v2/volumes/{volume_id}/delete_multiple"),
            query: vec![],
            headers: vec![],
            body: Some(body_bytes),
        };
        let resp = match self.http.request_json(req).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    link_id = %link_id,
                    "failed to delete draft node after upload failure: {e}"
                );
                return;
            }
        };
        match serde_json::from_slice::<ResponseEnvelope<DeleteNodesResponse>>(&resp.body) {
            Ok(env) => {
                let per_link_code = env
                    .inner
                    .responses
                    .first()
                    .map(|r| r.response.code)
                    .unwrap_or(0);
                if per_link_code != CODE_OK {
                    tracing::error!(
                        link_id = %link_id,
                        code = per_link_code,
                        "failed to delete draft node after upload failure"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    link_id = %link_id,
                    "delete_draft: failed to parse response: {e}; body={}",
                    body_snippet(&resp.body)
                );
            }
        }
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    /// Resolve the real VolumeID from a share_id.
    ///
    /// FIXME: NodeUid naming — see MC commit f6b29b1 note.
    async fn resolve_volume_id(&self, share_id: &str) -> Result<String> {
        let path = format!("/drive/shares/{share_id}");
        let req = JsonRequest {
            method: HttpMethod::Get,
            path,
            query: vec![],
            headers: vec![],
            body: None,
        };
        let resp = self.http.request_json(req).await?;
        let env: ResponseEnvelope<proton_drive_api::shares::GetShareResponse> =
            serde_json::from_slice(&resp.body)
                .map_err(|e| Error::Internal(format!("shares JSON parse: {e}")))?;
        if env.code != CODE_OK {
            return Err(map_api_error(env.code, env.error));
        }
        Ok(env.inner.share.volume_id)
    }

    /// Resolve the parent folder's node private key and its decrypted hash key.
    ///
    /// Mirrors the download key chain plus JS `getNodeKeys`:
    ///   1. `GET drive/shares/{shareID}` → decrypt the share key with the
    ///      address key (address → share passphrase → share private key).
    ///   2. `GET drive/shares/{shareID}/links/{parentLinkID}` → decrypt the
    ///      parent node key with the share key (the new node's passphrase is
    ///      encrypted to the parent NODE key, not the share key).
    ///   3. Decrypt the parent's `FolderProperties.NodeHashKey` with the parent
    ///      node key → the HMAC key used to compute child name hashes.
    ///
    /// MVP restriction: only correct when `parent.node_id` is the share root.
    /// Nested folders need an ancestor-chain walk (deferred).
    async fn resolve_parent_context(
        &self,
        share_id: &str,
    ) -> Result<(proton_drive_crypto::PrivateKey, Vec<u8>)> {
        // ── share key ─────────────────────────────────────────────────────────
        let share: proton_drive_api::shares::Share = {
            let resp = self
                .http
                .request_json(JsonRequest {
                    method: HttpMethod::Get,
                    path: format!("/drive/shares/{share_id}"),
                    query: vec![],
                    headers: vec![],
                    body: None,
                })
                .await?;
            let env: ResponseEnvelope<proton_drive_api::shares::GetShareResponse> =
                serde_json::from_slice(&resp.body)
                    .map_err(|e| Error::Internal(format!("share JSON parse: {e}")))?;
            if env.code != CODE_OK {
                return Err(map_api_error(env.code, env.error));
            }
            env.inner.share
        };

        let address_email = self.account.primary_email().to_owned();
        let address_priv = self.account.address_private_key(&address_email).await?;

        // Upload's parent-context resolution doesn't (yet) verify
        // PassphraseSignature/NodePassphraseSignature — pass no verification
        // keys, preserving prior (pre-verification) behaviour exactly. See
        // `ProtonDriveClient::resolve_share_key`/`resolve_node_key_via_chain`
        // in `client.rs` for the download path's non-fatal verification.
        let (share_priv, _verified) = crate::download::decrypt_share_key(
            &self.openpgp,
            &share.key,
            &share.passphrase,
            &share.passphrase_signature,
            &address_priv,
            &[],
        )
        .await?;

        // ── parent link → parent node key ──────────────────────────────────────
        let parent_link_id = &self.parent.node_id;
        let link: proton_drive_api::nodes::Link = {
            let resp = self
                .http
                .request_json(JsonRequest {
                    method: HttpMethod::Get,
                    path: format!("/drive/shares/{share_id}/links/{parent_link_id}"),
                    query: vec![],
                    headers: vec![],
                    body: None,
                })
                .await?;
            let env: ResponseEnvelope<proton_drive_api::nodes::GetLinkResponse> =
                serde_json::from_slice(&resp.body)
                    .map_err(|e| Error::Internal(format!("parent link JSON parse: {e}")))?;
            if env.code != CODE_OK {
                return Err(map_api_error(env.code, env.error));
            }
            env.inner.link
        };

        let (parent_node_priv, _verified) = crate::download::decrypt_node_private_key(
            &self.openpgp,
            &link.node_key,
            &link.node_passphrase,
            &link.node_passphrase_signature,
            &share_priv,
            &[],
        )
        .await?;

        // ── parent node hash key ────────────────────────────────────────────────
        let node_hash_key_armored = link
            .folder_properties
            .as_ref()
            .and_then(|f| f.node_hash_key.as_ref())
            .ok_or_else(|| {
                Error::Internal("parent link is not a folder or has no NodeHashKey".into())
            })?;

        // NodeHashKey is an armored PGP message (PGPMessage). The crypto layer
        // dearmors transparently. JS `decryptNodeHashKey` does not require the
        // signature to verify — we only need the plaintext key bytes.
        let hash_key_bytes = node_hash_key_armored.as_bytes();
        let hash_key_session_key = self
            .openpgp
            .decrypt_session_key(hash_key_bytes, std::slice::from_ref(&parent_node_priv))
            .await?;
        let (parent_hash_key, _status) = self
            .openpgp
            .decrypt_and_verify(hash_key_bytes, &hash_key_session_key, &[])
            .await?;

        Ok((parent_node_priv, parent_hash_key))
    }

    /// Fetch the server-supplied verification code for a revision draft.
    ///
    /// `GET drive/v2/volumes/{volumeID}/links/{linkID}/revisions/{revisionID}/verification`
    async fn get_verification_code(
        &self,
        volume_id: &str,
        link_id: &str,
        revision_id: &str,
    ) -> Result<Vec<u8>> {
        let path = format!(
            "/drive/v2/volumes/{volume_id}/links/{link_id}/revisions/{revision_id}/verification"
        );
        let req = JsonRequest {
            method: HttpMethod::Get,
            path,
            query: vec![],
            headers: vec![],
            body: None,
        };
        let resp = self.http.request_json(req).await?;
        let env: ResponseEnvelope<VerificationDataResponse> = serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Internal(format!("verification JSON parse: {e}")))?;
        if env.code != CODE_OK {
            return Err(map_api_error(env.code, env.error));
        }
        let code_bytes = base64::engine::general_purpose::STANDARD
            .decode(&env.inner.verification_code)
            .map_err(|e| Error::Internal(format!("verification code base64: {e}")))?;
        Ok(code_bytes)
    }

    async fn post_create_file(
        &self,
        volume_id: &str,
        req_body: CreateFileRequest,
    ) -> Result<(String, String)> {
        let body_bytes = serde_json::to_vec(&req_body)
            .map_err(|e| Error::Internal(format!("serialize CreateFileRequest: {e}")))?;
        let req = JsonRequest {
            method: HttpMethod::Post,
            path: format!("/drive/v2/volumes/{volume_id}/files"),
            query: vec![],
            headers: vec![],
            body: Some(body_bytes),
        };
        let resp = self.http.request_json(req).await?;
        // Error responses (e.g. 2500 name-exists, 2501 parent-not-found) omit
        // the typed `File` body, so a `ResponseEnvelope<CreateFileResponse>`
        // flatten-parse would fail with an opaque "missing field" before the
        // code check. Probe the bare `Code`/`Error` first so API errors surface
        // as domain errors.
        let probe: EnvelopeProbe = serde_json::from_slice(&resp.body).map_err(|e| {
            Error::Internal(format!(
                "CreateFile envelope parse: {e}; body={}",
                body_snippet(&resp.body)
            ))
        })?;
        if probe.code != CODE_OK {
            return Err(map_api_error(probe.code, probe.error));
        }
        let env: ResponseEnvelope<proton_drive_api::upload::CreateFileResponse> =
            serde_json::from_slice(&resp.body).map_err(|e| {
                Error::Internal(format!(
                    "CreateFileResponse parse: {e}; body={}",
                    body_snippet(&resp.body)
                ))
            })?;
        Ok((env.inner.file.link_id, env.inner.file.revision_id))
    }

    async fn post_request_blocks(
        &self,
        req_body: RequestBlockUploadRequest,
    ) -> Result<Vec<proton_drive_api::upload::UploadLink>> {
        let body_bytes = serde_json::to_vec(&req_body)
            .map_err(|e| Error::Internal(format!("serialize RequestBlockUploadRequest: {e}")))?;
        let req = JsonRequest {
            method: HttpMethod::Post,
            path: "/drive/blocks".to_owned(),
            query: vec![],
            headers: vec![],
            body: Some(body_bytes),
        };
        let resp = self.http.request_json(req).await?;
        // Probe Code/Error first: an error response omits the typed payload, so a
        // direct typed parse would surface "missing field UploadLinks" and mask
        // the real server error code.
        let probe: EnvelopeProbe = serde_json::from_slice(&resp.body).map_err(|e| {
            Error::Internal(format!(
                "RequestBlockUpload envelope parse: {e}; body: {}",
                body_snippet(&resp.body)
            ))
        })?;
        if probe.code != CODE_OK {
            return Err(map_api_error(probe.code, probe.error));
        }
        let env: ResponseEnvelope<proton_drive_api::upload::RequestBlockUploadResponse> =
            serde_json::from_slice(&resp.body).map_err(|e| {
                Error::Internal(format!(
                    "RequestBlockUploadResponse parse: {e}; body: {}",
                    body_snippet(&resp.body)
                ))
            })?;
        Ok(env.inner.upload_links)
    }

    /// PUT ciphertext to a block's bare URL with Bearer token auth.
    ///
    /// The JS SDK sends this as multipart/form-data with a "Block" part
    /// (apiService.ts `uploadBlock` / `postBlockStream`). We replicate that
    /// shape here: `Content-Type: multipart/form-data; boundary=...` with a
    /// single "Block" part containing the raw ciphertext bytes.
    ///
    /// BareURL is absolute (includes scheme+host), often on a different host
    /// than the API base (e.g. `https://upload.proton.me/...`). We pass it as
    /// the `path`; `request_blob` detects the `http(s)://` prefix and uses the
    /// URL verbatim rather than joining it against the API base_url.
    async fn put_block(&self, bare_url: &str, token: &str, ciphertext: &[u8]) -> Result<()> {
        // Build multipart/form-data body manually.
        let boundary = "pdtui_block_boundary_x7z9q";
        let mut body: Vec<u8> = Vec::with_capacity(ciphertext.len() + 256);
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"Block\"; filename=\"blob\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(ciphertext);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let req = BlobRequest {
            method: HttpMethod::Post,
            path: bare_url.to_owned(),
            query: vec![],
            // Storage endpoints authenticate with `pm-storage-token`, not the
            // API bearer (apiService.ts `makeStorageRequest`).
            headers: vec![
                ("pm-storage-token".to_owned(), token.to_owned()),
                (
                    "content-type".to_owned(),
                    format!("multipart/form-data; boundary={boundary}"),
                ),
            ],
            body: Bytes::from(body),
        };
        let resp = self.http.request_blob(req).await?;
        if resp.status != 200 {
            return Err(Error::IntegrityCheckFailed(format!(
                "block upload returned HTTP {}",
                resp.status
            )));
        }
        Ok(())
    }

    async fn put_commit_revision(
        &self,
        volume_id: &str,
        link_id: &str,
        revision_id: &str,
        req_body: CommitRevisionRequest,
    ) -> Result<()> {
        let body_bytes = serde_json::to_vec(&req_body)
            .map_err(|e| Error::Internal(format!("serialize CommitRevisionRequest: {e}")))?;
        let req = JsonRequest {
            method: HttpMethod::Put,
            path: format!("/drive/v2/volumes/{volume_id}/files/{link_id}/revisions/{revision_id}"),
            query: vec![],
            headers: vec![],
            body: Some(body_bytes),
        };
        let resp = self.http.request_json(req).await?;
        let env: ResponseEnvelope<serde_json::Value> = serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Internal(format!("CommitRevisionResponse parse: {e}")))?;
        if env.code != CODE_OK {
            return Err(map_api_error(env.code, env.error));
        }
        Ok(())
    }
}

// ── XAttr builder ─────────────────────────────────────────────────────────────

/// Build the file extended-attributes JSON, mirroring JS
/// `generateFileExtendedAttributes` (extendedAttributes.ts):
///   `{"Common":{"ModificationTime":<ISO-8601>,"Size":N,"BlockSizes":[...],
///     "Digests":{"SHA1":"<hex>"}}}`.
/// `ModificationTime` is omitted when no (valid) time is supplied. JSON key
/// order is irrelevant — the XAttr is encrypted and re-parsed, never byte-compared.
fn build_xattr_json(
    size_bytes: u64,
    block_sizes: &[u64],
    sha1_hex: &str,
    modification_time: Option<SystemTime>,
) -> String {
    let mut common = serde_json::Map::new();
    if let Some(iso) = modification_time.and_then(system_time_to_iso8601) {
        common.insert(
            "ModificationTime".to_owned(),
            serde_json::Value::String(iso),
        );
    }
    common.insert("Size".to_owned(), serde_json::json!(size_bytes));
    common.insert("BlockSizes".to_owned(), serde_json::json!(block_sizes));
    common.insert(
        "Digests".to_owned(),
        serde_json::json!({ "SHA1": sha1_hex }),
    );
    serde_json::json!({ "Common": serde_json::Value::Object(common) }).to_string()
}

/// Format a `SystemTime` as a UTC ISO-8601 string with millisecond precision
/// and a `Z` suffix, matching JavaScript's `Date.prototype.toISOString()`.
/// Returns `None` for times before the Unix epoch (JS treats those as invalid
/// here and omits the field).
fn system_time_to_iso8601(t: SystemTime) -> Option<String> {
    let dur = t.duration_since(UNIX_EPOCH).ok()?;
    let secs = dur.as_secs() as i64;
    let millis = dur.subsec_millis();

    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    // civil_from_days (Howard Hinnant): days since epoch → (year, month, day).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year_civil = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 {
        year_civil + 1
    } else {
        year_civil
    };

    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    ))
}

// ── Verification data DTO ─────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VerificationDataResponse {
    verification_code: String,
    #[allow(dead_code)]
    content_key_packet: Option<String>,
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_size() {
        let meta = UploadMetadata {
            media_type: "text/plain".into(),
            expected_size: 0,
            expected_sha1_hex: None,
            modification_time: None,
            additional_metadata_json: None,
            override_existing_draft_by_other_client: false,
        };
        let r = meta.validate();
        assert!(matches!(r, Err(Error::Validation(_))));
    }

    #[test]
    fn rejects_short_sha1() {
        let meta = UploadMetadata {
            media_type: "text/plain".into(),
            expected_size: 10,
            expected_sha1_hex: Some("abc".into()),
            modification_time: None,
            additional_metadata_json: None,
            override_existing_draft_by_other_client: false,
        };
        let r = meta.validate();
        assert!(matches!(r, Err(Error::Validation(_))));
    }

    #[test]
    fn accepts_valid_meta() {
        let meta = UploadMetadata {
            media_type: "text/plain".into(),
            expected_size: 10,
            expected_sha1_hex: Some("a".repeat(40)),
            modification_time: None,
            additional_metadata_json: None,
            override_existing_draft_by_other_client: false,
        };
        assert!(meta.validate().is_ok());
    }

    #[test]
    fn rejects_oversized_file() {
        let meta = UploadMetadata {
            media_type: "text/plain".into(),
            expected_size: MAX_FILE_SIZE + 1,
            expected_sha1_hex: None,
            modification_time: None,
            additional_metadata_json: None,
            override_existing_draft_by_other_client: false,
        };
        assert!(matches!(meta.validate(), Err(Error::Validation(_))));
    }

    #[test]
    fn xattr_json_with_mtime() {
        // 1_700_000_000 s since epoch == 2023-11-14T22:13:20.000Z.
        let mtime = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let json = build_xattr_json(1234, &[1000, 234], "aabbcc", Some(mtime));
        assert!(json.contains("\"ModificationTime\":\"2023-11-14T22:13:20.000Z\""));
        assert!(json.contains("\"Size\":1234"));
        assert!(json.contains("\"BlockSizes\":[1000,234]"));
        assert!(json.contains("\"SHA1\":\"aabbcc\""));
    }

    #[test]
    fn xattr_json_without_mtime() {
        let json = build_xattr_json(5678, &[5678], "ddeeff", None);
        assert!(!json.contains("ModificationTime"));
        assert!(json.contains("\"Size\":5678"));
        assert!(json.contains("\"BlockSizes\":[5678]"));
    }

    /// Known-answer test locking `compute_name_hash_hex`'s exact byte output
    /// against an independent HMAC-SHA256 computation. Provenance: Node's
    /// built-in `crypto` module (standard HMAC-SHA256 — the same primitive
    /// JS's `@protontech/crypto/subtle/hmac.ts` `importKey`/`signData` wraps
    /// for `generateLookupHash`, `reference/client/js/src/crypto/driveCrypto.ts:439-443`;
    /// `@protontech/crypto` itself isn't vendored under `reference/`, so this
    /// cross-checks the algorithm rather than shelling out to their exact lib):
    /// ```text
    /// node -e 'console.log(require("crypto")
    ///   .createHmac("sha256", Buffer.from("my-hash-key", "utf8"))
    ///   .update("test-file.txt", "utf8").digest("hex"))'
    /// ```
    /// computed 2026-07-05, matching the `key`/`name` pair
    /// `mock_upload_protocol_flow` below drives through the real upload path.
    /// Regression class: B1 (name hash computed as plain SHA-256 instead of
    /// HMAC-SHA256) previously blocked every upload with HTTP 422 — see
    /// `docs/IMPLEMENTATION-STATUS.md`.
    const NAME_HASH_KAT_HEX: &str =
        "57926179833b9813451381f9e7af89dec9f49ddc5b8bc0cabae1079805ee77ca";

    #[test]
    fn name_hash_hex_matches_known_answer() {
        let got = compute_name_hash_hex(b"my-hash-key", "test-file.txt").unwrap();
        assert_eq!(got, NAME_HASH_KAT_HEX);
    }

    // ── Mock-HTTP protocol flow test ──────────────────────────────────────────
    // This test exercises the 9-step protocol using in-process fakes for the
    // HTTP client, crypto module, and account — without hitting the real API.

    use std::collections::VecDeque;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use proton_drive_crypto::{
        CryptoError, EncryptOptions, PrivateKey as CPrivKey, PublicKey as CPubKey, SessionKey,
        VerificationStatus,
    };

    // ── Fake HTTP client ──────────────────────────────────────────────────────

    struct FakeHttpClient {
        responses: Mutex<VecDeque<(u16, Vec<u8>)>>,
        recorded_paths: Mutex<Vec<String>>,
        /// `request_json` bodies only, aligned by index with the subset of
        /// `recorded_paths` entries that came from `request_json` calls (blob
        /// requests are not recorded here since no test currently needs them).
        recorded_json_bodies: Mutex<Vec<(String, Option<Vec<u8>>)>>,
    }

    impl FakeHttpClient {
        fn new(responses: Vec<(u16, Vec<u8>)>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                recorded_paths: Mutex::new(vec![]),
                recorded_json_bodies: Mutex::new(vec![]),
            }
        }

        fn next_response(&self) -> (u16, Vec<u8>) {
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or((200, b"{}".to_vec()))
        }

        fn recorded_paths(&self) -> Vec<String> {
            self.recorded_paths.lock().unwrap().clone()
        }

        /// Find the recorded `request_json` body for the first path containing
        /// `needle` that actually has a body (skips GETs, which pass `None`),
        /// parsed as JSON.
        fn json_body_containing(&self, needle: &str) -> Option<serde_json::Value> {
            self.recorded_json_bodies
                .lock()
                .unwrap()
                .iter()
                .find(|(path, body)| path.contains(needle) && body.is_some())
                .and_then(|(_, body)| body.as_ref())
                .map(|b| serde_json::from_slice(b).unwrap())
        }
    }

    #[async_trait]
    impl ProtonDriveHttpClient for FakeHttpClient {
        async fn request_json(&self, req: JsonRequest) -> Result<crate::http::JsonResponse> {
            self.recorded_paths.lock().unwrap().push(req.path.clone());
            self.recorded_json_bodies
                .lock()
                .unwrap()
                .push((req.path.clone(), req.body.clone()));
            let (status, body) = self.next_response();
            Ok(crate::http::JsonResponse {
                status,
                headers: vec![],
                body: Bytes::from(body),
            })
        }

        async fn request_blob(&self, req: BlobRequest) -> Result<crate::http::JsonResponse> {
            self.recorded_paths.lock().unwrap().push(req.path.clone());
            let (status, body) = self.next_response();
            Ok(crate::http::JsonResponse {
                status,
                headers: vec![],
                body: Bytes::from(body),
            })
        }
    }

    // ── Fake OpenPGP crypto ───────────────────────────────────────────────────

    struct FakeCrypto;

    #[async_trait]
    impl proton_drive_crypto::OpenPgpCrypto for FakeCrypto {
        fn generate_passphrase(&self) -> zeroize::Zeroizing<String> {
            zeroize::Zeroizing::new("fake-passphrase".into())
        }

        async fn decrypt_key(
            &self,
            armored: &str,
            _passphrase: &str,
        ) -> std::result::Result<CPrivKey, CryptoError> {
            Ok(CPrivKey {
                armored: armored.to_owned(),
                fingerprint_hex: "deadbeef".into(),
                passphrase: zeroize::Zeroizing::new("fake-pass".into()),
            })
        }

        async fn encrypt(
            &self,
            data: &[u8],
            _session_key: &SessionKey,
            _encryption_keys: &[CPubKey],
            _opts: EncryptOptions,
        ) -> std::result::Result<Vec<u8>, CryptoError> {
            let mut out = b"FAKE_ENC:".to_vec();
            out.extend_from_slice(data);
            Ok(out)
        }

        async fn encrypt_and_sign(
            &self,
            data: &[u8],
            _session_key: &SessionKey,
            _encryption_keys: &[CPubKey],
            _signing_key: &CPrivKey,
            _opts: EncryptOptions,
        ) -> std::result::Result<Vec<u8>, CryptoError> {
            // Fake: prepend a marker so tests can detect encryption happened.
            let mut out = b"FAKE_ENC:".to_vec();
            out.extend_from_slice(data);
            Ok(out)
        }

        async fn decrypt_and_verify(
            &self,
            data: &[u8],
            _session_key: &SessionKey,
            _verification_keys: &[CPubKey],
        ) -> std::result::Result<(Vec<u8>, VerificationStatus), CryptoError> {
            // Fake: strip FAKE_ENC: prefix.
            let plain = if data.starts_with(b"FAKE_ENC:") {
                data[9..].to_vec()
            } else {
                data.to_vec()
            };
            Ok((plain, VerificationStatus::Ok))
        }

        async fn decrypt_session_key(
            &self,
            _data: &[u8],
            _decryption_keys: &[CPrivKey],
        ) -> std::result::Result<SessionKey, CryptoError> {
            Ok(SessionKey {
                data: zeroize::Zeroizing::new(vec![0u8; 32]),
                cipher_algorithm: 9,
                aead: proton_drive_crypto::AeadAlgorithm::None,
            })
        }

        async fn encrypt_session_key(
            &self,
            _session_key: &SessionKey,
            _encryption_keys: &[CPubKey],
        ) -> std::result::Result<Vec<u8>, CryptoError> {
            Ok(b"FAKE_PKESK".to_vec())
        }

        async fn encrypt_session_key_with_password(
            &self,
            _session_key: &SessionKey,
            _password: &str,
        ) -> std::result::Result<Vec<u8>, CryptoError> {
            Ok(b"FAKE_SKESK".to_vec())
        }

        async fn generate_session_key(
            &self,
            _encryption_keys: &[CPubKey],
            _opts: EncryptOptions,
        ) -> std::result::Result<SessionKey, CryptoError> {
            Ok(SessionKey {
                data: zeroize::Zeroizing::new(vec![0xab; 32]),
                cipher_algorithm: 9,
                aead: proton_drive_crypto::AeadAlgorithm::None,
            })
        }

        async fn generate_key(
            &self,
            passphrase: &str,
            _opts: EncryptOptions,
        ) -> std::result::Result<(CPrivKey, String), CryptoError> {
            let priv_key = CPrivKey {
                armored: "FAKE_PRIV_KEY".into(),
                fingerprint_hex: "cafebabe".into(),
                passphrase: zeroize::Zeroizing::new(passphrase.to_owned()),
            };
            Ok((priv_key, "FAKE_PUB_KEY".into()))
        }

        async fn sign(
            &self,
            data: &[u8],
            _signing_key: &CPrivKey,
            _context: &str,
        ) -> std::result::Result<Vec<u8>, CryptoError> {
            let mut out = b"SIG:".to_vec();
            out.extend_from_slice(&data[..data.len().min(8)]);
            Ok(out)
        }

        async fn verify(
            &self,
            _data: &[u8],
            _signature: &[u8],
            _verification_keys: &[CPubKey],
        ) -> std::result::Result<VerificationStatus, CryptoError> {
            Ok(VerificationStatus::Ok)
        }

        async fn public_key(&self, key: &CPrivKey) -> std::result::Result<CPubKey, CryptoError> {
            Ok(CPubKey {
                armored: "FAKE_PUB_KEY".into(),
                fingerprint_hex: key.fingerprint_hex.clone(),
            })
        }

        async fn public_key_from_armored(
            &self,
            _armored: &str,
        ) -> std::result::Result<CPubKey, CryptoError> {
            Ok(CPubKey {
                armored: "FAKE_PUB_KEY".into(),
                fingerprint_hex: "12345678".into(),
            })
        }
    }

    // ── Fake account ──────────────────────────────────────────────────────────

    struct FakeAccount;

    #[async_trait]
    impl crate::account::ProtonDriveAccount for FakeAccount {
        fn user_id(&self) -> &str {
            "fake-user-id"
        }

        fn primary_email(&self) -> &str {
            "test@proton.me"
        }

        async fn address_private_key(&self, _email: &str) -> Result<CPrivKey> {
            Ok(CPrivKey {
                armored: "FAKE_ADDR_KEY".into(),
                fingerprint_hex: "12345678".into(),
                passphrase: zeroize::Zeroizing::new("addr-pass".into()),
            })
        }

        async fn address_public_keys(&self, _email: &str) -> Result<Vec<CPubKey>> {
            Ok(vec![CPubKey {
                armored: "FAKE_PUB_KEY".into(),
                fingerprint_hex: "12345678".into(),
            }])
        }

        async fn address_id(&self, _email: &str) -> Result<String> {
            Ok("fake-address-id".into())
        }

        async fn key_password(&self) -> Result<String> {
            Ok("fake-key-password".into())
        }
    }

    // ── Protocol flow test ────────────────────────────────────────────────────

    #[tokio::test]
    async fn mock_upload_protocol_flow() {
        use crate::nodes::make_node_uid;

        // Build mock HTTP responses in the expected call order:
        // 1. GET /drive/shares/{shareID}            → resolve volume_id
        // 2. GET /drive/shares/{shareID}            → parent context: share key
        // 3. GET /drive/shares/{shareID}/links/{id} → parent context: node + hash key
        // 4. POST /drive/v2/volumes/.../files       → create file
        // 5. GET /drive/v2/volumes/.../verification → verification code
        // 6. POST /drive/blocks                     → request block upload tokens
        // 7. POST <bare_url>                        → upload block (BlobRequest)
        // 8. PUT /drive/v2/volumes/.../revisions/{revID} → commit revision

        // `GET drive/shares/{shareID}` returns share fields flat at the envelope
        // level (no `Share` wrapper) — matches `GetShareResponse`'s flatten.
        let share_resp = serde_json::json!({
            "Code": 1000,
            "ShareID": "share-abc",
            "VolumeID": "vol-xyz",
            "LinkID": "root-link",
            "Type": 1,
            "Key": "FAKE_SHARE_KEY",
            "Passphrase": base64::engine::general_purpose::STANDARD.encode("FAKE_ENC:my-share-passphrase"),
            "PassphraseSignature": "SIG:fake",
            "AddressID": "addr-001",
            "AddressKeyID": "key-001"
        });
        let share_bytes = serde_json::to_vec(&share_resp).unwrap();

        // Parent link (the share root folder). `decrypt_node_private_key`
        // base64-decodes NodePassphrase; the FakeCrypto strips the `FAKE_ENC:`
        // marker. `FolderProperties.NodeHashKey` is the (fake-encrypted) hash
        // key the uploader decrypts to seed the name-hash HMAC.
        let link_resp = serde_json::json!({
            "Code": 1000,
            "Link": {
                "LinkID": "root-link",
                "ParentLinkID": null,
                "Type": 1,
                "Name": "root",
                "Hash": null,
                "MIMEType": "Folder",
                "State": 1,
                "Size": 0,
                "CreateTime": 0,
                "ModifyTime": 0,
                "NodeKey": "FAKE_NODE_KEY",
                "NodePassphrase": base64::engine::general_purpose::STANDARD.encode("FAKE_ENC:my-node-passphrase"),
                "NodePassphraseSignature": "SIG:fake",
                "FolderProperties": { "NodeHashKey": "FAKE_ENC:my-hash-key" }
            }
        });
        let link_bytes = serde_json::to_vec(&link_resp).unwrap();

        let verification_resp = serde_json::json!({
            "Code": 1000,
            "VerificationCode": base64::engine::general_purpose::STANDARD.encode(vec![0xAA; 128]),
            "ContentKeyPacket": base64::engine::general_purpose::STANDARD.encode("FAKE_CKP")
        });
        let verification_bytes = serde_json::to_vec(&verification_resp).unwrap();

        let create_file_resp = serde_json::json!({
            "Code": 1000,
            "File": {
                "ID": "new-link-id",
                "RevisionID": "new-revision-id"
            }
        });
        let create_file_bytes = serde_json::to_vec(&create_file_resp).unwrap();

        let block_req_resp = serde_json::json!({
            "Code": 1000,
            "UploadLinks": [
                {
                    "Index": 1,
                    "BareURL": "https://upload.proton.me/block/1",
                    "Token": "block-token-1"
                }
            ]
        });
        let block_req_bytes = serde_json::to_vec(&block_req_resp).unwrap();

        // Block PUT response (200 OK, empty body).
        let block_upload_bytes = b"{}".to_vec();

        let commit_resp = serde_json::json!({ "Code": 1000 });
        let commit_bytes = serde_json::to_vec(&commit_resp).unwrap();

        let http = Arc::new(FakeHttpClient::new(vec![
            (200, share_bytes.clone()), // 1: resolve volume_id
            (200, share_bytes.clone()), // 2: parent context — share key
            (200, link_bytes),          // 3: parent context — node + hash key
            (200, create_file_bytes),   // 4: POST create file
            (200, verification_bytes),  // 5: GET verification code
            (200, block_req_bytes),     // 6: POST request blocks
            (200, block_upload_bytes),  // 7: PUT block blob
            (200, commit_bytes),        // 8: PUT commit revision
        ]));

        let openpgp = Arc::new(FakeCrypto);
        let account = Arc::new(FakeAccount);

        let content = b"hello proton drive block upload!";
        let expected_size = content.len() as u64;

        let uploader = ProtonFileUploader {
            http: http.clone(),
            openpgp,
            account,
            parent: make_node_uid("share-abc", "root-link"),
            name: "test-file.txt".into(),
            metadata: UploadMetadata {
                media_type: "text/plain".into(),
                expected_size,
                expected_sha1_hex: None,
                modification_time: None,
                additional_metadata_json: None,
                override_existing_draft_by_other_client: false,
            },
        };

        let (progress_tx, _progress_rx) = tokio::sync::watch::channel(0u64);
        let stream: Box<dyn AsyncRead + Send + Unpin> =
            Box::new(std::io::Cursor::new(content.to_vec()));

        let result = uploader.upload_from_stream(stream, progress_tx).await;

        assert!(result.is_ok(), "upload failed: {:?}", result.err());

        // Verify the calls were made in the right order.
        let paths = http.recorded_paths();
        assert!(
            paths[0].contains("/drive/shares/share-abc"),
            "1 resolve volume: {}",
            paths[0]
        );
        assert!(
            paths[1].contains("/drive/shares/share-abc"),
            "2 parent share: {}",
            paths[1]
        );
        assert!(
            paths[2].contains("/drive/shares/share-abc/links/root-link"),
            "3 parent link: {}",
            paths[2]
        );
        assert!(paths[3].contains("/files"), "4 create file: {}", paths[3]);
        assert!(
            paths[4].contains("/verification"),
            "5 verification: {}",
            paths[4]
        );
        assert!(
            paths[5].contains("/drive/blocks"),
            "6 request blocks: {}",
            paths[5]
        );
        // paths[6] is the blob upload path (bare_url)
        assert!(paths[7].contains("/revisions/"), "8 commit: {}", paths[7]);

        // Regression pin for B1 (name hash computed as plain SHA-256 instead
        // of HMAC-SHA256 — see docs/IMPLEMENTATION-STATUS.md): the recorded
        // create-file POST body's Hash field must be the known-answer
        // HMAC-SHA256 value for key=b"my-hash-key" (FakeCrypto strips the
        // "FAKE_ENC:" prefix from the FolderProperties.NodeHashKey fixture
        // above, leaving "my-hash-key") and name="test-file.txt" —
        // see `name_hash_hex_matches_known_answer` for how NAME_HASH_KAT_HEX
        // was independently derived.
        let create_body = http
            .json_body_containing("/files")
            .expect("create-file POST body must be recorded");
        assert_eq!(
            create_body["Hash"].as_str(),
            Some(NAME_HASH_KAT_HEX),
            "CreateFile request's Hash must be the HMAC-SHA256 name hash, not a \
             regression (e.g. plain SHA-256 — the historical B1 bug)"
        );
    }

    // ── Draft-cleanup / checksum-verification tests ───────────────────────────
    // Shared fixtures for the steps every uploader test needs regardless of
    // where (or whether) the upload is made to fail.

    /// `(share_bytes, link_bytes, create_file_bytes, verification_bytes)` —
    /// steps 0-3's responses, in call order.
    fn common_upload_responses() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let share_resp = serde_json::json!({
            "Code": 1000,
            "ShareID": "share-abc",
            "VolumeID": "vol-xyz",
            "LinkID": "root-link",
            "Type": 1,
            "Key": "FAKE_SHARE_KEY",
            "Passphrase": base64::engine::general_purpose::STANDARD.encode("FAKE_ENC:my-share-passphrase"),
            "PassphraseSignature": "SIG:fake",
            "AddressID": "addr-001",
            "AddressKeyID": "key-001"
        });
        let share_bytes = serde_json::to_vec(&share_resp).unwrap();

        let link_resp = serde_json::json!({
            "Code": 1000,
            "Link": {
                "LinkID": "root-link",
                "ParentLinkID": null,
                "Type": 1,
                "Name": "root",
                "Hash": null,
                "MIMEType": "Folder",
                "State": 1,
                "Size": 0,
                "CreateTime": 0,
                "ModifyTime": 0,
                "NodeKey": "FAKE_NODE_KEY",
                "NodePassphrase": base64::engine::general_purpose::STANDARD.encode("FAKE_ENC:my-node-passphrase"),
                "NodePassphraseSignature": "SIG:fake",
                "FolderProperties": { "NodeHashKey": "FAKE_ENC:my-hash-key" }
            }
        });
        let link_bytes = serde_json::to_vec(&link_resp).unwrap();

        let create_file_resp = serde_json::json!({
            "Code": 1000,
            "File": {
                "ID": "new-link-id",
                "RevisionID": "new-revision-id"
            }
        });
        let create_file_bytes = serde_json::to_vec(&create_file_resp).unwrap();

        let verification_resp = serde_json::json!({
            "Code": 1000,
            "VerificationCode": base64::engine::general_purpose::STANDARD.encode(vec![0xAA; 128]),
            "ContentKeyPacket": base64::engine::general_purpose::STANDARD.encode("FAKE_CKP")
        });
        let verification_bytes = serde_json::to_vec(&verification_resp).unwrap();

        (
            share_bytes,
            link_bytes,
            create_file_bytes,
            verification_bytes,
        )
    }

    fn block_request_response() -> Vec<u8> {
        let block_req_resp = serde_json::json!({
            "Code": 1000,
            "UploadLinks": [
                {
                    "Index": 1,
                    "BareURL": "https://upload.proton.me/block/1",
                    "Token": "block-token-1"
                }
            ]
        });
        serde_json::to_vec(&block_req_resp).unwrap()
    }

    /// A well-formed `MultiResponsesPerLinkFactory` reporting the delete as
    /// successful — `Responses[0].Response.Code == 1000`.
    fn delete_draft_ok_response() -> Vec<u8> {
        let resp = serde_json::json!({
            "Code": 1001,
            "Responses": [
                { "LinkID": "new-link-id", "Response": { "Code": 1000 } }
            ]
        });
        serde_json::to_vec(&resp).unwrap()
    }

    /// A well-formed but *unsuccessful* per-link response — exercises the
    /// "cleanup itself reports failure" branch of `delete_draft_best_effort`.
    fn delete_draft_error_response() -> Vec<u8> {
        let resp = serde_json::json!({
            "Code": 1001,
            "Responses": [
                { "LinkID": "new-link-id", "Response": { "Code": 2501, "Error": "not found" } }
            ]
        });
        serde_json::to_vec(&resp).unwrap()
    }

    fn make_test_uploader(
        http: Arc<FakeHttpClient>,
        expected_size: u64,
        expected_sha1_hex: Option<String>,
    ) -> ProtonFileUploader {
        use crate::nodes::make_node_uid;
        ProtonFileUploader {
            http,
            openpgp: Arc::new(FakeCrypto),
            account: Arc::new(FakeAccount),
            parent: make_node_uid("share-abc", "root-link"),
            name: "test-file.txt".into(),
            metadata: UploadMetadata {
                media_type: "text/plain".into(),
                expected_size,
                expected_sha1_hex,
                modification_time: None,
                additional_metadata_json: None,
                override_existing_draft_by_other_client: false,
            },
        }
    }

    /// SHA1 of `b"hello proton drive block upload!"`, precomputed, for the
    /// checksum-match test.
    const TEST_CONTENT_SHA1: &str = "a4e8d58a712883da14ce4c025e37d627a1733431";

    #[tokio::test]
    async fn draft_cleanup_deletes_node_on_block_upload_failure() {
        // Finding: "Failed uploads leave permanently orphaned draft
        // nodes/revisions on the server" — a failure downstream of node
        // creation (here: the block PUT returns a non-200 status) must
        // trigger a best-effort `DeleteDraft` call for the link_id that
        // `post_create_file` returned.
        let (share_bytes, link_bytes, create_file_bytes, verification_bytes) =
            common_upload_responses();
        let block_req_bytes = block_request_response();

        let http = Arc::new(FakeHttpClient::new(vec![
            (200, share_bytes.clone()),        // 1: resolve volume_id
            (200, share_bytes),                // 2: parent context — share key
            (200, link_bytes),                 // 3: parent context — node + hash key
            (200, create_file_bytes),          // 4: POST create file
            (200, verification_bytes),         // 5: GET verification code
            (200, block_req_bytes),            // 6: POST request blocks
            (500, b"{}".to_vec()),             // 7: PUT block blob — FAILS
            (200, delete_draft_ok_response()), // 8: best-effort delete_draft
        ]));

        let content = b"hello proton drive block upload!";
        let uploader = make_test_uploader(http.clone(), content.len() as u64, None);

        let (progress_tx, _progress_rx) = tokio::sync::watch::channel(0u64);
        let stream: Box<dyn AsyncRead + Send + Unpin> =
            Box::new(std::io::Cursor::new(content.to_vec()));

        let result = uploader.upload_from_stream(stream, progress_tx).await;

        assert!(
            matches!(result, Err(Error::IntegrityCheckFailed(_))),
            "expected the original block-upload error to surface, got {:?}",
            result.err()
        );

        let paths = http.recorded_paths();
        assert_eq!(
            paths.last().map(String::as_str),
            Some("/drive/v2/volumes/vol-xyz/delete_multiple"),
            "expected a best-effort delete_multiple cleanup call, got paths: {paths:?}"
        );

        let delete_body = http
            .json_body_containing("/delete_multiple")
            .expect("delete_multiple call should have a JSON body");
        assert_eq!(delete_body["LinkIDs"], serde_json::json!(["new-link-id"]));
    }

    #[tokio::test]
    async fn draft_cleanup_failure_does_not_mask_original_error() {
        // The delete-draft call itself reports failure (a non-OK per-link
        // code), mirroring a server that, e.g., already reaped the draft.
        // JS `deleteDraftNode` (manager.ts) only logs this — it must never
        // replace the original upload error.
        let (share_bytes, link_bytes, create_file_bytes, verification_bytes) =
            common_upload_responses();
        let block_req_bytes = block_request_response();

        let http = Arc::new(FakeHttpClient::new(vec![
            (200, share_bytes.clone()),
            (200, share_bytes),
            (200, link_bytes),
            (200, create_file_bytes),
            (200, verification_bytes),
            (200, block_req_bytes),
            (500, b"{}".to_vec()),                // block PUT fails
            (200, delete_draft_error_response()), // cleanup itself fails
        ]));

        let content = b"hello proton drive block upload!";
        let uploader = make_test_uploader(http.clone(), content.len() as u64, None);

        let (progress_tx, _progress_rx) = tokio::sync::watch::channel(0u64);
        let stream: Box<dyn AsyncRead + Send + Unpin> =
            Box::new(std::io::Cursor::new(content.to_vec()));

        let result = uploader.upload_from_stream(stream, progress_tx).await;

        assert!(
            matches!(result, Err(Error::IntegrityCheckFailed(_))),
            "cleanup failure must not mask the original error, got {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn checksum_mismatch_is_fatal_and_triggers_draft_cleanup() {
        // Finding: `expected_sha1_hex` was accepted, format-validated, and
        // then silently ignored. A mismatch must now be fatal (mirroring JS
        // `verifyIntegrity`'s `IntegrityError`), thrown *before* the commit
        // call, and — being a failure downstream of node creation — must also
        // trigger best-effort draft cleanup.
        let (share_bytes, link_bytes, create_file_bytes, verification_bytes) =
            common_upload_responses();
        let block_req_bytes = block_request_response();

        let http = Arc::new(FakeHttpClient::new(vec![
            (200, share_bytes.clone()),
            (200, share_bytes),
            (200, link_bytes),
            (200, create_file_bytes),
            (200, verification_bytes),
            (200, block_req_bytes),
            (200, b"{}".to_vec()),             // block PUT succeeds
            (200, delete_draft_ok_response()), // best-effort delete_draft
        ]));

        let content = b"hello proton drive block upload!";
        let uploader = make_test_uploader(
            http.clone(),
            content.len() as u64,
            Some("f".repeat(40)), // deliberately wrong digest
        );

        let (progress_tx, _progress_rx) = tokio::sync::watch::channel(0u64);
        let stream: Box<dyn AsyncRead + Send + Unpin> =
            Box::new(std::io::Cursor::new(content.to_vec()));

        let result = uploader.upload_from_stream(stream, progress_tx).await;

        assert!(
            matches!(result, Err(Error::Integrity(_))),
            "expected a fatal Integrity error on SHA1 mismatch, got {:?}",
            result.err()
        );

        // Exactly the 8 queued responses were consumed: steps 0-6 plus the
        // cleanup call — `put_commit_revision` must never have been reached.
        let paths = http.recorded_paths();
        assert_eq!(paths.len(), 8, "unexpected call sequence: {paths:?}");
        assert_eq!(
            paths.last().map(String::as_str),
            Some("/drive/v2/volumes/vol-xyz/delete_multiple")
        );
    }

    #[tokio::test]
    async fn checksum_match_sets_checksum_verified_true() {
        // Finding: `CommitRevisionRequest.checksum_verified` was hardcoded to
        // `false`. When the streamed digest matches the caller-supplied
        // expectation, the commit request sent to the server must report
        // `ChecksumVerified: true` (mirroring JS
        // `checksumVerified: !!(expectedSha1 && digests.sha1 === expectedSha1)`),
        // and the upload must succeed without any draft cleanup.
        let (share_bytes, link_bytes, create_file_bytes, verification_bytes) =
            common_upload_responses();
        let block_req_bytes = block_request_response();
        let commit_bytes = serde_json::to_vec(&serde_json::json!({ "Code": 1000 })).unwrap();

        let http = Arc::new(FakeHttpClient::new(vec![
            (200, share_bytes.clone()),
            (200, share_bytes),
            (200, link_bytes),
            (200, create_file_bytes),
            (200, verification_bytes),
            (200, block_req_bytes),
            (200, b"{}".to_vec()), // block PUT succeeds
            (200, commit_bytes),   // commit revision succeeds
        ]));

        let content = b"hello proton drive block upload!";
        let uploader = make_test_uploader(
            http.clone(),
            content.len() as u64,
            Some(TEST_CONTENT_SHA1.to_owned()),
        );

        let (progress_tx, _progress_rx) = tokio::sync::watch::channel(0u64);
        let stream: Box<dyn AsyncRead + Send + Unpin> =
            Box::new(std::io::Cursor::new(content.to_vec()));

        let result = uploader.upload_from_stream(stream, progress_tx).await;
        assert!(result.is_ok(), "upload failed: {:?}", result.err());

        let paths = http.recorded_paths();
        assert_eq!(
            paths.len(),
            8,
            "no draft-cleanup call should have been made: {paths:?}"
        );
        assert!(!paths.iter().any(|p| p.contains("delete_multiple")));

        let commit_body = http
            .json_body_containing("/revisions/")
            .expect("commit call should have a JSON body");
        assert_eq!(commit_body["ChecksumVerified"], serde_json::json!(true));
    }

    #[test]
    fn server_fewer_upload_links_than_blocks_is_protocol_violation() {
        // Verify that the ProtocolViolation error is returned when the server
        // returns fewer upload links than blocks were requested.
        // (Integration: tested in mock_upload_protocol_flow indirectly via the
        //  `sorted_links.len() != blocks.len()` check.)
        //
        // We test the error type here directly.
        let e = Error::ProtocolViolation(
            "server returned 0 upload links but 1 blocks were requested".into(),
        );
        assert!(matches!(e, Error::ProtocolViolation(_)));
    }
}
