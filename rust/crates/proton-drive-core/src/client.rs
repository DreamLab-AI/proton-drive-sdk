//! Root client. Mirrors `js/sdk/src/protonDriveClient.ts` shape.

use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::{self, BoxStream, StreamExt as _};
use serde::de::DeserializeOwned;

use crate::account::ProtonDriveAccount;
use crate::config::ProtonDriveConfig;
use crate::download::{
    FileDownloader, decrypt_node_name, decrypt_node_private_key, decrypt_share_key,
    resolve_volume_id,
};
use crate::error::{Error, Result};
use crate::events::{
    DriveListener, EventSubscription, InMemoryLatestEventId, LatestEventIdProvider,
    spawn_volume_event_loop,
};
use crate::http::{HttpMethod, JsonRequest, ProtonDriveHttpClient};
use crate::nodes::{
    CachedCryptoMaterial, FolderChildrenFilter, MaybeNode, NodeUid, link_to_maybe_node,
    map_api_error,
};
use crate::upload::{FileUploader, ProtonFileUploader, UploadMetadata};
use proton_drive_api::common::{CODE_OK, ResponseEnvelope};
use proton_drive_cache::ProtonDriveCache;
use proton_drive_crypto::{OpenPgpCrypto, PrivateKey, PublicKey, SrpModule, VerificationStatus};
use proton_drive_telemetry::Telemetry;

/// All host-supplied dependencies for the SDK.
/// Mirrors JS `ProtonDriveClientContructorParameters`.
pub struct ProtonDriveClientOptions {
    pub http_client: Arc<dyn ProtonDriveHttpClient>,
    pub entities_cache: Arc<dyn ProtonDriveCache<String>>,
    pub crypto_cache: Arc<dyn ProtonDriveCache<CachedCryptoMaterial>>,
    pub account: Arc<dyn ProtonDriveAccount>,
    pub openpgp: Arc<dyn OpenPgpCrypto>,
    pub srp: Arc<dyn SrpModule>,
    pub config: ProtonDriveConfig,
    pub telemetry: Option<Arc<dyn Telemetry>>,
    pub latest_event_id: Option<Arc<dyn LatestEventIdProvider>>,
}

/// Root entry point.
pub struct ProtonDriveClient {
    opts: ProtonDriveClientOptions,
}

impl ProtonDriveClient {
    pub fn new(opts: ProtonDriveClientOptions) -> Self {
        Self { opts }
    }

    pub fn config(&self) -> &ProtonDriveConfig {
        &self.opts.config
    }

    pub fn account(&self) -> &Arc<dyn ProtonDriveAccount> {
        &self.opts.account
    }

    // ----- HTTP helpers -----------------------------------------------------

    async fn api_get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let req = JsonRequest {
            method: HttpMethod::Get,
            path: path.to_owned(),
            query: vec![],
            headers: vec![],
            body: None,
        };
        let resp = self.opts.http_client.request_json(req).await?;
        let env: ResponseEnvelope<T> = serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Internal(format!("JSON parse: {e}")))?;
        if env.code != CODE_OK {
            return Err(map_api_error(env.code, env.error));
        }
        Ok(env.inner)
    }

    async fn api_get_with_query<T: DeserializeOwned>(
        &self,
        path: &str,
        query: Vec<(String, String)>,
    ) -> Result<T> {
        let req = JsonRequest {
            method: HttpMethod::Get,
            path: path.to_owned(),
            query,
            headers: vec![],
            body: None,
        };
        let resp = self.opts.http_client.request_json(req).await?;
        let env: ResponseEnvelope<T> = serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Internal(format!("JSON parse: {e}")))?;
        if env.code != CODE_OK {
            return Err(map_api_error(env.code, env.error));
        }
        Ok(env.inner)
    }

    // ----- Nodes ------------------------------------------------------------

    /// Fetch the user's My Files root node.
    ///
    /// Uses `GET drive/v2/shares/my-files` which returns the volume, share,
    /// and root link in a single round-trip. The root node name is decrypted
    /// as the literal string "root" (the share is bootstrapped with that name
    /// per the JS SDK's `generateVolumeBootstrap`). Full crypto verification
    /// of the node passphrase/name is a TODO MC-followup.
    pub async fn my_files_root(&self) -> Result<MaybeNode> {
        let resp: proton_drive_api::shares::GetMyFilesResponse =
            self.api_get("/drive/v2/shares/my-files").await?;

        // NodeUid.volume_id carries the *share id* for the legacy list/link
        // endpoints (see the FIXME on `file_uploader`); the real VolumeID is
        // resolved lazily during upload. Seeding it from `volume.volume_id`
        // breaks `/drive/shares/{shareID}/...` path construction.
        let share_id = resp.share.share_id;
        let link = resp.link.into_link();

        // Root node name is always "root" per Proton's volume bootstrap.
        // TODO MC-followup: verify by decrypting link.name with share key.
        Ok(link_to_maybe_node(link, &share_id, Some("root".to_owned())))
    }

    /// Fetch a single node by its uid.
    ///
    /// Uses `GET drive/shares/{shareID}/links/{linkID}`.
    /// Name decryption is deferred (placeholder name with link ID).
    ///
    /// # TODO MC-followup: full name decryption requires AddressProvider integration
    pub async fn node(&self, uid: &NodeUid) -> Result<MaybeNode> {
        let path = format!("/drive/shares/{}/links/{}", uid.volume_id, uid.node_id);
        let resp: proton_drive_api::nodes::GetLinkResponse = self.api_get(&path).await?;
        Ok(link_to_maybe_node(resp.link, &uid.volume_id, None))
    }

    /// Iterate all children of a folder.
    ///
    /// Uses `GET drive/shares/{shareID}/folders/{linkID}/children` with
    /// page-based pagination (Page=0..N, PageSize=page_size). Iterates until
    /// `More == 0`. Returns a `Vec` rather than a stream; for MVP a single
    /// collected result is sufficient. Streams would be preferable for large
    /// folders — see TODO below.
    ///
    /// # TODO MC-followup: convert to async stream for large folder support
    ///
    /// Name decryption is deferred (placeholder names with link IDs).
    pub async fn fetch_folder_children(
        &self,
        parent: &NodeUid,
        page_size: u32,
    ) -> Result<Vec<MaybeNode>> {
        // Resolve the parent folder's private key once so child names can be
        // decrypted (each child `Name` is encrypted to the parent node key).
        // If resolution fails (e.g. nested folders beyond MVP support), fall
        // back to placeholder names rather than failing the whole listing.
        let parent_key = self.resolve_folder_node_key(parent).await.ok();

        let mut results = Vec::new();
        let mut page: u32 = 0;

        loop {
            let path = format!(
                "/drive/shares/{}/folders/{}/children",
                parent.volume_id, parent.node_id
            );
            let query = vec![
                ("Page".to_owned(), page.to_string()),
                ("PageSize".to_owned(), page_size.to_string()),
            ];
            let resp: proton_drive_api::nodes::GetChildrenResponse =
                self.api_get_with_query(&path, query).await?;

            let more = resp.more;
            for link in resp.links {
                let name = match &parent_key {
                    Some(key) => decrypt_node_name(&self.opts.openpgp, &link.name, key)
                        .await
                        .ok(),
                    None => None,
                };
                results.push(link_to_maybe_node(link, &parent.volume_id, name));
            }

            if more == 0 {
                break;
            }
            page += 1;
        }

        Ok(results)
    }

    /// Resolve the private key of a folder node, used to decrypt its children's
    /// names. The chain is: address key → share key → root node key → … →
    /// target node key. Each node's passphrase is encrypted to its *parent*
    /// node's key; the share root's passphrase is encrypted to the share key.
    /// Works for the share root and arbitrarily nested folders.
    async fn resolve_folder_node_key(&self, parent: &NodeUid) -> Result<PrivateKey> {
        let share_id = &parent.volume_id;
        let share_priv = self.resolve_share_key(share_id).await?;
        self.resolve_node_key_via_chain(share_id, &parent.node_id, &share_priv)
            .await
    }

    /// Decrypt the share private key for `share_id` via the user's address key.
    ///
    /// Non-fatally verifies the share's `PassphraseSignature` against the
    /// creator address's public keys (JS `SharesCryptoService.decryptRootShare`
    /// -> `account.getPublicKeys(share.creatorEmail)`); an unresolvable or
    /// unverifiable signature is only logged, never aborts share-key
    /// derivation.
    async fn resolve_share_key(&self, share_id: &str) -> Result<PrivateKey> {
        let share_resp: proton_drive_api::shares::GetShareResponse =
            self.api_get(&format!("/drive/shares/{share_id}")).await?;
        let share = share_resp.share;

        let address_email = self.opts.account.primary_email();
        let address_key = self.opts.account.address_private_key(address_email).await?;

        let verification_keys = match &share.creator_email {
            Some(email) => match self.opts.account.address_public_keys(email).await {
                Ok(keys) => keys,
                Err(e) => {
                    tracing::warn!(
                        email = %email,
                        "could not resolve share creator public keys for \
                         PassphraseSignature verification: {e}"
                    );
                    Vec::new()
                }
            },
            None => Vec::new(),
        };

        let (share_priv, verified) = decrypt_share_key(
            &self.opts.openpgp,
            &share.key,
            &share.passphrase,
            &share.passphrase_signature,
            &address_key,
            &verification_keys,
        )
        .await?;

        if verified != VerificationStatus::Ok {
            tracing::warn!(
                share_id = %share_id,
                status = ?verified,
                "share PassphraseSignature present but unverifiable (non-fatal, \
                 JS-faithful) — key still unlocked"
            );
        }

        Ok(share_priv)
    }

    /// Resolve a node's private key by walking the parent chain to the share
    /// root and folding key derivation top-down.
    ///
    /// A node's `NodePassphrase` is encrypted to its **parent node's** key
    /// (JS `getParentKeys`); only the share root's passphrase is encrypted to
    /// the share key directly. To unlock an arbitrarily nested node we collect
    /// the ancestor links bottom-up (target → … → root) by following
    /// `ParentLinkID`, then derive keys top-down starting from `share_priv`.
    ///
    /// `MAX_CHAIN_DEPTH` guards against a malformed/cyclic parent chain.
    ///
    /// Each node's `NodePassphraseSignature` is verified non-fatally against
    /// the resolved verification keys — the signer address's public keys
    /// when the node carries a `SignatureEmail`, else the parent key's own
    /// public portion (JS `decryptNode`'s `keyVerificationKeys` /
    /// `nodeParentKeys` fallback). An unresolvable/invalid signature is only
    /// logged; it never aborts key derivation (JS-faithful, non-fatal
    /// `keyAuthor`).
    async fn resolve_node_key_via_chain(
        &self,
        share_id: &str,
        link_id: &str,
        share_priv: &PrivateKey,
    ) -> Result<PrivateKey> {
        const MAX_CHAIN_DEPTH: usize = 64;

        struct ChainLink {
            node_key: String,
            node_passphrase: String,
            node_passphrase_signature: String,
            signature_email: Option<String>,
        }

        // Collect the chain from the target up to the root.
        let mut chain: Vec<ChainLink> = Vec::new();
        let mut current_id = link_id.to_owned();

        loop {
            if chain.len() >= MAX_CHAIN_DEPTH {
                return Err(Error::Internal(format!(
                    "node key chain exceeded depth {MAX_CHAIN_DEPTH} (cyclic parent links?)"
                )));
            }

            let path = format!("/drive/shares/{share_id}/links/{current_id}");
            let resp: proton_drive_api::nodes::GetLinkResponse = self.api_get(&path).await?;
            let link = resp.link;
            let parent = link.parent_link_id.clone();
            chain.push(ChainLink {
                node_key: link.node_key,
                node_passphrase: link.node_passphrase,
                node_passphrase_signature: link.node_passphrase_signature,
                signature_email: link.signature_email,
            });

            match parent {
                Some(p) => current_id = p,
                None => break,
            }
        }

        // Fold from the root down: the deepest ancestor (last pushed) unlocks
        // with the share key, each descendant with its parent's node key.
        let mut current: Option<PrivateKey> = None;
        for entry in chain.iter().rev() {
            let parent_ref: &PrivateKey = current.as_ref().unwrap_or(share_priv);

            let verification_keys: Vec<PublicKey> = match &entry.signature_email {
                Some(email) => match self.opts.account.address_public_keys(email).await {
                    Ok(keys) => keys,
                    Err(e) => {
                        tracing::warn!(
                            email = %email,
                            "could not resolve node signature address public keys: {e}"
                        );
                        Vec::new()
                    }
                },
                None => match self.opts.openpgp.public_key(parent_ref).await {
                    Ok(pk) => vec![pk],
                    Err(_) => Vec::new(),
                },
            };

            let (next, verified) = decrypt_node_private_key(
                &self.opts.openpgp,
                &entry.node_key,
                &entry.node_passphrase,
                &entry.node_passphrase_signature,
                parent_ref,
                &verification_keys,
            )
            .await?;

            if verified != VerificationStatus::Ok {
                tracing::warn!(
                    signature_email = ?entry.signature_email,
                    status = ?verified,
                    "node NodePassphraseSignature present but unverifiable \
                     (non-fatal, JS-faithful) — key still unlocked"
                );
            }

            current = Some(next);
        }

        current.ok_or_else(|| Error::Internal("empty node key chain".into()))
    }

    /// Stream children of a folder as a `BoxStream`.
    ///
    /// For MVP this collects all pages up front then yields from the Vec.
    /// Full streaming pagination is a post-MVP concern (see TODO MC-followup).
    pub fn iter_folder_children<'a>(
        &'a self,
        parent: &NodeUid,
        _filter: FolderChildrenFilter,
    ) -> BoxStream<'a, Result<MaybeNode>> {
        let parent = parent.clone();
        // Collect all children eagerly, then stream from the resulting Vec.
        // Using a constant page size of 150 (Proton's typical max per page).
        Box::pin(
            stream::once(async move { self.fetch_folder_children(&parent, 150).await }).flat_map(
                |result| {
                    let items: Vec<Result<MaybeNode>> = match result {
                        Ok(nodes) => nodes.into_iter().map(Ok).collect(),
                        Err(e) => vec![Err(e)],
                    };
                    stream::iter(items)
                },
            ),
        )
    }

    pub async fn available_name(&self, _parent: &NodeUid, name: &str) -> Result<String> {
        // Until full listing is in place, echo — call sites should not rely on conflict-safety.
        Ok(name.to_owned())
    }

    // ----- Transfer ---------------------------------------------------------

    /// Construct a `FileUploader` for uploading a file to `parent`.
    ///
    /// Validates metadata then returns a `ProtonFileUploader` ready to stream
    /// data. Call `upload_from_stream` on the returned uploader to execute the
    /// 5-step block-upload protocol (ADR-0008).
    ///
    /// # FIXME: NodeUid naming — see MC commit f6b29b1 note
    /// `parent.volume_id` holds the share_id from listing endpoints;
    /// the real VolumeID is resolved lazily inside `run_upload`.
    pub async fn file_uploader(
        &self,
        parent: &NodeUid,
        name: &str,
        meta: UploadMetadata,
    ) -> Result<Box<dyn FileUploader>> {
        meta.validate()?;
        Ok(Box::new(ProtonFileUploader {
            http: self.opts.http_client.clone(),
            openpgp: self.opts.openpgp.clone(),
            account: self.opts.account.clone(),
            parent: parent.clone(),
            name: name.to_owned(),
            metadata: meta,
        }))
    }

    /// Construct a `FileDownloader` for the given node.
    ///
    /// # Protocol steps (ADR-0009)
    /// 1. Re-fetch the link to get the active revision ID and the node's key material.
    /// 2. Resolve the true volume ID via `GET drive/shares/{shareID}`.
    ///    `NodeUid.volume_id` from MC's listing holds a **share ID**, not the volume ID.
    ///    FIXME: NodeUid naming — see MC commit f6b29b1
    /// 3. Decrypt the share key (address_key → share passphrase → share private key).
    /// 4. Decrypt the node private key by walking the parent chain to the share
    ///    root (each node's passphrase is encrypted to its parent node's key).
    ///    Supports root-level and arbitrarily nested files.
    /// 5. Build `FileDownloader` with resolved context.
    pub async fn file_downloader(&self, uid: &NodeUid) -> Result<FileDownloader> {
        // Step 1: re-fetch the link for active revision + key material.
        // uid.volume_id is actually the share_id from MC's listing.
        // FIXME: NodeUid naming — see MC commit f6b29b1
        let share_id = &uid.volume_id;
        let link_id = &uid.node_id;

        let link_path = format!("/drive/shares/{share_id}/links/{link_id}");
        let link_resp: proton_drive_api::nodes::GetLinkResponse = self.api_get(&link_path).await?;
        let link = link_resp.link;

        // Verify this is a file node.
        if link.r#type != 2 {
            return Err(Error::Validation(
                "file_downloader: node is not a file (type != 2)".into(),
            ));
        }

        let file_props = link
            .file_properties
            .as_ref()
            .ok_or_else(|| Error::Internal("file link missing FileProperties".into()))?;

        let revision_id = file_props
            .active_revision
            .as_ref()
            .map(|r| r.id.clone())
            .ok_or_else(|| Error::NotFound("file has no active revision".into()))?;

        let signature_email = file_props
            .active_revision
            .as_ref()
            .and_then(|r| r.signature_email.clone());

        // Step 2: resolve volume_id from share.
        let volume_id = resolve_volume_id(&self.opts.http_client, share_id).await?;

        // Step 3: decrypt the share key (address key → share passphrase).
        let share_priv = self.resolve_share_key(share_id).await?;

        // Step 4: decrypt the file's node key. A node's `NodePassphrase` is
        // encrypted to its *parent node* key (JS `getParentKeys`), so we walk
        // the parent chain to the share root and fold key derivation top-down.
        // Works for root-level and arbitrarily nested files.
        let node_priv = self
            .resolve_node_key_via_chain(share_id, link_id, &share_priv)
            .await?;

        // Step 5: resolve the signer's verification keys. The address keeps
        // rotated-out keys alongside the current one, and a revision can be
        // signed by any of them, so fetch the full public-key set (JS
        // `getRevisionVerificationKeys` → `account.getPublicKeys`). Empty when
        // there is no signer address — verify_manifest then falls back to the
        // node's own public key.
        let signature_address_pubs = if let Some(ref email) = signature_email {
            match self.opts.account.address_public_keys(email).await {
                Ok(keys) => {
                    tracing::debug!(
                        signer = %email,
                        key_count = keys.len(),
                        fingerprints = ?keys.iter().map(|k| &k.fingerprint_hex).collect::<Vec<_>>(),
                        "resolved manifest verification keys for signer"
                    );
                    keys
                }
                Err(e) => {
                    tracing::warn!(
                        email = %email,
                        "could not resolve signature address public keys: {e} — \
                         falling back to node-key verification"
                    );
                    Vec::new()
                }
            }
        } else {
            tracing::debug!("revision has no signer email — node-key verification fallback");
            Vec::new()
        };

        // ContentKeyPacket (+ its signature) is on the node (file link), not
        // the revision; `download_to_writer` falls back to the revision's own
        // field for legacy shapes.
        let content_key_packet = link
            .file_properties
            .as_ref()
            .and_then(|fp| fp.content_key_packet.clone());
        let content_key_packet_signature = link
            .file_properties
            .as_ref()
            .and_then(|fp| fp.content_key_packet_signature.clone());

        // ContentKeyPacketSignature verification keys: JS `decryptContentKeyPacket`
        // verifies against `[nodeKey, ...keyVerificationKeys]`, where
        // `keyVerificationKeys` comes from the node's own `SignatureEmail`
        // (`link.signature_email`) — which can differ from the revision's own
        // signer used for `signature_address_pubs` above. The node key itself
        // is added automatically in `download_to_writer`; only the resolved
        // address key set is carried here.
        let content_key_verification_pubs = match &link.signature_email {
            Some(email) => match self.opts.account.address_public_keys(email).await {
                Ok(keys) => keys,
                Err(e) => {
                    tracing::warn!(
                        email = %email,
                        "could not resolve node signature address public keys for \
                         ContentKeyPacket verification: {e}"
                    );
                    Vec::new()
                }
            },
            None => Vec::new(),
        };

        Ok(FileDownloader {
            http: self.opts.http_client.clone(),
            crypto: self.opts.openpgp.clone(),
            node_uid: uid.clone(),
            volume_id,
            share_id: share_id.clone(),
            revision_id,
            node_private_key: node_priv,
            signature_address_pubs,
            content_key_packet,
            content_key_packet_signature,
            content_key_verification_pubs,
        })
    }

    // ----- Events -----------------------------------------------------------

    /// Subscribe to the host's My Files volume events.
    ///
    /// Spawns an event-based polling loop (ADR-0001: sync is event-based, never
    /// recursive tree traversal). The loop drains
    /// `GET drive/v2/volumes/{volumeID}/events/{eventID}`, maps each raw event
    /// onto a [`DriveEvent`], dispatches to `listener`, and persists the resume
    /// cursor through the host's [`LatestEventIdProvider`] (or an in-memory
    /// default when none is wired).
    ///
    /// The volume is resolved the same way the listing/download paths resolve
    /// it: My Files share → `GET drive/shares/{shareID}` → real `VolumeID`.
    ///
    /// Dropping (or cancelling) the returned [`EventSubscription`] stops the
    /// loop at the next await point.
    pub async fn subscribe_drive_events(
        &self,
        listener: Box<dyn DriveListener>,
    ) -> Result<EventSubscription> {
        // Resolve the My Files share, then translate it to the true volume id
        // (NodeUid.volume_id from listing holds a *share id* — see FIXME on
        // `file_uploader`/`file_downloader`).
        let my_files: proton_drive_api::shares::GetMyFilesResponse =
            self.api_get("/drive/v2/shares/my-files").await?;
        let share_id = my_files.share.share_id;
        let volume_id = resolve_volume_id(&self.opts.http_client, &share_id).await?;

        // Host-supplied resume cursor, or an in-memory default that starts from
        // the server's latest event id on each fresh subscription.
        let provider: Arc<dyn LatestEventIdProvider> = match &self.opts.latest_event_id {
            Some(p) => Arc::clone(p),
            None => Arc::new(InMemoryLatestEventId::new()),
        };

        Ok(spawn_volume_event_loop(
            Arc::clone(&self.opts.http_client),
            volume_id,
            listener,
            provider,
        ))
    }
}

// Re-export so callers don't have to chase the trait import.
pub use async_trait::async_trait as _async_trait;

#[async_trait]
trait _AssertSendSync: Send + Sync {}
impl _AssertSendSync for ProtonDriveClient {}
