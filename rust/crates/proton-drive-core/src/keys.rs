//! Shared node-key resolution — the single source of truth for walking a
//! node's parent chain and folding key derivation top-down.
//!
//! Mirrors the JS SDK's `getParentKeys`/`decryptNode` chain
//! (`reference/client/js/src/internal/nodes/cryptoService.ts`): a node's
//! `NodePassphrase` is encrypted to its **parent node's** key, so to unlock an
//! arbitrarily nested node we collect the ancestor links bottom-up (target →
//! … → root) by following `ParentLinkID`, then derive keys top-down starting
//! from the share key.
//!
//! Both the read side (`client.rs`: `file_downloader`, `fetch_folder_children`)
//! and the write side (`upload.rs`: new-file, revision, and folder creation
//! parent-context resolution) call these functions, so nested-parent support is
//! identical everywhere — closing the B2 upload-half gap where upload used to
//! resolve only the share-root parent (see `docs/IMPLEMENTATION-STATUS.md`).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use proton_drive_api::common::{CODE_OK, ResponseEnvelope};
use proton_drive_api::nodes::Link;
use proton_drive_crypto::{OpenPgpCrypto, PrivateKey, PublicKey, VerificationStatus};

use crate::account::ProtonDriveAccount;
use crate::download::{decrypt_node_private_key, decrypt_share_key};
use crate::error::{Error, Result};
use crate::http::{HttpMethod, JsonRequest, ProtonDriveHttpClient};
use crate::nodes::map_api_error;

/// `MAX_CHAIN_DEPTH` guards against a malformed/cyclic parent chain.
const MAX_CHAIN_DEPTH: usize = 64;

/// A resolved upload parent: the parent node's private key (to encrypt a new
/// child's passphrase to) and the parent folder's decrypted `NodeHashKey`
/// bytes (the HMAC key for computing the child's name hash).
pub(crate) struct ParentContext {
    pub node_key: PrivateKey,
    pub hash_key: Vec<u8>,
}

/// Decrypt the share private key for `share_id` via the user's address key.
///
/// Non-fatally verifies the share's `PassphraseSignature` against the creator
/// address's public keys (JS `SharesCryptoService.decryptRootShare` →
/// `account.getPublicKeys(share.creatorEmail)`); an unresolvable or
/// unverifiable signature is only logged, never aborts share-key derivation.
pub(crate) async fn resolve_share_key(
    http: &Arc<dyn ProtonDriveHttpClient>,
    openpgp: &Arc<dyn OpenPgpCrypto>,
    account: &Arc<dyn ProtonDriveAccount>,
    share_id: &str,
) -> Result<PrivateKey> {
    let share_resp: proton_drive_api::shares::GetShareResponse =
        api_get(http, &format!("/drive/shares/{share_id}")).await?;
    let share = share_resp.share;

    let address_email = account.primary_email();
    let address_key = account.address_private_key(address_email).await?;

    let verification_keys = match &share.creator_email {
        Some(email) => match account.address_public_keys(email).await {
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
        openpgp,
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

/// Resolve a node's private key by walking the parent chain to the share root
/// and folding key derivation top-down.
///
/// See the module docs for the chain rationale. Each node's
/// `NodePassphraseSignature` is verified non-fatally against the signer
/// address's public keys (when the node carries a `SignatureEmail`) or the
/// parent key's own public portion (JS `decryptNode`'s `keyVerificationKeys` /
/// `nodeParentKeys` fallback); an unresolvable/invalid signature is only
/// logged, never aborts derivation.
pub(crate) async fn resolve_node_key_via_chain(
    http: &Arc<dyn ProtonDriveHttpClient>,
    openpgp: &Arc<dyn OpenPgpCrypto>,
    account: &Arc<dyn ProtonDriveAccount>,
    share_id: &str,
    link_id: &str,
    share_priv: &PrivateKey,
) -> Result<PrivateKey> {
    let (node_key, _link) =
        resolve_node_key_and_link(http, openpgp, account, share_id, link_id, share_priv).await?;
    Ok(node_key)
}

/// Like [`resolve_node_key_via_chain`], but also returns the **target** link's
/// wire DTO (the deepest node whose key we unlocked). The caller needs it to
/// read folder- or file-specific fields (e.g. a folder parent's `NodeHashKey`,
/// a file node's `ContentKeyPacket`/active revision) without a redundant fetch.
pub(crate) async fn resolve_node_key_and_link(
    http: &Arc<dyn ProtonDriveHttpClient>,
    openpgp: &Arc<dyn OpenPgpCrypto>,
    account: &Arc<dyn ProtonDriveAccount>,
    share_id: &str,
    link_id: &str,
    share_priv: &PrivateKey,
) -> Result<(PrivateKey, Link)> {
    // Collect the chain from the target up to the root (`chain[0]` is the
    // target itself, `chain.last()` the deepest ancestor).
    let mut chain: Vec<Link> = Vec::new();
    let mut current_id = link_id.to_owned();

    loop {
        if chain.len() >= MAX_CHAIN_DEPTH {
            return Err(Error::Internal(format!(
                "node key chain exceeded depth {MAX_CHAIN_DEPTH} (cyclic parent links?)"
            )));
        }

        let path = format!("/drive/shares/{share_id}/links/{current_id}");
        let resp: proton_drive_api::nodes::GetLinkResponse = api_get(http, &path).await?;
        let link = resp.link;
        let parent = link.parent_link_id.clone();
        chain.push(link);

        match parent {
            Some(p) => current_id = p,
            None => break,
        }
    }

    // Fold from the root down: the deepest ancestor (last pushed) unlocks with
    // the share key, each descendant with its parent's node key.
    let mut current: Option<PrivateKey> = None;
    for entry in chain.iter().rev() {
        let parent_ref: &PrivateKey = current.as_ref().unwrap_or(share_priv);

        let verification_keys: Vec<PublicKey> = match &entry.signature_email {
            Some(email) => match account.address_public_keys(email).await {
                Ok(keys) => keys,
                Err(e) => {
                    tracing::warn!(
                        email = %email,
                        "could not resolve node signature address public keys: {e}"
                    );
                    Vec::new()
                }
            },
            None => match openpgp.public_key(parent_ref).await {
                Ok(pk) => vec![pk],
                Err(_) => Vec::new(),
            },
        };

        let (next, verified) = decrypt_node_private_key(
            openpgp,
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

    let node_key = current.ok_or_else(|| Error::Internal("empty node key chain".into()))?;
    // The target is the first link we pushed; hand it back to the caller.
    let target_link = chain
        .into_iter()
        .next()
        .ok_or_else(|| Error::Internal("empty node key chain".into()))?;
    Ok((node_key, target_link))
}

/// A batch-scoped memo of resolved node private keys, keyed by link id.
///
/// Shared across the per-file resolutions of a single [`fetch_revision_xattrs`]
/// batch so a subtree of N files at depth D costs O(unique folders) link GETs +
/// key decrypts instead of O(N·D): each file's climb stops at the first ancestor
/// already unlocked by a sibling.
///
/// [`fetch_revision_xattrs`]: crate::ProtonDriveClient::fetch_revision_xattrs
pub(crate) type NodeKeyCache = Mutex<HashMap<String, PrivateKey>>;

/// Like [`resolve_node_key_via_chain`], but consults and populates a
/// batch-scoped [`NodeKeyCache`] so ancestor keys shared across a set of target
/// links are unlocked once, not once per target.
///
/// Semantically identical to the uncached walk (same fold order, same
/// non-fatal signature handling); the cache only elides redundant work. The
/// lock is taken solely for map get/insert and is never held across an `await`.
pub(crate) async fn resolve_node_key_via_chain_cached(
    http: &Arc<dyn ProtonDriveHttpClient>,
    openpgp: &Arc<dyn OpenPgpCrypto>,
    account: &Arc<dyn ProtonDriveAccount>,
    share_id: &str,
    link_id: &str,
    share_priv: &PrivateKey,
    cache: &NodeKeyCache,
) -> Result<PrivateKey> {
    // Climb target → root, but stop at the first link whose key a sibling has
    // already cached; seed the fold from that key rather than re-deriving it.
    let mut chain: Vec<(String, Link)> = Vec::new();
    let mut current_id = link_id.to_owned();
    let mut seed: Option<PrivateKey> = None;

    loop {
        if let Some(cached) = cache.lock().await.get(&current_id).cloned() {
            seed = Some(cached);
            break;
        }
        if chain.len() >= MAX_CHAIN_DEPTH {
            return Err(Error::Internal(format!(
                "node key chain exceeded depth {MAX_CHAIN_DEPTH} (cyclic parent links?)"
            )));
        }
        let path = format!("/drive/shares/{share_id}/links/{current_id}");
        let resp: proton_drive_api::nodes::GetLinkResponse = api_get(http, &path).await?;
        let link = resp.link;
        let parent = link.parent_link_id.clone();
        chain.push((current_id.clone(), link));
        match parent {
            Some(p) => current_id = p,
            None => break,
        }
    }

    // Fold from the deepest uncached ancestor down to the target, unlocking and
    // caching each. `parent_ref` is the cached seed (if the climb stopped early)
    // or the share key (if it reached the root).
    let mut current = seed;
    for (id, entry) in chain.iter().rev() {
        let parent_ref: &PrivateKey = current.as_ref().unwrap_or(share_priv);

        let verification_keys: Vec<PublicKey> = match &entry.signature_email {
            Some(email) => account.address_public_keys(email).await.unwrap_or_default(),
            None => match openpgp.public_key(parent_ref).await {
                Ok(pk) => vec![pk],
                Err(_) => Vec::new(),
            },
        };

        let (next, verified) = decrypt_node_private_key(
            openpgp,
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

        cache.lock().await.insert(id.clone(), next.clone());
        current = Some(next);
    }

    current.ok_or_else(|| Error::Internal("empty node key chain".into()))
}

/// Resolve the full upload parent context (parent node key + decrypted
/// `NodeHashKey`) for a parent folder at **any depth**.
///
/// Mirrors JS `UploadManager.createDraftNode`'s `getNodeKeys(parentUid)` step
/// plus `decryptNodeHashKey`. This is the B2 upload-half fix: the parent node
/// key is resolved via the full-chain walk (not a share-root-only single fetch),
/// and its own `NodeHashKey` is decrypted with that resolved key, so uploading
/// into a nested folder derives the correct hash key/parent key.
pub(crate) async fn resolve_parent_context(
    http: &Arc<dyn ProtonDriveHttpClient>,
    openpgp: &Arc<dyn OpenPgpCrypto>,
    account: &Arc<dyn ProtonDriveAccount>,
    share_id: &str,
    parent_link_id: &str,
) -> Result<ParentContext> {
    let share_priv = resolve_share_key(http, openpgp, account, share_id).await?;
    let (node_key, link) = resolve_node_key_and_link(
        http,
        openpgp,
        account,
        share_id,
        parent_link_id,
        &share_priv,
    )
    .await?;

    let node_hash_key_armored = link
        .folder_properties
        .and_then(|f| f.node_hash_key)
        .ok_or_else(|| {
            Error::Internal("parent link is not a folder or has no NodeHashKey".into())
        })?;

    let hash_key = decrypt_node_hash_key(openpgp, &node_hash_key_armored, &node_key).await?;
    Ok(ParentContext { node_key, hash_key })
}

/// Decrypt a folder's `NodeHashKey` (armored PGP message) with the folder's own
/// node key. JS `decryptNodeHashKey` does not require the embedded signature to
/// verify — only the plaintext key bytes are needed for the child name-hash
/// HMAC.
pub(crate) async fn decrypt_node_hash_key(
    openpgp: &Arc<dyn OpenPgpCrypto>,
    node_hash_key_armored: &str,
    node_key: &PrivateKey,
) -> Result<Vec<u8>> {
    let bytes = node_hash_key_armored.as_bytes();
    let session_key = openpgp
        .decrypt_session_key(bytes, std::slice::from_ref(node_key))
        .await?;
    let (hash_key, _status) = openpgp.decrypt_and_verify(bytes, &session_key, &[]).await?;
    Ok(hash_key)
}

/// Minimal `GET` + envelope-code check, local to this module so it does not
/// depend on `ProtonDriveClient`'s private helpers.
async fn api_get<T: serde::de::DeserializeOwned>(
    http: &Arc<dyn ProtonDriveHttpClient>,
    path: &str,
) -> Result<T> {
    let req = JsonRequest {
        method: HttpMethod::Get,
        path: path.to_owned(),
        query: vec![],
        headers: vec![],
        body: None,
    };
    let resp = http.request_json(req).await?;
    let env: ResponseEnvelope<T> = serde_json::from_slice(&resp.body)
        // Name the endpoint that produced the malformed body — a chained
        // share/parent-link resolution issues several GETs, and a bare
        // "JSON parse" gave no clue which one Proton answered with HTML/an
        // error page. Diagnosability, not behaviour.
        .map_err(|e| Error::Internal(format!("JSON parse ({path}): {e}")))?;
    if env.code != CODE_OK {
        return Err(map_api_error(env.code, env.error));
    }
    Ok(env.inner)
}
