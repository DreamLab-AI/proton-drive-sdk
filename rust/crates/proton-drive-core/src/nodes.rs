//! Node aggregate. Mirrors `client/js/src/interface/nodes.ts`.

use crate::account::Author;
use crate::error::Error;
use proton_drive_api::nodes::Link;
use proton_drive_crypto::{PrivateKey, SessionKey};
use std::time::SystemTime;

/// Stable handle for a Node: `(volume_id, node_id)`.
///
/// Mirrors JS `NodeUid` (an opaque base64 string encoding both ids).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeUid {
    pub volume_id: String,
    pub node_id: String,
}

/// Build a `NodeUid` from raw ids. Mirrors JS `generateNodeUid`/`makeNodeUid`.
pub fn make_node_uid(volume_id: impl Into<String>, node_id: impl Into<String>) -> NodeUid {
    NodeUid {
        volume_id: volume_id.into(),
        node_id: node_id.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    File,
    Folder,
    Album,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionState {
    Draft,
    Active,
    Superseded,
}

#[derive(Debug, Clone)]
pub struct Revision {
    pub uid: String,
    pub state: RevisionState,
    pub size_bytes: Option<u64>,
    pub created_at: SystemTime,
    pub author: Author,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub uid: NodeUid,
    pub parent: Option<NodeUid>,
    pub name: String,
    pub node_type: NodeType,
    pub media_type: Option<String>,
    pub size_bytes: Option<u64>,
    pub created_at: SystemTime,
    pub modified_at: SystemTime,
    pub trashed: bool,
    pub author: Author,
    pub active_revision: Option<Revision>,
}

/// Maybe-degraded node — mirrors JS `MaybeNode` (`Node | DegradedNode | MissingNode`).
///
/// `Node` is boxed because the fully-decoded variant is far larger than the
/// fallback variants; keeps the enum compact for hot paths (folder iteration).
#[derive(Debug, Clone)]
pub enum MaybeNode {
    Node(Box<Node>),
    Degraded { uid: NodeUid, reason: String },
    Missing { uid: NodeUid },
}

impl MaybeNode {
    pub fn uid(&self) -> &NodeUid {
        match self {
            MaybeNode::Node(n) => &n.uid,
            MaybeNode::Degraded { uid, .. } => uid,
            MaybeNode::Missing { uid } => uid,
        }
    }
}

/// Convert a wire `Link` DTO into a domain `Node`.
///
/// Name decryption requires the node's passphrase to be decrypted by the
/// parent (or share) key, then the encrypted name decrypted with that node key.
/// For MVP, full crypto chain decryption is deferred: if a `decrypted_name`
/// is not supplied by the caller, the name is a placeholder. Callers that
/// can supply a decrypted name (e.g. root link from `my_files_root`) pass
/// it directly.
///
/// # TODO MC-followup: full name decryption requires AddressProvider integration
/// Once the `AddressProvider` trait surface is extended to expose per-address
/// PGP keys, callers should decrypt `link.node_passphrase` with the share/parent
/// key and then call `OpenPgpCrypto::decrypt_and_verify` on `link.name`.
pub fn link_to_maybe_node(
    link: Link,
    volume_id: &str,
    decrypted_name: Option<String>,
) -> MaybeNode {
    let uid = make_node_uid(volume_id, &link.link_id);
    let parent = link
        .parent_link_id
        .as_deref()
        .map(|pid| make_node_uid(volume_id, pid));

    let name = decrypted_name.unwrap_or_else(|| {
        tracing::warn!(
            link_id = %link.link_id,
            "name decryption deferred — AddressProvider integration pending (TODO MC-followup)"
        );
        format!("<encrypted-{}>", link.link_id)
    });

    let node_type = match link.r#type {
        1 => NodeType::Folder,
        2 => NodeType::File,
        _ => NodeType::Album,
    };

    let created_at =
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(link.created_time.max(0) as u64);
    let modified_at =
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(link.modify_time.max(0) as u64);

    let active_revision = link.file_properties.as_ref().and_then(|fp| {
        fp.active_revision.as_ref().map(|rev| {
            let rev_created = SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(rev.created_time.max(0) as u64);
            Revision {
                uid: rev.id.clone(),
                state: RevisionState::Active,
                size_bytes: Some(rev.size),
                created_at: rev_created,
                author: Author::Anonymous,
            }
        })
    });

    let size_bytes = if link.size == 0 && node_type == NodeType::Folder {
        None
    } else {
        Some(link.size)
    };

    MaybeNode::Node(Box::new(Node {
        uid,
        parent,
        name,
        node_type,
        media_type: link.mime_type.filter(|s| !s.is_empty()),
        size_bytes,
        created_at,
        modified_at,
        trashed: link.trashed.is_some(),
        author: Author::Anonymous,
        active_revision,
    }))
}

/// Parse a protocol error into the appropriate domain `Error`.
///
/// The Proton API returns `Code` ≠ 1000 for known error conditions.
/// We surface the message directly; callers decide whether to retry.
pub fn map_api_error(code: u32, message: Option<String>) -> Error {
    let msg = message.unwrap_or_else(|| format!("API error {code}"));
    match code {
        2501 => Error::NotFound(msg),
        2011 => Error::NodeWithSameNameExists { name: msg },
        _ => Error::Internal(msg),
    }
}

#[derive(Debug, Clone, Default)]
pub struct FolderChildrenFilter {
    pub include_trashed: bool,
    pub only_type: Option<NodeType>,
}

/// Cached cryptographic material for a Node or Share.
/// Mirrors JS `CachedCryptoMaterial`.
#[derive(Debug, Clone)]
pub struct CachedCryptoMaterial {
    pub node_keys: Option<NodeKeyMaterial>,
    pub share_key: Option<ShareKeyMaterial>,
    pub public_share_key: Option<PrivateKey>,
}

#[derive(Debug, Clone)]
pub struct NodeKeyMaterial {
    pub passphrase: String,
    pub key: PrivateKey,
    pub passphrase_session_key: SessionKey,
    pub content_key_packet_session_key: Option<SessionKey>,
    pub hash_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ShareKeyMaterial {
    pub key: PrivateKey,
    pub passphrase_session_key: SessionKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_uid_eq_and_hash() {
        let a = make_node_uid("vol-1", "node-1");
        let b = make_node_uid("vol-1", "node-1");
        let c = make_node_uid("vol-2", "node-1");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn maybe_node_uid_extracts_for_each_variant() {
        let uid = make_node_uid("v", "n");
        let missing = MaybeNode::Missing { uid: uid.clone() };
        let degraded = MaybeNode::Degraded {
            uid: uid.clone(),
            reason: "decrypt".into(),
        };
        assert_eq!(missing.uid(), &uid);
        assert_eq!(degraded.uid(), &uid);
    }
}
