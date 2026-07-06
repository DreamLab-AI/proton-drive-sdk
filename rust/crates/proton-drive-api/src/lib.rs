//! Happy-path JSON DTOs for the Proton Drive API.
//!
//! Anti-corruption layer (domain-model.md §4): the domain types in
//! `proton-drive-core` never see these wire structs. Translators live next
//! to the call sites that issue HTTP requests.
//!
//! **Coverage**: only the endpoints needed for list/upload/download/events.
//! The full OpenAPI surface (40K LoC in JS) is out of scope until proven
//! necessary.
//!
//! Field names use Proton's `PascalCase` convention — preserved via `serde
//! rename_all` so debugging captured traffic stays readable.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Protobuf wire types, generated at build time from the cross-language
/// `.proto` source in `client/cs/src/protos` (the source of truth shared with
/// the C#/Kotlin/Swift implementations). Codegen runs in `build.rs`: a bundled
/// `protoc` (via `protoc-bin-vendored`) compiles the editions proto to a
/// `FileDescriptorSet`, which is relabelled to proto3 and fed to `prost-build`;
/// the output lands in `OUT_DIR` and is pulled in with `include!` below.
///
/// These types are **additive** and entirely separate from the hand-written
/// JSON REST DTOs in this crate's other modules — the REST surface is driven by
/// Proton's HTTP API, which is described by OpenAPI specs that live **outside**
/// this repository (`api/openapi-*.json`). Generating Rust from those specs is
/// deferred until the specs are vendored here; the REST DTOs therefore remain
/// hand-written and are not touched by this protobuf codegen.
///
/// Upstream merged the former two-package split (`proton.sdk` +
/// `proton.drive.sdk`, the latter importing the former) into a single
/// `package proton.drive.sdk;` (see `reference/VENDORED.md`), so only one
/// protobuf package is generated:
/// - `proton.drive.sdk` → `proto::proton::drive::sdk`
// `large_enum_variant` fires on prost-generated `oneof` enums (`Node`,
// `DegradedNode`); the wire layout is fixed by the schema, so it is not ours to
// "box". Scoped to the generated module only.
#[allow(clippy::large_enum_variant)]
pub mod proto {
    /// Module tree mirrors the protobuf package components.
    pub mod proton {
        /// `package proton.drive.sdk;` — SDK primitives (sessions, HTTP,
        /// telemetry, errors, addresses) merged with Drive-specific
        /// request/response messages (nodes, uploads, downloads, photos).
        pub mod drive {
            pub mod sdk {
                include!(concat!(env!("OUT_DIR"), "/proton.drive.sdk.rs"));
            }
        }
    }
}

pub mod common {
    use super::*;

    /// Standard envelope of Proton API responses.
    #[derive(Debug, Clone, Deserialize)]
    pub struct ResponseEnvelope<T> {
        #[serde(rename = "Code")]
        pub code: u32,
        #[serde(flatten)]
        pub inner: T,
        #[serde(default)]
        #[serde(rename = "Error")]
        pub error: Option<String>,
    }

    pub const CODE_OK: u32 = 1000;
}

pub mod user {
    use super::*;

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetUserResponse {
        pub user: User,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct User {
        #[serde(rename = "ID")]
        pub id: String,
        pub name: String,
        pub email: String,
        pub keys: Vec<UserKey>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct UserKey {
        #[serde(rename = "ID")]
        pub id: String,
        pub primary: u8,
        pub private_key: String,
        /// On modern accounts the user key is locked with a per-key passphrase
        /// stored in this Token (armored PGP message encrypted to another key).
        /// `None` on legacy accounts where key_password unlocks directly.
        #[serde(default)]
        pub token: Option<String>,
    }
}

pub mod addresses {
    use super::*;

    /// Response from `GET /core/v4/addresses`.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetAddressesResponse {
        pub addresses: Vec<Address>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Address {
        #[serde(rename = "ID")]
        pub id: String,
        pub email: String,
        /// Sort order — the primary address has the lowest value.
        pub order: u32,
        pub keys: Vec<AddressKey>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct AddressKey {
        #[serde(rename = "ID")]
        pub id: String,
        pub primary: u8,
        pub private_key: String,
        /// Armored PGP message: the address-key passphrase encrypted to one of
        /// the user's keys. Absent for some legacy key layouts.
        #[serde(default)]
        pub token: Option<String>,
    }
}

pub mod shares {
    use super::*;

    /// Response from `GET drive/v2/shares/my-files`.
    ///
    /// Mirrors `PrimaryRootShareResponseDto` in driveTypes.ts.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetMyFilesResponse {
        pub volume: MyFilesVolume,
        pub share: MyFilesShare,
        /// Root link wrapped as FolderDetailsDto — outer field is "Link".
        pub link: FolderDetails,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct MyFilesVolume {
        #[serde(rename = "VolumeID")]
        pub volume_id: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct MyFilesShare {
        #[serde(rename = "ShareID")]
        pub share_id: String,
        pub creator_email: Option<String>,
        pub key: String,
        pub passphrase: String,
        pub passphrase_signature: String,
        #[serde(rename = "AddressID")]
        pub address_id: String,
    }

    /// `FolderDetailsDto` from the v2 endpoints: the node's link metadata
    /// (`Link`) and folder-specific fields (`Folder`) are split into sibling
    /// objects — unlike the legacy flat [`super::nodes::Link`] that carries
    /// `MIMEType`/`Size`/`FileProperties`/`FolderProperties` inline.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct FolderDetails {
        pub link: LinkV2,
        #[serde(default)]
        pub folder: Option<FolderV2>,
    }

    /// v2 `LinkDto`. Notable differences from the legacy link: no `MIMEType`
    /// or `Size` (those live in the sibling `File`/`Folder` objects), `NameHash`
    /// instead of `Hash`, and `TrashTime` instead of `Trashed`.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct LinkV2 {
        #[serde(rename = "LinkID")]
        pub link_id: String,
        #[serde(rename = "ParentLinkID")]
        pub parent_link_id: Option<String>,
        pub r#type: u8,
        pub state: u8,
        pub name: String,
        #[serde(default)]
        pub name_hash: Option<String>,
        pub name_signature_email: Option<String>,
        pub create_time: i64,
        pub modify_time: i64,
        #[serde(default)]
        pub trash_time: Option<i64>,
        pub node_key: String,
        pub node_passphrase: String,
        pub node_passphrase_signature: String,
        pub signature_email: Option<String>,
    }

    /// v2 `FolderDto` — only the hash key is needed for upload-parent HMAC.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct FolderV2 {
        #[serde(default)]
        pub node_hash_key: Option<String>,
    }

    impl FolderDetails {
        /// Project the split v2 shape onto the legacy [`super::nodes::Link`] so
        /// downstream node conversion stays in one place. `mime_type`/`size`
        /// are absent for a folder root (a folder has no media type and the
        /// domain reports `None` size for folders).
        #[must_use]
        pub fn into_link(self) -> super::nodes::Link {
            let folder_properties = self.folder.map(|f| super::nodes::FolderProperties {
                node_hash_key: f.node_hash_key,
            });
            let l = self.link;
            super::nodes::Link {
                link_id: l.link_id,
                parent_link_id: l.parent_link_id,
                r#type: l.r#type,
                name: l.name,
                name_signature_email: l.name_signature_email,
                hash: l.name_hash,
                mime_type: None,
                state: l.state,
                size: 0,
                created_time: l.create_time,
                modify_time: l.modify_time,
                trashed: l.trash_time,
                node_key: l.node_key,
                node_passphrase: l.node_passphrase,
                node_passphrase_signature: l.node_passphrase_signature,
                signature_email: l.signature_email,
                file_properties: None,
                folder_properties,
            }
        }
    }

    /// `GET drive/shares/{shareID}` returns the share fields **flat** at the
    /// envelope level (not wrapped in a `Share` object). `#[serde(flatten)]`
    /// reproduces the wire shape while keeping the `.share` accessor for callers.
    #[derive(Debug, Clone, Deserialize)]
    pub struct GetShareResponse {
        #[serde(flatten)]
        pub share: Share,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Share {
        #[serde(rename = "ShareID")]
        pub share_id: String,
        #[serde(rename = "VolumeID")]
        pub volume_id: String,
        #[serde(rename = "LinkID")]
        pub link_id: String,
        pub r#type: u8,
        /// Email of the address that created the share. Used to resolve the
        /// verification keys for `PassphraseSignature` (JS `decryptRootShare`
        /// -> `account.getPublicKeys(share.creatorEmail)`). `#[serde(default)]`
        /// since not every `/drive/shares/{shareID}` response shape has been
        /// observed to include it.
        #[serde(default)]
        pub creator_email: Option<String>,
        pub key: String,
        pub passphrase: String,
        pub passphrase_signature: String,
        #[serde(rename = "AddressID")]
        pub address_id: String,
        /// Not present on all share responses (the flat `drive/shares/{id}`
        /// payload omits it); only meaningful for shares with direct access.
        #[serde(rename = "AddressKeyID", default)]
        pub address_key_id: Option<String>,
    }
}

pub mod nodes {
    use super::*;

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetLinkResponse {
        pub link: Link,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetChildrenResponse {
        pub links: Vec<Link>,
        /// Non-zero means more pages exist; fetch with next `Page` index.
        ///
        /// **Not part of the current wire schema.** The vendored OpenAPI spec
        /// for this deprecated endpoint
        /// (`get_drive-shares-{shareID}-folders-{linkID}-children` in
        /// `reference/client/js/src/internal/apiService/driveTypes.ts`)
        /// defines the response as `{ Code, AllowSorting, Links }` only — no
        /// `More`/cursor field. This defaults to `0` on every real response,
        /// so callers must not treat `more == 0` alone as end-of-pagination;
        /// compare the returned page length against the requested `PageSize`
        /// instead (see `ProtonDriveClient::fetch_folder_children`). Kept (and
        /// still read) only for tolerance of a possible future/undocumented
        /// server-side `More` signal.
        #[serde(default)]
        pub more: u8,
    }

    /// A link is Proton's wire name for what the domain calls a Node.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Link {
        #[serde(rename = "LinkID")]
        pub link_id: String,
        #[serde(rename = "ParentLinkID")]
        pub parent_link_id: Option<String>,
        pub r#type: u8, // 1 = folder, 2 = file
        pub name: String,
        pub name_signature_email: Option<String>,
        /// Name hash. Nullable on the wire (e.g. some folder layouts).
        #[serde(default)]
        pub hash: Option<String>,
        /// Nullable/absent on the wire for folders and root nodes (the JS SDK
        /// treats it as `MIMEType || undefined`); only files carry a real type.
        #[serde(rename = "MIMEType", default)]
        pub mime_type: Option<String>,
        // `LinkTransformer.State` (driveTypes.ts): 0 = draft, 1 = active,
        // 2 = trashed. Not currently branched on by domain conversion (see
        // `trashed`, a separate nullable timestamp field, for trash status).
        pub state: u8,
        pub size: u64,
        /// Proton's field is `CreateTime` (not `CreatedTime`); `CreationTime`
        /// is a deprecated alias. Required on link responses.
        #[serde(rename = "CreateTime")]
        pub created_time: i64,
        pub modify_time: i64,
        pub trashed: Option<i64>,
        pub node_key: String,
        pub node_passphrase: String,
        pub node_passphrase_signature: String,
        pub signature_email: Option<String>,
        #[serde(default)]
        pub file_properties: Option<FileProperties>,
        #[serde(default)]
        pub folder_properties: Option<FolderProperties>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct FileProperties {
        /// Optional on the wire (`ContentKeyPacket?`).
        #[serde(default)]
        pub content_key_packet: Option<String>,
        /// Optional key on the wire (`ContentKeyPacketSignature?: string` in
        /// `ExtendedLinkTransformer.FileProperties`,
        /// `reference/client/js/src/internal/apiService/driveTypes.ts`).
        /// `Option<T>` fields deserialize a missing key as `None` without
        /// needing `#[serde(default)]` (serde derive special-cases `Option`),
        /// so this already tolerates absence.
        pub content_key_packet_signature: Option<String>,
        /// Optional key on the wire (`ActiveRevision?:`) — absent for files
        /// with no committed revision (e.g. still-draft uploads surfaced in
        /// a listing). Same `Option<T>`-absence tolerance as above.
        pub active_revision: Option<Revision>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct FolderProperties {
        /// Optional on the wire (`NodeHashKey?`); needed to compute the HMAC
        /// name hash when this folder is an upload parent.
        #[serde(default)]
        pub node_hash_key: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Revision {
        #[serde(rename = "ID", default)]
        pub id: String,
        /// `RevisionState` (driveTypes.ts: `0 | 1 | 2`; mirrored client-side
        /// as `APIRevisionState` in
        /// `client/js/src/internal/nodes/apiService.ts`): 0 = draft,
        /// 1 = active, 2 = obsolete/superseded.
        #[serde(default)]
        pub state: u8,
        /// Proton's field is `CreateTime`; optional within `ActiveRevision`.
        #[serde(rename = "CreateTime", default)]
        pub created_time: i64,
        #[serde(default)]
        pub size: u64,
        /// Optional key on the wire (`ManifestSignature?: string` within
        /// `ExtendedLinkTransformer.FileProperties.ActiveRevision` in
        /// driveTypes.ts) — `Option<T>` already tolerates a missing key.
        pub manifest_signature: Option<String>,
        /// Optional key on the wire (`SignatureEmail?: string`), same
        /// `Option<T>`-absence tolerance.
        pub signature_email: Option<String>,
    }
}

pub mod upload {
    use super::*;

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CreateFileRequest {
        pub name: String,
        pub hash: String,
        #[serde(rename = "ParentLinkID")]
        pub parent_link_id: String,
        #[serde(rename = "MIMEType")]
        pub mime_type: String,
        #[serde(rename = "ClientUID")]
        pub client_uid: Option<String>,
        /// Coarse size hint for early quota validation; sent as `null` when
        /// unknown (the server re-validates during commit).
        pub intended_upload_size: Option<u64>,
        pub node_key: String,
        pub node_passphrase: String,
        pub node_passphrase_signature: String,
        pub content_key_packet: String,
        pub content_key_packet_signature: String,
        pub signature_address: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CreateFileResponse {
        pub file: CreatedFile,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CreatedFile {
        #[serde(rename = "ID")]
        pub link_id: String,
        #[serde(rename = "RevisionID")]
        pub revision_id: String,
    }

    /// `POST drive/v2/volumes/{volumeID}/files/{linkID}/revisions` request body.
    /// Mirrors JS `UploadAPIService.createDraftRevision`'s
    /// `PostCreateDraftRevisionRequest`
    /// (`reference/client/js/src/internal/upload/apiService.ts:137-161`): a
    /// revision draft on an *existing* file carries only the optimistic
    /// concurrency guard (`CurrentRevisionID`), the per-process draft-owner id
    /// (`ClientUID`), and the coarse size hint — **no** node key, content key,
    /// name, or hash (those are reused from the existing node).
    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CreateRevisionRequest {
        /// The currently-active revision's ID (server rejects if the active
        /// revision has moved since the client last read it).
        #[serde(rename = "CurrentRevisionID")]
        pub current_revision_id: String,
        #[serde(rename = "ClientUID")]
        pub client_uid: Option<String>,
        /// Coarse size hint for early quota validation; sent as `null` when
        /// unknown (the server re-validates during commit).
        pub intended_upload_size: Option<u64>,
    }

    /// `POST .../revisions` response — `{ "Revision": { "ID": ... } }`.
    /// Mirrors JS `PostCreateDraftRevisionResponse` (apiService.ts:137-161):
    /// the new draft revision's id is combined with the volume/node ids into a
    /// `NodeRevisionUid` client-side.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CreateRevisionResponse {
        pub revision: CreatedRevision,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CreatedRevision {
        #[serde(rename = "ID")]
        pub id: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RequestBlockUploadRequest {
        #[serde(rename = "AddressID")]
        pub address_id: String,
        #[serde(rename = "VolumeID")]
        pub volume_id: String,
        #[serde(rename = "LinkID")]
        pub link_id: String,
        #[serde(rename = "RevisionID")]
        pub revision_id: String,
        pub block_list: Vec<BlockUploadEntry>,
        /// Always sent (empty for non-thumbnail uploads) to match the JS client.
        pub thumbnail_list: Vec<ThumbnailUploadEntry>,
    }

    /// `Index` + `EncSignature` + `Verifier` only — Proton ignores client-sent
    /// `Hash`/`Size` for content blocks (the JS client omits them), so they are
    /// not part of this struct.
    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct BlockUploadEntry {
        pub index: u32,
        #[serde(rename = "EncSignature")]
        pub enc_signature: String,
        pub verifier: BlockVerifier,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ThumbnailUploadEntry {
        pub r#type: u8,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct BlockVerifier {
        pub token: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RequestBlockUploadResponse {
        pub upload_links: Vec<UploadLink>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct UploadLink {
        pub index: u32,
        #[serde(rename = "BareURL")]
        pub bare_url: String,
        pub token: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CommitRevisionRequest {
        pub manifest_signature: String,
        pub signature_address: String,
        /// Encrypted extended attributes — Proton's field is `XAttr`.
        #[serde(rename = "XAttr")]
        pub x_attr: String,
        /// Whether the client verified the content checksum during upload.
        pub checksum_verified: bool,
        /// Only used for photos in the Photo volume; always `null` here.
        pub photo: Option<serde_json::Value>,
    }

    /// `POST drive/v2/volumes/{volumeID}/delete_multiple` request body.
    /// Mirrors JS `apiService.ts` `deleteDraft`'s `PostDeleteNodesRequest`
    /// (`LinkIDsRequestDto`): a bare list of link ids to delete.
    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct DeleteNodesRequest {
        #[serde(rename = "LinkIDs")]
        pub link_ids: Vec<String>,
    }

    /// `POST drive/v2/volumes/{volumeID}/delete_multiple` response —
    /// `MultiResponsesPerLinkFactory` in the OpenAPI schema. The outer `Code`
    /// is always the fixed multi-status marker `1001`; the real per-link
    /// result lives in `Responses[i].Response.Code`. JS `deleteDraft` ignores
    /// the outer code entirely and reads `response.Responses?.[0].Response.Code`.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct DeleteNodesResponse {
        pub responses: Vec<DeleteNodeResponseEntry>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct DeleteNodeResponseEntry {
        #[serde(rename = "LinkID")]
        pub link_id: String,
        pub response: DeleteNodeResponseInner,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct DeleteNodeResponseInner {
        pub code: u32,
        #[serde(default)]
        pub error: Option<String>,
    }
}

pub mod folders {
    use super::*;

    /// `POST drive/v2/volumes/{volumeID}/folders` request body.
    ///
    /// Mirrors JS `NodesAPIService.createFolder`'s `PostCreateFolderRequest`
    /// (`reference/client/js/src/internal/nodes/apiService.ts:498-536`). Unlike
    /// [`super::upload::CreateFileRequest`], a folder carries a `NodeHashKey`
    /// (the HMAC key that this folder's own children will hash their names
    /// against — the read side consumes it in
    /// `ProtonDriveClient::resolve_folder_node_key`) and has **no** content-key
    /// material (there is no file content to wrap a session key for). Folder
    /// creation also signs with `SignatureEmail`, not the file path's
    /// `SignatureAddress`. `XAttr` is optional and omitted from the wire when
    /// absent (JS sends it as `undefined`, which `JSON.stringify` drops).
    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CreateFolderRequest {
        #[serde(rename = "ParentLinkID")]
        pub parent_link_id: String,
        pub node_key: String,
        pub node_hash_key: String,
        pub node_passphrase: String,
        pub node_passphrase_signature: String,
        pub signature_email: String,
        pub name: String,
        pub hash: String,
        #[serde(rename = "XAttr", skip_serializing_if = "Option::is_none")]
        pub x_attr: Option<String>,
    }

    /// `POST .../folders` response — `{ "Folder": { "ID": ... } }`.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CreateFolderResponse {
        pub folder: CreatedFolder,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CreatedFolder {
        #[serde(rename = "ID")]
        pub id: String,
    }
}

pub mod download {
    use super::*;

    /// Response from `GET drive/v2/volumes/{VolumeID}/files/{linkID}/revisions/{revisionID}`.
    ///
    /// Mirrors `GetRevisionResponse` in `client/js/src/internal/download/apiService.ts`.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetRevisionResponse {
        #[serde(rename = "Revision")]
        pub revision: RevisionWithBlocks,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RevisionWithBlocks {
        #[serde(rename = "ID")]
        pub id: String,
        /// `RevisionState` (`DetailedRevisionResponseDto.State` in
        /// driveTypes.ts: `0 | 1 | 2`): 0 = draft, 1 = active,
        /// 2 = obsolete/superseded.
        pub state: Option<u8>,
        pub blocks: Vec<BlockResponse>,
        /// Optional key on the wire (`ManifestSignature?: PGPSignature | null`
        /// in `DetailedRevisionResponseDto`) — absent for draft/uncommitted
        /// revisions. `Option<T>` fields already deserialize a missing key
        /// as `None` (serde derive special-cases `Option`), so this
        /// tolerates absence without needing `#[serde(default)]`.
        pub manifest_signature: Option<String>,
        /// Armored PKESK packet: wraps the content session key for the node
        /// key. **Not present at all** on `DetailedRevisionResponseDto` in
        /// the current vendored OpenAPI spec (content-key material lives on
        /// the file's `FileProperties` from `GET .../links/{linkID}`
        /// instead, see `nodes::FileProperties`) — `Option<T>`'s built-in
        /// missing-key tolerance means this still round-trips regardless.
        /// download.rs's `FileDownloader` prefers its own cached
        /// `FileProperties` value and only falls back to this field.
        pub content_key_packet: Option<String>,
        pub content_key_packet_signature: Option<String>,
        /// Encrypted extended attributes (modification time, size, SHA1 digest).
        /// Optional key on the wire (`XAttr?: PGPMessage | null`) — absent for
        /// legacy/draft revisions.
        pub x_attr: Option<String>,
        /// Email of the address that signed this revision's content.
        pub signature_email: Option<String>,
    }

    /// A single block within a revision.
    ///
    /// `Hash` is the base64-encoded SHA-256 of the **ciphertext** (not plaintext).
    /// As noted in `domain-model-mvp.md`: "Hash is sha256 of ciphertext, not plaintext."
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct BlockResponse {
        /// 1-based block index within the revision.
        pub index: u32,
        /// Opaque CDN URL — treated as a blob, never parsed (domain-model anti-corruption rule).
        /// The API uses uppercase "URL" suffix, not "Url".
        #[serde(rename = "BareURL")]
        pub bare_url: String,
        /// Bearer token for the `Authorization` header when fetching `bare_url`.
        pub token: String,
        /// Base64-encoded SHA-256 of the ciphertext bytes.
        pub hash: String,
        /// Encrypted detached signature for this block — Proton's field is
        /// `EncSignature` (optional for legacy revisions).
        #[serde(rename = "EncSignature", default)]
        pub encrypted_signature: Option<String>,
        /// Ciphertext size in bytes.
        #[serde(default)]
        pub size: u64,
    }
}

pub mod events;

pub mod auth {
    use super::*;

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct AuthInfoRequest {
        pub username: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct AuthInfoResponse {
        pub version: u32,
        pub modulus: String,
        pub server_ephemeral: String,
        pub salt: String,
        #[serde(rename = "SRPSession")]
        pub srp_session: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct AuthRequest {
        pub username: String,
        pub client_ephemeral: String,
        pub client_proof: String,
        #[serde(rename = "SRPSession")]
        pub srp_session: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct AuthResponse {
        #[serde(rename = "UID")]
        pub uid: String,
        pub access_token: String,
        pub refresh_token: String,
        pub server_proof: String,
        // Proton returns LocalID (int) on some API versions and omits or nulls UserID.
        #[serde(rename = "UserID", default, deserialize_with = "null_to_empty")]
        pub user_id: String,
        #[serde(rename = "2FA", default)]
        pub two_factor: TwoFactor,
    }

    fn null_to_empty<'de, D>(d: D) -> Result<String, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
    }

    #[derive(Debug, Clone, Deserialize, Default)]
    #[serde(rename_all = "PascalCase")]
    pub struct TwoFactor {
        pub enabled: u32,
    }

    /// Body for `POST /core/v4/auth/2fa` — submits the TOTP (or recovery)
    /// code for a `twofactor`-scoped session. Wire shape per the C# account
    /// SDK's `SecondFactorValidationRequest` and the JS OpenAPI route
    /// `/core/{_version}/auth/2fa` (coreTypes.ts).
    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct TwoFactorRequest {
        pub two_factor_code: String,
    }

    /// Response payload of `POST /core/v4/auth/2fa` (inside the standard
    /// envelope). Upstream's `ScopesResponse` — the scopes granted once the
    /// second factor validates. Informational: this port doesn't track
    /// scopes, success is established by the envelope code alone.
    #[derive(Debug, Clone, Deserialize, Default)]
    #[serde(rename_all = "PascalCase")]
    pub struct TwoFactorResponse {
        #[serde(default)]
        pub scopes: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RefreshRequest {
        pub response_type: String,
        pub grant_type: String,
        pub refresh_token: String,
        pub redirect_uri: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RefreshResponse {
        // The refresh response's `UID` is deprecated and optional on the wire —
        // the UID is supplied via the `x-pm-uid` request header, and `do_refresh`
        // keeps using the session's existing UID. Only the rotated tokens matter.
        pub access_token: String,
        pub refresh_token: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct KeySaltsResponse {
        pub key_salts: Vec<KeySalt>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct KeySalt {
        #[serde(rename = "ID")]
        pub id: String,
        // Proton returns null for keys that have no passphrase (e.g. hardware keys).
        #[serde(default, deserialize_with = "null_to_empty")]
        pub key_salt: String,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_get_user_envelope() {
        let body = r#"{
            "Code": 1000,
            "User": {
                "ID": "u1",
                "Name": "alice",
                "Email": "alice@proton.me",
                "Keys": [{ "ID": "k1", "Primary": 1, "PrivateKey": "-----BEGIN PGP----- ..." }]
            }
        }"#;
        let env: common::ResponseEnvelope<user::GetUserResponse> =
            serde_json::from_str(body).expect("parse");
        assert_eq!(env.code, common::CODE_OK);
        assert_eq!(env.inner.user.email, "alice@proton.me");
        assert_eq!(env.inner.user.keys.len(), 1);
    }

    #[test]
    fn serialize_two_factor_request_wire_shape() {
        // Must match the C# account SDK's `SecondFactorValidationRequest`:
        // a single `TwoFactorCode` string, nothing else.
        let body = serde_json::to_value(auth::TwoFactorRequest {
            two_factor_code: "123456".to_owned(),
        })
        .expect("serialize");
        assert_eq!(body, serde_json::json!({"TwoFactorCode": "123456"}));
    }

    #[test]
    fn deserialize_two_factor_response_envelope() {
        let body = r#"{ "Code": 1000, "Scopes": ["full", "drive"] }"#;
        let env: common::ResponseEnvelope<auth::TwoFactorResponse> =
            serde_json::from_str(body).expect("parse");
        assert_eq!(env.code, common::CODE_OK);
        assert_eq!(env.inner.scopes, vec!["full", "drive"]);

        // Scopes may be absent entirely — only the envelope code matters.
        let bare = r#"{ "Code": 1000 }"#;
        let env: common::ResponseEnvelope<auth::TwoFactorResponse> =
            serde_json::from_str(bare).expect("parse without Scopes");
        assert_eq!(env.code, common::CODE_OK);
        assert!(env.inner.scopes.is_empty());
    }

    #[test]
    fn deserialize_children_response() {
        let body = r#"{
            "Links": [{
                "LinkID": "l1", "ParentLinkID": "root",
                "Type": 1, "Name": "encrypted-name", "Hash": "hex",
                "MIMEType": "Folder", "State": 1, "Size": 0,
                "CreateTime": 1, "ModifyTime": 2,
                "NodeKey": "armored", "NodePassphrase": "armored",
                "NodePassphraseSignature": "armored",
                "FolderProperties": { "NodeHashKey": "armored" }
            }],
            "More": 0
        }"#;
        let resp: nodes::GetChildrenResponse = serde_json::from_str(body).expect("parse");
        assert_eq!(resp.links.len(), 1);
        assert_eq!(resp.links[0].r#type, 1);
        assert!(resp.links[0].folder_properties.is_some());
        assert_eq!(resp.more, 0);
    }

    /// The real wire shape for the deprecated legacy children endpoint
    /// (`get_drive-shares-{shareID}-folders-{linkID}-children` response in
    /// `reference/client/js/src/internal/apiService/driveTypes.ts`) is
    /// `{ Code, AllowSorting, Links }` — there is no `More`/cursor field at
    /// all (that only exists on the v2 volume-scoped sibling endpoint). This
    /// must still deserialize (`more` defaulting to `0`); pagination
    /// continuation must NOT be decided by `more` alone — see
    /// `ProtonDriveClient::fetch_folder_children` in `proton-drive-core`.
    #[test]
    fn deserialize_children_response_without_more_field() {
        let body = r#"{
            "Code": 1000,
            "AllowSorting": true,
            "Links": [{
                "LinkID": "l1", "ParentLinkID": "root",
                "Type": 1, "Name": "encrypted-name", "Hash": "hex",
                "MIMEType": "Folder", "State": 1, "Size": 0,
                "CreateTime": 1, "ModifyTime": 2,
                "NodeKey": "armored", "NodePassphrase": "armored",
                "NodePassphraseSignature": "armored",
                "FolderProperties": { "NodeHashKey": "armored" }
            }]
        }"#;
        let resp: nodes::GetChildrenResponse = serde_json::from_str(body)
            .expect("must parse the real wire shape lacking a More field");
        assert_eq!(resp.links.len(), 1);
        assert_eq!(
            resp.more, 0,
            "absent More key defaults to 0 — callers must not treat this as authoritative"
        );
    }

    #[test]
    fn deserialize_children_response_with_pagination() {
        // Realistic JSON matching the v1 children endpoint shape.
        // Includes a file node (Type=2) with FileProperties, an active revision,
        // and More=1 indicating a second page exists.
        let body = r#"{
            "Code": 1000,
            "Links": [
                {
                    "LinkID": "folder-link-1",
                    "ParentLinkID": "root-link",
                    "Type": 1,
                    "Name": "yyMwuB1jJ2jGlHbzT3bxpgKQaVWpzlEn4R6B5X0cOiU=",
                    "Hash": "abc123hash",
                    "MIMEType": "Folder",
                    "State": 1,
                    "Size": 0,
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000100,
                    "NodeKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\\nabc\\n-----END PGP PUBLIC KEY BLOCK-----",
                    "NodePassphrase": "-----BEGIN PGP MESSAGE-----\\ndef\\n-----END PGP MESSAGE-----",
                    "NodePassphraseSignature": "-----BEGIN PGP SIGNATURE-----\\nghi\\n-----END PGP SIGNATURE-----",
                    "FolderProperties": { "NodeHashKey": "-----BEGIN PGP MESSAGE-----\\njkl\\n-----END PGP MESSAGE-----" }
                },
                {
                    "LinkID": "file-link-1",
                    "ParentLinkID": "root-link",
                    "Type": 2,
                    "Name": "zzEncryptedFileName==",
                    "Hash": "def456hash",
                    "MIMEType": "text/plain",
                    "State": 1,
                    "Size": 1234,
                    "CreateTime": 1700001000,
                    "ModifyTime": 1700001100,
                    "NodeKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\\nxyz\\n-----END PGP PUBLIC KEY BLOCK-----",
                    "NodePassphrase": "-----BEGIN PGP MESSAGE-----\\nuvw\\n-----END PGP MESSAGE-----",
                    "NodePassphraseSignature": "-----BEGIN PGP SIGNATURE-----\\nrst\\n-----END PGP SIGNATURE-----",
                    "FileProperties": {
                        "ContentKeyPacket": "-----BEGIN PGP MESSAGE-----\\ncontent\\n-----END PGP MESSAGE-----",
                        "ContentKeyPacketSignature": "-----BEGIN PGP SIGNATURE-----\\ncontentsig\\n-----END PGP SIGNATURE-----",
                        "ActiveRevision": {
                            "ID": "rev-1",
                            "State": 1,
                            "CreateTime": 1700001050,
                            "Size": 1234
                        }
                    }
                }
            ],
            "More": 1
        }"#;
        let resp: nodes::GetChildrenResponse = serde_json::from_str(body).expect("parse");
        assert_eq!(resp.links.len(), 2, "expected 2 links");
        assert_eq!(resp.more, 1, "More flag should indicate another page");

        let folder = &resp.links[0];
        assert_eq!(folder.link_id, "folder-link-1");
        assert_eq!(folder.r#type, 1);
        assert!(folder.folder_properties.is_some());
        assert!(folder.file_properties.is_none());

        let file = &resp.links[1];
        assert_eq!(file.link_id, "file-link-1");
        assert_eq!(file.r#type, 2);
        assert!(file.file_properties.is_some());
        let fp = file.file_properties.as_ref().unwrap();
        assert!(fp.active_revision.is_some());
        assert_eq!(fp.active_revision.as_ref().unwrap().id, "rev-1");
    }

    #[test]
    fn deserialize_my_files_response() {
        // Mirrors PrimaryRootShareResponseDto shape.
        let body = r#"{
            "Code": 1000,
            "Volume": { "VolumeID": "vol-abc123" },
            "Share": {
                "ShareID": "share-xyz789",
                "CreatorEmail": "alice@proton.me",
                "Key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\\nsharekey\\n-----END PGP PRIVATE KEY BLOCK-----",
                "Passphrase": "-----BEGIN PGP MESSAGE-----\\npassphrase\\n-----END PGP MESSAGE-----",
                "PassphraseSignature": "-----BEGIN PGP SIGNATURE-----\\npasssig\\n-----END PGP SIGNATURE-----",
                "AddressID": "addr-001"
            },
            "Link": {
                "Link": {
                    "LinkID": "root-link-001",
                    "Type": 1,
                    "ParentLinkID": null,
                    "State": 1,
                    "Name": "EncryptedRootName==",
                    "NameHash": null,
                    "NameSignatureEmail": null,
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000001,
                    "TrashTime": null,
                    "NodeKey": "rootnodekey",
                    "NodePassphrase": "rootpassphrase",
                    "NodePassphraseSignature": "rootpasssig",
                    "SignatureEmail": null
                },
                "Folder": {
                    "NodeHashKey": "-----BEGIN PGP MESSAGE-----\\nhashkey\\n-----END PGP MESSAGE-----"
                },
                "File": null,
                "Sharing": null,
                "Membership": null,
                "Album": null
            }
        }"#;
        let resp: shares::GetMyFilesResponse = serde_json::from_str(body).expect("parse");
        assert_eq!(resp.volume.volume_id, "vol-abc123");
        assert_eq!(resp.share.share_id, "share-xyz789");
        assert_eq!(resp.share.address_id, "addr-001");
        let link = resp.link.into_link();
        assert_eq!(link.link_id, "root-link-001");
        assert_eq!(link.r#type, 1);
        assert!(link.parent_link_id.is_none());
        assert!(link.mime_type.is_none());
        assert!(
            link.folder_properties
                .and_then(|f| f.node_hash_key)
                .is_some(),
            "Folder.NodeHashKey must project onto folder_properties"
        );
    }

    /// `GET drive/shares/{shareID}` returns share fields **flat** at the
    /// top level (no `Share` wrapper). `#[serde(flatten)]` must reproduce
    /// this while keeping the `.share` accessor, and `AddressKeyID` must
    /// tolerate absence (the flat payload omits it).
    #[test]
    fn deserialize_flat_get_share_response() {
        let body = r#"{
            "Code": 1000,
            "ShareID": "share-flat-1",
            "VolumeID": "vol-flat-1",
            "LinkID": "link-flat-1",
            "Type": 1,
            "Key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\\nk\\n-----END PGP PRIVATE KEY BLOCK-----",
            "Passphrase": "-----BEGIN PGP MESSAGE-----\\np\\n-----END PGP MESSAGE-----",
            "PassphraseSignature": "-----BEGIN PGP SIGNATURE-----\\ns\\n-----END PGP SIGNATURE-----",
            "AddressID": "addr-flat-1"
        }"#;
        let env: common::ResponseEnvelope<shares::GetShareResponse> =
            serde_json::from_str(body).expect("parse flat share");
        assert_eq!(env.code, common::CODE_OK);
        let s = &env.inner.share;
        assert_eq!(s.share_id, "share-flat-1");
        assert_eq!(s.volume_id, "vol-flat-1");
        assert_eq!(s.link_id, "link-flat-1");
        assert_eq!(s.address_id, "addr-flat-1");
        assert!(
            s.address_key_id.is_none(),
            "flat payload omits AddressKeyID"
        );
    }

    /// `ActiveRevision` carries `CreateTime` (not `CreatedTime`); the rename
    /// must map it onto `created_time`. A fabricated `CreatedTime` fixture
    /// would silently default to 0 — guard against that regression.
    #[test]
    fn revision_uses_create_time_field() {
        let body = r#"{
            "ID": "rev-9",
            "State": 1,
            "CreateTime": 1700009999,
            "Size": 42
        }"#;
        let rev: nodes::Revision = serde_json::from_str(body).expect("parse revision");
        assert_eq!(
            rev.created_time, 1700009999,
            "CreateTime must map to created_time"
        );
        assert_eq!(rev.size, 42);
    }

    /// Upload create request must emit Proton's exact PascalCase keys, send
    /// `IntendedUploadSize: null` when unknown, and key the client identifier
    /// as `ClientUID` (uppercase UID).
    #[test]
    fn serialize_create_file_request_shape() {
        let req = upload::CreateFileRequest {
            name: "enc-name".into(),
            hash: "namehash".into(),
            parent_link_id: "parent-1".into(),
            mime_type: "text/plain".into(),
            client_uid: None,
            intended_upload_size: None,
            node_key: "nk".into(),
            node_passphrase: "np".into(),
            node_passphrase_signature: "nps".into(),
            content_key_packet: "ckp".into(),
            content_key_packet_signature: "ckps".into(),
            signature_address: "sig@addr".into(),
        };
        let v = serde_json::to_value(&req).expect("serialize");
        let obj = v.as_object().expect("object");
        assert!(
            obj.contains_key("MIMEType"),
            "must use MIMEType, not MimeType"
        );
        assert!(
            obj.contains_key("ClientUID"),
            "must use ClientUID, not ClientUid"
        );
        assert!(obj.contains_key("ParentLinkID"));
        assert!(obj.contains_key("IntendedUploadSize"));
        assert!(
            obj["IntendedUploadSize"].is_null(),
            "unknown size sent as null"
        );
        assert!(obj["ClientUID"].is_null());
        assert_eq!(obj["Hash"], "namehash");
    }

    /// Content block entries carry only Index/EncSignature/Verifier — Proton
    /// ignores client-sent Hash/Size, and the JS client omits them, so they
    /// must NOT appear on the wire.
    #[test]
    fn serialize_block_upload_entry_omits_hash_and_size() {
        let entry = upload::BlockUploadEntry {
            index: 1,
            enc_signature: "encsig".into(),
            verifier: upload::BlockVerifier {
                token: "tok".into(),
            },
        };
        let v = serde_json::to_value(&entry).expect("serialize");
        let obj = v.as_object().expect("object");
        assert!(obj.contains_key("Index"));
        assert!(obj.contains_key("EncSignature"));
        assert!(obj.contains_key("Verifier"));
        assert!(
            !obj.contains_key("Hash"),
            "Hash must not be sent for content blocks"
        );
        assert!(
            !obj.contains_key("Size"),
            "Size must not be sent for content blocks"
        );
        assert_eq!(obj["Verifier"]["Token"], "tok");
    }

    /// Revision-draft create request must emit Proton's exact PascalCase keys:
    /// `CurrentRevisionID` (uppercase ID), `ClientUID` (uppercase UID), and
    /// `IntendedUploadSize` sent as `null` when unknown. Mirrors JS
    /// `PostCreateDraftRevisionRequest` (apiService.ts:137-161).
    #[test]
    fn serialize_create_revision_request_shape() {
        let req = upload::CreateRevisionRequest {
            current_revision_id: "rev-current".into(),
            client_uid: None,
            intended_upload_size: None,
        };
        let v = serde_json::to_value(&req).expect("serialize");
        let obj = v.as_object().expect("object");
        assert!(
            obj.contains_key("CurrentRevisionID"),
            "must use CurrentRevisionID, not CurrentRevisionId"
        );
        assert_eq!(obj["CurrentRevisionID"], "rev-current");
        assert!(
            obj.contains_key("ClientUID"),
            "must use ClientUID, not ClientUid"
        );
        assert!(obj["ClientUID"].is_null());
        assert!(obj.contains_key("IntendedUploadSize"));
        assert!(
            obj["IntendedUploadSize"].is_null(),
            "unknown size sent as null"
        );
        // No node key / content key / name / hash on a revision draft.
        assert!(!obj.contains_key("NodeKey"));
        assert!(!obj.contains_key("ContentKeyPacket"));
        assert!(!obj.contains_key("Name"));
        assert!(!obj.contains_key("Hash"));
    }

    /// `CreateRevisionResponse` deserializes the `{ "Revision": { "ID" } }`
    /// wire shape onto `revision.id`.
    #[test]
    fn deserialize_create_revision_response() {
        let body = r#"{ "Code": 1000, "Revision": { "ID": "new-rev-777" } }"#;
        let env: common::ResponseEnvelope<upload::CreateRevisionResponse> =
            serde_json::from_str(body).expect("parse");
        assert_eq!(env.code, common::CODE_OK);
        assert_eq!(env.inner.revision.id, "new-rev-777");
    }

    /// Folder-create request must emit Proton's exact PascalCase keys,
    /// carry a `NodeHashKey` (folders have one, files don't), sign with
    /// `SignatureEmail` (not the file path's `SignatureAddress`), send **no**
    /// content-key material, and omit `XAttr` entirely when absent. Mirrors JS
    /// `PostCreateFolderRequest` (nodes/apiService.ts:498-536).
    #[test]
    fn serialize_create_folder_request_shape() {
        let req = folders::CreateFolderRequest {
            parent_link_id: "parent-1".into(),
            node_key: "nk".into(),
            node_hash_key: "nhk".into(),
            node_passphrase: "np".into(),
            node_passphrase_signature: "nps".into(),
            signature_email: "sig@addr".into(),
            name: "enc-name".into(),
            hash: "namehash".into(),
            x_attr: None,
        };
        let v = serde_json::to_value(&req).expect("serialize");
        let obj = v.as_object().expect("object");
        assert!(obj.contains_key("ParentLinkID"));
        assert!(
            obj.contains_key("NodeHashKey"),
            "folders carry a NodeHashKey"
        );
        assert!(
            obj.contains_key("SignatureEmail"),
            "folder create signs with SignatureEmail, not SignatureAddress"
        );
        assert!(!obj.contains_key("SignatureAddress"));
        assert!(
            !obj.contains_key("ContentKeyPacket"),
            "folders have no content key material"
        );
        assert!(
            !obj.contains_key("XAttr"),
            "absent XAttr must be omitted from the wire entirely"
        );
        assert_eq!(obj["Hash"], "namehash");
        assert_eq!(obj["Name"], "enc-name");
    }

    /// A present `XAttr` must serialize under the `XAttr` key.
    #[test]
    fn serialize_create_folder_request_includes_xattr_when_present() {
        let req = folders::CreateFolderRequest {
            parent_link_id: "parent-1".into(),
            node_key: "nk".into(),
            node_hash_key: "nhk".into(),
            node_passphrase: "np".into(),
            node_passphrase_signature: "nps".into(),
            signature_email: "sig@addr".into(),
            name: "enc-name".into(),
            hash: "namehash".into(),
            x_attr: Some("enc-xattr".into()),
        };
        let v = serde_json::to_value(&req).expect("serialize");
        let obj = v.as_object().expect("object");
        assert_eq!(obj["XAttr"], "enc-xattr");
    }

    /// `CreateFolderResponse` deserializes the `{ "Folder": { "ID" } }` wire
    /// shape onto `folder.id`.
    #[test]
    fn deserialize_create_folder_response() {
        let body = r#"{ "Code": 1000, "Folder": { "ID": "new-folder-42" } }"#;
        let env: common::ResponseEnvelope<folders::CreateFolderResponse> =
            serde_json::from_str(body).expect("parse");
        assert_eq!(env.code, common::CODE_OK);
        assert_eq!(env.inner.folder.id, "new-folder-42");
    }

    /// Commit request uses `XAttr` (not `XAttribute`), `ChecksumVerified`,
    /// and a `Photo` field that serializes to null for non-photo uploads.
    #[test]
    fn serialize_commit_revision_request_shape() {
        let req = upload::CommitRevisionRequest {
            manifest_signature: "msig".into(),
            signature_address: "sig@addr".into(),
            x_attr: "encrypted-xattr".into(),
            checksum_verified: true,
            photo: None,
        };
        let v = serde_json::to_value(&req).expect("serialize");
        let obj = v.as_object().expect("object");
        assert!(obj.contains_key("XAttr"), "must use XAttr key");
        assert!(obj.contains_key("ChecksumVerified"));
        assert!(obj.contains_key("Photo"));
        assert!(obj["Photo"].is_null(), "non-photo upload sends Photo: null");
        assert_eq!(obj["ChecksumVerified"], true);
    }
}

/// Proves the build-time protobuf codegen produces usable, wire-correct types:
/// constructs representative generated messages and round-trips them through
/// `prost::Message` encode/decode, including a same-package message reference
/// (`proton.drive.sdk.NodeResultPair` -> `proton.drive.sdk.Error` — upstream
/// merged the former `proton.sdk` package into `proton.drive.sdk`, see
/// `reference/VENDORED.md`) and a well-known type (`google.protobuf.Timestamp`).
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod proto_tests {
    use prost::Message as _;

    use crate::proto::proton::drive;

    #[test]
    fn roundtrip_proton_sdk_error_with_enum_and_nested() {
        let original = drive::sdk::Error {
            r#type: "ApiError".to_owned(),
            message: "rate limited".to_owned(),
            domain: drive::sdk::ErrorDomain::Api as i32,
            primary_code: 429,
            secondary_code: 2028,
            context: "upload".to_owned(),
            inner_error: Some(Box::new(drive::sdk::Error {
                message: "retry exhausted".to_owned(),
                domain: drive::sdk::ErrorDomain::Network as i32,
                ..Default::default()
            })),
            additional_data: None,
        };

        let bytes = original.encode_to_vec();
        let decoded =
            drive::sdk::Error::decode(bytes.as_slice()).expect("decode proton.drive.sdk.Error");

        assert_eq!(decoded, original);
        assert_eq!(decoded.domain(), drive::sdk::ErrorDomain::Api);
        assert_eq!(
            decoded.inner_error.as_ref().map(|e| e.domain()),
            Some(drive::sdk::ErrorDomain::Network)
        );
    }

    #[test]
    fn roundtrip_drive_node_result_references_sdk_error() {
        // Exercises the generated message reference
        // (`proton.drive.sdk.NodeResultPair.error: proton.drive.sdk.Error`).
        let original = drive::sdk::NodeResultListResponse {
            results: vec![
                drive::sdk::NodeResultPair {
                    node_uid: "node-ok".to_owned(),
                    error: None,
                },
                drive::sdk::NodeResultPair {
                    node_uid: "node-bad".to_owned(),
                    error: Some(drive::sdk::Error {
                        message: "trash failed".to_owned(),
                        domain: drive::sdk::ErrorDomain::BusinessLogic as i32,
                        ..Default::default()
                    }),
                },
            ],
        };

        let bytes = original.encode_to_vec();
        let decoded = drive::sdk::NodeResultListResponse::decode(bytes.as_slice())
            .expect("decode NodeResultListResponse");

        assert_eq!(decoded, original);
        assert_eq!(decoded.results.len(), 2);
        assert!(decoded.results[0].error.is_none());
        assert_eq!(
            decoded.results[1]
                .error
                .as_ref()
                .map(|e| e.message.as_str()),
            Some("trash failed")
        );
    }

    #[test]
    fn roundtrip_drive_upload_result_with_timestamp() {
        // Pairs a flat Drive message with a well-known-type field to prove the
        // `google.protobuf.Timestamp` import generates and round-trips.
        let upload = drive::sdk::UploadResult {
            node_uid: "uid-1".to_owned(),
            revision_uid: "rev-1".to_owned(),
        };
        let decoded =
            drive::sdk::UploadResult::decode(upload.encode_to_vec().as_slice()).expect("decode");
        assert_eq!(decoded, upload);

        let revision = drive::sdk::FileRevision {
            uid: "rev-1".to_owned(),
            creation_time: Some(prost_types::Timestamp {
                seconds: 1_700_000_000,
                nanos: 0,
            }),
            size_on_cloud_storage: 4096,
            ..Default::default()
        };
        let decoded_rev = drive::sdk::FileRevision::decode(revision.encode_to_vec().as_slice())
            .expect("decode FileRevision");
        assert_eq!(decoded_rev, revision);
        assert_eq!(
            decoded_rev.creation_time.map(|t| t.seconds),
            Some(1_700_000_000)
        );
    }
}
