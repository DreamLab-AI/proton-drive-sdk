# Domain Model: Proton Drive SDK (Rust port)

This document captures the bounded contexts, aggregates, and ubiquitous language for the Rust port. The model is **derived from `client/js/src/interface/`**, not invented. Naming follows Proton's vocabulary so that file-by-file mapping between JS and Rust holds.

## 1. Bounded Contexts

```
┌─────────────────────────────────────────────────────────────────────┐
│                      ProtonDriveClient (root)                       │
├─────────────┬─────────────┬──────────────┬───────────────┬──────────┤
│  Identity   │   Nodes &   │   Transfer   │    Events     │  Crypto  │
│  (support)  │   Folders   │    (core)    │    (core)     │(support) │
│             │   (core)    │              │               │          │
├─────────────┴─────────────┴──────────────┴───────────────┴──────────┤
│                Cache (support) · Telemetry (generic)                │
└─────────────────────────────────────────────────────────────────────┘
       ▲             ▲             ▲                            ▲
       │             │             │                            │
 host-supplied host-supplied host-supplied                host-supplied
    Account    EntitiesCache  HttpClient                  OpenPgpCrypto
                CryptoCache                                 SrpModule
```

Sync is a sixth, later-added bounded context: its own box, hanging off
**Nodes & Folders** (not Events). See `domain-model-sync.md` §1 for that half
of the map and the reasoning.

Core vs supporting follows Eric Evans' definitions: **core** is where Drive correctness is determined; **supporting** sub-domains exist to make core possible.

### 1.1 Identity (supporting)
The SDK does **not** model users, sessions, or login. The host supplies a `ProtonDriveAccount` that resolves: the active user identifier, their address(es), and the cryptographic material to decrypt content addressed to them. The crate's job is to consume this, not to manufacture it.

### 1.2 Nodes & Folders (core)
The heart of the model. A **Node** is the polymorphic unit of storage. Subtypes:

- **Folder**: has children, has a hash key for child-name indexing.
- **File**: has revisions.
- **Album** (photos context): folder-like with extra attributes.

Each Node belongs to a **Share** (the unit of cryptographic root) inside a **Volume** (the unit of billing/quota). The `NodeUid` encodes `(volumeId, nodeId)` and is the public stable handle.

A Node can be in states: `active`, `trashed`, `degraded` (decryption succeeded partially), `missing` (referenced but unfetchable).

### 1.3 Transfer (core)
Two aggregates, both per-operation. `UploadJob`/`DownloadJob` are the JS-mirrored
names for this concept; the Rust port never created matching types under those
names. The behaviour lands as the `FileUploader`/`FileDownloader` traits in
`proton-drive-core::{upload,download}`, plus, at the app layer, `pdtui`'s own
`Transfer` queue entry (`domain-model-mvp.md` §Transfer) that drives one call
and tracks its progress for the UI:

- **UploadJob**: owns a `FileUploader` from the SDK. Tracks `(parentNodeUid, name, expectedSize, expectedSha1?, mediaType, modificationTime?)`. State: queued → in-flight → completed/failed/cancelled. Emits `UploadedBytes` progress.
- **DownloadJob**: owns a `FileDownloader`. Tracks `(nodeUid, claimedSize?, integrityChecks)`. State as above. Emits `DownloadedBytes` progress.

Integrity is part of the aggregate, not a cross-cutting concern: an upload that completes without SHA1 match is a *failed* upload.

### 1.4 Events (core)
Two distinct event streams in the JS model, both preserved:

- **DriveEvent** stream: per-volume change feed (`NodeEvent`, `TreeRefreshEvent`, `TreeRemovalEvent`, `FastForwardEvent`, `SharedWithMeUpdated`).
- **SDKEvent** stream: process-internal signals (e.g. cache invalidation, settings change).

An **EventSubscription** is an aggregate root with a single lifetime: born from `subscribe_drive_events`, dies on `cancel()` or process exit. It owns the cursor (`latestEventId`) and is the only sanctioned way to keep a UI fresh; polling is forbidden.

See `domain-model-sync.md` for the separate **Sync** context (local↔remote hash-based reconciliation) that consumes this event stream to detect snapshot staleness.

### 1.5 Crypto (supporting)
Defined in ADR-0002. Aggregates here are pure value objects:

- **KeyMaterial**: armoured private keys plus their decrypted handles, cached per-Node, per-Share.
- **SessionKey**: symmetric key and algorithm tag (`gcm` for AEAD, otherwise SEIPDv1 cipher).
- **SignatureContext**: string plus critical flag, attached to every Drive-emitted signature.

### 1.6 Cache (supporting)
Two caches, two lifecycles (per ADR-0005):

- **EntitiesCache**: keyed by `NodeUid` or similar, holds serialised metadata. Survives any auth event.
- **CryptoCache**: keyed by Node/Share, holds `CachedCryptoMaterial`. Wiped on sign-out or key rotation.

### 1.7 Telemetry (generic)
Counters and timings emitted to a host-supplied sink. No business logic. We re-export `MetricEvent` variants from the JS model verbatim because Proton has telemetry expectations even for personal clients (e.g. degraded-decryption reporting).

## 2. Ubiquitous Language

Names appear identically in code, docs, commits, and PR titles.

| Term | Meaning | Anti-name |
|---|---|---|
| **Node** | The polymorphic storage unit (file or folder or album) | "item", "entry", "object" |
| **NodeUid** | Stable handle = `(volumeId, nodeId)` | "id", "path", "key" |
| **Share** | Cryptographic root of a subtree | "namespace", "scope" |
| **Volume** | Account-level container; one per user typically | "drive", "root" |
| **Revision** | An immutable version of a file's content | "version", "snapshot" |
| **Author** | Identity that produced a node or signature | "owner", "creator" |
| **Membership** | A user's relationship to a Share (role + state) | "permission" |
| **Bookmark** | A saved reference to a public link | "favourite", "shortcut" |
| **Degraded** node | Partial decryption succeeded | "broken", "partial" |
| **FileUploader / FileDownloader** | Transfer engine for one operation | "transfer", "session" |
| **EventSubscription** | Active feed of `DriveEvent`s | "watcher", "listener" |
| **Hash key** | Per-folder key for deterministic child-name hashing | "name hash", "child key" |
| **Address key** | A user-address-bound OpenPGP key | "user key" |
| **SignatureContext** | Critical-notation string tying a signature to its semantic role | "purpose", "tag" |

## 3. Aggregate-to-Module Mapping

| Aggregate | JS module | Rust module |
|---|---|---|
| Node, Folder | `internal/nodes/` | `proton-drive-core::nodes` |
| Share, Membership | `internal/shares/`, `internal/sharing/` | `proton-drive-core::shares` (v1 stub) |
| Revision | `internal/nodes/`, mixed | `proton-drive-core::nodes::revision` |
| UploadJob *(concept only; landed as `FileUploader`)* | `internal/upload/` | `proton-drive-core::upload` |
| DownloadJob *(concept only; landed as `FileDownloader`)* | `internal/download/` | `proton-drive-core::download` |
| EventSubscription, DriveEvent | `internal/events/`, `sdkEvents.ts` | `proton-drive-core::events` |
| Album, PhotoNode, PhotoAttributes | `internal/photos/` | `proton-drive-core::photos` (v1 stub) |
| Bookmark, PublicLink | `internal/sharingPublic/` | `proton-drive-core::sharing_public` (v1 stub) |
| KeyMaterial, SessionKey | `crypto/` | `proton-drive-crypto::material` |
| EntitiesCache, CryptoCache | `cache/` | `proton-drive-cache::memory` |
| Telemetry, MetricEvent | `telemetry.ts` | `proton-drive-telemetry` |
| LocalIndex, RemoteSnapshot, SyncPlan | *(none; Rust-only, see `domain-model-sync.md`)* | `proton-drive-sync` |

## 4. Anti-corruption Boundaries

- **HTTP / wire types** (`internal/apiService/*Types.ts`) are **not** part of the domain. They live in `proton-drive-api` and are translated at the boundary. Domain types never carry generated OpenAPI struct fields.
- **OpenPGP packet structures** (`rpgp` types) are **not** part of the domain. They are wrapped in `KeyMaterial` / `SessionKey` value objects. Call sites in `proton-drive-core` never see an `rpgp::Message`.
- **Terminal types** (ratatui widgets) are **not** part of the domain. `pdtui` owns its own view-model that projects from domain aggregates.

These three boundaries are enforceable by `cargo deny`-style module-visibility lints; see `proton-drive-core/src/lib.rs` for the re-export gate.

## 5. Invariants

Encoded as compile-time types where possible, runtime assertions otherwise.

1. **A FileDownloader integrity-verifies by default.** `unsafe_download_to_stream` exists, mirrors the JS API, and is the only escape hatch.
2. **An UploadJob without `expectedSize` cannot start.** Server uses it for integrity; missing it is a programming error.
3. **A Node is queried by `NodeUid` only.** Raw `nodeId` requires explicit `make_node_uid(volume, node)`.
4. **A cached crypto material has a deletion path.** When an Address rotates, the CryptoCache is wiped for that subtree.
5. **An EventSubscription is the only sync mechanism.** No timer-driven `iter_folder_children` calls allowed in production code (lint).

## 6. Out-of-Scope Aggregates (v1)

These exist in the JS SDK and are deliberately stubbed in the Rust port:

- Devices (`ProtonDriveClient.{createDevice, renameDevice, deleteDevice, getDevice}`)
- Sharing (proton invitations, non-proton invitations, member management)
- Public links (creation, password rotation)
- Bookmarks
- Photos (albums, photo-specific attributes, tags)
- Trash management beyond "do not display"

Each maps to a module that exposes its types but returns `Error::NotImplemented` from operations. See ADR-0007 for scope rationale.
