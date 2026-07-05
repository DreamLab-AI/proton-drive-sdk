//! Core domain for the Proton Drive SDK.
//!
//! Module layout mirrors `client/js/src/internal/` 1:1 (see ADR-0001):
//! - [`nodes`] — Node aggregate, folder iteration, revisions
//! - [`upload`] / [`download`] — Transfer aggregates
//! - [`events`] — Event subscription, drive events
//!
//! Out-of-scope stubs (ADR-0007 / domain-model §6):
//! - [`shares`], [`sharing`], [`sharing_public`], [`devices`], [`photos`]

#![forbid(unsafe_code)]

pub mod account;
pub mod client;
pub mod config;
pub mod devices;
pub mod download;
pub mod error;
pub mod events;
pub mod http;
pub mod nodes;
pub mod photos;
pub mod shares;
pub mod sharing;
pub mod sharing_public;
pub mod upload;

pub use account::{Author, ProtonDriveAccount};
pub use client::{ProtonDriveClient, ProtonDriveClientOptions};
pub use config::ProtonDriveConfig;
pub use download::{DownloadStats, FileDownloader};
pub use error::{Error, Result};
pub use events::{
    DriveEvent, DriveListener, EventSubscription, FastForwardEvent, InMemoryLatestEventId,
    LatestEventIdProvider, NodeEvent, NodeEventKind, TreeRefreshEvent, TreeRemovalEvent,
};
pub use http::ProtonDriveHttpClient;
pub use nodes::{
    CachedCryptoMaterial, FolderChildrenFilter, MaybeNode, Node, NodeType, NodeUid, Revision,
    make_node_uid,
};
pub use upload::{FileUploader, ProtonFileUploader, UploadController, UploadMetadata};
