//! Drive event-subscription wire DTOs.
//!
//! Mirrors the Proton "light events" v2 surface consumed by
//! `client/js/src/internal/events/apiService.ts`:
//! - `GET drive/volumes/{volumeID}/events/latest` → [`GetLatestEventIdResponse`]
//! - `GET drive/v2/volumes/{volumeID}/events/{eventID}` → [`GetVolumeEventsResponse`]
//!   (`ListEventsV2ResponseDto` in the generated OpenAPI types)
//!
//! The v2 response (`ListEventsV2ResponseDto`) reports `More`/`Refresh` as JSON
//! booleans — unlike the deprecated core/share events surface which used the
//! `0|1` integer form. Each event carries a `Link` sub-object
//! (`EventLinkDataDto`) rather than the full node `Link`; only the ids and
//! shared/trashed flags travel on the wire.

use serde::Deserialize;

/// Response from `GET drive/volumes/{volumeID}/events/latest`.
///
/// Used to obtain the resume cursor when no host-persisted cursor exists.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetLatestEventIdResponse {
    #[serde(rename = "EventID")]
    pub event_id: String,
}

/// Response from `GET drive/v2/volumes/{volumeID}/events/{eventID}`.
///
/// `ListEventsV2ResponseDto`. `EventID` is the newest event id seen by the
/// server and becomes the next request cursor (it equals the latest id even
/// when `Events` is empty). `More` signals further pages; `Refresh` signals the
/// client must full-resync because its cursor expired.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetVolumeEventsResponse {
    #[serde(rename = "EventID")]
    pub event_id: String,
    #[serde(default)]
    pub events: Vec<VolumeEventEntry>,
    /// `true` when more events remain beyond this page.
    #[serde(default)]
    pub more: bool,
    /// `true` when the client must discard local state and resync.
    #[serde(default)]
    pub refresh: bool,
}

/// A single volume event (`EventV2ResponseDto`).
///
/// `EventType` map (`VOLUME_EVENT_TYPE_MAP` in the JS SDK):
/// `0` = node deleted, `1` = node created, `2`/`3` = node updated.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VolumeEventEntry {
    #[serde(rename = "EventID")]
    pub event_id: String,
    pub event_type: u8,
    pub link: EventLinkData,
}

/// The link payload carried by a volume event (`EventLinkDataDto`).
///
/// Distinct from the full node [`crate::nodes::Link`]: events ship only the
/// affected link id, its parent, and the shared/trashed flags.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EventLinkData {
    #[serde(rename = "LinkID")]
    pub link_id: String,
    #[serde(rename = "ParentLinkID", default)]
    pub parent_link_id: Option<String>,
    #[serde(default)]
    pub is_shared: bool,
    #[serde(default)]
    pub is_trashed: bool,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::common::{CODE_OK, ResponseEnvelope};

    /// The latest-event endpoint returns just the cursor.
    #[test]
    fn deserialize_latest_event_id() {
        let body = r#"{ "Code": 1000, "EventID": "evt-latest-1" }"#;
        let env: ResponseEnvelope<GetLatestEventIdResponse> =
            serde_json::from_str(body).expect("parse");
        assert_eq!(env.code, CODE_OK);
        assert_eq!(env.inner.event_id, "evt-latest-1");
    }

    /// v2 events list: `More`/`Refresh` are JSON booleans, each event carries a
    /// `Link` sub-object with id/parent/flags.
    #[test]
    fn deserialize_volume_events_v2() {
        let body = r#"{
            "Code": 1000,
            "EventID": "evt-9",
            "More": true,
            "Refresh": false,
            "Events": [
                {
                    "EventID": "evt-8",
                    "EventType": 1,
                    "Link": {
                        "LinkID": "node-a",
                        "ParentLinkID": "root",
                        "IsShared": false,
                        "IsTrashed": false
                    }
                },
                {
                    "EventID": "evt-9",
                    "EventType": 0,
                    "Link": {
                        "LinkID": "node-b",
                        "ParentLinkID": null,
                        "IsShared": true,
                        "IsTrashed": true
                    }
                }
            ]
        }"#;
        let env: ResponseEnvelope<GetVolumeEventsResponse> =
            serde_json::from_str(body).expect("parse");
        assert_eq!(env.code, CODE_OK);
        let resp = env.inner;
        assert_eq!(resp.event_id, "evt-9");
        assert!(resp.more, "More must deserialize from JSON bool true");
        assert!(!resp.refresh);
        assert_eq!(resp.events.len(), 2);

        let created = &resp.events[0];
        assert_eq!(created.event_type, 1);
        assert_eq!(created.link.link_id, "node-a");
        assert_eq!(created.link.parent_link_id.as_deref(), Some("root"));
        assert!(!created.link.is_trashed);

        let deleted = &resp.events[1];
        assert_eq!(deleted.event_type, 0);
        assert!(deleted.link.parent_link_id.is_none());
        assert!(deleted.link.is_shared);
        assert!(deleted.link.is_trashed);
    }

    /// An empty page (no events) still carries the advanced cursor and a
    /// `Refresh` flag the client must honour.
    #[test]
    fn deserialize_refresh_signal() {
        let body = r#"{ "Code": 1000, "EventID": "evt-new", "More": false, "Refresh": true, "Events": [] }"#;
        let env: ResponseEnvelope<GetVolumeEventsResponse> =
            serde_json::from_str(body).expect("parse");
        let resp = env.inner;
        assert!(resp.refresh);
        assert!(resp.events.is_empty());
        assert_eq!(resp.event_id, "evt-new");
    }
}
