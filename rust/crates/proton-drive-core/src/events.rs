//! Event subscription aggregate. Mirrors `client/js/src/interface/events.ts` plus
//! the volume polling loop in `client/js/src/internal/events/`.
//!
//! Sync is **event-based polling** (never recursive tree traversal): a
//! background task repeatedly drains `GET drive/v2/volumes/{volumeID}/events/
//! {eventID}`, maps each raw event onto a [`DriveEvent`], dispatches to the
//! host [`DriveListener`], and advances a resume cursor persisted through the
//! host's [`LatestEventIdProvider`]. The server's `Refresh` flag triggers a
//! [`DriveEvent::TreeRefresh`] full-resync; `More` drives pagination within a
//! single poll tick.
//!
//! This mirrors the *callback-based* subscription path
//! (`subscribeToTreeEvents`/`EventManager`/`VolumeEventManager`) that upstream
//! JS/C# now mark deprecated in favour of a host-driven pull iterator
//! (`iterateEvents`/`EnumerateEventsAsync`). That newer surface is a
//! deliberate, documented divergence — see "v0.19 alignment" in
//! `docs/audit-2026-07-05.md` — not implemented here because it is a new
//! public API shape, not a payload/naming tweak.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::error::{Error, Result};
use crate::http::{HttpMethod, JsonRequest, ProtonDriveHttpClient};
use crate::nodes::{NodeUid, make_node_uid};
use proton_drive_api::common::{CODE_OK, ResponseEnvelope};
use proton_drive_api::events::{
    GetLatestEventIdResponse, GetVolumeEventsResponse, VolumeEventEntry,
};

#[derive(Debug, Clone)]
pub enum DriveEvent {
    Node(NodeEvent),
    TreeRefresh(TreeRefreshEvent),
    TreeRemoval(TreeRemovalEvent),
    FastForward(FastForwardEvent),
    SharedWithMeUpdated,
}

#[derive(Debug, Clone)]
pub struct NodeEvent {
    pub uid: NodeUid,
    /// Parent of the affected node, when the server reports one. Mirrors JS
    /// `NodeEvent.parentNodeUid` (`client/js/src/internal/events/apiService.ts`
    /// `getVolumeEvents`, which sets it from `event.Link.ParentLinkID`);
    /// `None` when the wire payload carries no `ParentLinkID`.
    pub parent_uid: Option<NodeUid>,
    pub kind: NodeEventKind,
    /// Mirrors JS `NodeEvent.isShared` (`event.Link.IsShared` on the same wire
    /// entry) — previously parsed off the wire into [`EventLinkData`] but
    /// dropped instead of surfaced on the domain event.
    pub is_shared: bool,
    /// The individual event's own id (`EventID` on the event entry), distinct
    /// from the page cursor returned in [`DrainResult::cursor`]. Mirrors JS
    /// `NodeEvent.eventId`.
    pub event_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeEventKind {
    Created,
    Updated,
    Trashed,
    Restored,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone)]
pub struct TreeRefreshEvent {
    pub root: NodeUid,
    /// The event id the server advanced to when it signalled the refresh.
    /// Mirrors JS `TreeRefreshEvent.eventId` / C# `EventsContinuityLostEvent`'s
    /// carried id (`client/js/src/internal/events/volumeEventManager.ts`,
    /// `Proton.Drive.Sdk/Volumes/VolumeOperations.cs` `EnumerateEventsAsync`).
    pub new_event_id: String,
}

#[derive(Debug, Clone)]
pub struct TreeRemovalEvent {
    pub root: NodeUid,
}

#[derive(Debug, Clone)]
pub struct FastForwardEvent {
    pub new_event_id: String,
}

/// Host-installed sink for drive events. Mirrors JS `DriveListener`.
#[async_trait]
pub trait DriveListener: Send + Sync {
    async fn on_event(&self, event: DriveEvent);
}

/// Lifetime handle for an event subscription. Dropping cancels the feed.
pub struct EventSubscription {
    pub(crate) cancel: CancellationToken,
}

impl EventSubscription {
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Host-supplied storage for the last-seen event id (resume cursor).
/// Mirrors JS `LatestEventIdProvider`.
#[async_trait]
pub trait LatestEventIdProvider: Send + Sync {
    async fn get(&self) -> Result<Option<String>>;
    async fn set(&self, event_id: &str) -> Result<()>;
}

/// Default in-memory resume cursor used when the host wires no
/// [`LatestEventIdProvider`]. Holds the cursor for the lifetime of the
/// subscription only — nothing is persisted across process restarts, so each
/// fresh subscription starts from the server's latest event id.
#[derive(Debug, Default)]
pub struct InMemoryLatestEventId {
    inner: Mutex<Option<String>>,
}

impl InMemoryLatestEventId {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}

#[async_trait]
impl LatestEventIdProvider for InMemoryLatestEventId {
    async fn get(&self) -> Result<Option<String>> {
        Ok(self.inner.lock().await.clone())
    }

    async fn set(&self, event_id: &str) -> Result<()> {
        *self.inner.lock().await = Some(event_id.to_owned());
        Ok(())
    }
}

// ── event polling ───────────────────────────────────────────────────────────

/// Base poll interval for an owned volume. Mirrors JS
/// `OWN_VOLUME_POLLING_INTERVAL` (30s).
const POLL_INTERVAL_SECS: u64 = 30;

/// Fibonacci backoff multipliers applied to [`POLL_INTERVAL_SECS`] on
/// consecutive transient failures. Mirrors JS `FIBONACCI_LIST`.
const BACKOFF_FIB: [u64; 7] = [1, 1, 2, 3, 5, 8, 13];

/// Map a raw volume event onto a domain [`DriveEvent`].
///
/// `EventType` map (`VOLUME_EVENT_TYPE_MAP` in the JS SDK):
/// `0` = deleted, `1` = created, `2`/`3` = updated. The trashed/restored
/// distinction is derived from the event's `IsTrashed` flag, matching how the
/// JS listener interprets metadata updates.
///
/// Carries through `parent_uid`/`is_shared`/`event_id` — already parsed off
/// the wire into [`EventLinkData`]/[`VolumeEventEntry`] but previously dropped
/// here — so the domain event has the same payload fields as JS `NodeEvent`
/// (`client/js/src/internal/events/apiService.ts` `getVolumeEvents`).
#[must_use]
pub fn map_volume_event(volume_id: &str, entry: &VolumeEventEntry) -> DriveEvent {
    let uid = make_node_uid(volume_id, entry.link.link_id.clone());
    let parent_uid = entry
        .link
        .parent_link_id
        .clone()
        .map(|parent_id| make_node_uid(volume_id, parent_id));
    let kind = match entry.event_type {
        0 => NodeEventKind::Deleted,
        1 => NodeEventKind::Created,
        // 2/3 are metadata/content updates; a trashed flag promotes the update
        // to a Trashed signal so listeners can prune without a separate fetch.
        _ if entry.link.is_trashed => NodeEventKind::Trashed,
        _ => NodeEventKind::Updated,
    };
    DriveEvent::Node(NodeEvent {
        uid,
        parent_uid,
        kind,
        is_shared: entry.link.is_shared,
        event_id: entry.event_id.clone(),
    })
}

/// Outcome of one full drain of a volume's event feed (one poll tick).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainResult {
    /// Cursor to persist and resume from on the next tick.
    pub cursor: String,
    /// Set when the server signalled a full resync — the loop should stop
    /// draining for this tick after emitting [`DriveEvent::TreeRefresh`].
    pub refreshed: bool,
}

/// Drain a volume's event feed starting at `cursor`, dispatching each derived
/// [`DriveEvent`] to `listener`, and return the advanced cursor.
///
/// Mirrors `VolumeEventManager.getEvents` + `EventManager.processEvents`:
/// - Pages while the server reports `More`.
/// - On `Refresh`, emits a single [`DriveEvent::TreeRefresh`] and stops.
/// - On an empty page whose cursor advanced past the request id, emits a
///   [`DriveEvent::FastForward`] so inactive volumes do not drift, then stops.
/// - Otherwise maps and dispatches each event, advancing the cursor.
///
/// Listener dispatch happens inline (sequential) exactly like the JS
/// `notifyListeners`. The caller persists [`DrainResult::cursor`].
pub async fn drain_volume_events(
    http: &Arc<dyn ProtonDriveHttpClient>,
    volume_id: &str,
    listener: &dyn DriveListener,
    mut cursor: String,
) -> Result<DrainResult> {
    loop {
        let request_cursor = cursor.clone();
        let resp = fetch_volume_events(http, volume_id, &request_cursor).await?;

        cursor = resp.event_id.clone();

        if resp.refresh {
            listener
                .on_event(DriveEvent::TreeRefresh(TreeRefreshEvent {
                    root: make_node_uid(volume_id, volume_id),
                    new_event_id: cursor.clone(),
                }))
                .await;
            return Ok(DrainResult {
                cursor,
                refreshed: true,
            });
        }

        if resp.events.is_empty() {
            // Empty page: fast-forward the cursor if the server advanced it,
            // so an idle volume keeps its resume point fresh, then stop.
            if resp.event_id != request_cursor {
                listener
                    .on_event(DriveEvent::FastForward(FastForwardEvent {
                        new_event_id: resp.event_id.clone(),
                    }))
                    .await;
            }
            return Ok(DrainResult {
                cursor,
                refreshed: false,
            });
        }

        for entry in &resp.events {
            listener.on_event(map_volume_event(volume_id, entry)).await;
        }

        if !resp.more {
            return Ok(DrainResult {
                cursor,
                refreshed: false,
            });
        }

        // `More`: keep draining from the advanced cursor. Guard against a
        // misbehaving server that sets `More` without advancing the cursor —
        // continuing would spin forever requesting the same page.
        if cursor == request_cursor {
            tracing::warn!(
                volume_id = %volume_id,
                cursor = %cursor,
                "server set More without advancing the cursor — stopping drain"
            );
            return Ok(DrainResult {
                cursor,
                refreshed: false,
            });
        }
    }
}

/// Fetch the newest event id for a volume — the starting cursor when the host
/// supplies no persisted resume point.
pub async fn fetch_latest_event_id(
    http: &Arc<dyn ProtonDriveHttpClient>,
    volume_id: &str,
) -> Result<String> {
    let path = format!("/drive/volumes/{volume_id}/events/latest");
    let resp = http_get(http, &path).await?;
    check_code(&resp)?;
    let env: ResponseEnvelope<GetLatestEventIdResponse> = serde_json::from_slice(&resp)
        .map_err(|e| Error::Internal(format!("latest-event JSON: {e}")))?;
    Ok(env.inner.event_id)
}

async fn fetch_volume_events(
    http: &Arc<dyn ProtonDriveHttpClient>,
    volume_id: &str,
    event_id: &str,
) -> Result<GetVolumeEventsResponse> {
    let path = format!("/drive/v2/volumes/{volume_id}/events/{event_id}");
    let resp = http_get(http, &path).await?;
    check_code(&resp)?;
    let env: ResponseEnvelope<GetVolumeEventsResponse> =
        serde_json::from_slice(&resp).map_err(|e| Error::Internal(format!("events JSON: {e}")))?;
    Ok(env.inner)
}

async fn http_get(http: &Arc<dyn ProtonDriveHttpClient>, path: &str) -> Result<bytes::Bytes> {
    let req = JsonRequest {
        method: HttpMethod::Get,
        path: path.to_owned(),
        query: vec![],
        headers: vec![],
        body: None,
    };
    let resp = http.request_json(req).await?;
    Ok(resp.body)
}

/// Inspect the Proton `Code`/`Error` envelope *before* attempting to decode the
/// full payload. Error responses (e.g. 2501) omit the success-shape fields, so
/// decoding the typed envelope first would surface a misleading JSON parse
/// error instead of the real domain error (and would mask `NotFound`, which the
/// poll loop must distinguish to emit a terminal `TreeRemoval`).
fn check_code(body: &[u8]) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct CodeOnly {
        #[serde(rename = "Code", default)]
        code: u32,
        #[serde(rename = "Error", default)]
        error: Option<String>,
    }
    let head: CodeOnly =
        serde_json::from_slice(body).map_err(|e| Error::Internal(format!("envelope JSON: {e}")))?;
    if head.code == CODE_OK {
        return Ok(());
    }
    let msg = head
        .error
        .unwrap_or_else(|| format!("API error {}", head.code));
    Err(if head.code == 2501 {
        Error::NotFound(msg)
    } else {
        Error::Internal(msg)
    })
}

/// Spawn the background polling loop for a single volume's event feed.
///
/// Returns an [`EventSubscription`]; dropping or cancelling it stops the loop
/// at the next await point. The loop:
/// 1. resolves the start cursor (host provider, else server latest),
/// 2. drains events each tick via [`drain_volume_events`], persisting the
///    advanced cursor through `provider`,
/// 3. waits [`POLL_INTERVAL_SECS`] between ticks (Fibonacci backoff on
///    transient errors), and
/// 4. exits cleanly when the [`CancellationToken`] fires.
///
/// A [`DriveEvent::TreeRemoval`] is emitted and the loop stops if the volume's
/// events become permanently inaccessible (server `NotFound`), mirroring the
/// JS `TreeRemove` terminal event.
pub fn spawn_volume_event_loop(
    http: Arc<dyn ProtonDriveHttpClient>,
    volume_id: String,
    listener: Box<dyn DriveListener>,
    provider: Arc<dyn LatestEventIdProvider>,
) -> EventSubscription {
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();

    tokio::spawn(async move {
        // ── resolve the start cursor ────────────────────────────────────────
        let mut cursor = match resolve_start_cursor(&http, &volume_id, &provider).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    volume_id = %volume_id,
                    "could not resolve start cursor: {e} — event loop will not start"
                );
                return;
            }
        };

        let mut retry: usize = 0;
        loop {
            // Wait for the poll interval (with backoff) or cancellation.
            let wait = POLL_INTERVAL_SECS * BACKOFF_FIB[retry.min(BACKOFF_FIB.len() - 1)];
            tokio::select! {
                () = task_cancel.cancelled() => {
                    tracing::debug!(volume_id = %volume_id, "event loop cancelled");
                    return;
                }
                () = tokio::time::sleep(std::time::Duration::from_secs(wait)) => {}
            }

            // Re-check cancellation before issuing the next request.
            if task_cancel.is_cancelled() {
                return;
            }

            match drain_volume_events(&http, &volume_id, listener.as_ref(), cursor.clone()).await {
                Ok(outcome) => {
                    cursor = outcome.cursor;
                    if let Err(e) = provider.set(&cursor).await {
                        tracing::warn!(
                            volume_id = %volume_id,
                            "failed to persist event cursor: {e}"
                        );
                    }
                    retry = 0;
                }
                Err(Error::NotFound(msg)) => {
                    // Volume events permanently gone: emit a terminal removal
                    // and stop the loop (JS `TreeRemove`).
                    tracing::info!(volume_id = %volume_id, "volume events removed: {msg}");
                    listener
                        .on_event(DriveEvent::TreeRemoval(TreeRemovalEvent {
                            root: make_node_uid(&volume_id, &volume_id),
                        }))
                        .await;
                    return;
                }
                Err(e) => {
                    tracing::warn!(
                        volume_id = %volume_id,
                        retry,
                        "event poll failed: {e} (cursor {cursor})"
                    );
                    retry = retry.saturating_add(1);
                }
            }
        }
    });

    EventSubscription { cancel }
}

/// Determine the cursor to resume from: the host-persisted value if present,
/// otherwise the server's latest event id (which is also persisted so the next
/// tick resumes consistently).
async fn resolve_start_cursor(
    http: &Arc<dyn ProtonDriveHttpClient>,
    volume_id: &str,
    provider: &Arc<dyn LatestEventIdProvider>,
) -> Result<String> {
    if let Some(cursor) = provider.get().await? {
        return Ok(cursor);
    }
    let latest = fetch_latest_event_id(http, volume_id).await?;
    provider.set(&latest).await?;
    Ok(latest)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::http::{BlobRequest, JsonRequest, JsonResponse};
    use bytes::Bytes;
    use proton_drive_api::events::{EventLinkData, VolumeEventEntry};
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    const VOLUME: &str = "vol-test-1";

    // ── recording listener ────────────────────────────────────────────────────

    /// Captures every dispatched [`DriveEvent`] for assertions.
    #[derive(Default)]
    struct RecordingListener {
        events: Arc<StdMutex<Vec<DriveEvent>>>,
    }

    impl RecordingListener {
        fn new() -> (Self, Arc<StdMutex<Vec<DriveEvent>>>) {
            let events = Arc::new(StdMutex::new(Vec::new()));
            (
                Self {
                    events: Arc::clone(&events),
                },
                events,
            )
        }
    }

    #[async_trait]
    impl DriveListener for RecordingListener {
        async fn on_event(&self, event: DriveEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    // ── queue-backed mock HTTP client ─────────────────────────────────────────

    /// Serves a FIFO queue of `(status_path_substring, body)` responses. The
    /// drain loop issues sequential GETs; the latest-event endpoint and each
    /// events page are matched by substring so a single queue suffices.
    struct MockHttp {
        /// Each entry matches by path substring; consumed on first match in order.
        queue: StdMutex<Vec<(String, Bytes)>>,
        /// Fallback when the queue is exhausted (e.g. a NotFound envelope).
        fallback: Bytes,
    }

    impl MockHttp {
        fn new(responses: Vec<(&str, String)>) -> Self {
            Self {
                queue: StdMutex::new(
                    responses
                        .into_iter()
                        .map(|(k, v)| (k.to_owned(), Bytes::from(v)))
                        .collect(),
                ),
                fallback: Bytes::from(r#"{"Code":2501,"Error":"not found"}"#),
            }
        }

        fn arc(self) -> Arc<dyn ProtonDriveHttpClient> {
            Arc::new(self)
        }
    }

    #[async_trait]
    impl ProtonDriveHttpClient for MockHttp {
        async fn request_json(&self, req: JsonRequest) -> Result<JsonResponse> {
            let body = {
                let mut q = self.queue.lock().unwrap();
                let idx = q.iter().position(|(k, _)| req.path.contains(k.as_str()));
                match idx {
                    Some(i) => q.remove(i).1,
                    None => self.fallback.clone(),
                }
            };
            Ok(JsonResponse {
                status: 200,
                headers: vec![],
                body,
            })
        }

        async fn request_blob(&self, _req: BlobRequest) -> Result<JsonResponse> {
            Err(Error::Internal("blob not used in event tests".into()))
        }
    }

    fn events_page(
        cursor: &str,
        more: bool,
        refresh: bool,
        events: &[(&str, &str, u8, bool)],
    ) -> String {
        let entries: Vec<serde_json::Value> = events
            .iter()
            .map(|(event_id, link_id, event_type, trashed)| {
                serde_json::json!({
                    "EventID": event_id,
                    "EventType": event_type,
                    "Link": {
                        "LinkID": link_id,
                        "ParentLinkID": "root",
                        "IsShared": false,
                        "IsTrashed": trashed,
                    }
                })
            })
            .collect();
        serde_json::json!({
            "Code": 1000,
            "EventID": cursor,
            "More": more,
            "Refresh": refresh,
            "Events": entries,
        })
        .to_string()
    }

    /// Let the spawned event loop make progress under a paused clock: yield so
    /// it registers its sleep, advance past the poll interval, then yield
    /// repeatedly so the multi-await drain runs to completion.
    async fn pump(secs: u64) {
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(secs)).await;
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
    }

    fn entry(event_id: &str, link_id: &str, event_type: u8, trashed: bool) -> VolumeEventEntry {
        VolumeEventEntry {
            event_id: event_id.to_owned(),
            event_type,
            link: EventLinkData {
                link_id: link_id.to_owned(),
                parent_link_id: Some("root".to_owned()),
                is_shared: false,
                is_trashed: trashed,
            },
        }
    }

    // ── event-type → DriveEvent mapping ───────────────────────────────────────

    #[test]
    fn maps_event_types_to_node_event_kinds() {
        let created = map_volume_event(VOLUME, &entry("e1", "n1", 1, false));
        match created {
            DriveEvent::Node(NodeEvent { uid, kind, .. }) => {
                assert_eq!(uid, make_node_uid(VOLUME, "n1"));
                assert_eq!(kind, NodeEventKind::Created);
            }
            other => panic!("expected Node(Created), got {other:?}"),
        }

        let deleted = map_volume_event(VOLUME, &entry("e2", "n2", 0, false));
        assert!(matches!(
            deleted,
            DriveEvent::Node(NodeEvent {
                kind: NodeEventKind::Deleted,
                ..
            })
        ));

        let updated = map_volume_event(VOLUME, &entry("e3", "n3", 2, false));
        assert!(matches!(
            updated,
            DriveEvent::Node(NodeEvent {
                kind: NodeEventKind::Updated,
                ..
            })
        ));

        // EventType 3 is also an update.
        let updated_meta = map_volume_event(VOLUME, &entry("e4", "n4", 3, false));
        assert!(matches!(
            updated_meta,
            DriveEvent::Node(NodeEvent {
                kind: NodeEventKind::Updated,
                ..
            })
        ));

        // A trashed flag on an update promotes it to Trashed.
        let trashed = map_volume_event(VOLUME, &entry("e5", "n5", 2, true));
        assert!(matches!(
            trashed,
            DriveEvent::Node(NodeEvent {
                kind: NodeEventKind::Trashed,
                ..
            })
        ));
    }

    // ── payload fields: parent/shared/event-id carried through (v0.19 align) ──

    /// `parent_uid`, `is_shared`, and the per-event `event_id` are parsed off
    /// the wire (`EventLinkData`/`VolumeEventEntry`) but were previously
    /// dropped by `map_volume_event`. Mirrors JS `NodeEvent.parentNodeUid` /
    /// `.isShared` / `.eventId` (`client/js/src/internal/events/apiService.ts`
    /// `getVolumeEvents`).
    #[test]
    fn maps_parent_uid_is_shared_and_event_id() {
        let e = VolumeEventEntry {
            event_id: "e42".to_owned(),
            event_type: 2,
            link: EventLinkData {
                link_id: "child".to_owned(),
                parent_link_id: Some("parent-1".to_owned()),
                is_shared: true,
                is_trashed: false,
            },
        };
        match map_volume_event(VOLUME, &e) {
            DriveEvent::Node(NodeEvent {
                uid,
                parent_uid,
                is_shared,
                event_id,
                ..
            }) => {
                assert_eq!(uid, make_node_uid(VOLUME, "child"));
                assert_eq!(parent_uid, Some(make_node_uid(VOLUME, "parent-1")));
                assert!(is_shared);
                assert_eq!(event_id, "e42");
            }
            other => panic!("expected Node event, got {other:?}"),
        }
    }

    /// A missing `ParentLinkID` on the wire (e.g. a deleted top-level item)
    /// maps to `parent_uid: None` rather than a fabricated uid.
    #[test]
    fn maps_missing_parent_link_id_to_none() {
        let e = VolumeEventEntry {
            event_id: "e43".to_owned(),
            event_type: 0,
            link: EventLinkData {
                link_id: "gone".to_owned(),
                parent_link_id: None,
                is_shared: false,
                is_trashed: false,
            },
        };
        match map_volume_event(VOLUME, &e) {
            DriveEvent::Node(NodeEvent { parent_uid, .. }) => assert!(parent_uid.is_none()),
            other => panic!("expected Node event, got {other:?}"),
        }
    }

    // ── drain: cursor advancement ─────────────────────────────────────────────

    #[tokio::test]
    async fn drain_advances_cursor_and_dispatches_events() {
        let http = MockHttp::new(vec![(
            "/drive/v2/volumes/vol-test-1/events/cursor-0",
            events_page(
                "cursor-1",
                false,
                false,
                &[("cursor-1", "node-a", 1, false)],
            ),
        )])
        .arc();
        let (listener, captured) = RecordingListener::new();

        let outcome = drain_volume_events(&http, VOLUME, &listener, "cursor-0".to_owned())
            .await
            .unwrap();

        assert_eq!(outcome.cursor, "cursor-1", "cursor must advance to EventID");
        assert!(!outcome.refreshed);
        let evs = captured.lock().unwrap();
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            DriveEvent::Node(NodeEvent {
                kind: NodeEventKind::Created,
                ..
            })
        ));
    }

    // ── drain: More pagination keeps draining ─────────────────────────────────

    #[tokio::test]
    async fn drain_follows_more_pagination() {
        let http = MockHttp::new(vec![
            (
                "/drive/v2/volumes/vol-test-1/events/cursor-0",
                events_page("cursor-1", true, false, &[("cursor-1", "node-a", 1, false)]),
            ),
            (
                "/drive/v2/volumes/vol-test-1/events/cursor-1",
                events_page(
                    "cursor-2",
                    false,
                    false,
                    &[("cursor-2", "node-b", 2, false)],
                ),
            ),
        ])
        .arc();
        let (listener, captured) = RecordingListener::new();

        let outcome = drain_volume_events(&http, VOLUME, &listener, "cursor-0".to_owned())
            .await
            .unwrap();

        assert_eq!(outcome.cursor, "cursor-2", "drains across both pages");
        let evs = captured.lock().unwrap();
        assert_eq!(evs.len(), 2, "events from both pages dispatched");
    }

    // ── drain: More without cursor advance does not spin ──────────────────────

    #[tokio::test]
    async fn drain_stops_when_more_set_but_cursor_stalls() {
        // Server pathologically reports More=true while echoing the same cursor.
        // A single queued response (consumed once) means a spinning loop would
        // fall through to the NotFound fallback; the guard must stop first.
        let http = MockHttp::new(vec![(
            "/drive/v2/volumes/vol-test-1/events/cursor-0",
            events_page("cursor-0", true, false, &[("cursor-0", "node-a", 1, false)]),
        )])
        .arc();
        let (listener, captured) = RecordingListener::new();

        let outcome = drain_volume_events(&http, VOLUME, &listener, "cursor-0".to_owned())
            .await
            .unwrap();

        assert_eq!(outcome.cursor, "cursor-0");
        assert!(!outcome.refreshed);
        // The one real event was dispatched; the loop did not spin into the
        // NotFound fallback (which would have errored).
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    // ── drain: Refresh signals full resync ────────────────────────────────────

    #[tokio::test]
    async fn drain_emits_tree_refresh_on_refresh_flag() {
        let http = MockHttp::new(vec![(
            "/drive/v2/volumes/vol-test-1/events/cursor-0",
            events_page("cursor-refresh", false, true, &[]),
        )])
        .arc();
        let (listener, captured) = RecordingListener::new();

        let outcome = drain_volume_events(&http, VOLUME, &listener, "cursor-0".to_owned())
            .await
            .unwrap();

        assert!(outcome.refreshed, "refresh flag must be reported");
        assert_eq!(outcome.cursor, "cursor-refresh");
        let evs = captured.lock().unwrap();
        assert_eq!(evs.len(), 1);
        match &evs[0] {
            DriveEvent::TreeRefresh(TreeRefreshEvent { root, new_event_id }) => {
                assert_eq!(*root, make_node_uid(VOLUME, VOLUME));
                assert_eq!(new_event_id, "cursor-refresh");
            }
            other => panic!("expected TreeRefresh, got {other:?}"),
        }
    }

    // ── drain: empty page advances cursor via FastForward ─────────────────────

    #[tokio::test]
    async fn drain_fast_forwards_empty_advanced_page() {
        let http = MockHttp::new(vec![(
            "/drive/v2/volumes/vol-test-1/events/cursor-0",
            events_page("cursor-7", false, false, &[]),
        )])
        .arc();
        let (listener, captured) = RecordingListener::new();

        let outcome = drain_volume_events(&http, VOLUME, &listener, "cursor-0".to_owned())
            .await
            .unwrap();

        assert_eq!(outcome.cursor, "cursor-7");
        let evs = captured.lock().unwrap();
        assert_eq!(evs.len(), 1);
        assert!(matches!(&evs[0], DriveEvent::FastForward(_)));
    }

    // ── drain: empty page with unchanged cursor yields nothing ────────────────

    #[tokio::test]
    async fn drain_idle_unchanged_cursor_yields_no_events() {
        let http = MockHttp::new(vec![(
            "/drive/v2/volumes/vol-test-1/events/cursor-0",
            events_page("cursor-0", false, false, &[]),
        )])
        .arc();
        let (listener, captured) = RecordingListener::new();

        let outcome = drain_volume_events(&http, VOLUME, &listener, "cursor-0".to_owned())
            .await
            .unwrap();

        assert_eq!(outcome.cursor, "cursor-0");
        assert!(captured.lock().unwrap().is_empty());
    }

    // ── in-memory provider round-trips the cursor ─────────────────────────────

    #[tokio::test]
    async fn in_memory_provider_persists_cursor() {
        let provider = InMemoryLatestEventId::new();
        assert!(provider.get().await.unwrap().is_none());
        provider.set("cursor-x").await.unwrap();
        assert_eq!(provider.get().await.unwrap().as_deref(), Some("cursor-x"));
    }

    // ── start cursor: provider value wins; else server latest is fetched ──────

    #[tokio::test]
    async fn resolve_start_cursor_prefers_provider() {
        let http = MockHttp::new(vec![]).arc();
        let provider: Arc<dyn LatestEventIdProvider> = Arc::new(InMemoryLatestEventId::new());
        provider.set("persisted-cursor").await.unwrap();

        let cursor = resolve_start_cursor(&http, VOLUME, &provider)
            .await
            .unwrap();
        assert_eq!(cursor, "persisted-cursor");
    }

    #[tokio::test]
    async fn resolve_start_cursor_falls_back_to_server_latest() {
        let http = MockHttp::new(vec![(
            "/drive/volumes/vol-test-1/events/latest",
            r#"{"Code":1000,"EventID":"server-latest"}"#.to_owned(),
        )])
        .arc();
        let provider: Arc<dyn LatestEventIdProvider> = Arc::new(InMemoryLatestEventId::new());

        let cursor = resolve_start_cursor(&http, VOLUME, &provider)
            .await
            .unwrap();
        assert_eq!(cursor, "server-latest");
        // The fetched latest must also be persisted for the next tick.
        assert_eq!(
            provider.get().await.unwrap().as_deref(),
            Some("server-latest")
        );
    }

    // ── loop: cancellation stops polling and persists the cursor ──────────────

    #[tokio::test(start_paused = true)]
    async fn poll_loop_dispatches_then_stops_on_cancel() {
        // Provider seeded with a start cursor so the loop skips the latest call.
        let provider: Arc<dyn LatestEventIdProvider> = Arc::new(InMemoryLatestEventId::new());
        provider.set("cursor-0").await.unwrap();

        // One non-empty page on the first tick, then empty (idle) pages.
        let http = MockHttp::new(vec![
            (
                "/drive/v2/volumes/vol-test-1/events/cursor-0",
                events_page(
                    "cursor-1",
                    false,
                    false,
                    &[("cursor-1", "node-a", 1, false)],
                ),
            ),
            (
                "/drive/v2/volumes/vol-test-1/events/cursor-1",
                events_page("cursor-1", false, false, &[]),
            ),
        ])
        .arc();
        let (listener, captured) = RecordingListener::new();

        let sub = spawn_volume_event_loop(
            Arc::clone(&http),
            VOLUME.to_owned(),
            Box::new(listener),
            Arc::clone(&provider),
        );

        // Advance past the first poll interval so one drain runs.
        pump(POLL_INTERVAL_SECS + 1).await;

        {
            let evs = captured.lock().unwrap();
            assert_eq!(evs.len(), 1, "first tick dispatched one event");
        }
        // Cursor advanced and was persisted.
        assert_eq!(provider.get().await.unwrap().as_deref(), Some("cursor-1"));

        // Cancel and confirm no further events arrive after more time passes.
        sub.cancel();
        assert!(sub.is_cancelled());
        pump(POLL_INTERVAL_SECS * 5).await;

        let evs = captured.lock().unwrap();
        assert_eq!(evs.len(), 1, "cancellation stopped further dispatch");
    }

    // ── loop: NotFound emits TreeRemoval and stops ────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn poll_loop_emits_tree_removal_on_not_found() {
        let provider: Arc<dyn LatestEventIdProvider> = Arc::new(InMemoryLatestEventId::new());
        provider.set("cursor-0").await.unwrap();

        // Empty queue → mock returns the NotFound fallback envelope.
        let http = MockHttp::new(vec![]).arc();
        let (listener, captured) = RecordingListener::new();

        let _sub = spawn_volume_event_loop(
            Arc::clone(&http),
            VOLUME.to_owned(),
            Box::new(listener),
            provider,
        );

        pump(POLL_INTERVAL_SECS + 1).await;

        let evs = captured.lock().unwrap();
        assert_eq!(evs.len(), 1);
        assert!(matches!(&evs[0], DriveEvent::TreeRemoval(_)));
    }
}
