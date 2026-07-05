//! Live-event bridge — wires the SDK's `subscribe_drive_events` (already a
//! fully tested consumer in `proton-drive-core::events`) into pdtui's
//! remote-pane refresh.
//!
//! This module adds **no polling of its own**. `subscribe_drive_events`
//! spawns and owns the background poll/backoff loop against the Proton
//! events API (see `proton_drive_core::events::spawn_volume_event_loop`);
//! this bridge only translates its listener callback into a `watch`
//! staleness signal that `App::tick` checks once per redraw cycle — the same
//! "spawn a task, drive state through a `tokio::sync::watch` channel polled
//! from the app loop" shape `transfer.rs` uses for upload/download progress.
//!
//! Subscription failure (e.g. a transient error resolving the My Files
//! volume right after login) degrades gracefully: it is logged and the
//! receiver returned to `App` simply never fires, so manual refresh
//! (F5 / focus / navigate) keeps working exactly as it did before this
//! module existed.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch;
use tracing::warn;

use proton_drive::{DriveEvent, DriveListener, EventSubscription, ProtonDriveClient};

/// Flips `stale_tx` on any drive event that can change what the remote pane
/// shows. `FastForward` (cursor-only bookkeeping, no tree change) and
/// `SharedWithMeUpdated` (pdtui only browses My Files) are deliberately not
/// treated as relevant — a `send` is skipped for both so they never trigger
/// a refresh.
struct StaleOnRelevantEvent {
    stale_tx: watch::Sender<bool>,
}

impl StaleOnRelevantEvent {
    fn is_relevant(event: &DriveEvent) -> bool {
        matches!(
            event,
            DriveEvent::Node(_) | DriveEvent::TreeRefresh(_) | DriveEvent::TreeRemoval(_)
        )
    }
}

#[async_trait]
impl DriveListener for StaleOnRelevantEvent {
    async fn on_event(&self, event: DriveEvent) {
        if Self::is_relevant(&event) {
            // `watch::Sender::send` marks the channel changed on every call
            // regardless of the carried value, which is exactly the signal
            // `App::take_stale_event` looks for; the receiver having no
            // listeners left (TUI shutting down) is not an error worth
            // logging.
            let _ = self.stale_tx.send(true);
        }
    }
}

/// Subscribe to the client's My Files drive events in the background.
///
/// Returns a `watch::Receiver<bool>` for `App` to poll from its tick loop,
/// plus the `EventSubscription` guard — the caller must hold onto it for as
/// long as live updates are wanted; dropping it cancels the subscription
/// (see `EventSubscription`'s `Drop` impl).
///
/// On failure, logs a warning and returns `(receiver, None)`: the receiver
/// never fires, so callers should treat the pane as "manual refresh only"
/// rather than error out.
pub async fn subscribe(
    client: &Arc<ProtonDriveClient>,
) -> (watch::Receiver<bool>, Option<EventSubscription>) {
    let (stale_tx, stale_rx) = watch::channel(false);
    let listener: Box<dyn DriveListener> = Box::new(StaleOnRelevantEvent { stale_tx });

    match client.subscribe_drive_events(listener).await {
        Ok(sub) => (stale_rx, Some(sub)),
        Err(e) => {
            warn!("drive event subscription failed: {e} — falling back to manual refresh only");
            (stale_rx, None)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use proton_drive::{FastForwardEvent, NodeEvent, NodeEventKind, NodeUid, TreeRemovalEvent};

    fn uid() -> NodeUid {
        NodeUid {
            volume_id: "vol".into(),
            node_id: "node".into(),
        }
    }

    #[tokio::test]
    async fn node_event_marks_stale() {
        let (tx, mut rx) = watch::channel(false);
        let listener = StaleOnRelevantEvent { stale_tx: tx };
        assert!(!rx.has_changed().unwrap());

        listener
            .on_event(DriveEvent::Node(NodeEvent {
                uid: uid(),
                parent_uid: None,
                kind: NodeEventKind::Created,
                is_shared: false,
                event_id: "e1".into(),
            }))
            .await;

        assert!(rx.has_changed().unwrap(), "Node event must mark stale");
        let _ = rx.borrow_and_update();
        assert!(!rx.has_changed().unwrap(), "flag clears after consuming");
    }

    #[tokio::test]
    async fn tree_refresh_and_removal_mark_stale() {
        let (tx, mut rx) = watch::channel(false);
        let listener = StaleOnRelevantEvent { stale_tx: tx };

        listener
            .on_event(DriveEvent::TreeRefresh(proton_drive::TreeRefreshEvent {
                root: uid(),
                new_event_id: "e1".into(),
            }))
            .await;
        assert!(rx.has_changed().unwrap());
        let _ = rx.borrow_and_update();

        listener
            .on_event(DriveEvent::TreeRemoval(TreeRemovalEvent { root: uid() }))
            .await;
        assert!(rx.has_changed().unwrap());
    }

    #[tokio::test]
    async fn fast_forward_does_not_mark_stale() {
        let (tx, rx) = watch::channel(false);
        let listener = StaleOnRelevantEvent { stale_tx: tx };

        listener
            .on_event(DriveEvent::FastForward(FastForwardEvent {
                new_event_id: "e2".into(),
            }))
            .await;

        assert!(
            !rx.has_changed().unwrap(),
            "FastForward is cursor bookkeeping, not a tree change"
        );
    }

    #[tokio::test]
    async fn shared_with_me_updated_does_not_mark_stale() {
        let (tx, rx) = watch::channel(false);
        let listener = StaleOnRelevantEvent { stale_tx: tx };

        listener.on_event(DriveEvent::SharedWithMeUpdated).await;

        assert!(
            !rx.has_changed().unwrap(),
            "pdtui only browses My Files — shared-with-me changes are out of scope"
        );
    }

    #[test]
    fn is_relevant_classifies_variants() {
        assert!(StaleOnRelevantEvent::is_relevant(&DriveEvent::Node(
            NodeEvent {
                uid: uid(),
                parent_uid: None,
                kind: NodeEventKind::Updated,
                is_shared: false,
                event_id: "e0".into(),
            }
        )));
        assert!(StaleOnRelevantEvent::is_relevant(&DriveEvent::TreeRefresh(
            proton_drive::TreeRefreshEvent {
                root: uid(),
                new_event_id: "e0".into(),
            }
        )));
        assert!(StaleOnRelevantEvent::is_relevant(&DriveEvent::TreeRemoval(
            TreeRemovalEvent { root: uid() }
        )));
        assert!(!StaleOnRelevantEvent::is_relevant(
            &DriveEvent::FastForward(FastForwardEvent {
                new_event_id: "x".into(),
            })
        ));
        assert!(!StaleOnRelevantEvent::is_relevant(
            &DriveEvent::SharedWithMeUpdated
        ));
    }
}
