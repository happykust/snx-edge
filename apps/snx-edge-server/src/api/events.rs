use std::convert::Infallible;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::{Extension, Router};
use futures_util::stream::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::api::auth::Claims;
use crate::state::{AppState, ServerEvent};

/// GET /api/v1/events — SSE stream of state change events.
///
/// # Permission model
///
/// No explicit permission check is performed here because the auth middleware
/// already guarantees that `_claims` belongs to a valid, authenticated user.
/// Every role (admin, operator, viewer) has `tunnel.status` which makes an
/// additional gate redundant.
///
/// LogEntry events are broadcast to all subscribers regardless of the
/// `logs.read` permission. This is a deliberate trade-off: the log entries
/// sent over SSE are the same ephemeral in-memory lines visible in the
/// `/api/v1/logs` endpoint, and filtering per-connection would require
/// wrapping the broadcast stream in a per-role filter that references the
/// claims — adding complexity for marginal security benefit. If fine-grained
/// log-event filtering becomes necessary, add a `.filter()` stage here that
/// checks `has_permission(&claims, "logs.read")` before emitting `LogEntry`
/// variants.
async fn events_stream(
    State(state): State<AppState>,
    Extension(_claims): Extension<Claims>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| {
        match result {
            Ok(event) => {
                let data = serde_json::to_string(&event).unwrap_or_default();
                let event_type = match &event {
                    ServerEvent::ConnectionStatus { .. } => "connection_status",
                    ServerEvent::RoutingChanged => "routing_changed",
                    ServerEvent::ConfigChanged => "config_changed",
                    ServerEvent::LogEntry { .. } => "log",
                };
                Some(Ok(Event::default().event(event_type).data(data)))
            }
            Err(_) => None, // lagged receiver, skip
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/events", get(events_stream))
}
