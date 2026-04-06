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
