use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::{Extension, Json, Router};
use chrono::Utc;
use futures_util::stream::{self, Stream};
use serde::Deserialize;
use tokio::sync::RwLock;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

pub use snx_edge_types::events::LogEntry;

use crate::api::auth::{Claims, has_permission};
use crate::api::events::{lag_event, schema_event};
use crate::error::AppError;
use crate::state::{AppState, ServerEvent};

/// Ring buffer for log history.
pub struct LogBuffer {
    entries: Vec<LogEntry>,
    capacity: usize,
    write_pos: usize,
    count: usize,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        // `push` does `self.write_pos = (self.write_pos + 1) % self.capacity`,
        // which panics with divide-by-zero when capacity == 0. Reject that
        // case up-front so the panic happens at construction, not on first
        // log entry.
        assert!(capacity > 0, "LogBuffer capacity must be > 0");
        Self {
            entries: Vec::with_capacity(capacity),
            capacity,
            write_pos: 0,
            count: 0,
        }
    }

    pub fn push(&mut self, entry: LogEntry) {
        if self.entries.len() < self.capacity {
            self.entries.push(entry);
        } else {
            self.entries[self.write_pos] = entry;
        }
        self.write_pos = (self.write_pos + 1) % self.capacity;
        self.count += 1;
    }

    /// Get last N entries in chronological order.
    pub fn last_n(&self, n: usize) -> Vec<LogEntry> {
        let len = self.entries.len();
        let take = n.min(len);

        if len < self.capacity {
            // Buffer not full yet, entries are in order
            self.entries[len.saturating_sub(take)..].to_vec()
        } else {
            // Buffer wrapped; order starts from write_pos
            let mut result = Vec::with_capacity(take);
            let start = (self.write_pos + len - take) % len;
            for i in 0..take {
                result.push(self.entries[(start + i) % len].clone());
            }
            result
        }
    }
}

/// Shared log buffer accessible from handlers and the log subscriber.
pub type SharedLogBuffer = Arc<RwLock<LogBuffer>>;

pub fn new_log_buffer(capacity: usize) -> SharedLogBuffer {
    Arc::new(RwLock::new(LogBuffer::new(capacity)))
}

/// GET /api/v1/logs — SSE stream of log entries in real-time.
async fn logs_stream(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AppError> {
    if !has_permission(&claims, "logs.read") {
        return Err(AppError::Forbidden(
            "permission 'logs.read' required".to_string(),
        ));
    }

    let rx = state.event_tx.subscribe();
    let body = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(ServerEvent::LogEntry { level, message }) => {
            let entry = serde_json::json!({
                "timestamp": Utc::now().to_rfc3339(),
                "level": level,
                "message": message,
            });
            Some(Ok(Event::default().event("log").data(entry.to_string())))
        }
        Ok(_) => None,
        Err(BroadcastStreamRecvError::Lagged(n)) => Some(Ok(lag_event(n))),
    });

    // Prepend the schema-handshake frame (see SSE_SCHEMA_VERSION docs).
    let head = stream::once(async { Ok::<_, Infallible>(schema_event()) });
    let stream = head.chain(body);

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    level: Option<String>,
}

fn default_limit() -> usize {
    100
}

/// GET /api/v1/logs/history — last N entries from ring buffer.
async fn logs_history(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Vec<LogEntry>>, AppError> {
    if !has_permission(&claims, "logs.read") {
        return Err(AppError::Forbidden(
            "permission 'logs.read' required".to_string(),
        ));
    }

    let buffer = state.log_buffer.read().await;
    let mut entries = buffer.last_n(query.limit);

    // Filter by level if specified
    if let Some(ref level) = query.level {
        entries.retain(|e| e.level.eq_ignore_ascii_case(level));
    }

    Ok(Json(entries))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/logs", get(logs_stream))
        .route("/logs/history", get(logs_history))
}
