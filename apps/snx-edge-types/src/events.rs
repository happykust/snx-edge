//! SSE event and log entry wire-format types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single log entry returned by `GET /logs/history` or streamed over
/// `GET /logs` (SSE). Canonicalised to `DateTime<Utc>` for the timestamp;
/// older clients that read `String` will still parse the RFC3339 wire form
/// because chrono's serde impl emits/accepts RFC3339.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    #[serde(default)]
    pub target: String,
    pub message: String,
}

/// SSE event broadcast to all connected clients.
///
/// Tagged with `type` / `data` to match the historical wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ServerEvent {
    ConnectionStatus { status: String },
    RoutingChanged,
    ConfigChanged,
    LogEntry { level: String, message: String },
}
