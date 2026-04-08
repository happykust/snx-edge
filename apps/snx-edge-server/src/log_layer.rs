//! Custom tracing Layer that captures log entries into the shared ring buffer
//! and broadcasts them as SSE events.

use std::fmt;

use chrono::Utc;
use tokio::sync::broadcast;
use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use crate::api::logs::{LogEntry, SharedLogBuffer};
use crate::state::ServerEvent;

/// A tracing Layer that writes every event into the log ring buffer
/// and sends a `ServerEvent::LogEntry` on the broadcast channel.
pub struct LogCaptureLayer {
    buffer: SharedLogBuffer,
    event_tx: broadcast::Sender<ServerEvent>,
}

impl LogCaptureLayer {
    pub fn new(buffer: SharedLogBuffer, event_tx: broadcast::Sender<ServerEvent>) -> Self {
        Self { buffer, event_tx }
    }
}

impl<S: Subscriber> Layer<S> for LogCaptureLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let level = metadata.level().as_str().to_uppercase();
        let target = metadata.target().to_string();

        // Extract the message from the event fields
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let message = visitor.message;

        let entry = LogEntry {
            timestamp: Utc::now(),
            level: level.clone(),
            target,
            message: message.clone(),
        };

        // Write to ring buffer (blocking — must be fast)
        // Use try_write to avoid blocking the tracing hot path
        if let Ok(mut buf) = self.buffer.try_write() {
            buf.push(entry);
        }

        // Broadcast to SSE listeners (non-blocking send)
        let _ = self.event_tx.send(ServerEvent::LogEntry { level, message });
    }
}

/// Visitor that extracts the `message` field from a tracing event.
#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else if self.message.is_empty() {
            // Fallback: use first field as message
            self.message = format!("{}: {value:?}", field.name());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else if self.message.is_empty() {
            self.message = format!("{}: {value}", field.name());
        }
    }
}
