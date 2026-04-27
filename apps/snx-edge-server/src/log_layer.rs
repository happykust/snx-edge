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

        // Fan out to live SSE listeners only. With zero subscribers the
        // broadcast channel would still allocate and serialise the event
        // before dropping it, which is wasted work on every log line.
        // Persistence (the ring buffer above) is unaffected by this gate.
        broadcast_log_if_listening(&self.event_tx, level, message);
    }
}

/// Send a `LogEntry` to SSE listeners, but only if at least one receiver is
/// alive. Extracted as a free function so the gating predicate can be
/// unit-tested without spinning up a `tracing` Subscriber.
pub(crate) fn broadcast_log_if_listening(
    event_tx: &broadcast::Sender<ServerEvent>,
    level: String,
    message: String,
) {
    if event_tx.receiver_count() == 0 {
        return;
    }
    let _ = event_tx.send(ServerEvent::LogEntry { level, message });
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Gating short-circuits when no receivers are subscribed.
    ///
    /// We can't observe "didn't send" directly, but we can verify the call
    /// returns instantly without blocking and without panicking — even with
    /// a tiny channel capacity that would otherwise saturate quickly.
    #[test]
    fn no_receivers_short_circuits_send() {
        let (tx, rx) = broadcast::channel::<ServerEvent>(1);
        // Drop the only receiver so receiver_count() == 0.
        drop(rx);
        assert_eq!(tx.receiver_count(), 0);

        // Should be a no-op; would otherwise return Err from send() but our
        // helper swallows that anyway. The point is we never reach send().
        for i in 0..100 {
            broadcast_log_if_listening(&tx, "INFO".to_string(), format!("msg {i}"));
        }
        assert_eq!(tx.receiver_count(), 0);
    }

    /// With a live receiver the message is delivered.
    #[test]
    fn delivers_when_receiver_is_alive() {
        let (tx, mut rx) = broadcast::channel::<ServerEvent>(4);
        broadcast_log_if_listening(&tx, "WARN".to_string(), "hello".to_string());
        let got = rx.try_recv().expect("expected a broadcast frame");
        match got {
            ServerEvent::LogEntry { level, message } => {
                assert_eq!(level, "WARN");
                assert_eq!(message, "hello");
            }
            other => panic!("unexpected event variant: {other:?}"),
        }
    }
}
