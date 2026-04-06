use std::sync::Arc;

use futures_util::StreamExt;
use reqwest_eventsource::{Event, RequestBuilderExt};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Events received from the server SSE stream, forwarded to the GTK main loop.
#[derive(Debug, Clone)]
pub enum SseEvent {
    /// VPN connection status changed ("connected", "disconnected", etc.).
    ConnectionStatus(String),
    /// Server-side routing table was modified.
    RoutingChanged,
    /// Server configuration was modified.
    ConfigChanged,
    /// The SSE connection itself was lost.
    Disconnected,
}

/// Manages a background SSE connection to the snx-edge-server.
///
/// Call [`start`](Self::start) to spawn the listener and [`stop`](Self::stop)
/// to tear it down.
pub struct SseManager {
    base_url: Arc<std::sync::RwLock<String>>,
    token: Arc<RwLock<Option<String>>>,
    /// Sending `true` signals the background task to exit.
    stop_tx: tokio::sync::watch::Sender<bool>,
    stop_rx: tokio::sync::watch::Receiver<bool>,
}

impl SseManager {
    /// Create a new manager.
    ///
    /// * `base_url` - shared server origin (e.g. `"https://10.0.0.1:8443"`),
    ///   shared with `ApiClient` so server URL changes are picked up
    ///   automatically on reconnect.
    /// * `token`    - shared JWT; the SSE task reads the current value on each
    ///   (re)connect so token refreshes are picked up automatically.
    pub fn new(base_url: Arc<std::sync::RwLock<String>>, token: Arc<RwLock<Option<String>>>) -> Self {
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        Self {
            base_url,
            token,
            stop_tx,
            stop_rx,
        }
    }

    /// Spawn a tokio task that connects to the event stream and forwards
    /// parsed events to `event_sender` (a `glib::Sender` bound to the GTK
    /// main loop).
    ///
    /// The task reconnects automatically with a 3-second backoff on any
    /// disconnect or error.  Call [`stop`](Self::stop) to cancel it.
    pub fn start(&self, event_sender: tokio::sync::mpsc::UnboundedSender<SseEvent>) {
        // Reset the stop signal so a previous stop() does not immediately
        // abort the new session.
        let _ = self.stop_tx.send(false);

        let base_url = Arc::clone(&self.base_url);
        let token = Arc::clone(&self.token);
        let mut stop_rx = self.stop_rx.clone();

        tokio::spawn(async move {
            loop {
                // Check if we have been asked to stop.
                if *stop_rx.borrow() {
                    debug!("SSE task: stop signal received, exiting");
                    return;
                }

                // Read the current base URL on each (re)connect so server
                // changes are picked up automatically.
                let url = {
                    let guard = base_url.read().unwrap();
                    format!("{}/api/v1/events", *guard)
                };

                // Read the current bearer token.
                let bearer = {
                    let guard = token.read().await;
                    match guard.as_deref() {
                        Some(t) => format!("Bearer {t}"),
                        None => {
                            warn!("SSE: no auth token available, retrying in 3 s");
                            tokio::select! {
                                _ = stop_rx.changed() => return,
                                _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => continue,
                            }
                        }
                    }
                };

                info!("SSE: connecting to {url}");

                let request = reqwest::Client::new()
                    .get(&url)
                    .header(reqwest::header::AUTHORIZATION, &bearer);

                let mut es = request.eventsource().unwrap();

                // Process the stream until it ends or we are asked to stop.
                loop {
                    tokio::select! {
                        _ = stop_rx.changed() => {
                            es.close();
                            debug!("SSE task: stop signal received while streaming");
                            return;
                        }
                        maybe_event = es.next() => {
                            match maybe_event {
                                Some(Ok(Event::Open)) => {
                                    info!("SSE: connection opened");
                                }
                                Some(Ok(Event::Message(msg))) => {
                                    if let Some(sse_event) = parse_event(&msg.event, &msg.data) {
                                        if event_sender.send(sse_event).is_err() {
                                            debug!("SSE: glib receiver dropped, stopping");
                                            es.close();
                                            return;
                                        }
                                    }
                                }
                                Some(Err(err)) => {
                                    error!("SSE stream error: {err}");
                                    es.close();
                                    // Notify GTK that we lost the connection.
                                    let _ = event_sender.send(SseEvent::Disconnected);
                                    break; // exit inner loop -> reconnect
                                }
                                None => {
                                    warn!("SSE: stream ended");
                                    let _ = event_sender.send(SseEvent::Disconnected);
                                    break; // reconnect
                                }
                            }
                        }
                    }
                }

                // Back off before reconnecting.
                info!("SSE: reconnecting in 3 s");
                tokio::select! {
                    _ = stop_rx.changed() => return,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {}
                }
            }
        });
    }

    /// Signal the background task to stop.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The server serializes `ServerEvent` with `#[serde(tag = "type", content = "data")]`,
/// so the JSON on the `data` field of an SSE message looks like:
///
/// ```json
/// {"type":"ConnectionStatus","data":{"status":"connected"}}
/// ```
///
/// The SSE *event type* is also set separately (e.g. `event: connection_status`).
/// We parse the outer wrapper to extract the inner `data.status` field.
fn parse_event(event_type: &str, data: &str) -> Option<SseEvent> {
    match event_type {
        "connection_status" => {
            // Parse the outer wrapper first, then extract the inner data.
            if let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(data) {
                if let Some(inner) = wrapper.get("data") {
                    if let Some(status) = inner.get("status").and_then(|s| s.as_str()) {
                        return Some(SseEvent::ConnectionStatus(status.to_string()));
                    }
                }
                // Fallback: maybe the server sent the flat form directly
                if let Some(status) = wrapper.get("status").and_then(|s| s.as_str()) {
                    return Some(SseEvent::ConnectionStatus(status.to_string()));
                }
            }
            warn!("SSE: failed to parse connection_status data: {data}");
            None
        }
        "routing_changed" => Some(SseEvent::RoutingChanged),
        "config_changed" => Some(SseEvent::ConfigChanged),
        other => {
            debug!("SSE: ignoring unknown event type: {other}");
            None
        }
    }
}
