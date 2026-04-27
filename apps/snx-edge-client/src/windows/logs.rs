use std::time::Duration;

use futures_util::StreamExt;
use gtk4::{
    Align, Orientation, WrapMode,
    glib::{self, clone},
    prelude::*,
};
use reqwest_eventsource::{Event, EventSource};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{api::ApiClient, get_window, main_window, set_window};

/// SSE reconnect backoff configuration.
const SSE_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const SSE_MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Show the logs viewer window.
pub fn show_logs_window(api: ApiClient) {
    if let Some(window) = get_window("logs") {
        window.present();
        return;
    }

    let window = gtk4::Window::builder()
        .title("SNX Edge - Logs")
        .transient_for(&main_window())
        .default_width(750)
        .default_height(500)
        .build();

    let outer = gtk4::Box::builder()
        .orientation(Orientation::Vertical)
        .build();

    // --- Header: level filter + connection status label ---
    let header = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_top(6)
        .margin_start(6)
        .margin_end(6)
        .build();

    header.append(
        &gtk4::Label::builder()
            .label("Level Filter:")
            .halign(Align::Start)
            .build(),
    );

    let level_model = gtk4::StringList::new(&["all", "error", "warn", "info", "debug"]);
    let level_dropdown = gtk4::DropDown::builder()
        .model(&level_model)
        .selected(0)
        .build();
    header.append(&level_dropdown);

    let refresh_btn = gtk4::Button::builder().label("Reload").build();
    header.append(&refresh_btn);

    // Spacer + status label
    let spacer = gtk4::Box::builder().hexpand(true).build();
    header.append(&spacer);

    let status_label = gtk4::Label::builder()
        .label("")
        .halign(Align::End)
        .css_classes(vec!["dim-label".to_string()])
        .build();
    header.append(&status_label);

    outer.append(&header);

    // --- Log view ---
    let text_view = gtk4::TextView::builder()
        .editable(false)
        .cursor_visible(false)
        .wrap_mode(WrapMode::WordChar)
        .monospace(true)
        .vexpand(true)
        .margin_top(4)
        .margin_start(6)
        .margin_end(6)
        .margin_bottom(4)
        .build();

    let scrolled = gtk4::ScrolledWindow::builder().vexpand(true).build();
    scrolled.set_child(Some(&text_view));
    outer.append(&scrolled);

    // --- Bottom bar ---
    let bottom_bar = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .margin_top(4)
        .margin_start(6)
        .margin_end(6)
        .margin_bottom(6)
        .halign(Align::End)
        .build();

    let close_btn = gtk4::Button::builder().label("Close").build();
    bottom_bar.append(&close_btn);

    outer.append(&bottom_bar);

    close_btn.connect_clicked(clone!(
        #[weak]
        window,
        move |_| window.close()
    ));

    // Escape to close
    let key_controller = gtk4::EventControllerKey::new();
    key_controller.connect_key_pressed(clone!(
        #[weak]
        window,
        #[upgrade_or]
        glib::Propagation::Proceed,
        move |_, key, _, _| {
            if key == gtk4::gdk::Key::Escape {
                window.close();
                glib::Propagation::Stop
            } else {
                glib::Propagation::Proceed
            }
        }
    ));
    window.add_controller(key_controller);

    window.set_child(Some(&outer));

    // SSE cancellation token — cancelled when window is closed.
    let cancel = CancellationToken::new();
    let cancel_close = cancel.clone();

    window.connect_close_request(move |_| {
        cancel_close.cancel();
        set_window("logs", None::<gtk4::Window>);
        glib::Propagation::Proceed
    });
    set_window("logs", Some(window.clone()));

    // Load initial history
    let api_init = api.clone();
    let text_view_init = text_view.clone();
    let scrolled_init = scrolled.clone();
    let level_dropdown_load = level_dropdown.clone();
    glib::spawn_future_local(async move {
        load_history(
            &api_init,
            &text_view_init,
            &scrolled_init,
            &level_dropdown_load,
        )
        .await;
    });

    // Refresh button
    let api_refresh = api.clone();
    let text_view_refresh = text_view.clone();
    let scrolled_refresh = scrolled.clone();
    let level_dropdown_refresh = level_dropdown.clone();
    refresh_btn.connect_clicked(move |_| {
        let api = api_refresh.clone();
        let text_view = text_view_refresh.clone();
        let scrolled = scrolled_refresh.clone();
        let level_dropdown = level_dropdown_refresh.clone();
        glib::spawn_future_local(async move {
            load_history(&api, &text_view, &scrolled, &level_dropdown).await;
        });
    });

    // Start SSE streaming with cancellation + reconnect-with-backoff
    start_sse_stream(
        api,
        text_view,
        scrolled,
        level_dropdown,
        status_label,
        cancel,
    );

    window.present();
}

async fn load_history(
    api: &ApiClient,
    text_view: &gtk4::TextView,
    scrolled: &gtk4::ScrolledWindow,
    level_dropdown: &gtk4::DropDown,
) {
    let level = selected_level(level_dropdown);
    let level_param = if level == "all" {
        None
    } else {
        Some(level.clone())
    };

    let (tx, rx) = async_channel::bounded(1);
    let api2 = api.clone();
    tokio::spawn(async move {
        let _ = tx
            .send(api2.logs_history(200, level_param.as_deref()).await)
            .await;
    });

    match rx.recv().await {
        Ok(Ok(entries)) => {
            let buffer = text_view.buffer();
            buffer.set_text("");

            for entry in &entries {
                let line = format_log_entry(entry);
                if should_show(&line, &level) {
                    let mut end = buffer.end_iter();
                    buffer.insert(&mut end, &line);
                    buffer.insert(&mut end, "\n");
                }
            }

            scroll_to_bottom(scrolled);
        }
        Ok(Err(e)) => {
            let buffer = text_view.buffer();
            buffer.set_text(&format!("Error loading logs: {}", e));
        }
        _ => {}
    }
}

/// Status events sent from the SSE worker task to the UI updater.
enum SseUiMsg {
    /// A log line received from the server (raw SSE message data).
    Line(String),
    /// Stream is connected and receiving events.
    Connected,
    /// Stream is reconnecting; payload is the next attempt delay.
    Reconnecting(Duration),
}

fn start_sse_stream(
    api: ApiClient,
    text_view: gtk4::TextView,
    scrolled: gtk4::ScrolledWindow,
    level_dropdown: gtk4::DropDown,
    status_label: gtk4::Label,
    cancel: CancellationToken,
) {
    let (tx, rx) = async_channel::unbounded::<SseUiMsg>();

    // SSE reader task: reconnect loop with exponential backoff.
    // Honours the per-server `insecure` flag because we reuse the ApiClient's
    // underlying reqwest::Client (configured in ApiClient::with_insecure).
    let cancel_task = cancel.clone();
    tokio::spawn(async move {
        let mut delay = SSE_INITIAL_BACKOFF;
        let mut attempt: u32 = 0;

        loop {
            if cancel_task.is_cancelled() {
                return;
            }

            // Build a fresh authenticated request each iteration since
            // RequestBuilder is not Clone.
            let builder = api.sse_request("/api/v1/logs").await;
            let mut es = match EventSource::new(builder) {
                Ok(es) => es,
                Err(e) => {
                    warn!("SSE: failed to construct EventSource: {}", e);
                    let _ = tx.send(SseUiMsg::Reconnecting(delay)).await;
                    if wait_or_cancel(&cancel_task, delay).await {
                        return;
                    }
                    delay = (delay * 2).min(SSE_MAX_BACKOFF);
                    attempt = attempt.saturating_add(1);
                    continue;
                }
            };

            let mut got_event = false;
            loop {
                tokio::select! {
                    _ = cancel_task.cancelled() => return,
                    next = es.next() => match next {
                        Some(Ok(Event::Open)) => {
                            got_event = true;
                            // Reset backoff once the connection is open.
                            delay = SSE_INITIAL_BACKOFF;
                            attempt = 0;
                            let _ = tx.send(SseUiMsg::Connected).await;
                        }
                        Some(Ok(Event::Message(m))) => {
                            got_event = true;
                            // Reset backoff on a successful event received.
                            delay = SSE_INITIAL_BACKOFF;
                            attempt = 0;
                            if tx.send(SseUiMsg::Line(m.data)).await.is_err() {
                                return;
                            }
                        }
                        Some(Err(e)) => {
                            warn!("SSE: connection error (attempt {}): {}", attempt, e);
                            break;
                        }
                        None => {
                            warn!("SSE: stream ended (attempt {})", attempt);
                            break;
                        }
                    }
                }
            }

            // If we never received an event this attempt, increase backoff;
            // otherwise the loop above already reset it.
            if !got_event {
                attempt = attempt.saturating_add(1);
            }

            let _ = tx.send(SseUiMsg::Reconnecting(delay)).await;

            if wait_or_cancel(&cancel_task, delay).await {
                return;
            }
            delay = (delay * 2).min(SSE_MAX_BACKOFF);
        }
    });

    // UI updater. Cancellation breaks out of the recv loop too — but the
    // sender task drops `tx` when it returns, which closes `rx` naturally.
    glib::spawn_future_local(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                msg = rx.recv() => match msg {
                    Ok(SseUiMsg::Line(data)) => {
                        let line = if let Ok(entry) =
                            serde_json::from_str::<serde_json::Value>(&data)
                        {
                            format_log_entry(&entry)
                        } else {
                            data
                        };
                        let level = selected_level(&level_dropdown);
                        if should_show(&line, &level) {
                            let buffer = text_view.buffer();
                            let mut end = buffer.end_iter();
                            buffer.insert(&mut end, &line);
                            buffer.insert(&mut end, "\n");
                            scroll_to_bottom(&scrolled);
                        }
                    }
                    Ok(SseUiMsg::Connected) => {
                        status_label.set_label("");
                    }
                    Ok(SseUiMsg::Reconnecting(d)) => {
                        status_label.set_label(&format!(
                            "Reconnecting in {}s...",
                            d.as_secs().max(1),
                        ));
                    }
                    Err(_) => break,
                }
            }
        }
    });
}

/// Wait for `delay` or until `cancel` fires. Returns `true` if cancelled.
async fn wait_or_cancel(cancel: &CancellationToken, delay: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(delay) => false,
        _ = cancel.cancelled() => true,
    }
}

fn format_log_entry(entry: &serde_json::Value) -> String {
    let ts = entry["timestamp"].as_str().unwrap_or("");
    let level = entry["level"].as_str().unwrap_or("info");
    let message = entry["message"].as_str().unwrap_or("");
    let target = entry["target"].as_str().unwrap_or("");

    if target.is_empty() {
        format!("{} [{}] {}", ts, level.to_uppercase(), message)
    } else {
        format!("{} [{}] {}: {}", ts, level.to_uppercase(), target, message)
    }
}

fn selected_level(dropdown: &gtk4::DropDown) -> String {
    match dropdown.selected() {
        1 => "error".to_string(),
        2 => "warn".to_string(),
        3 => "info".to_string(),
        4 => "debug".to_string(),
        _ => "all".to_string(),
    }
}

fn should_show(line: &str, level: &str) -> bool {
    if level == "all" {
        return true;
    }
    let levels_to_show: &[&str] = match level {
        "error" => &["ERROR"],
        "warn" => &["ERROR", "WARN"],
        "info" => &["ERROR", "WARN", "INFO"],
        "debug" => &["ERROR", "WARN", "INFO", "DEBUG"],
        _ => return true,
    };
    let upper = line.to_uppercase();
    levels_to_show.iter().any(|l| upper.contains(l))
}

fn scroll_to_bottom(scrolled: &gtk4::ScrolledWindow) {
    let adj = scrolled.vadjustment();
    adj.set_value(adj.upper() - adj.page_size());
}
