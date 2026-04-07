use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use gtk4::{
    Align, Orientation, WrapMode,
    glib::{self, clone},
    prelude::*,
};
use reqwest_eventsource::{Event, EventSource};
use futures_util::StreamExt;

use crate::{api::ApiClient, get_window, main_window, set_window};

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

    // --- Header: level filter ---
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

    let scrolled = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .build();
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
        #[weak] window,
        move |_| window.close()
    ));

    // Escape to close
    let key_controller = gtk4::EventControllerKey::new();
    key_controller.connect_key_pressed(clone!(
        #[weak] window,
        #[upgrade_or] glib::Propagation::Proceed,
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

    // SSE cancellation flag — set when window is closed
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_close = stop_flag.clone();

    window.connect_close_request(move |_| {
        stop_flag_close.store(true, Ordering::SeqCst);
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
        load_history(&api_init, &text_view_init, &scrolled_init, &level_dropdown_load).await;
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

    // Start SSE streaming with cancellation support
    let api_sse = api.clone();
    let text_view_sse = text_view.clone();
    let scrolled_sse = scrolled.clone();
    let level_dropdown_sse = level_dropdown.clone();
    start_sse_stream(api_sse, text_view_sse, scrolled_sse, level_dropdown_sse, stop_flag);

    window.present();
}

async fn load_history(
    api: &ApiClient,
    text_view: &gtk4::TextView,
    scrolled: &gtk4::ScrolledWindow,
    level_dropdown: &gtk4::DropDown,
) {
    let level = selected_level(level_dropdown);
    let level_param = if level == "all" { None } else { Some(level.clone()) };

    let (tx, rx) = async_channel::bounded(1);
    let api2 = api.clone();
    tokio::spawn(async move {
        let _ = tx.send(api2.logs_history(200, level_param.as_deref()).await).await;
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

fn start_sse_stream(
    api: ApiClient,
    text_view: gtk4::TextView,
    scrolled: gtk4::ScrolledWindow,
    level_dropdown: gtk4::DropDown,
    stop_flag: Arc<AtomicBool>,
) {
    let (tx, rx) = async_channel::unbounded::<String>();

    // SSE reader task — checks stop_flag and drops tx on exit
    tokio::spawn(async move {
        let base_url = api.base_url().await;
        let token = api.token().await;
        let url = format!("{}/api/v1/logs", base_url);

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        let mut builder = client.get(&url);

        if let Some(ref tok) = token {
            builder = builder.bearer_auth(tok);
        }

        let Ok(mut es) = EventSource::new(builder) else {
            return;
        };

        while let Some(event) = es.next().await {
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }
            match event {
                Ok(Event::Message(msg)) => {
                    if tx.send(msg.data).await.is_err() {
                        break;
                    }
                }
                Ok(Event::Open) => {}
                Err(_) => {
                    // Connection lost; stop
                    break;
                }
            }
        }
        // tx is dropped here, causing the rx receiver to finish
    });

    // UI updater
    glib::spawn_future_local(async move {
        while let Ok(data) = rx.recv().await {
            let level = selected_level(&level_dropdown);
            if should_show(&data, &level) {
                let buffer = text_view.buffer();
                let mut end = buffer.end_iter();
                buffer.insert(&mut end, &data);
                buffer.insert(&mut end, "\n");
                scroll_to_bottom(&scrolled);
            }
        }
    });
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
