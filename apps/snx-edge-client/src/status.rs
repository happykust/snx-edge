
use gtk4::{
    Align, Orientation,
    glib::{self, clone},
    prelude::{BoxExt, ButtonExt, Cast, DisplayExt, GtkWindowExt, WidgetExt},
};
use libadwaita::prelude::ActionRowExt;
use tokio::sync::mpsc::Sender;

use crate::{
    POLL_INTERVAL, api::ApiClient, get_window, main_window, set_window,
    tray::{ConnectionState, TrayEvent},
};

/// Routing health state derived from diagnostics API.
#[derive(Debug, Clone, PartialEq)]
pub enum RoutingHealth {
    Unknown,
    Healthy,
    Degraded,
    Error,
}

impl RoutingHealth {
    pub fn from_diagnostics(value: &serde_json::Value) -> Self {
        // Try "status" field first, fall back to heuristics
        if let Some(status) = value.get("status").and_then(|v| v.as_str()) {
            return match status {
                "healthy" | "ok" => RoutingHealth::Healthy,
                "degraded" | "warning" => RoutingHealth::Degraded,
                "error" | "unreachable" | "failed" => RoutingHealth::Error,
                _ => RoutingHealth::Unknown,
            };
        }
        // If we got a valid response but no status field, consider it healthy
        if value.is_object() && !value.as_object().unwrap().is_empty() {
            RoutingHealth::Healthy
        } else {
            RoutingHealth::Unknown
        }
    }

    pub fn icon_name(&self) -> &'static str {
        match self {
            RoutingHealth::Unknown => "dialog-question-symbolic",
            RoutingHealth::Healthy => "emblem-ok-symbolic",
            RoutingHealth::Degraded => "dialog-warning-symbolic",
            RoutingHealth::Error => "dialog-error-symbolic",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            RoutingHealth::Unknown => "Unknown",
            RoutingHealth::Healthy => "Healthy",
            RoutingHealth::Degraded => "Degraded",
            RoutingHealth::Error => "Error",
        }
    }
}

pub fn same_status(lhs: &ConnectionState, rhs: &ConnectionState) -> bool {
    lhs == rhs
}

fn status_entry(label: &str, value: &str) -> gtk4::Box {
    let form = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .homogeneous(true)
        .spacing(6)
        .build();

    form.append(
        &gtk4::Label::builder()
            .label(label)
            .halign(Align::End)
            .css_classes(vec!["darkened"])
            .build(),
    );
    form.append(
        &gtk4::Label::builder()
            .label(value)
            .max_width_chars(50)
            .wrap(true)
            .halign(Align::Start)
            .selectable(true)
            .build(),
    );
    form
}

fn status_entries_from_json(value: &serde_json::Value) -> Vec<(String, String)> {
    let mut entries = vec![];

    let state = value.get("state").and_then(|v| v.as_str()).unwrap_or("unknown");
    entries.push(("State:".to_string(), state.to_string()));

    if let Some(server) = value.get("server").and_then(|v| v.as_str()) {
        entries.push(("Server:".to_string(), server.to_string()));
    }
    if let Some(ip) = value.get("ip_address").and_then(|v| v.as_str()) {
        entries.push(("IP Address:".to_string(), ip.to_string()));
    }
    if let Some(uptime) = value.get("uptime").and_then(|v| v.as_str()) {
        entries.push(("Uptime:".to_string(), uptime.to_string()));
    }
    if let Some(tx) = value.get("tx_bytes").and_then(|v| v.as_u64()) {
        entries.push(("TX:".to_string(), format_bytes(tx)));
    }
    if let Some(rx) = value.get("rx_bytes").and_then(|v| v.as_u64()) {
        entries.push(("RX:".to_string(), format_bytes(rx)));
    }
    if let Some(dns) = value.get("dns").and_then(|v| v.as_str()) {
        entries.push(("DNS:".to_string(), dns.to_string()));
    }

    entries
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

pub async fn show_status_dialog(sender: Sender<TrayEvent>, exit_on_close: bool, api: ApiClient) {
    if let Some(window) = get_window("status") {
        window.present();
        return;
    }

    let window = gtk4::Window::builder()
        .title("SNX Edge - Status")
        .transient_for(&main_window())
        .build();

    let ok = gtk4::Button::builder().label("OK").build();

    ok.connect_clicked(clone!(
        #[weak]
        window,
        move |_| window.close()
    ));

    let copy = gtk4::Button::builder().label("Copy").build();

    let api_copy = api.clone();
    copy.connect_clicked(move |_| {
        let api = api_copy.clone();
        tokio::spawn(async move {
            if let Ok(status_json) = api.tunnel_status().await {
                let entries = status_entries_from_json(&status_json);
                let text = entries.iter().fold(String::new(), |mut acc, (k, v)| {
                    acc.push_str(&format!("{} {}\n", k, v));
                    acc
                });
                glib::idle_add_once(move || {
                    gtk4::gdk::Display::default().unwrap().clipboard().set_text(&text);
                });
            }
        });
    });

    let settings = gtk4::Button::builder().label("Settings").build();

    let sender2 = sender.clone();
    settings.connect_clicked(move |_| {
        let sender = sender2.clone();
        tokio::spawn(async move { sender.send(TrayEvent::Settings).await });
    });

    let button_box = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .margin_top(6)
        .margin_start(6)
        .margin_end(6)
        .margin_bottom(6)
        .homogeneous(true)
        .halign(Align::End)
        .build();

    let connect = {
        let sender2 = sender.clone();
        let btn = gtk4::Button::builder().label("Connect").build();
        btn.connect_clicked(move |btn| {
            let sender = sender2.clone();
            tokio::spawn(async move { sender.send(TrayEvent::Connect(String::new())).await });
            btn.set_sensitive(false);
        });
        btn.upcast::<gtk4::Widget>()
    };

    let disconnect = gtk4::Button::builder().label("Disconnect").build();

    let sender2 = sender.clone();
    disconnect.connect_clicked(move |btn| {
        let sender = sender2.clone();
        tokio::spawn(async move { sender.send(TrayEvent::Disconnect).await });
        btn.set_sensitive(false);
    });

    button_box.append(&connect);
    button_box.append(&disconnect);
    button_box.append(&settings);
    button_box.append(&copy);
    button_box.append(&ok);

    let content = gtk4::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(6)
        .build();
    window.set_child(Some(&content));

    let inner = gtk4::Box::builder()
        .orientation(Orientation::Vertical)
        .margin_bottom(6)
        .margin_top(6)
        .margin_start(6)
        .margin_end(6)
        .spacing(6)
        .vexpand(true)
        .build();
    inner.add_css_class("bordered");

    // Routing health indicator row
    let routing_icon = gtk4::Image::from_icon_name("dialog-question-symbolic");
    let routing_row = libadwaita::ActionRow::builder()
        .title("Routing")
        .subtitle("Checking...")
        .activatable(true)
        .build();
    routing_row.add_suffix(&routing_icon);

    let sender_routing = sender.clone();
    routing_row.connect_activated(move |_| {
        let sender = sender_routing.clone();
        tokio::spawn(async move { sender.send(TrayEvent::Routing).await });
    });

    let update_ui = clone!(
        #[weak]
        inner,
        #[weak]
        connect,
        #[weak]
        disconnect,
        move |state: &ConnectionState, entries: &[(String, String)]| {
            connect.set_sensitive(matches!(state, ConnectionState::Disconnected));
            disconnect.set_sensitive(!matches!(state, ConnectionState::Disconnected));

            let mut child = inner.first_child();
            while let Some(widget) = child {
                child = widget.next_sibling();
                inner.remove(&widget);
            }

            for (key, value) in entries {
                inner.append(&status_entry(key, value));
            }
        }
    );

    let update_routing = clone!(
        #[weak]
        routing_icon,
        #[weak]
        routing_row,
        move |health: &RoutingHealth| {
            routing_icon.set_icon_name(Some(health.icon_name()));
            routing_row.set_subtitle(health.label());
        }
    );

    let (tx, rx) = async_channel::bounded::<(ConnectionState, Vec<(String, String)>, Option<RoutingHealth>)>(1);

    glib::spawn_future_local(async move {
        while let Ok((state, entries, routing_health)) = rx.recv().await {
            update_ui(&state, &entries);
            if let Some(health) = routing_health {
                update_routing(&health);
            }
        }
    });

    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let mut old_state = ConnectionState::Error("Connecting to server...".to_string());
        let mut poll_count: u32 = 0;
        let mut last_routing_health = RoutingHealth::Unknown;
        loop {
            // Check routing diagnostics every 5th poll (~10 seconds) or on first load
            let routing_health = if poll_count % 5 == 0 {
                match api.routing_diagnostics().await {
                    Ok(json) => {
                        let health = RoutingHealth::from_diagnostics(&json);
                        if health != last_routing_health {
                            last_routing_health = health.clone();
                            Some(health)
                        } else {
                            None
                        }
                    }
                    Err(_) => {
                        if last_routing_health != RoutingHealth::Error {
                            last_routing_health = RoutingHealth::Error;
                            Some(RoutingHealth::Error)
                        } else {
                            None
                        }
                    }
                }
            } else {
                None
            };

            let _new_state = match api.tunnel_status().await {
                Ok(json) => {
                    let state = ConnectionState::from_json(&json);
                    let entries = status_entries_from_json(&json);
                    if !same_status(&state, &old_state) || routing_health.is_some() {
                        old_state = state.clone();
                        if tx.send((state, entries, routing_health)).await.is_err() {
                            break;
                        }
                    }
                    old_state.clone()
                }
                Err(e) => {
                    let state = ConnectionState::Error(e.to_string());
                    let entries = vec![("State:".to_string(), format!("Error: {}", e))];
                    if !same_status(&state, &old_state) || routing_health.is_some() {
                        old_state = state.clone();
                        if tx.send((state, entries, routing_health)).await.is_err() {
                            break;
                        }
                    }
                    old_state.clone()
                }
            };

            poll_count = poll_count.wrapping_add(1);

            tokio::select! {
                _ = tokio::time::sleep(POLL_INTERVAL) => {}
                _ = &mut stop_rx => break,
            }
        }
    });

    content.append(&inner);
    content.append(&routing_row);
    content.append(&button_box);

    window.set_default_widget(Some(&ok));
    gtk4::prelude::GtkWindowExt::set_focus(&window, Some(&ok));

    let (close_tx, close_rx) = async_channel::bounded::<()>(1);
    window.connect_close_request(move |_| {
        let _ = close_tx.try_send(());
        glib::Propagation::Proceed
    });

    if !exit_on_close {
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
    }

    set_window("status", Some(window.clone()));
    window.present();
    close_rx.recv().await.ok();
    set_window("status", None::<gtk4::Window>);
    let _ = stop_tx.send(());

    if exit_on_close {
        let sender2 = sender.clone();
        tokio::spawn(async move { sender2.send(TrayEvent::Exit).await });
    }
}
