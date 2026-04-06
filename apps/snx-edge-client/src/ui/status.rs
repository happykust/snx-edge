use gtk4::prelude::*;
use libadwaita as adw;
use adw::prelude::*;

// ═══════════════════════════════════════════════════════════════════════
//  Main status window
// ═══════════════════════════════════════════════════════════════════════

/// Build the primary application window that displays live VPN status.
pub fn build_status_window(app: &adw::Application) -> adw::ApplicationWindow {
    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("SNX Edge")
        .default_width(480)
        .default_height(640)
        .build();

    // ── Header bar ───────────────────────────────────────────────────

    let header = adw::HeaderBar::new();

    // ── Status page (hero area) ──────────────────────────────────────

    let status_page = adw::StatusPage::builder()
        .icon_name("network-vpn-disconnected")
        .title("Disconnected")
        .description("Not connected to any server")
        .build();
    status_page.set_widget_name("vpn_status_page");

    // ── Info rows ────────────────────────────────────────────────────

    let uptime_row = adw::ActionRow::builder()
        .title("Uptime")
        .subtitle("—")
        .build();
    uptime_row.set_widget_name("uptime_row");

    let traffic_row = adw::ActionRow::builder()
        .title("Traffic")
        .subtitle("↑ 0 MB / ↓ 0 MB")
        .build();
    traffic_row.set_widget_name("traffic_row");

    let profile_row = adw::ActionRow::builder()
        .title("Profile")
        .subtitle("None")
        .build();
    profile_row.set_widget_name("profile_row");

    let info_group = adw::PreferencesGroup::builder()
        .title("Connection Details")
        .margin_start(12)
        .margin_end(12)
        .build();
    info_group.add(&uptime_row);
    info_group.add(&traffic_row);
    info_group.add(&profile_row);

    // ── Routing health indicator ─────────────────────────────────────

    let routing_dot = gtk4::Label::builder()
        .label("●")
        .css_classes(vec!["routing-unknown".to_string()])
        .build();

    let routing_row = adw::ActionRow::builder()
        .title("Routing")
        .subtitle("Unknown")
        .build();
    routing_row.set_widget_name("routing_row");
    routing_row.add_prefix(&routing_dot);

    let routing_group = adw::PreferencesGroup::builder()
        .margin_start(12)
        .margin_end(12)
        .build();
    routing_group.add(&routing_row);

    // ── Action controls ──────────────────────────────────────────────

    let profile_model = gtk4::StringList::new(&["Default"]);
    let profile_dropdown = gtk4::DropDown::builder()
        .model(&profile_model)
        .halign(gtk4::Align::Center)
        .build();
    profile_dropdown.set_widget_name("profile_dropdown");

    let toggle_btn = gtk4::Button::builder()
        .label("Connect")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .halign(gtk4::Align::Center)
        .build();
    toggle_btn.set_widget_name("toggle_btn");

    let actions_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(12)
        .halign(gtk4::Align::Center)
        .margin_top(12)
        .margin_bottom(24)
        .build();
    actions_box.append(&profile_dropdown);
    actions_box.append(&toggle_btn);

    // ── Assemble content ─────────────────────────────────────────────

    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();

    content.append(&header);

    let clamp = adw::Clamp::builder()
        .maximum_size(600)
        .child(&{
            let inner = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Vertical)
                .spacing(12)
                .build();
            inner.append(&status_page);
            inner.append(&info_group);
            inner.append(&routing_group);
            inner.append(&actions_box);
            inner
        })
        .build();

    content.append(&clamp);
    window.set_content(Some(&content));

    // ── CSS for the routing health dot colours ───────────────────────

    let provider = gtk4::CssProvider::new();
    provider.load_from_string(
        r#"
        .routing-healthy  { color: #2ec27e; }
        .routing-degraded { color: #e5a50a; }
        .routing-unknown  { color: #9a9996; }
        .routing-error    { color: #e01b24; }
        "#,
    );

    gtk4::style_context_add_provider_for_display(
        &gtk4::gdk::Display::default().expect("display required"),
        &provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    window
}

// ═══════════════════════════════════════════════════════════════════════
//  Status update helpers
// ═══════════════════════════════════════════════════════════════════════

/// Helper: walk named children under `root` to find a widget by its
/// GtkWidget name (set via `set_widget_name`).
fn find_by_name<W: IsA<gtk4::Widget>>(root: &gtk4::Widget, name: &str) -> Option<W> {
    let mut queue: Vec<gtk4::Widget> = vec![root.clone()];
    while let Some(w) = queue.pop() {
        if w.widget_name() == name {
            return w.downcast::<W>().ok();
        }
        let mut child = w.first_child();
        while let Some(c) = child {
            queue.push(c.clone());
            child = c.next_sibling();
        }
    }
    None
}

/// Refresh every status field from a `TunnelStatus` JSON value.
///
/// Expected shape (from the server):
/// ```json
/// {
///   "connection": {
///     "state": "Connected" | "Disconnected" | "Connecting" | "Error",
///     "server_name": "vpn.example.com",
///     "ip_address": "10.0.0.5",
///     "error": "optional error string"
///   },
///   "uptime_seconds": 123,
///   "tx_bytes": 0,
///   "rx_bytes": 0,
///   "profile": "Office",
///   "routing_health": "Healthy" | "Degraded" | "Unknown"
/// }
/// ```
pub fn update_status(window: &adw::ApplicationWindow, status: &serde_json::Value) {
    let root: gtk4::Widget = window.clone().upcast();

    let connection = status.get("connection");

    // ── Status page (icon + title + description) ─────────────────────

    if let Some(status_page) = find_by_name::<adw::StatusPage>(&root, "vpn_status_page") {
        let state = connection
            .and_then(|c| c.get("state"))
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");

        let (icon, title) = match state {
            "Connected" => ("network-vpn", "Connected"),
            "Connecting" => ("network-vpn-acquiring", "Connecting..."),
            "Error" => ("dialog-error", "Error"),
            _ => ("network-vpn-disconnected", "Disconnected"),
        };

        status_page.set_icon_name(Some(icon));
        status_page.set_title(title);

        let description = if state == "Connected" {
            let server = connection
                .and_then(|c| c.get("server_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("—");
            let ip = connection
                .and_then(|c| c.get("ip_address"))
                .and_then(|v| v.as_str())
                .unwrap_or("—");
            format!("{server} ({ip})")
        } else if state == "Error" {
            connection
                .and_then(|c| c.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error")
                .to_string()
        } else {
            "Not connected to any server".to_string()
        };
        status_page.set_description(Some(&description));
    }

    // ── Uptime ───────────────────────────────────────────────────────

    if let Some(uptime_row) = find_by_name::<adw::ActionRow>(&root, "uptime_row") {
        let uptime = status
            .get("uptime_seconds")
            .and_then(|v| v.as_u64())
            .map(|secs| {
                let h = secs / 3600;
                let m = (secs % 3600) / 60;
                let s = secs % 60;
                format!("{h}h {m}m {s}s")
            })
            .unwrap_or_else(|| "—".to_string());
        uptime_row.set_subtitle(&uptime);
    }

    // ── Traffic ──────────────────────────────────────────────────────

    if let Some(traffic_row) = find_by_name::<adw::ActionRow>(&root, "traffic_row") {
        let tx = status
            .get("tx_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let rx = status
            .get("rx_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let fmt = |bytes: u64| -> String {
            if bytes < 1_000_000 {
                format!("{:.1} KB", bytes as f64 / 1_000.0)
            } else if bytes < 1_000_000_000 {
                format!("{:.1} MB", bytes as f64 / 1_000_000.0)
            } else {
                format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
            }
        };

        traffic_row.set_subtitle(&format!("↑ {} / ↓ {}", fmt(tx), fmt(rx)));
    }

    // ── Profile ──────────────────────────────────────────────────────

    if let Some(profile_row) = find_by_name::<adw::ActionRow>(&root, "profile_row") {
        let profile = status
            .get("profile")
            .and_then(|v| v.as_str())
            .unwrap_or("None");
        profile_row.set_subtitle(profile);
    }

    // ── Routing health ───────────────────────────────────────────────

    if let Some(routing_row) = find_by_name::<adw::ActionRow>(&root, "routing_row") {
        let health = status
            .get("routing_health")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");

        routing_row.set_subtitle(health);

        // Update the colour-dot prefix.
        if let Some(dot) = routing_row.first_child() {
            // Try to get the Label that is the prefix.
            if let Ok(label) = dot.downcast::<gtk4::Label>() {
                let classes = ["routing-healthy", "routing-degraded", "routing-unknown", "routing-error"];
                for cls in &classes {
                    label.remove_css_class(cls);
                }
                let css_class = match health {
                    "Healthy" => "routing-healthy",
                    "Degraded" => "routing-degraded",
                    "Error" => "routing-error",
                    _ => "routing-unknown",
                };
                label.add_css_class(css_class);
            }
        }
    }

    // ── Toggle button label ──────────────────────────────────────────

    if let Some(toggle_btn) = find_by_name::<gtk4::Button>(&root, "toggle_btn") {
        let state = connection
            .and_then(|c| c.get("state"))
            .and_then(|v| v.as_str())
            .unwrap_or("Disconnected");

        match state {
            "Connected" | "Connecting" => {
                toggle_btn.set_label("Disconnect");
                toggle_btn.remove_css_class("suggested-action");
                toggle_btn.add_css_class("destructive-action");
            }
            _ => {
                toggle_btn.set_label("Connect");
                toggle_btn.remove_css_class("destructive-action");
                toggle_btn.add_css_class("suggested-action");
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Profile dropdown
// ═══════════════════════════════════════════════════════════════════════

/// Replace the contents of the profile `DropDown` with names extracted
/// from the JSON array.
///
/// Each element is expected to have at least a `"name"` string field.
pub fn update_profiles(dropdown: &gtk4::DropDown, profiles: &[serde_json::Value]) {
    let names: Vec<&str> = profiles
        .iter()
        .filter_map(|p| p.get("name").and_then(|n| n.as_str()))
        .collect();

    let model = gtk4::StringList::new(&names);
    dropdown.set_model(Some(&model));

    // Select the first entry by default if available.
    if !names.is_empty() {
        dropdown.set_selected(0);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  MFA dialog
// ═══════════════════════════════════════════════════════════════════════

/// Present a small modal dialog requesting an OTP / challenge-response
/// code from the user.
///
/// `prompt` is displayed as the dialog description (e.g. "Enter your
/// one-time password").  `on_submit` receives the text the user typed
/// when they press Submit.
pub fn show_mfa_dialog(
    parent: &adw::ApplicationWindow,
    prompt: &str,
    on_submit: impl Fn(String) + 'static,
) {
    let dialog = adw::Window::builder()
        .title("Multi-Factor Authentication")
        .default_width(360)
        .default_height(220)
        .modal(true)
        .transient_for(parent)
        .build();

    let header = adw::HeaderBar::new();

    let prompt_label = gtk4::Label::builder()
        .label(prompt)
        .wrap(true)
        .margin_start(12)
        .margin_end(12)
        .margin_top(12)
        .build();

    let entry = adw::EntryRow::builder()
        .title("Code")
        .build();

    let entry_group = adw::PreferencesGroup::builder()
        .margin_start(12)
        .margin_end(12)
        .margin_top(12)
        .build();
    entry_group.add(&entry);

    let submit_btn = gtk4::Button::builder()
        .label("Submit")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .halign(gtk4::Align::Center)
        .margin_top(12)
        .margin_bottom(12)
        .build();

    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    content.append(&header);
    content.append(&prompt_label);
    content.append(&entry_group);
    content.append(&submit_btn);

    dialog.set_content(Some(&content));

    // ── Signals ──────────────────────────────────────────────────────

    submit_btn.connect_clicked({
        let entry = entry.clone();
        let dialog = dialog.clone();
        move |_| {
            let code = entry.text().to_string();
            on_submit(code);
            dialog.close();
        }
    });

    entry.connect_apply({
        let submit_btn = submit_btn.clone();
        move |_| {
            submit_btn.emit_clicked();
        }
    });

    dialog.present();
}
