use adw::prelude::*;
use gtk4::prelude::*;
use libadwaita as adw;

// ============================================================================
// Widget names used for tree lookups
// ============================================================================

const CLIENTS_LIST: &str = "clients-list";
const BYPASS_LIST: &str = "bypass-list";
const DIAGNOSTICS_STATUS: &str = "diagnostics-status";

// ============================================================================
// Public: build the routing management window
// ============================================================================

/// Build the routing management window with VPN Clients, VPN Bypass, and
/// Diagnostics sections.  The window is modal and transient for `parent`.
pub fn build_routing_window(parent: &impl IsA<gtk4::Window>) -> adw::Window {
    let window = adw::Window::builder()
        .title("Routing Management")
        .default_width(560)
        .default_height(700)
        .modal(true)
        .transient_for(parent)
        .build();

    // ── Header ──────────────────────────────────────────────────────────

    let header = adw::HeaderBar::new();

    // ── VPN Clients section ─────────────────────────────────────────────

    let clients_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::Single)
        .css_classes(vec!["boxed-list".to_string()])
        .build();
    clients_list.set_widget_name(CLIENTS_LIST);

    let clients_placeholder = adw::StatusPage::builder()
        .icon_name("network-server-symbolic")
        .title("No VPN Clients")
        .description("Add hosts that should be routed through the VPN tunnel.")
        .build();
    clients_list.set_placeholder(Some(&clients_placeholder));

    let clients_group = adw::PreferencesGroup::builder()
        .title("VPN Clients")
        .description("Hosts whose traffic is routed through the VPN tunnel")
        .build();
    clients_group.add(&clients_list);

    let clients_btn_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk4::Align::Center)
        .margin_top(8)
        .margin_bottom(12)
        .build();

    let add_host_btn = gtk4::Button::builder()
        .label("Add Host")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .build();

    let add_my_ip_btn = gtk4::Button::builder()
        .label("Add My IP")
        .css_classes(vec!["pill".to_string()])
        .build();

    let remove_client_btn = gtk4::Button::builder()
        .label("Remove")
        .css_classes(vec!["destructive-action".to_string(), "pill".to_string()])
        .sensitive(false)
        .build();

    clients_btn_box.append(&add_host_btn);
    clients_btn_box.append(&add_my_ip_btn);
    clients_btn_box.append(&remove_client_btn);

    // Enable Remove only when a row is selected.
    clients_list.connect_row_selected({
        let remove_btn = remove_client_btn.clone();
        move |_, row| {
            remove_btn.set_sensitive(row.is_some());
        }
    });

    // ── VPN Bypass section ──────────────────────────────────────────────

    let bypass_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::Single)
        .css_classes(vec!["boxed-list".to_string()])
        .build();
    bypass_list.set_widget_name(BYPASS_LIST);

    let bypass_placeholder = adw::StatusPage::builder()
        .icon_name("network-offline-symbolic")
        .title("No Bypass Addresses")
        .description("Add addresses that should bypass the VPN tunnel.")
        .build();
    bypass_list.set_placeholder(Some(&bypass_placeholder));

    let bypass_group = adw::PreferencesGroup::builder()
        .title("VPN Bypass")
        .description("Addresses excluded from VPN routing")
        .build();
    bypass_group.add(&bypass_list);

    let bypass_btn_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk4::Align::Center)
        .margin_top(8)
        .margin_bottom(12)
        .build();

    let add_bypass_btn = gtk4::Button::builder()
        .label("Add Host")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .build();

    let remove_bypass_btn = gtk4::Button::builder()
        .label("Remove")
        .css_classes(vec!["destructive-action".to_string(), "pill".to_string()])
        .sensitive(false)
        .build();

    bypass_btn_box.append(&add_bypass_btn);
    bypass_btn_box.append(&remove_bypass_btn);

    bypass_list.connect_row_selected({
        let remove_btn = remove_bypass_btn.clone();
        move |_, row| {
            remove_btn.set_sensitive(row.is_some());
        }
    });

    // ── Diagnostics section ─────────────────────────────────────────────

    let diag_status = adw::StatusPage::builder()
        .icon_name("emblem-ok-symbolic")
        .title("Healthy")
        .description("PBR routing is configured correctly.")
        .build();
    diag_status.set_widget_name(DIAGNOSTICS_STATUS);

    let diag_btn_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk4::Align::Center)
        .margin_top(8)
        .margin_bottom(12)
        .build();

    let run_diag_btn = gtk4::Button::builder()
        .label("Run Diagnostics")
        .css_classes(vec!["pill".to_string()])
        .build();

    let setup_pbr_btn = gtk4::Button::builder()
        .label("Setup PBR")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .build();

    let teardown_pbr_btn = gtk4::Button::builder()
        .label("Teardown PBR")
        .css_classes(vec!["destructive-action".to_string(), "pill".to_string()])
        .tooltip_text("Admin only -- removes all managed PBR rules")
        .build();

    diag_btn_box.append(&run_diag_btn);
    diag_btn_box.append(&setup_pbr_btn);
    diag_btn_box.append(&teardown_pbr_btn);

    let diag_group = adw::PreferencesGroup::builder()
        .title("Diagnostics")
        .description("PBR health and management")
        .build();
    diag_group.add(&diag_status);

    // ── Layout (vertical) ───────────────────────────────────────────────

    let page = adw::PreferencesPage::new();
    page.add(&clients_group);
    page.add(&bypass_group);
    page.add(&diag_group);

    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();

    content.append(&header);
    content.append(&page);
    content.append(&clients_btn_box);
    content.append(&bypass_btn_box);
    content.append(&diag_btn_box);

    // Re-order: put button boxes right after their respective sections
    // by using a single scrollable column instead.
    // Actually, let's use a flat Box layout for precise control.

    let outer = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();

    let scrolled = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .build();

    let inner = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .margin_start(16)
        .margin_end(16)
        .margin_top(8)
        .margin_bottom(8)
        .spacing(4)
        .build();

    // Clients
    let clients_label = gtk4::Label::builder()
        .label("VPN Clients")
        .css_classes(vec!["title-3".to_string()])
        .halign(gtk4::Align::Start)
        .margin_top(8)
        .build();
    let clients_desc = gtk4::Label::builder()
        .label("Hosts whose traffic is routed through the VPN tunnel")
        .css_classes(vec!["dim-label".to_string()])
        .halign(gtk4::Align::Start)
        .margin_bottom(4)
        .build();

    inner.append(&clients_label);
    inner.append(&clients_desc);
    inner.append(&clients_list);
    inner.append(&clients_btn_box);

    // Separator
    inner.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));

    // Bypass
    let bypass_label = gtk4::Label::builder()
        .label("VPN Bypass")
        .css_classes(vec!["title-3".to_string()])
        .halign(gtk4::Align::Start)
        .margin_top(8)
        .build();
    let bypass_desc = gtk4::Label::builder()
        .label("Addresses excluded from VPN routing")
        .css_classes(vec!["dim-label".to_string()])
        .halign(gtk4::Align::Start)
        .margin_bottom(4)
        .build();

    inner.append(&bypass_label);
    inner.append(&bypass_desc);
    inner.append(&bypass_list);
    inner.append(&bypass_btn_box);

    // Separator
    inner.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));

    // Diagnostics
    let diag_label = gtk4::Label::builder()
        .label("Diagnostics")
        .css_classes(vec!["title-3".to_string()])
        .halign(gtk4::Align::Start)
        .margin_top(8)
        .build();

    inner.append(&diag_label);
    inner.append(&diag_status);
    inner.append(&diag_btn_box);

    scrolled.set_child(Some(&inner));
    outer.append(&header);
    outer.append(&scrolled);

    window.set_content(Some(&outer));

    // ── Signal: Add Host (clients) ──────────────────────────────────────

    add_host_btn.connect_clicked({
        let win = window.clone();
        move |_| {
            show_add_address_dialog(&win, "Add VPN Client");
        }
    });

    // ── Signal: Add My IP (placeholder) ─────────────────────────────────

    add_my_ip_btn.connect_clicked({
        let win = window.clone();
        move |_| {
            let toast = adw::Toast::new("Add My IP: will be resolved at runtime");
            if let Some(overlay) = find_toast_overlay(&win) {
                overlay.add_toast(toast);
            }
        }
    });

    // ── Signal: Remove client ───────────────────────────────────────────

    remove_client_btn.connect_clicked({
        let list = clients_list.clone();
        move |_| {
            if let Some(row) = list.selected_row() {
                list.remove(&row);
            }
        }
    });

    // ── Signal: Add bypass ──────────────────────────────────────────────

    add_bypass_btn.connect_clicked({
        let win = window.clone();
        move |_| {
            show_add_address_dialog(&win, "Add Bypass Address");
        }
    });

    // ── Signal: Remove bypass ───────────────────────────────────────────

    remove_bypass_btn.connect_clicked({
        let list = bypass_list.clone();
        move |_| {
            if let Some(row) = list.selected_row() {
                list.remove(&row);
            }
        }
    });

    // ── Signal: Run Diagnostics ─────────────────────────────────────────

    run_diag_btn.connect_clicked({
        let status = diag_status.clone();
        move |_| {
            // Placeholder: in production this triggers an API call
            status.set_title("Running...");
            status.set_icon_name(Some("content-loading-symbolic"));
        }
    });

    // ── Signal: Setup PBR ───────────────────────────────────────────────

    setup_pbr_btn.connect_clicked({
        let status = diag_status.clone();
        move |_| {
            status.set_title("Setting up PBR...");
            status.set_icon_name(Some("content-loading-symbolic"));
        }
    });

    // ── Signal: Teardown PBR ────────────────────────────────────────────

    teardown_pbr_btn.connect_clicked({
        let status = diag_status.clone();
        move |_| {
            status.set_title("Tearing down PBR...");
            status.set_icon_name(Some("content-loading-symbolic"));
        }
    });

    window
}

// ============================================================================
// Public: data-update helpers
// ============================================================================

/// Replace the contents of the VPN Clients list with the given entries.
///
/// Each entry is expected to have `"address"` and optionally `"comment"` keys.
pub fn update_clients(window: &adw::Window, clients: &[serde_json::Value]) {
    if let Some(list) = find_list_box(window, CLIENTS_LIST) {
        clear_list_box(&list);
        for entry in clients {
            let address = entry["address"].as_str().unwrap_or("unknown");
            let comment = entry["comment"].as_str().unwrap_or("");
            let id = entry[".id"]
                .as_str()
                .or_else(|| entry["id"].as_str())
                .unwrap_or("");

            let row = adw::ActionRow::builder()
                .title(address)
                .subtitle(comment)
                .build();
            row.set_widget_name(id);

            let icon = gtk4::Image::from_icon_name("network-server-symbolic");
            row.add_prefix(&icon);

            list.append(&row);
        }
    }
}

/// Replace the contents of the VPN Bypass list with the given entries.
///
/// Each entry is expected to have `"address"` and optionally `"comment"` keys.
pub fn update_bypass(window: &adw::Window, bypass: &[serde_json::Value]) {
    if let Some(list) = find_list_box(window, BYPASS_LIST) {
        clear_list_box(&list);
        for entry in bypass {
            let address = entry["address"].as_str().unwrap_or("unknown");
            let comment = entry["comment"].as_str().unwrap_or("");
            let id = entry[".id"]
                .as_str()
                .or_else(|| entry["id"].as_str())
                .unwrap_or("");

            let row = adw::ActionRow::builder()
                .title(address)
                .subtitle(comment)
                .build();
            row.set_widget_name(id);

            let icon = gtk4::Image::from_icon_name("network-offline-symbolic");
            row.add_prefix(&icon);

            list.append(&row);
        }
    }
}

/// Update the diagnostics status page from a server response.
///
/// Expected keys: `"healthy"` (bool), `"summary"` (string),
/// `"details"` (optional string).
pub fn update_diagnostics(window: &adw::Window, diag: &serde_json::Value) {
    if let Some(status) = find_status_page(window, DIAGNOSTICS_STATUS) {
        let healthy = diag["healthy"].as_bool().unwrap_or(false);
        let summary = diag["summary"].as_str().unwrap_or("Unknown");
        let details = diag["details"].as_str().unwrap_or("");

        if healthy {
            status.set_icon_name(Some("emblem-ok-symbolic"));
            status.set_title("Healthy");
        } else {
            status.set_icon_name(Some("dialog-warning-symbolic"));
            status.set_title("Unhealthy");
        }

        status.set_description(Some(&format!("{summary}\n{details}")));
    }
}

// ============================================================================
// Internal: add-address dialog
// ============================================================================

/// Show a dialog that collects an IP address and optional comment.
fn show_add_address_dialog(parent: &adw::Window, title: &str) {
    let dialog = adw::Window::builder()
        .title(title)
        .default_width(380)
        .default_height(260)
        .modal(true)
        .transient_for(parent)
        .build();

    let address_row = adw::EntryRow::builder()
        .title("Address (IP or CIDR)")
        .build();

    let comment_row = adw::EntryRow::builder().title("Comment").build();

    let group = adw::PreferencesGroup::builder()
        .title("New Address")
        .build();
    group.add(&address_row);
    group.add(&comment_row);

    let page = adw::PreferencesPage::new();
    page.add(&group);

    let add_btn = gtk4::Button::builder()
        .label("Add")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .halign(gtk4::Align::Center)
        .margin_top(12)
        .margin_bottom(12)
        .build();

    let header = adw::HeaderBar::new();

    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    content.append(&header);
    content.append(&page);
    content.append(&add_btn);

    dialog.set_content(Some(&content));

    add_btn.connect_clicked({
        let dlg = dialog.clone();
        let address_row = address_row.clone();
        move |_| {
            let _address = address_row.text().to_string();
            // In production the caller would invoke the API here.
            dlg.close();
        }
    });

    // Allow Enter in comment field to submit.
    comment_row.connect_apply({
        let add_btn = add_btn.clone();
        move |_| {
            add_btn.emit_clicked();
        }
    });

    dialog.present();
}

// ============================================================================
// Internal: widget-tree helpers
// ============================================================================

/// Recursively search the widget tree for a `ListBox` with the given name.
fn find_list_box(root: &impl IsA<gtk4::Widget>, name: &str) -> Option<gtk4::ListBox> {
    find_widget_by_name::<gtk4::ListBox>(root.upcast_ref(), name)
}

/// Recursively search the widget tree for a `StatusPage` with the given name.
fn find_status_page(root: &impl IsA<gtk4::Widget>, name: &str) -> Option<adw::StatusPage> {
    find_widget_by_name::<adw::StatusPage>(root.upcast_ref(), name)
}

/// Attempt to find a `ToastOverlay` in the widget tree for ephemeral messages.
fn find_toast_overlay(root: &impl IsA<gtk4::Widget>) -> Option<adw::ToastOverlay> {
    find_widget_by_type::<adw::ToastOverlay>(root.upcast_ref())
}

fn find_widget_by_name<T: IsA<gtk4::Widget>>(widget: &gtk4::Widget, name: &str) -> Option<T> {
    if widget.widget_name() == name {
        if let Some(typed) = widget.clone().downcast::<T>().ok() {
            return Some(typed);
        }
    }

    let mut child = widget.first_child();
    while let Some(c) = child {
        if let Some(found) = find_widget_by_name::<T>(&c, name) {
            return Some(found);
        }
        child = c.next_sibling();
    }
    None
}

fn find_widget_by_type<T: IsA<gtk4::Widget>>(widget: &gtk4::Widget) -> Option<T> {
    if let Some(typed) = widget.clone().downcast::<T>().ok() {
        return Some(typed);
    }

    let mut child = widget.first_child();
    while let Some(c) = child {
        if let Some(found) = find_widget_by_type::<T>(&c) {
            return Some(found);
        }
        child = c.next_sibling();
    }
    None
}

/// Remove all rows from a `ListBox`.
fn clear_list_box(list: &gtk4::ListBox) {
    while let Some(row) = list.row_at_index(0) {
        list.remove(&row);
    }
}
