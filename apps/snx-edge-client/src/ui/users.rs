use adw::prelude::*;
use gtk4::prelude::*;
use libadwaita as adw;

// ============================================================================
// Widget names used for tree lookups
// ============================================================================

const USERS_LIST: &str = "users-list";

// ============================================================================
// Public: build the user management window
// ============================================================================

/// Build the user management window (admin only).
///
/// Displays a list of all users with their role and enabled state, plus
/// buttons to add, delete, and reset passwords.
pub fn build_users_window(parent: &impl IsA<gtk4::Window>) -> adw::Window {
    let window = adw::Window::builder()
        .title("User Management")
        .default_width(520)
        .default_height(580)
        .modal(true)
        .transient_for(parent)
        .build();

    // ── Header ──────────────────────────────────────────────────────────

    let header = adw::HeaderBar::new();

    // ── Users list ──────────────────────────────────────────────────────

    let users_list = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::Single)
        .css_classes(vec!["boxed-list".to_string()])
        .build();
    users_list.set_widget_name(USERS_LIST);

    let placeholder = adw::StatusPage::builder()
        .icon_name("system-users-symbolic")
        .title("No Users")
        .description("No users have been created yet.")
        .build();
    users_list.set_placeholder(Some(&placeholder));

    let group = adw::PreferencesGroup::builder()
        .title("Users")
        .description("Manage server accounts and roles")
        .build();
    group.add(&users_list);

    let page = adw::PreferencesPage::new();
    page.add(&group);

    // ── Action buttons ──────────────────────────────────────────────────

    let btn_box = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk4::Align::Center)
        .margin_top(12)
        .margin_bottom(12)
        .build();

    let add_user_btn = gtk4::Button::builder()
        .label("Add User")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .build();

    let delete_user_btn = gtk4::Button::builder()
        .label("Delete User")
        .css_classes(vec!["destructive-action".to_string(), "pill".to_string()])
        .sensitive(false)
        .build();

    let reset_pw_btn = gtk4::Button::builder()
        .label("Reset Password")
        .css_classes(vec!["pill".to_string()])
        .sensitive(false)
        .build();

    btn_box.append(&add_user_btn);
    btn_box.append(&delete_user_btn);
    btn_box.append(&reset_pw_btn);

    // Enable Delete / Reset only when a row is selected.
    users_list.connect_row_selected({
        let del_btn = delete_user_btn.clone();
        let pw_btn = reset_pw_btn.clone();
        move |_, row| {
            let has_selection = row.is_some();
            del_btn.set_sensitive(has_selection);
            pw_btn.set_sensitive(has_selection);
        }
    });

    // ── Layout ──────────────────────────────────────────────────────────

    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();

    content.append(&header);
    content.append(&page);
    content.append(&btn_box);

    window.set_content(Some(&content));

    // ── Signal: Add User ────────────────────────────────────────────────

    add_user_btn.connect_clicked({
        let win = window.clone();
        move |_| {
            show_add_user_dialog(&win, |username, password, role, comment| {
                // Placeholder: in production the caller would invoke the API.
                let _ = (username, password, role, comment);
            });
        }
    });

    // ── Signal: Delete User ─────────────────────────────────────────────

    delete_user_btn.connect_clicked({
        let list = users_list.clone();
        let win = window.clone();
        move |_| {
            if let Some(row) = list.selected_row() {
                show_confirm_dialog(
                    &win,
                    "Delete User",
                    "Are you sure you want to delete this user? This action cannot be undone.",
                    {
                        let list = list.clone();
                        let row = row.clone();
                        move || {
                            list.remove(&row);
                        }
                    },
                );
            }
        }
    });

    // ── Signal: Reset Password ──────────────────────────────────────────

    reset_pw_btn.connect_clicked({
        let win = window.clone();
        let list = users_list.clone();
        move |_| {
            if let Some(row) = list.selected_row() {
                show_reset_password_dialog(&win, &row);
            }
        }
    });

    // ── Signal: Row activated (edit user) ───────────────────────────────

    users_list.connect_row_activated({
        let win = window.clone();
        move |_, row| {
            show_edit_user_popover(&win, row);
        }
    });

    window
}

// ============================================================================
// Public: add-user dialog
// ============================================================================

/// Show a dialog to create a new user.
///
/// The `on_create` callback receives `(username, password, role, comment)`.
pub fn show_add_user_dialog(
    parent: &impl IsA<gtk4::Window>,
    on_create: impl Fn(String, String, String, String) + 'static,
) {
    let dialog = adw::Window::builder()
        .title("Add User")
        .default_width(400)
        .default_height(400)
        .modal(true)
        .transient_for(parent)
        .build();

    // ── Fields ───────────────────────────────────────────────────────────

    let username_row = adw::EntryRow::builder().title("Username").build();

    let password_row = adw::PasswordEntryRow::builder().title("Password").build();

    let role_model = gtk4::StringList::new(&["admin", "operator", "viewer"]);
    let role_row = adw::ComboRow::builder()
        .title("Role")
        .model(&role_model)
        .selected(2) // default to "viewer"
        .build();

    let comment_row = adw::EntryRow::builder().title("Comment").build();

    let group = adw::PreferencesGroup::builder().title("New User").build();
    group.add(&username_row);
    group.add(&password_row);
    group.add(&role_row);
    group.add(&comment_row);

    let page = adw::PreferencesPage::new();
    page.add(&group);

    // ── Error label ──────────────────────────────────────────────────────

    let error_label = gtk4::Label::builder()
        .label("")
        .css_classes(vec!["error".to_string()])
        .wrap(true)
        .visible(false)
        .margin_start(12)
        .margin_end(12)
        .build();

    // ── Create button ────────────────────────────────────────────────────

    let create_btn = gtk4::Button::builder()
        .label("Create")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .halign(gtk4::Align::Center)
        .margin_top(12)
        .margin_bottom(12)
        .build();

    // ── Layout ───────────────────────────────────────────────────────────

    let header = adw::HeaderBar::new();

    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    content.append(&header);
    content.append(&page);
    content.append(&error_label);
    content.append(&create_btn);

    dialog.set_content(Some(&content));

    // ── Signals ──────────────────────────────────────────────────────────

    let roles = ["admin", "operator", "viewer"];

    create_btn.connect_clicked({
        let dlg = dialog.clone();
        let username_row = username_row.clone();
        let password_row = password_row.clone();
        let role_row = role_row.clone();
        let comment_row = comment_row.clone();
        let error_label = error_label.clone();
        move |_| {
            error_label.set_visible(false);

            let username = username_row.text().to_string();
            let password = password_row.text().to_string();
            let role_idx = role_row.selected() as usize;
            let role = roles.get(role_idx).unwrap_or(&"viewer").to_string();
            let comment = comment_row.text().to_string();

            if username.is_empty() {
                error_label.set_text("Username is required.");
                error_label.set_visible(true);
                return;
            }

            if password.is_empty() {
                error_label.set_text("Password is required.");
                error_label.set_visible(true);
                return;
            }

            on_create(username, password, role, comment);
            dlg.close();
        }
    });

    // Allow Enter in comment field to submit.
    comment_row.connect_apply({
        let create_btn = create_btn.clone();
        move |_| {
            create_btn.emit_clicked();
        }
    });

    dialog.present();
}

// ============================================================================
// Public: update users list from API data
// ============================================================================

/// Replace the contents of the users list with the given entries.
///
/// Each entry is expected to have `"id"`, `"username"`, `"role"`, `"comment"`,
/// and `"enabled"` keys matching the `UserResponse` model.
pub fn update_users(window: &adw::Window, users: &[serde_json::Value]) {
    if let Some(list) = find_list_box(window, USERS_LIST) {
        clear_list_box(&list);
        for user in users {
            let username = user["username"].as_str().unwrap_or("unknown");
            let role = user["role"].as_str().unwrap_or("viewer");
            let comment = user["comment"].as_str().unwrap_or("");
            let enabled = user["enabled"].as_bool().unwrap_or(true);
            let id = user["id"].as_str().unwrap_or("");

            let subtitle = if comment.is_empty() {
                format_role_badge(role, enabled)
            } else {
                format!("{} -- {}", format_role_badge(role, enabled), comment)
            };

            let row = adw::ActionRow::builder()
                .title(username)
                .subtitle(&subtitle)
                .activatable(true)
                .build();
            row.set_widget_name(id);

            // Role icon
            let icon_name = match role {
                "admin" => "starred-symbolic",
                "operator" => "emblem-system-symbolic",
                _ => "avatar-default-symbolic",
            };
            let icon = gtk4::Image::from_icon_name(icon_name);
            row.add_prefix(&icon);

            // Enabled indicator
            if !enabled {
                let disabled_icon = gtk4::Image::from_icon_name("action-unavailable-symbolic");
                disabled_icon.set_tooltip_text(Some("Disabled"));
                row.add_suffix(&disabled_icon);
            }

            // Navigation arrow
            let arrow = gtk4::Image::from_icon_name("go-next-symbolic");
            row.add_suffix(&arrow);

            list.append(&row);
        }
    }
}

// ============================================================================
// Internal: edit-user popover
// ============================================================================

/// Show a popover anchored to the selected row for quick edits:
/// toggle enabled, change role.
fn show_edit_user_popover(_window: &adw::Window, row: &gtk4::ListBoxRow) {
    let popover = gtk4::Popover::builder().autohide(true).build();

    let vbox = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .spacing(8)
        .margin_start(12)
        .margin_end(12)
        .margin_top(12)
        .margin_bottom(12)
        .build();

    let toggle_enabled_btn = gtk4::Button::builder().label("Toggle Enabled").build();

    let role_model = gtk4::StringList::new(&["admin", "operator", "viewer"]);
    let role_combo = adw::ComboRow::builder()
        .title("Change Role")
        .model(&role_model)
        .build();

    vbox.append(&toggle_enabled_btn);
    vbox.append(&role_combo);

    popover.set_child(Some(&vbox));
    popover.set_parent(row);
    popover.connect_closed({
        let pop = popover.clone();
        move |_| { pop.unparent(); }
    });

    toggle_enabled_btn.connect_clicked({
        let pop = popover.clone();
        move |_| {
            // Placeholder: in production this triggers an API call
            pop.popdown();
        }
    });

    role_combo.connect_selected_notify({
        let pop = popover.clone();
        move |_combo| {
            // Placeholder: in production this triggers an API call
            pop.popdown();
        }
    });

    popover.popup();
}

// ============================================================================
// Internal: confirm deletion dialog
// ============================================================================

fn show_confirm_dialog(
    parent: &adw::Window,
    title: &str,
    body: &str,
    on_confirm: impl Fn() + 'static,
) {
    let dialog = adw::MessageDialog::new(Some(parent), Some(title), Some(body));

    dialog.add_response("cancel", "Cancel");
    dialog.add_response("confirm", "Delete");
    dialog.set_response_appearance("confirm", adw::ResponseAppearance::Destructive);
    dialog.set_default_response(Some("cancel"));
    dialog.set_close_response("cancel");

    dialog.connect_response(None, move |_dlg, response| {
        if response == "confirm" {
            on_confirm();
        }
    });

    dialog.present();
}

// ============================================================================
// Internal: reset-password dialog
// ============================================================================

fn show_reset_password_dialog(parent: &adw::Window, _row: &gtk4::ListBoxRow) {
    let dialog = adw::Window::builder()
        .title("Reset Password")
        .default_width(360)
        .default_height(240)
        .modal(true)
        .transient_for(parent)
        .build();

    let password_row = adw::PasswordEntryRow::builder()
        .title("New Password")
        .build();

    let confirm_row = adw::PasswordEntryRow::builder()
        .title("Confirm Password")
        .build();

    let group = adw::PreferencesGroup::new();
    group.add(&password_row);
    group.add(&confirm_row);

    let page = adw::PreferencesPage::new();
    page.add(&group);

    let error_label = gtk4::Label::builder()
        .label("")
        .css_classes(vec!["error".to_string()])
        .wrap(true)
        .visible(false)
        .margin_start(12)
        .margin_end(12)
        .build();

    let save_btn = gtk4::Button::builder()
        .label("Reset")
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
    content.append(&error_label);
    content.append(&save_btn);

    dialog.set_content(Some(&content));

    save_btn.connect_clicked({
        let dlg = dialog.clone();
        let password_row = password_row.clone();
        let confirm_row = confirm_row.clone();
        let error_label = error_label.clone();
        move |_| {
            error_label.set_visible(false);

            let password = password_row.text().to_string();
            let confirm = confirm_row.text().to_string();

            if password.is_empty() {
                error_label.set_text("Password is required.");
                error_label.set_visible(true);
                return;
            }

            if password != confirm {
                error_label.set_text("Passwords do not match.");
                error_label.set_visible(true);
                return;
            }

            // Placeholder: in production this triggers an API call.
            dlg.close();
        }
    });

    confirm_row.connect_apply({
        let save_btn = save_btn.clone();
        move |_| {
            save_btn.emit_clicked();
        }
    });

    dialog.present();
}

// ============================================================================
// Internal: helpers
// ============================================================================

/// Format a role string with an enabled indicator for display as a subtitle.
fn format_role_badge(role: &str, enabled: bool) -> String {
    let badge = match role {
        "admin" => "Admin",
        "operator" => "Operator",
        "viewer" => "Viewer",
        other => other,
    };
    if enabled {
        badge.to_string()
    } else {
        format!("{badge} (disabled)")
    }
}

fn find_list_box(root: &impl IsA<gtk4::Widget>, name: &str) -> Option<gtk4::ListBox> {
    find_widget_by_name::<gtk4::ListBox>(root.upcast_ref(), name)
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

fn clear_list_box(list: &gtk4::ListBox) {
    while let Some(row) = list.row_at_index(0) {
        list.remove(&row);
    }
}
