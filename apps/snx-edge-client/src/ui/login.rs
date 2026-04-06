use gtk4::prelude::*;
use libadwaita as adw;
use adw::prelude::*;

/// Show a login dialog for authenticating against the snx-edge-server.
///
/// The `on_login` callback receives `(server_url, username, password)` when
/// the user presses the Connect button.
pub fn show_login_dialog(
    parent: &impl IsA<gtk4::Window>,
    on_login: impl Fn(String, String, String) + 'static,
) -> adw::Window {
    let dialog = adw::Window::builder()
        .title("Login to SNX Edge")
        .default_width(420)
        .default_height(380)
        .modal(true)
        .transient_for(parent)
        .build();

    // ── Preference rows ──────────────────────────────────────────────

    let server_row = adw::EntryRow::builder()
        .title("Server URL")
        .build();
    server_row.set_text("http://172.19.0.2:8080");

    let username_row = adw::EntryRow::builder()
        .title("Username")
        .build();

    let password_row = adw::PasswordEntryRow::builder()
        .title("Password")
        .build();

    // ── Group / page ─────────────────────────────────────────────────

    let group = adw::PreferencesGroup::builder()
        .title("Credentials")
        .description("Enter your snx-edge-server credentials")
        .build();
    group.add(&server_row);
    group.add(&username_row);
    group.add(&password_row);

    let page = adw::PreferencesPage::new();
    page.add(&group);

    // ── Error label (hidden until a login attempt fails) ─────────────

    let error_label = gtk4::Label::builder()
        .label("")
        .css_classes(vec!["error".to_string()])
        .wrap(true)
        .visible(false)
        .margin_start(12)
        .margin_end(12)
        .build();

    // ── Connect button ───────────────────────────────────────────────

    let connect_btn = gtk4::Button::builder()
        .label("Connect")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .halign(gtk4::Align::Center)
        .margin_top(12)
        .margin_bottom(12)
        .build();

    // ── Layout ───────────────────────────────────────────────────────

    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();

    let header = adw::HeaderBar::new();
    content.append(&header);
    content.append(&page);
    content.append(&error_label);
    content.append(&connect_btn);

    dialog.set_content(Some(&content));

    // ── Signals ──────────────────────────────────────────────────────

    connect_btn.connect_clicked({
        let server_row = server_row.clone();
        let username_row = username_row.clone();
        let password_row = password_row.clone();
        let error_label = error_label.clone();
        move |_btn| {
            // Hide any previous error on a new attempt.
            error_label.set_visible(false);

            let server_url = server_row.text().to_string();
            let username = username_row.text().to_string();
            let password = password_row.text().to_string();

            on_login(server_url, username, password);
        }
    });

    // Allow pressing Enter in the password field to submit.
    password_row.connect_apply({
        let connect_btn = connect_btn.clone();
        move |_| {
            connect_btn.emit_clicked();
        }
    });

    dialog.present();

    dialog
}

/// Display an inline error message inside the login dialog.
///
/// Call this from the `on_login` callback (on failure) to surface the error
/// to the user without opening a new dialog.
pub fn show_login_error(dialog: &adw::Window, message: &str) {
    // Walk the widget tree: content box -> children, find the error label.
    let Some(content) = dialog.content() else {
        return;
    };

    let content_box: gtk4::Box = match content.downcast() {
        Ok(b) => b,
        Err(_) => return,
    };

    let mut child = content_box.first_child();
    while let Some(widget) = child {
        if let Ok(label) = widget.clone().downcast::<gtk4::Label>() {
            if label.css_classes().iter().any(|c| c == "error") {
                label.set_text(message);
                label.set_visible(true);
                return;
            }
        }
        child = widget.next_sibling();
    }
}
