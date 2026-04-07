use gtk4::{
    Align, Orientation,
    glib::{self, clone},
    prelude::*,
};

use crate::{api::ApiClient, get_window, main_window, set_window};

/// Show the user management window.
/// Only admin users are allowed to open this window.
pub fn show_users_window(api: ApiClient, role: &str) {
    if role != "admin" {
        // Non-admin users cannot manage users — show an error
        let alert = gtk4::AlertDialog::builder()
            .message("Access Denied")
            .detail("User management requires admin privileges.")
            .buttons(["OK"].as_slice())
            .default_button(0)
            .build();
        let parent = get_window("main");
        glib::spawn_future_local(async move {
            let _ = alert.choose_future(parent.as_ref()).await;
        });
        return;
    }

    if let Some(window) = get_window("users") {
        window.present();
        return;
    }

    let window = gtk4::Window::builder()
        .title("SNX Edge - Users")
        .transient_for(&main_window())
        .default_width(550)
        .default_height(450)
        .build();

    let outer = gtk4::Box::builder()
        .orientation(Orientation::Vertical)
        .build();

    let list_box = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::Single)
        .css_classes(vec!["boxed-list".to_string()])
        .build();

    let scrolled = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .build();
    scrolled.set_child(Some(&list_box));
    outer.append(&scrolled);

    // Buttons
    let btn_box = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .margin_top(6)
        .margin_start(6)
        .margin_end(6)
        .margin_bottom(6)
        .halign(Align::End)
        .build();

    let add_btn = gtk4::Button::builder()
        .label("Add User")
        .css_classes(vec!["suggested-action".to_string()])
        .build();

    let refresh_btn = gtk4::Button::builder().label("Refresh").build();
    let close_btn = gtk4::Button::builder().label("Close").build();

    btn_box.append(&add_btn);
    btn_box.append(&refresh_btn);
    btn_box.append(&close_btn);

    outer.append(&btn_box);

    // Add user
    let api_add = api.clone();
    let list_box_add = list_box.clone();
    add_btn.connect_clicked(move |_| {
        let api = api_add.clone();
        let list_box = list_box_add.clone();
        glib::spawn_future_local(async move {
            if let Some((username, password, role, comment)) = show_add_user_dialog().await {
                let (tx, rx) = async_channel::bounded(1);
                let api2 = api.clone();
                tokio::spawn(async move {
                    let _ = tx.send(api2.create_user(&username, &password, &role, &comment).await).await;
                });
                if let Ok(Ok(_)) = rx.recv().await {
                    reload_users(&list_box, api).await;
                }
            }
        });
    });

    // Refresh
    let api_refresh = api.clone();
    let list_box_refresh = list_box.clone();
    refresh_btn.connect_clicked(move |_| {
        let api = api_refresh.clone();
        let list_box = list_box_refresh.clone();
        glib::spawn_future_local(async move {
            reload_users(&list_box, api).await;
        });
    });

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
    window.connect_close_request(|_| {
        set_window("users", None::<gtk4::Window>);
        glib::Propagation::Proceed
    });
    set_window("users", Some(window.clone()));
    window.present();

    // Initial load
    let api_init = api.clone();
    let list_box_init = list_box.clone();
    glib::spawn_future_local(async move {
        reload_users(&list_box_init, api_init).await;
    });
}

async fn reload_users(list_box: &gtk4::ListBox, api: ApiClient) {
    // Clear existing rows
    while let Some(child) = list_box.first_child() {
        list_box.remove(&child);
    }

    let (tx, rx) = async_channel::bounded(1);
    let api2 = api.clone();
    tokio::spawn(async move {
        let _ = tx.send(api2.list_users().await).await;
    });

    if let Ok(Ok(users)) = rx.recv().await {
        let user_count = users.len();
        let admin_count = users
            .iter()
            .filter(|u| u["role"].as_str() == Some("admin"))
            .count();

        for user in &users {
            let id = user["id"].as_str().unwrap_or("").to_string();
            let username = user["username"].as_str().unwrap_or("").to_string();
            let role = user["role"].as_str().unwrap_or("viewer").to_string();
            let comment = user["comment"].as_str().unwrap_or("").to_string();
            let enabled = user["enabled"].as_bool().unwrap_or(true);
            let is_admin = role == "admin";
            let can_delete = !(is_admin && admin_count <= 1);

            append_user_row(
                list_box,
                &id,
                &username,
                &role,
                &comment,
                enabled,
                can_delete,
                user_count,
                api.clone(),
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn append_user_row(
    list_box: &gtk4::ListBox,
    id: &str,
    username: &str,
    role: &str,
    comment: &str,
    enabled: bool,
    can_delete: bool,
    _user_count: usize,
    api: ApiClient,
) {
    let row_box = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(8)
        .margin_end(8)
        .build();

    let labels = gtk4::Box::builder()
        .orientation(Orientation::Vertical)
        .hexpand(true)
        .build();

    let title_box = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .build();

    title_box.append(
        &gtk4::Label::builder()
            .label(username)
            .halign(Align::Start)
            .css_classes(vec!["heading".to_string()])
            .build(),
    );

    // Role badge
    let role_class = match role {
        "admin" => "error",
        "operator" => "warning",
        _ => "dim-label",
    };
    title_box.append(
        &gtk4::Label::builder()
            .label(&format!("[{}]", role))
            .halign(Align::Start)
            .css_classes(vec![role_class.to_string()])
            .build(),
    );

    if !enabled {
        title_box.append(
            &gtk4::Label::builder()
                .label("(disabled)")
                .halign(Align::Start)
                .css_classes(vec!["dim-label".to_string()])
                .build(),
        );
    }

    labels.append(&title_box);

    if !comment.is_empty() {
        labels.append(
            &gtk4::Label::builder()
                .label(comment)
                .halign(Align::Start)
                .css_classes(vec!["dim-label".to_string()])
                .build(),
        );
    }

    row_box.append(&labels);

    // Reset password button
    let reset_btn = gtk4::Button::builder()
        .icon_name("system-lock-screen-symbolic")
        .css_classes(vec!["flat".to_string()])
        .valign(Align::Center)
        .tooltip_text("Reset Password")
        .build();

    let api_reset = api.clone();
    let id_reset = id.to_string();
    let list_box_reset = list_box.clone();
    reset_btn.connect_clicked(move |_| {
        let api = api_reset.clone();
        let id = id_reset.clone();
        let list_box = list_box_reset.clone();
        glib::spawn_future_local(async move {
            if let Some(new_password) = show_password_dialog().await {
                let (tx, rx) = async_channel::bounded(1);
                let api2 = api.clone();
                let id2 = id.clone();
                tokio::spawn(async move {
                    let _ = tx.send(api2.change_user_password(&id2, &new_password).await).await;
                });
                if let Ok(Ok(())) = rx.recv().await {
                    reload_users(&list_box, api).await;
                }
            }
        });
    });

    row_box.append(&reset_btn);

    // Delete button
    let delete_btn = gtk4::Button::builder()
        .icon_name("edit-delete-symbolic")
        .css_classes(vec!["flat".to_string()])
        .valign(Align::Center)
        .tooltip_text("Delete User")
        .sensitive(can_delete)
        .build();

    let api_del = api.clone();
    let id_del = id.to_string();
    let username_del = username.to_string();
    let list_box_del = list_box.clone();
    delete_btn.connect_clicked(move |_| {
        let api = api_del.clone();
        let id = id_del.clone();
        let username = username_del.clone();
        let list_box = list_box_del.clone();
        glib::spawn_future_local(async move {
            if show_confirm_dialog(&format!("Delete user '{}'?", username)).await {
                let (tx, rx) = async_channel::bounded(1);
                let api2 = api.clone();
                let id2 = id.clone();
                tokio::spawn(async move {
                    let _ = tx.send(api2.delete_user(&id2).await).await;
                });
                if let Ok(Ok(())) = rx.recv().await {
                    reload_users(&list_box, api).await;
                }
            }
        });
    });

    row_box.append(&delete_btn);

    let list_row = gtk4::ListBoxRow::builder().child(&row_box).build();
    list_box.append(&list_row);
}

async fn show_add_user_dialog() -> Option<(String, String, String, String)> {
    let (tx, rx) = async_channel::bounded(1);

    let window = gtk4::Window::builder()
        .title("Add User")
        .transient_for(&main_window())
        .modal(true)
        .default_width(380)
        .build();

    let inner = gtk4::Box::builder()
        .orientation(Orientation::Vertical)
        .margin_top(12)
        .margin_start(12)
        .margin_end(12)
        .margin_bottom(12)
        .spacing(8)
        .build();

    inner.append(
        &gtk4::Label::builder()
            .label("Username:")
            .halign(Align::Start)
            .build(),
    );
    let username_entry = gtk4::Entry::builder()
        .placeholder_text("johndoe")
        .build();
    inner.append(&username_entry);

    inner.append(
        &gtk4::Label::builder()
            .label("Password:")
            .halign(Align::Start)
            .build(),
    );
    let password_entry = gtk4::PasswordEntry::builder()
        .show_peek_icon(true)
        .build();
    inner.append(&password_entry);

    inner.append(
        &gtk4::Label::builder()
            .label("Role:")
            .halign(Align::Start)
            .build(),
    );
    let role_model = gtk4::StringList::new(&["admin", "operator", "viewer"]);
    let role_dropdown = gtk4::DropDown::builder()
        .model(&role_model)
        .selected(2) // default: viewer
        .build();
    inner.append(&role_dropdown);

    inner.append(
        &gtk4::Label::builder()
            .label("Comment:")
            .halign(Align::Start)
            .build(),
    );
    let comment_entry = gtk4::Entry::builder()
        .placeholder_text("Optional comment")
        .build();
    inner.append(&comment_entry);

    let error_label = gtk4::Label::builder()
        .label("")
        .css_classes(vec!["error".to_string()])
        .wrap(true)
        .visible(false)
        .build();
    inner.append(&error_label);

    let btn_box = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_top(8)
        .halign(Align::End)
        .build();

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let ok_btn = gtk4::Button::builder()
        .label("Create")
        .css_classes(vec!["suggested-action".to_string()])
        .build();
    btn_box.append(&cancel_btn);
    btn_box.append(&ok_btn);
    inner.append(&btn_box);

    window.set_child(Some(&inner));

    let tx_ok = tx.clone();
    ok_btn.connect_clicked(clone!(
        #[weak] window,
        #[weak] username_entry,
        #[weak] password_entry,
        #[weak] role_dropdown,
        #[weak] comment_entry,
        #[weak] error_label,
        move |_| {
            let username = username_entry.text().trim().to_string();
            let password = password_entry.text().to_string();
            let comment = comment_entry.text().trim().to_string();

            if username.is_empty() || password.is_empty() {
                error_label.set_text("Username and password are required");
                error_label.set_visible(true);
                return;
            }

            let role_idx = role_dropdown.selected();
            let role = match role_idx {
                0 => "admin",
                1 => "operator",
                _ => "viewer",
            }.to_string();

            let _ = tx_ok.try_send(Some((username, password, role, comment)));
            window.close();
        }
    ));

    cancel_btn.connect_clicked(clone!(
        #[weak] window,
        move |_| {
            let _ = tx.try_send(None::<(String, String, String, String)>);
            window.close();
        }
    ));

    window.present();
    rx.recv().await.ok().flatten()
}

async fn show_password_dialog() -> Option<String> {
    let (tx, rx) = async_channel::bounded(1);

    let window = gtk4::Window::builder()
        .title("Reset Password")
        .transient_for(&main_window())
        .modal(true)
        .default_width(350)
        .build();

    let inner = gtk4::Box::builder()
        .orientation(Orientation::Vertical)
        .margin_top(12)
        .margin_start(12)
        .margin_end(12)
        .margin_bottom(12)
        .spacing(8)
        .build();

    inner.append(
        &gtk4::Label::builder()
            .label("New Password:")
            .halign(Align::Start)
            .build(),
    );
    let password_entry = gtk4::PasswordEntry::builder()
        .show_peek_icon(true)
        .build();
    inner.append(&password_entry);

    let btn_box = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_top(8)
        .halign(Align::End)
        .build();

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let ok_btn = gtk4::Button::builder()
        .label("Set Password")
        .css_classes(vec!["suggested-action".to_string()])
        .build();
    btn_box.append(&cancel_btn);
    btn_box.append(&ok_btn);
    inner.append(&btn_box);

    window.set_child(Some(&inner));

    let tx_ok = tx.clone();
    ok_btn.connect_clicked(clone!(
        #[weak] window,
        #[weak] password_entry,
        move |_| {
            let password = password_entry.text().to_string();
            if !password.is_empty() {
                let _ = tx_ok.try_send(Some(password));
                window.close();
            }
        }
    ));

    cancel_btn.connect_clicked(clone!(
        #[weak] window,
        move |_| {
            let _ = tx.try_send(None::<String>);
            window.close();
        }
    ));

    window.present();
    rx.recv().await.ok().flatten()
}

async fn show_confirm_dialog(message: &str) -> bool {
    let alert = gtk4::AlertDialog::builder()
        .message(message)
        .buttons(["Cancel", "Delete"].as_slice())
        .cancel_button(0)
        .default_button(0)
        .build();

    matches!(alert.choose_future(Some(&main_window())).await, Ok(1))
}
