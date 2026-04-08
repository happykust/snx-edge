use gtk4::{
    Align, Orientation,
    glib::{self, clone},
    prelude::*,
};

use crate::{
    client_settings::{ClientSettings, ServerConnection},
    get_window, main_window, set_window,
};

/// Show the server management window.
pub fn show_servers_window() {
    if let Some(window) = get_window("servers") {
        window.present();
        return;
    }

    let window = gtk4::Window::builder()
        .title("SNX Edge - Servers")
        .transient_for(&main_window())
        .default_width(500)
        .default_height(400)
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
        .label("Add Server")
        .css_classes(vec!["suggested-action".to_string()])
        .build();
    let close_btn = gtk4::Button::builder().label("Close").build();

    btn_box.append(&add_btn);
    btn_box.append(&close_btn);

    outer.append(&btn_box);

    // Add server
    let list_box_add = list_box.clone();
    add_btn.connect_clicked(move |_| {
        let list_box = list_box_add.clone();
        glib::spawn_future_local(async move {
            if let Some((name, url)) = show_server_edit_dialog(None).await {
                let mut settings = ClientSettings::load();
                settings.servers.push(ServerConnection {
                    name,
                    url,
                    auto_connect: false,
                    last_profile_id: None,
                    insecure: false,
                });
                let _ = settings.save();
                reload_servers(&list_box);
            }
        });
    });

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
    window.connect_close_request(|_| {
        set_window("servers", None::<gtk4::Window>);
        glib::Propagation::Proceed
    });
    set_window("servers", Some(window.clone()));

    // Initial load
    reload_servers(&list_box);

    window.present();
}

fn reload_servers(list_box: &gtk4::ListBox) {
    while let Some(child) = list_box.first_child() {
        list_box.remove(&child);
    }

    let settings = ClientSettings::load();
    let active_idx = settings.active_server;

    for (idx, server) in settings.servers.iter().enumerate() {
        let is_active = active_idx == Some(idx);
        append_server_row(list_box, idx, server, is_active);
    }
}

fn append_server_row(
    list_box: &gtk4::ListBox,
    idx: usize,
    server: &ServerConnection,
    is_active: bool,
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
            .label(&server.name)
            .halign(Align::Start)
            .css_classes(vec!["heading".to_string()])
            .build(),
    );

    if is_active {
        title_box.append(
            &gtk4::Label::builder()
                .label("[active]")
                .halign(Align::Start)
                .css_classes(vec!["success".to_string()])
                .build(),
        );
    }

    labels.append(&title_box);
    labels.append(
        &gtk4::Label::builder()
            .label(&server.url)
            .halign(Align::Start)
            .css_classes(vec!["dim-label".to_string()])
            .build(),
    );

    row_box.append(&labels);

    // Set default button
    if !is_active {
        let default_btn = gtk4::Button::builder()
            .icon_name("emblem-default-symbolic")
            .css_classes(vec!["flat".to_string()])
            .valign(Align::Center)
            .tooltip_text("Set as Active")
            .build();

        let list_box_ref = list_box.clone();
        default_btn.connect_clicked(move |_| {
            let mut settings = ClientSettings::load();
            settings.active_server = Some(idx);
            let _ = settings.save();
            reload_servers(&list_box_ref);

            // Notify user that a restart is required
            let list_box_ref2 = list_box_ref.clone();
            glib::spawn_future_local(async move {
                let parent = list_box_ref2
                    .root()
                    .and_then(|r| r.downcast::<gtk4::Window>().ok());
                let alert = gtk4::AlertDialog::builder()
                    .message("Server Changed")
                    .detail("Server changed. Please restart the application to connect to the new server.")
                    .buttons(["OK"].as_slice())
                    .default_button(0)
                    .build();
                let _ = alert.choose_future(parent.as_ref()).await;
            });
        });

        row_box.append(&default_btn);
    }

    // Edit button
    let edit_btn = gtk4::Button::builder()
        .icon_name("document-edit-symbolic")
        .css_classes(vec!["flat".to_string()])
        .valign(Align::Center)
        .tooltip_text("Edit")
        .build();

    let server_name = server.name.clone();
    let server_url = server.url.clone();
    let list_box_edit = list_box.clone();
    edit_btn.connect_clicked(move |_| {
        let name = server_name.clone();
        let url = server_url.clone();
        let list_box = list_box_edit.clone();
        glib::spawn_future_local(async move {
            if let Some((new_name, new_url)) = show_server_edit_dialog(Some((&name, &url))).await {
                let mut settings = ClientSettings::load();
                if let Some(s) = settings.servers.get_mut(idx) {
                    s.name = new_name;
                    s.url = new_url;
                }
                let _ = settings.save();
                reload_servers(&list_box);
            }
        });
    });
    row_box.append(&edit_btn);

    // Delete button
    let delete_btn = gtk4::Button::builder()
        .icon_name("edit-delete-symbolic")
        .css_classes(vec!["flat".to_string()])
        .valign(Align::Center)
        .tooltip_text("Remove Server")
        .build();

    let list_box_del = list_box.clone();
    let server_name_del = server.name.clone();
    delete_btn.connect_clicked(move |_| {
        let list_box = list_box_del.clone();
        let name = server_name_del.clone();
        glib::spawn_future_local(async move {
            if show_confirm_dialog(&format!("Remove server '{}'?", name)).await {
                let mut settings = ClientSettings::load();
                if idx < settings.servers.len() {
                    settings.servers.remove(idx);
                    // Adjust active_server index
                    match settings.active_server {
                        Some(active) if active == idx => {
                            settings.active_server = if settings.servers.is_empty() {
                                None
                            } else {
                                Some(0)
                            };
                        }
                        Some(active) if active > idx => {
                            settings.active_server = Some(active - 1);
                        }
                        _ => {}
                    }
                    let _ = settings.save();
                }
                reload_servers(&list_box);
            }
        });
    });
    row_box.append(&delete_btn);

    let list_row = gtk4::ListBoxRow::builder().child(&row_box).build();
    list_box.append(&list_row);
}

async fn show_server_edit_dialog(existing: Option<(&str, &str)>) -> Option<(String, String)> {
    let (tx, rx) = async_channel::bounded(1);

    let title = if existing.is_some() {
        "Edit Server"
    } else {
        "Add Server"
    };

    let window = gtk4::Window::builder()
        .title(title)
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
            .label("Server Name:")
            .halign(Align::Start)
            .build(),
    );
    let name_entry = gtk4::Entry::builder()
        .placeholder_text("My Server")
        .text(existing.map(|(n, _)| n).unwrap_or_default())
        .build();
    inner.append(&name_entry);

    inner.append(
        &gtk4::Label::builder()
            .label("Server URL:")
            .halign(Align::Start)
            .build(),
    );
    let url_entry = gtk4::Entry::builder()
        .placeholder_text("http://172.19.0.2:8080")
        .text(existing.map(|(_, u)| u).unwrap_or_default())
        .build();
    inner.append(&url_entry);

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
        .label("Save")
        .css_classes(vec!["suggested-action".to_string()])
        .build();
    btn_box.append(&cancel_btn);
    btn_box.append(&ok_btn);
    inner.append(&btn_box);

    window.set_child(Some(&inner));

    let tx_ok = tx.clone();
    ok_btn.connect_clicked(clone!(
        #[weak]
        window,
        #[weak]
        name_entry,
        #[weak]
        url_entry,
        #[weak]
        error_label,
        move |_| {
            let name = name_entry.text().trim().to_string();
            let url = url_entry.text().trim().to_string();

            if url.is_empty() {
                error_label.set_text("Server URL is required");
                error_label.set_visible(true);
                return;
            }
            if !url.starts_with("http://") && !url.starts_with("https://") {
                error_label.set_text("URL must start with http:// or https://");
                error_label.set_visible(true);
                return;
            }

            let display_name = if name.is_empty() { url.clone() } else { name };
            let _ = tx_ok.try_send(Some((display_name, url)));
            window.close();
        }
    ));

    cancel_btn.connect_clicked(clone!(
        #[weak]
        window,
        move |_| {
            let _ = tx.try_send(None::<(String, String)>);
            window.close();
        }
    ));

    window.present();
    rx.recv().await.ok().flatten()
}

async fn show_confirm_dialog(message: &str) -> bool {
    let alert = gtk4::AlertDialog::builder()
        .message(message)
        .buttons(["Cancel", "Remove"].as_slice())
        .cancel_button(0)
        .default_button(0)
        .build();

    matches!(alert.choose_future(Some(&main_window())).await, Ok(1))
}
