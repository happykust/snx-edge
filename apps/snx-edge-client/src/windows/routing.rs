use gtk4::{
    Align, Orientation,
    glib::{self, clone},
    prelude::*,
};

use crate::{api::ApiClient, get_window, main_window, set_window};

/// Detect the local IP address by connecting a UDP socket to a public address.
/// No data is actually sent.
fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|a| a.ip().to_string())
}

/// Build and show the routing management window.
/// Two-tab Notebook: "VPN-clients" and "Bypass rules".
/// Each tab has a list of entries with add/delete, plus bottom action bar.
///
/// `role` controls what actions are visible:
/// - "viewer": read-only list, no add/delete/setup/teardown buttons
/// - "operator": add/delete clients/bypass, but no setup/teardown
/// - "admin": full access
pub fn show_routing_window(api: ApiClient, role: &str) {
    if let Some(window) = get_window("routing") {
        window.present();
        return;
    }

    let window = gtk4::Window::builder()
        .title("SNX Edge - Routing")
        .transient_for(&main_window())
        .default_width(600)
        .default_height(500)
        .build();

    let outer = gtk4::Box::builder()
        .orientation(Orientation::Vertical)
        .build();

    let notebook = gtk4::Notebook::new();
    notebook.set_vexpand(true);

    let can_edit = role != "viewer";

    // --- Clients tab ---
    let clients_page = build_list_tab(api.clone(), ListKind::Clients, can_edit);
    notebook.append_page(&clients_page, Some(&gtk4::Label::new(Some("VPN Clients"))));

    // --- Bypass tab ---
    let bypass_page = build_list_tab(api.clone(), ListKind::Bypass, can_edit);
    notebook.append_page(&bypass_page, Some(&gtk4::Label::new(Some("Bypass Rules"))));

    outer.append(&notebook);

    // --- Bottom action bar ---
    let action_bar = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .margin_top(6)
        .margin_start(6)
        .margin_end(6)
        .margin_bottom(6)
        .halign(Align::End)
        .build();

    let setup_btn = gtk4::Button::builder()
        .label("Setup PBR")
        .css_classes(vec!["suggested-action".to_string()])
        .build();

    let teardown_btn = gtk4::Button::builder()
        .label("Teardown")
        .css_classes(vec!["destructive-action".to_string()])
        .build();

    let diag_btn = gtk4::Button::builder().label("Diagnostics").build();

    let close_btn = gtk4::Button::builder().label("Close").build();

    // Setup/Teardown only for admin
    if role == "admin" {
        action_bar.append(&setup_btn);
        action_bar.append(&teardown_btn);
    }
    action_bar.append(&diag_btn);
    action_bar.append(&close_btn);

    outer.append(&action_bar);

    // --- Callbacks ---
    let api_setup = api.clone();
    setup_btn.connect_clicked(clone!(
        #[weak]
        window,
        move |btn| {
            btn.set_sensitive(false);
            let api = api_setup.clone();
            let btn2 = btn.clone();
            glib::spawn_future_local(clone!(
                #[weak]
                window,
                async move {
                    let (tx, rx) = async_channel::bounded(1);
                    tokio::spawn(async move {
                        let _ = tx.send(api.routing_setup().await).await;
                    });
                    match rx.recv().await {
                        Ok(Ok(val)) => {
                            let msg = serde_json::to_string_pretty(&val).unwrap_or_default();
                            show_info_dialog(&window, "Routing Setup", &msg).await;
                        }
                        Ok(Err(e)) => {
                            show_info_dialog(&window, "Routing Setup Error", &e.to_string()).await;
                        }
                        _ => {}
                    }
                    btn2.set_sensitive(true);
                }
            ));
        }
    ));

    let api_teardown = api.clone();
    teardown_btn.connect_clicked(clone!(
        #[weak]
        window,
        move |btn| {
            btn.set_sensitive(false);
            let api = api_teardown.clone();
            let btn2 = btn.clone();
            glib::spawn_future_local(clone!(
                #[weak]
                window,
                async move {
                    let (tx, rx) = async_channel::bounded(1);
                    tokio::spawn(async move {
                        let _ = tx.send(api.routing_teardown().await).await;
                    });
                    match rx.recv().await {
                        Ok(Ok(())) => {
                            show_info_dialog(
                                &window,
                                "Routing Teardown",
                                "Routing torn down successfully.",
                            )
                            .await;
                        }
                        Ok(Err(e)) => {
                            show_info_dialog(&window, "Routing Teardown Error", &e.to_string())
                                .await;
                        }
                        _ => {}
                    }
                    btn2.set_sensitive(true);
                }
            ));
        }
    ));

    let api_diag = api.clone();
    diag_btn.connect_clicked(clone!(
        #[weak]
        window,
        move |btn| {
            btn.set_sensitive(false);
            let api = api_diag.clone();
            let btn2 = btn.clone();
            glib::spawn_future_local(clone!(
                #[weak]
                window,
                async move {
                    let (tx, rx) = async_channel::bounded(1);
                    tokio::spawn(async move {
                        let _ = tx.send(api.routing_diagnostics().await).await;
                    });
                    match rx.recv().await {
                        Ok(Ok(val)) => {
                            let msg = format_diagnostics(&val);
                            show_info_dialog(&window, "Routing Diagnostics", &msg).await;
                        }
                        Ok(Err(e)) => {
                            show_info_dialog(&window, "Diagnostics Error", &e.to_string()).await;
                        }
                        _ => {}
                    }
                    btn2.set_sensitive(true);
                }
            ));
        }
    ));

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
        set_window("routing", None::<gtk4::Window>);
        glib::Propagation::Proceed
    });
    set_window("routing", Some(window.clone()));
    window.present();
}

#[derive(Clone, Copy, PartialEq)]
enum ListKind {
    Clients,
    Bypass,
}

fn build_list_tab(api: ApiClient, kind: ListKind, can_edit: bool) -> gtk4::Box {
    let page = gtk4::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(6)
        .margin_top(6)
        .margin_start(6)
        .margin_end(6)
        .margin_bottom(6)
        .build();

    let list_box = gtk4::ListBox::builder()
        .selection_mode(gtk4::SelectionMode::None)
        .css_classes(vec!["boxed-list".to_string()])
        .build();

    let scrolled = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .build();
    scrolled.set_child(Some(&list_box));
    page.append(&scrolled);

    // Buttons
    let btn_box = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .halign(Align::Start)
        .build();

    if can_edit {
        let add_btn = gtk4::Button::builder()
            .label("Add")
            .css_classes(vec!["suggested-action".to_string()])
            .build();
        btn_box.append(&add_btn);

        if kind == ListKind::Clients {
            let add_my_ip_btn = gtk4::Button::builder().label("Add My IP").build();
            let api_ip = api.clone();
            let list_box_ip = list_box.clone();
            add_my_ip_btn.connect_clicked(move |btn| {
                btn.set_sensitive(false);
                let api = api_ip.clone();
                let list_box = list_box_ip.clone();
                let btn2 = btn.clone();
                glib::spawn_future_local(async move {
                    let local_ip = match get_local_ip() {
                        Some(ip) => ip,
                        None => {
                            let parent: gtk4::Window = main_window().upcast();
                            show_info_dialog(
                                &parent,
                                "Error",
                                "Could not detect local IP address.",
                            )
                            .await;
                            btn2.set_sensitive(true);
                            return;
                        }
                    };
                    let (tx, rx) = async_channel::bounded(1);
                    let api2 = api.clone();
                    let ip = local_ip.clone();
                    tokio::spawn(async move {
                        let _ = tx
                            .send(
                                api2.add_routing_client(&ip, "Added from client (my IP)")
                                    .await,
                            )
                            .await;
                    });
                    if let Ok(Ok(val)) = rx.recv().await {
                        let address = val["address"].as_str().unwrap_or("auto").to_string();
                        let comment = val["comment"].as_str().unwrap_or("").to_string();
                        let id = val[".id"].as_str().unwrap_or("").to_string();
                        append_list_row(
                            &list_box,
                            &id,
                            &address,
                            &comment,
                            api.clone(),
                            ListKind::Clients,
                            true,
                        );
                    }
                    btn2.set_sensitive(true);
                });
            });
            btn_box.append(&add_my_ip_btn);
        }

        // Add button callback
        let api_add = api.clone();
        let list_box_add = list_box.clone();
        add_btn.connect_clicked(move |_| {
            let api = api_add.clone();
            let list_box = list_box_add.clone();
            glib::spawn_future_local(async move {
                if let Some((address, comment)) = show_add_entry_dialog().await {
                    let (tx, rx) = async_channel::bounded(1);
                    let api2 = api.clone();
                    let address2 = address.clone();
                    let comment2 = comment.clone();
                    tokio::spawn(async move {
                        let result = match kind {
                            ListKind::Clients => {
                                api2.add_routing_client(&address2, &comment2).await
                            }
                            ListKind::Bypass => api2.add_routing_bypass(&address2, &comment2).await,
                        };
                        let _ = tx.send(result).await;
                    });
                    if let Ok(Ok(val)) = rx.recv().await {
                        let id = val[".id"].as_str().unwrap_or("").to_string();
                        let addr = val["address"].as_str().unwrap_or(&address).to_string();
                        let cmt = val["comment"].as_str().unwrap_or(&comment).to_string();
                        append_list_row(&list_box, &id, &addr, &cmt, api.clone(), kind, true);
                    }
                }
            });
        });
    }

    let refresh_btn = gtk4::Button::builder().label("Refresh").build();
    btn_box.append(&refresh_btn);

    // Refresh callback
    let api_refresh = api.clone();
    let list_box_refresh = list_box.clone();
    refresh_btn.connect_clicked(move |_| {
        let api = api_refresh.clone();
        let list_box = list_box_refresh.clone();
        glib::spawn_future_local(async move {
            reload_list(&list_box, api, kind, can_edit).await;
        });
    });

    page.append(&btn_box);

    // Initial load
    let api_init = api.clone();
    let list_box_init = list_box.clone();
    glib::spawn_future_local(async move {
        reload_list(&list_box_init, api_init, kind, can_edit).await;
    });

    page
}

async fn reload_list(list_box: &gtk4::ListBox, api: ApiClient, kind: ListKind, can_edit: bool) {
    // Clear existing rows
    while let Some(child) = list_box.first_child() {
        list_box.remove(&child);
    }

    let (tx, rx) = async_channel::bounded(1);
    let api2 = api.clone();
    tokio::spawn(async move {
        let result = match kind {
            ListKind::Clients => api2.list_routing_clients().await,
            ListKind::Bypass => api2.list_routing_bypass().await,
        };
        let _ = tx.send(result).await;
    });

    if let Ok(Ok(items)) = rx.recv().await {
        for item in &items {
            let id = item[".id"].as_str().unwrap_or("").to_string();
            let address = item["address"].as_str().unwrap_or("").to_string();
            let comment = item["comment"].as_str().unwrap_or("").to_string();
            append_list_row(
                list_box,
                &id,
                &address,
                &comment,
                api.clone(),
                kind,
                can_edit,
            );
        }
    }
}

fn append_list_row(
    list_box: &gtk4::ListBox,
    id: &str,
    address: &str,
    comment: &str,
    api: ApiClient,
    kind: ListKind,
    can_edit: bool,
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

    labels.append(
        &gtk4::Label::builder()
            .label(address)
            .halign(Align::Start)
            .css_classes(vec!["heading".to_string()])
            .build(),
    );

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

    if can_edit {
        let delete_btn = gtk4::Button::builder()
            .icon_name("edit-delete-symbolic")
            .css_classes(vec!["flat".to_string()])
            .valign(Align::Center)
            .build();

        let id_owned = id.to_string();
        let list_box_ref = list_box.clone();
        delete_btn.connect_clicked(move |_| {
            let api = api.clone();
            let id = id_owned.clone();
            let list_box = list_box_ref.clone();
            glib::spawn_future_local(async move {
                let (tx, rx) = async_channel::bounded(1);
                let api2 = api.clone();
                let id2 = id.clone();
                tokio::spawn(async move {
                    let result = match kind {
                        ListKind::Clients => api2.remove_routing_client(&id2).await,
                        ListKind::Bypass => api2.remove_routing_bypass(&id2).await,
                    };
                    let _ = tx.send(result).await;
                });
                if let Ok(Ok(())) = rx.recv().await {
                    reload_list(&list_box, api, kind, can_edit).await;
                }
            });
        });

        row_box.append(&delete_btn);
    }

    let list_row = gtk4::ListBoxRow::builder().child(&row_box).build();
    list_box.append(&list_row);
}

async fn show_add_entry_dialog() -> Option<(String, String)> {
    let (tx, rx) = async_channel::bounded(1);

    let window = gtk4::Window::builder()
        .title("Add Entry")
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
            .label("Address (IP or CIDR):")
            .halign(Align::Start)
            .build(),
    );
    let address_entry = gtk4::Entry::builder()
        .placeholder_text("192.168.1.0/24")
        .build();
    inner.append(&address_entry);

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

    let btn_box = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_top(8)
        .halign(Align::End)
        .build();

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let ok_btn = gtk4::Button::builder()
        .label("Add")
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
        address_entry,
        #[weak]
        comment_entry,
        move |_| {
            let address = address_entry.text().trim().to_string();
            let comment = comment_entry.text().trim().to_string();
            if !address.is_empty() {
                let _ = tx_ok.try_send(Some((address, comment)));
                window.close();
            }
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

/// Format routing diagnostics JSON as human-readable text.
fn format_diagnostics(val: &serde_json::Value) -> String {
    let mut lines = Vec::new();

    // Overall status
    if let Some(status) = val.get("status").and_then(|v| v.as_str()) {
        let label = match status {
            "healthy" | "ok" => "Status: healthy",
            "degraded" | "warning" => "Status: degraded",
            "error" | "failed" => "Status: error",
            other => other,
        };
        lines.push(label.to_string());
        lines.push(String::new());
    }

    // Server returns: { status, checks: { routing_table_exists: bool, mangle_rules_count: num, ... }, warnings: [] }
    if let Some(checks) = val.get("checks").and_then(|v| v.as_object()) {
        for (key, value) in checks {
            match value {
                serde_json::Value::Bool(b) => {
                    let icon = if *b { "[ok]" } else { "[FAIL]" };
                    lines.push(format!("{} {}", icon, key.replace('_', " ")));
                }
                serde_json::Value::Number(n) => {
                    lines.push(format!("  {} = {}", key.replace('_', " "), n));
                }
                _ => {
                    lines.push(format!("  {}: {}", key, value));
                }
            }
        }
    }

    // Warnings
    if let Some(warnings) = val.get("warnings").and_then(|v| v.as_array())
        && !warnings.is_empty()
    {
        lines.push(String::new());
        lines.push("Warnings:".to_string());
        for w in warnings {
            if let Some(s) = w.as_str() {
                lines.push(format!("  - {}", s));
            }
        }
    }

    if lines.is_empty() {
        // Fallback to pretty-printed JSON
        serde_json::to_string_pretty(val).unwrap_or_default()
    } else {
        lines.join("\n")
    }
}

async fn show_info_dialog(parent: &gtk4::Window, title: &str, message: &str) {
    let alert = gtk4::AlertDialog::builder()
        .message(title)
        .detail(message)
        .buttons(["OK"].as_slice())
        .default_button(0)
        .build();
    let _ = alert.choose_future(Some(parent)).await;
}
