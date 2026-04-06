use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use gtk4::prelude::*;
use libadwaita as adw;
use adw::prelude::*;
use tokio::sync::RwLock;

use crate::settings::ClientSettings;

/// Build and present the "Manage Servers" window.
///
/// The callbacks are invoked when the user adds, removes, or activates a
/// server. The caller (main.rs) is responsible for actually mutating settings
/// and performing the server switch.
pub fn build_servers_window(
    parent: &impl IsA<gtk4::Window>,
    settings: Arc<RwLock<ClientSettings>>,
    on_add: impl Fn(String, String) + 'static,
    on_remove: impl Fn(usize) + 'static,
    on_switch: impl Fn(usize) + 'static,
) -> adw::Window {
    let dialog = adw::Window::builder()
        .title("Manage Servers")
        .default_width(500)
        .default_height(420)
        .modal(true)
        .transient_for(parent)
        .build();

    let header = adw::HeaderBar::new();

    // Add server button in header bar
    let add_btn = gtk4::Button::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text("Add Server")
        .build();
    header.pack_start(&add_btn);

    let group = adw::PreferencesGroup::builder()
        .title("Configured Servers")
        .description("Select a server to make it active, or add/remove servers.")
        .build();

    let page = adw::PreferencesPage::new();
    page.add(&group);

    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    content.append(&header);
    content.append(&page);

    dialog.set_content(Some(&content));

    // Shared state for dynamic updates inside closures.
    let on_add = Rc::new(on_add);
    let on_remove = Rc::new(on_remove);
    let on_switch = Rc::new(on_switch);

    // Populate the list from current settings.
    let group_ref = group.clone();
    let dialog_ref = dialog.clone();
    let settings_clone = settings.clone();
    let on_remove_clone = on_remove.clone();
    let on_switch_clone = on_switch.clone();

    // We need a blocking read here since we are on the GTK main thread.
    // Use spawn_future_local to await the RwLock.
    let populate = Rc::new(RefCell::new(None::<Box<dyn Fn()>>));
    let populate_ref = populate.clone();

    let make_populate = {
        let group = group_ref.clone();
        let settings = settings_clone.clone();
        let on_remove = on_remove_clone.clone();
        let on_switch = on_switch_clone.clone();
        let dialog = dialog_ref.clone();
        let populate_ref = populate_ref.clone();

        move || {
            let group = group.clone();
            let settings = settings.clone();
            let on_remove = on_remove.clone();
            let on_switch = on_switch.clone();
            let _dialog = dialog.clone();
            let _populate_ref = populate_ref.clone();

            gtk4::glib::spawn_future_local(async move {
                let s = settings.read().await;

                // Remove all existing rows from the group.
                // Walk children and remove ActionRows.
                let mut to_remove = Vec::new();
                let mut child = group.first_child();
                while let Some(c) = child {
                    let next = c.next_sibling();
                    if c.downcast_ref::<adw::ActionRow>().is_some() {
                        to_remove.push(c);
                    }
                    child = next;
                }
                for w in to_remove {
                    if let Ok(row) = w.downcast::<adw::ActionRow>() {
                        group.remove(&row);
                    }
                }

                let active_idx = s.active_server;

                for (i, server) in s.servers.iter().enumerate() {
                    let is_active = active_idx == Some(i);

                    let row = adw::ActionRow::builder()
                        .title(&server.name)
                        .subtitle(&server.url)
                        .activatable(true)
                        .build();

                    if is_active {
                        let check = gtk4::Image::from_icon_name("object-select-symbolic");
                        row.add_prefix(&check);
                    }

                    // Remove button suffix
                    let remove_btn = gtk4::Button::builder()
                        .icon_name("user-trash-symbolic")
                        .valign(gtk4::Align::Center)
                        .css_classes(vec!["flat".to_string()])
                        .tooltip_text("Remove server")
                        .build();

                    let on_remove_inner = on_remove.clone();
                    let idx = i;
                    remove_btn.connect_clicked(move |_| {
                        on_remove_inner(idx);
                    });
                    row.add_suffix(&remove_btn);

                    // Clicking the row switches to that server.
                    let on_switch_inner = on_switch.clone();
                    let idx = i;
                    row.set_activatable(true);
                    row.connect_activated(move |_| {
                        on_switch_inner(idx);
                    });

                    group.add(&row);
                }
            });
        }
    };

    *populate.borrow_mut() = Some(Box::new(make_populate.clone()));

    // Initial population
    (make_populate)();

    // Add button opens a small entry dialog.
    let on_add_for_btn = on_add.clone();
    let dialog_for_add = dialog.clone();
    add_btn.connect_clicked(move |_| {
        show_add_server_dialog(&dialog_for_add, {
            let on_add = on_add_for_btn.clone();
            move |name, url| {
                on_add(name, url);
            }
        });
    });

    dialog.present();
    dialog
}

/// A small dialog for entering a new server name and URL.
fn show_add_server_dialog(
    parent: &impl IsA<gtk4::Window>,
    on_confirm: impl Fn(String, String) + 'static,
) {
    let dialog = adw::Window::builder()
        .title("Add Server")
        .default_width(400)
        .default_height(280)
        .modal(true)
        .transient_for(parent)
        .build();

    let header = adw::HeaderBar::new();

    let name_row = adw::EntryRow::builder()
        .title("Display Name")
        .build();
    name_row.set_text("My VPN");

    let url_row = adw::EntryRow::builder()
        .title("Server URL")
        .build();
    url_row.set_text("https://");

    let group = adw::PreferencesGroup::builder()
        .title("Server Details")
        .build();
    group.add(&name_row);
    group.add(&url_row);

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

    let add_btn = gtk4::Button::builder()
        .label("Add")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .halign(gtk4::Align::Center)
        .margin_top(12)
        .margin_bottom(12)
        .build();

    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    content.append(&header);
    content.append(&page);
    content.append(&error_label);
    content.append(&add_btn);

    dialog.set_content(Some(&content));

    add_btn.connect_clicked({
        let name_row = name_row.clone();
        let url_row = url_row.clone();
        let error_label = error_label.clone();
        let dialog = dialog.clone();
        move |_| {
            let name = name_row.text().to_string().trim().to_string();
            let url = url_row.text().to_string().trim().to_string();

            if name.is_empty() {
                error_label.set_text("Display name cannot be empty");
                error_label.set_visible(true);
                return;
            }
            if url.is_empty() || (!url.starts_with("http://") && !url.starts_with("https://")) {
                error_label.set_text("Please enter a valid URL starting with http:// or https://");
                error_label.set_visible(true);
                return;
            }

            on_confirm(name, url);
            dialog.close();
        }
    });

    url_row.connect_apply({
        let add_btn = add_btn.clone();
        move |_| {
            add_btn.emit_clicked();
        }
    });

    dialog.present();
}

/// Present a server picker dialog for first-run or when no server is active.
///
/// `on_pick` receives the index of the server the user selected, or `None`
/// if they chose to add a new server (caller should show the add dialog).
pub fn show_server_picker(
    parent: &impl IsA<gtk4::Window>,
    settings: Arc<RwLock<ClientSettings>>,
    on_pick: impl Fn(Option<usize>) + 'static,
) {
    let dialog = adw::Window::builder()
        .title("Choose Server")
        .default_width(420)
        .default_height(360)
        .modal(true)
        .transient_for(parent)
        .build();

    let header = adw::HeaderBar::new();

    let group = adw::PreferencesGroup::builder()
        .title("Select a Server")
        .description("Pick the server to connect to.")
        .build();

    let page = adw::PreferencesPage::new();
    page.add(&group);

    let add_new_btn = gtk4::Button::builder()
        .label("Add New Server...")
        .css_classes(vec!["pill".to_string()])
        .halign(gtk4::Align::Center)
        .margin_top(12)
        .margin_bottom(12)
        .build();

    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    content.append(&header);
    content.append(&page);
    content.append(&add_new_btn);

    dialog.set_content(Some(&content));

    let on_pick = Rc::new(on_pick);

    // Populate list
    let group_ref = group.clone();
    let on_pick_for_list = on_pick.clone();
    let dialog_for_list = dialog.clone();
    gtk4::glib::spawn_future_local(async move {
        let s = settings.read().await;
        for (i, server) in s.servers.iter().enumerate() {
            let row = adw::ActionRow::builder()
                .title(&server.name)
                .subtitle(&server.url)
                .activatable(true)
                .build();

            let arrow = gtk4::Image::from_icon_name("go-next-symbolic");
            row.add_suffix(&arrow);

            let on_pick_inner = on_pick_for_list.clone();
            let dialog_inner = dialog_for_list.clone();
            let idx = i;
            row.connect_activated(move |_| {
                on_pick_inner(Some(idx));
                dialog_inner.close();
            });

            group_ref.add(&row);
        }
    });

    // "Add New" button
    let on_pick_for_add = on_pick.clone();
    let dialog_for_add = dialog.clone();
    add_new_btn.connect_clicked(move |_| {
        on_pick_for_add(None);
        dialog_for_add.close();
    });

    dialog.present();
}
