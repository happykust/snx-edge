use gtk4::{
    Align, Orientation,
    glib::{self, clone},
    prelude::*,
};

use crate::{dbus::send_notification, get_window, main_window, set_window};

/// Show a prompt dialog and return the user's input, or None if cancelled.
#[allow(dead_code)]
pub async fn show_prompt_dialog(title: &str, prompt: &str, secure: bool) -> Option<String> {
    let (tx, rx) = async_channel::bounded(1);

    let title = title.to_string();
    let prompt = prompt.to_string();

    glib::idle_add_once(move || {
        glib::spawn_future_local(async move {
            let window = gtk4::Window::builder()
                .title(&title)
                .transient_for(&main_window())
                .modal(true)
                .build();

            let ok = gtk4::Button::builder().label("OK").build();
            let cancel = gtk4::Button::builder().label("Cancel").build();

            let button_box = gtk4::Box::builder()
                .orientation(Orientation::Horizontal)
                .spacing(6)
                .margin_top(6)
                .margin_start(6)
                .margin_end(6)
                .margin_bottom(6)
                .homogeneous(true)
                .halign(Align::End)
                .valign(Align::End)
                .build();

            button_box.append(&ok);
            button_box.append(&cancel);

            let inner = gtk4::Box::builder()
                .orientation(Orientation::Vertical)
                .margin_top(6)
                .margin_start(6)
                .margin_end(6)
                .margin_bottom(6)
                .spacing(6)
                .build();

            inner.append(
                &gtk4::Label::builder()
                    .label(&prompt)
                    .halign(Align::Start)
                    .build(),
            );

            let entry = gtk4::Entry::builder()
                .name("entry")
                .visibility(!secure)
                .activates_default(true)
                .build();

            inner.append(&entry);

            let outer_box = gtk4::Box::builder()
                .orientation(Orientation::Vertical)
                .build();
            outer_box.append(&inner);
            outer_box.append(&button_box);

            window.set_child(Some(&outer_box));
            window.set_default_widget(Some(&ok));

            let tx_ok = tx.clone();
            ok.connect_clicked(clone!(
                #[weak]
                window,
                #[weak]
                entry,
                move |_| {
                    let _ = tx_ok.try_send(Some(entry.text().to_string()));
                    window.close();
                }
            ));

            let tx_cancel = tx.clone();
            cancel.connect_clicked(clone!(
                #[weak]
                window,
                move |_| {
                    let _ = tx_cancel.try_send(None::<String>);
                    window.close();
                }
            ));

            let tx_entry = tx.clone();
            entry.connect_activate(clone!(
                #[weak]
                window,
                #[weak]
                entry,
                move |_| {
                    let _ = tx_entry.try_send(Some(entry.text().to_string()));
                    window.close();
                }
            ));

            window.connect_close_request(move |_| {
                let _ = tx.try_send(None::<String>);
                glib::Propagation::Proceed
            });

            {
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

            window.present();
            let current_size = window.default_size();
            let new_width = current_size.0.max(400);
            window.set_default_size(new_width, current_size.1);
        });
    });

    rx.recv().await.ok().flatten()
}

/// Modal OTP prompt. Returns the entered code, or `None` if cancelled.
///
/// Single-instance: while an "mfa" dialog is already open, a second call
/// presents the existing window and returns `None` immediately instead of
/// stacking another dialog. This guards against the status poller firing
/// repeatedly (every 2s) while the user has not yet answered the challenge.
///
/// Mirrors [`show_prompt_dialog`] but uses a plain (non-masked) entry — an OTP
/// is not a secret to be hidden — and registers itself in the `WINDOWS` map
/// under "mfa" (the same single-instance pattern as the status dialog).
pub async fn show_mfa_dialog(prompt: &str) -> Option<String> {
    let (tx, rx) = async_channel::bounded(1);

    let prompt = prompt.to_string();

    glib::idle_add_once(move || {
        glib::spawn_future_local(async move {
            // Single-instance guard: never stack a second OTP dialog. Runs on
            // the GTK main thread (idle callback), so touching `WINDOWS` here
            // is safe.
            if let Some(existing) = get_window("mfa") {
                existing.present();
                let _ = tx.try_send(None::<String>);
                return;
            }

            let window = gtk4::Window::builder()
                .title("SNX Edge - MFA")
                .transient_for(&main_window())
                .modal(true)
                .build();

            let ok = gtk4::Button::builder().label("OK").build();
            let cancel = gtk4::Button::builder().label("Cancel").build();

            let button_box = gtk4::Box::builder()
                .orientation(Orientation::Horizontal)
                .spacing(6)
                .margin_top(6)
                .margin_start(6)
                .margin_end(6)
                .margin_bottom(6)
                .homogeneous(true)
                .halign(Align::End)
                .valign(Align::End)
                .build();

            button_box.append(&ok);
            button_box.append(&cancel);

            let inner = gtk4::Box::builder()
                .orientation(Orientation::Vertical)
                .margin_top(6)
                .margin_start(6)
                .margin_end(6)
                .margin_bottom(6)
                .spacing(6)
                .build();

            inner.append(
                &gtk4::Label::builder()
                    .label(&prompt)
                    .halign(Align::Start)
                    .build(),
            );

            let entry = gtk4::Entry::builder()
                .name("entry")
                .visibility(true)
                .activates_default(true)
                .build();

            inner.append(&entry);

            let outer_box = gtk4::Box::builder()
                .orientation(Orientation::Vertical)
                .build();
            outer_box.append(&inner);
            outer_box.append(&button_box);

            window.set_child(Some(&outer_box));
            window.set_default_widget(Some(&ok));

            let tx_ok = tx.clone();
            ok.connect_clicked(clone!(
                #[weak]
                window,
                #[weak]
                entry,
                move |_| {
                    let _ = tx_ok.try_send(Some(entry.text().to_string()));
                    window.close();
                }
            ));

            let tx_cancel = tx.clone();
            cancel.connect_clicked(clone!(
                #[weak]
                window,
                move |_| {
                    let _ = tx_cancel.try_send(None::<String>);
                    window.close();
                }
            ));

            let tx_entry = tx.clone();
            entry.connect_activate(clone!(
                #[weak]
                window,
                #[weak]
                entry,
                move |_| {
                    let _ = tx_entry.try_send(Some(entry.text().to_string()));
                    window.close();
                }
            ));

            window.connect_close_request(move |_| {
                // Sending `None` is a no-op if OK/Enter already queued a code
                // (the bounded(1) channel is full); the first value wins.
                let _ = tx.try_send(None::<String>);
                // Clear the single-instance registration on every close path
                // (OK, Cancel, Enter, Escape and WM-close all route here).
                set_window("mfa", None::<gtk4::Window>);
                glib::Propagation::Proceed
            });

            {
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

            set_window("mfa", Some(window.clone()));
            window.present();
            let current_size = window.default_size();
            let new_width = current_size.0.max(400);
            window.set_default_size(new_width, current_size.1);
        });
    });

    rx.recv().await.ok().flatten()
}

/// Show a login dialog with username and password fields.
#[allow(dead_code)]
pub async fn show_login_dialog() -> Option<(String, String)> {
    let (tx, rx) = async_channel::bounded(1);

    glib::idle_add_once(move || {
        glib::spawn_future_local(async move {
            let window = gtk4::Window::builder()
                .title("SNX Edge - Login")
                .transient_for(&main_window())
                .modal(true)
                .build();

            let ok = gtk4::Button::builder().label("Login").build();
            let cancel = gtk4::Button::builder().label("Cancel").build();

            let button_box = gtk4::Box::builder()
                .orientation(Orientation::Horizontal)
                .spacing(6)
                .margin_top(6)
                .margin_start(6)
                .margin_end(6)
                .margin_bottom(6)
                .homogeneous(true)
                .halign(Align::End)
                .valign(Align::End)
                .build();

            button_box.append(&ok);
            button_box.append(&cancel);

            let inner = gtk4::Box::builder()
                .orientation(Orientation::Vertical)
                .margin_top(6)
                .margin_start(6)
                .margin_end(6)
                .margin_bottom(6)
                .spacing(6)
                .build();

            inner.append(
                &gtk4::Label::builder()
                    .label("Username:")
                    .halign(Align::Start)
                    .build(),
            );

            let username_entry = gtk4::Entry::builder()
                .name("username")
                .placeholder_text(std::env::var("USER").unwrap_or_default())
                .build();
            inner.append(&username_entry);

            inner.append(
                &gtk4::Label::builder()
                    .label("Password:")
                    .halign(Align::Start)
                    .build(),
            );

            let password_entry = gtk4::PasswordEntry::builder().show_peek_icon(true).build();
            inner.append(&password_entry);

            let outer_box = gtk4::Box::builder()
                .orientation(Orientation::Vertical)
                .build();
            outer_box.append(&inner);
            outer_box.append(&button_box);

            window.set_child(Some(&outer_box));
            window.set_default_widget(Some(&ok));

            let tx_ok = tx.clone();
            ok.connect_clicked(clone!(
                #[weak]
                window,
                #[weak]
                username_entry,
                #[weak]
                password_entry,
                move |_| {
                    let _ = tx_ok.try_send(Some((
                        username_entry.text().to_string(),
                        password_entry.text().to_string(),
                    )));
                    window.close();
                }
            ));

            let tx_cancel = tx.clone();
            cancel.connect_clicked(clone!(
                #[weak]
                window,
                move |_| {
                    let _ = tx_cancel.try_send(None::<(String, String)>);
                    window.close();
                }
            ));

            window.connect_close_request(move |_| {
                let _ = tx.try_send(None::<(String, String)>);
                glib::Propagation::Proceed
            });

            {
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

            window.present();
            let current_size = window.default_size();
            let new_width = current_size.0.max(400);
            window.set_default_size(new_width, current_size.1);
        });
    });

    rx.recv().await.ok().flatten()
}

/// Show a desktop notification via D-Bus.
pub async fn show_notification(summary: &str, message: &str) -> anyhow::Result<()> {
    send_notification(summary, message).await
}
