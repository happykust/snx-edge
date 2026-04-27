//! Lightweight in-window feedback via libadwaita toasts, with a D-Bus
//! notification fallback.
//!
//! Some window managers (i3, sway-minimal) ship without a notification
//! daemon, so a `show_notification` call vanishes silently. To make
//! feedback always visible, callers can register their `ToastOverlay`
//! here when a window opens (and unregister on close); the rest of the
//! app then calls [`show_feedback`] which:
//!
//! 1. Iterates the registered overlays and adds an [`adw::Toast`].
//! 2. Always also fires the D-Bus notification, so a focused desktop
//!    user still sees an OS-level toast even if no window of ours is
//!    mapped.
//!
//! All registry access must happen on the GTK main thread (the
//! overlays are GTK widgets and are `!Send`). The `debug_assert!`s on
//! the public functions guard against accidental misuse from a
//! `tokio::spawn` task.

use std::cell::RefCell;
use std::collections::HashMap;

use gtk4::glib;
use libadwaita::{Toast, ToastOverlay};

use crate::prompt::show_notification;

thread_local! {
    static OVERLAYS: RefCell<HashMap<String, ToastOverlay>> = RefCell::new(HashMap::new());
}

#[inline]
fn assert_main_thread() {
    debug_assert!(
        glib::MainContext::default().is_owner(),
        "toast registry must only be touched from the GTK main thread"
    );
}

/// Register a window's `ToastOverlay` under a name. Replaces any prior
/// registration for that name. Pair every call with
/// `unregister_overlay(name)` in the window's `connect_close_request`.
pub fn register_overlay(name: &str, overlay: ToastOverlay) {
    assert_main_thread();
    OVERLAYS.with(|cell| {
        cell.borrow_mut().insert(name.to_string(), overlay);
    });
}

/// Drop a previously registered overlay. Idempotent.
pub fn unregister_overlay(name: &str) {
    assert_main_thread();
    OVERLAYS.with(|cell| {
        cell.borrow_mut().remove(name);
    });
}

/// Show transient user feedback. Always fires a D-Bus notification (so
/// users on non-GTK desktops still see something) and additionally
/// queues an in-window `Adw::Toast` on every registered overlay.
///
/// Safe to call from any task: the in-window part is dispatched to the
/// GTK main loop via `glib::idle_add_once`.
#[allow(dead_code)]
pub async fn show_feedback(summary: &str, message: &str) {
    let _ = show_notification(summary, message).await;

    let label = if summary.is_empty() {
        message.to_string()
    } else if message.is_empty() {
        summary.to_string()
    } else {
        format!("{summary}: {message}")
    };

    glib::idle_add_once(move || {
        OVERLAYS.with(|cell| {
            for overlay in cell.borrow().values() {
                overlay.add_toast(Toast::new(&label));
            }
        });
    });
}
