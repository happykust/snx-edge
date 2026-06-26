use std::{cell::RefCell, collections::HashMap, sync::Arc, time::Duration};

use gtk4::{
    ApplicationWindow, License, Window,
    gio::ApplicationFlags,
    glib::{self, clone},
    prelude::*,
};
use libadwaita::{Application, prelude::AdwDialogExt};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::{
    api::ApiClient,
    auth::AuthManager,
    client_settings::{ClientSettings, ServerConnection},
    profiles::ProfileStore,
    prompt::show_notification,
    status::show_status_dialog,
    theme::init_theme_monitoring,
    toast::show_feedback,
    tray::{ConnectionState, ProfileEntry, TrayCommand, TrayEvent},
};

mod api;
mod assets;
mod auth;
mod client_settings;
mod dbus;
mod profiles;
mod prompt;
mod settings;
mod status;
mod theme;
mod toast;
mod tray;
mod windows;

pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

// === WINDOWS singleton map ===
//
// `WINDOWS` is a per-thread map of named singleton windows. GTK4 widget types
// are `!Send` / `!Sync`, so the map itself is `thread_local!`. All accessors
// below MUST be called from the GTK main thread (the thread that owns the
// default `glib::MainContext`). The `debug_assert!` calls catch accidental
// calls from `tokio::spawn`'d tasks in debug builds — release builds will
// still violate `!Send` invariants if you misuse them, but at least the
// thread_local will return a fresh empty map and the bug becomes obvious.
thread_local! {
    static WINDOWS: RefCell<HashMap<String, Window>> = RefCell::new(HashMap::new());
}

#[inline]
fn assert_main_thread() {
    debug_assert!(
        glib::MainContext::default().is_owner(),
        "WINDOWS must only be accessed from the GTK main thread"
    );
}

pub fn main_window() -> ApplicationWindow {
    assert_main_thread();
    get_window("main")
        .unwrap()
        .downcast::<ApplicationWindow>()
        .unwrap()
}

pub fn get_window(name: &str) -> Option<Window> {
    assert_main_thread();
    WINDOWS.with(|cell| cell.borrow().get(name).cloned())
}

pub fn set_window<W: Cast + IsA<Window>>(name: &str, window: Option<W>) {
    assert_main_thread();
    WINDOWS.with(|cell| {
        if let Some(window) = window {
            cell.borrow_mut()
                .insert(name.to_string(), window.upcast::<Window>());
        } else {
            cell.borrow_mut().remove(name);
        }
    });
}

// === Shared app state ===

#[derive(Clone)]
pub struct AppContext {
    pub api: ApiClient,
    pub auth: AuthManager,
    pub profile_store: Arc<ProfileStore>,
    pub settings: Arc<tokio::sync::RwLock<ClientSettings>>,
    pub tray_cmd: mpsc::Sender<TrayCommand>,
    pub tray_evt: mpsc::Sender<TrayEvent>,
    /// Latest tunnel status, updated by a single background poller. UI
    /// surfaces (tray, status dialog) subscribe via `Receiver::changed`
    /// instead of running independent timers.
    pub status_tx: watch::Sender<Arc<ConnectionState>>,
    pub status_rx: watch::Receiver<Arc<ConnectionState>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    let _ = init_theme_monitoring().await;

    let settings = ClientSettings::load();
    let settings = Arc::new(tokio::sync::RwLock::new(settings));

    let (tray_event_sender, mut tray_event_receiver) = mpsc::channel(16);

    // Create tray (retries)
    let mut retry_count = 5;
    let mut my_tray = loop {
        match tray::AppTray::new(tray_event_sender.clone(), false, settings.clone()).await {
            Ok(tray) => break tray,
            Err(e) => {
                if retry_count == 0 {
                    anyhow::bail!("Failed to create tray: {}", e);
                }
                warn!("Failed to create tray: {}, retrying in 2s", e);
                retry_count -= 1;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };

    let tray_command_sender = my_tray.sender();
    tokio::spawn(async move { my_tray.run().await });

    // Dummy API/Auth — will be replaced after login
    let api = ApiClient::new("http://localhost");
    let auth = AuthManager::new(api.clone(), "http://localhost");
    let profile_store = Arc::new(ProfileStore::new());

    let (status_tx, status_rx) = watch::channel(Arc::new(ConnectionState::Disconnected));

    let ctx = AppContext {
        api,
        auth,
        profile_store,
        settings: settings.clone(),
        tray_cmd: tray_command_sender.clone(),
        tray_evt: tray_event_sender.clone(),
        status_tx,
        status_rx,
    };

    // Wrap ctx in Arc<RwLock> so we can update it after login
    let ctx = Arc::new(tokio::sync::RwLock::new(ctx));

    // libadwaita::Application initialises libadwaita (calls `adw_init()`,
    // installs the StyleManager) so we don't have to do it manually.
    //
    // ApplicationFlags::default() makes the GApplication framework enforce
    // single-instance: if another process with the same application_id is
    // running, our `g_application_register` call will route the activation
    // to that primary instance and `is_remote()` returns true here, after
    // which we can simply exit. The user-visible behaviour is that
    // double-clicking the desktop launcher just brings the running tray to
    // focus instead of starting a duplicate process.
    let app = Application::builder()
        .application_id("com.github.snx-edge-client")
        .flags(ApplicationFlags::default())
        .build();

    // Style manager is now driven by libadwaita; this is a no-op in the
    // common case but ensures the singleton exists and follows the system
    // color scheme. The fallback theme detection in `theme.rs` is still
    // used by `tray.rs` for the icon theme choice (libadwaita StyleManager
    // doesn't influence the tray icon set we ship as PNG).
    let _style_manager = libadwaita::StyleManager::default();

    let ctx_activate = ctx.clone();
    let settings_activate = settings.clone();

    app.connect_activate(move |app| {
        // If a main window is already mapped, this is a re-activation
        // (e.g. user double-clicked the launcher and GApplication routed
        // the second activation to us). Just present the existing window
        // and skip the startup flow so we don't open the add-server
        // dialog a second time.
        if let Some(existing) = get_window("main") {
            existing.present();
            return;
        }

        let app_window = ApplicationWindow::builder()
            .application(app)
            .visible(false)
            .build();

        let provider = gtk4::CssProvider::new();
        provider.load_from_string(assets::APP_CSS);
        gtk4::style_context_add_provider_for_display(
            &gtk4::prelude::WidgetExt::display(&app_window),
            &provider,
            gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
        set_window("main", Some(app_window));

        // Startup flow: check if we have a saved server
        let ctx = ctx_activate.clone();
        let settings = settings_activate.clone();
        glib::spawn_future_local(async move {
            let s = settings.read().await;
            if let Some(server) = s.active_server().cloned() {
                drop(s);
                // Try restoring saved session
                try_restore_or_login(ctx, server).await;
            } else {
                drop(s);
                // No server configured → show server setup dialog
                show_add_server_dialog(ctx);
            }
        });
    });

    // Main tray event loop
    let ctx_events = ctx.clone();

    glib::spawn_future_local(clone!(
        #[weak]
        app,
        async move {
            while let Some(v) = tray_event_receiver.recv().await {
                let ctx = ctx_events.read().await.clone();
                match v {
                    TrayEvent::Connect(profile_id) => {
                        let ctx2 = ctx.clone();
                        tokio::spawn(async move {
                            do_connect(&ctx2, &profile_id).await;
                        });
                    }
                    TrayEvent::Disconnect => {
                        let ctx2 = ctx.clone();
                        tokio::spawn(async move {
                            do_disconnect(&ctx2).await;
                        });
                    }
                    TrayEvent::Settings => {
                        settings::start_settings_dialog(
                            main_window(),
                            ctx.tray_cmd.clone(),
                            ctx.api.clone(),
                            ctx.auth.clone(),
                            ctx.profile_store.clone(),
                            ctx.settings.clone(),
                        );
                    }
                    TrayEvent::AddServer => {
                        let ctx_ref = ctx_events.clone();
                        show_add_server_dialog(ctx_ref);
                    }
                    TrayEvent::Exit => {
                        let _ = ctx.tray_cmd.send(TrayCommand::Exit).await;
                        app.quit();
                    }
                    TrayEvent::About => do_about(),
                    TrayEvent::Status => {
                        do_status(
                            ctx.tray_evt.clone(),
                            false,
                            ctx.api.clone(),
                            ctx.status_rx.clone(),
                        );
                    }
                    TrayEvent::Routing => {
                        let api = ctx.api.clone();
                        let auth = ctx.auth.clone();
                        glib::spawn_future_local(async move {
                            let role = auth.role().await.unwrap_or_else(|| "viewer".to_string());
                            windows::routing::show_routing_window(api, &role);
                        });
                    }
                    TrayEvent::Users => {
                        let api = ctx.api.clone();
                        let auth = ctx.auth.clone();
                        glib::spawn_future_local(async move {
                            let role = auth.role().await.unwrap_or_else(|| "viewer".to_string());
                            if role != "admin" {
                                let _ = show_notification("Access Denied", "Admin access required")
                                    .await;
                                return;
                            }
                            windows::users::show_users_window(api, &role);
                        });
                    }
                    TrayEvent::Servers => {
                        let settings = ctx.settings.clone();
                        glib::idle_add_once(move || {
                            windows::servers::show_servers_window(settings);
                        });
                    }
                    TrayEvent::Logs => {
                        let api = ctx.api.clone();
                        glib::idle_add_once(move || {
                            windows::logs::show_logs_window(api);
                        });
                    }
                }
            }
        }
    ));

    app.run_with_args::<&str>(&[]);
    Ok(())
}

// === Startup flow ===

async fn try_restore_or_login(ctx: Arc<tokio::sync::RwLock<AppContext>>, server: ServerConnection) {
    info!("trying to restore session for {}", server.url);

    // Setup API for this server
    {
        let mut c = ctx.write().await;
        c.api = ApiClient::with_insecure(&server.url, server.insecure);
        c.auth = AuthManager::new(c.api.clone(), &server.url);
    }

    let c = ctx.read().await;
    match c.auth.refresh().await {
        Ok(()) => {
            info!("session restored for {}", server.url);
            let _ = profiles::load_profiles(&c.api, &c.profile_store).await;
            push_profiles_to_tray(&c).await;
            start_status_polling(c.api.clone(), c.tray_cmd.clone(), c.status_tx.clone());
        }
        Err(_) => {
            drop(c);
            show_login_for_server(ctx, server.url, server.name);
        }
    }
}

fn show_add_server_dialog(ctx: Arc<tokio::sync::RwLock<AppContext>>) {
    glib::spawn_future_local(show_add_server_dialog_inner(ctx));
}

async fn show_add_server_dialog_inner(ctx: Arc<tokio::sync::RwLock<AppContext>>) {
    let (tx, rx) = async_channel::bounded(1);

    glib::idle_add_once(move || {
        glib::spawn_future_local(async move {
            let result = show_server_input_dialog().await;
            let _ = tx.send(result).await;
        });
    });

    if let Ok(Some((name, url, username, password))) = rx.recv().await {
        // Save server to settings
        {
            let c = ctx.read().await;
            let mut settings = c.settings.write().await;
            settings.servers.push(ServerConnection {
                name: name.clone(),
                url: url.clone(),
                auto_connect: false,
                last_profile_id: None,
                insecure: false,
            });
            settings.active_server = Some(settings.servers.len() - 1);
            let _ = settings.save();
        }

        // Setup API and login
        {
            let mut c = ctx.write().await;
            c.api = ApiClient::new(&url);
            c.auth = AuthManager::new(c.api.clone(), &url);
        }

        let c = ctx.read().await;
        match c.auth.login(&username, &password).await {
            Ok(()) => {
                info!("logged in to {}", url);
                let _ = profiles::load_profiles(&c.api, &c.profile_store).await;
                push_profiles_to_tray(&c).await;
                start_status_polling(c.api.clone(), c.tray_cmd.clone(), c.status_tx.clone());
            }
            Err(e) => {
                let _ = show_notification("Login Failed", &e.to_string()).await;
                // Retry — non-recursive to avoid boxing
                drop(c);
                show_add_server_dialog(ctx);
            }
        }
    }
    // User cancelled → app stays in tray with no active connection
}

fn show_login_for_server(ctx: Arc<tokio::sync::RwLock<AppContext>>, url: String, name: String) {
    glib::spawn_future_local(show_login_for_server_inner(ctx, url, name));
}

async fn show_login_for_server_inner(
    ctx: Arc<tokio::sync::RwLock<AppContext>>,
    url: String,
    name: String,
) {
    let (tx, rx) = async_channel::bounded(1);

    let url2 = url.clone();
    let name2 = name.clone();
    glib::idle_add_once(move || {
        glib::spawn_future_local(async move {
            let result = show_login_only_dialog(&name2, &url2).await;
            let _ = tx.send(result).await;
        });
    });

    if let Ok(Some((username, password))) = rx.recv().await {
        let c = ctx.read().await;
        match c.auth.login(&username, &password).await {
            Ok(()) => {
                info!("logged in to {}", url);
                let _ = profiles::load_profiles(&c.api, &c.profile_store).await;
                push_profiles_to_tray(&c).await;
                start_status_polling(c.api.clone(), c.tray_cmd.clone(), c.status_tx.clone());
            }
            Err(e) => {
                let _ = show_notification("Login Failed", &e.to_string()).await;
                drop(c);
                show_login_for_server(ctx, url, name);
            }
        }
    }
}

/// Push the current profile list (and active profile id) into the tray so
/// the "Profiles" submenu reflects the server. Safe to call repeatedly.
async fn push_profiles_to_tray(ctx: &AppContext) {
    let profiles: Vec<ProfileEntry> = ctx
        .profile_store
        .all()
        .into_iter()
        .map(|p| ProfileEntry {
            id: p.id,
            name: p.name,
        })
        .collect();
    let active = ctx.profile_store.connected_profile_id().or_else(|| {
        // Fall back to ClientSettings.last_profile_id of the active server
        // when the store has no in-memory active id (i.e. fresh start).
        let settings = ctx.settings.try_read().ok()?;
        settings.active_server()?.last_profile_id.clone()
    });
    let _ = ctx
        .tray_cmd
        .send(TrayCommand::SetProfiles { profiles, active })
        .await;
}

/// Single source of truth for tunnel status. Polls the server, then fans
/// out to:
///   * the tray (via `cmd_sender` so the icon/label updates),
///   * `status_tx` so any UI subscriber (status dialog, future widgets)
///     can `changed().await` instead of running its own poll timer.
fn start_status_polling(
    api: ApiClient,
    cmd_sender: mpsc::Sender<TrayCommand>,
    status_tx: watch::Sender<Arc<ConnectionState>>,
) {
    tokio::spawn(async move {
        let mut old_state = ConnectionState::Disconnected;
        loop {
            let new_state = match api.tunnel_status().await {
                Ok(json) => ConnectionState::from_json(&json),
                Err(_) => ConnectionState::Disconnected, // silently retry
            };

            if !status::same_status(&new_state, &old_state) {
                // Detect a *fresh* transition into Mfa (previous state was not
                // already Mfa) so we prompt exactly once, not on every 2s poll
                // while the server keeps reporting the same challenge.
                let entering_mfa = matches!(new_state, ConnectionState::Mfa(_))
                    && !matches!(old_state, ConnectionState::Mfa(_));

                old_state = new_state.clone();
                let arc = Arc::new(old_state.clone());
                let _ = cmd_sender
                    .send(TrayCommand::Update(Some(arc.clone())))
                    .await;
                // send_replace overrides regardless of receiver count, which
                // matches our "always reflect latest" semantic.
                status_tx.send_replace(arc);

                if entering_mfa && let ConnectionState::Mfa(prompt) = &new_state {
                    // Spawn the prompt as a detached task so the poll loop
                    // keeps running while the (modal) OTP dialog is open. The
                    // dialog's own single-instance guard plus this
                    // transition-edge check together prevent stacking.
                    let api = api.clone();
                    let prompt = prompt.clone();
                    tokio::spawn(async move { handle_mfa_challenge(api, prompt).await });
                }
            }

            tokio::time::sleep(POLL_INTERVAL).await;
        }
    });
}

/// Surface a desktop notification, prompt the user for the OTP, and submit it.
///
/// Runs as a detached task (see `start_status_polling`). The challenge result
/// is logged and otherwise ignored — the next status poll reflects whether the
/// reconnect succeeded.
async fn handle_mfa_challenge(api: ApiClient, prompt: String) {
    show_feedback("VPN - action needed", "Enter OTP to reconnect").await;

    if let Some(code) = crate::prompt::show_mfa_dialog(&prompt).await {
        match api.tunnel_challenge(code.trim()).await {
            Ok(_) => info!("submitted MFA challenge response"),
            Err(e) => warn!("MFA challenge submission failed: {e}"),
        }
    }
}

// === Dialogs ===

/// Dialog: add new server (URL + name + credentials)
async fn show_server_input_dialog() -> Option<(String, String, String, String)> {
    use gtk4::{Align, Orientation};

    let (tx, rx) = async_channel::bounded(1);

    let window = gtk4::Window::builder()
        .title("SNX Edge — Add Server")
        .transient_for(&main_window())
        .modal(true)
        .default_width(400)
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
            .label("Server name:")
            .halign(Align::Start)
            .build(),
    );
    let name_entry = gtk4::Entry::builder()
        .placeholder_text("Office MikroTik")
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
        .build();
    inner.append(&url_entry);

    inner.append(
        &gtk4::Label::builder()
            .label("Username:")
            .halign(Align::Start)
            .build(),
    );
    let user_entry = gtk4::Entry::builder().placeholder_text("admin").build();
    inner.append(&user_entry);

    inner.append(
        &gtk4::Label::builder()
            .label("Password:")
            .halign(Align::Start)
            .build(),
    );
    let pass_entry = gtk4::PasswordEntry::new();
    inner.append(&pass_entry);

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
    let connect_btn = gtk4::Button::builder()
        .label("Connect")
        .css_classes(vec!["suggested-action".to_string()])
        .build();
    btn_box.append(&cancel_btn);
    btn_box.append(&connect_btn);
    inner.append(&btn_box);

    window.set_child(Some(&inner));

    let tx_ok = tx.clone();
    connect_btn.connect_clicked(clone!(
        #[weak]
        window,
        #[weak]
        name_entry,
        #[weak]
        url_entry,
        #[weak]
        user_entry,
        #[weak]
        pass_entry,
        #[weak]
        error_label,
        move |_| {
            let name = name_entry.text().trim().to_string();
            let url = url_entry.text().trim().to_string();
            let user = user_entry.text().trim().to_string();
            let pass = pass_entry.text().to_string();

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
            if user.is_empty() || pass.is_empty() {
                error_label.set_text("Username and password are required");
                error_label.set_visible(true);
                return;
            }

            let display_name = if name.is_empty() { url.clone() } else { name };
            let _ = tx_ok.try_send(Some((display_name, url, user, pass)));
            window.close();
        }
    ));

    cancel_btn.connect_clicked(clone!(
        #[weak]
        window,
        move |_| {
            let _ = tx.try_send(None::<(String, String, String, String)>);
            window.close();
        }
    ));

    window.present();
    rx.recv().await.ok().flatten()
}

/// Dialog: login to existing server (username + password only)
async fn show_login_only_dialog(server_name: &str, server_url: &str) -> Option<(String, String)> {
    use gtk4::{Align, Orientation};

    let (tx, rx) = async_channel::bounded(1);

    let window = gtk4::Window::builder()
        .title(format!("SNX Edge — Login to {server_name}"))
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
            .label(format!("Server: {server_url}"))
            .halign(Align::Start)
            .css_classes(vec!["dim-label".to_string()])
            .build(),
    );

    inner.append(
        &gtk4::Label::builder()
            .label("Username:")
            .halign(Align::Start)
            .build(),
    );
    let user_entry = gtk4::Entry::builder().placeholder_text("admin").build();
    inner.append(&user_entry);

    inner.append(
        &gtk4::Label::builder()
            .label("Password:")
            .halign(Align::Start)
            .build(),
    );
    let pass_entry = gtk4::PasswordEntry::new();
    inner.append(&pass_entry);

    let btn_box = gtk4::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_top(8)
        .halign(Align::End)
        .build();

    let cancel_btn = gtk4::Button::builder().label("Cancel").build();
    let login_btn = gtk4::Button::builder()
        .label("Login")
        .css_classes(vec!["suggested-action".to_string()])
        .build();
    btn_box.append(&cancel_btn);
    btn_box.append(&login_btn);
    inner.append(&btn_box);

    window.set_child(Some(&inner));

    let tx_ok = tx.clone();
    login_btn.connect_clicked(clone!(
        #[weak]
        window,
        #[weak]
        user_entry,
        #[weak]
        pass_entry,
        move |_| {
            let user = user_entry.text().trim().to_string();
            let pass = pass_entry.text().to_string();
            let _ = tx_ok.try_send(Some((user, pass)));
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

// === Actions ===

async fn do_connect(ctx: &AppContext, profile_id: &str) {
    // Resolve profile_id: if empty, use connected_profile_id or first available profile
    let resolved_id = if profile_id.is_empty() {
        if let Some(id) = ctx
            .profile_store
            .connected_profile_id()
            .filter(|s| !s.is_empty())
        {
            id
        } else {
            let profiles = ctx.profile_store.all();
            if let Some(first) = profiles.first() {
                first.id.clone()
            } else {
                show_feedback("Error", "No VPN profiles configured").await;
                return;
            }
        }
    } else {
        profile_id.to_string()
    };

    let _ = ctx
        .tray_cmd
        .send(TrayCommand::Update(Some(Arc::new(
            ConnectionState::Connecting,
        ))))
        .await;

    match ctx.api.tunnel_connect(&resolved_id).await {
        Ok(json) => {
            let state = ConnectionState::from_json(&json);
            show_feedback("VPN", &format!("{state}")).await;
            // Track the active profile so the tray submenu shows the
            // correct checkmark next time it opens.
            ctx.profile_store.set_connected(Some(resolved_id.clone()));
            push_profiles_to_tray(ctx).await;
            let _ = ctx
                .tray_cmd
                .send(TrayCommand::Update(Some(Arc::new(state))))
                .await;
        }
        Err(e) => {
            show_feedback("Connection Error", &e.to_string()).await;
            let _ = ctx
                .tray_cmd
                .send(TrayCommand::Update(Some(Arc::new(ConnectionState::Error(
                    e.to_string(),
                )))))
                .await;
        }
    }
}

async fn do_disconnect(ctx: &AppContext) {
    match ctx.api.tunnel_disconnect().await {
        Ok(json) => {
            let state = ConnectionState::from_json(&json);
            let _ = ctx
                .tray_cmd
                .send(TrayCommand::Update(Some(Arc::new(state))))
                .await;
        }
        Err(e) => {
            show_feedback("Disconnect Error", &e.to_string()).await;
        }
    }
}

fn do_about() {
    glib::idle_add_once(|| {
        // libadwaita >= 1.5 prefers `AboutDialog` over the deprecated
        // `AboutWindow`. The dialog uses `present(parent)` instead of being
        // built with `transient_for` + `modal`.
        let parent = main_window();
        let about = libadwaita::AboutDialog::builder()
            .application_name("snx-edge")
            .application_icon("network-vpn")
            .version(env!("CARGO_PKG_VERSION"))
            .developer_name("snx-edge contributors")
            .license_type(License::Agpl30)
            .website("https://github.com/happykust/snx-edge")
            .issue_url("https://github.com/happykust/snx-edge/issues")
            .build();

        about.present(Some(&parent));
    });
}

fn do_status(
    sender: mpsc::Sender<TrayEvent>,
    exit_on_close: bool,
    api: ApiClient,
    status_rx: watch::Receiver<Arc<ConnectionState>>,
) {
    glib::idle_add_once(move || {
        glib::spawn_future_local(async move {
            show_status_dialog(sender, exit_on_close, api, status_rx).await
        });
    });
}

fn init_logging() {
    // Use try_init so we never panic if another library has already installed
    // a global subscriber. EnvFilter honors RUST_LOG (default: info).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();
}
