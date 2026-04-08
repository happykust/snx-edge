use std::{cell::RefCell, collections::HashMap, sync::Arc, time::Duration};

use gtk4::{
    Application, ApplicationWindow, License, Window,
    glib::{self, clone},
    prelude::*,
};
use tokio::sync::mpsc;
use tracing::{info, level_filters::LevelFilter, warn};

use crate::{
    api::ApiClient,
    auth::AuthManager,
    client_settings::{ClientSettings, ServerConnection},
    profiles::ProfileStore,
    prompt::show_notification,
    status::show_status_dialog,
    theme::init_theme_monitoring,
    tray::{ConnectionState, TrayCommand, TrayEvent},
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
mod tray;
mod windows;

pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

thread_local! {
    static WINDOWS: RefCell<HashMap<String, Window>> = RefCell::new(HashMap::new());
}

pub fn main_window() -> ApplicationWindow {
    get_window("main")
        .unwrap()
        .downcast::<ApplicationWindow>()
        .unwrap()
}

pub fn get_window(name: &str) -> Option<Window> {
    WINDOWS.with(|cell| cell.borrow().get(name).cloned())
}

pub fn set_window<W: Cast + IsA<Window>>(name: &str, window: Option<W>) {
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
        match tray::AppTray::new(tray_event_sender.clone(), false).await {
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

    let ctx = AppContext {
        api,
        auth,
        profile_store,
        settings: settings.clone(),
        tray_cmd: tray_command_sender.clone(),
        tray_evt: tray_event_sender.clone(),
    };

    // Wrap ctx in Arc<RwLock> so we can update it after login
    let ctx = Arc::new(tokio::sync::RwLock::new(ctx));

    let app = Application::builder()
        .application_id("com.github.snx-edge-client")
        .build();

    let ctx_activate = ctx.clone();
    let settings_activate = settings.clone();

    app.connect_activate(move |app| {
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
                        do_status(ctx.tray_evt.clone(), false, ctx.api.clone());
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
                        glib::idle_add_once(|| {
                            windows::servers::show_servers_window();
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
            start_status_polling(c.api.clone(), c.tray_cmd.clone());
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
                start_status_polling(c.api.clone(), c.tray_cmd.clone());
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
                start_status_polling(c.api.clone(), c.tray_cmd.clone());
            }
            Err(e) => {
                let _ = show_notification("Login Failed", &e.to_string()).await;
                drop(c);
                show_login_for_server(ctx, url, name);
            }
        }
    }
}

fn start_status_polling(api: ApiClient, cmd_sender: mpsc::Sender<TrayCommand>) {
    tokio::spawn(async move {
        let mut old_state = ConnectionState::Disconnected;
        loop {
            let new_state = match api.tunnel_status().await {
                Ok(json) => ConnectionState::from_json(&json),
                Err(_) => ConnectionState::Disconnected, // silently retry
            };

            if !status::same_status(&new_state, &old_state) {
                old_state = new_state.clone();
                let _ = cmd_sender
                    .send(TrayCommand::Update(Some(Arc::new(old_state.clone()))))
                    .await;
            }

            tokio::time::sleep(POLL_INTERVAL).await;
        }
    });
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
                let _ = show_notification("Error", "No VPN profiles configured").await;
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
            let _ = show_notification("VPN", &format!("{state}")).await;
            let _ = ctx
                .tray_cmd
                .send(TrayCommand::Update(Some(Arc::new(state))))
                .await;
        }
        Err(e) => {
            let _ = show_notification("Connection Error", &e.to_string()).await;
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
            let _ = show_notification("Disconnect Error", &e.to_string()).await;
        }
    }
}

fn do_about() {
    glib::idle_add_once(|| {
        // NOTE: AboutWindow is deprecated since libadwaita 1.5 in favor of AboutDialog,
        // but AboutDialog requires the v1_5 feature flag which is not enabled.
        // When upgrading to v1_5+, replace with:
        //   libadwaita::AboutDialog::builder()...build().present(Some(&main_window()));
        let parent = main_window();
        let about = libadwaita::AboutWindow::builder()
            .transient_for(&parent)
            .modal(true)
            .application_name("snx-edge")
            .application_icon("network-vpn")
            .version(env!("CARGO_PKG_VERSION"))
            .developer_name("snx-edge contributors")
            .license_type(License::Agpl30)
            .website("https://github.com/happykust/snx-edge")
            .issue_url("https://github.com/happykust/snx-edge/issues")
            .build();

        about.present();
    });
}

fn do_status(sender: mpsc::Sender<TrayEvent>, exit_on_close: bool, api: ApiClient) {
    glib::idle_add_once(move || {
        glib::spawn_future_local(
            async move { show_status_dialog(sender, exit_on_close, api).await },
        );
    });
}

fn init_logging() {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(LevelFilter::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
}
