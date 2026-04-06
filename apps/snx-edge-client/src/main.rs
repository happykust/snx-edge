mod api;
mod auth;
mod settings;
mod sse;
mod tray;
mod ui;

use std::sync::Arc;

use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use tokio::sync::RwLock;

use api::ApiClient;
use auth::AuthManager;
use settings::ClientSettings;
use sse::SseManager;

/// Shared application context available to all UI handlers.
#[derive(Clone)]
pub struct AppContext {
    pub api: Arc<ApiClient>,
    pub auth: Arc<AuthManager>,
    pub settings: Arc<RwLock<ClientSettings>>,
    pub sse: Arc<SseManager>,
    pub tray_handle: Arc<RwLock<Option<tray::TrayHandle>>>,
}

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Create a tokio runtime so that tokio::spawn is available globally.
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let _guard = runtime.enter();

    let app = adw::Application::builder()
        .application_id("com.github.happykust.snx-edge-client")
        .build();

    app.connect_activate(on_activate);
    app.run();
}

fn on_activate(app: &adw::Application) {
    // Guard: if already running, just present the existing window
    if let Some(window) = app.active_window() {
        window.present();
        return;
    }

    let settings = ClientSettings::load();

    // Use the active server URL if available, otherwise start with an empty URL.
    let initial_url = settings
        .active()
        .map(|s| s.url.as_str())
        .unwrap_or("");

    let api = Arc::new(ApiClient::new(initial_url).expect("failed to create API client"));
    let auth = Arc::new(AuthManager::new(api.clone()));
    let sse = Arc::new(SseManager::new(
        api.base_url_handle(),
        api.token_handle(),
    ));

    let ctx = AppContext {
        api: api.clone(),
        auth: auth.clone(),
        settings: Arc::new(RwLock::new(settings.clone())),
        sse: sse.clone(),
        tray_handle: Arc::new(RwLock::new(None)),
    };

    // Build the main status window (hidden by default, shown from tray)
    let window = ui::status::build_status_window(app);

    // Decide startup flow based on number of configured servers.
    if settings.servers.is_empty() {
        // No servers: show login dialog so user can add one.
        show_login(app, ctx.clone(), window.clone());
    } else if let Some(active) = settings.active() {
        // We have an active server -- try restoring saved session.
        let server_url = active.url.clone();
        let ctx2 = ctx.clone();
        let window2 = window.clone();
        let app2 = app.clone();
        gtk4::glib::spawn_future_local(async move {
            match ctx2.auth.load_saved_token(&server_url).await {
                Ok(()) => {
                    tracing::info!("restored saved session for {server_url}");
                    post_login(ctx2, window2).await;
                }
                Err(_) => {
                    show_login(&app2, ctx2, window2);
                }
            }
        });
    } else {
        // Servers exist but none active -- show server picker.
        let ctx2 = ctx.clone();
        let window2 = window.clone();
        let app2 = app.clone();
        show_server_picker(&app2, ctx2, window2);
    }
}

/// Show the server picker dialog that lets the user choose or add a server.
fn show_server_picker(
    app: &adw::Application,
    ctx: AppContext,
    main_window: adw::ApplicationWindow,
) {
    let app2 = app.clone();
    let ctx2 = ctx.clone();
    let main_window2 = main_window.clone();

    ui::servers::show_server_picker(
        &main_window,
        ctx.settings.clone(),
        move |pick| {
            let ctx3 = ctx2.clone();
            let main_window3 = main_window2.clone();
            let app3 = app2.clone();

            match pick {
                Some(idx) => {
                    // User picked an existing server -- switch to it.
                    gtk4::glib::spawn_future_local(async move {
                        do_switch_server(idx, &ctx3, &main_window3, &app3).await;
                    });
                }
                None => {
                    // User wants to add a new server -- show login dialog.
                    show_login(&app3, ctx3, main_window3);
                }
            }
        },
    );
}

fn show_login(app: &adw::Application, ctx: AppContext, main_window: adw::ApplicationWindow) {
    let _app2 = app.clone();
    let main_window_ref = main_window.clone();

    // Rc<RefCell> lets the closure reference the dialog that is created inside
    // show_login_dialog and returned to us.
    let dialog_holder: std::rc::Rc<std::cell::RefCell<Option<adw::Window>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));
    let dialog_for_cb = dialog_holder.clone();
    let ctx2 = ctx.clone();

    let dialog = ui::login::show_login_dialog(
        &main_window_ref,
        move |server_url, username, password| {
            let ctx3 = ctx2.clone();
            let main_window2 = main_window.clone();
            let dialog_ref = dialog_for_cb.borrow().clone();
            gtk4::glib::spawn_future_local(async move {
                // Update API base URL
                ctx3.api.set_base_url(&server_url);

                match ctx3.auth.login(&server_url, &username, &password).await {
                    Ok(()) => {
                        // Ensure the server is in the settings list.
                        let mut settings = ctx3.settings.write().await;

                        let existing_idx = settings
                            .servers
                            .iter()
                            .position(|s| s.url == server_url);

                        if let Some(idx) = existing_idx {
                            settings.set_active(idx);
                        } else {
                            // Derive a display name from the URL.
                            let name = display_name_from_url(&server_url);
                            let idx = settings.add_server(name, server_url);
                            settings.set_active(idx);
                        }

                        let _ = settings.save();
                        drop(settings);

                        // Close the login dialog on success
                        if let Some(ref dlg) = dialog_ref {
                            dlg.close();
                        }

                        post_login(ctx3, main_window2).await;
                    }
                    Err(e) => {
                        tracing::error!("login failed: {e}");
                        // Show error inside the login dialog
                        if let Some(ref dlg) = dialog_ref {
                            ui::login::show_login_error(dlg, &format!("{e}"));
                        }
                    }
                }
            });
        },
    );

    // Store the dialog reference so the callback can access it on future clicks.
    *dialog_holder.borrow_mut() = Some(dialog);
}

async fn post_login(ctx: AppContext, window: adw::ApplicationWindow) {
    // Sync tray server list.
    sync_tray_servers(&ctx).await;

    // Stop any previous SSE session before starting a new one so tasks
    // from earlier calls to post_login (e.g. after a server switch) are
    // cleaned up.
    ctx.sse.stop();

    // Start SSE subscription
    let (sse_tx, mut sse_rx) = tokio::sync::mpsc::unbounded_channel::<sse::SseEvent>();
    ctx.sse.start(sse_tx);

    // Shut down an existing tray before spawning a new one.
    {
        let mut guard = ctx.tray_handle.write().await;
        if let Some(ref old_handle) = *guard {
            old_handle.shutdown();
        }
        *guard = None;
    }

    // Start tray
    let (tray_tx, mut tray_rx) =
        tokio::sync::mpsc::unbounded_channel::<tray::TrayAction>();

    // Spawn tray in background, storing the handle so it is not dropped.
    let tray_tx2 = tray_tx.clone();
    let tray_handle = ctx.tray_handle.clone();
    tokio::spawn(async move {
        match tray::spawn(tray_tx2).await {
            Ok(handle) => {
                *tray_handle.write().await = Some(handle);
            }
            Err(e) => {
                tracing::error!("failed to spawn tray: {e}");
            }
        }
    });

    // After tray spawns, push server list to it.
    {
        let ctx_for_tray = ctx.clone();
        gtk4::glib::spawn_future_local(async move {
            // Give ksni a moment to initialize before sending commands.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            sync_tray_servers(&ctx_for_tray).await;
        });
    }

    // Handle tray actions on the GTK main loop
    {
        let ctx2 = ctx.clone();
        let window2 = window.clone();
        gtk4::glib::spawn_future_local(async move {
            while let Some(action) = tray_rx.recv().await {
                handle_tray_action(action, &ctx2, &window2).await;
            }
        });
    }

    // Handle SSE events on the GTK main loop
    {
        let ctx3 = ctx.clone();
        let window3 = window.clone();
        gtk4::glib::spawn_future_local(async move {
            while let Some(event) = sse_rx.recv().await {
                match event {
                    sse::SseEvent::ConnectionStatus(status) => {
                        tracing::info!("connection status: {status}");

                        // Forward status to tray icon
                        let tray_handle = ctx3.tray_handle.clone();
                        let tray_status = status.clone();
                        tokio::spawn(async move {
                            let guard = tray_handle.read().await;
                            if let Some(ref handle) = *guard {
                                handle.send_command(
                                    tray::TrayCommand::UpdateStatus(tray_status),
                                ).await;
                            }
                        });

                        // Refresh status display
                        let ctx4 = ctx3.clone();
                        let window4 = window3.clone();
                        gtk4::glib::spawn_future_local(async move {
                            if let Ok(status) = ctx4.api.tunnel_status().await {
                                let json = serde_json::to_value(&status).unwrap_or_default();
                                ui::status::update_status(&window4, &json);
                            }
                        });
                    }
                    sse::SseEvent::RoutingChanged => {
                        tracing::info!("routing changed");
                    }
                    sse::SseEvent::ConfigChanged => {
                        tracing::info!("config changed");
                    }
                    sse::SseEvent::Disconnected => {
                        tracing::warn!("SSE disconnected, will reconnect");
                    }
                }
            }
        });
    }

    // Initial status fetch
    let ctx5 = ctx.clone();
    let window5 = window.clone();
    gtk4::glib::spawn_future_local(async move {
        if let Ok(status) = ctx5.api.tunnel_status().await {
            let json = serde_json::to_value(&status).unwrap_or_default();
            ui::status::update_status(&window5, &json);
        }
        if let Ok(profiles) = ctx5.api.list_profiles().await {
            let json: Vec<serde_json::Value> = profiles
                .iter()
                .map(|p| serde_json::to_value(p).unwrap_or_default())
                .collect();
            // Update profile dropdown
            if let Some(dropdown) = window5
                .content()
                .and_then(|c: gtk4::Widget| find_widget_by_name(&c, "profile_dropdown"))
                .and_then(|w: gtk4::Widget| w.downcast::<gtk4::DropDown>().ok())
            {
                ui::status::update_profiles(&dropdown, &json);
            }
        }
    });

    // Auto-connect if configured for the active server.
    let settings = ctx.settings.read().await;
    if let Some(active) = settings.active() {
        if active.auto_connect {
            if let Some(ref profile_id) = active.last_profile_id {
                let api = ctx.api.clone();
                let pid = profile_id.clone();
                gtk4::glib::spawn_future_local(async move {
                    let _ = api.tunnel_connect(&pid).await;
                });
            }
        }
    }
}

/// Switch to a different server by index.
///
/// This stops SSE, updates the API base URL, attempts to restore the session
/// from keyring, and if that fails shows the login dialog.
async fn do_switch_server(
    index: usize,
    ctx: &AppContext,
    window: &adw::ApplicationWindow,
    app: &adw::Application,
) {
    let server_url = {
        let mut settings = ctx.settings.write().await;
        if !settings.set_active(index) {
            tracing::warn!("switch_server: invalid index {index}");
            return;
        }
        let _ = settings.save();
        settings.active().unwrap().url.clone()
    };

    tracing::info!("switching to server {index}: {server_url}");

    // Stop SSE for the old server.
    ctx.sse.stop();

    // Clear current auth tokens from memory (do NOT delete from keyring --
    // we only clear the in-memory state for the old server).
    ctx.api.set_token(None).await;

    // Point API at the new server.
    ctx.api.set_base_url(&server_url);

    // Sync tray.
    sync_tray_servers(ctx).await;

    // Try to restore the saved session.
    match ctx.auth.load_saved_token(&server_url).await {
        Ok(()) => {
            tracing::info!("restored session for {server_url}");
            post_login(ctx.clone(), window.clone()).await;
        }
        Err(_) => {
            tracing::info!("no saved session for {server_url}, showing login");
            show_login(app, ctx.clone(), window.clone());
        }
    }
}

async fn handle_tray_action(
    action: tray::TrayAction,
    ctx: &AppContext,
    window: &adw::ApplicationWindow,
) {
    match action {
        tray::TrayAction::Connect => {
            let api = ctx.api.clone();
            let settings = ctx.settings.clone();
            gtk4::glib::spawn_future_local(async move {
                let s = settings.read().await;
                if let Some(active) = s.active() {
                    if let Some(ref pid) = active.last_profile_id {
                        let _ = api.tunnel_connect(pid).await;
                    }
                }
            });
        }
        tray::TrayAction::Disconnect => {
            let api = ctx.api.clone();
            gtk4::glib::spawn_future_local(async move {
                let _ = api.tunnel_disconnect().await;
            });
        }
        tray::TrayAction::ShowProfiles => {
            let _win = ui::profiles::build_profiles_window(window);
        }
        tray::TrayAction::ShowRouting => {
            let _win = ui::routing::build_routing_window(window);
        }
        tray::TrayAction::ShowLogs => {
            let _win = ui::logs::build_logs_window(window);
        }
        tray::TrayAction::ShowUsers => {
            let _win = ui::users::build_users_window(window);
        }
        tray::TrayAction::ShowAbout => {
            ui::about::show_about_dialog(window);
        }
        tray::TrayAction::SwitchServer(index) => {
            let ctx2 = ctx.clone();
            let window2 = window.clone();
            let app = window
                .application()
                .and_then(|a| a.downcast::<adw::Application>().ok());
            if let Some(app) = app {
                gtk4::glib::spawn_future_local(async move {
                    do_switch_server(index, &ctx2, &window2, &app).await;
                });
            }
        }
        tray::TrayAction::ManageServers => {
            show_manage_servers(ctx, window);
        }
        tray::TrayAction::Quit => {
            window.application().map(|a| a.quit());
        }
    }
}

/// Open the "Manage Servers" window.
fn show_manage_servers(ctx: &AppContext, window: &adw::ApplicationWindow) {
    let ctx2 = ctx.clone();
    let ctx3 = ctx.clone();
    let ctx4 = ctx.clone();
    let window2 = window.clone();
    let window4 = window.clone();

    let _dialog = ui::servers::build_servers_window(
        window,
        ctx.settings.clone(),
        // on_add
        move |name, url| {
            let ctx = ctx2.clone();
            let window = window2.clone();
            gtk4::glib::spawn_future_local(async move {
                {
                    let mut settings = ctx.settings.write().await;
                    let idx = settings.add_server(name.clone(), url);
                    settings.set_active(idx);
                    let _ = settings.save();
                }
                sync_tray_servers(&ctx).await;

                // Switch to the newly added server.
                let app = window
                    .application()
                    .and_then(|a| a.downcast::<adw::Application>().ok());
                if let Some(app) = app {
                    let settings = ctx.settings.read().await;
                    let idx = settings.active_server.unwrap_or(0);
                    drop(settings);
                    do_switch_server(idx, &ctx, &window, &app).await;
                }
            });
        },
        // on_remove
        move |index| {
            let ctx = ctx3.clone();
            gtk4::glib::spawn_future_local(async move {
                {
                    let mut settings = ctx.settings.write().await;
                    settings.remove_server(index);
                    let _ = settings.save();
                }
                sync_tray_servers(&ctx).await;
            });
        },
        // on_switch
        move |index| {
            let ctx = ctx4.clone();
            let window = window4.clone();
            gtk4::glib::spawn_future_local(async move {
                let app = window
                    .application()
                    .and_then(|a| a.downcast::<adw::Application>().ok());
                if let Some(app) = app {
                    do_switch_server(index, &ctx, &window, &app).await;
                }
            });
        },
    );
}

/// Push the current server list to the tray icon.
async fn sync_tray_servers(ctx: &AppContext) {
    let (entries, active) = {
        let settings = ctx.settings.read().await;
        let entries: Vec<tray::ServerEntry> = settings
            .servers
            .iter()
            .map(|s| tray::ServerEntry {
                name: s.name.clone(),
            })
            .collect();
        (entries, settings.active_server)
    };

    let tray_handle = ctx.tray_handle.clone();
    tokio::spawn(async move {
        let guard = tray_handle.read().await;
        if let Some(ref handle) = *guard {
            handle
                .send_command(tray::TrayCommand::UpdateServers {
                    servers: entries,
                    active,
                })
                .await;
        }
    });
}

/// Derive a short display name from a URL, e.g. "172.19.0.2" from
/// "https://172.19.0.2:8443".
fn display_name_from_url(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or("Server")
        .to_string()
}

/// Recursively find a widget by its CSS name.
fn find_widget_by_name(root: &impl IsA<gtk4::Widget>, name: &str) -> Option<gtk4::Widget> {
    let widget = root.as_ref();
    if widget.widget_name() == name {
        return Some(widget.clone());
    }
    let mut child = widget.first_child();
    while let Some(c) = child {
        if let Some(found) = find_widget_by_name(&c, name) {
            return Some(found);
        }
        child = c.next_sibling();
    }
    None
}
