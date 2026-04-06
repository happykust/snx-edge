use ksni::menu::{MenuItem, StandardItem, SubMenu};
use ksni::{Handle, Tray, TrayMethods};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Commands sent *to* the tray to update its visual state.
#[derive(Debug, Clone)]
pub enum TrayCommand {
    /// Update VPN connection status.
    /// Recognized values: "connected", "disconnected", "connecting", "error".
    UpdateStatus(String),
    /// Set the current user's role (e.g. `Some("admin")`).
    /// Controls visibility of admin-only menu entries.
    SetRole(Option<String>),
    /// Update the list of configured servers and the active index.
    UpdateServers {
        servers: Vec<ServerEntry>,
        active: Option<usize>,
    },
}

/// Lightweight description of a server for the tray submenu.
#[derive(Debug, Clone)]
pub struct ServerEntry {
    pub name: String,
}

/// Actions emitted *by* the tray when the user clicks a menu item.
/// These are forwarded to the GTK main loop via `glib::Sender`.
#[derive(Debug, Clone)]
pub enum TrayAction {
    Connect,
    Disconnect,
    ShowProfiles,
    ShowRouting,
    ShowLogs,
    ShowUsers,
    ShowAbout,
    SwitchServer(usize),
    ManageServers,
    Quit,
}

// ---------------------------------------------------------------------------
// Tray state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrayState {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

impl TrayState {
    fn from_status(s: &str) -> Self {
        match s {
            "connected" => Self::Connected,
            "connecting" => Self::Connecting,
            "error" => Self::Error,
            _ => Self::Disconnected,
        }
    }

    /// FreeDesktop icon theme name for the current state.
    fn icon_name(self) -> &'static str {
        match self {
            Self::Disconnected => "network-vpn-disconnected",
            Self::Connecting => "network-vpn-acquiring",
            Self::Connected => "network-vpn",
            Self::Error => "network-vpn-error",
        }
    }
}

// ---------------------------------------------------------------------------
// ksni::Tray implementation
// ---------------------------------------------------------------------------

struct SnxTray {
    state: TrayState,
    role: Option<String>,
    servers: Vec<ServerEntry>,
    active_server: Option<usize>,
    /// Channel back to the GTK main loop.
    action_tx: UnboundedSender<TrayAction>,
}

impl Tray for SnxTray {
    fn id(&self) -> String {
        "snx-edge-client".into()
    }

    fn title(&self) -> String {
        "SNX Edge VPN".into()
    }

    fn icon_name(&self) -> String {
        self.state.icon_name().into()
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let is_connected = self.state == TrayState::Connected;
        let is_admin = self
            .role
            .as_deref()
            .is_some_and(|r| r.eq_ignore_ascii_case("admin"));

        let mut items: Vec<MenuItem<Self>> = Vec::new();

        // -- Servers submenu --
        if !self.servers.is_empty() {
            let active_idx = self.active_server;
            let mut server_items: Vec<MenuItem<Self>> = Vec::new();

            for (i, server) in self.servers.iter().enumerate() {
                let is_active = active_idx == Some(i);
                let label = if is_active {
                    format!("\u{2713} {}", server.name)
                } else {
                    format!("  {}", server.name)
                };
                let idx = i;
                server_items.push(
                    StandardItem {
                        label,
                        enabled: !is_active,
                        activate: Box::new(move |this: &mut Self| {
                            let _ = this.action_tx.send(TrayAction::SwitchServer(idx));
                        }),
                        ..Default::default()
                    }
                    .into(),
                );
            }

            server_items.push(MenuItem::Separator);
            server_items.push(
                StandardItem {
                    label: "Manage Servers...".into(),
                    activate: Box::new(|this: &mut Self| {
                        let _ = this.action_tx.send(TrayAction::ManageServers);
                    }),
                    ..Default::default()
                }
                .into(),
            );

            items.push(
                SubMenu {
                    label: "Servers".into(),
                    submenu: server_items,
                    ..Default::default()
                }
                .into(),
            );

            items.push(MenuItem::Separator);
        }

        // -- Connect / Disconnect --
        items.push(
            StandardItem {
                label: "Connect".into(),
                enabled: !is_connected && self.state != TrayState::Connecting,
                activate: Box::new(|this: &mut Self| {
                    let _ = this.action_tx.send(TrayAction::Connect);
                }),
                ..Default::default()
            }
            .into(),
        );

        items.push(
            StandardItem {
                label: "Disconnect".into(),
                enabled: is_connected,
                activate: Box::new(|this: &mut Self| {
                    let _ = this.action_tx.send(TrayAction::Disconnect);
                }),
                ..Default::default()
            }
            .into(),
        );

        // -- Separator --
        items.push(MenuItem::Separator);

        // -- Profiles / Routing / Logs --
        items.push(
            StandardItem {
                label: "Profiles...".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.action_tx.send(TrayAction::ShowProfiles);
                }),
                ..Default::default()
            }
            .into(),
        );

        items.push(
            StandardItem {
                label: "Routing...".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.action_tx.send(TrayAction::ShowRouting);
                }),
                ..Default::default()
            }
            .into(),
        );

        items.push(
            StandardItem {
                label: "Logs...".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.action_tx.send(TrayAction::ShowLogs);
                }),
                ..Default::default()
            }
            .into(),
        );

        // -- Admin section (only if role == "admin") --
        if is_admin {
            items.push(MenuItem::Separator);

            items.push(
                StandardItem {
                    label: "Users...".into(),
                    activate: Box::new(|this: &mut Self| {
                        let _ = this.action_tx.send(TrayAction::ShowUsers);
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }

        // -- Bottom section --
        items.push(MenuItem::Separator);

        items.push(
            StandardItem {
                label: "About".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.action_tx.send(TrayAction::ShowAbout);
                }),
                ..Default::default()
            }
            .into(),
        );

        items.push(
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.action_tx.send(TrayAction::Quit);
                }),
                ..Default::default()
            }
            .into(),
        );

        items
    }
}

// ---------------------------------------------------------------------------
// TrayHandle -- public wrapper
// ---------------------------------------------------------------------------

/// Wrapper around the running ksni tray.
///
/// Use [`spawn`] to create it.  Then call [`send_command`] to update the
/// tray state, and receive [`TrayAction`]s from the `glib::Sender` passed
/// at creation time.
pub struct TrayHandle {
    handle: Handle<SnxTray>,
}

impl TrayHandle {
    /// Push a [`TrayCommand`] to the tray, updating its visual state.
    /// Returns `false` if the tray has already shut down.
    pub async fn send_command(&self, cmd: TrayCommand) -> bool {
        match cmd {
            TrayCommand::UpdateStatus(status) => {
                let new_state = TrayState::from_status(&status);
                self.handle
                    .update(move |tray| {
                        tray.state = new_state;
                    })
                    .await
                    .is_some()
            }
            TrayCommand::SetRole(role) => {
                self.handle
                    .update(move |tray| {
                        tray.role = role;
                    })
                    .await
                    .is_some()
            }
            TrayCommand::UpdateServers { servers, active } => {
                self.handle
                    .update(move |tray| {
                        tray.servers = servers;
                        tray.active_server = active;
                    })
                    .await
                    .is_some()
            }
        }
    }

    /// Shut down the tray icon.
    pub fn shutdown(&self) {
        self.handle.shutdown();
    }

    /// Check if the tray service has already stopped.
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }
}

// ---------------------------------------------------------------------------
// Spawn helper
// ---------------------------------------------------------------------------

/// Spawn the system tray.
///
/// * `action_tx` - an `UnboundedSender<TrayAction>` whose receiver lives on
///   the GTK main loop side (e.g. via `glib::spawn_future_local` or a channel
///   bridge).
///
/// Returns a [`TrayHandle`] that can be used to push [`TrayCommand`]s to
/// the tray from any async context.
///
/// This function is `async` because ksni 0.3 spawns the tray on the tokio
/// runtime.
pub async fn spawn(action_tx: UnboundedSender<TrayAction>) -> Result<TrayHandle, ksni::Error> {
    let tray = SnxTray {
        state: TrayState::Disconnected,
        role: None,
        servers: Vec::new(),
        active_server: None,
        action_tx,
    };

    info!("Starting system tray");

    let handle = tray.spawn().await?;

    debug!("System tray spawned successfully");

    Ok(TrayHandle { handle })
}
