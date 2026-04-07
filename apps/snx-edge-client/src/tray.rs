use std::{str::FromStr, sync::Arc};

use anyhow::anyhow;
use ksni::{
    Handle, Icon, MenuItem, TrayMethods,
    menu::StandardItem,
};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::{
    assets,
    theme::{SystemColorTheme, system_color_theme},
    client_settings::ClientSettings,
};

#[derive(Debug, Clone, PartialEq)]
pub enum TrayEvent {
    Connect(String), // profile_id
    Disconnect,
    Settings,
    Status,
    AddServer,
    Exit,
    About,
    Routing,
    Users,
    Servers,
    Logs,
}

impl TrayEvent {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            TrayEvent::Connect(_) => "connect",
            TrayEvent::Disconnect => "disconnect",
            TrayEvent::Settings => "settings",
            TrayEvent::Status => "status",
            TrayEvent::AddServer => "add_server",
            TrayEvent::Exit => "exit",
            TrayEvent::About => "about",
            TrayEvent::Routing => "routing",
            TrayEvent::Users => "users",
            TrayEvent::Servers => "servers",
            TrayEvent::Logs => "logs",
        }
    }
}

impl FromStr for TrayEvent {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "connect" => Ok(TrayEvent::Connect(String::new())),
            "disconnect" => Ok(TrayEvent::Disconnect),
            "settings" => Ok(TrayEvent::Settings),
            "status" => Ok(TrayEvent::Status),
            "exit" => Ok(TrayEvent::Exit),
            "about" => Ok(TrayEvent::About),
            "routing" => Ok(TrayEvent::Routing),
            "users" => Ok(TrayEvent::Users),
            "servers" => Ok(TrayEvent::Servers),
            "logs" => Ok(TrayEvent::Logs),
            _ => Err(anyhow!("Unknown event: {}", s)),
        }
    }
}

/// Status representation for the tray, parsed from server JSON.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Connected { info: String },
    Disconnected,
    Connecting,
    Error(String),
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Connected { info } => write!(f, "Connected: {}", info),
            ConnectionState::Disconnected => write!(f, "Disconnected"),
            ConnectionState::Connecting => write!(f, "Connecting..."),
            ConnectionState::Error(e) => write!(f, "Error: {}", e),
        }
    }
}

impl ConnectionState {
    /// Parse from a serde_json::Value returned by the tunnel status API.
    pub fn from_json(value: &serde_json::Value) -> Self {
        let state = value
            .get("state")
            .and_then(|v| v.as_str())
            .unwrap_or("disconnected");
        match state {
            "connected" => {
                let server = value.get("server").and_then(|v| v.as_str()).unwrap_or("unknown");
                ConnectionState::Connected {
                    info: server.to_string(),
                }
            }
            "connecting" => ConnectionState::Connecting,
            "disconnected" => ConnectionState::Disconnected,
            _ => ConnectionState::Error(format!("Unknown state: {}", state)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TrayCommand {
    Update(Option<Arc<ConnectionState>>),
    Exit,
}

enum PixmapOrName {
    Pixmap(Icon),
    Name(&'static str),
}

pub struct AppTray {
    command_sender: Sender<TrayCommand>,
    command_receiver: Option<Receiver<TrayCommand>>,
    status: Arc<ConnectionState>,
    tray_icon: Option<Handle<KsniTray>>,
}

impl AppTray {
    pub async fn new(event_sender: Sender<TrayEvent>, no_tray: bool) -> anyhow::Result<Self> {
        let (tx, rx) = tokio::sync::mpsc::channel(16);

        let handle = if !no_tray {
            let tray_icon = KsniTray::new(event_sender);
            Some(tray_icon.spawn().await?)
        } else {
            None
        };

        let app_tray = AppTray {
            command_sender: tx,
            command_receiver: Some(rx),
            status: Arc::new(ConnectionState::Disconnected),
            tray_icon: handle,
        };

        app_tray.update().await;

        Ok(app_tray)
    }

    pub fn sender(&self) -> Sender<TrayCommand> {
        self.command_sender.clone()
    }

    fn status_label(&self) -> String {
        self.status.to_string()
    }

    fn icon_theme(&self) -> &'static assets::IconTheme {
        let settings = ClientSettings::load();
        let system_theme = match settings.icon_theme.as_str() {
            "dark" => SystemColorTheme::Light,
            "light" => SystemColorTheme::Dark,
            _ => system_color_theme().ok().unwrap_or_default(),
        };

        if system_theme.is_dark() {
            &assets::DARK_THEME
        } else {
            &assets::LIGHT_THEME
        }
    }

    fn icon(&self) -> Icon {
        let theme = self.icon_theme();

        let data = match &*self.status {
            ConnectionState::Connected { .. } => theme.connected.clone(),
            ConnectionState::Disconnected => theme.disconnected.clone(),
            ConnectionState::Connecting => theme.acquiring.clone(),
            ConnectionState::Error(_) => theme.error.clone(),
        };

        Icon {
            width: 256,
            height: 256,
            data,
        }
    }

    fn icon_name(&self) -> &'static str {
        match &*self.status {
            ConnectionState::Connected { .. } => "network-vpn-symbolic",
            ConnectionState::Disconnected => "network-vpn-disconnected-symbolic",
            ConnectionState::Connecting => "network-vpn-acquiring-symbolic",
            ConnectionState::Error(_) => "network-vpn-disabled-symbolic",
        }
    }

    async fn update(&self) {
        let status_label = self.status_label();

        let icon = if self.pixmap_icons_supported() {
            PixmapOrName::Pixmap(self.icon())
        } else {
            PixmapOrName::Name(self.icon_name())
        };

        let connect_enabled = matches!(&*self.status, ConnectionState::Disconnected);
        let disconnect_enabled = !matches!(&*self.status, ConnectionState::Disconnected);

        if let Some(ref tray_icon) = self.tray_icon {
            tray_icon
                .update(|tray| {
                    tray.status_label = status_label;
                    tray.icon = icon;
                    tray.connect_enabled = connect_enabled;
                    tray.disconnect_enabled = disconnect_enabled;
                })
                .await;
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut rx = self.command_receiver.take().unwrap();

        while let Some(command) = rx.recv().await {
            match command {
                TrayCommand::Update(status) => {
                    if let Some(status) = status {
                        self.status = status;
                    }
                    self.update().await;
                }
                TrayCommand::Exit => {
                    break;
                }
            }
        }

        Ok(())
    }

    fn pixmap_icons_supported(&self) -> bool {
        std::env::var("XDG_CURRENT_DESKTOP")
            .map(|s| s.to_lowercase())
            .is_ok_and(|s| s.contains("gnome") || s.contains("kde"))
    }
}

struct KsniTray {
    status_label: String,
    connect_enabled: bool,
    disconnect_enabled: bool,
    icon: PixmapOrName,
    event_sender: Sender<TrayEvent>,
}

impl KsniTray {
    fn new(event_sender: Sender<TrayEvent>) -> Self {
        Self {
            status_label: String::new(),
            connect_enabled: false,
            disconnect_enabled: false,
            icon: PixmapOrName::Name(""),
            event_sender,
        }
    }

    fn send_tray_event(&self, event: TrayEvent) {
        let sender = self.event_sender.clone();
        tokio::spawn(async move { sender.send(event).await });
    }
}

impl ksni::Tray for KsniTray {
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        "SNX-Edge".to_string()
    }

    fn icon_name(&self) -> String {
        if let PixmapOrName::Name(name) = &self.icon {
            name.to_string()
        } else {
            String::new()
        }
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        if let PixmapOrName::Pixmap(icon) = &self.icon {
            vec![icon.clone()]
        } else {
            vec![]
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        // TODO: When profiles are loaded from the server, populate Connect submenu.
        // For now, simple connect with empty profile ID (server picks default).
        let connect_item = MenuItem::Standard(StandardItem {
            label: "Connect".to_string(),
            enabled: self.connect_enabled,
            activate: Box::new(|tray: &mut KsniTray| {
                tray.send_tray_event(TrayEvent::Connect(String::new()))
            }),
            ..Default::default()
        });

        vec![
            MenuItem::Standard(StandardItem {
                label: self.status_label.clone(),
                enabled: false,
                ..Default::default()
            }),
            MenuItem::Separator,
            connect_item,
            MenuItem::Standard(StandardItem {
                label: "Disconnect".to_string(),
                enabled: self.disconnect_enabled,
                activate: Box::new(|tray: &mut KsniTray| tray.send_tray_event(TrayEvent::Disconnect)),
                ..Default::default()
            }),
            MenuItem::Standard(StandardItem {
                label: "Status".to_string(),
                activate: Box::new(|tray: &mut KsniTray| tray.send_tray_event(TrayEvent::Status)),
                ..Default::default()
            }),
            MenuItem::Standard(StandardItem {
                label: "Routing".to_string(),
                activate: Box::new(|tray: &mut KsniTray| tray.send_tray_event(TrayEvent::Routing)),
                ..Default::default()
            }),
            MenuItem::Standard(StandardItem {
                label: "Logs".to_string(),
                activate: Box::new(|tray: &mut KsniTray| tray.send_tray_event(TrayEvent::Logs)),
                ..Default::default()
            }),
            MenuItem::Standard(StandardItem {
                label: "Settings".to_string(),
                activate: Box::new(|tray: &mut KsniTray| tray.send_tray_event(TrayEvent::Settings)),
                ..Default::default()
            }),
            MenuItem::Separator,
            MenuItem::Standard(StandardItem {
                label: "Servers".to_string(),
                activate: Box::new(|tray: &mut KsniTray| tray.send_tray_event(TrayEvent::Servers)),
                ..Default::default()
            }),
            // NOTE: Ideally "Users" should only show for admin users, but KSNI
            // tray menus are static and don't have access to async role checks.
            // The role check is enforced in main.rs when the event is handled.
            MenuItem::Standard(StandardItem {
                label: "Users".to_string(),
                activate: Box::new(|tray: &mut KsniTray| tray.send_tray_event(TrayEvent::Users)),
                ..Default::default()
            }),
            MenuItem::Standard(StandardItem {
                label: "About".to_string(),
                activate: Box::new(|tray: &mut KsniTray| tray.send_tray_event(TrayEvent::About)),
                ..Default::default()
            }),
            MenuItem::Standard(StandardItem {
                label: "Exit".to_string(),
                activate: Box::new(|tray: &mut KsniTray| tray.send_tray_event(TrayEvent::Exit)),
                ..Default::default()
            }),
        ]
    }
}
