use std::sync::Arc;

use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use snxcore::model::params::{CertType, TransportType, TunnelType};
use snxcore::model::SessionState;
use snxcore::tunnel::{
    CheckPointTunnelConnectorFactory, TunnelConnector, TunnelConnectorFactory, TunnelEvent,
};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};

use crate::state::ServerEvent;

/// VPN connection parameters — sent by the client with each connect request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VpnConfig {
    #[serde(default)]
    pub server: String,
    #[serde(default = "default_login_type")]
    pub login_type: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_cert_type")]
    pub cert_type: String,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub cert_password: Option<String>,
    #[serde(default)]
    pub no_dns: bool,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub ignored_dns_servers: Vec<String>,
    #[serde(default)]
    pub search_domains: Vec<String>,
    #[serde(default)]
    pub ignored_search_domains: Vec<String>,
    #[serde(default)]
    pub search_domains_as_routes: bool,
    #[serde(default)]
    pub no_routing: bool,
    #[serde(default)]
    pub default_route: bool,
    #[serde(default)]
    pub add_routes: Vec<String>,
    #[serde(default)]
    pub ignored_routes: Vec<String>,
    #[serde(default)]
    pub no_ipv6: bool,
    #[serde(default)]
    pub ca_cert: Vec<String>,
    #[serde(default)]
    pub no_cert_check: bool,
    #[serde(default = "default_password_factor")]
    pub password_factor: u32,
    #[serde(default = "default_ike_lifetime")]
    pub ike_lifetime: u32,
    #[serde(default)]
    pub ike_persist: bool,
    #[serde(default)]
    pub no_keepalive: bool,
    #[serde(default)]
    pub port_knock: bool,
    #[serde(default)]
    pub ip_lease_duration: Option<u32>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default = "default_transport_type")]
    pub transport_type: String,
}

fn default_login_type() -> String { "password".to_string() }
fn default_cert_type() -> String { "pkcs12".to_string() }
fn default_password_factor() -> u32 { 1 }
fn default_ike_lifetime() -> u32 { 28800 }
fn default_mtu() -> u16 { 1350 }
fn default_transport_type() -> String { "auto".to_string() }

// === API response types (our own, serializable) ===

/// VPN connection status returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(tag = "state")]
pub enum ConnectionStatus {
    #[default]
    Disconnected,
    Connecting,
    Connected(ConnectionInfo),
    Mfa(MfaChallenge),
    Error { message: String },
}

/// Information about an active VPN connection.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ConnectionInfo {
    pub since: Option<DateTime<Utc>>,
    pub server_name: String,
    pub username: String,
    pub login_type: String,
    pub tunnel_type: String,
    pub transport_type: String,
    pub ip_address: String,
    pub dns_servers: Vec<String>,
    pub search_domains: Vec<String>,
    pub interface_name: String,
    pub mtu: u16,
}

/// MFA challenge requiring user input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MfaChallenge {
    pub mfa_type: String,
    pub prompt: String,
}

/// Route received from the VPN server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnRoute {
    pub destination: String,
    pub gateway: Option<String>,
    pub interface: String,
}

/// Tunnel status with traffic statistics.
#[derive(Debug, Clone, Serialize)]
pub struct TunnelStatus {
    pub connection: ConnectionStatus,
    pub uptime_seconds: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

// === Conversion from snxcore types ===

fn map_connection_info(info: &snxcore::model::ConnectionInfo) -> ConnectionInfo {
    ConnectionInfo {
        since: info.since.map(|dt| dt.to_utc()),
        server_name: info.server_name.clone(),
        username: info.username.clone(),
        login_type: info.login_type.clone(),
        tunnel_type: format!("{:?}", info.tunnel_type).to_lowercase(),
        transport_type: format!("{:?}", info.transport_type).to_lowercase(),
        ip_address: info.ip_address.to_string(),
        dns_servers: info.dns_servers.iter().map(|d| d.to_string()).collect(),
        search_domains: info
            .search_domains
            .iter()
            .map(|d| d.to_string())
            .collect(),
        interface_name: info.interface_name.clone(),
        mtu: 0,
    }
}

/// Build snxcore TunnelParams from our VpnConfig.
pub fn build_tunnel_params(vpn: &VpnConfig) -> snxcore::model::params::TunnelParams {
    let mut params = snxcore::model::params::TunnelParams::default();

    params.server_name = vpn.server.clone();
    params.user_name = vpn.username.clone();

    if let Some(ref pw) = vpn.password {
        params.password = SecretString::new(pw.clone().into_boxed_str());
    }

    params.login_type = vpn.login_type.clone();
    params.password_factor = vpn.password_factor as usize;

    params.transport_type = match vpn.transport_type.as_str() {
        "udp" => TransportType::Udp,
        "tcpt" => TransportType::Tcpt,
        _ => TransportType::AutoDetect,
    };
    params.tunnel_type = TunnelType::Ipsec;

    params.cert_type = match vpn.cert_type.as_str() {
        "pkcs12" => CertType::Pkcs12,
        "pkcs8" => CertType::Pkcs8,
        "pkcs11" => CertType::Pkcs11,
        _ => CertType::None,
    };
    if let Some(ref path) = vpn.cert_path {
        params.cert_path = Some(path.into());
    }
    if let Some(ref pw) = vpn.cert_password {
        params.cert_password = Some(SecretString::new(pw.clone().into_boxed_str()));
    }

    params.no_dns = vpn.no_dns;
    params.dns_servers = vpn.dns_servers.iter().filter_map(|s| s.parse().ok()).collect();
    params.ignore_dns_servers = vpn.ignored_dns_servers.iter().filter_map(|s| s.parse().ok()).collect();
    params.search_domains = vpn.search_domains.clone();
    params.ignore_search_domains = vpn.ignored_search_domains.clone();
    params.set_routing_domains = vpn.search_domains_as_routes;

    params.no_routing = vpn.no_routing;
    params.default_route = vpn.default_route;
    params.add_routes = vpn.add_routes.iter().filter_map(|s| s.parse().ok()).collect();
    params.ignore_routes = vpn.ignored_routes.iter().filter_map(|s| s.parse().ok()).collect();
    params.disable_ipv6 = vpn.no_ipv6;

    params.ca_cert = vpn.ca_cert.iter().map(|s| s.into()).collect();
    params.ignore_server_cert = vpn.no_cert_check;

    params.ike_lifetime = std::time::Duration::from_secs(vpn.ike_lifetime as u64);
    params.ike_persist = vpn.ike_persist;
    params.no_keepalive = vpn.no_keepalive;
    params.port_knock = vpn.port_knock;
    params.mtu = vpn.mtu;

    params.log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

    params
}

// === Tunnel Manager ===

/// Manages VPN tunnel lifecycle using snxcore.
pub struct TunnelManager {
    factory: CheckPointTunnelConnectorFactory,
    connector: Arc<Mutex<Option<Box<dyn TunnelConnector + Send + Sync>>>>,
    session: Arc<Mutex<Option<Arc<snxcore::model::VpnSession>>>>,
    status: Arc<RwLock<ConnectionStatus>>,
    event_tx: broadcast::Sender<ServerEvent>,
    tx_bytes: Arc<Mutex<u64>>,
    rx_bytes: Arc<Mutex<u64>>,
    /// Server name from the last connect attempt (used by GET /server/info
    /// when the tunnel is disconnected).
    last_server: Arc<RwLock<Option<String>>>,
}

impl TunnelManager {
    pub fn new(event_tx: broadcast::Sender<ServerEvent>) -> Self {
        Self {
            factory: CheckPointTunnelConnectorFactory,
            connector: Arc::new(Mutex::new(None)),
            session: Arc::new(Mutex::new(None)),
            status: Arc::new(RwLock::new(ConnectionStatus::Disconnected)),
            event_tx,
            tx_bytes: Arc::new(Mutex::new(0)),
            rx_bytes: Arc::new(Mutex::new(0)),
            last_server: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn status(&self) -> TunnelStatus {
        let connection = self.status.read().await.clone();
        let uptime_seconds = if let ConnectionStatus::Connected(ref info) = connection {
            info.since
                .map(|s| (Utc::now() - s).num_seconds().max(0) as u64)
        } else {
            None
        };

        TunnelStatus {
            connection,
            uptime_seconds,
            tx_bytes: *self.tx_bytes.lock().await,
            rx_bytes: *self.rx_bytes.lock().await,
        }
    }

    pub async fn connect(&self, vpn_config: &VpnConfig) -> anyhow::Result<ConnectionStatus> {
        {
            let mut status = self.status.write().await;
            if matches!(
                *status,
                ConnectionStatus::Connected(_) | ConnectionStatus::Connecting
            ) {
                anyhow::bail!("already connected or connecting");
            }
            *status = ConnectionStatus::Connecting;
        }

        // Remember the server for GET /server/info when disconnected.
        if !vpn_config.server.is_empty() {
            *self.last_server.write().await = Some(vpn_config.server.clone());
        }

        let params = Arc::new(build_tunnel_params(vpn_config));

        let mut connector = match self.factory.create(params.clone()).await {
            Ok(c) => c,
            Err(e) => {
                self.set_status(ConnectionStatus::Error {
                    message: e.to_string(),
                })
                .await;
                return Err(e);
            }
        };

        let session = if params.ike_persist {
            match connector.restore_session().await {
                Ok(s) => s,
                Err(_) => connector.authenticate().await?,
            }
        } else {
            connector.authenticate().await?
        };

        *self.session.lock().await = Some(session.clone());
        *self.connector.lock().await = Some(connector);

        if let SessionState::PendingChallenge(ref challenge) = session.state {
            let mfa = ConnectionStatus::Mfa(MfaChallenge {
                mfa_type: format!("{:?}", challenge.mfa_type),
                prompt: challenge.prompt.clone(),
            });
            self.set_status(mfa.clone()).await;
            return Ok(mfa);
        }

        self.start_tunnel(session).await
    }

    async fn start_tunnel(
        &self,
        session: Arc<snxcore::model::VpnSession>,
    ) -> anyhow::Result<ConnectionStatus> {
        // Command channel: tunnel receives commands (terminate, rekey)
        let (cmd_tx, cmd_rx) = mpsc::channel::<snxcore::tunnel::TunnelCommand>(16);
        // Event channel: tunnel sends events (connected, disconnected)
        let (evt_tx, mut evt_rx) = mpsc::channel::<TunnelEvent>(16);

        *self.tx_bytes.lock().await = 0;
        *self.rx_bytes.lock().await = 0;

        let tunnel = {
            let mut guard = self.connector.lock().await;
            let connector = guard.as_mut().ok_or_else(|| anyhow::anyhow!("no connector"))?;
            connector.create_tunnel(session, cmd_tx).await?
        };

        // Spawn tunnel task
        tokio::spawn(async move {
            if let Err(e) = tunnel.run(cmd_rx, evt_tx).await {
                tracing::warn!("tunnel exited: {e}");
            }
        });

        // Spawn event handler
        let status = self.status.clone();
        let connector = self.connector.clone();
        let broadcast_tx = self.event_tx.clone();
        let session_ref = self.session.clone();

        tokio::spawn(async move {
            while let Some(event) = evt_rx.recv().await {
                // Forward to connector for internal handling (rekey etc.)
                {
                    let mut guard = connector.lock().await;
                    if let Some(c) = guard.as_mut() {
                        if let Err(e) = c.handle_tunnel_event(event.clone()).await {
                            tracing::warn!("tunnel event handler error: {e}");
                            *status.write().await = ConnectionStatus::Error {
                                message: e.to_string(),
                            };
                            let _ = broadcast_tx.send(ServerEvent::ConnectionStatus {
                                status: "error".to_string(),
                            });
                            break;
                        }
                    }
                }

                match event {
                    TunnelEvent::Connected(info) => {
                        *status.write().await =
                            ConnectionStatus::Connected(map_connection_info(&info));
                        let _ = broadcast_tx.send(ServerEvent::ConnectionStatus {
                            status: "connected".to_string(),
                        });
                    }
                    TunnelEvent::Disconnected => {
                        *status.write().await = ConnectionStatus::Disconnected;
                        *connector.lock().await = None;
                        *session_ref.lock().await = None;
                        let _ = broadcast_tx.send(ServerEvent::ConnectionStatus {
                            status: "disconnected".to_string(),
                        });
                        break;
                    }
                    TunnelEvent::Rekeyed(addr) => {
                        let mut guard = status.write().await;
                        if let ConnectionStatus::Connected(ref mut info) = *guard {
                            info.ip_address = addr.to_string();
                        }
                    }
                    _ => {}
                }
            }
        });

        self.set_status(ConnectionStatus::Connecting).await;
        Ok(ConnectionStatus::Connecting)
    }

    pub async fn disconnect(&self) -> anyhow::Result<()> {
        let current = self.status.read().await.clone();
        if matches!(current, ConnectionStatus::Disconnected) {
            anyhow::bail!("not connected");
        }

        if let Some(connector) = self.connector.lock().await.as_mut() {
            let _ = connector.delete_session().await;
            let _ = connector.terminate_tunnel(true).await;
        }

        *self.connector.lock().await = None;
        *self.session.lock().await = None;
        self.set_status(ConnectionStatus::Disconnected).await;

        Ok(())
    }

    pub async fn reconnect(&self, vpn_config: &VpnConfig) -> anyhow::Result<ConnectionStatus> {
        let _ = self.disconnect().await;
        self.connect(vpn_config).await
    }

    pub async fn challenge_code(&self, code: &str) -> anyhow::Result<ConnectionStatus> {
        let session = self
            .session
            .lock()
            .await
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no active session"))?;

        if !matches!(session.state, SessionState::PendingChallenge(_)) {
            anyhow::bail!("no pending MFA challenge");
        }

        let new_session = {
            let mut guard = self.connector.lock().await;
            let connector = guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("no connector"))?;
            connector.challenge_code(session, code).await?
        };

        *self.session.lock().await = Some(new_session.clone());

        if let SessionState::PendingChallenge(ref challenge) = new_session.state {
            let mfa = ConnectionStatus::Mfa(MfaChallenge {
                mfa_type: format!("{:?}", challenge.mfa_type),
                prompt: challenge.prompt.clone(),
            });
            self.set_status(mfa.clone()).await;
            Ok(mfa)
        } else {
            self.start_tunnel(new_session).await
        }
    }

    /// Query server info via snxcore CCC protocol.
    pub async fn server_info(
        &self,
        vpn_config: &VpnConfig,
    ) -> anyhow::Result<serde_json::Value> {
        let params = build_tunnel_params(vpn_config);
        let info = snxcore::server_info::get(&params).await?;
        Ok(serde_json::to_value(&info)?)
    }

    /// Return the server name of the current (or last) connection.
    ///
    /// Prefers the server from an active `Connected` status; falls back to the
    /// server remembered from the most recent `connect()` call.
    pub async fn current_server(&self) -> Option<String> {
        let status = self.status.read().await;
        if let ConnectionStatus::Connected(ref info) = *status {
            return Some(info.server_name.clone());
        }
        drop(status);

        self.last_server.read().await.clone()
    }

    pub async fn routes(&self) -> Vec<VpnRoute> {
        if let ConnectionStatus::Connected(ref info) = *self.status.read().await {
            vec![VpnRoute {
                destination: "0.0.0.0/0".to_string(),
                gateway: Some(info.ip_address.clone()),
                interface: info.interface_name.clone(),
            }]
        } else {
            vec![]
        }
    }

    async fn set_status(&self, status: ConnectionStatus) {
        let status_str = match &status {
            ConnectionStatus::Disconnected => "disconnected",
            ConnectionStatus::Connecting => "connecting",
            ConnectionStatus::Connected(_) => "connected",
            ConnectionStatus::Mfa(_) => "mfa",
            ConnectionStatus::Error { .. } => "error",
        };

        *self.status.write().await = status;
        let _ = self.event_tx.send(ServerEvent::ConnectionStatus {
            status: status_str.to_string(),
        });
    }
}
