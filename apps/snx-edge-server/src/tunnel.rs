#![deny(clippy::wildcard_enum_match_arm)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::Utc;
use secrecy::SecretString;
use snxcore::model::SessionState;
use snxcore::model::params::{CertType, TransportType, TunnelType};
use snxcore::tunnel::{
    CheckPointTunnelConnectorFactory, TunnelConnector, TunnelConnectorFactory, TunnelEvent,
};
use tokio::sync::{Mutex, RwLock, broadcast, mpsc};
use tokio::task::JoinHandle;

pub use snx_edge_types::profiles::{VpnConfig, default_mtu};
pub use snx_edge_types::tunnel::{
    ConnectionInfo, ConnectionStatus, MfaChallenge, TunnelStatus, VpnRoute,
};

use crate::state::ServerEvent;

// === Conversion from snxcore types ===

/// Map `snxcore::model::params::TunnelType` to a stable wire-format string.
///
/// Using an explicit match (rather than `format!("{:?}", ...)`) decouples the
/// API contract from snxcore's `Debug` derive — a future rename of an enum
/// variant upstream would otherwise silently change the public API.
fn tunnel_type_str(t: TunnelType) -> &'static str {
    match t {
        TunnelType::Ipsec => "ipsec",
        TunnelType::Ssl => "ssl",
    }
}

/// Map `snxcore::model::params::TransportType` to a stable wire-format string.
///
/// See [`tunnel_type_str`] for rationale.
fn transport_type_str(t: TransportType) -> &'static str {
    match t {
        TransportType::AutoDetect => "auto",
        TransportType::Kernel => "kernel",
        TransportType::Udp => "udp",
        TransportType::Tcpt => "tcpt",
    }
}

fn map_connection_info(info: &snxcore::model::ConnectionInfo, mtu: u16) -> ConnectionInfo {
    ConnectionInfo {
        since: info.since.map(|dt| dt.to_utc()),
        server_name: info.server_name.clone(),
        username: info.username.clone(),
        login_type: info.login_type.clone(),
        tunnel_type: tunnel_type_str(info.tunnel_type).to_string(),
        transport_type: transport_type_str(info.transport_type).to_string(),
        ip_address: info.ip_address.to_string(),
        dns_servers: info.dns_servers.iter().map(|d| d.to_string()).collect(),
        search_domains: info.search_domains.iter().map(|d| d.to_string()).collect(),
        interface_name: info.interface_name.clone(),
        mtu,
    }
}

/// Build snxcore TunnelParams from our VpnConfig.
pub fn build_tunnel_params(vpn: &VpnConfig) -> snxcore::model::params::TunnelParams {
    let mut params = snxcore::model::params::TunnelParams {
        server_name: vpn.server.clone(),
        user_name: vpn.username.clone(),
        ..Default::default()
    };

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
    params.dns_servers = vpn
        .dns_servers
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    params.ignore_dns_servers = vpn
        .ignored_dns_servers
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    params.search_domains = vpn.search_domains.clone();
    params.ignore_search_domains = vpn.ignored_search_domains.clone();
    params.set_routing_domains = vpn.search_domains_as_routes;

    params.no_routing = vpn.no_routing;
    params.default_route = vpn.default_route;
    params.add_routes = vpn
        .add_routes
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    params.ignore_routes = vpn
        .ignored_routes
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    params.disable_ipv6 = vpn.no_ipv6;

    params.ca_cert = vpn.ca_cert.iter().map(|s| s.into()).collect();
    params.ignore_server_cert = vpn.no_cert_check;

    if let Some(lease) = vpn.ip_lease_duration {
        params.ip_lease_time = Some(std::time::Duration::from_secs(lease as u64));
    }

    params.ike_lifetime = std::time::Duration::from_secs(vpn.ike_lifetime as u64);
    params.ike_persist = vpn.ike_persist;
    params.no_keepalive = vpn.no_keepalive;
    params.port_knock = vpn.port_knock;
    params.mtu = vpn.mtu;
    params.keychain = !vpn.no_keychain;

    params.log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

    params
}

/// Status to apply when the tunnel event channel closes with no explicit
/// Connected/Disconnected transition. `None` when an intentional `disconnect()`
/// already owns the transition.
fn terminal_status_on_channel_close(disconnect_initiated: bool) -> Option<ConnectionStatus> {
    if disconnect_initiated {
        None
    } else {
        Some(ConnectionStatus::Error {
            message: "tunnel ended unexpectedly".to_string(),
        })
    }
}

// === Tunnel Manager ===

/// Manages VPN tunnel lifecycle using snxcore.
pub struct TunnelManager {
    factory: CheckPointTunnelConnectorFactory,
    connector: Arc<Mutex<Option<Box<dyn TunnelConnector + Send + Sync>>>>,
    session: Arc<Mutex<Option<Arc<snxcore::model::VpnSession>>>>,
    /// Connection status. Held in a `std::sync::Mutex` because the lock is
    /// only ever taken for trivial reads/writes and we need a synchronous
    /// reset path from `connect()` on the cold/error branch (see the
    /// `with_status_reset_on_err` helper below).
    status: Arc<std::sync::Mutex<ConnectionStatus>>,
    event_tx: broadcast::Sender<ServerEvent>,
    tx_bytes: Arc<Mutex<u64>>,
    rx_bytes: Arc<Mutex<u64>>,
    /// Server name from the last connect attempt (used by GET /server/info
    /// when the tunnel is disconnected).
    last_server: Arc<RwLock<Option<String>>>,
    /// MTU from the last connect config (snxcore doesn't expose it in ConnectionInfo).
    last_mtu: Arc<RwLock<u16>>,
    /// Tunnel + event-handler `JoinHandle`s spawned during `start_tunnel`.
    /// Aborted on `disconnect` so we don't leak tasks across reconnects.
    tasks: Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
    /// Set by `disconnect()` so the spawned event handler knows the
    /// shutdown is operator-initiated and skips writing to `status`
    /// (which `disconnect()` is about to reset directly). Cleared at the
    /// start of every `connect()`.
    disconnect_initiated: Arc<AtomicBool>,
}

impl TunnelManager {
    pub fn new(event_tx: broadcast::Sender<ServerEvent>) -> Self {
        Self {
            factory: CheckPointTunnelConnectorFactory,
            connector: Arc::new(Mutex::new(None)),
            session: Arc::new(Mutex::new(None)),
            status: Arc::new(std::sync::Mutex::new(ConnectionStatus::Disconnected)),
            event_tx,
            tx_bytes: Arc::new(Mutex::new(0)),
            rx_bytes: Arc::new(Mutex::new(0)),
            last_server: Arc::new(RwLock::new(None)),
            last_mtu: Arc::new(RwLock::new(default_mtu())),
            tasks: Arc::new(std::sync::Mutex::new(Vec::new())),
            disconnect_initiated: Arc::new(AtomicBool::new(false)),
        }
    }

    fn read_status(&self) -> ConnectionStatus {
        self.status.lock().expect("status mutex poisoned").clone()
    }

    pub async fn status(&self) -> TunnelStatus {
        let connection = self.read_status();
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
            let mut status = self.status.lock().expect("status mutex poisoned");
            if matches!(
                *status,
                ConnectionStatus::Connected(_) | ConnectionStatus::Connecting
            ) {
                anyhow::bail!("already connected or connecting");
            }
            *status = ConnectionStatus::Connecting;
        }
        // Fresh attempt — clear any leftover disconnect flag from a previous
        // session.
        self.disconnect_initiated.store(false, Ordering::SeqCst);

        // Wrap the rest of the body so any early exit (`?`) resets `status`
        // back to `Disconnected` instead of leaving it stuck on `Connecting`
        // — that bug previously locked out every subsequent connect attempt
        // until the process restarted.
        //
        // NOTE: chose the `async-block + post-match` pattern over a `Drop`
        // guard because `Drop` interacts poorly with our mix of sync and
        // async locks; a plain async block is much easier to follow.
        let result = self.connect_inner(vpn_config).await;
        if let Err(ref e) = result {
            self.set_status(ConnectionStatus::Error {
                message: e.to_string(),
            });
        }
        result
    }

    async fn connect_inner(&self, vpn_config: &VpnConfig) -> anyhow::Result<ConnectionStatus> {
        // Remember the server for GET /server/info when disconnected.
        if !vpn_config.server.is_empty() {
            *self.last_server.write().await = Some(vpn_config.server.clone());
        }
        *self.last_mtu.write().await = vpn_config.mtu;

        let params = Arc::new(build_tunnel_params(vpn_config));

        let mut connector = self.factory.create(params.clone()).await?;

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
            self.set_status(mfa.clone());
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
            let connector = guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("no connector"))?;
            connector.create_tunnel(session, cmd_tx).await?
        };

        // Spawn tunnel task
        let tunnel_handle = tokio::spawn(async move {
            if let Err(e) = tunnel.run(cmd_rx, evt_tx).await {
                tracing::warn!("tunnel exited: {e}");
            }
        });

        // Spawn event handler
        let status = self.status.clone();
        let connector = self.connector.clone();
        let broadcast_tx = self.event_tx.clone();
        let session_ref = self.session.clone();
        let disconnect_flag = self.disconnect_initiated.clone();
        let mtu = *self.last_mtu.read().await;

        let event_handle = tokio::spawn(async move {
            // Tracks whether a `break` inside the loop already performed a
            // terminal status transition (Disconnected / Error). When the loop
            // instead ends because the event channel closed (the tunnel
            // run-loop exited on its own), this stays false and the
            // channel-close fallback below applies a terminal status.
            let mut terminal_handled = false;
            while let Some(event) = evt_rx.recv().await {
                // If `disconnect()` is already running, it owns the status
                // transition; we must not race it. Drop the event and exit.
                if disconnect_flag.load(Ordering::SeqCst) {
                    break;
                }

                // Forward to connector for internal handling (rekey etc.)
                {
                    let mut guard = connector.lock().await;
                    if let Some(c) = guard.as_mut()
                        && let Err(e) = c.handle_tunnel_event(event.clone()).await
                    {
                        tracing::warn!("tunnel event handler error: {e}");
                        if !disconnect_flag.load(Ordering::SeqCst) {
                            *status.lock().expect("status mutex poisoned") =
                                ConnectionStatus::Error {
                                    message: e.to_string(),
                                };
                            let _ = broadcast_tx.send(ServerEvent::ConnectionStatus {
                                status: "error".to_string(),
                            });
                        }
                        terminal_handled = true;
                        break;
                    }
                }

                match event {
                    TunnelEvent::Connected(info) => {
                        *status.lock().expect("status mutex poisoned") =
                            ConnectionStatus::Connected(map_connection_info(&info, mtu));
                        let _ = broadcast_tx.send(ServerEvent::ConnectionStatus {
                            status: "connected".to_string(),
                        });
                    }
                    TunnelEvent::Disconnected => {
                        // Spontaneous disconnect (server-initiated, network
                        // failure, etc.). Owner of the transition because
                        // `disconnect()` is not running.
                        *status.lock().expect("status mutex poisoned") =
                            ConnectionStatus::Disconnected;
                        *connector.lock().await = None;
                        *session_ref.lock().await = None;
                        let _ = broadcast_tx.send(ServerEvent::ConnectionStatus {
                            status: "disconnected".to_string(),
                        });
                        terminal_handled = true;
                        break;
                    }
                    TunnelEvent::Rekeyed(addr) => {
                        let mut guard = status.lock().expect("status mutex poisoned");
                        if let ConnectionStatus::Connected(ref mut info) = *guard {
                            info.ip_address = addr.to_string();
                        }
                    }
                    // Forwarded above to `handle_tunnel_event`; nothing else
                    // for us to do at the API layer.
                    event @ TunnelEvent::RekeyCheck | event @ TunnelEvent::RemoteControlData(_) => {
                        tracing::debug!(?event, "unhandled tunnel event");
                    }
                }
            }

            // Event channel closed without a terminal transition (e.g. the
            // tunnel run-loop ended on its own). Avoid leaving a stale
            // `Connected`. An intentional `disconnect()` already owns the
            // transition, so the helper returns `None` in that case.
            if !terminal_handled
                && let Some(s) =
                    terminal_status_on_channel_close(disconnect_flag.load(Ordering::SeqCst))
            {
                *status.lock().expect("status mutex poisoned") = s;
                *connector.lock().await = None;
                *session_ref.lock().await = None;
                let _ = broadcast_tx.send(ServerEvent::ConnectionStatus {
                    status: "error".to_string(),
                });
            }
        });

        // Track handles so disconnect() can abort them.
        {
            let mut tasks = self.tasks.lock().expect("tasks mutex poisoned");
            tasks.push(tunnel_handle);
            tasks.push(event_handle);
        }

        self.set_status(ConnectionStatus::Connecting);
        Ok(ConnectionStatus::Connecting)
    }

    pub async fn disconnect(&self) -> anyhow::Result<()> {
        let current = self.read_status();
        if matches!(current, ConnectionStatus::Disconnected) {
            anyhow::bail!("not connected");
        }

        // Claim the status transition so the spawned event handler stops
        // touching `status` once it observes this flag.
        self.disconnect_initiated.store(true, Ordering::SeqCst);

        if let Some(connector) = self.connector.lock().await.as_mut() {
            let _ = connector.delete_session().await;
            let _ = connector.terminate_tunnel(true).await;
        }

        *self.connector.lock().await = None;
        *self.session.lock().await = None;

        // Abort any spawned tasks. We don't await them — the event handler
        // typically exits on its own once the channel closes, and abort is
        // cheap insurance against the rare case where it doesn't.
        let drained: Vec<JoinHandle<()>> = {
            let mut tasks = self.tasks.lock().expect("tasks mutex poisoned");
            std::mem::take(&mut *tasks)
        };
        for handle in drained {
            handle.abort();
        }

        self.set_status(ConnectionStatus::Disconnected);

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
            self.set_status(mfa.clone());
            Ok(mfa)
        } else {
            self.start_tunnel(new_session).await
        }
    }

    /// Query server info via snxcore CCC protocol.
    pub async fn server_info(&self, vpn_config: &VpnConfig) -> anyhow::Result<serde_json::Value> {
        let params = build_tunnel_params(vpn_config);
        let info = snxcore::server_info::get(&params).await?;
        Ok(serde_json::to_value(&info)?)
    }

    /// Return the server name of the current (or last) connection.
    ///
    /// Prefers the server from an active `Connected` status; falls back to the
    /// server remembered from the most recent `connect()` call.
    pub async fn current_server(&self) -> Option<String> {
        if let ConnectionStatus::Connected(info) = self.read_status() {
            return Some(info.server_name);
        }
        self.last_server.read().await.clone()
    }

    pub async fn routes(&self) -> Vec<VpnRoute> {
        if let ConnectionStatus::Connected(info) = self.read_status() {
            vec![VpnRoute {
                destination: "0.0.0.0/0".to_string(),
                gateway: Some(info.ip_address.clone()),
                interface: info.interface_name,
            }]
        } else {
            vec![]
        }
    }

    fn set_status(&self, status: ConnectionStatus) {
        let status_str = match &status {
            ConnectionStatus::Disconnected => "disconnected",
            ConnectionStatus::Connecting => "connecting",
            ConnectionStatus::Connected(_) => "connected",
            ConnectionStatus::Mfa(_) => "mfa",
            ConnectionStatus::Error { .. } => "error",
        };

        *self.status.lock().expect("status mutex poisoned") = status;
        let _ = self.event_tx.send(ServerEvent::ConnectionStatus {
            status: status_str.to_string(),
        });
    }
}

#[cfg(test)]
impl TunnelManager {
    /// Test-only helper used to drive the `connect()` failure-recovery path
    /// without standing up a full mock `TunnelConnectorFactory`. We can't
    /// easily mock `CheckPointTunnelConnectorFactory` (it's a foreign type),
    /// so the test triggers the same code path by setting `Connecting`
    /// directly and then invoking the post-connect reset logic.
    fn force_status(&self, status: ConnectionStatus) {
        *self.status.lock().expect("status mutex poisoned") = status;
    }
}

#[cfg(test)]
mod tests {
    //! These tests guard the wire-format strings exposed by the API for
    //! `tunnel_type` and `transport_type`.  An snxcore upgrade that renames
    //! a `Debug`-derived variant must NOT silently change our public API —
    //! that's exactly the bug an explicit `match` was added to prevent.
    use super::{
        ConnectionStatus, TunnelManager, VpnConfig, terminal_status_on_channel_close,
        transport_type_str, tunnel_type_str,
    };
    use snxcore::model::params::{TransportType, TunnelType};

    #[test]
    fn channel_close_yields_error_unless_user_disconnected() {
        assert_eq!(
            terminal_status_on_channel_close(false),
            Some(ConnectionStatus::Error {
                message: "tunnel ended unexpectedly".to_string()
            })
        );
        assert_eq!(terminal_status_on_channel_close(true), None);
    }

    #[test]
    fn tunnel_type_strings_are_stable() {
        assert_eq!(tunnel_type_str(TunnelType::Ipsec), "ipsec");
        assert_eq!(tunnel_type_str(TunnelType::Ssl), "ssl");
    }

    #[test]
    fn transport_type_strings_are_stable() {
        assert_eq!(transport_type_str(TransportType::AutoDetect), "auto");
        assert_eq!(transport_type_str(TransportType::Kernel), "kernel");
        assert_eq!(transport_type_str(TransportType::Udp), "udp");
        assert_eq!(transport_type_str(TransportType::Tcpt), "tcpt");
    }

    #[test]
    fn tunnel_type_default_maps_to_ipsec() {
        // If snxcore changes the default, our API contract should also be
        // explicitly considered — surface that via a test rather than a
        // silent change.
        assert_eq!(tunnel_type_str(TunnelType::default()), "ipsec");
    }

    #[test]
    fn transport_type_default_maps_to_auto() {
        assert_eq!(transport_type_str(TransportType::default()), "auto");
    }

    /// Regression test for the bug where a failure inside `connect()` (e.g.
    /// `authenticate().await?` returning Err) would leave `status` stuck on
    /// `Connecting`, locking out every subsequent connect attempt. After
    /// the fix, an Err return must transition `status` to `Error { .. }`.
    #[tokio::test]
    async fn connect_failure_does_not_leave_status_in_connecting() {
        let (tx, _rx) = tokio::sync::broadcast::channel(8);
        let mgr = TunnelManager::new(tx);

        // Use an empty VpnConfig — the underlying snxcore factory will
        // reject this with an error, which is exactly the failure we want
        // to drive through `connect()`.
        let bad = VpnConfig::default();

        let result = mgr.connect(&bad).await;
        assert!(
            result.is_err(),
            "expected connect to fail with empty config"
        );

        // The critical property: status is NOT stuck on Connecting.
        let status = mgr.status().await.connection;
        assert!(
            !matches!(status, ConnectionStatus::Connecting),
            "status was left as Connecting after error, got {status:?}"
        );
    }

    /// Direct test of the reset semantics that `connect()` relies on:
    /// putting status into `Connecting` and then writing `Error { .. }`
    /// on top of it must succeed and be observable via `status()`.
    #[tokio::test]
    async fn set_status_overwrites_connecting() {
        let (tx, _rx) = tokio::sync::broadcast::channel(8);
        let mgr = TunnelManager::new(tx);

        mgr.force_status(ConnectionStatus::Connecting);
        mgr.set_status(ConnectionStatus::Error {
            message: "test".into(),
        });

        let status = mgr.status().await.connection;
        assert!(matches!(status, ConnectionStatus::Error { .. }));
    }

    /// `disconnect()` must abort spawned tunnel/event tasks (so they don't
    /// accumulate across reconnects) and reset status to Disconnected.
    /// We only assert the visible properties: status is Disconnected and
    /// the task list is empty after disconnect.
    #[tokio::test]
    async fn disconnect_clears_tasks_and_resets_status() {
        let (tx, _rx) = tokio::sync::broadcast::channel(8);
        let mgr = TunnelManager::new(tx);

        // Inject a fake background task so the disconnect path has
        // something to drain. This task would run forever if not aborted.
        let dummy = tokio::spawn(async {
            futures_util::future::pending::<()>().await;
        });
        mgr.tasks.lock().expect("tasks mutex poisoned").push(dummy);

        // Put manager into a non-Disconnected state so disconnect() runs
        // its full path instead of bailing early.
        mgr.force_status(ConnectionStatus::Connecting);

        mgr.disconnect().await.expect("disconnect should succeed");

        let status = mgr.status().await.connection;
        assert!(matches!(status, ConnectionStatus::Disconnected));
        assert!(
            mgr.tasks.lock().expect("tasks mutex poisoned").is_empty(),
            "task list should be drained after disconnect"
        );
    }
}
