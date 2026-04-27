//! Tunnel/VPN wire-format types: connection status, MFA challenge, requests.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// VPN connection status returned by the API. Tagged enum on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(tag = "state")]
pub enum ConnectionStatus {
    #[default]
    Disconnected,
    Connecting,
    Connected(ConnectionInfo),
    Mfa(MfaChallenge),
    Error {
        message: String,
    },
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub connection: ConnectionStatus,
    pub uptime_seconds: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    /// ID of the VPN profile stored on the server.
    pub profile_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfoRequest {
    pub server: String,
}
