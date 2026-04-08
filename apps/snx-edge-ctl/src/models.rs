use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tabled::Tabled;

// === Auth ===

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    #[allow(dead_code)]
    pub token_type: String,
    #[allow(dead_code)]
    pub expires_in: i64,
}

// === Tunnel ===

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TunnelStatus {
    pub connection: ConnectionStatus,
    pub uptime_seconds: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "state")]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected(ConnectionInfo),
    Mfa(MfaChallenge),
    Error { message: String },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct MfaChallenge {
    pub mfa_type: String,
    pub prompt: String,
}

// === Profiles ===

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub config: serde_json::Value,
    pub enabled: bool,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

impl Tabled for Profile {
    const LENGTH: usize = 4;

    fn fields(&self) -> Vec<std::borrow::Cow<'_, str>> {
        vec![
            std::borrow::Cow::Borrowed(&self.id),
            std::borrow::Cow::Borrowed(&self.name),
            std::borrow::Cow::Owned(self.enabled.to_string()),
            std::borrow::Cow::Owned(
                self.config
                    .get("server")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-")
                    .to_string(),
            ),
        ]
    }

    fn headers() -> Vec<std::borrow::Cow<'static, str>> {
        vec![
            std::borrow::Cow::Borrowed("ID"),
            std::borrow::Cow::Borrowed("Name"),
            std::borrow::Cow::Borrowed("Enabled"),
            std::borrow::Cow::Borrowed("Server"),
        ]
    }
}

// === Users ===

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub role: String,
    pub comment: String,
    pub enabled: bool,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub active_sessions: usize,
}

impl Tabled for UserResponse {
    const LENGTH: usize = 5;

    fn fields(&self) -> Vec<std::borrow::Cow<'_, str>> {
        vec![
            std::borrow::Cow::Borrowed(&self.id),
            std::borrow::Cow::Borrowed(&self.username),
            std::borrow::Cow::Borrowed(&self.role),
            std::borrow::Cow::Owned(self.enabled.to_string()),
            std::borrow::Cow::Owned(self.active_sessions.to_string()),
        ]
    }

    fn headers() -> Vec<std::borrow::Cow<'static, str>> {
        vec![
            std::borrow::Cow::Borrowed("ID"),
            std::borrow::Cow::Borrowed("Username"),
            std::borrow::Cow::Borrowed("Role"),
            std::borrow::Cow::Borrowed("Enabled"),
            std::borrow::Cow::Borrowed("Sessions"),
        ]
    }
}

// === Sessions ===

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl Tabled for Session {
    const LENGTH: usize = 5;

    fn fields(&self) -> Vec<std::borrow::Cow<'_, str>> {
        vec![
            std::borrow::Cow::Borrowed(&self.id),
            std::borrow::Cow::Borrowed(&self.user_id),
            std::borrow::Cow::Owned(self.ip_address.as_deref().unwrap_or("-").to_string()),
            std::borrow::Cow::Owned(self.created_at.format("%Y-%m-%d %H:%M").to_string()),
            std::borrow::Cow::Owned(self.expires_at.format("%Y-%m-%d %H:%M").to_string()),
        ]
    }

    fn headers() -> Vec<std::borrow::Cow<'static, str>> {
        vec![
            std::borrow::Cow::Borrowed("ID"),
            std::borrow::Cow::Borrowed("User ID"),
            std::borrow::Cow::Borrowed("IP"),
            std::borrow::Cow::Borrowed("Created"),
            std::borrow::Cow::Borrowed("Expires"),
        ]
    }
}

// === Routing / RouterOS ===

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddressListEntry {
    #[serde(rename = ".id", alias = "id", default)]
    pub id: String,
    #[serde(default)]
    pub list: String,
    pub address: String,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub disabled: Option<String>,
    #[serde(alias = "creation-time", default)]
    pub creation_time: Option<String>,
}

impl Tabled for AddressListEntry {
    const LENGTH: usize = 4;

    fn fields(&self) -> Vec<std::borrow::Cow<'_, str>> {
        vec![
            std::borrow::Cow::Borrowed(&self.id),
            std::borrow::Cow::Borrowed(&self.address),
            std::borrow::Cow::Owned(self.comment.as_deref().unwrap_or("-").to_string()),
            std::borrow::Cow::Owned(self.disabled.as_deref().unwrap_or("false").to_string()),
        ]
    }

    fn headers() -> Vec<std::borrow::Cow<'static, str>> {
        vec![
            std::borrow::Cow::Borrowed("ID"),
            std::borrow::Cow::Borrowed("Address"),
            std::borrow::Cow::Borrowed("Comment"),
            std::borrow::Cow::Borrowed("Disabled"),
        ]
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiagnosticsResult {
    pub status: String,
    pub checks: DiagnosticsChecks,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiagnosticsChecks {
    pub routing_table_exists: bool,
    pub mangle_rules_present: bool,
    pub mangle_rules_count: usize,
    pub vpn_route_active: bool,
    pub killswitch_present: bool,
    pub dns_redirect_active: bool,
    pub fasttrack_configured: bool,
    pub gateway_reachable: bool,
    pub vpn_clients_count: usize,
    pub vpn_bypass_count: usize,
}

// === Logs ===

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    #[serde(default)]
    pub target: Option<String>,
    pub message: String,
}

// === Health ===

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}
