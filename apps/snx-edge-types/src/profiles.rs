//! VPN profile wire-format types.
//!
//! The on-disk encrypted `ProfileRow` and the encryption helpers stay in
//! the server crate — only the post-decryption, secret-masked wire form
//! lives here.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// VPN profile as returned over the wire.
///
/// `config` is plaintext JSON (post-decryption) with secret fields
/// (`password`, `cert_password`) masked by the server before serialisation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub config: serde_json::Value,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Profile response with secrets masked. Wraps [`Profile`] but serialises
/// the timestamps as RFC3339 strings — kept as a separate type because the
/// server historically rendered the timestamps via `.to_rfc3339()` while
/// `Profile` derives serde directly. Identical JSON shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileResponse {
    pub id: String,
    pub name: String,
    pub config: serde_json::Value,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProfileRequest {
    pub name: String,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProfileRequest {
    pub name: Option<String>,
    pub config: Option<serde_json::Value>,
    pub enabled: Option<bool>,
}

/// VPN connection parameters — the JSON blob inside `Profile.config`.
///
/// Server callers parse this with `serde_json::from_value` to drive the
/// `snxcore` tunnel factory; clients usually pass it through verbatim
/// (as `serde_json::Value`) but the typed shape is here for tools that
/// want to inspect or build a config programmatically.
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
    #[serde(default = "default_no_keychain")]
    pub no_keychain: bool,
}

pub fn default_login_type() -> String {
    "password".to_string()
}
pub fn default_cert_type() -> String {
    "pkcs12".to_string()
}
pub fn default_password_factor() -> u32 {
    1
}
pub fn default_ike_lifetime() -> u32 {
    28800
}
pub fn default_mtu() -> u16 {
    1350
}
pub fn default_transport_type() -> String {
    "auto".to_string()
}
pub fn default_no_keychain() -> bool {
    true
}
