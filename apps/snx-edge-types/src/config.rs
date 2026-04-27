//! Config wire-format types: redacted view + partial-update payload.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub api: ApiConfigView,
    pub auth: AuthConfigView,
    pub routeros: RouterOsConfigView,
    pub logging: LoggingConfigView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfigView {
    pub listen: String,
    pub tls_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfigView {
    pub max_login_attempts: u32,
    pub lockout_duration_minutes: u32,
    pub access_token_ttl_minutes: u64,
    pub refresh_token_ttl_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterOsConfigView {
    pub tls_skip_verify: bool,
    pub comment_tag: String,
    pub address_list_vpn: String,
    pub address_list_bypass: String,
    pub routing_table: String,
    pub auto_setup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfigView {
    pub level: String,
    pub buffer_size: usize,
}

/// Partial update payload accepted by `PUT /config`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigUpdate {
    #[serde(default)]
    pub api: Option<ApiConfigUpdate>,
    #[serde(default)]
    pub auth: Option<AuthConfigUpdate>,
    #[serde(default)]
    pub routeros: Option<RouterOsConfigUpdate>,
    #[serde(default)]
    pub logging: Option<LoggingConfigUpdate>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiConfigUpdate {
    pub listen: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfigUpdate {
    pub max_login_attempts: Option<u32>,
    pub lockout_duration_minutes: Option<u32>,
    pub access_token_ttl_minutes: Option<u64>,
    pub refresh_token_ttl_days: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouterOsConfigUpdate {
    pub tls_skip_verify: Option<bool>,
    pub comment_tag: Option<String>,
    pub address_list_vpn: Option<String>,
    pub address_list_bypass: Option<String>,
    pub routing_table: Option<String>,
    pub auto_setup: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoggingConfigUpdate {
    pub level: Option<String>,
    pub buffer_size: Option<usize>,
}
