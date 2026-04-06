use serde::{Deserialize, Serialize};

/// Root application configuration loaded from TOML.
/// Contains only server infrastructure settings.
/// VPN connection parameters are sent per-request by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub api: ApiConfig,
    pub auth: AuthConfig,
    pub routeros: RouterOsConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub tls_client_ca: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_jwt_secret_env")]
    pub jwt_secret_env: String,
    #[serde(default = "default_user_db")]
    pub user_db: String,
    #[serde(default = "default_max_login_attempts")]
    pub max_login_attempts: u32,
    #[serde(default = "default_lockout_duration")]
    pub lockout_duration_minutes: u32,
    #[serde(default = "default_access_ttl")]
    pub access_token_ttl_minutes: u64,
    #[serde(default = "default_refresh_ttl")]
    pub refresh_token_ttl_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterOsConfig {
    #[serde(default = "default_routeros_host_env")]
    pub host_env: String,
    #[serde(default = "default_routeros_user_env")]
    pub user_env: String,
    #[serde(default = "default_routeros_password_env")]
    pub password_env: String,
    #[serde(default)]
    pub tls_skip_verify: bool,
    #[serde(default = "default_comment_tag")]
    pub comment_tag: String,
    #[serde(default = "default_address_list_vpn")]
    pub address_list_vpn: String,
    #[serde(default = "default_address_list_bypass")]
    pub address_list_bypass: String,
    #[serde(default = "default_routing_table")]
    pub routing_table: String,
    #[serde(default = "default_connection_mark")]
    pub connection_mark: String,
    #[serde(default = "default_routing_mark")]
    pub routing_mark: String,
    #[serde(default)]
    pub auto_setup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default = "default_max_file_size")]
    pub max_file_size: String,
    #[serde(default = "default_max_files")]
    pub max_files: u32,
}

impl AppConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn jwt_secret(&self) -> anyhow::Result<String> {
        std::env::var(&self.auth.jwt_secret_env)
            .map_err(|_| anyhow::anyhow!("env {} not set", self.auth.jwt_secret_env))
    }
}

// Default value functions

fn default_listen() -> String {
    "0.0.0.0:8080".to_string()
}
fn default_jwt_secret_env() -> String {
    "SNX_EDGE_JWT_SECRET".to_string()
}
fn default_user_db() -> String {
    "/var/lib/snx-edge/users.db".to_string()
}
fn default_max_login_attempts() -> u32 {
    5
}
fn default_lockout_duration() -> u32 {
    15
}
fn default_access_ttl() -> u64 {
    15
}
fn default_refresh_ttl() -> u64 {
    7
}
fn default_routeros_host_env() -> String {
    "ROUTEROS_HOST".to_string()
}
fn default_routeros_user_env() -> String {
    "ROUTEROS_USER".to_string()
}
fn default_routeros_password_env() -> String {
    "ROUTEROS_PASSWORD".to_string()
}
fn default_comment_tag() -> String {
    "managed-by=snx-edge".to_string()
}
fn default_address_list_vpn() -> String {
    "vpn-clients".to_string()
}
fn default_address_list_bypass() -> String {
    "vpn-bypass".to_string()
}
fn default_routing_table() -> String {
    "vpn-route".to_string()
}
fn default_connection_mark() -> String {
    "vpn-conn".to_string()
}
fn default_routing_mark() -> String {
    "vpn-route".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_buffer_size() -> usize {
    10_000
}
fn default_max_file_size() -> String {
    "10MB".to_string()
}
fn default_max_files() -> u32 {
    3
}
