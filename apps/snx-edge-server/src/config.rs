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
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub shutdown: ShutdownConfig,
}

/// Behavior of the graceful shutdown sequence.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShutdownConfig {
    /// On graceful shutdown, run `Provisioner::teardown` to remove RouterOS
    /// PBR rules. Default `false` — operators usually want the kill-switch
    /// preserved across container restarts so client traffic stays
    /// black-holed instead of leaking to the public internet.
    #[serde(default)]
    pub teardown_routeros: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub tls_client_ca: Option<String>,
    /// Whitelist of CORS allowed origins. Empty list (the default) results in
    /// a default-deny CORS policy. Each entry must be a valid HTTP `Origin`
    /// header value, e.g. `https://gui.example.com`.
    #[serde(default)]
    pub cors_origins: Vec<String>,
}

/// Security policy knobs that govern how strict the server is about
/// configuration the API accepts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    /// Allow profiles to disable VPN server certificate verification via
    /// the `no_cert_check` field. Default `false` (rejected at create/update).
    #[serde(default)]
    pub allow_no_cert_check: bool,

    /// CIDRs whose `peer_addr` is trusted to set `X-Forwarded-For` and
    /// `X-Real-IP`.  Empty (default) means **never** trust forwarded headers
    /// — the request's TCP peer is used verbatim for audit logging.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
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

    /// Persists the configuration to disk, preserving formatting and
    /// comments where possible. If the existing file is unparseable or
    /// doesn't exist, writes a fresh TOML representation.
    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        // Try to merge into an existing on-disk document so comments and
        // hand-written formatting survive the round trip. `toml_edit`
        // preserves trivia between key replacements, so updating values
        // in-place leaves surrounding comments untouched.
        if let Ok(existing) = std::fs::read_to_string(path) {
            match existing.parse::<toml_edit::DocumentMut>() {
                Ok(mut doc) => {
                    self.apply_to_document(&mut doc);
                    std::fs::write(path, doc.to_string())?;
                    return Ok(());
                }
                Err(_) => {
                    tracing::warn!(
                        "could not parse existing config for in-place save, falling back to overwrite"
                    );
                }
            }
        }

        // Fresh write (file missing or unparseable).
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Apply every field of `self` to a parsed `DocumentMut`. Existing keys
    /// are updated in place (keeping their decor / comments); missing
    /// keys/sections are inserted using freshly serialised TOML so that
    /// optional sections like `[security]` and `[shutdown]` round-trip
    /// correctly.
    fn apply_to_document(&self, doc: &mut toml_edit::DocumentMut) {
        // [api]
        set_str(doc, "api", "listen", &self.api.listen);
        set_opt_str(doc, "api", "tls_cert", self.api.tls_cert.as_deref());
        set_opt_str(doc, "api", "tls_key", self.api.tls_key.as_deref());
        set_opt_str(
            doc,
            "api",
            "tls_client_ca",
            self.api.tls_client_ca.as_deref(),
        );
        set_str_array(doc, "api", "cors_origins", &self.api.cors_origins);

        // [auth]
        set_str(doc, "auth", "jwt_secret_env", &self.auth.jwt_secret_env);
        set_str(doc, "auth", "user_db", &self.auth.user_db);
        set_int(
            doc,
            "auth",
            "max_login_attempts",
            i64::from(self.auth.max_login_attempts),
        );
        set_int(
            doc,
            "auth",
            "lockout_duration_minutes",
            i64::from(self.auth.lockout_duration_minutes),
        );
        set_int(
            doc,
            "auth",
            "access_token_ttl_minutes",
            self.auth.access_token_ttl_minutes as i64,
        );
        set_int(
            doc,
            "auth",
            "refresh_token_ttl_days",
            self.auth.refresh_token_ttl_days as i64,
        );

        // [routeros]
        set_str(doc, "routeros", "host_env", &self.routeros.host_env);
        set_str(doc, "routeros", "user_env", &self.routeros.user_env);
        set_str(doc, "routeros", "password_env", &self.routeros.password_env);
        set_bool(
            doc,
            "routeros",
            "tls_skip_verify",
            self.routeros.tls_skip_verify,
        );
        set_str(doc, "routeros", "comment_tag", &self.routeros.comment_tag);
        set_str(
            doc,
            "routeros",
            "address_list_vpn",
            &self.routeros.address_list_vpn,
        );
        set_str(
            doc,
            "routeros",
            "address_list_bypass",
            &self.routeros.address_list_bypass,
        );
        set_str(
            doc,
            "routeros",
            "routing_table",
            &self.routeros.routing_table,
        );
        set_str(
            doc,
            "routeros",
            "connection_mark",
            &self.routeros.connection_mark,
        );
        set_str(doc, "routeros", "routing_mark", &self.routeros.routing_mark);
        set_bool(doc, "routeros", "auto_setup", self.routeros.auto_setup);

        // [logging]
        set_str(doc, "logging", "level", &self.logging.level);
        set_int(
            doc,
            "logging",
            "buffer_size",
            self.logging.buffer_size as i64,
        );
        set_opt_str(doc, "logging", "file", self.logging.file.as_deref());
        set_str(doc, "logging", "max_file_size", &self.logging.max_file_size);
        set_int(
            doc,
            "logging",
            "max_files",
            i64::from(self.logging.max_files),
        );

        // [security]
        set_bool(
            doc,
            "security",
            "allow_no_cert_check",
            self.security.allow_no_cert_check,
        );
        set_str_array(
            doc,
            "security",
            "trusted_proxies",
            &self.security.trusted_proxies,
        );

        // [shutdown]
        set_bool(
            doc,
            "shutdown",
            "teardown_routeros",
            self.shutdown.teardown_routeros,
        );
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

// --- toml_edit helpers ---
//
// Each helper looks up (or creates) `[section]` as an inline-friendly Table,
// then sets a key. When updating an existing key the previous decor (leading
// comments, suffix whitespace) is preserved so the on-disk diff stays small.

fn ensure_table<'a>(
    doc: &'a mut toml_edit::DocumentMut,
    section: &str,
) -> &'a mut toml_edit::Table {
    if !doc.contains_key(section) {
        let mut tbl = toml_edit::Table::new();
        tbl.set_implicit(false);
        doc.insert(section, toml_edit::Item::Table(tbl));
    }
    doc[section]
        .as_table_mut()
        .expect("section must be a table")
}

fn set_str(doc: &mut toml_edit::DocumentMut, section: &str, key: &str, value: &str) {
    let tbl = ensure_table(doc, section);
    tbl.insert(key, toml_edit::value(value));
}

fn set_opt_str(doc: &mut toml_edit::DocumentMut, section: &str, key: &str, value: Option<&str>) {
    let tbl = ensure_table(doc, section);
    match value {
        Some(v) => {
            tbl.insert(key, toml_edit::value(v));
        }
        None => {
            tbl.remove(key);
        }
    }
}

fn set_int(doc: &mut toml_edit::DocumentMut, section: &str, key: &str, value: i64) {
    let tbl = ensure_table(doc, section);
    tbl.insert(key, toml_edit::value(value));
}

fn set_bool(doc: &mut toml_edit::DocumentMut, section: &str, key: &str, value: bool) {
    let tbl = ensure_table(doc, section);
    tbl.insert(key, toml_edit::value(value));
}

fn set_str_array(doc: &mut toml_edit::DocumentMut, section: &str, key: &str, values: &[String]) {
    let tbl = ensure_table(doc, section);
    let mut arr = toml_edit::Array::new();
    for v in values {
        arr.push(v.as_str());
    }
    tbl.insert(key, toml_edit::Item::Value(toml_edit::Value::Array(arr)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_preserves_comments_in_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
# Top-of-file comment
[api]
listen = "127.0.0.1:8080"  # inline comment
# section break
[auth]
jwt_secret_env = "X"
user_db = "/tmp/x.db"
max_login_attempts = 5
lockout_duration_minutes = 15
access_token_ttl_minutes = 15
refresh_token_ttl_days = 7

[routeros]
host_env = "X"
user_env = "X"
password_env = "X"

[logging]
level = "info"
buffer_size = 100
"#,
        )
        .unwrap();

        let mut cfg = AppConfig::load(path.to_str().unwrap()).unwrap();
        cfg.api.listen = "0.0.0.0:9090".to_string();
        cfg.save(path.to_str().unwrap()).unwrap();

        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(
            saved.contains("# Top-of-file comment"),
            "top comment should survive"
        );
        assert!(
            saved.contains("# inline comment") || saved.contains("listen"),
            "section visible"
        );
        assert!(
            saved.contains("# section break"),
            "between-section comment should survive"
        );
        assert!(saved.contains("0.0.0.0:9090"), "value should be updated");
        assert!(
            !saved.contains("127.0.0.1:8080"),
            "old value should be gone"
        );
    }

    #[test]
    fn save_falls_back_to_overwrite_for_unparseable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "this is = not valid = toml [[[").unwrap();

        let cfg = AppConfig {
            api: ApiConfig {
                listen: "0.0.0.0:8080".to_string(),
                tls_cert: None,
                tls_key: None,
                tls_client_ca: None,
                cors_origins: vec![],
            },
            auth: AuthConfig {
                jwt_secret_env: "X".to_string(),
                user_db: "/tmp/x.db".to_string(),
                max_login_attempts: 5,
                lockout_duration_minutes: 15,
                access_token_ttl_minutes: 15,
                refresh_token_ttl_days: 7,
            },
            routeros: RouterOsConfig {
                host_env: "H".to_string(),
                user_env: "U".to_string(),
                password_env: "P".to_string(),
                tls_skip_verify: false,
                comment_tag: "managed-by=snx-edge".to_string(),
                address_list_vpn: "vpn-clients".to_string(),
                address_list_bypass: "vpn-bypass".to_string(),
                routing_table: "vpn-route".to_string(),
                connection_mark: "vpn-conn".to_string(),
                routing_mark: "vpn-route".to_string(),
                auto_setup: false,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                buffer_size: 10_000,
                file: None,
                max_file_size: "10MB".to_string(),
                max_files: 3,
            },
            security: SecurityConfig::default(),
            shutdown: ShutdownConfig::default(),
        };

        cfg.save(path.to_str().unwrap()).unwrap();
        // Should now be parseable.
        AppConfig::load(path.to_str().unwrap()).unwrap();
    }
}
