use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const CONFIG_DIR: &str = "snx-edge";
const CONFIG_FILE: &str = "client.toml";

/// A single server connection entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConnection {
    /// Display name shown in tray and UI, e.g. "Office VPN".
    pub name: String,
    /// Full URL including scheme and port, e.g. "https://172.19.0.2:8443".
    pub url: String,
    /// Whether to connect automatically when this server becomes active.
    pub auto_connect: bool,
    /// ID of the last used VPN profile on this server.
    pub last_profile_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSettings {
    /// List of configured server connections.
    #[serde(default)]
    pub servers: Vec<ServerConnection>,
    /// Index into `servers` for the currently active server, if any.
    pub active_server: Option<usize>,
    /// Icon theme preference.
    pub icon_theme: String,
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            active_server: None,
            icon_theme: "system".to_string(),
        }
    }
}

/// Legacy format for backward-compatible migration from single-server config.
#[derive(Debug, Deserialize)]
struct LegacySettings {
    server_url: Option<String>,
    icon_theme: Option<String>,
    auto_connect: Option<bool>,
    last_profile_id: Option<String>,
}

impl ClientSettings {
    /// Load settings from `~/.config/snx-edge/client.toml`.
    /// Returns defaults if the file does not exist or cannot be parsed.
    ///
    /// Automatically migrates the legacy single-server format if detected.
    pub fn load() -> Self {
        let path = match Self::config_path() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("could not determine config path, using defaults: {e}");
                return Self::default();
            }
        };

        if !path.exists() {
            tracing::debug!("config file not found at {}, using defaults", path.display());
            return Self::default();
        }

        match fs::read_to_string(&path) {
            Ok(contents) => {
                // Try new multi-server format first.
                if let Ok(settings) = toml::from_str::<ClientSettings>(&contents) {
                    tracing::debug!("loaded settings from {}", path.display());
                    return settings;
                }

                // Fall back to legacy single-server format and migrate.
                if let Ok(legacy) = toml::from_str::<LegacySettings>(&contents) {
                    tracing::info!("migrating legacy single-server config to multi-server format");
                    let mut settings = ClientSettings {
                        icon_theme: legacy.icon_theme.unwrap_or_else(|| "system".to_string()),
                        ..Default::default()
                    };

                    if let Some(url) = legacy.server_url {
                        if !url.is_empty() {
                            settings.servers.push(ServerConnection {
                                name: "Server".to_string(),
                                url,
                                auto_connect: legacy.auto_connect.unwrap_or(false),
                                last_profile_id: legacy.last_profile_id,
                            });
                            settings.active_server = Some(0);
                        }
                    }

                    // Persist the migrated config.
                    if let Err(e) = settings.save() {
                        tracing::warn!("failed to save migrated config: {e}");
                    }

                    return settings;
                }

                tracing::warn!("failed to parse {}, using defaults", path.display());
                Self::default()
            }
            Err(e) => {
                tracing::warn!("failed to read {}: {e}, using defaults", path.display());
                Self::default()
            }
        }
    }

    /// Persist current settings to `~/.config/snx-edge/client.toml`.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create config directory {}", parent.display()))?;
        }

        let contents =
            toml::to_string_pretty(self).context("failed to serialize settings to TOML")?;

        fs::write(&path, contents)
            .with_context(|| format!("failed to write config file {}", path.display()))?;

        tracing::debug!("saved settings to {}", path.display());
        Ok(())
    }

    // ── Multi-server helpers ────────────────────────────────────────

    /// Get the currently active server connection, if any.
    pub fn active(&self) -> Option<&ServerConnection> {
        self.active_server.and_then(|idx| self.servers.get(idx))
    }

    /// Get a mutable reference to the currently active server connection.
    pub fn active_mut(&mut self) -> Option<&mut ServerConnection> {
        self.active_server.and_then(|idx| self.servers.get_mut(idx))
    }

    /// Add a new server connection and return its index.
    pub fn add_server(&mut self, name: String, url: String) -> usize {
        let idx = self.servers.len();
        self.servers.push(ServerConnection {
            name,
            url,
            auto_connect: false,
            last_profile_id: None,
        });
        // If this is the first server, make it active automatically.
        if self.servers.len() == 1 {
            self.active_server = Some(0);
        }
        idx
    }

    /// Remove a server connection by index.
    /// Adjusts `active_server` accordingly.
    pub fn remove_server(&mut self, index: usize) {
        if index >= self.servers.len() {
            return;
        }
        self.servers.remove(index);

        // Fix active_server index after removal.
        match self.active_server {
            Some(active) if active == index => {
                // The removed server was active.
                self.active_server = if self.servers.is_empty() {
                    None
                } else {
                    Some(active.min(self.servers.len() - 1))
                };
            }
            Some(active) if active > index => {
                self.active_server = Some(active - 1);
            }
            _ => {}
        }
    }

    /// Switch the active server. Returns `true` if the index was valid.
    pub fn set_active(&mut self, index: usize) -> bool {
        if index < self.servers.len() {
            self.active_server = Some(index);
            true
        } else {
            false
        }
    }

    /// Resolve the path `~/.config/snx-edge/client.toml`.
    fn config_path() -> Result<PathBuf> {
        let config_dir = dirs_next::config_dir()
            .or_else(|| {
                // Fallback: $HOME/.config
                dirs_next::home_dir().map(|h| h.join(".config"))
            })
            .context("could not determine user config directory")?;

        Ok(config_dir.join(CONFIG_DIR).join(CONFIG_FILE))
    }
}
