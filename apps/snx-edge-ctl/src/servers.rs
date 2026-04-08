use std::path::PathBuf;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

/// Shared settings format compatible with snx-edge-client (GUI).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientSettings {
    #[serde(default)]
    pub servers: Vec<ServerEntry>,
    pub active_server: Option<usize>,
    #[serde(default = "default_icon_theme")]
    pub icon_theme: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub auto_connect: bool,
    pub last_profile_id: Option<String>,
}

fn default_icon_theme() -> String {
    "system".to_string()
}

impl ClientSettings {
    pub fn config_dir() -> PathBuf {
        dirs_next::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("snx-edge")
    }

    pub fn config_path() -> PathBuf {
        Self::config_dir().join("client.toml")
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| toml::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Self::default()
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let dir = Self::config_dir();
        std::fs::create_dir_all(&dir)?;
        let content = toml::to_string_pretty(self)?;
        std::fs::write(Self::config_path(), content)?;
        Ok(())
    }

    /// Return the active server entry, if any.
    pub fn active(&self) -> Option<&ServerEntry> {
        self.active_server.and_then(|i| self.servers.get(i))
    }

    /// Find a server by name or URL (case-insensitive name match).
    pub fn find_by_name_or_url(&self, query: &str) -> Option<(usize, &ServerEntry)> {
        self.servers
            .iter()
            .enumerate()
            .find(|(_, s)| s.name.eq_ignore_ascii_case(query) || s.url == query)
    }

    /// Add a new server and return its index.
    pub fn add(&mut self, name: &str, url: &str) -> anyhow::Result<usize> {
        // Check for duplicate name
        if self
            .servers
            .iter()
            .any(|s| s.name.eq_ignore_ascii_case(name))
        {
            bail!("Server with name '{}' already exists", name);
        }

        let entry = ServerEntry {
            name: name.to_string(),
            url: url.trim_end_matches('/').to_string(),
            auto_connect: false,
            last_profile_id: None,
        };
        self.servers.push(entry);
        let idx = self.servers.len() - 1;

        // If this is the first server, make it default
        if self.servers.len() == 1 {
            self.active_server = Some(0);
        }

        Ok(idx)
    }

    /// Remove a server by name, adjusting the active index.
    pub fn remove(&mut self, name: &str) -> anyhow::Result<ServerEntry> {
        let idx = self
            .servers
            .iter()
            .position(|s| s.name.eq_ignore_ascii_case(name))
            .context(format!("Server '{}' not found", name))?;

        let removed = self.servers.remove(idx);

        // Adjust active_server index
        match self.active_server {
            Some(active) if active == idx => {
                self.active_server = if self.servers.is_empty() {
                    None
                } else {
                    Some(0)
                };
            }
            Some(active) if active > idx => {
                self.active_server = Some(active - 1);
            }
            _ => {}
        }

        Ok(removed)
    }

    /// Set the default (active) server by name.
    pub fn set_default(&mut self, name: &str) -> anyhow::Result<()> {
        let idx = self
            .servers
            .iter()
            .position(|s| s.name.eq_ignore_ascii_case(name))
            .context(format!("Server '{}' not found", name))?;
        self.active_server = Some(idx);
        Ok(())
    }
}
