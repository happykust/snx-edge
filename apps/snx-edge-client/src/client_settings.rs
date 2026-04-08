use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSettings {
    #[serde(default)]
    pub servers: Vec<ServerConnection>,
    pub active_server: Option<usize>,
    #[serde(default = "default_icon_theme")]
    pub icon_theme: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConnection {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub auto_connect: bool,
    pub last_profile_id: Option<String>,
    /// Accept invalid TLS certificates (for self-signed certs on MikroTik)
    #[serde(default)]
    pub insecure: bool,
}

fn default_icon_theme() -> String {
    "system".to_string()
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            servers: vec![],
            active_server: None,
            icon_theme: default_icon_theme(),
        }
    }
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

    pub fn active_server(&self) -> Option<&ServerConnection> {
        self.active_server.and_then(|i| self.servers.get(i))
    }

    pub fn active_server_url(&self) -> Option<String> {
        self.active_server().map(|s| s.url.clone())
    }
}
