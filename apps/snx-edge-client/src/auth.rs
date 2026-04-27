use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::api::ApiClient;

/// Process-wide in-memory cache for refresh tokens, keyed by server URL.
///
/// Keyring access is a synchronous D-Bus IPC roundtrip (~10–200ms) and we
/// hit it on every login restore + every refresh. Caching avoids that on
/// repeat reads. Cache is invalidated on `logout` and refreshed on every
/// successful `set_password` call.
fn token_cache() -> &'static Arc<Mutex<HashMap<String, String>>> {
    static CACHE: OnceLock<Arc<Mutex<HashMap<String, String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct AuthManager {
    api: ApiClient,
    server_url: String,
}

impl AuthManager {
    pub fn new(api: ApiClient, server_url: &str) -> Self {
        Self {
            api,
            server_url: server_url.to_string(),
        }
    }

    pub fn set_server_url(&mut self, url: &str) {
        self.server_url = url.to_string();
    }

    pub async fn login(&self, username: &str, password: &str) -> anyhow::Result<()> {
        let token_resp = self.api.login(username, password).await?;
        if let Some(refresh_token) = &token_resp.refresh_token {
            self.save_refresh_token(refresh_token).await;
        }
        Ok(())
    }

    pub async fn refresh(&self) -> anyhow::Result<()> {
        let refresh_token = self
            .load_saved_token()
            .await
            .context("No saved refresh token")?;
        let token_resp = self.api.refresh(&refresh_token).await?;
        if let Some(new_refresh) = &token_resp.refresh_token {
            self.save_refresh_token(new_refresh).await;
        }
        Ok(())
    }

    pub async fn ensure_authenticated(&self) -> anyhow::Result<()> {
        if self.api.token().await.is_some() {
            // Check if token is still valid by trying status
            if self.api.tunnel_status().await.is_ok() {
                return Ok(());
            }
        }
        // Try refresh
        if self.refresh().await.is_ok() {
            return Ok(());
        }
        bail!("Not authenticated — please log in");
    }

    pub async fn logout(&self) {
        self.api.set_token(None).await;
        self.delete_saved_token().await;
    }

    pub async fn load_saved_token(&self) -> Option<String> {
        // Cache fast-path
        if let Ok(cache) = token_cache().lock()
            && let Some(token) = cache.get(&self.server_url).cloned()
        {
            return Some(token);
        }

        let server_url = self.server_url.clone();
        let token = tokio::task::spawn_blocking(move || -> Option<String> {
            let entry = keyring::Entry::new("snx-edge", &server_url).ok()?;
            entry.get_password().ok()
        })
        .await
        .ok()
        .flatten()?;

        if let Ok(mut cache) = token_cache().lock() {
            cache.insert(self.server_url.clone(), token.clone());
        }

        Some(token)
    }

    async fn save_refresh_token(&self, token: &str) {
        let server_url = self.server_url.clone();
        let token_owned = token.to_string();

        // Update cache eagerly so subsequent reads are instant.
        if let Ok(mut cache) = token_cache().lock() {
            cache.insert(server_url.clone(), token_owned.clone());
        }

        // Write through to keyring on a blocking thread.
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(entry) = keyring::Entry::new("snx-edge", &server_url) {
                let _ = entry.set_password(&token_owned);
            }
        })
        .await;
    }

    async fn delete_saved_token(&self) {
        let server_url = self.server_url.clone();

        // Invalidate cache.
        if let Ok(mut cache) = token_cache().lock() {
            cache.remove(&server_url);
        }

        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(entry) = keyring::Entry::new("snx-edge", &server_url) {
                let _ = entry.delete_credential();
            }
        })
        .await;
    }

    /// Decode the JWT payload to extract the user role (if present).
    pub async fn role(&self) -> Option<String> {
        let token = self.api.token().await?;
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 2 {
            return None;
        }
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
        let json: serde_json::Value = serde_json::from_slice(&payload).ok()?;
        json.get("role")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
}
