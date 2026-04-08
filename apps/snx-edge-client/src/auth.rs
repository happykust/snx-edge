use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::api::ApiClient;

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
            self.save_refresh_token(refresh_token);
        }
        Ok(())
    }

    pub async fn refresh(&self) -> anyhow::Result<()> {
        let refresh_token = self.load_saved_token().context("No saved refresh token")?;
        let token_resp = self.api.refresh(&refresh_token).await?;
        if let Some(new_refresh) = &token_resp.refresh_token {
            self.save_refresh_token(new_refresh);
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
        self.delete_saved_token();
    }

    pub fn load_saved_token(&self) -> Option<String> {
        let entry = keyring::Entry::new("snx-edge", &self.server_url).ok()?;
        entry.get_password().ok()
    }

    fn save_refresh_token(&self, token: &str) {
        if let Ok(entry) = keyring::Entry::new("snx-edge", &self.server_url) {
            let _ = entry.set_password(token);
        }
    }

    fn delete_saved_token(&self) {
        if let Ok(entry) = keyring::Entry::new("snx-edge", &self.server_url) {
            let _ = entry.delete_credential();
        }
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
