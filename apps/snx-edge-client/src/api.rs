use std::sync::Arc;

use anyhow::{Context, bail};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use tokio::sync::RwLock;

#[derive(Clone)]
#[allow(dead_code)]
pub struct ApiClient {
    client: Client,
    base_url: Arc<RwLock<String>>,
    token: Arc<RwLock<Option<String>>>,
}

#[derive(Debug, serde::Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_default(),
            base_url: Arc::new(RwLock::new(base_url.trim_end_matches('/').to_string())),
            token: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn set_base_url(&self, url: &str) {
        *self.base_url.write().await = url.trim_end_matches('/').to_string();
    }

    pub async fn base_url(&self) -> String {
        self.base_url.read().await.clone()
    }

    pub async fn set_token(&self, token: Option<String>) {
        *self.token.write().await = token;
    }

    pub async fn token(&self) -> Option<String> {
        self.token.read().await.clone()
    }

    async fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url.read().await, path)
    }

    async fn request_builder(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = self.url(path).await;
        let mut builder = self.client.request(method, &url);
        if let Some(ref token) = *self.token.read().await {
            builder = builder.bearer_auth(token);
        }
        builder
    }

    pub async fn login(&self, username: &str, password: &str) -> anyhow::Result<TokenResponse> {
        let url = self.url("/api/v1/auth/login").await;
        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "username": username,
                "password": password,
            }))
            .send()
            .await
            .context("Failed to connect to server")?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            bail!("Invalid username or password");
        }
        if !resp.status().is_success() {
            bail!("Login failed: HTTP {}", resp.status());
        }

        let token_resp: TokenResponse = resp.json().await.context("Failed to parse login response")?;
        *self.token.write().await = Some(token_resp.access_token.clone());
        Ok(token_resp)
    }

    pub async fn refresh(&self, refresh_token: &str) -> anyhow::Result<TokenResponse> {
        let url = self.url("/api/v1/auth/refresh").await;
        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "refresh_token": refresh_token,
            }))
            .send()
            .await
            .context("Failed to connect to server")?;

        if !resp.status().is_success() {
            bail!("Token refresh failed: HTTP {}", resp.status());
        }

        let token_resp: TokenResponse = resp.json().await.context("Failed to parse refresh response")?;
        *self.token.write().await = Some(token_resp.access_token.clone());
        Ok(token_resp)
    }

    pub async fn tunnel_connect(&self, profile_id: &str) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/tunnel/connect")
            .await
            .json(&serde_json::json!({"profile_id": profile_id}))
            .send()
            .await
            .context("Failed to connect tunnel")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Tunnel connect failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse tunnel connect response")
    }

    pub async fn tunnel_disconnect(&self) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/tunnel/disconnect")
            .await
            .send()
            .await
            .context("Failed to disconnect tunnel")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Tunnel disconnect failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse tunnel disconnect response")
    }

    pub async fn tunnel_reconnect(&self, profile_id: &str) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/tunnel/reconnect")
            .await
            .json(&serde_json::json!({"profile_id": profile_id}))
            .send()
            .await
            .context("Failed to reconnect tunnel")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Tunnel reconnect failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse tunnel reconnect response")
    }

    pub async fn tunnel_status(&self) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::GET, "/api/v1/tunnel/status")
            .await
            .send()
            .await
            .context("Failed to get tunnel status")?;

        if !resp.status().is_success() {
            bail!("Tunnel status failed: HTTP {}", resp.status());
        }
        resp.json().await.context("Failed to parse tunnel status response")
    }

    pub async fn list_profiles(&self) -> anyhow::Result<Vec<Value>> {
        let resp = self
            .request_builder(reqwest::Method::GET, "/api/v1/profiles")
            .await
            .send()
            .await
            .context("Failed to list profiles")?;

        if !resp.status().is_success() {
            bail!("List profiles failed: HTTP {}", resp.status());
        }
        resp.json().await.context("Failed to parse profiles response")
    }

    pub async fn create_profile(&self, name: &str, config: &Value) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/profiles")
            .await
            .json(&serde_json::json!({
                "name": name,
                "config": config,
            }))
            .send()
            .await
            .context("Failed to create profile")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Create profile failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse create profile response")
    }

    pub async fn update_profile(&self, id: &str, body: &Value) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::PUT, &format!("/api/v1/profiles/{}", id))
            .await
            .json(body)
            .send()
            .await
            .context("Failed to update profile")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Update profile failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse update profile response")
    }

    pub async fn delete_profile(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request_builder(reqwest::Method::DELETE, &format!("/api/v1/profiles/{}", id))
            .await
            .send()
            .await
            .context("Failed to delete profile")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Delete profile failed: HTTP {} - {}", status, body);
        }
        Ok(())
    }

    // === Routing ===

    pub async fn list_routing_clients(&self) -> anyhow::Result<Vec<Value>> {
        let resp = self
            .request_builder(reqwest::Method::GET, "/api/v1/routing/clients")
            .await
            .send()
            .await
            .context("Failed to list routing clients")?;

        if !resp.status().is_success() {
            bail!("List routing clients failed: HTTP {}", resp.status());
        }
        resp.json().await.context("Failed to parse routing clients response")
    }

    pub async fn add_routing_client(&self, address: &str, comment: &str) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/routing/clients")
            .await
            .json(&serde_json::json!({
                "address": address,
                "comment": comment,
            }))
            .send()
            .await
            .context("Failed to add routing client")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Add routing client failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse add routing client response")
    }

    pub async fn remove_routing_client(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request_builder(reqwest::Method::DELETE, &format!("/api/v1/routing/clients/{}", id))
            .await
            .send()
            .await
            .context("Failed to remove routing client")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Remove routing client failed: HTTP {} - {}", status, body);
        }
        Ok(())
    }

    pub async fn list_routing_bypass(&self) -> anyhow::Result<Vec<Value>> {
        let resp = self
            .request_builder(reqwest::Method::GET, "/api/v1/routing/bypass")
            .await
            .send()
            .await
            .context("Failed to list routing bypass")?;

        if !resp.status().is_success() {
            bail!("List routing bypass failed: HTTP {}", resp.status());
        }
        resp.json().await.context("Failed to parse routing bypass response")
    }

    pub async fn add_routing_bypass(&self, address: &str, comment: &str) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/routing/bypass")
            .await
            .json(&serde_json::json!({
                "address": address,
                "comment": comment,
            }))
            .send()
            .await
            .context("Failed to add routing bypass")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Add routing bypass failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse add routing bypass response")
    }

    pub async fn remove_routing_bypass(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request_builder(reqwest::Method::DELETE, &format!("/api/v1/routing/bypass/{}", id))
            .await
            .send()
            .await
            .context("Failed to remove routing bypass")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Remove routing bypass failed: HTTP {} - {}", status, body);
        }
        Ok(())
    }

    pub async fn routing_setup(&self) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/routing/setup")
            .await
            .send()
            .await
            .context("Failed to setup routing")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Routing setup failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse routing setup response")
    }

    pub async fn routing_teardown(&self) -> anyhow::Result<()> {
        let resp = self
            .request_builder(reqwest::Method::DELETE, "/api/v1/routing/setup")
            .await
            .send()
            .await
            .context("Failed to teardown routing")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Routing teardown failed: HTTP {} - {}", status, body);
        }
        Ok(())
    }

    pub async fn routing_diagnostics(&self) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::GET, "/api/v1/routing/diagnostics")
            .await
            .send()
            .await
            .context("Failed to get routing diagnostics")?;

        if !resp.status().is_success() {
            bail!("Routing diagnostics failed: HTTP {}", resp.status());
        }
        resp.json().await.context("Failed to parse routing diagnostics response")
    }

    // === Users ===

    pub async fn list_users(&self) -> anyhow::Result<Vec<Value>> {
        let resp = self
            .request_builder(reqwest::Method::GET, "/api/v1/users")
            .await
            .send()
            .await
            .context("Failed to list users")?;

        if !resp.status().is_success() {
            bail!("List users failed: HTTP {}", resp.status());
        }
        resp.json().await.context("Failed to parse users response")
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: &str,
        comment: &str,
    ) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/users")
            .await
            .json(&serde_json::json!({
                "username": username,
                "password": password,
                "role": role,
                "comment": comment,
            }))
            .send()
            .await
            .context("Failed to create user")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Create user failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse create user response")
    }

    pub async fn update_user(&self, id: &str, updates: &Value) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::PUT, &format!("/api/v1/users/{}", id))
            .await
            .json(updates)
            .send()
            .await
            .context("Failed to update user")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Update user failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse update user response")
    }

    pub async fn delete_user(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request_builder(reqwest::Method::DELETE, &format!("/api/v1/users/{}", id))
            .await
            .send()
            .await
            .context("Failed to delete user")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Delete user failed: HTTP {} - {}", status, body);
        }
        Ok(())
    }

    pub async fn change_user_password(&self, id: &str, new_password: &str) -> anyhow::Result<()> {
        let resp = self
            .request_builder(reqwest::Method::POST, &format!("/api/v1/users/{}/password", id))
            .await
            .json(&serde_json::json!({
                "new_password": new_password,
            }))
            .send()
            .await
            .context("Failed to change user password")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Change user password failed: HTTP {} - {}", status, body);
        }
        Ok(())
    }

    pub async fn list_sessions(&self) -> anyhow::Result<Vec<Value>> {
        let resp = self
            .request_builder(reqwest::Method::GET, "/api/v1/users/sessions")
            .await
            .send()
            .await
            .context("Failed to list sessions")?;

        if !resp.status().is_success() {
            bail!("List sessions failed: HTTP {}", resp.status());
        }
        resp.json().await.context("Failed to parse sessions response")
    }

    pub async fn kick_session(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request_builder(reqwest::Method::DELETE, &format!("/api/v1/users/sessions/{}", id))
            .await
            .send()
            .await
            .context("Failed to kick session")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Kick session failed: HTTP {} - {}", status, body);
        }
        Ok(())
    }

    pub async fn get_me(&self) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::GET, "/api/v1/users/me")
            .await
            .send()
            .await
            .context("Failed to get current user")?;

        if !resp.status().is_success() {
            bail!("Get me failed: HTTP {}", resp.status());
        }
        resp.json().await.context("Failed to parse current user response")
    }

    pub async fn change_my_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> anyhow::Result<()> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/users/me/password")
            .await
            .json(&serde_json::json!({
                "current_password": current_password,
                "new_password": new_password,
            }))
            .send()
            .await
            .context("Failed to change password")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Change password failed: HTTP {} - {}", status, body);
        }
        Ok(())
    }

    // === Logs ===

    pub async fn logs_history(&self, limit: u32, level: Option<&str>) -> anyhow::Result<Vec<Value>> {
        let path = match level {
            Some(l) => format!("/api/v1/logs/history?limit={}&level={}", limit, l),
            None => format!("/api/v1/logs/history?limit={}", limit),
        };
        let resp = self
            .request_builder(reqwest::Method::GET, &path)
            .await
            .send()
            .await
            .context("Failed to get logs history")?;

        if !resp.status().is_success() {
            bail!("Logs history failed: HTTP {}", resp.status());
        }
        resp.json().await.context("Failed to parse logs history response")
    }
}
