use anyhow::{Context, bail};
use reqwest::{Client, StatusCode};

use crate::models::*;

/// HTTP client for all snx-edge-server API endpoints.
pub struct ApiClient {
    client: Client,
    base_url: String,
    token: Option<String>,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_default(),
            base_url: base_url.trim_end_matches('/').to_string(),
            token: None,
        }
    }

    pub fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }

    /// Return a reference to the inner reqwest Client (for SSE streaming).
    pub fn raw_client(&self) -> &Client {
        &self.client
    }

    /// Return the current access token, if any.
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Return the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn auth_builder(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = self.url(path);
        let mut builder = self.client.request(method, &url);
        if let Some(ref token) = self.token {
            builder = builder.bearer_auth(token);
        }
        builder
    }

    // === Auth ===

    pub async fn login(&mut self, username: &str, password: &str) -> anyhow::Result<TokenResponse> {
        let url = self.url("/api/v1/auth/login");
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
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Login failed: HTTP {} - {}", status, body);
        }

        let token_resp: TokenResponse = resp.json().await.context("Failed to parse login response")?;
        self.token = Some(token_resp.access_token.clone());
        Ok(token_resp)
    }

    pub async fn refresh(&mut self, refresh_token: &str) -> anyhow::Result<TokenResponse> {
        let url = self.url("/api/v1/auth/refresh");
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
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Token refresh failed: HTTP {} - {}", status, body);
        }

        let token_resp: TokenResponse = resp.json().await.context("Failed to parse refresh response")?;
        self.token = Some(token_resp.access_token.clone());
        Ok(token_resp)
    }

    // === Tunnel ===

    pub async fn tunnel_connect(&self, profile_id: &str) -> anyhow::Result<TunnelStatus> {
        let resp = self
            .auth_builder(reqwest::Method::POST, "/api/v1/tunnel/connect")
            .json(&serde_json::json!({ "profile_id": profile_id }))
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

    pub async fn tunnel_disconnect(&self) -> anyhow::Result<TunnelStatus> {
        let resp = self
            .auth_builder(reqwest::Method::POST, "/api/v1/tunnel/disconnect")
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

    pub async fn tunnel_reconnect(&self, profile_id: &str) -> anyhow::Result<TunnelStatus> {
        let resp = self
            .auth_builder(reqwest::Method::POST, "/api/v1/tunnel/reconnect")
            .json(&serde_json::json!({ "profile_id": profile_id }))
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

    pub async fn tunnel_status(&self) -> anyhow::Result<TunnelStatus> {
        let resp = self
            .auth_builder(reqwest::Method::GET, "/api/v1/tunnel/status")
            .send()
            .await
            .context("Failed to get tunnel status")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Tunnel status failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse tunnel status response")
    }

    pub async fn server_info(&self) -> anyhow::Result<serde_json::Value> {
        let resp = self
            .auth_builder(reqwest::Method::GET, "/api/v1/server/info")
            .send()
            .await
            .context("Failed to get server info")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Server info failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse server info response")
    }

    // === Profiles ===

    pub async fn list_profiles(&self) -> anyhow::Result<Vec<Profile>> {
        let resp = self
            .auth_builder(reqwest::Method::GET, "/api/v1/profiles")
            .send()
            .await
            .context("Failed to list profiles")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("List profiles failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse profiles response")
    }

    pub async fn get_profile(&self, id: &str) -> anyhow::Result<Profile> {
        let resp = self
            .auth_builder(reqwest::Method::GET, &format!("/api/v1/profiles/{}", id))
            .send()
            .await
            .context("Failed to get profile")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Get profile failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse profile response")
    }

    pub async fn create_profile(
        &self,
        name: &str,
        config: &serde_json::Value,
    ) -> anyhow::Result<Profile> {
        let resp = self
            .auth_builder(reqwest::Method::POST, "/api/v1/profiles")
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

    pub async fn update_profile(
        &self,
        id: &str,
        body: &serde_json::Value,
    ) -> anyhow::Result<Profile> {
        let resp = self
            .auth_builder(reqwest::Method::PUT, &format!("/api/v1/profiles/{}", id))
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
            .auth_builder(reqwest::Method::DELETE, &format!("/api/v1/profiles/{}", id))
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

    pub async fn import_profile(&self, toml_body: &str) -> anyhow::Result<Profile> {
        let resp = self
            .auth_builder(reqwest::Method::POST, "/api/v1/profiles/import")
            .header("content-type", "application/toml")
            .body(toml_body.to_string())
            .send()
            .await
            .context("Failed to import profile")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Import profile failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse import profile response")
    }

    pub async fn export_profile(&self, id: &str) -> anyhow::Result<String> {
        let resp = self
            .auth_builder(reqwest::Method::GET, &format!("/api/v1/profiles/{}/export", id))
            .send()
            .await
            .context("Failed to export profile")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Export profile failed: HTTP {} - {}", status, body);
        }
        resp.text().await.context("Failed to read export response")
    }

    // === Routing ===

    pub async fn list_clients(&self) -> anyhow::Result<Vec<AddressListEntry>> {
        let resp = self
            .auth_builder(reqwest::Method::GET, "/api/v1/routing/clients")
            .send()
            .await
            .context("Failed to list VPN clients")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("List clients failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse clients response")
    }

    pub async fn add_client(
        &self,
        address: &str,
        comment: Option<&str>,
    ) -> anyhow::Result<AddressListEntry> {
        let mut body = serde_json::json!({ "address": address });
        if let Some(c) = comment {
            body["comment"] = serde_json::json!(c);
        }

        let resp = self
            .auth_builder(reqwest::Method::POST, "/api/v1/routing/clients")
            .json(&body)
            .send()
            .await
            .context("Failed to add VPN client")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Add client failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse add client response")
    }

    pub async fn remove_client(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .auth_builder(reqwest::Method::DELETE, &format!("/api/v1/routing/clients/{}", id))
            .send()
            .await
            .context("Failed to remove VPN client")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Remove client failed: HTTP {} - {}", status, body);
        }
        Ok(())
    }

    pub async fn list_bypass(&self) -> anyhow::Result<Vec<AddressListEntry>> {
        let resp = self
            .auth_builder(reqwest::Method::GET, "/api/v1/routing/bypass")
            .send()
            .await
            .context("Failed to list bypass entries")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("List bypass failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse bypass response")
    }

    pub async fn add_bypass(
        &self,
        address: &str,
        comment: Option<&str>,
    ) -> anyhow::Result<AddressListEntry> {
        let mut body = serde_json::json!({ "address": address });
        if let Some(c) = comment {
            body["comment"] = serde_json::json!(c);
        }

        let resp = self
            .auth_builder(reqwest::Method::POST, "/api/v1/routing/bypass")
            .json(&body)
            .send()
            .await
            .context("Failed to add bypass entry")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Add bypass failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse add bypass response")
    }

    pub async fn remove_bypass(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .auth_builder(reqwest::Method::DELETE, &format!("/api/v1/routing/bypass/{}", id))
            .send()
            .await
            .context("Failed to remove bypass entry")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Remove bypass failed: HTTP {} - {}", status, body);
        }
        Ok(())
    }

    pub async fn routing_setup(&self) -> anyhow::Result<serde_json::Value> {
        let resp = self
            .auth_builder(reqwest::Method::POST, "/api/v1/routing/setup")
            .send()
            .await
            .context("Failed to setup PBR")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Routing setup failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse routing setup response")
    }

    pub async fn routing_teardown(&self) -> anyhow::Result<serde_json::Value> {
        let resp = self
            .auth_builder(reqwest::Method::DELETE, "/api/v1/routing/setup")
            .send()
            .await
            .context("Failed to teardown PBR")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Routing teardown failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse routing teardown response")
    }

    pub async fn routing_diagnostics(&self) -> anyhow::Result<DiagnosticsResult> {
        let resp = self
            .auth_builder(reqwest::Method::GET, "/api/v1/routing/diagnostics")
            .send()
            .await
            .context("Failed to get routing diagnostics")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Routing diagnostics failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse routing diagnostics response")
    }

    // === Users ===

    pub async fn list_users(&self) -> anyhow::Result<Vec<UserResponse>> {
        let resp = self
            .auth_builder(reqwest::Method::GET, "/api/v1/users")
            .send()
            .await
            .context("Failed to list users")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("List users failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse users response")
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: &str,
        comment: &str,
    ) -> anyhow::Result<UserResponse> {
        let resp = self
            .auth_builder(reqwest::Method::POST, "/api/v1/users")
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

    pub async fn update_user(
        &self,
        id: &str,
        role: Option<&str>,
        comment: Option<&str>,
        enabled: Option<bool>,
    ) -> anyhow::Result<UserResponse> {
        let mut body = serde_json::Map::new();
        if let Some(r) = role {
            body.insert("role".to_string(), serde_json::json!(r));
        }
        if let Some(c) = comment {
            body.insert("comment".to_string(), serde_json::json!(c));
        }
        if let Some(e) = enabled {
            body.insert("enabled".to_string(), serde_json::json!(e));
        }

        let resp = self
            .auth_builder(reqwest::Method::PUT, &format!("/api/v1/users/{}", id))
            .json(&serde_json::Value::Object(body))
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
            .auth_builder(reqwest::Method::DELETE, &format!("/api/v1/users/{}", id))
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

    pub async fn change_password(
        &self,
        id: &str,
        new_password: &str,
        current_password: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut body = serde_json::json!({ "new_password": new_password });
        if let Some(cp) = current_password {
            body["current_password"] = serde_json::json!(cp);
        }

        let resp = self
            .auth_builder(reqwest::Method::POST, &format!("/api/v1/users/{}/password", id))
            .json(&body)
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

    pub async fn get_me(&self) -> anyhow::Result<UserResponse> {
        let resp = self
            .auth_builder(reqwest::Method::GET, "/api/v1/users/me")
            .send()
            .await
            .context("Failed to get current user")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Get me failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse current user response")
    }

    pub async fn list_sessions(&self) -> anyhow::Result<Vec<Session>> {
        let resp = self
            .auth_builder(reqwest::Method::GET, "/api/v1/users/sessions")
            .send()
            .await
            .context("Failed to list sessions")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("List sessions failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse sessions response")
    }

    pub async fn kick_session(&self, session_id: &str) -> anyhow::Result<()> {
        let resp = self
            .auth_builder(
                reqwest::Method::DELETE,
                &format!("/api/v1/users/sessions/{}", session_id),
            )
            .send()
            .await
            .context("Failed to revoke session")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Kick session failed: HTTP {} - {}", status, body);
        }
        Ok(())
    }

    // === Logs ===

    pub async fn logs_history(
        &self,
        limit: usize,
        level: Option<&str>,
    ) -> anyhow::Result<Vec<LogEntry>> {
        let mut url = format!("/api/v1/logs/history?limit={}", limit);
        if let Some(l) = level {
            url.push_str(&format!("&level={}", l));
        }

        let resp = self
            .auth_builder(reqwest::Method::GET, &url)
            .send()
            .await
            .context("Failed to get log history")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Log history failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse log history response")
    }

    // === Health ===

    pub async fn health(&self) -> anyhow::Result<HealthResponse> {
        let url = self.url("/api/v1/health");
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to connect to server")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Health check failed: HTTP {} - {}", status, body);
        }
        resp.json().await.context("Failed to parse health response")
    }
}
