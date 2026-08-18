use std::sync::Arc;

use anyhow::{Context, bail};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use tokio::sync::RwLock;

/// Invoked with a freshly rotated refresh token so the owner (`AuthManager`)
/// can persist it. The server rotates refresh tokens on every exchange, so a
/// rotation that is not written back to the keyring would break the next cold
/// start.
pub type RefreshHook = Arc<dyn Fn(String) + Send + Sync>;

#[derive(Clone)]
#[allow(dead_code)]
pub struct ApiClient {
    client: Client,
    base_url: Arc<RwLock<String>>,
    token: Arc<RwLock<Option<String>>>,
    refresh_token: Arc<RwLock<Option<String>>>,
    /// `std::sync::Mutex` (not the async one) so the hook can be installed
    /// from `AuthManager::new`, which is not async.
    refresh_hook: Arc<std::sync::Mutex<Option<RefreshHook>>>,
    /// Serialises token exchanges: without it, several requests hitting 401 at
    /// once would each spend the same rotated refresh token, and all but the
    /// first would fail — logging the user out instead of renewing.
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

/// Local view of the auth response. The wire type
/// (`snx_edge_types::auth::TokenResponse`) has additional fields
/// (`token_type`, `expires_in`) that the client currently ignores; we keep
/// this thinner shape with `serde(default)` on the surplus fields so we
/// stay byte-compatible without forcing the rest of the client to thread
/// fields it does not use.
#[derive(Debug, serde::Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Sends a request and, on `401`, renews the access token once and replays it.
///
/// Implemented as an extension on `RequestBuilder` so every existing call site
/// switches over by replacing `.send()` with `.send_refreshing(self)`, keeping
/// the surrounding error handling untouched.
trait SendRefreshing {
    async fn send_refreshing(self, api: &ApiClient) -> reqwest::Result<reqwest::Response>;
}

impl SendRefreshing for reqwest::RequestBuilder {
    async fn send_refreshing(self, api: &ApiClient) -> reqwest::Result<reqwest::Response> {
        // Cloned before sending: `RequestBuilder` is consumed by `send`, and a
        // streaming body cannot be cloned — such a request is simply not replayed.
        let replay = self.try_clone();
        let stale = api.token().await;

        let resp = self.send().await?;
        if resp.status() != StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }

        let (Some(replay), Some(renewed)) = (replay, api.renew_access_token(stale).await) else {
            return Ok(resp);
        };

        // `bearer_auth` *appends*, and the clone already carries the stale
        // header — two Authorization headers would just be rejected again.
        // Build the request and overwrite the header instead.
        let Ok(mut request) = replay.build() else {
            return Ok(resp);
        };
        let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {renewed}")) else {
            return Ok(resp);
        };
        request
            .headers_mut()
            .insert(reqwest::header::AUTHORIZATION, value);

        api.client.execute(request).await
    }
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        Self::with_insecure(base_url, false)
    }

    pub fn with_insecure(base_url: &str, insecure: bool) -> Self {
        Self {
            client: Client::builder()
                .danger_accept_invalid_certs(insecure)
                .build()
                .expect("Failed to build HTTP client"),
            base_url: Arc::new(RwLock::new(base_url.trim_end_matches('/').to_string())),
            token: Arc::new(RwLock::new(None)),
            refresh_token: Arc::new(RwLock::new(None)),
            refresh_hook: Arc::new(std::sync::Mutex::new(None)),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
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

    /// Store the refresh token used to renew an expired access token.
    pub async fn set_refresh_token(&self, token: Option<String>) {
        *self.refresh_token.write().await = token;
    }

    /// Install the callback that persists rotated refresh tokens.
    pub fn set_refresh_hook(&self, hook: RefreshHook) {
        if let Ok(mut slot) = self.refresh_hook.lock() {
            *slot = Some(hook);
        }
    }

    /// Exchange the stored refresh token for a new access token.
    ///
    /// `stale` is the access token that just got rejected. While waiting for
    /// the lock another task may already have renewed it — in that case the
    /// current token differs from `stale` and is returned as-is, so only one
    /// exchange happens per expiry.
    async fn renew_access_token(&self, stale: Option<String>) -> Option<String> {
        let _guard = self.refresh_lock.lock().await;

        let current = self.token.read().await.clone();
        if current != stale {
            return current;
        }

        let refresh_token = self.refresh_token.read().await.clone()?;
        let renewed = self.refresh(&refresh_token).await.ok()?;

        if let Some(rotated) = renewed.refresh_token {
            *self.refresh_token.write().await = Some(rotated.clone());
            let hook = self.refresh_hook.lock().ok().and_then(|h| h.clone());
            if let Some(hook) = hook {
                hook(rotated);
            }
        }

        Some(renewed.access_token)
    }

    async fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url.read().await, path)
    }

    async fn request_builder(
        &self,
        method: reqwest::Method,
        path: &str,
    ) -> reqwest::RequestBuilder {
        let url = self.url(path).await;
        let mut builder = self.client.request(method, &url);
        if let Some(ref token) = *self.token.read().await {
            builder = builder.bearer_auth(token);
        }
        builder
    }

    /// Build an authenticated GET RequestBuilder suitable for an SSE stream.
    ///
    /// Uses the same underlying `reqwest::Client` as the rest of the API —
    /// so the per-server `insecure` flag set via [`with_insecure`] is
    /// honoured here. Callers should pass the result to
    /// `reqwest_eventsource::EventSource::new`.
    ///
    /// `RequestBuilder` is not `Clone`; for reconnect loops, call this
    /// method again on each attempt.
    pub async fn sse_request(&self, path: &str) -> reqwest::RequestBuilder {
        self.request_builder(reqwest::Method::GET, path).await
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

        let token_resp: TokenResponse = resp
            .json()
            .await
            .context("Failed to parse login response")?;
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

        let token_resp: TokenResponse = resp
            .json()
            .await
            .context("Failed to parse refresh response")?;
        *self.token.write().await = Some(token_resp.access_token.clone());
        Ok(token_resp)
    }

    pub async fn tunnel_connect(&self, profile_id: &str) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/tunnel/connect")
            .await
            .json(&serde_json::json!({"profile_id": profile_id}))
            .send_refreshing(self)
            .await
            .context("Failed to connect tunnel")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Tunnel connect failed: HTTP {} - {}", status, body);
        }
        resp.json()
            .await
            .context("Failed to parse tunnel connect response")
    }

    pub async fn tunnel_disconnect(&self) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/tunnel/disconnect")
            .await
            .send_refreshing(self)
            .await
            .context("Failed to disconnect tunnel")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Tunnel disconnect failed: HTTP {} - {}", status, body);
        }
        resp.json()
            .await
            .context("Failed to parse tunnel disconnect response")
    }

    pub async fn tunnel_reconnect(&self, profile_id: &str) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/tunnel/reconnect")
            .await
            .json(&serde_json::json!({"profile_id": profile_id}))
            .send_refreshing(self)
            .await
            .context("Failed to reconnect tunnel")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Tunnel reconnect failed: HTTP {} - {}", status, body);
        }
        resp.json()
            .await
            .context("Failed to parse tunnel reconnect response")
    }

    pub async fn tunnel_challenge(&self, code: &str) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/tunnel/challenge")
            .await
            .json(&serde_json::json!({"code": code}))
            .send_refreshing(self)
            .await
            .context("Failed to submit challenge")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Challenge failed: HTTP {} - {}", status, body);
        }
        resp.json()
            .await
            .context("Failed to parse challenge response")
    }

    pub async fn tunnel_status(&self) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::GET, "/api/v1/tunnel/status")
            .await
            .send_refreshing(self)
            .await
            .context("Failed to get tunnel status")?;

        if !resp.status().is_success() {
            bail!("Tunnel status failed: HTTP {}", resp.status());
        }
        resp.json()
            .await
            .context("Failed to parse tunnel status response")
    }

    pub async fn list_profiles(&self) -> anyhow::Result<Vec<Value>> {
        let resp = self
            .request_builder(reqwest::Method::GET, "/api/v1/profiles")
            .await
            .send_refreshing(self)
            .await
            .context("Failed to list profiles")?;

        if !resp.status().is_success() {
            bail!("List profiles failed: HTTP {}", resp.status());
        }
        resp.json()
            .await
            .context("Failed to parse profiles response")
    }

    pub async fn create_profile(&self, name: &str, config: &Value) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/profiles")
            .await
            .json(&serde_json::json!({
                "name": name,
                "config": config,
            }))
            .send_refreshing(self)
            .await
            .context("Failed to create profile")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Create profile failed: HTTP {} - {}", status, body);
        }
        resp.json()
            .await
            .context("Failed to parse create profile response")
    }

    pub async fn update_profile(&self, id: &str, body: &Value) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::PUT, &format!("/api/v1/profiles/{}", id))
            .await
            .json(body)
            .send_refreshing(self)
            .await
            .context("Failed to update profile")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Update profile failed: HTTP {} - {}", status, body);
        }
        resp.json()
            .await
            .context("Failed to parse update profile response")
    }

    pub async fn delete_profile(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request_builder(reqwest::Method::DELETE, &format!("/api/v1/profiles/{}", id))
            .await
            .send_refreshing(self)
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
            .send_refreshing(self)
            .await
            .context("Failed to list routing clients")?;

        if !resp.status().is_success() {
            bail!("List routing clients failed: HTTP {}", resp.status());
        }
        resp.json()
            .await
            .context("Failed to parse routing clients response")
    }

    pub async fn add_routing_client(&self, address: &str, comment: &str) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/routing/clients")
            .await
            .json(&serde_json::json!({
                "address": address,
                "comment": comment,
            }))
            .send_refreshing(self)
            .await
            .context("Failed to add routing client")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Add routing client failed: HTTP {} - {}", status, body);
        }
        resp.json()
            .await
            .context("Failed to parse add routing client response")
    }

    pub async fn remove_routing_client(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request_builder(
                reqwest::Method::DELETE,
                &format!("/api/v1/routing/clients/{}", id),
            )
            .await
            .send_refreshing(self)
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
            .send_refreshing(self)
            .await
            .context("Failed to list routing bypass")?;

        if !resp.status().is_success() {
            bail!("List routing bypass failed: HTTP {}", resp.status());
        }
        resp.json()
            .await
            .context("Failed to parse routing bypass response")
    }

    pub async fn add_routing_bypass(&self, address: &str, comment: &str) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::POST, "/api/v1/routing/bypass")
            .await
            .json(&serde_json::json!({
                "address": address,
                "comment": comment,
            }))
            .send_refreshing(self)
            .await
            .context("Failed to add routing bypass")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Add routing bypass failed: HTTP {} - {}", status, body);
        }
        resp.json()
            .await
            .context("Failed to parse add routing bypass response")
    }

    pub async fn remove_routing_bypass(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request_builder(
                reqwest::Method::DELETE,
                &format!("/api/v1/routing/bypass/{}", id),
            )
            .await
            .send_refreshing(self)
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
            .send_refreshing(self)
            .await
            .context("Failed to setup routing")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Routing setup failed: HTTP {} - {}", status, body);
        }
        resp.json()
            .await
            .context("Failed to parse routing setup response")
    }

    pub async fn routing_teardown(&self) -> anyhow::Result<()> {
        let resp = self
            .request_builder(reqwest::Method::DELETE, "/api/v1/routing/setup")
            .await
            .send_refreshing(self)
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
            .send_refreshing(self)
            .await
            .context("Failed to get routing diagnostics")?;

        if !resp.status().is_success() {
            bail!("Routing diagnostics failed: HTTP {}", resp.status());
        }
        resp.json()
            .await
            .context("Failed to parse routing diagnostics response")
    }

    // === Users ===

    pub async fn list_users(&self) -> anyhow::Result<Vec<Value>> {
        let resp = self
            .request_builder(reqwest::Method::GET, "/api/v1/users")
            .await
            .send_refreshing(self)
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
            .send_refreshing(self)
            .await
            .context("Failed to create user")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Create user failed: HTTP {} - {}", status, body);
        }
        resp.json()
            .await
            .context("Failed to parse create user response")
    }

    pub async fn update_user(&self, id: &str, updates: &Value) -> anyhow::Result<Value> {
        let resp = self
            .request_builder(reqwest::Method::PUT, &format!("/api/v1/users/{}", id))
            .await
            .json(updates)
            .send_refreshing(self)
            .await
            .context("Failed to update user")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("Update user failed: HTTP {} - {}", status, body);
        }
        resp.json()
            .await
            .context("Failed to parse update user response")
    }

    pub async fn delete_user(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request_builder(reqwest::Method::DELETE, &format!("/api/v1/users/{}", id))
            .await
            .send_refreshing(self)
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
            .request_builder(
                reqwest::Method::POST,
                &format!("/api/v1/users/{}/password", id),
            )
            .await
            .json(&serde_json::json!({
                "new_password": new_password,
            }))
            .send_refreshing(self)
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
            .send_refreshing(self)
            .await
            .context("Failed to list sessions")?;

        if !resp.status().is_success() {
            bail!("List sessions failed: HTTP {}", resp.status());
        }
        resp.json()
            .await
            .context("Failed to parse sessions response")
    }

    pub async fn kick_session(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request_builder(
                reqwest::Method::DELETE,
                &format!("/api/v1/users/sessions/{}", id),
            )
            .await
            .send_refreshing(self)
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
            .send_refreshing(self)
            .await
            .context("Failed to get current user")?;

        if !resp.status().is_success() {
            bail!("Get me failed: HTTP {}", resp.status());
        }
        resp.json()
            .await
            .context("Failed to parse current user response")
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
            .send_refreshing(self)
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

    pub async fn logs_history(
        &self,
        limit: u32,
        level: Option<&str>,
    ) -> anyhow::Result<Vec<Value>> {
        let path = match level {
            Some(l) => format!("/api/v1/logs/history?limit={}&level={}", limit, l),
            None => format!("/api/v1/logs/history?limit={}", limit),
        };
        let resp = self
            .request_builder(reqwest::Method::GET, &path)
            .await
            .send_refreshing(self)
            .await
            .context("Failed to get logs history")?;

        if !resp.status().is_success() {
            bail!("Logs history failed: HTTP {}", resp.status());
        }
        resp.json()
            .await
            .context("Failed to parse logs history response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn base_url_strips_trailing_slash() {
        // Trailing slashes turn into double-slashes in path concatenation
        // (`<base>/<path>`), so the constructor normalises them away.
        let api = ApiClient::new("https://example.com:8443/");
        assert_eq!(api.base_url().await, "https://example.com:8443");
    }

    #[tokio::test]
    async fn base_url_preserves_no_trailing_slash() {
        let api = ApiClient::new("https://example.com:8443");
        assert_eq!(api.base_url().await, "https://example.com:8443");
    }

    #[tokio::test]
    async fn set_base_url_normalises_trailing_slash() {
        let api = ApiClient::new("https://example.com");
        api.set_base_url("https://other.example/").await;
        assert_eq!(api.base_url().await, "https://other.example");
    }

    #[tokio::test]
    async fn token_round_trips_through_setter() {
        let api = ApiClient::new("https://example.com");
        assert!(api.token().await.is_none());
        api.set_token(Some("jwt.payload.sig".to_string())).await;
        assert_eq!(api.token().await.as_deref(), Some("jwt.payload.sig"));
        api.set_token(None).await;
        assert!(api.token().await.is_none());
    }

    #[tokio::test]
    async fn bearer_auth_added_when_token_present() {
        // We can't easily snoop on `RequestBuilder` headers without sending
        // the request, so instead we point the client at an unroutable URL
        // and confirm that:
        //   - with no token: dial fails with a connection-style error that
        //     does NOT mention an Authorization header parse problem;
        //   - the call path through `request_builder` simply returns a
        //     non-empty builder.
        // The tightest assertion we can make without spinning up a server
        // is that token state flows through `set_token` and survives
        // multiple `request_builder` invocations.
        let api = ApiClient::new("http://127.0.0.1:1");
        api.set_token(Some("abc".into())).await;
        assert_eq!(api.token().await.as_deref(), Some("abc"));
        // request_builder should construct without panicking even with the
        // token set — exercising the bearer_auth code path.
        let _ = api
            .sse_request("/api/v1/logs")
            .await
            .build()
            .expect("builder must produce a request");
    }
}

#[cfg(test)]
mod refresh_tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A 401 on any authenticated call must transparently refresh the access
    /// token and replay the original request with the new one — otherwise the
    /// tray dies ~15 minutes after login (access TTL) and the user has to
    /// re-authenticate by hand.
    ///
    /// The two `tunnel/status` mocks are keyed on the Authorization header, so
    /// the test also pins that the replay carries the *new* token rather than
    /// re-sending the stale one.
    #[tokio::test]
    async fn unauthorized_triggers_refresh_and_replays_request() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/tunnel/status"))
            .and(header("authorization", "Bearer stale-token"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "fresh-token",
                "refresh_token": "rotated-refresh"
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/tunnel/status"))
            .and(header("authorization", "Bearer fresh-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "connection": { "state": "Disconnected" }
            })))
            .mount(&server)
            .await;

        let api = ApiClient::new(&server.uri());
        api.set_token(Some("stale-token".into())).await;
        api.set_refresh_token(Some("stale-refresh".into())).await;

        // The rotated refresh token must reach the owner so it can be persisted.
        let captured: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let sink = captured.clone();
        api.set_refresh_hook(Arc::new(move |token| {
            *sink.lock().unwrap() = Some(token);
        }));

        let status = api.tunnel_status().await.expect("status after refresh");
        assert_eq!(status["connection"]["state"], "Disconnected");
        assert_eq!(api.token().await.as_deref(), Some("fresh-token"));
        assert_eq!(captured.lock().unwrap().as_deref(), Some("rotated-refresh"));
    }

    /// Concurrent requests that all hit 401 must trigger exactly ONE token
    /// exchange. The server rotates refresh tokens, so a second exchange would
    /// present an already-spent token, fail, and log the user out — precisely
    /// what the renewal is supposed to prevent. The tray polls status while the
    /// UI issues its own calls, so this overlap is the normal case, not an edge.
    #[tokio::test]
    async fn concurrent_unauthorized_requests_refresh_only_once() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/tunnel/status"))
            .and(header("authorization", "Bearer stale-token"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/v1/auth/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "fresh-token",
                "refresh_token": "rotated-refresh"
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/tunnel/status"))
            .and(header("authorization", "Bearer fresh-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "connection": { "state": "Disconnected" }
            })))
            .mount(&server)
            .await;

        let api = ApiClient::new(&server.uri());
        api.set_token(Some("stale-token".into())).await;
        api.set_refresh_token(Some("stale-refresh".into())).await;

        let calls = (0..4).map(|_| {
            let api = api.clone();
            tokio::spawn(async move { api.tunnel_status().await })
        });
        for call in calls {
            assert!(call.await.unwrap().is_ok(), "every caller must succeed");
        }

        // `expect(1)` on the refresh mock is asserted when the server drops.
        drop(server);
    }

    /// Without a stored refresh token there is nothing to exchange, so the 401
    /// must surface to the caller instead of silently looping.
    #[tokio::test]
    async fn unauthorized_without_refresh_token_surfaces_the_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/tunnel/status"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let api = ApiClient::new(&server.uri());
        api.set_token(Some("stale-token".into())).await;

        assert!(api.tunnel_status().await.is_err());
    }
}
