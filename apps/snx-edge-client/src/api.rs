use std::sync::Arc;

use anyhow::Result;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

// ============================================================================
// Error types
// ============================================================================

/// API-specific errors that callers can match on.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Server returned 401 Unauthorized -- caller should trigger re-login.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Server returned 403 Forbidden.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Server returned 404 Not Found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Server returned 409 Conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Any other server-side error (4xx/5xx) with the RFC 7807 detail.
    #[error("server error ({status}): {detail}")]
    Server { status: u16, detail: String },

    /// Network / deserialization / other client-side error.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// RFC 7807 Problem Details body returned by snx-edge-server on errors.
#[derive(Debug, Deserialize)]
struct ProblemDetails {
    #[serde(default)]
    status: u16,
    #[serde(default)]
    detail: Option<String>,
}

// ============================================================================
// Response types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub connection: serde_json::Value,
    pub uptime_seconds: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnRoute {
    pub destination: String,
    pub gateway: Option<String>,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub config: serde_json::Value,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressEntry {
    #[serde(rename = ".id", default)]
    pub id: String,
    pub list: String,
    pub address: String,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub disabled: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub role: String,
    pub comment: String,
    pub enabled: bool,
    pub permissions: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub active_sessions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

// ============================================================================
// ApiClient
// ============================================================================

/// HTTP client wrapper for all snx-edge-server endpoints.
///
/// The base URL should include the scheme and host (e.g. `http://172.19.0.2:8080`).
/// All REST paths are appended under `/api/v1/`.
pub struct ApiClient {
    client: Client,
    pub base_url: Arc<std::sync::RwLock<String>>,
    pub token: Arc<RwLock<Option<String>>>,
}

impl ApiClient {
    /// Create a new client pointing at the given server.
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .use_rustls_tls()
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build HTTP client: {e}"))?;

        Ok(Self {
            client,
            base_url: Arc::new(std::sync::RwLock::new(base_url.into().trim_end_matches('/').to_string())),
            token: Arc::new(RwLock::new(None)),
        })
    }

    /// Create a new client with a pre-existing access token.
    pub fn with_token(base_url: impl Into<String>, token: String) -> Result<Self> {
        let api = Self::new(base_url)?;
        *api.token.blocking_write() = Some(token);
        Ok(api)
    }

    /// Get a shared handle to the token store.
    pub fn token_handle(&self) -> Arc<RwLock<Option<String>>> {
        Arc::clone(&self.token)
    }

    /// Get a shared handle to the base URL, e.g. to share with `SseManager`.
    pub fn base_url_handle(&self) -> Arc<std::sync::RwLock<String>> {
        Arc::clone(&self.base_url)
    }

    /// Replace the current access token.
    pub async fn set_token(&self, token: Option<String>) {
        *self.token.write().await = token;
    }

    /// Replace the base URL (e.g. when the user changes the server in the login dialog).
    pub fn set_base_url(&self, url: &str) {
        *self.base_url.write().unwrap() = url.trim_end_matches('/').to_string();
    }

    /// Read the current base URL.
    pub fn get_base_url(&self) -> String {
        self.base_url.read().unwrap().clone()
    }

    /// Build the full URL for an API path (without leading `/api/v1`).
    fn url(&self, path: &str) -> String {
        let base = self.base_url.read().unwrap();
        format!("{}/api/v1{}", *base, path)
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Map an HTTP response to an `ApiError` when the status is not success.
    async fn check_response(response: reqwest::Response) -> Result<reqwest::Response, ApiError> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        // Try to parse the RFC 7807 body for a detail message.
        let detail = match response.json::<ProblemDetails>().await {
            Ok(pd) => pd.detail.unwrap_or_else(|| status.to_string()),
            Err(_) => status.to_string(),
        };

        match status {
            StatusCode::UNAUTHORIZED => Err(ApiError::Unauthorized(detail)),
            StatusCode::FORBIDDEN => Err(ApiError::Forbidden(detail)),
            StatusCode::NOT_FOUND => Err(ApiError::NotFound(detail)),
            StatusCode::CONFLICT => Err(ApiError::Conflict(detail)),
            _ => Err(ApiError::Server {
                status: status.as_u16(),
                detail,
            }),
        }
    }

    /// Issue a GET request to `path` with the current bearer token.
    async fn auth_get(&self, path: &str) -> Result<reqwest::Response, ApiError> {
        let token = self.token.read().await.clone();
        let mut builder = self.client.get(self.url(path));
        if let Some(ref t) = token {
            builder = builder.bearer_auth(t);
        }
        let resp = builder.send().await.map_err(|e| ApiError::Other(e.into()))?;
        Self::check_response(resp).await
    }

    /// Issue a POST request with a JSON body and the current bearer token.
    async fn auth_post(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<reqwest::Response, ApiError> {
        let token = self.token.read().await.clone();
        let mut builder = self.client.post(self.url(path)).json(body);
        if let Some(ref t) = token {
            builder = builder.bearer_auth(t);
        }
        let resp = builder.send().await.map_err(|e| ApiError::Other(e.into()))?;
        Self::check_response(resp).await
    }

    /// Issue a PUT request with a JSON body and the current bearer token.
    async fn auth_put(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<reqwest::Response, ApiError> {
        let token = self.token.read().await.clone();
        let mut builder = self.client.put(self.url(path)).json(body);
        if let Some(ref t) = token {
            builder = builder.bearer_auth(t);
        }
        let resp = builder.send().await.map_err(|e| ApiError::Other(e.into()))?;
        Self::check_response(resp).await
    }

    /// Issue a DELETE request with the current bearer token.
    async fn auth_delete(&self, path: &str) -> Result<reqwest::Response, ApiError> {
        let token = self.token.read().await.clone();
        let mut builder = self.client.delete(self.url(path));
        if let Some(ref t) = token {
            builder = builder.bearer_auth(t);
        }
        let resp = builder.send().await.map_err(|e| ApiError::Other(e.into()))?;
        Self::check_response(resp).await
    }

    /// Issue a POST request *without* a body and with the current bearer token.
    async fn auth_post_empty(&self, path: &str) -> Result<reqwest::Response, ApiError> {
        let token = self.token.read().await.clone();
        let mut builder = self.client.post(self.url(path));
        if let Some(ref t) = token {
            builder = builder.bearer_auth(t);
        }
        let resp = builder.send().await.map_err(|e| ApiError::Other(e.into()))?;
        Self::check_response(resp).await
    }

    /// Public helper: issue a POST with JSON body and bearer token, returning
    /// the deserialized response.  Used by `AuthManager` and other callers that
    /// need a typed response without going through endpoint-specific wrappers.
    pub async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, ApiError> {
        let resp = self.auth_post(path, body).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    // ========================================================================
    // Tunnel
    // ========================================================================

    /// POST /api/v1/tunnel/connect
    pub async fn tunnel_connect(&self, profile_id: &str) -> Result<TunnelStatus, ApiError> {
        let body = serde_json::json!({ "profile_id": profile_id });
        let resp = self.auth_post("/tunnel/connect", &body).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// POST /api/v1/tunnel/disconnect
    pub async fn tunnel_disconnect(&self) -> Result<TunnelStatus, ApiError> {
        let resp = self.auth_post_empty("/tunnel/disconnect").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// POST /api/v1/tunnel/reconnect
    pub async fn tunnel_reconnect(&self, profile_id: &str) -> Result<TunnelStatus, ApiError> {
        let body = serde_json::json!({ "profile_id": profile_id });
        let resp = self.auth_post("/tunnel/reconnect", &body).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// GET /api/v1/tunnel/status
    pub async fn tunnel_status(&self) -> Result<TunnelStatus, ApiError> {
        let resp = self.auth_get("/tunnel/status").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// POST /api/v1/tunnel/challenge
    pub async fn tunnel_challenge(&self, code: &str) -> Result<TunnelStatus, ApiError> {
        let body = serde_json::json!({ "code": code });
        let resp = self.auth_post("/tunnel/challenge", &body).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// POST /api/v1/server/info
    pub async fn server_info(&self, server: &str) -> Result<serde_json::Value, ApiError> {
        let body = serde_json::json!({ "server": server });
        let resp = self.auth_post("/server/info", &body).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// GET /api/v1/routes
    pub async fn routes(&self) -> Result<Vec<VpnRoute>, ApiError> {
        let resp = self.auth_get("/routes").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    // ========================================================================
    // Profiles
    // ========================================================================

    /// GET /api/v1/profiles
    pub async fn list_profiles(&self) -> Result<Vec<Profile>, ApiError> {
        let resp = self.auth_get("/profiles").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// GET /api/v1/profiles/{id}
    pub async fn get_profile(&self, id: &str) -> Result<Profile, ApiError> {
        let resp = self.auth_get(&format!("/profiles/{id}")).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// POST /api/v1/profiles
    pub async fn create_profile(
        &self,
        name: &str,
        config: &serde_json::Value,
    ) -> Result<Profile, ApiError> {
        let body = serde_json::json!({
            "name": name,
            "config": config,
        });
        let resp = self.auth_post("/profiles", &body).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// PUT /api/v1/profiles/{id}
    pub async fn update_profile(
        &self,
        id: &str,
        name: Option<&str>,
        config: Option<&serde_json::Value>,
        enabled: Option<bool>,
    ) -> Result<Profile, ApiError> {
        let body = serde_json::json!({
            "name": name,
            "config": config,
            "enabled": enabled,
        });
        let resp = self.auth_put(&format!("/profiles/{id}"), &body).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// DELETE /api/v1/profiles/{id}
    pub async fn delete_profile(&self, id: &str) -> Result<(), ApiError> {
        self.auth_delete(&format!("/profiles/{id}")).await?;
        Ok(())
    }

    /// GET /api/v1/profiles/{id}/export
    pub async fn export_profile(&self, id: &str) -> Result<serde_json::Value, ApiError> {
        let resp = self.auth_get(&format!("/profiles/{id}/export")).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// POST /api/v1/profiles/import
    pub async fn import_profile(
        &self,
        name: &str,
        config: &serde_json::Value,
    ) -> Result<Profile, ApiError> {
        let body = serde_json::json!({
            "name": name,
            "config": config,
        });
        let resp = self.auth_post("/profiles/import", &body).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    // ========================================================================
    // Routing -- clients
    // ========================================================================

    /// GET /api/v1/routing/clients
    pub async fn list_clients(&self) -> Result<Vec<AddressEntry>, ApiError> {
        let resp = self.auth_get("/routing/clients").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// POST /api/v1/routing/clients
    pub async fn add_client(
        &self,
        address: &str,
        comment: Option<&str>,
    ) -> Result<AddressEntry, ApiError> {
        let body = serde_json::json!({
            "address": address,
            "comment": comment,
        });
        let resp = self.auth_post("/routing/clients", &body).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// DELETE /api/v1/routing/clients/{id}
    pub async fn remove_client(&self, id: &str) -> Result<(), ApiError> {
        self.auth_delete(&format!("/routing/clients/{id}")).await?;
        Ok(())
    }

    // ========================================================================
    // Routing -- bypass
    // ========================================================================

    /// GET /api/v1/routing/bypass
    pub async fn list_bypass(&self) -> Result<Vec<AddressEntry>, ApiError> {
        let resp = self.auth_get("/routing/bypass").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// POST /api/v1/routing/bypass
    pub async fn add_bypass(
        &self,
        address: &str,
        comment: Option<&str>,
    ) -> Result<AddressEntry, ApiError> {
        let body = serde_json::json!({
            "address": address,
            "comment": comment,
        });
        let resp = self.auth_post("/routing/bypass", &body).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// DELETE /api/v1/routing/bypass/{id}
    pub async fn remove_bypass(&self, id: &str) -> Result<(), ApiError> {
        self.auth_delete(&format!("/routing/bypass/{id}")).await?;
        Ok(())
    }

    // ========================================================================
    // Routing -- PBR management
    // ========================================================================

    /// GET /api/v1/routing/status
    pub async fn routing_status(&self) -> Result<serde_json::Value, ApiError> {
        let resp = self.auth_get("/routing/status").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// GET /api/v1/routing/diagnostics
    pub async fn routing_diagnostics(&self) -> Result<serde_json::Value, ApiError> {
        let resp = self.auth_get("/routing/diagnostics").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// POST /api/v1/routing/setup
    pub async fn routing_setup(&self) -> Result<serde_json::Value, ApiError> {
        let resp = self.auth_post_empty("/routing/setup").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// DELETE /api/v1/routing/setup
    pub async fn routing_teardown(&self) -> Result<serde_json::Value, ApiError> {
        let resp = self.auth_delete("/routing/setup").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    // ========================================================================
    // Users
    // ========================================================================

    /// GET /api/v1/users
    pub async fn list_users(&self) -> Result<Vec<UserResponse>, ApiError> {
        let resp = self.auth_get("/users").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// POST /api/v1/users
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: &str,
        comment: &str,
    ) -> Result<UserResponse, ApiError> {
        let body = serde_json::json!({
            "username": username,
            "password": password,
            "role": role,
            "comment": comment,
        });
        let resp = self.auth_post("/users", &body).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// PUT /api/v1/users/{id}
    pub async fn update_user(
        &self,
        id: &str,
        role: Option<&str>,
        comment: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<UserResponse, ApiError> {
        let body = serde_json::json!({
            "role": role,
            "comment": comment,
            "enabled": enabled,
        });
        let resp = self.auth_put(&format!("/users/{id}"), &body).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// DELETE /api/v1/users/{id}
    pub async fn delete_user(&self, id: &str) -> Result<(), ApiError> {
        self.auth_delete(&format!("/users/{id}")).await?;
        Ok(())
    }

    /// POST /api/v1/users/{id}/password
    pub async fn change_user_password(
        &self,
        id: &str,
        new_password: &str,
        caller_password: &str,
    ) -> Result<(), ApiError> {
        let body = serde_json::json!({
            "new_password": new_password,
            "caller_password": caller_password,
        });
        self.auth_post(&format!("/users/{id}/password"), &body)
            .await?;
        Ok(())
    }

    /// GET /api/v1/users/me
    pub async fn get_me(&self) -> Result<UserResponse, ApiError> {
        let resp = self.auth_get("/users/me").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// POST /api/v1/users/me/password
    pub async fn change_my_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), ApiError> {
        let body = serde_json::json!({
            "current_password": current_password,
            "new_password": new_password,
        });
        self.auth_post("/users/me/password", &body).await?;
        Ok(())
    }

    /// GET /api/v1/users/sessions
    pub async fn list_sessions(&self) -> Result<Vec<Session>, ApiError> {
        let resp = self.auth_get("/users/sessions").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    /// DELETE /api/v1/users/sessions/{id}
    pub async fn revoke_session(&self, id: &str) -> Result<(), ApiError> {
        self.auth_delete(&format!("/users/sessions/{id}")).await?;
        Ok(())
    }

    // ========================================================================
    // Config
    // ========================================================================

    /// GET /api/v1/config
    pub async fn get_config(&self) -> Result<serde_json::Value, ApiError> {
        let resp = self.auth_get("/config").await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }

    // ========================================================================
    // Health  (public, no auth)
    // ========================================================================

    /// GET /api/v1/health
    pub async fn health(&self) -> Result<serde_json::Value, ApiError> {
        let resp = self
            .client
            .get(self.url("/health"))
            .send()
            .await
            .map_err(|e| ApiError::Other(e.into()))?;

        let resp = Self::check_response(resp).await?;
        resp.json().await.map_err(|e| ApiError::Other(e.into()))
    }
}
