use std::sync::Arc;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::api::ApiClient;

// === JWT payload (client-side, no signature validation) ===

#[derive(Debug, Deserialize)]
struct JwtPayload {
    #[allow(dead_code)]
    sub: String,
    role: String,
    #[allow(dead_code)]
    exp: i64,
}

// === Server response types ===

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    #[allow(dead_code)]
    token_type: String,
    expires_in: i64,
}

// === AuthManager ===

pub struct AuthManager {
    api: Arc<ApiClient>,
    refresh_token: Arc<RwLock<Option<String>>>,
    expires_at: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Prevents concurrent token refreshes from racing each other.
    refresh_lock: Mutex<()>,
}

impl AuthManager {
    pub fn new(api: Arc<ApiClient>) -> Self {
        Self {
            api,
            refresh_token: Arc::new(RwLock::new(None)),
            expires_at: Arc::new(RwLock::new(None)),
            refresh_lock: Mutex::new(()),
        }
    }

    /// Authenticate with username/password, store tokens.
    pub async fn login(
        &self,
        server_url: &str,
        username: &str,
        password: &str,
    ) -> Result<()> {
        let body = serde_json::json!({
            "username": username,
            "password": password,
        });

        let resp: TokenResponse = self
            .api
            .post("/auth/login", &body)
            .await
            .context("login request failed")?;

        self.store_tokens(&resp, server_url).await?;

        info!("logged in as {username}");
        Ok(())
    }

    /// Ensure the current access token is still valid.
    /// If it expires within 60 seconds, refresh it automatically.
    /// The refresh_lock prevents concurrent callers from racing.
    pub async fn ensure_authenticated(&self) -> Result<()> {
        let _guard = self.refresh_lock.lock().await;

        let expires = {
            let guard = self.expires_at.read().await;
            *guard
        };

        let Some(exp) = expires else {
            bail!("not authenticated");
        };

        if Utc::now() + Duration::seconds(60) < exp {
            // Token still valid for more than 60s
            return Ok(());
        }

        debug!("access token expiring soon, refreshing");
        self.do_refresh_inner().await
    }

    /// Try to restore a session from a saved refresh token in the keyring.
    pub async fn load_saved_token(&self, server_url: &str) -> Result<()> {
        let entry = keyring::Entry::new("snx-edge", server_url)
            .context("failed to open keyring entry")?;

        let saved = entry
            .get_password()
            .context("no saved refresh token in keyring")?;

        {
            let mut guard = self.refresh_token.write().await;
            *guard = Some(saved);
        }

        self.do_refresh().await.context("saved refresh token is expired or invalid")?;
        info!("restored session from keyring for {server_url}");
        Ok(())
    }

    /// Clear all tokens from memory and keyring.
    pub async fn logout(&self, server_url: &str) -> Result<()> {
        {
            let mut guard = self.api.token.write().await;
            *guard = None;
        }
        {
            let mut guard = self.refresh_token.write().await;
            *guard = None;
        }
        {
            let mut guard = self.expires_at.write().await;
            *guard = None;
        }

        if let Ok(entry) = keyring::Entry::new("snx-edge", server_url) {
            if let Err(e) = entry.delete_credential() {
                warn!("failed to remove keyring credential: {e}");
            }
        }

        info!("logged out");
        Ok(())
    }

    /// Check whether an access token is currently held.
    pub async fn is_authenticated(&self) -> bool {
        let guard = self.api.token.read().await;
        guard.is_some()
    }

    /// Decode the JWT access token payload to extract the user role.
    /// This is a client-side convenience -- no signature validation.
    pub async fn role(&self) -> Option<String> {
        let guard = self.api.token.read().await;
        let token = guard.as_deref()?;
        decode_jwt_payload(token)
            .ok()
            .map(|p| p.role)
    }

    // ------ internal helpers ------

    /// Public-facing refresh that acquires the refresh_lock.
    async fn do_refresh(&self) -> Result<()> {
        let _guard = self.refresh_lock.lock().await;
        self.do_refresh_inner().await
    }

    /// Inner refresh logic, must be called with refresh_lock already held.
    async fn do_refresh_inner(&self) -> Result<()> {
        let rt = {
            let guard = self.refresh_token.read().await;
            guard.clone()
        };

        let Some(rt) = rt else {
            bail!("no refresh token available");
        };

        let body = serde_json::json!({ "refresh_token": rt });

        let resp: TokenResponse = self
            .api
            .post("/auth/refresh", &body)
            .await
            .context("refresh request failed")?;

        // We don't know server_url here, so just update in-memory tokens.
        // The keyring is updated during login / load_saved_token.
        self.apply_tokens(&resp).await;

        debug!("access token refreshed successfully");
        Ok(())
    }

    async fn store_tokens(&self, resp: &TokenResponse, server_url: &str) -> Result<()> {
        self.apply_tokens(resp).await;

        // Persist refresh token in keyring
        let entry = keyring::Entry::new("snx-edge", server_url)
            .context("failed to open keyring entry")?;

        entry
            .set_password(&resp.refresh_token)
            .context("failed to save refresh token to keyring")?;

        Ok(())
    }

    async fn apply_tokens(&self, resp: &TokenResponse) {
        // Write access token into the shared ApiClient slot
        {
            let mut guard = self.api.token.write().await;
            *guard = Some(resp.access_token.clone());
        }

        // Store refresh token
        {
            let mut guard = self.refresh_token.write().await;
            *guard = Some(resp.refresh_token.clone());
        }

        // Compute expiry timestamp
        {
            let mut guard = self.expires_at.write().await;
            *guard = Some(Utc::now() + Duration::seconds(resp.expires_in));
        }
    }
}

/// Decode the payload (second segment) of a JWT without verifying the signature.
fn decode_jwt_payload(token: &str) -> Result<JwtPayload> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        bail!("malformed JWT: expected 3 segments");
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .context("failed to base64-decode JWT payload")?;

    let payload: JwtPayload =
        serde_json::from_slice(&payload_bytes).context("failed to parse JWT payload JSON")?;

    Ok(payload)
}
