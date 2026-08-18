use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use anyhow::Context;
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

/// Persist a refresh token: eager cache update, then write-through to the
/// keyring on a blocking thread.
async fn persist_refresh_token(server_url: String, token: String) {
    if let Ok(mut cache) = token_cache().lock() {
        cache.insert(server_url.clone(), token.clone());
    }

    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(entry) = keyring::Entry::new("snx-edge", &server_url) {
            let _ = entry.set_password(&token);
        }
    })
    .await;
}

impl AuthManager {
    pub fn new(api: ApiClient, server_url: &str) -> Self {
        // The client renews expired access tokens on its own; the server
        // rotates the refresh token on every exchange, so the rotated one has
        // to reach the keyring or the next cold start would have nothing valid
        // to restore from.
        let hook_url = server_url.to_string();
        api.set_refresh_hook(Arc::new(move |rotated| {
            tokio::spawn(persist_refresh_token(hook_url.clone(), rotated));
        }));

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
            self.api
                .set_refresh_token(Some(refresh_token.clone()))
                .await;
        }
        Ok(())
    }

    pub async fn refresh(&self) -> anyhow::Result<()> {
        let refresh_token = self
            .load_saved_token()
            .await
            .context("No saved refresh token")?;
        let token_resp = self.api.refresh(&refresh_token).await?;

        let current = token_resp.refresh_token.clone().unwrap_or(refresh_token);
        if token_resp.refresh_token.is_some() {
            self.save_refresh_token(&current).await;
        }
        // Hand it to the client so it can renew on its own from now on.
        self.api.set_refresh_token(Some(current)).await;
        Ok(())
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
        persist_refresh_token(self.server_url.clone(), token.to_string()).await;
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

    /// Test-only: seed the in-memory token cache for a server URL. Used by
    /// unit tests to verify the cache fast-path without touching the OS
    /// keyring (which would prompt or fail in CI).
    #[cfg(test)]
    fn seed_cache_for_tests(server_url: &str, token: &str) {
        if let Ok(mut cache) = token_cache().lock() {
            cache.insert(server_url.to_string(), token.to_string());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ApiClient;

    /// Each test uses a unique server URL key so the process-wide cache
    /// can be poked without inter-test interference. Using the test name
    /// guarantees uniqueness without needing `serial_test`.
    fn unique_url(suffix: &str) -> String {
        format!("https://test-cache-{suffix}.invalid")
    }

    #[tokio::test]
    async fn token_cache_hit_returns_value_without_keyring_call() {
        // Seeding the cache directly bypasses the keyring entirely. If
        // `load_saved_token` honours the cache, the seeded value comes
        // back; if it skipped straight to keyring, the call would block
        // or return None depending on host configuration. We assert the
        // cache hit and accept that as proof of the fast-path.
        let url = unique_url("hit");
        AuthManager::seed_cache_for_tests(&url, "cached-token");

        let api = ApiClient::new(&url);
        let auth = AuthManager::new(api, &url);
        let token = auth.load_saved_token().await;

        assert_eq!(token.as_deref(), Some("cached-token"));
    }

    #[tokio::test]
    async fn role_returns_none_without_token() {
        let url = unique_url("role-none");
        let api = ApiClient::new(&url);
        let auth = AuthManager::new(api, &url);
        // No token has been set on the underlying ApiClient.
        assert!(auth.role().await.is_none());
    }

    #[tokio::test]
    async fn role_decodes_jwt_payload() {
        // Construct a JWT with a known payload. We don't sign it — only the
        // payload section is decoded by `role()`.
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"role":"admin","sub":"u1"}"#);
        let token = format!("{header}.{payload}.sig");

        let url = unique_url("role-admin");
        let api = ApiClient::new(&url);
        api.set_token(Some(token)).await;
        let auth = AuthManager::new(api, &url);

        assert_eq!(auth.role().await.as_deref(), Some("admin"));
    }
}
