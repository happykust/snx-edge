use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{RwLock, broadcast};
use tokio_util::sync::CancellationToken;

use crate::api::logs::SharedLogBuffer;
use crate::config::AppConfig;
use crate::db::UserDb;
use crate::routeros::client::RouterOsClient;
use crate::tunnel::TunnelManager;

/// In-memory cache of `users.id -> (token_generation, fetched_at)`. Backs the
/// `require_auth` middleware's per-request generation lookup so the hot auth
/// path doesn't hit SQLite for every authenticated request. Entries expire 30s
/// after `fetched_at`; the middleware always refreshes from DB after a miss
/// or expiry. Counter-bumping helpers (`bump_token_generation`,
/// `delete_user`, `change_password`, etc.) write the new value through here so
/// the next request sees the bump immediately, without waiting for the TTL.
pub type TokenGenCache = Arc<RwLock<HashMap<String, TokenGenEntry>>>;

#[derive(Debug, Clone, Copy)]
pub struct TokenGenEntry {
    pub generation: i64,
    pub fetched_at: Instant,
}

pub use snx_edge_types::events::ServerEvent;

/// Shared application state available to all handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<AppConfig>>,
    pub config_path: Arc<String>,
    pub db: UserDb,
    pub event_tx: broadcast::Sender<ServerEvent>,
    pub jwt_secret: Arc<String>,
    pub log_buffer: SharedLogBuffer,
    pub tunnel: Arc<TunnelManager>,
    /// Cancelled when the process receives a shutdown signal. Background tasks
    /// (e.g. `db::start_cleanup_task`) subscribe via `.cancelled()` so they
    /// can exit promptly instead of being aborted mid-iteration.
    pub shutdown: CancellationToken,
    /// Cached RouterOS REST client. Built lazily on first use; invalidated
    /// (set back to `None`) when `[routeros]` configuration changes via the
    /// management API. Credential changes that come from environment
    /// variables require a process restart — re-reading env on every request
    /// would defeat the purpose of caching.
    pub routeros_client: Arc<RwLock<Option<RouterOsClient>>>,
    /// In-memory generation cache used by the require_auth middleware. See
    /// `TokenGenCache` doc for details.
    pub token_gen_cache: TokenGenCache,
    /// In-session latch that durably suspends supervisor auto-reconnect after
    /// the pre-MFA failure cap is hit (`supervisor::initiate_with_backoff`
    /// give-up). Once set, the steady-state loop stops re-arming on tunnel
    /// `Error` events — including the supervisor's own failed-connect events,
    /// which would otherwise re-trigger a fresh backoff burst forever. Cleared
    /// by an explicit API `connect` (re-arms for that session) or by the tunnel
    /// actually reaching `Connected` (a real session un-suspends future drops).
    /// Not persisted: desired-state stays in the DB; only this latch is volatile.
    pub reconnect_suspended: Arc<std::sync::atomic::AtomicBool>,
}

impl AppState {
    /// Create AppState with pre-created log_buffer and event_tx
    /// (so tracing Layer can capture from the start).
    pub async fn with_shared(
        config: AppConfig,
        config_path: String,
        log_buffer: SharedLogBuffer,
        event_tx: broadcast::Sender<ServerEvent>,
        shutdown: CancellationToken,
    ) -> anyhow::Result<Self> {
        let jwt_secret = config.jwt_secret()?;

        if jwt_secret.len() < 32 {
            anyhow::bail!(
                "JWT secret must be at least 32 bytes long (currently {} bytes). \
                 Set a stronger secret in the {} environment variable.",
                jwt_secret.len(),
                config.auth.jwt_secret_env,
            );
        }

        // Decode the optional profile-encryption key from the env. We read
        // it once at startup; rotating the key requires a restart (which is
        // operationally fine — secrets need re-encrypting anyway).
        let profile_key = config.profile_key()?;

        if profile_key.is_none() {
            // Soft warning: legacy plaintext mode is fine for backwards
            // compatibility, but operators should know they're in it.
            tracing::warn!(
                env = %config.security.profile_encryption_key_env,
                "profile encryption key not set; storing VPN profile passwords as plaintext \
                 in the SQLite database (set the env var with a 32-byte base64/hex value to \
                 enable at-rest encryption)"
            );
        }

        let db = UserDb::new_with_key(&config.auth.user_db, profile_key).await?;

        // Initialize admin user from env if database is empty
        db.ensure_admin_exists().await?;

        // Start background session cleanup (hourly) — exits when `shutdown`
        // is cancelled.
        db.clone().start_cleanup_task(shutdown.clone());

        let tunnel = Arc::new(TunnelManager::new(event_tx.clone()));

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            config_path: Arc::new(config_path),
            db,
            event_tx,
            jwt_secret: Arc::new(jwt_secret),
            log_buffer,
            tunnel,
            shutdown,
            routeros_client: Arc::new(RwLock::new(None)),
            token_gen_cache: Arc::new(RwLock::new(HashMap::new())),
            reconnect_suspended: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Update the cached token-generation entry for `user_id`. Called by
    /// every code path that bumps the on-disk counter so the next request
    /// observes the new value immediately rather than waiting out the 30s
    /// TTL. Pass `None` to evict the entry instead (e.g. after `delete_user`).
    pub async fn refresh_token_generation_cache(&self, user_id: &str, generation: Option<i64>) {
        let mut cache = self.token_gen_cache.write().await;
        match generation {
            Some(g) => {
                cache.insert(
                    user_id.to_string(),
                    TokenGenEntry {
                        generation: g,
                        fetched_at: Instant::now(),
                    },
                );
            }
            None => {
                cache.remove(user_id);
            }
        }
    }

    /// Return a `RouterOsClient`, building and caching it on first call.
    ///
    /// Rebuild is forced after `invalidate_routeros_client()` is called
    /// (e.g. on config update). Two callers that race the cold path may both
    /// build a client — that's harmless: the second `write()` simply
    /// overwrites the first cached value.
    pub async fn routeros_client(&self) -> Result<RouterOsClient, crate::error::AppError> {
        if let Some(client) = self.routeros_client.read().await.clone() {
            return Ok(client);
        }
        let config = self.config.read().await;
        let client = RouterOsClient::new(&config.routeros)?;
        drop(config);
        *self.routeros_client.write().await = Some(client.clone());
        Ok(client)
    }

    /// Drop the cached RouterOS client. Call this after mutating
    /// `[routeros]` configuration so the next request rebuilds with the new
    /// settings.
    pub async fn invalidate_routeros_client(&self) {
        *self.routeros_client.write().await = None;
    }
}
