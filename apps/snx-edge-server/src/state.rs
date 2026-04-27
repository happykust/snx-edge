use std::sync::Arc;

use tokio::sync::{RwLock, broadcast};
use tokio_util::sync::CancellationToken;

use crate::api::logs::SharedLogBuffer;
use crate::config::AppConfig;
use crate::db::UserDb;
use crate::routeros::client::RouterOsClient;
use crate::tunnel::TunnelManager;

/// SSE event broadcast to all connected clients.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", content = "data")]
pub enum ServerEvent {
    ConnectionStatus { status: String },
    RoutingChanged,
    ConfigChanged,
    LogEntry { level: String, message: String },
}

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

        let db = UserDb::new(&config.auth.user_db).await?;

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
        })
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
