use std::sync::Arc;

use tokio::sync::{broadcast, RwLock};

use crate::api::logs::SharedLogBuffer;
use crate::config::AppConfig;
use crate::db::UserDb;
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
}

impl AppState {
    /// Create AppState with pre-created log_buffer and event_tx
    /// (so tracing Layer can capture from the start).
    pub async fn with_shared(
        config: AppConfig,
        config_path: String,
        log_buffer: SharedLogBuffer,
        event_tx: broadcast::Sender<ServerEvent>,
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

        // Start background session cleanup (hourly)
        db.start_cleanup_task();

        let tunnel = Arc::new(TunnelManager::new(event_tx.clone()));

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            config_path: Arc::new(config_path),
            db,
            event_tx,
            jwt_secret: Arc::new(jwt_secret),
            log_buffer,
            tunnel,
        })
    }
}
