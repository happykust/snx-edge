use axum::extract::State;
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::Deserialize;

use crate::api::auth::{Claims, has_permission};
use crate::error::AppError;
use crate::state::{AppState, ServerEvent};

/// GET /api/v1/config — return server infrastructure config (no VPN settings).
async fn get_config(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !has_permission(&claims, "config.read") {
        return Err(AppError::Forbidden(
            "permission 'config.read' required".to_string(),
        ));
    }

    let config = state.config.read().await;

    // Return only non-sensitive server settings
    Ok(Json(serde_json::json!({
        "api": {
            "listen": config.api.listen,
            "tls_enabled": config.api.tls_cert.is_some(),
        },
        "auth": {
            "max_login_attempts": config.auth.max_login_attempts,
            "lockout_duration_minutes": config.auth.lockout_duration_minutes,
            "access_token_ttl_minutes": config.auth.access_token_ttl_minutes,
            "refresh_token_ttl_days": config.auth.refresh_token_ttl_days,
        },
        "routeros": {
            "tls_skip_verify": config.routeros.tls_skip_verify,
            "comment_tag": config.routeros.comment_tag,
            "address_list_vpn": config.routeros.address_list_vpn,
            "address_list_bypass": config.routeros.address_list_bypass,
            "routing_table": config.routeros.routing_table,
            "auto_setup": config.routeros.auto_setup,
        },
        "logging": {
            "level": config.logging.level,
            "buffer_size": config.logging.buffer_size,
        },
    })))
}

// --- Partial update request types (only non-sensitive fields) ---

#[derive(Debug, Deserialize)]
struct UpdateConfigRequest {
    #[serde(default)]
    api: Option<UpdateApiConfig>,
    #[serde(default)]
    auth: Option<UpdateAuthConfig>,
    #[serde(default)]
    routeros: Option<UpdateRouterOsConfig>,
    #[serde(default)]
    logging: Option<UpdateLoggingConfig>,
}

#[derive(Debug, Deserialize)]
struct UpdateApiConfig {
    listen: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateAuthConfig {
    max_login_attempts: Option<u32>,
    lockout_duration_minutes: Option<u32>,
    access_token_ttl_minutes: Option<u64>,
    refresh_token_ttl_days: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct UpdateRouterOsConfig {
    tls_skip_verify: Option<bool>,
    comment_tag: Option<String>,
    address_list_vpn: Option<String>,
    address_list_bypass: Option<String>,
    routing_table: Option<String>,
    auto_setup: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UpdateLoggingConfig {
    level: Option<String>,
    buffer_size: Option<usize>,
}

/// PUT /api/v1/config — update global configuration (partial updates).
///
/// Sensitive fields (`jwt_secret_env`, `user_db`, `host_env`, `user_env`,
/// `password_env`, TLS cert paths) cannot be changed through the API.
async fn update_config(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !has_permission(&claims, "config.write") {
        return Err(AppError::Forbidden(
            "permission 'config.write' required".to_string(),
        ));
    }

    // Validate logging level if provided
    if let Some(ref logging) = req.logging {
        if let Some(ref level) = logging.level {
            const VALID_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];
            if !VALID_LEVELS.contains(&level.as_str()) {
                return Err(AppError::BadRequest(format!(
                    "invalid log level '{}', must be one of: {}",
                    level,
                    VALID_LEVELS.join(", ")
                )));
            }
        }
    }

    {
        let mut config = state.config.write().await;

        // Apply partial updates — only provided fields are changed
        if let Some(api) = req.api {
            if let Some(listen) = api.listen {
                config.api.listen = listen;
            }
        }

        if let Some(auth) = req.auth {
            if let Some(v) = auth.max_login_attempts {
                config.auth.max_login_attempts = v;
            }
            if let Some(v) = auth.lockout_duration_minutes {
                config.auth.lockout_duration_minutes = v;
            }
            if let Some(v) = auth.access_token_ttl_minutes {
                config.auth.access_token_ttl_minutes = v;
            }
            if let Some(v) = auth.refresh_token_ttl_days {
                config.auth.refresh_token_ttl_days = v;
            }
        }

        if let Some(ros) = req.routeros {
            if let Some(v) = ros.tls_skip_verify {
                config.routeros.tls_skip_verify = v;
            }
            if let Some(v) = ros.comment_tag {
                config.routeros.comment_tag = v;
            }
            if let Some(v) = ros.address_list_vpn {
                config.routeros.address_list_vpn = v;
            }
            if let Some(v) = ros.address_list_bypass {
                config.routeros.address_list_bypass = v;
            }
            if let Some(v) = ros.routing_table {
                config.routeros.routing_table = v;
            }
            if let Some(v) = ros.auto_setup {
                config.routeros.auto_setup = v;
            }
        }

        if let Some(logging) = req.logging {
            if let Some(v) = logging.level {
                config.logging.level = v;
            }
            if let Some(v) = logging.buffer_size {
                config.logging.buffer_size = v;
            }
        }

        // Persist to disk
        config
            .save(&state.config_path)
            .map_err(|e| AppError::Internal(format!("failed to save config: {e}")))?;
    }

    // Broadcast change event (outside write lock)
    let _ = state.event_tx.send(ServerEvent::ConfigChanged);

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/config", get(get_config).put(update_config))
}
