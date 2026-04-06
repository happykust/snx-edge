use axum::extract::State;
use axum::routing::get;
use axum::{Extension, Json, Router};

use crate::api::auth::{has_permission, Claims};
use crate::error::AppError;
use crate::state::AppState;

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

pub fn routes() -> Router<AppState> {
    Router::new().route("/config", get(get_config))
}
