use axum::extract::State;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;

use crate::api::auth::{Claims, has_permission};
use crate::error::AppError;
use crate::state::AppState;
use crate::tunnel::{TunnelStatus, VpnConfig, VpnRoute};

#[derive(Deserialize)]
pub struct ConnectRequest {
    /// ID of the VPN profile stored on the server.
    pub profile_id: String,
}

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct ServerInfoRequest {
    pub server: String,
}

/// POST /api/v1/tunnel/connect
async fn connect(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<ConnectRequest>,
) -> Result<Json<TunnelStatus>, AppError> {
    if !has_permission(&claims, "tunnel.connect") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.connect' required".to_string(),
        ));
    }

    // Load VPN config from profile
    let config_str = state.db.get_profile_config(&req.profile_id).await?;
    let vpn_config: VpnConfig = serde_json::from_str(&config_str)
        .map_err(|e| AppError::Internal(format!("invalid profile config: {e}")))?;

    if vpn_config.server.is_empty() {
        return Err(AppError::BadRequest(
            "profile has no VPN server configured".to_string(),
        ));
    }

    state
        .tunnel
        .connect(&vpn_config)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Json(state.tunnel.status().await))
}

/// POST /api/v1/tunnel/disconnect
async fn disconnect(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<TunnelStatus>, AppError> {
    if !has_permission(&claims, "tunnel.disconnect") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.disconnect' required".to_string(),
        ));
    }

    state
        .tunnel
        .disconnect()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Json(state.tunnel.status().await))
}

/// POST /api/v1/tunnel/reconnect
async fn reconnect(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<ConnectRequest>,
) -> Result<Json<TunnelStatus>, AppError> {
    if !has_permission(&claims, "tunnel.connect") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.connect' required".to_string(),
        ));
    }

    let config_str = state.db.get_profile_config(&req.profile_id).await?;
    let vpn_config: VpnConfig = serde_json::from_str(&config_str)
        .map_err(|e| AppError::Internal(format!("invalid profile config: {e}")))?;

    state
        .tunnel
        .reconnect(&vpn_config)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Json(state.tunnel.status().await))
}

/// GET /api/v1/tunnel/status
async fn status(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<TunnelStatus>, AppError> {
    if !has_permission(&claims, "tunnel.status") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.status' required".to_string(),
        ));
    }

    Ok(Json(state.tunnel.status().await))
}

/// GET /api/v1/server/info — return info about the current (or last) VPN server.
async fn server_info_current(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !has_permission(&claims, "tunnel.status") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.status' required".to_string(),
        ));
    }

    let server = state.tunnel.current_server().await.ok_or_else(|| {
        AppError::NotFound(
            "no server available; connect first or use POST with a server address".to_string(),
        )
    })?;

    let vpn_config = VpnConfig {
        server,
        ..VpnConfig::default()
    };

    let info = state
        .tunnel
        .server_info(&vpn_config)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(info))
}

/// POST /api/v1/server/info — query Check Point server capabilities.
async fn server_info(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<ServerInfoRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !has_permission(&claims, "tunnel.status") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.status' required".to_string(),
        ));
    }

    let vpn_config = VpnConfig {
        server: req.server,
        ..VpnConfig::default()
    };

    let info = state
        .tunnel
        .server_info(&vpn_config)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(info))
}

/// GET /api/v1/routes
async fn vpn_routes(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<VpnRoute>>, AppError> {
    if !has_permission(&claims, "tunnel.status") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.status' required".to_string(),
        ));
    }

    Ok(Json(state.tunnel.routes().await))
}

/// POST /api/v1/tunnel/challenge — submit MFA code
async fn challenge(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<TunnelStatus>, AppError> {
    if !has_permission(&claims, "tunnel.connect") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.connect' required".to_string(),
        ));
    }

    state
        .tunnel
        .challenge_code(&req.code)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Json(state.tunnel.status().await))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/tunnel/connect", post(connect))
        .route("/tunnel/disconnect", post(disconnect))
        .route("/tunnel/reconnect", post(reconnect))
        .route("/tunnel/status", get(status))
        .route("/tunnel/challenge", post(challenge))
        .route("/server/info", get(server_info_current).post(server_info))
        .route("/tunnel/routes", get(vpn_routes))
}
