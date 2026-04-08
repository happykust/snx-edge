use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::UserDb;
use crate::error::AppError;
use crate::state::AppState;

// === JWT Claims ===

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // user_id
    pub role: String,
    pub permissions: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    /// "access" or "refresh"
    pub token_type: String,
}

// === Request/Response types ===

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

// === Handlers ===

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let user = state
        .db
        .get_user_by_username(&req.username)
        .await
        .map_err(|_| AppError::Unauthorized("invalid credentials".to_string()))?;

    // Check if account is locked (generic message — don't reveal unlock time)
    if let Some(locked_until) = user.locked_until {
        if Utc::now() < locked_until {
            return Err(AppError::Unauthorized(
                "account temporarily locked due to too many failed attempts".to_string(),
            ));
        }
        // Lock expired, reset atomically to prevent race condition
        // (multiple concurrent requests seeing expired lock all reset and get fresh attempts)
        state.db.reset_failed_logins(&user.id).await?;
    }

    if !user.enabled {
        return Err(AppError::Unauthorized("account disabled".to_string()));
    }

    // Verify password (offload CPU-intensive bcrypt to blocking thread)
    let password = req.password.clone();
    let password_hash = user.password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || bcrypt::verify(password, &password_hash))
        .await
        .map_err(|e| AppError::Internal(format!("blocking task error: {e}")))?
        .map_err(|e| AppError::Internal(format!("bcrypt error: {e}")))?;
    if !valid {
        let config = state.config.read().await;
        let max_attempts = config.auth.max_login_attempts;
        let lockout_minutes = config.auth.lockout_duration_minutes;
        drop(config);
        state
            .db
            .record_failed_login(&user.id, max_attempts, lockout_minutes)
            .await?;
        return Err(AppError::Unauthorized("invalid credentials".to_string()));
    }

    // Reset failed attempts on successful login
    state.db.reset_failed_logins(&user.id).await?;

    let ip = extract_client_ip(&headers);
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let tokens = issue_tokens(
        &state,
        &user.id,
        &user.role,
        ip.as_deref(),
        user_agent.as_deref(),
    )
    .await?;
    Ok(Json(tokens))
}

async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let claims = decode_token(&state.jwt_secret, &req.refresh_token)?;

    if claims.token_type != "refresh" {
        return Err(AppError::Unauthorized("not a refresh token".to_string()));
    }

    // Check session still valid
    if !state.db.session_exists(&claims.jti).await? {
        return Err(AppError::Unauthorized("session revoked".to_string()));
    }

    // Invalidate old refresh session
    state.db.delete_session(&claims.jti).await?;

    // Check user still exists and enabled
    let user = state.db.get_user_by_id(&claims.sub).await?;
    if !user.enabled {
        return Err(AppError::Unauthorized("account disabled".to_string()));
    }

    let ip = extract_client_ip(&headers);
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let tokens = issue_tokens(
        &state,
        &user.id,
        &user.role,
        ip.as_deref(),
        user_agent.as_deref(),
    )
    .await?;
    Ok(Json(tokens))
}

// === Token helpers ===

async fn issue_tokens(
    state: &AppState,
    user_id: &str,
    role: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<TokenResponse, AppError> {
    let config = state.config.read().await;
    let access_ttl_min = config.auth.access_token_ttl_minutes;
    let refresh_ttl_days = config.auth.refresh_token_ttl_days;
    drop(config);

    let permissions = UserDb::permissions_for_role(role);
    let now = Utc::now();

    // Access token
    let access_exp = now + Duration::minutes(access_ttl_min as i64);
    let access_jti = Uuid::new_v4().to_string();
    let access_claims = Claims {
        sub: user_id.to_string(),
        role: role.to_string(),
        permissions: permissions.clone(),
        exp: access_exp.timestamp(),
        iat: now.timestamp(),
        jti: access_jti,
        token_type: "access".to_string(),
    };

    // Refresh token
    let refresh_exp = now + Duration::days(refresh_ttl_days as i64);
    let refresh_jti = Uuid::new_v4().to_string();
    let refresh_claims = Claims {
        sub: user_id.to_string(),
        role: role.to_string(),
        permissions,
        exp: refresh_exp.timestamp(),
        iat: now.timestamp(),
        jti: refresh_jti.clone(),
        token_type: "refresh".to_string(),
    };

    let key = EncodingKey::from_secret(state.jwt_secret.as_bytes());
    let access_token = jsonwebtoken::encode(&Header::default(), &access_claims, &key)?;
    let refresh_token = jsonwebtoken::encode(&Header::default(), &refresh_claims, &key)?;

    // Store refresh session
    state
        .db
        .create_session(&refresh_jti, user_id, ip, user_agent, refresh_exp)
        .await?;

    Ok(TokenResponse {
        access_token,
        refresh_token,
        token_type: "Bearer",
        expires_in: access_ttl_min as i64 * 60,
    })
}

pub fn decode_token(secret: &str, token: &str) -> Result<Claims, AppError> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let data = jsonwebtoken::decode::<Claims>(token, &key, &Validation::default())?;
    Ok(data.claims)
}

/// Axum middleware: extract and validate JWT from Authorization header.
///
/// NOTE: Access tokens are stateless JWTs -- they are NOT checked against
/// the database on every request.  This means an access token remains
/// valid for up to `access_token_ttl_minutes` (default 15 min) after the
/// owning user is deleted or has all sessions revoked.  This is an
/// intentional tradeoff: it avoids a DB round-trip on every authenticated
/// request while keeping the exposure window short.  Refresh tokens *are*
/// validated against stored sessions, so revocation takes full effect once
/// the current access token expires.
pub async fn require_auth(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AppError> {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("invalid authorization scheme".to_string()))?;

    let claims = decode_token(&state.jwt_secret, token)?;

    if claims.token_type != "access" {
        return Err(AppError::Unauthorized("not an access token".to_string()));
    }

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

/// Check if the current user has a specific permission.
pub fn has_permission(claims: &Claims, required: &str) -> bool {
    claims.permissions.iter().any(|p| {
        p == required || {
            // Wildcard: "tunnel.*" matches "tunnel.connect" but not "tunnel_evil"
            if let Some(prefix) = p.strip_suffix(".*") {
                required.starts_with(&format!("{prefix}."))
            } else {
                false
            }
        }
    })
}

/// Extract client IP from X-Forwarded-For or X-Real-IP headers.
fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
}
