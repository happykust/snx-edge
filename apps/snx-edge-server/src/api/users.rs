use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;

use crate::api::auth::{Claims, has_permission};
use crate::db::{UserDb, UserResponse};
use crate::error::AppError;
use crate::state::AppState;

// === Request types ===

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: String,
    #[serde(default)]
    pub comment: String,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub role: Option<String>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    #[serde(default)]
    pub current_password: Option<String>,
    pub new_password: String,
}

// === Helpers ===

async fn user_to_response(db: &UserDb, user: &crate::db::User) -> UserResponse {
    let active_sessions = db.count_user_sessions(&user.id).await.unwrap_or(0);
    UserResponse {
        id: user.id.clone(),
        username: user.username.clone(),
        role: user.role.clone(),
        comment: user.comment.clone(),
        enabled: user.enabled,
        permissions: UserDb::permissions_for_role(&user.role)
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        created_at: user.created_at,
        updated_at: user.updated_at,
        active_sessions,
    }
}

fn require_permission(claims: &Claims, permission: &str) -> Result<(), AppError> {
    if !has_permission(claims, permission) {
        return Err(AppError::Forbidden(format!(
            "permission '{permission}' required",
        )));
    }
    Ok(())
}

fn validate_role(role: &str) -> Result<(), AppError> {
    match role {
        "admin" | "operator" | "viewer" => Ok(()),
        _ => Err(AppError::BadRequest(format!("invalid role: {role}"))),
    }
}

// === Handlers ===

async fn list_users(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<UserResponse>>, AppError> {
    require_permission(&claims, "users.list")?;
    let users = state.db.list_users().await?;
    let mut responses = Vec::with_capacity(users.len());
    for user in &users {
        responses.push(user_to_response(&state.db, user).await);
    }
    Ok(Json(responses))
}

async fn create_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CreateUserRequest>,
) -> Result<(axum::http::StatusCode, Json<UserResponse>), AppError> {
    require_permission(&claims, "users.create")?;
    validate_role(&req.role)?;

    // Cannot create user with role higher than own
    if role_level(&req.role) > role_level(&claims.role) {
        return Err(AppError::Forbidden(
            "cannot create user with higher role than your own".to_string(),
        ));
    }

    let user = state
        .db
        .create_user(&req.username, &req.password, &req.role, &req.comment)
        .await?;
    let resp = user_to_response(&state.db, &user).await;
    Ok((axum::http::StatusCode::CREATED, Json(resp)))
}

async fn get_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<Json<UserResponse>, AppError> {
    require_permission(&claims, "users.read")?;
    let user = state.db.get_user_by_id(&id).await?;
    Ok(Json(user_to_response(&state.db, &user).await))
}

async fn update_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, AppError> {
    require_permission(&claims, "users.update")?;

    if let Some(ref role) = req.role {
        validate_role(role)?;
        if role_level(role) > role_level(&claims.role) {
            return Err(AppError::Forbidden(
                "cannot set role higher than your own".to_string(),
            ));
        }
    }

    let user = state
        .db
        .update_user(
            &id,
            req.role.as_deref(),
            req.comment.as_deref(),
            req.enabled,
        )
        .await?;
    Ok(Json(user_to_response(&state.db, &user).await))
}

async fn delete_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<axum::http::StatusCode, AppError> {
    require_permission(&claims, "users.delete")?;

    if claims.sub == id {
        return Err(AppError::Conflict("cannot delete yourself".to_string()));
    }

    state.db.delete_user(&id).await?;
    // The user row is gone, so the require_auth middleware's lookup will
    // fail and return 401. Drop any cached generation entry so a stale entry
    // doesn't accidentally let a token through during the 30s TTL window.
    state.refresh_token_generation_cache(&id, None).await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn change_user_password(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    if claims.sub == id {
        // User is changing their own password — require current_password
        let current = req
            .current_password
            .as_deref()
            .ok_or_else(|| AppError::BadRequest("current_password is required".to_string()))?;

        let user = state.db.get_user_by_id(&claims.sub).await?;
        let current_owned = current.to_string();
        let hash = user.password_hash.clone();
        let valid = tokio::task::spawn_blocking(move || bcrypt::verify(current_owned, &hash))
            .await
            .map_err(|e| AppError::Internal(format!("blocking task error: {e}")))?
            .map_err(|e| AppError::Internal(format!("bcrypt error: {e}")))?;
        if !valid {
            return Err(AppError::Unauthorized(
                "current password is incorrect".to_string(),
            ));
        }
    } else if claims.role != "admin" {
        // Non-admin trying to change another user's password
        return Err(AppError::Forbidden(
            "only admins can change other users' passwords".to_string(),
        ));
    }
    // else: admin changing another user's password — no current_password needed

    state.db.change_password(&id, &req.new_password).await?;
    // Invalidate all sessions for this user (revokes refresh tokens) and
    // refresh the generation cache so already-issued access tokens fail at
    // the next request rather than waiting out the 30s TTL.
    state.db.delete_user_sessions(&id).await?;
    if let Ok(g) = state.db.get_token_generation(&id).await {
        state.refresh_token_generation_cache(&id, Some(g)).await;
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn get_me(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<UserResponse>, AppError> {
    let user = state.db.get_user_by_id(&claims.sub).await?;
    Ok(Json(user_to_response(&state.db, &user).await))
}

async fn change_my_password(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    // ALL users must provide current password to change their own
    let current = req
        .current_password
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("current_password is required".to_string()))?;

    let user = state.db.get_user_by_id(&claims.sub).await?;
    let current_owned = current.to_string();
    let hash = user.password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || bcrypt::verify(current_owned, &hash))
        .await
        .map_err(|e| AppError::Internal(format!("blocking task error: {e}")))?
        .map_err(|e| AppError::Internal(format!("bcrypt error: {e}")))?;
    if !valid {
        return Err(AppError::Unauthorized(
            "current password is incorrect".to_string(),
        ));
    }

    state
        .db
        .change_password(&claims.sub, &req.new_password)
        .await?;
    // Invalidate all sessions after password change.
    state.db.delete_user_sessions(&claims.sub).await?;
    // Refresh the generation cache so the user's outstanding access tokens
    // (including the one used to make this very request, on its next reuse)
    // start failing immediately rather than waiting out the cache TTL.
    if let Ok(g) = state.db.get_token_generation(&claims.sub).await {
        state
            .refresh_token_generation_cache(&claims.sub, Some(g))
            .await;
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn list_sessions(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<crate::db::Session>>, AppError> {
    require_permission(&claims, "users.sessions")?;
    let sessions = state.db.list_sessions().await?;
    Ok(Json(sessions))
}

async fn revoke_session(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(session_id): Path<String>,
) -> Result<axum::http::StatusCode, AppError> {
    require_permission(&claims, "users.sessions")?;

    // Look up the session's owner before deletion so we can bump that
    // user's `token_generation` — without the bump, only the refresh token
    // dies, but their outstanding access token would still pass middleware
    // checks for up to access_token_ttl_minutes.
    let owner = state.db.session_owner(&session_id).await.ok().flatten();

    state.db.delete_session(&session_id).await?;

    if let Some(user_id) = owner
        && let Ok(Some(g)) = state.db.bump_token_generation(&user_id).await
    {
        state
            .refresh_token_generation_cache(&user_id, Some(g))
            .await;
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// POST /api/v1/users/{id}/revoke-tokens — admin-only: bump the user's
/// `token_generation` so all outstanding JWT access tokens are rejected by
/// the middleware. Refresh sessions are not touched here (use the existing
/// `/users/{id}/password` if you also want to log them out of refresh).
async fn revoke_user_tokens(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<axum::http::StatusCode, AppError> {
    if claims.role != "admin" {
        return Err(AppError::Forbidden(
            "only admins can revoke other users' tokens".to_string(),
        ));
    }

    let new_gen = state
        .db
        .bump_token_generation(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("user not found".to_string()))?;

    state
        .refresh_token_generation_cache(&id, Some(new_gen))
        .await;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Numeric level for role hierarchy comparison.
fn role_level(role: &str) -> u8 {
    match role {
        "viewer" => 1,
        "operator" => 2,
        "admin" => 3,
        _ => 0,
    }
}

/// Routes that require authentication (middleware applied in mod.rs).
pub fn routes() -> Router<AppState> {
    // Order matters: literal paths (`/users/me`, `/users/sessions`) must be
    // registered before the `{id}` wildcard so axum's matchit router resolves
    // them as literals rather than treating "me"/"sessions" as a user id.
    Router::new()
        .route("/users", get(list_users).post(create_user))
        // Self-service (any authenticated user) — registered before `{id}`.
        .route("/users/me", get(get_me))
        .route("/users/me/password", post(change_my_password))
        // Sessions — also literal, registered before `{id}`.
        .route("/users/sessions", get(list_sessions))
        .route("/users/sessions/{id}", delete(revoke_session))
        // User management (admin only via permission checks in handlers).
        .route(
            "/users/{id}",
            get(get_user).put(update_user).delete(delete_user),
        )
        .route("/users/{id}/password", post(change_user_password))
        .route("/users/{id}/revoke-tokens", post(revoke_user_tokens))
}
