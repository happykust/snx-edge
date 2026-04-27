//! User and session wire-format types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// User data for API responses (without internal fields like password_hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub role: String,
    pub comment: String,
    pub enabled: bool,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub active_sessions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: String,
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub role: Option<String>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    #[serde(default)]
    pub current_password: Option<String>,
    pub new_password: String,
}

/// Active refresh-token session. Returned by `GET /users/sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
