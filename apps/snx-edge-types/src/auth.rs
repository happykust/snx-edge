//! Auth wire-format types: JWT claims, login/refresh request/response.

use serde::{Deserialize, Serialize};

/// JWT claims exchanged between server and clients.
///
/// The server uses `jsonwebtoken::{encode, decode}` against this struct;
/// clients can decode it after login to read role/permissions if needed.
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
    /// Snapshot of `users.token_generation` at the moment this token was
    /// issued. The `require_auth` middleware compares the JWT's `gen` against
    /// the user's current value and returns 401 when they differ — that's
    /// how `delete_user`, `change_password`, etc., revoke outstanding access
    /// tokens before their natural TTL.
    ///
    /// `default` so legacy tokens issued before the field was added (no `gen`
    /// claim in the JWT body) decode as `gen = 0`. They will still be rejected
    /// once the user's counter is bumped above 0, which is the desired
    /// behaviour: a server upgrade fast-tracks tokens to the revocable scheme.
    #[serde(default, rename = "gen")]
    pub token_generation: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Token bundle returned by `POST /auth/login` and `POST /auth/refresh`.
///
/// `token_type` is always `"Bearer"`, but it stays a `String` rather than a
/// `&'static str` so the same struct deserialises in clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}
