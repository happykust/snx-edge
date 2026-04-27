use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub use snx_edge_types::error::ProblemDetails;

/// Application error type used across all API handlers.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("bad gateway: {0}")]
    BadGateway(String),

    #[error("service unavailable: {0}")]
    Unavailable(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::BadGateway(_) => StatusCode::BAD_GATEWAY,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = ProblemDetails {
            r#type: "about:blank".to_string(),
            title: status.canonical_reason().unwrap_or("Error").to_string(),
            status: status.as_u16(),
            detail: Some(self.to_string()),
        };
        (status, axum::Json(body)).into_response()
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        tracing::error!(error = %err, "rusqlite error");
        if let rusqlite::Error::SqliteFailure(ref sqlite_err, ref msg) = err {
            if matches!(
                sqlite_err.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) {
                return Self::Unavailable("database busy".to_string());
            }
            if matches!(sqlite_err.code, rusqlite::ErrorCode::ConstraintViolation) {
                let detail = msg
                    .as_deref()
                    .map(|m| format!("constraint violation: {m}"))
                    .unwrap_or_else(|| "constraint violation".to_string());
                return Self::Conflict(detail);
            }
        }
        Self::Internal("database error".to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        tracing::error!("jwt error: {err}");
        Self::Unauthorized("invalid token".to_string())
    }
}
