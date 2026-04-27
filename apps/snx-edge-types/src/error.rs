//! RFC 7807 error envelope.
//!
//! The server's typed `AppError` enum stays in the server crate; only
//! the JSON-on-the-wire shape lives here so clients can deserialise
//! `application/problem+json` responses.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemDetails {
    pub r#type: String,
    pub title: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<String>,
}
