//! ctl-side wire-type re-exports plus `Tabled` impls.
//!
//! The wire-format DTOs themselves live in `snx-edge-types`. We re-export
//! them here so existing call sites can keep using `models::Profile` etc.
//! `Tabled` is a foreign trait, so for each type we present in a tabular
//! view we wrap it in a small newtype and forward `Serialize` / `Deserialize`
//! transparently to the inner wire shape.

use std::borrow::Cow;
use std::ops::Deref;

use serde::{Deserialize, Serialize};
use tabled::Tabled;

#[allow(unused_imports)]
pub use snx_edge_types::auth::TokenResponse;
#[allow(unused_imports)]
pub use snx_edge_types::events::LogEntry;
#[allow(unused_imports)]
pub use snx_edge_types::health::HealthResponse;
#[allow(unused_imports)]
pub use snx_edge_types::routing::{DiagnosticsChecks, DiagnosticsResult};
#[allow(unused_imports)]
pub use snx_edge_types::tunnel::{ConnectionInfo, ConnectionStatus, MfaChallenge, TunnelStatus};

/// Newtype wrapper around the shared `Profile` wire type that adds a
/// `Tabled` impl. Serializes as the inner type (transparent on the wire).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Profile(pub snx_edge_types::profiles::Profile);

impl Deref for Profile {
    type Target = snx_edge_types::profiles::Profile;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Tabled for Profile {
    const LENGTH: usize = 4;

    fn fields(&self) -> Vec<Cow<'_, str>> {
        vec![
            Cow::Borrowed(&self.0.id),
            Cow::Borrowed(&self.0.name),
            Cow::Owned(self.0.enabled.to_string()),
            Cow::Owned(
                self.0
                    .config
                    .get("server")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-")
                    .to_string(),
            ),
        ]
    }

    fn headers() -> Vec<Cow<'static, str>> {
        vec![
            Cow::Borrowed("ID"),
            Cow::Borrowed("Name"),
            Cow::Borrowed("Enabled"),
            Cow::Borrowed("Server"),
        ]
    }
}

/// Wrapper around the shared `UserResponse` wire type with a `Tabled` impl.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserResponse(pub snx_edge_types::users::UserResponse);

impl Deref for UserResponse {
    type Target = snx_edge_types::users::UserResponse;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Tabled for UserResponse {
    const LENGTH: usize = 5;

    fn fields(&self) -> Vec<Cow<'_, str>> {
        vec![
            Cow::Borrowed(&self.0.id),
            Cow::Borrowed(&self.0.username),
            Cow::Borrowed(&self.0.role),
            Cow::Owned(self.0.enabled.to_string()),
            Cow::Owned(self.0.active_sessions.to_string()),
        ]
    }

    fn headers() -> Vec<Cow<'static, str>> {
        vec![
            Cow::Borrowed("ID"),
            Cow::Borrowed("Username"),
            Cow::Borrowed("Role"),
            Cow::Borrowed("Enabled"),
            Cow::Borrowed("Sessions"),
        ]
    }
}

/// Wrapper around the shared `Session` wire type with a `Tabled` impl.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Session(pub snx_edge_types::users::Session);

impl Deref for Session {
    type Target = snx_edge_types::users::Session;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Tabled for Session {
    const LENGTH: usize = 5;

    fn fields(&self) -> Vec<Cow<'_, str>> {
        vec![
            Cow::Borrowed(&self.0.id),
            Cow::Borrowed(&self.0.user_id),
            Cow::Owned(self.0.ip_address.as_deref().unwrap_or("-").to_string()),
            Cow::Owned(self.0.created_at.format("%Y-%m-%d %H:%M").to_string()),
            Cow::Owned(self.0.expires_at.format("%Y-%m-%d %H:%M").to_string()),
        ]
    }

    fn headers() -> Vec<Cow<'static, str>> {
        vec![
            Cow::Borrowed("ID"),
            Cow::Borrowed("User ID"),
            Cow::Borrowed("IP"),
            Cow::Borrowed("Created"),
            Cow::Borrowed("Expires"),
        ]
    }
}

/// Wrapper around the shared `AddressListEntry` wire type with a `Tabled` impl.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AddressListEntry(pub snx_edge_types::routing::AddressListEntry);

impl Deref for AddressListEntry {
    type Target = snx_edge_types::routing::AddressListEntry;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Tabled for AddressListEntry {
    const LENGTH: usize = 4;

    fn fields(&self) -> Vec<Cow<'_, str>> {
        vec![
            Cow::Borrowed(&self.0.id),
            Cow::Borrowed(&self.0.address),
            Cow::Owned(self.0.comment.as_deref().unwrap_or("-").to_string()),
            Cow::Owned(self.0.disabled.as_deref().unwrap_or("false").to_string()),
        ]
    }

    fn headers() -> Vec<Cow<'static, str>> {
        vec![
            Cow::Borrowed("ID"),
            Cow::Borrowed("Address"),
            Cow::Borrowed("Comment"),
            Cow::Borrowed("Disabled"),
        ]
    }
}
