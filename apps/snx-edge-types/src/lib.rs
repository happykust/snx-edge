//! Wire-format DTOs shared between `snx-edge-server`, `snx-edge-client`,
//! and `snx-edge-ctl`.
//!
//! Only types that cross the HTTP or SSE boundary live here. Internal
//! runtime structures (e.g. `AppState`, `TunnelManager`, database row
//! shapes) stay in their owning crate.
//!
//! Field shapes (names, `#[serde(rename = ...)]`, tag/content attributes)
//! are byte-identical to the previous server-side definitions; the server
//! is the canonical source of truth, and clients adapt.

pub mod auth;
pub mod config;
pub mod error;
pub mod events;
pub mod health;
pub mod profiles;
pub mod routing;
pub mod tunnel;
pub mod users;
