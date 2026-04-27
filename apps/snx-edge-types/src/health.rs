//! Health probe wire-format types.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadyResponse {
    pub status: String,
    pub components: ReadyComponents,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadyComponents {
    pub db: ComponentHealth,
    pub routeros: ComponentHealth,
    pub tunnel: TunnelComponentHealth,
}

/// Generic up/down/not_configured component status with latency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub status: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelComponentHealth {
    pub state: String,
}
