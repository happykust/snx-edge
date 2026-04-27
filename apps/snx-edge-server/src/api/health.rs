use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::AppError;
use crate::state::AppState;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

/// Liveness probe. Cheap, dependency-free — Docker healthchecks rely on this
/// returning 200 even when downstream services (RouterOS, the VPN) are down.
async fn health() -> (StatusCode, Json<HealthResponse>) {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}

// === Readiness probe ===

#[derive(Serialize)]
struct ReadinessResponse {
    status: &'static str,
    components: Components,
}

#[derive(Serialize)]
struct Components {
    db: DbStatus,
    routeros: RouterOsStatus,
    tunnel: TunnelStatus,
}

#[derive(Serialize)]
struct DbStatus {
    status: &'static str,
    latency_ms: u64,
}

#[derive(Serialize)]
struct RouterOsStatus {
    status: &'static str,
    latency_ms: u64,
}

#[derive(Serialize)]
struct TunnelStatus {
    state: String,
}

const DB_TIMEOUT: Duration = Duration::from_secs(1);
const ROUTEROS_TIMEOUT: Duration = Duration::from_secs(2);

/// Probe the database with a 1s timeout. A timeout or query error reports
/// `down`; on success we return how long the round-trip took.
async fn probe_db(state: &AppState) -> DbStatus {
    let start = Instant::now();
    let result = tokio::time::timeout(DB_TIMEOUT, state.db.health_check()).await;
    let latency_ms = start.elapsed().as_millis() as u64;

    let status = match result {
        Ok(Ok(())) => "up",
        Ok(Err(e)) => {
            tracing::warn!("readiness: db probe failed: {e}");
            "down"
        }
        Err(_) => {
            tracing::warn!("readiness: db probe timed out after {:?}", DB_TIMEOUT);
            "down"
        }
    };

    DbStatus { status, latency_ms }
}

/// Probe RouterOS reachability with a 2s timeout. Reports `not_configured`
/// when the env vars (host/user/password) aren't set so operators can run
/// the server stand-alone without RouterOS — that's not a readiness failure.
async fn probe_routeros(state: &AppState) -> RouterOsStatus {
    let start = Instant::now();

    // Build (or fetch the cached) client. If env vars are missing,
    // `routeros_client()` returns AppError::Internal("env ... not set") —
    // surface that as `not_configured` rather than `down`.
    let client = match state.routeros_client().await {
        Ok(c) => c,
        Err(AppError::Internal(msg)) if msg.contains("env ") && msg.contains(" not set") => {
            return RouterOsStatus {
                status: "not_configured",
                latency_ms: start.elapsed().as_millis() as u64,
            };
        }
        Err(e) => {
            tracing::warn!("readiness: routeros client build failed: {e}");
            return RouterOsStatus {
                status: "down",
                latency_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    // Use the existing list/GET path — `/system/identity` is a single small
    // record that every RouterOS device exposes. We don't care about the
    // payload, only that the request completes inside the timeout window.
    #[derive(serde::Deserialize)]
    struct Identity {
        #[allow(dead_code)]
        #[serde(default)]
        name: Option<String>,
    }

    let probe = client.list::<Identity>("/system/identity");
    let result = tokio::time::timeout(ROUTEROS_TIMEOUT, probe).await;
    let latency_ms = start.elapsed().as_millis() as u64;

    let status = match result {
        Ok(Ok(_)) => "up",
        Ok(Err(e)) => {
            tracing::warn!("readiness: routeros probe failed: {e}");
            "down"
        }
        Err(_) => {
            tracing::warn!(
                "readiness: routeros probe timed out after {:?}",
                ROUTEROS_TIMEOUT
            );
            "down"
        }
    };

    RouterOsStatus { status, latency_ms }
}

/// Readiness probe. 503 only when the DB is unreachable — RouterOS being
/// down or unconfigured is acceptable: an operator may legitimately want to
/// start the server before the router is ready, and the VPN tunnel state
/// is informational (Disconnected is the normal startup state).
async fn ready(State(state): State<AppState>) -> (StatusCode, Json<ReadinessResponse>) {
    let db = probe_db(&state).await;
    let routeros = probe_routeros(&state).await;
    let tunnel_state = format!("{:?}", state.tunnel.status().await.connection);
    // Strip enum payload (e.g. `Connected(ConnectionInfo { .. })` ->
    // `Connected`) so the field is a stable, machine-readable token.
    let tunnel_state = tunnel_state
        .split(['(', ' '])
        .next()
        .unwrap_or(&tunnel_state)
        .to_string();

    let db_up = db.status == "up";
    let status = if db_up { "ready" } else { "degraded" };
    let http_status = if db_up {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        http_status,
        Json(ReadinessResponse {
            status,
            components: Components {
                db,
                routeros,
                tunnel: TunnelStatus {
                    state: tunnel_state,
                },
            },
        }),
    )
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/health/ready", get(ready))
}
