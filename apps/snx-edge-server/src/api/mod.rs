pub mod auth;
pub mod config;
pub mod events;
pub mod health;
pub mod logs;
pub mod profiles;
pub mod routing;
pub mod tunnel;
pub mod users;

use axum::Router;
use axum::http::HeaderValue;
use axum::http::Method;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::middleware;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the complete API router.
pub fn router(state: AppState) -> Router {
    // Public routes (no auth required). `auth::routes` carries its own
    // per-IP rate-limit layer; `health::routes` does not.
    let public = Router::new()
        .merge(health::routes())
        .merge(auth::routes(&state));

    // Protected routes (JWT auth required)
    let protected = Router::new()
        .merge(users::routes())
        .merge(config::routes())
        .merge(profiles::routes())
        .merge(tunnel::routes())
        .merge(routing::routes())
        .merge(events::routes())
        .merge(logs::routes())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    // Build a CORS layer from the configured origin whitelist. An empty
    // whitelist (default) yields a restrictive policy with no `allow_origin`
    // call at all, which means browsers are denied cross-origin access.
    let cors = build_cors_layer(&state);

    Router::new()
        .nest("/api/v1", public.merge(protected))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

/// Build a [`CorsLayer`] honoring `[api].cors_origins` from configuration.
///
/// * Empty list → default-deny (no `allow_origin` call).
/// * Non-empty list → each entry parsed as `HeaderValue`; entries that fail to
///   parse are logged and skipped.
fn build_cors_layer(state: &AppState) -> CorsLayer {
    let origins: Vec<String> = {
        // Snapshot the configured origins synchronously. `try_read` is fine
        // here because this runs at router-build time during startup.
        match state.config.try_read() {
            Ok(cfg) => cfg.api.cors_origins.clone(),
            Err(_) => Vec::new(),
        }
    };

    let base = CorsLayer::new()
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE]);

    if origins.is_empty() {
        return base;
    }

    let parsed: Vec<HeaderValue> = origins
        .into_iter()
        .filter_map(|origin| match HeaderValue::from_str(&origin) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::error!("invalid CORS origin '{origin}': {e}; skipping");
                None
            }
        })
        .collect();

    if parsed.is_empty() {
        // All entries were invalid — fall back to default-deny.
        return base;
    }

    base.allow_origin(AllowOrigin::list(parsed))
}
