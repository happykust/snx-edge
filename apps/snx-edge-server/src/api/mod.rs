pub mod auth;
pub mod config;
pub mod events;
pub mod health;
pub mod logs;
pub mod profiles;
pub mod routing;
pub mod tunnel;
pub mod users;

use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::Method;
use axum::middleware;
use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the complete API router.
pub fn router(state: AppState) -> Router {
    // Public routes (no auth required)
    let public = Router::new()
        .merge(health::routes())
        .merge(auth::routes());

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

    Router::new()
        .nest("/api/v1", public.merge(protected))
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers([AUTHORIZATION, CONTENT_TYPE])
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE]),
        )
        .with_state(state)
}
