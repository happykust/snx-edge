use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

/// Helper to build the test app and get an admin JWT token.
/// Returns (router, token, _tempdir_guard) — keep the guard alive to prevent cleanup.
async fn setup() -> (axum::Router, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let config_path = dir.path().join("config.toml");

    let config_content = format!(
        r#"
[api]
listen = "127.0.0.1:0"

[auth]
jwt_secret_env = "TEST_JWT_SECRET"
user_db = "{}"
max_login_attempts = 5
lockout_duration_minutes = 15
access_token_ttl_minutes = 15
refresh_token_ttl_days = 7

[routeros]
host_env = "ROUTEROS_HOST"
user_env = "ROUTEROS_USER"
password_env = "ROUTEROS_PASSWORD"

[logging]
level = "info"
buffer_size = 100
"#,
        db_path.to_string_lossy()
    );

    std::fs::write(&config_path, &config_content).unwrap();
    // SAFETY: test env vars set before any multithreaded work
    unsafe {
        std::env::set_var(
            "TEST_JWT_SECRET",
            "test-secret-for-testing-only-must-be-32-bytes-long!",
        );
        std::env::set_var("SNX_EDGE_ADMIN_PASSWORD", "adminpass123");
        std::env::set_var("ROUTEROS_HOST", "127.0.0.1");
        std::env::set_var("ROUTEROS_USER", "admin");
        std::env::set_var("ROUTEROS_PASSWORD", "test");
    }

    let config = snx_edge_server::config::AppConfig::load(&config_path.to_string_lossy()).unwrap();
    let log_buffer = snx_edge_server::api::logs::new_log_buffer(100);
    let (event_tx, _) = tokio::sync::broadcast::channel(64);
    let shutdown = tokio_util::sync::CancellationToken::new();
    let state = snx_edge_server::state::AppState::with_shared(
        config,
        config_path.to_string_lossy().to_string(),
        log_buffer,
        event_tx,
        shutdown,
    )
    .await
    .unwrap();
    let app = snx_edge_server::api::router(state);

    // Login to get admin token
    let login_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username": "admin", "password": "adminpass123"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(login_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_resp: Value = serde_json::from_slice(&body).unwrap();
    let token = token_resp["access_token"].as_str().unwrap().to_string();

    (app, token, dir)
}

fn auth_get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn auth_post(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn auth_put(uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn auth_delete(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn resp_json(resp: axum::http::Response<Body>) -> Value {
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

// === Tests ===

#[tokio::test]
async fn test_health() {
    let (app, _, _dir) = setup().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn test_health_ready_returns_components() {
    let (app, _, _dir) = setup().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // RouterOS env vars are set by the test fixture but the host is unreachable;
    // expect 200 (db is fine — RouterOS down is acceptable).
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    assert_eq!(body["components"]["db"]["status"], "up");
    let routeros_status = body["components"]["routeros"]["status"].as_str().unwrap();
    assert!(
        routeros_status == "down" || routeros_status == "not_configured",
        "unexpected routeros status: {routeros_status}"
    );
    assert!(body["components"]["tunnel"]["state"].is_string());
}

#[tokio::test]
async fn test_auth_login_success() {
    let (_, token, _dir) = setup().await;
    assert!(!token.is_empty());
}

#[tokio::test]
async fn test_auth_login_wrong_password() {
    let (app, _, _dir) = setup().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username": "admin", "password": "wrong"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_protected_endpoint_without_token() {
    let (app, _, _dir) = setup().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_me() {
    let (app, token, _dir) = setup().await;
    let resp = app
        .oneshot(auth_get("/api/v1/users/me", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    assert_eq!(body["username"], "admin");
    assert_eq!(body["role"], "admin");
}

#[tokio::test]
async fn test_create_and_list_users() {
    let (app, token, _dir) = setup().await;

    // Create operator
    let resp = app
        .clone()
        .oneshot(auth_post(
            "/api/v1/users",
            &token,
            json!({"username": "op1", "password": "operator123", "role": "operator"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let user = resp_json(resp).await;
    assert_eq!(user["username"], "op1");
    assert_eq!(user["role"], "operator");

    // List users
    let resp = app
        .oneshot(auth_get("/api/v1/users", &token))
        .await
        .unwrap();
    let users = resp_json(resp).await;
    assert_eq!(users.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_cannot_delete_last_admin() {
    let (app, token, _dir) = setup().await;

    // Get admin user ID
    let resp = app
        .clone()
        .oneshot(auth_get("/api/v1/users/me", &token))
        .await
        .unwrap();
    let me = resp_json(resp).await;
    let admin_id = me["id"].as_str().unwrap();

    // Try to delete self
    let resp = app
        .oneshot(auth_delete(&format!("/api/v1/users/{admin_id}"), &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_config_returns_server_settings() {
    let (app, token, _dir) = setup().await;
    let resp = app
        .oneshot(auth_get("/api/v1/config", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let config = resp_json(resp).await;
    // Server config has no VPN settings — only infrastructure
    assert!(config.get("api").is_some());
    assert!(config.get("auth").is_some());
    assert!(config.get("routeros").is_some());
    assert!(config.get("server").is_none()); // no VPN server field
    assert!(config.get("password").is_none()); // no VPN password
}

#[tokio::test]
async fn test_tunnel_status() {
    let (app, token, _dir) = setup().await;
    let resp = app
        .oneshot(auth_get("/api/v1/tunnel/status", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    assert_eq!(body["connection"]["state"], "Disconnected");
}

#[tokio::test]
async fn test_rbac_viewer_cannot_connect() {
    let (app, token, _dir) = setup().await;

    // Create viewer
    app.clone()
        .oneshot(auth_post(
            "/api/v1/users",
            &token,
            json!({"username": "viewer1", "password": "viewer12345", "role": "viewer"}),
        ))
        .await
        .unwrap();

    // Login as viewer
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username": "viewer1", "password": "viewer12345"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp_json(resp).await;
    let viewer_token = body["access_token"].as_str().unwrap();

    // Viewer can read status
    let resp = app
        .clone()
        .oneshot(auth_get("/api/v1/tunnel/status", viewer_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Viewer cannot connect
    let resp = app
        .clone()
        .oneshot(auth_post(
            "/api/v1/tunnel/connect",
            viewer_token,
            json!({"profile_id": "nonexistent"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Viewer cannot manage users
    let resp = app
        .oneshot(auth_get("/api/v1/users", viewer_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_password_min_length() {
    let (app, token, _dir) = setup().await;
    let resp = app
        .oneshot(auth_post(
            "/api/v1/users",
            &token,
            json!({"username": "short", "password": "abc", "role": "viewer"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_profiles_crud() {
    let (app, token, _dir) = setup().await;

    // Create profile
    let resp = app
        .clone()
        .oneshot(auth_post(
            "/api/v1/profiles",
            &token,
            json!({
                "name": "Office VPN",
                "config": {
                    "server": "vpn.office.com",
                    "login_type": "password",
                    "username": "john",
                    "password": "secret123",
                    "mtu": 1400
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let profile = resp_json(resp).await;
    assert_eq!(profile["name"], "Office VPN");
    assert_eq!(profile["config"]["server"], "vpn.office.com");
    assert_eq!(profile["config"]["password"], "***"); // masked
    assert_eq!(profile["config"]["mtu"], 1400);
    let profile_id = profile["id"].as_str().unwrap().to_string();

    // List profiles
    let resp = app
        .clone()
        .oneshot(auth_get("/api/v1/profiles", &token))
        .await
        .unwrap();
    let profiles = resp_json(resp).await;
    assert_eq!(profiles.as_array().unwrap().len(), 1);

    // Update profile
    let resp = app
        .clone()
        .oneshot(auth_put(
            &format!("/api/v1/profiles/{profile_id}"),
            &token,
            json!({
                "name": "Office VPN (updated)",
                "config": {"server": "vpn2.office.com", "password": "***", "mtu": 1300}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let updated = resp_json(resp).await;
    assert_eq!(updated["name"], "Office VPN (updated)");
    assert_eq!(updated["config"]["server"], "vpn2.office.com");
    assert_eq!(updated["config"]["password"], "***"); // kept from original

    // Delete profile
    let resp = app
        .oneshot(auth_delete(
            &format!("/api/v1/profiles/{profile_id}"),
            &token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_create_profile_rejects_no_cert_check_by_default() {
    let (app, token, _dir) = setup().await;

    let resp = app
        .oneshot(auth_post(
            "/api/v1/profiles",
            &token,
            json!({
                "name": "Insecure VPN",
                "config": {
                    "server": "vpn.test.com",
                    "login_type": "password",
                    "username": "u",
                    "password": "p",
                    "no_cert_check": true
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp_json(resp).await;
    let detail = body["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("certificate verification"),
        "unexpected error detail: {detail}"
    );
}

#[tokio::test]
async fn test_connect_with_profile() {
    let (app, token, _dir) = setup().await;

    // Create profile
    let resp = app
        .clone()
        .oneshot(auth_post(
            "/api/v1/profiles",
            &token,
            json!({
                "name": "Test VPN",
                "config": {
                    "server": "vpn.test.com",
                    "login_type": "password",
                    "username": "user1",
                    "password": "pass123"
                }
            }),
        ))
        .await
        .unwrap();
    let profile = resp_json(resp).await;
    let profile_id = profile["id"].as_str().unwrap();

    // Connect using profile (will fail because no real VPN server, but should not be 404/403)
    let resp = app
        .oneshot(auth_post(
            "/api/v1/tunnel/connect",
            &token,
            json!({"profile_id": profile_id}),
        ))
        .await
        .unwrap();
    // 400 = snxcore connection error (expected — no real VPN server)
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp_json(resp).await;
    assert!(body["detail"].as_str().unwrap().contains("error"));
}

// === SSE wire-format tests ===

/// Pull just the first chunk off a streaming response body.
///
/// SSE responses stay open indefinitely, so `to_bytes` would hang. We poll
/// the data stream once via `tokio_stream::StreamExt::next`.
async fn first_sse_chunk(body: Body) -> String {
    use tokio_stream::StreamExt;

    let mut stream = body.into_data_stream();
    let chunk = stream
        .next()
        .await
        .expect("expected at least one body chunk")
        .expect("stream error");
    String::from_utf8(chunk.to_vec()).expect("utf-8 SSE frame")
}

/// The SSE stream must announce its wire-schema version as the very first
/// frame so clients can fail loud on incompatible upgrades.
#[tokio::test]
async fn test_sse_events_first_frame_is_schema_version() {
    let (app, token, _dir) = setup().await;
    let resp = app
        .oneshot(auth_get("/api/v1/events", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let text = first_sse_chunk(resp.into_body()).await;
    assert!(
        text.contains("event: schema"),
        "first SSE frame must announce schema, got: {text}"
    );
    assert!(
        text.contains(r#""version":1"#),
        "schema frame must carry version=1, got: {text}"
    );
}

/// Same handshake on the dedicated log SSE endpoint.
#[tokio::test]
async fn test_sse_logs_first_frame_is_schema_version() {
    let (app, token, _dir) = setup().await;
    let resp = app.oneshot(auth_get("/api/v1/logs", &token)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let text = first_sse_chunk(resp.into_body()).await;
    assert!(
        text.contains("event: schema"),
        "first SSE frame must announce schema, got: {text}"
    );
    assert!(
        text.contains(r#""version":1"#),
        "schema frame must carry version=1, got: {text}"
    );
}

// === Rate-limit tests (task 5.1) ===

/// Sibling of `setup()` that does NOT spend a request on the bootstrap login.
///
/// Each test fixture builds a fresh `axum::Router`, which builds a fresh
/// `tower_governor::GovernorLayer` with its own bucket — so this test runs
/// in isolation from the rest of the suite even when the harness uses
/// `--test-threads`.
async fn setup_for_rate_limit() -> (axum::Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let config_path = dir.path().join("config.toml");

    // Force `login_rps = 1, login_burst = 10` explicitly — these are the
    // defaults today, but pinning them in the test config protects this
    // test from a future relaxation of the defaults.
    let config_content = format!(
        r#"
[api]
listen = "127.0.0.1:0"

[auth]
jwt_secret_env = "TEST_JWT_SECRET"
user_db = "{}"
max_login_attempts = 5
lockout_duration_minutes = 15
access_token_ttl_minutes = 15
refresh_token_ttl_days = 7

[routeros]
host_env = "ROUTEROS_HOST"
user_env = "ROUTEROS_USER"
password_env = "ROUTEROS_PASSWORD"

[logging]
level = "info"
buffer_size = 100

[security]
login_rps = 1
login_burst = 10
"#,
        db_path.to_string_lossy()
    );
    std::fs::write(&config_path, &config_content).unwrap();
    // SAFETY: env vars set before any multithreaded work
    unsafe {
        std::env::set_var(
            "TEST_JWT_SECRET",
            "test-secret-for-testing-only-must-be-32-bytes-long!",
        );
        std::env::set_var("SNX_EDGE_ADMIN_PASSWORD", "adminpass123");
        std::env::set_var("ROUTEROS_HOST", "127.0.0.1");
        std::env::set_var("ROUTEROS_USER", "admin");
        std::env::set_var("ROUTEROS_PASSWORD", "test");
    }

    let config = snx_edge_server::config::AppConfig::load(&config_path.to_string_lossy()).unwrap();
    let log_buffer = snx_edge_server::api::logs::new_log_buffer(100);
    let (event_tx, _) = tokio::sync::broadcast::channel(64);
    let shutdown = tokio_util::sync::CancellationToken::new();
    let state = snx_edge_server::state::AppState::with_shared(
        config,
        config_path.to_string_lossy().to_string(),
        log_buffer,
        event_tx,
        shutdown,
    )
    .await
    .unwrap();
    let app = snx_edge_server::api::router(state);
    (app, dir)
}

fn login_request(username: &str, password: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"username": username, "password": password}).to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn test_auth_login_rate_limit_kicks_in() {
    // burst = 10 → first 10 logins survive (regardless of whether the
    // credentials are valid; rate-limit runs before auth). The 11th hits
    // 429 from the GovernorLayer.
    //
    // We use a NON-EXISTENT username so each handler returns 401 fast
    // without running bcrypt; bcrypt at cost=13 takes ~600ms per call,
    // long enough that the 1 rps refill would top up the bucket faster
    // than the test consumes burst capacity, and the 11th request would
    // never see 429.
    //
    // Test harness sends requests with no `ConnectInfo<SocketAddr>` extension
    // (axum's `oneshot` skips `into_make_service_with_connect_info`), so all
    // requests share the synthetic-IP bucket from `PeerIpOrSynthetic`.
    let (app, _dir) = setup_for_rate_limit().await;

    for i in 0..10 {
        let resp = app
            .clone()
            .oneshot(login_request("nonexistent", "x"))
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "request {i} should not yet be rate-limited"
        );
    }

    let resp = app
        .clone()
        .oneshot(login_request("nonexistent", "x"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "11th request must be rate-limited"
    );

    // Body must follow the RFC 7807 envelope so clients/CTL parse it the
    // same way they parse other API errors.
    let body = resp_json(resp).await;
    assert_eq!(body["status"], 429);
    assert_eq!(body["title"], "rate limited");
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or("")
            .contains("too many login attempts"),
        "unexpected detail: {body:?}"
    );
}

// === SSE wire-format tests ===

/// Asserting that a slow SSE consumer receives a `lag` frame requires
/// publishing >channel_capacity events strictly between the consumer's
/// subscribe and the consumer's first poll. With axum's response body
/// machinery polling eagerly and only the `event_tx` clone available
/// externally, we cannot reliably stuff the channel before axum drains it.
/// The unit-level mechanics are covered in `log_layer::tests` and the
/// lag-frame construction lives in `api::events::lag_event`. End-to-end
/// repro is best done manually:
///
///   1. Lower the broadcast capacity in main.rs to 4.
///   2. `curl -N` /api/v1/events with a `Bearer` token.
///   3. Stop reading (Ctrl-Z the curl) while triggering >4 logs server-side.
///   4. Resume curl — the next frame should be `event: lag` with `missed > 0`.
#[tokio::test]
#[ignore = "non-deterministic; see comment for manual repro"]
async fn test_sse_logs_emits_lag_event_when_consumer_falls_behind() {
    // Intentionally empty — kept as a marker so future contributors can find
    // and unfreeze this once a deterministic harness exists.
}

// === Task 5.3: JWT generation revocation ===

/// Helper: log in as a user and return the resulting access token.
async fn login_as(app: &axum::Router, username: &str, password: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username": username, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    body["access_token"].as_str().unwrap().to_string()
}

/// Deleting a user must immediately invalidate their outstanding JWT access
/// tokens — without the token-generation check, the JWT keeps passing
/// `require_auth` until its natural ~15 min TTL.
#[tokio::test]
async fn delete_user_invalidates_existing_tokens() {
    let (app, admin_token, _dir) = setup().await;

    // Create a victim user and log in as them to capture an access token.
    let resp = app
        .clone()
        .oneshot(auth_post(
            "/api/v1/users",
            &admin_token,
            json!({"username": "victim", "password": "victim12345", "role": "viewer"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let user = resp_json(resp).await;
    let user_id = user["id"].as_str().unwrap().to_string();

    let victim_token = login_as(&app, "victim", "victim12345").await;

    // Sanity check: token works before deletion.
    let resp = app
        .clone()
        .oneshot(auth_get("/api/v1/users/me", &victim_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Admin deletes the victim.
    let resp = app
        .clone()
        .oneshot(auth_delete(
            &format!("/api/v1/users/{user_id}"),
            &admin_token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The captured token is now stale: middleware must reject it.
    let resp = app
        .oneshot(auth_get("/api/v1/users/me", &victim_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Same property on the change-password path: bumping `token_generation`
/// inside `change_password` must reject already-issued access tokens.
#[tokio::test]
async fn change_password_invalidates_existing_tokens() {
    let (app, admin_token, _dir) = setup().await;

    app.clone()
        .oneshot(auth_post(
            "/api/v1/users",
            &admin_token,
            json!({"username": "alice", "password": "alicepass1", "role": "viewer"}),
        ))
        .await
        .unwrap();

    let alice_token = login_as(&app, "alice", "alicepass1").await;

    // Look up Alice's id while we still have a valid token.
    let me_resp = app
        .clone()
        .oneshot(auth_get("/api/v1/users/me", &alice_token))
        .await
        .unwrap();
    let me = resp_json(me_resp).await;
    let alice_id = me["id"].as_str().unwrap().to_string();

    // Change Alice's password (admin path — no current_password needed).
    let url = format!("/api/v1/users/{alice_id}/password");
    let resp = app
        .clone()
        .oneshot(auth_post(
            &url,
            &admin_token,
            json!({"new_password": "newpass5678"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The pre-change token should now be revoked.
    let resp = app
        .oneshot(auth_get("/api/v1/users/me", &alice_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// `POST /users/{id}/revoke-tokens` is a pure generation bump — no other
/// side effects on the user row or sessions table.
#[tokio::test]
async fn revoke_tokens_endpoint_works() {
    let (app, admin_token, _dir) = setup().await;

    let resp = app
        .clone()
        .oneshot(auth_post(
            "/api/v1/users",
            &admin_token,
            json!({"username": "bob", "password": "bobpass123", "role": "viewer"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let user = resp_json(resp).await;
    let user_id = user["id"].as_str().unwrap().to_string();

    let bob_token = login_as(&app, "bob", "bobpass123").await;

    // Sanity check.
    let resp = app
        .clone()
        .oneshot(auth_get("/api/v1/users/me", &bob_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Admin revokes Bob's tokens via the dedicated endpoint.
    let resp = app
        .clone()
        .oneshot(auth_post(
            &format!("/api/v1/users/{user_id}/revoke-tokens"),
            &admin_token,
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Bob's old token is now revoked.
    let resp = app
        .oneshot(auth_get("/api/v1/users/me", &bob_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// === Task 5.4: Profile encryption at rest ===
//
// These two tests both mutate the `SNX_EDGE_PROFILE_KEY` env var and would
// race if cargo's test harness ran them in parallel — a "no key" test could
// observe the "with key" test's value and vice versa. We fold them into a
// single sequential test so the env-var transitions are deterministic.
// AppState reads the env once at construction time, so each phase builds a
// fresh state with a fresh DB file under its own tempdir.

#[tokio::test]
async fn profile_encryption_create_get_round_trip_and_legacy_compat() {
    use base64::Engine;

    // --- Phase 1: with the env var SET, the on-disk blob must be ciphertext.
    let key_bytes: [u8; 32] = [7u8; 32];
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(key_bytes);
    // SAFETY: env mutations are confined to this single (sequential) test.
    unsafe {
        std::env::set_var("SNX_EDGE_PROFILE_KEY", &key_b64);
    }

    let (app, admin_token, dir) = setup().await;

    let resp = app
        .clone()
        .oneshot(auth_post(
            "/api/v1/profiles",
            &admin_token,
            json!({
                "name": "Encrypted VPN",
                "config": {
                    "server": "vpn.test.com",
                    "username": "u",
                    "password": "supersecret-PLAIN",
                    "mtu": 1400,
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp_json(resp).await;
    assert_eq!(body["config"]["password"], "***");
    let id = body["id"].as_str().unwrap().to_string();

    let db_path = dir.path().join("test.db");
    let cfg: String = {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.query_row(
            "SELECT config FROM profiles WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert!(
        cfg.contains("__enc_v"),
        "expected on-disk JSON to carry __enc_v marker, got: {cfg}"
    );
    assert!(
        !cfg.contains("supersecret-PLAIN"),
        "plaintext password leaked into SQLite: {cfg}"
    );

    // Drop the first state's tempdir before phase 2 so the next AppState
    // gets a clean slate and isn't fighting WAL / file handles.
    drop(app);
    drop(dir);

    // --- Phase 2: with the env var UNSET, the on-disk blob is plaintext.
    // SAFETY: see above.
    unsafe {
        std::env::remove_var("SNX_EDGE_PROFILE_KEY");
    }
    let (app, admin_token, dir) = setup().await;
    let resp = app
        .clone()
        .oneshot(auth_post(
            "/api/v1/profiles",
            &admin_token,
            json!({
                "name": "Plaintext VPN",
                "config": {
                    "server": "vpn.test.com",
                    "username": "u",
                    "password": "compatpass",
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp_json(resp).await;
    let id = body["id"].as_str().unwrap().to_string();

    let db_path = dir.path().join("test.db");
    let cfg: String = {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.query_row(
            "SELECT config FROM profiles WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert!(
        !cfg.contains("__enc_v"),
        "expected no encryption marker in legacy mode, got: {cfg}"
    );
    assert!(
        cfg.contains("compatpass"),
        "expected plaintext in legacy mode, got: {cfg}"
    );
}

// === Task 1.6: corp subnets (vpn-corp) for split-tunnel marking ===

/// `POST /api/v1/routing/corp` must validate the CIDR *before* touching
/// RouterOS. A malformed address is rejected with 400 with no network call,
/// while a well-formed IPv4 CIDR passes validation and then fails at the
/// (unreachable, in tests) RouterOS layer — i.e. anything but a 400.
#[tokio::test]
async fn corp_subnet_add_validates_cidr() {
    let (app, token, _dir) = setup().await;

    // Invalid CIDR → 400 BadRequest, short-circuited before RouterOS.
    let resp = app
        .clone()
        .oneshot(auth_post(
            "/api/v1/routing/corp",
            &token,
            json!({"address": "not-a-cidr"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Valid IPv4 CIDR → passes validation; RouterOS is unreachable in tests
    // (config points at 127.0.0.1, no REST server) so the handler reaches the
    // RouterOS layer and returns a 5xx (502 Bad Gateway) — crucially NOT 400.
    let resp = app
        .oneshot(auth_post(
            "/api/v1/routing/corp",
            &token,
            json!({"address": "10.20.0.0/16"}),
        ))
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "valid CIDR must pass validation and reach the RouterOS layer"
    );
    assert!(
        resp.status().is_server_error(),
        "valid CIDR should fail at the unreachable RouterOS layer, got {}",
        resp.status()
    );
}

/// RBAC: the `operator` role must be able to manage corp subnets (split-tunnel
/// intent). Operator holds `routing.corp.*` but NOT `routing.read`, so a `GET
/// /api/v1/routing/corp` must pass the permission gate and reach the
/// (unreachable, in tests) RouterOS layer — i.e. anything but 403 FORBIDDEN.
/// For symmetry, a `viewer` (no `routing.corp.create`) must be 403 on create.
#[tokio::test]
async fn corp_subnet_rbac_operator_authorized() {
    let (app, token, _dir) = setup().await;

    // Create operator
    app.clone()
        .oneshot(auth_post(
            "/api/v1/users",
            &token,
            json!({"username": "op_corp", "password": "operator123", "role": "operator"}),
        ))
        .await
        .unwrap();

    // Login as operator
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username": "op_corp", "password": "operator123"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp_json(resp).await;
    let operator_token = body["access_token"].as_str().unwrap();

    // Operator can list corp subnets: the request passes RBAC and reaches the
    // RouterOS layer (unreachable in tests → 5xx). Crucially NOT 403.
    let resp = app
        .clone()
        .oneshot(auth_get("/api/v1/routing/corp", operator_token))
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "operator must be authorized to list corp subnets, got {}",
        resp.status()
    );

    // Symmetry: a viewer lacks `routing.corp.create` → 403 on create.
    app.clone()
        .oneshot(auth_post(
            "/api/v1/users",
            &token,
            json!({"username": "viewer_corp", "password": "viewer12345", "role": "viewer"}),
        ))
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username": "viewer_corp", "password": "viewer12345"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp_json(resp).await;
    let viewer_token = body["access_token"].as_str().unwrap();
    let resp = app
        .oneshot(auth_post(
            "/api/v1/routing/corp",
            viewer_token,
            json!({"address": "10.20.0.0/16"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "viewer must be forbidden from creating corp subnets"
    );
}

// === Task 5.5: bcrypt transparent rehash ===

/// Plant a user with a cost-10 bcrypt hash directly in the DB, log in via
/// the API, and assert the stored hash now uses the new cost.
#[tokio::test]
async fn login_rehashes_old_cost_bcrypt_to_new() {
    let (app, _admin_token, dir) = setup().await;

    // Insert a user whose password was hashed at the old cost (10) directly.
    let db_path = dir.path().join("test.db");
    let username = "legacyuser";
    let password = "legacypass1";
    let old_hash = bcrypt::hash(password, 10).unwrap();
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, comment,
                                enabled, failed_login_attempts, locked_until,
                                created_at, updated_at, token_generation)
             VALUES (?1, ?2, ?3, 'viewer', '', 1, 0, NULL, ?4, ?4, 0)",
            rusqlite::params![id, username, old_hash, now],
        )
        .unwrap();
    }

    // Sanity check on the old hash's cost.
    use bcrypt::HashParts;
    use std::str::FromStr;
    let parts = HashParts::from_str(&old_hash).unwrap();
    assert_eq!(parts.get_cost(), 10);

    // Log in via the API. The login handler should transparently rehash.
    let _ = login_as(&app, username, password).await;

    // Read back the stored hash and verify the cost has been bumped.
    let new_hash: String = {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.query_row(
            "SELECT password_hash FROM users WHERE username = ?1",
            rusqlite::params![username],
            |row| row.get(0),
        )
        .unwrap()
    };
    let new_parts = HashParts::from_str(&new_hash).unwrap();
    assert_eq!(
        new_parts.get_cost(),
        snx_edge_server::db::BCRYPT_COST,
        "stored hash should have been rehashed to BCRYPT_COST"
    );
    // The rehash path must NOT touch the old plaintext — verifying with the
    // original password should still succeed.
    assert!(bcrypt::verify(password, &new_hash).unwrap());
}
