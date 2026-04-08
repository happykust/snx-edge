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
    let state = snx_edge_server::state::AppState::with_shared(
        config,
        config_path.to_string_lossy().to_string(),
        log_buffer,
        event_tx,
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
