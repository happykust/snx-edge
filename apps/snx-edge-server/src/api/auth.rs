use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::db::UserDb;
use crate::error::AppError;
use crate::state::AppState;

// === JWT Claims ===

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // user_id
    pub role: String,
    pub permissions: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    /// "access" or "refresh"
    pub token_type: String,
}

// === Request/Response types ===

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

// === Handlers ===

/// Wrapper around `ConnectInfo<SocketAddr>` that yields `None` instead of
/// rejecting the request when the extension is missing.
///
/// `ConnectInfo` itself does not implement `OptionalFromRequestParts`, so
/// `Option<ConnectInfo<SocketAddr>>` does not compile. Test harnesses (e.g.
/// `tower::ServiceExt::oneshot`) drive the router without
/// `into_make_service_with_connect_info`, so we need to tolerate its absence.
struct OptPeerAddr(Option<SocketAddr>);

impl<S> FromRequestParts<S> for OptPeerAddr
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| ci.0),
        ))
    }
}

async fn login(
    State(state): State<AppState>,
    OptPeerAddr(peer_addr): OptPeerAddr,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let user = state
        .db
        .get_user_by_username(&req.username)
        .await
        .map_err(|_| AppError::Unauthorized("invalid credentials".to_string()))?;

    // Check if account is locked (generic message — don't reveal unlock time)
    if let Some(locked_until) = user.locked_until {
        if Utc::now() < locked_until {
            return Err(AppError::Unauthorized(
                "account temporarily locked due to too many failed attempts".to_string(),
            ));
        }
        // Lock expired, reset atomically to prevent race condition
        // (multiple concurrent requests seeing expired lock all reset and get fresh attempts)
        state.db.reset_failed_logins(&user.id).await?;
    }

    if !user.enabled {
        return Err(AppError::Unauthorized("account disabled".to_string()));
    }

    // Verify password (offload CPU-intensive bcrypt to blocking thread)
    let password = req.password.clone();
    let password_hash = user.password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || bcrypt::verify(password, &password_hash))
        .await
        .map_err(|e| AppError::Internal(format!("blocking task error: {e}")))?
        .map_err(|e| AppError::Internal(format!("bcrypt error: {e}")))?;
    if !valid {
        let config = state.config.read().await;
        let max_attempts = config.auth.max_login_attempts;
        let lockout_minutes = config.auth.lockout_duration_minutes;
        drop(config);
        state
            .db
            .record_failed_login(&user.id, max_attempts, lockout_minutes)
            .await?;
        return Err(AppError::Unauthorized("invalid credentials".to_string()));
    }

    // Reset failed attempts on successful login
    state.db.reset_failed_logins(&user.id).await?;

    let ip = {
        let cfg = state.config.read().await;
        extract_client_ip(&headers, peer_addr, &cfg)
    };
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let tokens = issue_tokens(
        &state,
        &user.id,
        &user.role,
        ip.as_deref(),
        user_agent.as_deref(),
    )
    .await?;
    Ok(Json(tokens))
}

async fn refresh(
    State(state): State<AppState>,
    OptPeerAddr(peer_addr): OptPeerAddr,
    headers: HeaderMap,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let claims = decode_token(&state.jwt_secret, &req.refresh_token)?;

    if claims.token_type != "refresh" {
        return Err(AppError::Unauthorized("not a refresh token".to_string()));
    }

    // Check session still valid
    if !state.db.session_exists(&claims.jti).await? {
        return Err(AppError::Unauthorized("session revoked".to_string()));
    }

    // Invalidate old refresh session
    state.db.delete_session(&claims.jti).await?;

    // Check user still exists and enabled
    let user = state.db.get_user_by_id(&claims.sub).await?;
    if !user.enabled {
        return Err(AppError::Unauthorized("account disabled".to_string()));
    }

    let ip = {
        let cfg = state.config.read().await;
        extract_client_ip(&headers, peer_addr, &cfg)
    };
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let tokens = issue_tokens(
        &state,
        &user.id,
        &user.role,
        ip.as_deref(),
        user_agent.as_deref(),
    )
    .await?;
    Ok(Json(tokens))
}

// === Token helpers ===

async fn issue_tokens(
    state: &AppState,
    user_id: &str,
    role: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<TokenResponse, AppError> {
    let config = state.config.read().await;
    let access_ttl_min = config.auth.access_token_ttl_minutes;
    let refresh_ttl_days = config.auth.refresh_token_ttl_days;
    drop(config);

    let permissions: Vec<String> = UserDb::permissions_for_role(role)
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let now = Utc::now();

    // Access token
    let access_exp = now + Duration::minutes(access_ttl_min as i64);
    let access_jti = Uuid::new_v4().to_string();
    let access_claims = Claims {
        sub: user_id.to_string(),
        role: role.to_string(),
        permissions: permissions.clone(),
        exp: access_exp.timestamp(),
        iat: now.timestamp(),
        jti: access_jti,
        token_type: "access".to_string(),
    };

    // Refresh token
    let refresh_exp = now + Duration::days(refresh_ttl_days as i64);
    let refresh_jti = Uuid::new_v4().to_string();
    let refresh_claims = Claims {
        sub: user_id.to_string(),
        role: role.to_string(),
        permissions,
        exp: refresh_exp.timestamp(),
        iat: now.timestamp(),
        jti: refresh_jti.clone(),
        token_type: "refresh".to_string(),
    };

    let key = EncodingKey::from_secret(state.jwt_secret.as_bytes());
    let access_token = jsonwebtoken::encode(&Header::default(), &access_claims, &key)?;
    let refresh_token = jsonwebtoken::encode(&Header::default(), &refresh_claims, &key)?;

    // Store refresh session
    state
        .db
        .create_session(&refresh_jti, user_id, ip, user_agent, refresh_exp)
        .await?;

    Ok(TokenResponse {
        access_token,
        refresh_token,
        token_type: "Bearer",
        expires_in: access_ttl_min as i64 * 60,
    })
}

pub fn decode_token(secret: &str, token: &str) -> Result<Claims, AppError> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let data = jsonwebtoken::decode::<Claims>(token, &key, &Validation::default())?;
    Ok(data.claims)
}

/// Axum middleware: extract and validate JWT from Authorization header.
///
/// NOTE: Access tokens are stateless JWTs -- they are NOT checked against
/// the database on every request.  This means an access token remains
/// valid for up to `access_token_ttl_minutes` (default 15 min) after the
/// owning user is deleted or has all sessions revoked.  This is an
/// intentional tradeoff: it avoids a DB round-trip on every authenticated
/// request while keeping the exposure window short.  Refresh tokens *are*
/// validated against stored sessions, so revocation takes full effect once
/// the current access token expires.
pub async fn require_auth(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AppError> {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("invalid authorization scheme".to_string()))?;

    let claims = decode_token(&state.jwt_secret, token)?;

    if claims.token_type != "access" {
        return Err(AppError::Unauthorized("not an access token".to_string()));
    }

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

/// Check if the current user has a specific permission.
pub fn has_permission(claims: &Claims, required: &str) -> bool {
    claims.permissions.iter().any(|p| {
        p == required || {
            // Wildcard: "tunnel.*" matches "tunnel.connect" but not "tunnel_evil"
            if let Some(prefix) = p.strip_suffix(".*") {
                required.starts_with(&format!("{prefix}."))
            } else {
                false
            }
        }
    })
}

/// Extract the client IP address for audit logging.
///
/// `X-Forwarded-For` / `X-Real-IP` are only honoured when the request's TCP
/// `peer_addr` matches one of `security.trusted_proxies` (CIDR strings).
/// Otherwise the peer address is used directly — this prevents an attacker
/// from spoofing audit-log IPs by setting their own forwarded-for header.
///
/// If `peer_addr` is `None` (e.g. running under a test harness that doesn't
/// supply `ConnectInfo`) the function falls back to the headers, since there
/// is no peer to trust against.
fn extract_client_ip(
    headers: &HeaderMap,
    peer_addr: Option<SocketAddr>,
    config: &AppConfig,
) -> Option<String> {
    let trust_proxy = match peer_addr {
        Some(peer) => peer_in_trusted_proxies(peer.ip(), &config.security.trusted_proxies),
        None => true, // tests / no ConnectInfo: best-effort header fallback
    };

    if trust_proxy {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
            .filter(|s| !s.is_empty())
        {
            return Some(ip);
        }
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
        {
            return Some(ip);
        }
    }

    peer_addr.map(|p| p.ip().to_string())
}

/// Returns `true` if `addr` falls inside any of the `cidrs` (each `"ip/prefix"`).
///
/// Inline parser to avoid adding the `ipnet` crate just for this. Bad CIDR
/// strings are silently skipped — admins should validate config before deploy
/// and we don't want a bad config entry to fail-open.
fn peer_in_trusted_proxies(addr: IpAddr, cidrs: &[String]) -> bool {
    cidrs.iter().any(|cidr| cidr_contains(cidr, addr))
}

fn cidr_contains(cidr: &str, addr: IpAddr) -> bool {
    let (net_str, prefix_str) = match cidr.split_once('/') {
        Some(parts) => parts,
        // No prefix: treat as a single-host match.
        None => return cidr.parse::<IpAddr>().map(|n| n == addr).unwrap_or(false),
    };

    let Ok(network) = net_str.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u8>() else {
        return false;
    };

    match (network, addr) {
        (IpAddr::V4(net), IpAddr::V4(host)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(net) & mask) == (u32::from(host) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(host)) => {
            if prefix > 128 {
                return false;
            }
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(net) & mask) == (u128::from(host) & mask)
        }
        // Mixed-family CIDR/peer comparisons can never match.
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn cidr_contains_ipv4_match() {
        assert!(cidr_contains(
            "10.0.0.0/8",
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))
        ));
        assert!(cidr_contains(
            "192.168.1.0/24",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))
        ));
    }

    #[test]
    fn cidr_contains_ipv4_miss() {
        assert!(!cidr_contains(
            "10.0.0.0/8",
            IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))
        ));
        assert!(!cidr_contains(
            "192.168.1.0/24",
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))
        ));
    }

    #[test]
    fn cidr_contains_zero_prefix_matches_all_v4() {
        // /0 must match everything in the same family without overshifting.
        assert!(cidr_contains(
            "0.0.0.0/0",
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        ));
    }

    #[test]
    fn cidr_contains_full_prefix_is_exact_host() {
        assert!(cidr_contains(
            "192.0.2.5/32",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5))
        ));
        assert!(!cidr_contains(
            "192.0.2.5/32",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 6))
        ));
    }

    #[test]
    fn cidr_contains_rejects_garbage() {
        assert!(!cidr_contains(
            "not-a-cidr",
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        ));
        assert!(!cidr_contains(
            "10.0.0.0/zz",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        ));
        assert!(!cidr_contains(
            "10.0.0.0/40",
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        ));
    }

    #[test]
    fn cidr_contains_mixed_family_is_false() {
        let v6 = "::1".parse::<IpAddr>().unwrap();
        assert!(!cidr_contains("10.0.0.0/8", v6));
    }

    #[test]
    fn extract_client_ip_distrusts_untrusted_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());

        let cfg = test_config(&[]);
        let peer: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let ip = extract_client_ip(&headers, Some(peer), &cfg);
        assert_eq!(ip.as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn extract_client_ip_trusts_listed_proxy_for_xff() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());

        let cfg = test_config(&["10.0.0.0/8"]);
        let peer: SocketAddr = "10.5.5.5:80".parse().unwrap();
        let ip = extract_client_ip(&headers, Some(peer), &cfg);
        assert_eq!(ip.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn extract_client_ip_takes_first_xff_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());

        let cfg = test_config(&["10.0.0.0/8"]);
        let peer: SocketAddr = "10.5.5.5:80".parse().unwrap();
        let ip = extract_client_ip(&headers, Some(peer), &cfg);
        assert_eq!(ip.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn extract_client_ip_falls_back_to_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "9.9.9.9".parse().unwrap());

        let cfg = test_config(&["10.0.0.0/8"]);
        let peer: SocketAddr = "10.5.5.5:80".parse().unwrap();
        let ip = extract_client_ip(&headers, Some(peer), &cfg);
        assert_eq!(ip.as_deref(), Some("9.9.9.9"));
    }

    /// Build a minimal `AppConfig` for unit tests.
    fn test_config(trusted: &[&str]) -> AppConfig {
        AppConfig {
            api: crate::config::ApiConfig {
                listen: "127.0.0.1:0".to_string(),
                tls_cert: None,
                tls_key: None,
                tls_client_ca: None,
                cors_origins: vec![],
            },
            auth: crate::config::AuthConfig {
                jwt_secret_env: "TEST".to_string(),
                user_db: ":memory:".to_string(),
                max_login_attempts: 5,
                lockout_duration_minutes: 15,
                access_token_ttl_minutes: 15,
                refresh_token_ttl_days: 7,
            },
            routeros: crate::config::RouterOsConfig {
                host_env: String::new(),
                user_env: String::new(),
                password_env: String::new(),
                tls_skip_verify: false,
                comment_tag: String::new(),
                address_list_vpn: String::new(),
                address_list_bypass: String::new(),
                routing_table: String::new(),
                connection_mark: String::new(),
                routing_mark: String::new(),
                auto_setup: false,
            },
            logging: crate::config::LoggingConfig {
                level: "info".to_string(),
                buffer_size: 0,
                file: None,
                max_file_size: String::new(),
                max_files: 0,
            },
            security: crate::config::SecurityConfig {
                allow_no_cert_check: false,
                trusted_proxies: trusted.iter().map(|s| (*s).to_string()).collect(),
            },
        }
    }
}
