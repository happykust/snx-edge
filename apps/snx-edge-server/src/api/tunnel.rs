use axum::extract::State;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};

use snx_edge_types::tunnel::{ChallengeRequest, ConnectRequest, ServerInfoRequest};

use crate::api::auth::{Claims, has_permission};
use crate::error::AppError;
use crate::state::AppState;
use crate::tunnel::{TunnelStatus, VpnConfig, VpnRoute};

/// POST /api/v1/tunnel/connect
async fn connect(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<ConnectRequest>,
) -> Result<Json<TunnelStatus>, AppError> {
    if !has_permission(&claims, "tunnel.connect") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.connect' required".to_string(),
        ));
    }

    // Load VPN config from profile
    let config_str = state.db.get_profile_config(&req.profile_id).await?;
    let vpn_config: VpnConfig = serde_json::from_str(&config_str)
        .map_err(|e| AppError::Internal(format!("invalid profile config: {e}")))?;

    if vpn_config.server.is_empty() {
        return Err(AppError::BadRequest(
            "profile has no VPN server configured".to_string(),
        ));
    }

    // Record the operator intent the supervisor reads (`KEY_DESIRED` /
    // `KEY_AUTO_CONNECT` in supervisor.rs) BEFORE dialing the tunnel, so an
    // unexpected drop mid-connect still leaves the supervisor able to reconnect.
    state
        .db
        .set_app_state("desired_profile_id", &req.profile_id)
        .await?;
    state.db.set_app_state("auto_connect", "true").await?;
    // Re-arm supervisor auto-reconnect: an explicit operator connect clears any
    // durable suspension latched after a prior give-up (see supervisor.rs).
    state
        .reconnect_suspended
        .store(false, std::sync::atomic::Ordering::SeqCst);

    state
        .tunnel
        .connect(&vpn_config)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Json(state.tunnel.status().await))
}

/// POST /api/v1/tunnel/disconnect
async fn disconnect(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<TunnelStatus>, AppError> {
    if !has_permission(&claims, "tunnel.disconnect") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.disconnect' required".to_string(),
        ));
    }

    // Clear the desired intent BEFORE tearing the tunnel down: a deliberate
    // user disconnect must stop the supervisor from auto-reconnecting (an
    // unexpected drop leaves these keys set so it does reconnect).
    state.db.delete_app_state("desired_profile_id").await?;
    state.db.delete_app_state("auto_connect").await?;

    state
        .tunnel
        .disconnect()
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Json(state.tunnel.status().await))
}

/// POST /api/v1/tunnel/reconnect
async fn reconnect(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<ConnectRequest>,
) -> Result<Json<TunnelStatus>, AppError> {
    if !has_permission(&claims, "tunnel.connect") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.connect' required".to_string(),
        ));
    }

    let config_str = state.db.get_profile_config(&req.profile_id).await?;
    let vpn_config: VpnConfig = serde_json::from_str(&config_str)
        .map_err(|e| AppError::Internal(format!("invalid profile config: {e}")))?;

    state
        .tunnel
        .reconnect(&vpn_config)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Json(state.tunnel.status().await))
}

/// GET /api/v1/tunnel/status
async fn status(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<TunnelStatus>, AppError> {
    if !has_permission(&claims, "tunnel.status") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.status' required".to_string(),
        ));
    }

    Ok(Json(state.tunnel.status().await))
}

/// GET /api/v1/server/info — return info about the current (or last) VPN server.
async fn server_info_current(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !has_permission(&claims, "tunnel.status") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.status' required".to_string(),
        ));
    }

    let server = state.tunnel.current_server().await.ok_or_else(|| {
        AppError::NotFound(
            "no server available; connect first or use POST with a server address".to_string(),
        )
    })?;

    let vpn_config = VpnConfig {
        server,
        ..VpnConfig::default()
    };

    let info = state
        .tunnel
        .server_info(&vpn_config)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(info))
}

/// Addresses the management API must never be talked into dialling.
///
/// `POST /server/info` takes a caller-supplied host, so without this the
/// endpoint is a probe into whatever the router can reach — LAN hosts, the
/// router's own services, cloud metadata endpoints. A Check Point gateway is
/// by definition reachable from the internet, so refusing internal ranges
/// costs nothing legitimate.
fn is_internal_addr(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || a == 0
                // CGNAT 100.64.0.0/10 — common on ISP-managed routers.
                || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique-local fc00::/7 and link-local fe80::/10.
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                // IPv4-mapped: unwrap and apply the v4 rules.
                || v6.to_ipv4_mapped().is_some_and(|v4| is_internal_addr(IpAddr::V4(v4)))
        }
    }
}

/// Split a `server` field into host and port, tolerating a bare host, a
/// `host:port` pair, and a bracketed IPv6 literal.
fn split_host_port(server: &str) -> (String, u16) {
    const DEFAULT_PORT: u16 = 443;

    if let Some(rest) = server.strip_prefix('[') {
        // [::1]:443 or [::1]
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(DEFAULT_PORT);
            return (host.to_string(), port);
        }
    }

    // A bare IPv6 literal has several colons; only treat the last colon as a
    // port separator when there is exactly one.
    if server.matches(':').count() == 1
        && let Some((host, port)) = server.split_once(':')
        && let Ok(port) = port.parse()
    {
        return (host.to_string(), port);
    }

    (server.to_string(), DEFAULT_PORT)
}

/// Reject targets that resolve into the router's own networks.
///
/// Hostnames are resolved first, and *every* returned address must be
/// external — a name with one public and one private A record is refused
/// rather than raced.
async fn reject_internal_target(server: &str) -> Result<(), AppError> {
    let (host, port) = split_host_port(server);

    if host.is_empty() {
        return Err(AppError::BadRequest("server address is empty".to_string()));
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return if is_internal_addr(ip) {
            Err(AppError::BadRequest(format!(
                "refusing to query {host}: address is inside a private, loopback, or \
                 link-local range"
            )))
        } else {
            Ok(())
        };
    }

    let resolved = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| AppError::BadRequest(format!("cannot resolve {host}: {e}")))?;

    let mut any = false;
    for addr in resolved {
        any = true;
        if is_internal_addr(addr.ip()) {
            return Err(AppError::BadRequest(format!(
                "refusing to query {host}: it resolves to {}, which is inside a private, \
                 loopback, or link-local range",
                addr.ip()
            )));
        }
    }

    if !any {
        return Err(AppError::BadRequest(format!(
            "cannot resolve {host}: no addresses returned"
        )));
    }

    Ok(())
}

/// POST /api/v1/server/info — query Check Point server capabilities.
async fn server_info(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<ServerInfoRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Deliberately stricter than the GET form: this one dials a host the
    // caller chose, which is an action, not a read.
    if !has_permission(&claims, "tunnel.connect") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.connect' required".to_string(),
        ));
    }

    reject_internal_target(&req.server).await?;

    let vpn_config = VpnConfig {
        server: req.server,
        ..VpnConfig::default()
    };

    let info = state
        .tunnel
        .server_info(&vpn_config)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(info))
}

/// GET /api/v1/routes
async fn vpn_routes(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<VpnRoute>>, AppError> {
    if !has_permission(&claims, "tunnel.status") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.status' required".to_string(),
        ));
    }

    Ok(Json(state.tunnel.routes().await))
}

/// POST /api/v1/tunnel/challenge — submit MFA code
async fn challenge(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<TunnelStatus>, AppError> {
    if !has_permission(&claims, "tunnel.connect") {
        return Err(AppError::Forbidden(
            "permission 'tunnel.connect' required".to_string(),
        ));
    }

    state
        .tunnel
        .challenge_code(&req.code)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Json(state.tunnel.status().await))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/tunnel/connect", post(connect))
        .route("/tunnel/disconnect", post(disconnect))
        .route("/tunnel/reconnect", post(reconnect))
        .route("/tunnel/status", get(status))
        .route("/tunnel/challenge", post(challenge))
        .route("/server/info", get(server_info_current).post(server_info))
        .route("/tunnel/routes", get(vpn_routes))
}

#[cfg(test)]
mod ssrf_guard_tests {
    use super::{is_internal_addr, split_host_port};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address must parse")
    }

    #[test]
    fn internal_ranges_are_recognised() {
        for addr in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.88.1",
            "169.254.169.254", // cloud metadata
            "100.100.0.1",     // CGNAT
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1", // IPv4-mapped private
        ] {
            assert!(is_internal_addr(ip(addr)), "{addr} must count as internal");
        }
    }

    #[test]
    fn public_addresses_are_allowed() {
        for addr in ["1.1.1.1", "8.8.8.8", "203.0.113.10", "2606:4700::1111"] {
            assert!(!is_internal_addr(ip(addr)), "{addr} must be allowed");
        }
    }

    #[test]
    fn host_port_splitting_handles_every_shape() {
        assert_eq!(
            split_host_port("vpn.example.com"),
            ("vpn.example.com".to_string(), 443)
        );
        assert_eq!(
            split_host_port("vpn.example.com:8443"),
            ("vpn.example.com".to_string(), 8443)
        );
        assert_eq!(split_host_port("[::1]:8443"), ("::1".to_string(), 8443));
        assert_eq!(split_host_port("[::1]"), ("::1".to_string(), 443));
        // A bare IPv6 literal has more than one colon and no brackets: it must
        // stay intact rather than lose its tail to a phantom port.
        assert_eq!(
            split_host_port("2606:4700::1111"),
            ("2606:4700::1111".to_string(), 443)
        );
    }
}
