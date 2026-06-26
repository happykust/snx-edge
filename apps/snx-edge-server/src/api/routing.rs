use std::net::IpAddr;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};

use snx_edge_types::routing::AddressListEntryCreate as AddClientRequest;

use crate::api::auth::{Claims, has_permission};
use crate::error::AppError;
use crate::routeros::models::{AddressListEntry, DiagnosticsResult};
use crate::routeros::provisioner::Provisioner;
use crate::state::{AppState, ServerEvent};

/// Validate that `address` is one of the following accepted forms:
///   - Plain IPv4/IPv6 address (e.g. `192.168.1.1`, `::1`)
///   - CIDR notation            (e.g. `10.0.0.0/24`, `fd00::/64`)
///   - IPv4 range               (e.g. `192.168.1.1-192.168.1.254`)
///
/// Returns `Ok(())` on success, or `Err(AppError::BadRequest)` describing the
/// problem.
fn validate_address(address: &str) -> Result<(), AppError> {
    // 1. Plain IP address
    if address.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    // 2. CIDR notation: ip/prefix
    if let Some((ip_part, prefix_part)) = address.split_once('/') {
        let ip: IpAddr = ip_part
            .parse()
            .map_err(|_| AppError::BadRequest(format!("invalid IP in CIDR notation: {address}")))?;
        let prefix: u8 = prefix_part.parse().map_err(|_| {
            AppError::BadRequest(format!("invalid prefix length in CIDR: {address}"))
        })?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(AppError::BadRequest(format!(
                "prefix length {prefix} exceeds maximum {max} for {address}"
            )));
        }
        return Ok(());
    }

    // 3. IP range: ip-ip  (IPv4 only, as RouterOS uses this form)
    if let Some((start, end)) = address.split_once('-') {
        let _start: std::net::Ipv4Addr = start.parse().map_err(|_| {
            AppError::BadRequest(format!("invalid start address in range: {address}"))
        })?;
        let _end: std::net::Ipv4Addr = end.parse().map_err(|_| {
            AppError::BadRequest(format!("invalid end address in range: {address}"))
        })?;
        return Ok(());
    }

    Err(AppError::BadRequest(format!(
        "invalid address format: expected IPv4/IPv6 address, CIDR (x.x.x.x/N), or range (x.x.x.x-y.y.y.y), got: {address}"
    )))
}

// === VPN Clients (address-list) ===

/// GET /api/v1/routing/clients
async fn list_clients(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<AddressListEntry>>, AppError> {
    if !has_permission(&claims, "routing.clients.read") && !has_permission(&claims, "routing.read")
    {
        return Err(AppError::Forbidden("permission required".to_string()));
    }

    let client = state.routeros_client().await?;
    let address_list_vpn = {
        let config = state.config.read().await;
        config.routeros.address_list_vpn.clone()
    };
    let entries = client.list_address_list(&address_list_vpn).await?;
    Ok(Json(entries))
}

/// POST /api/v1/routing/clients
async fn add_client(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<AddClientRequest>,
) -> Result<(StatusCode, Json<AddressListEntry>), AppError> {
    if !has_permission(&claims, "routing.clients.create") {
        return Err(AppError::Forbidden("permission required".to_string()));
    }

    validate_address(&req.address)?;

    let client = state.routeros_client().await?;
    let address_list_vpn = {
        let config = state.config.read().await;
        config.routeros.address_list_vpn.clone()
    };
    let entry = client
        .add_address(
            &address_list_vpn,
            &req.address,
            "vpn-client",
            req.comment.as_deref(),
            req.disabled,
        )
        .await?;

    let _ = state.event_tx.send(ServerEvent::RoutingChanged);
    Ok((StatusCode::CREATED, Json(entry)))
}

/// DELETE /api/v1/routing/clients/{id}
async fn remove_client(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    if !has_permission(&claims, "routing.clients.delete") {
        return Err(AppError::Forbidden("permission required".to_string()));
    }

    let client = state.routeros_client().await?;
    client.remove_address(&id).await?;

    let _ = state.event_tx.send(ServerEvent::RoutingChanged);
    Ok(StatusCode::NO_CONTENT)
}

// === VPN Bypass (address-list) ===

/// GET /api/v1/routing/bypass
async fn list_bypass(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<Vec<AddressListEntry>>, AppError> {
    if !has_permission(&claims, "routing.bypass.read") && !has_permission(&claims, "routing.read") {
        return Err(AppError::Forbidden("permission required".to_string()));
    }

    let client = state.routeros_client().await?;
    let address_list_bypass = {
        let config = state.config.read().await;
        config.routeros.address_list_bypass.clone()
    };
    let entries = client.list_address_list(&address_list_bypass).await?;
    Ok(Json(entries))
}

/// POST /api/v1/routing/bypass
async fn add_bypass(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<AddClientRequest>,
) -> Result<(StatusCode, Json<AddressListEntry>), AppError> {
    if !has_permission(&claims, "routing.bypass.create") {
        return Err(AppError::Forbidden("permission required".to_string()));
    }

    validate_address(&req.address)?;

    let client = state.routeros_client().await?;
    let address_list_bypass = {
        let config = state.config.read().await;
        config.routeros.address_list_bypass.clone()
    };
    let entry = client
        .add_address(
            &address_list_bypass,
            &req.address,
            "vpn-bypass",
            req.comment.as_deref(),
            req.disabled,
        )
        .await?;

    let _ = state.event_tx.send(ServerEvent::RoutingChanged);
    Ok((StatusCode::CREATED, Json(entry)))
}

/// DELETE /api/v1/routing/bypass/{id}
async fn remove_bypass(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    if !has_permission(&claims, "routing.bypass.delete") {
        return Err(AppError::Forbidden("permission required".to_string()));
    }

    let client = state.routeros_client().await?;
    client.remove_address(&id).await?;

    let _ = state.event_tx.send(ServerEvent::RoutingChanged);
    Ok(StatusCode::NO_CONTENT)
}

// === PBR Setup / Teardown / Status / Diagnostics ===

/// GET /api/v1/routing/status
async fn routing_status(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !has_permission(&claims, "routing.read") {
        return Err(AppError::Forbidden("permission required".to_string()));
    }

    let client = state.routeros_client().await?;
    let routeros_config = {
        let config = state.config.read().await;
        config.routeros.clone()
    };

    let mangles: Vec<crate::routeros::models::MangleRule> =
        client.list_managed("/ip/firewall/mangle").await?;
    let routes: Vec<crate::routeros::models::RouteEntry> = client.list_managed("/ip/route").await?;
    let nats: Vec<crate::routeros::models::NatRule> =
        client.list_managed("/ip/firewall/nat").await?;

    let provisioner = Provisioner::new(&client, &routeros_config);
    let presence = provisioner.presence_snapshot().await?;

    Ok(Json(serde_json::json!({
        "mangle_rules": mangles,
        "routes": routes,
        "nat_rules": nats,
        "routing_table": routeros_config.routing_table,
        "state": presence.state(),
        "presence": {
            "routing_table":       presence.routing_table,
            "mangle_conn_mark":    presence.mangle_conn_mark,
            "mangle_routing_mark": presence.mangle_routing_mark,
            "default_route":       presence.default_route,
            "kill_switch":         presence.kill_switch,
            "dns_dst_nat":         presence.dns_dst_nat,
            "dot_block":           presence.dot_block,
            "fasttrack_bypass":    presence.fasttrack_bypass,
            "rfc1918_bypass":      presence.rfc1918_bypass,
        },
    })))
}

/// POST /api/v1/routing/setup
///
/// Returns:
///   - `200 OK` with `{status: "ok", applied: [...]}` on full success.
///   - `207 Multi-Status` with `{status: "partial", applied: [...],
///     failed: {step, error}}` if any step failed; the steps before the
///     failure were committed on RouterOS and re-running `setup` is safe
///     (each `ensure_*` is idempotent on the new structured comment).
async fn setup_pbr(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Response, AppError> {
    if !has_permission(&claims, "routing.setup") {
        return Err(AppError::Forbidden(
            "permission 'routing.setup' required".to_string(),
        ));
    }

    let client = state.routeros_client().await?;
    let routeros_config = {
        let config = state.config.read().await;
        config.routeros.clone()
    };

    // Determine container IP (our gateway in the veth network)
    let container_ip = detect_container_ip()?;

    let provisioner = Provisioner::new(&client, &routeros_config);
    let report = provisioner.setup(&container_ip).await;

    // Always emit the routing-changed event — even a partial setup
    // mutated state on the router.
    let _ = state.event_tx.send(ServerEvent::RoutingChanged);

    let body = match &report.failed {
        None => serde_json::json!({
            "status": "ok",
            "applied": report.applied,
        }),
        Some((step, err)) => serde_json::json!({
            "status": "partial",
            "applied": report.applied,
            "failed": {
                "step": step,
                "error": err.to_string(),
            },
        }),
    };

    let status = if report.failed.is_some() {
        StatusCode::MULTI_STATUS
    } else {
        StatusCode::OK
    };
    Ok((status, Json(body)).into_response())
}

/// DELETE /api/v1/routing/setup
async fn teardown_pbr(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !has_permission(&claims, "routing.teardown") {
        return Err(AppError::Forbidden(
            "permission 'routing.teardown' required".to_string(),
        ));
    }

    let client = state.routeros_client().await?;
    let routeros_config = {
        let config = state.config.read().await;
        config.routeros.clone()
    };

    let provisioner = Provisioner::new(&client, &routeros_config);
    let removed = provisioner.teardown().await?;

    let _ = state.event_tx.send(ServerEvent::RoutingChanged);

    Ok(Json(serde_json::json!({
        "status": "ok",
        "removed_rules": removed
    })))
}

/// GET /api/v1/routing/diagnostics
async fn diagnostics(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<DiagnosticsResult>, AppError> {
    if !has_permission(&claims, "routing.diagnostics") {
        return Err(AppError::Forbidden("permission required".to_string()));
    }

    let client = state.routeros_client().await?;
    let routeros_config = {
        let config = state.config.read().await;
        config.routeros.clone()
    };

    let provisioner = Provisioner::new(&client, &routeros_config);
    let result = provisioner.diagnostics().await?;

    Ok(Json(result))
}

/// Discover the container's IPv4 address on `eth0` by parsing
/// `ip -4 -o addr show eth0`.
///
/// Returns an `Internal` error if the command fails to spawn, exits non-zero,
/// or produces output we can't parse — the previous silent fallback to
/// `172.19.0.2` would mask a real misconfiguration of the docker network.
pub(crate) fn detect_container_ip() -> Result<String, AppError> {
    let output = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "eth0"])
        .output()
        .map_err(|e| {
            tracing::error!(error = %e, "failed to spawn `ip` command");
            AppError::Internal(format!("could not detect container IP: {e}"))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!(
            status = %output.status,
            stderr = %stderr,
            "`ip` command exited with non-zero status",
        );
        return Err(AppError::Internal(
            "could not detect container IP from `ip` command output".to_string(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Format: `<idx>: <iface> inet <ip>/<prefix> ...` — column 3 (zero-indexed)
    // is the CIDR.  Strip the prefix to leave just the address.
    let cidr = stdout.split_whitespace().nth(3).ok_or_else(|| {
        tracing::error!(
            stdout = %stdout,
            "`ip` command output did not contain a CIDR in column 3",
        );
        AppError::Internal("could not detect container IP from `ip` command output".to_string())
    })?;

    let ip = cidr.split('/').next().ok_or_else(|| {
        tracing::error!(stdout = %stdout, "could not strip CIDR prefix");
        AppError::Internal("could not detect container IP from `ip` command output".to_string())
    })?;

    // Validate it parses as an IPv4 address — guards against junk in column 3.
    ip.parse::<std::net::Ipv4Addr>().map_err(|e| {
        tracing::error!(stdout = %stdout, ip = %ip, error = %e, "failed to parse container IP");
        AppError::Internal("could not detect container IP from `ip` command output".to_string())
    })?;

    Ok(ip.to_string())
}

pub fn routes() -> Router<AppState> {
    Router::new()
        // VPN clients address-list
        .route("/routing/clients", get(list_clients).post(add_client))
        .route("/routing/clients/{id}", delete(remove_client))
        // VPN bypass address-list
        .route("/routing/bypass", get(list_bypass).post(add_bypass))
        .route("/routing/bypass/{id}", delete(remove_bypass))
        // PBR management
        .route("/routing/status", get(routing_status))
        .route("/routing/setup", post(setup_pbr).delete(teardown_pbr))
        .route("/routing/diagnostics", get(diagnostics))
}

#[cfg(test)]
mod tests {
    use super::validate_address;
    use proptest::prelude::*;

    proptest! {
        /// `validate_address` is a pure parser run on user-supplied strings;
        /// it must return `Ok` or `Err` for every input but never panic. The
        /// proptest `.*` strategy generates arbitrary UTF-8 strings (incl.
        /// empty, control chars, multibyte) — the only assertion is that the
        /// function returns at all.
        #[test]
        fn validate_address_does_not_panic(s in ".*") {
            let _ = validate_address(&s);
        }
    }

    #[test]
    fn validate_address_accepts_known_good() {
        assert!(validate_address("192.168.1.1").is_ok());
        assert!(validate_address("::1").is_ok());
        assert!(validate_address("10.0.0.0/8").is_ok());
        assert!(validate_address("fd00::/64").is_ok());
        assert!(validate_address("192.168.1.1-192.168.1.10").is_ok());
    }

    #[test]
    fn validate_address_rejects_garbage() {
        assert!(validate_address("not an address").is_err());
        assert!(validate_address("10.0.0.0/64").is_err()); // prefix > 32 for v4
        assert!(validate_address("").is_err());
    }
}
