use std::net::IpAddr;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;

use crate::api::auth::{Claims, has_permission};
use crate::error::AppError;
use crate::routeros::client::RouterOsClient;
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

// NOTE: RouterOsClient is re-created per request. This is intentional — the env var
// reads (ROUTEROS_HOST, ROUTEROS_USER, ROUTEROS_PASSWORD) are microsecond-cheap
// compared to the HTTP calls that follow, and re-creating allows picking up rotated
// credentials without a server restart. Caching the client in AppState would save
// negligible time while complicating credential rotation and config reload.
async fn make_client(state: &AppState) -> Result<RouterOsClient, AppError> {
    let config = state.config.read().await;
    RouterOsClient::new(&config.routeros)
}

#[derive(Deserialize)]
pub struct AddClientRequest {
    pub address: String,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub disabled: Option<bool>,
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

    let client = make_client(&state).await?;
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

    let client = make_client(&state).await?;
    let address_list_vpn = {
        let config = state.config.read().await;
        config.routeros.address_list_vpn.clone()
    };
    let entry = client
        .add_address(
            &address_list_vpn,
            &req.address,
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

    let client = make_client(&state).await?;
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

    let client = make_client(&state).await?;
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

    let client = make_client(&state).await?;
    let address_list_bypass = {
        let config = state.config.read().await;
        config.routeros.address_list_bypass.clone()
    };
    let entry = client
        .add_address(
            &address_list_bypass,
            &req.address,
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

    let client = make_client(&state).await?;
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

    let client = make_client(&state).await?;
    let routing_table = {
        let config = state.config.read().await;
        config.routeros.routing_table.clone()
    };

    let mangles: Vec<crate::routeros::models::MangleRule> =
        client.list_managed("/ip/firewall/mangle").await?;
    let routes: Vec<crate::routeros::models::RouteEntry> = client.list_managed("/ip/route").await?;
    let nats: Vec<crate::routeros::models::NatRule> =
        client.list_managed("/ip/firewall/nat").await?;

    Ok(Json(serde_json::json!({
        "mangle_rules": mangles,
        "routes": routes,
        "nat_rules": nats,
        "routing_table": routing_table,
    })))
}

/// POST /api/v1/routing/setup
async fn setup_pbr(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !has_permission(&claims, "routing.setup") {
        return Err(AppError::Forbidden(
            "permission 'routing.setup' required".to_string(),
        ));
    }

    let client = make_client(&state).await?;
    let routeros_config = {
        let config = state.config.read().await;
        config.routeros.clone()
    };

    // Determine container IP (our gateway in the veth network)
    let container_ip = detect_container_ip();

    let provisioner = Provisioner::new(&client, &routeros_config);
    provisioner.setup(&container_ip).await?;

    let _ = state.event_tx.send(ServerEvent::RoutingChanged);

    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": "PBR setup completed"
    })))
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

    let client = make_client(&state).await?;
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

    let client = make_client(&state).await?;
    let routeros_config = {
        let config = state.config.read().await;
        config.routeros.clone()
    };

    let provisioner = Provisioner::new(&client, &routeros_config);
    let result = provisioner.diagnostics().await?;

    Ok(Json(result))
}

fn detect_container_ip() -> String {
    std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "eth0"])
        .output()
        .ok()
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            s.split_whitespace()
                .nth(3)
                .map(|cidr| cidr.split('/').next().unwrap_or("172.19.0.2").to_string())
        })
        .unwrap_or_else(|| "172.19.0.2".to_string())
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
