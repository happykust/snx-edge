//! Reconciler: ties the data plane to the real tunnel state.
//!
//! A single background task subscribes to [`ServerEvent::ConnectionStatus`] and,
//! whenever the tunnel transitions, re-reads the authoritative status and brings
//! the data plane into line with it:
//!
//!   * **Connected** (with a named interface) → engage: tagged MASQUERADE on the
//!     dynamic VPN interface (fixes P0-1) + ensure the RouterOS distance-1
//!     default route into the container exists (fixes P0-4).
//!   * **Disconnected / Error** → disengage: clear the managed MASQUERADE and
//!     drop the distance-1 default route. The blackhole route (distance 254)
//!     stays, so corp traffic fails *closed*; normal internet traffic is
//!     unmarked and therefore unaffected.
//!
//! This module is bin-local (declared in `main.rs`, not `lib.rs`) so its
//! `crate::state::AppState` resolves to the same `AppState` type that `main.rs`
//! constructs and hands to the axum router. `net` has no bin-local module, so it
//! is imported from the library exactly as `main.rs` does.

use snx_edge_server::net;

use snx_edge_types::events::ServerEvent;
use snx_edge_types::tunnel::ConnectionStatus;

use crate::state::AppState;

/// What the reconciler should do in response to the current tunnel state.
#[derive(Debug, PartialEq)]
pub enum Action {
    /// Tunnel is up on `iface`: apply MASQUERADE + ensure the default route.
    Engage { iface: String },
    /// Tunnel is down/errored: clear MASQUERADE + drop the default route.
    Disengage,
}

/// Pure decision function: map a connection status onto an [`Action`].
///
/// `Connected` only engages once snxcore has populated a non-empty interface
/// name — the MASQUERADE target is the dynamic VPN interface, which is only
/// known in the `Connected` state. `Connecting`/`Mfa` (and a `Connected` with
/// no interface yet) are no-ops; the next status event will carry the name.
pub fn decide(status: &ConnectionStatus) -> Option<Action> {
    match status {
        ConnectionStatus::Connected(info) if !info.interface_name.is_empty() => {
            Some(Action::Engage {
                iface: info.interface_name.clone(),
            })
        }
        ConnectionStatus::Disconnected | ConnectionStatus::Error { .. } => Some(Action::Disengage),
        _ => None,
    }
}

/// Background loop. Reacts to tunnel connection-state changes until the shared
/// shutdown token is cancelled.
pub async fn run(state: AppState) {
    let mut rx = state.event_tx.subscribe();
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            ev = rx.recv() => match ev {
                Ok(ServerEvent::ConnectionStatus { .. }) => {
                    // The event payload is just a label; re-read the
                    // authoritative status (which carries the interface name).
                    let status = state.tunnel.status().await.connection;
                    if let Some(action) = decide(&status)
                        && let Err(e) = apply(&state, action).await
                    {
                        tracing::error!(error = %e, "reconciler apply failed");
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    }
}

/// Bring the data plane into line with `action`.
async fn apply(state: &AppState, action: Action) -> anyhow::Result<()> {
    match action {
        Action::Engage { iface } => {
            net::apply_vpn_masquerade(&iface)?;
            // Use the lazy building accessor (not a raw cache peek) so a client
            // invalidated by a `[routeros]` config update is rebuilt here. An
            // `Err` means RouterOS is simply not configured (env vars absent) or
            // unavailable — skip quietly rather than error-spamming on every
            // event in non-RouterOS deployments.
            match state.routeros_client().await {
                Ok(client) => {
                    let routeros_config = {
                        let config = state.config.read().await;
                        config.routeros.clone()
                    };
                    let prov =
                        crate::routeros::provisioner::Provisioner::new(&client, &routeros_config);
                    let container_ip = crate::api::routing::detect_container_ip()?;
                    prov.set_default_route_present(&container_ip).await?;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "routeros client unavailable; skipping route reconcile");
                }
            }
        }
        Action::Disengage => {
            // Clear MASQUERADE for any prior tunnel iface, then drop the
            // default route so corp traffic fails closed against the blackhole.
            net::cleanup_managed_iptables_rules()?;
            // Building accessor, not a cache peek: after `invalidate_routeros_client()`
            // (e.g. a config update) the cache is `None`, and peeking it would skip
            // the route clear while MASQUERADE was just removed — leaking corp
            // traffic instead of failing closed. Rebuilding here keeps the
            // kill-switch fail-closed. An `Err` still means RouterOS is not
            // configured/unavailable, which is safe to skip quietly.
            match state.routeros_client().await {
                Ok(client) => {
                    let routeros_config = {
                        let config = state.config.read().await;
                        config.routeros.clone()
                    };
                    let prov =
                        crate::routeros::provisioner::Provisioner::new(&client, &routeros_config);
                    prov.clear_default_route().await?;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "routeros client unavailable; skipping route reconcile");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use snx_edge_types::tunnel::{ConnectionInfo, ConnectionStatus};

    #[test]
    fn connected_engages_on_named_interface() {
        let info = ConnectionInfo {
            interface_name: "tun0".into(),
            ..Default::default()
        };
        assert_eq!(
            decide(&ConnectionStatus::Connected(info)),
            Some(Action::Engage {
                iface: "tun0".into()
            })
        );
    }
    #[test]
    fn disconnect_and_error_disengage() {
        assert_eq!(
            decide(&ConnectionStatus::Disconnected),
            Some(Action::Disengage)
        );
        assert_eq!(
            decide(&ConnectionStatus::Error { message: "x".into() }),
            Some(Action::Disengage)
        );
    }
    #[test]
    fn connecting_and_empty_iface_do_nothing() {
        assert_eq!(decide(&ConnectionStatus::Connecting), None);
        assert_eq!(
            decide(&ConnectionStatus::Connected(ConnectionInfo::default())),
            None
        );
    }
}
