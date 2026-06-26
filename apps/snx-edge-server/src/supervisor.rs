//! Supervisor: reconnect decision logic plus the background run-loop.
//!
//! The side-effect-free core lives in [`decide`] (given the current
//! [`ConnectionStatus`] and whether a desired profile is set, return the
//! [`SupervisorAction`] the run-loop should take) and [`backoff_delay`]
//! (exponential backoff with a 60-second cap). Keeping that logic pure makes
//! every branch trivially unit-testable without touching the tunnel, the
//! network, or any clock.
//!
//! [`run`] drives those pure functions: on boot it optionally provisions the
//! RouterOS PBR layout (`routeros.auto_setup`, kill-switch fail-closed) and
//! initiates the persisted desired profile — which lands at the MFA gate and
//! holds for the operator's OTP. Thereafter it watches
//! [`ServerEvent::ConnectionStatus`] and, when the tunnel drops while a desired
//! profile is set, re-initiates the connection with backoff. Like the
//! reconciler, this module is bin-local so `crate::state::AppState` resolves to
//! the same type `main.rs` constructs.

use snx_edge_types::events::ServerEvent;
use snx_edge_types::tunnel::ConnectionStatus;
use std::time::Duration;

use crate::state::AppState;
use crate::tunnel::VpnConfig;

/// `app_state` key holding the operator-selected profile id to keep connected.
const KEY_DESIRED: &str = "desired_profile_id";
/// `app_state` key gating auto-connect; only the literal `"true"` opts in.
const KEY_AUTO_CONNECT: &str = "auto_connect";

/// The action the supervisor run-loop should take for a given tunnel state.
#[derive(Debug, PartialEq, Eq)]
pub enum SupervisorAction {
    /// Terminal state with a desired profile: kick off a reconnect.
    Reconnect,
    /// Active or transitional state (incl. MFA gate): leave it alone.
    Hold,
    /// Terminal state with no desired profile: stay idle.
    Idle,
}

/// Decide what to do based on the current tunnel status and whether a desired
/// profile is set. Pure: no I/O, no clock.
pub fn decide(status: &ConnectionStatus, has_desired: bool) -> SupervisorAction {
    match status {
        ConnectionStatus::Connected(_)
        | ConnectionStatus::Connecting
        | ConnectionStatus::Mfa(_) => SupervisorAction::Hold,
        ConnectionStatus::Error { .. } | ConnectionStatus::Disconnected => {
            if has_desired {
                SupervisorAction::Reconnect
            } else {
                SupervisorAction::Idle
            }
        }
    }
}

/// Exponential backoff delay for the given (zero-based) attempt: 2, 4, 8, …
/// seconds, capped at 60. Pure: no I/O, no clock.
pub fn backoff_delay(attempt: u32) -> Duration {
    // 2,4,8,16,32 then capped at 60s; clamp the attempt so the shift can't overflow.
    let secs = if attempt >= 5 { 60 } else { 2u64 << attempt };
    Duration::from_secs(secs)
}

/// Return the desired profile id, but only when auto-connect is explicitly
/// enabled. Both reads are best-effort: a DB error or absent key yields `None`
/// (stay idle) rather than an error — the supervisor must never crash the
/// process over a missing persisted intent.
async fn desired_profile(state: &AppState) -> Option<String> {
    let auto = state
        .db
        .get_app_state(KEY_AUTO_CONNECT)
        .await
        .ok()
        .flatten();
    if auto.as_deref() != Some("true") {
        return None;
    }
    state.db.get_app_state(KEY_DESIRED).await.ok().flatten()
}

/// Load the profile's stored VPN config and initiate a single connect attempt.
///
/// Mirrors `api::tunnel::connect`: read the decrypted config JSON via
/// [`UserDb::get_profile_config`], deserialize it into the same
/// [`VpnConfig`](crate::tunnel::VpnConfig) the API uses, and hand it to
/// [`TunnelManager::connect`]. Every failure is logged and swallowed — the
/// authoritative tunnel status (re-read by [`initiate_with_backoff`]) decides
/// whether to retry, not this function's return.
async fn try_connect(state: &AppState, profile_id: &str) {
    let config_str = match state.db.get_profile_config(profile_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, profile_id, "supervisor: profile load failed");
            return;
        }
    };
    let vpn_config: VpnConfig = match serde_json::from_str(&config_str) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, profile_id, "supervisor: bad profile config");
            return;
        }
    };
    if let Err(e) = state.tunnel.connect(&vpn_config).await {
        tracing::warn!(error = %e, profile_id, "supervisor: connect attempt failed");
    }
}

/// Background supervisor loop. Runs until the shared shutdown token is cancelled.
///
/// Boot: optionally provision the RouterOS PBR layout (kill-switch fail-closed),
/// then initiate the desired profile — which lands at the MFA gate and holds for
/// the operator's OTP. Steady state: on each tunnel-status transition, re-read
/// the authoritative status and, if the tunnel dropped while a desired profile
/// is set, re-initiate the connection with backoff.
pub async fn run(state: AppState) {
    // --- Boot ---
    {
        let auto_setup = state.config.read().await.routeros.auto_setup;
        if auto_setup {
            // Building accessor, not a raw cache peek, so a client invalidated
            // by a `[routeros]` config update is rebuilt here. An `Err` means
            // RouterOS is simply not configured (env vars absent) or
            // unavailable — skip quietly rather than fail the boot.
            match state.routeros_client().await {
                Ok(client) => {
                    let routeros_config = state.config.read().await.routeros.clone();
                    let prov =
                        crate::routeros::provisioner::Provisioner::new(&client, &routeros_config);
                    match crate::api::routing::detect_container_ip() {
                        // `setup` logs each step (and any failure) internally and
                        // is fail-closed by construction (the kill-switch route
                        // stays even if a later step fails), so the report is
                        // advisory here.
                        Ok(ip) => {
                            let _report = prov.setup(&ip).await;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "supervisor: auto_setup skipped, container ip undetectable");
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "supervisor: auto_setup skipped, routeros not configured");
                }
            }
        }
        if let Some(p) = desired_profile(&state).await {
            tracing::info!(profile_id = %p, "supervisor: boot auto-connect");
            initiate_with_backoff(&state, &p).await;
        }
    }

    // --- Steady state ---
    let mut rx = state.event_tx.subscribe();
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => break,
            ev = rx.recv() => match ev {
                Ok(ServerEvent::ConnectionStatus { .. }) => {
                    // The event payload is just a label; re-read the
                    // authoritative status. A desired profile being set
                    // implies `has_desired = true`; with none set `decide`
                    // would return `Idle`, so the `let Some` guard is exactly
                    // the no-desired-profile short-circuit.
                    let status = state.tunnel.status().await.connection;
                    if let Some(p) = desired_profile(&state).await
                        && decide(&status, true) == SupervisorAction::Reconnect
                    {
                        tracing::info!("supervisor: reconnecting after unexpected drop");
                        initiate_with_backoff(&state, &p).await;
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    }
}

/// Initiate a connect, retrying transient pre-MFA failures with backoff until
/// the status reaches a hold state (Mfa/Connected/Connecting) or shutdown.
///
/// After each attempt the *authoritative* tunnel status decides the next step:
/// `Hold` (incl. the MFA gate — we stop and wait for the human's OTP) or `Idle`
/// ends the loop; only a terminal `Error`/`Disconnected` (→ `Reconnect`) sleeps
/// for [`backoff_delay`] and tries again. Shutdown-aware at both the top of the
/// loop and inside the sleep.
async fn initiate_with_backoff(state: &AppState, profile_id: &str) {
    let mut attempt = 0u32;
    loop {
        if state.shutdown.is_cancelled() {
            return;
        }
        try_connect(state, profile_id).await;
        // Status is authoritative after connect(): Mfa/Connected/Connecting
        // => hold (Mfa holds for the operator's OTP).
        match decide(&state.tunnel.status().await.connection, true) {
            SupervisorAction::Hold | SupervisorAction::Idle => return,
            SupervisorAction::Reconnect => {
                let d = backoff_delay(attempt);
                attempt = attempt.saturating_add(1);
                tokio::select! {
                    _ = state.shutdown.cancelled() => return,
                    _ = tokio::time::sleep(d) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snx_edge_types::tunnel::{ConnectionInfo, MfaChallenge};

    fn mfa() -> ConnectionStatus {
        ConnectionStatus::Mfa(MfaChallenge {
            mfa_type: "otp".into(),
            prompt: "code".into(),
        })
    }

    #[test]
    fn terminal_with_desired_reconnects() {
        assert_eq!(
            decide(&ConnectionStatus::Disconnected, true),
            SupervisorAction::Reconnect
        );
        assert_eq!(
            decide(
                &ConnectionStatus::Error {
                    message: "x".into()
                },
                true
            ),
            SupervisorAction::Reconnect
        );
    }

    #[test]
    fn terminal_without_desired_is_idle() {
        assert_eq!(
            decide(&ConnectionStatus::Disconnected, false),
            SupervisorAction::Idle
        );
        assert_eq!(
            decide(
                &ConnectionStatus::Error {
                    message: "x".into()
                },
                false
            ),
            SupervisorAction::Idle
        );
    }

    #[test]
    fn active_states_hold() {
        assert_eq!(
            decide(&ConnectionStatus::Connecting, true),
            SupervisorAction::Hold
        );
        assert_eq!(
            decide(
                &ConnectionStatus::Connected(ConnectionInfo::default()),
                true
            ),
            SupervisorAction::Hold
        );
        assert_eq!(decide(&mfa(), true), SupervisorAction::Hold);
    }

    #[test]
    fn backoff_is_2_4_8_capped_at_60() {
        assert_eq!(backoff_delay(0), Duration::from_secs(2));
        assert_eq!(backoff_delay(1), Duration::from_secs(4));
        assert_eq!(backoff_delay(2), Duration::from_secs(8));
        assert_eq!(backoff_delay(5), Duration::from_secs(60));
        assert_eq!(backoff_delay(100), Duration::from_secs(60));
    }

    #[test]
    fn backoff_has_no_overflow_dip() {
        assert_eq!(backoff_delay(4), Duration::from_secs(32));
        assert_eq!(backoff_delay(63), Duration::from_secs(60));
        assert_eq!(backoff_delay(u32::MAX), Duration::from_secs(60));
    }
}
