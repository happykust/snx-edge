//! Supervisor pure decision + backoff logic.
//!
//! This module holds only the side-effect-free core of the reconnect
//! supervisor: given the current [`ConnectionStatus`] and whether a desired
//! profile is set, [`decide`] returns the [`SupervisorAction`] the run-loop
//! should take, and [`backoff_delay`] computes the exponential backoff with a
//! 60-second cap. The run-loop that drives these functions is wired in Task 5.
//!
//! Keeping this logic pure makes every branch trivially unit-testable without
//! touching the tunnel, the network, or any clock.

use snx_edge_types::tunnel::ConnectionStatus;
use std::time::Duration;

/// The action the supervisor run-loop should take for a given tunnel state.
#[derive(Debug, PartialEq, Eq)]
// wired in Task 5 (run-loop consumes these actions)
#[allow(dead_code)]
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
// wired in Task 5 (run-loop consumes this decision)
#[allow(dead_code)]
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
// wired in Task 5 (run-loop schedules reconnects with this delay)
#[allow(dead_code)]
pub fn backoff_delay(attempt: u32) -> Duration {
    // 2,4,8,16,32 then capped at 60s; clamp the attempt so the shift can't overflow.
    let secs = if attempt >= 5 { 60 } else { 2u64 << attempt };
    Duration::from_secs(secs)
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
