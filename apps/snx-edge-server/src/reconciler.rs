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

/// Servers-file that drives the in-container dnsmasq split-DNS forwarder.
///
/// dnsmasq is configured (in `docker/dnsmasq.conf`) with `servers-file=` pointing
/// here. We write per-corp-domain upstream lines into it and SIGHUP dnsmasq to
/// reload them. A *servers-file* is used (not a `conf-dir` drop-in) because
/// dnsmasq re-reads a servers-file on SIGHUP, whereas `server=/domain/...`
/// directives in a `conf-dir` are NOT re-read on SIGHUP.
///
/// The file lives under `/var/lib/snx-edge`, which the init script chowns to the
/// `snxedge` user so the (privilege-dropped) server can rewrite it.
const CORP_SERVERS_FILE: &str = "/var/lib/snx-edge/corp-servers.conf";

/// dnsmasq pidfile (set via `pid-file=` in `docker/dnsmasq.conf`). Read to find
/// the process to SIGHUP for a servers-file reload.
const DNSMASQ_PIDFILE: &str = "/run/dnsmasq.pid";

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

/// Validate a (already `~`-stripped) DNS name before it is emitted into the
/// dnsmasq servers-file.
///
/// `search_domains` ultimately come from the VPN gateway's Office-Mode response
/// (snxcore `SearchDomain.name`), which is an unvalidated, attacker-influenceable
/// `String`. Without this gate a value containing a newline — e.g.
/// `corp.example\nserver=8.8.8.8` — would inject an arbitrary `server=` directive
/// into a file dnsmasq reads as root, hijacking DNS for every LAN/VPN client
/// (whose :53 is dst-nat'd to this dnsmasq). So we accept only syntactically
/// valid DNS names: non-empty, ≤ 253 chars, no `/`/`#`/whitespace/control chars,
/// and dot-separated labels each 1–63 chars of `[A-Za-z0-9-]` not edged by `-`.
fn is_valid_dns_name(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    // Reject anything that could break out of the `server=/<domain>/...` slot or
    // open a new directive: path/comment markers, whitespace, control chars
    // (covers `\n`, `\r`, `\t`).
    if domain
        .chars()
        .any(|c| c == '/' || c == '#' || c.is_whitespace() || c.is_control())
    {
        return false;
    }
    // Dot-separated labels: each 1–63 chars of [A-Za-z0-9-], not starting or
    // ending with `-`. (An empty label — leading/trailing/double dot — fails the
    // non-empty check below.)
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Render the dnsmasq corp split-DNS servers-file body.
///
/// Pure: maps **each** corp search domain to **each** corp DNS server, emitting
/// one `server=/<domain>/<srv>` line per pair so that corp-internal names are
/// forwarded to the corp resolvers (reachable through the tunnel) while every
/// other name falls through to the static fallback upstream in `dnsmasq.conf`.
/// Returns an empty string when there are no domains or no servers.
///
/// **Untrusted input**: each domain has a single leading `~` stripped first
/// (snxcore's `SearchDomain` `Display` prepends `~` for *routing* domains; left
/// in place it would yield a non-matching `server=/~corp.example/...` line that
/// silently disables split-DNS for the very domains marked for routing). After
/// stripping, both the domain ([`is_valid_dns_name`]) and the server
/// ([`std::net::IpAddr`]) are validated; pairs where either side is invalid are
/// dropped (not emitted), guarding against dnsmasq config injection. The caller
/// surfaces the drop count via a `tracing::warn!` so this function stays pure.
pub fn render_corp_dnsmasq(dns_servers: &[String], search_domains: &[String]) -> String {
    use std::net::IpAddr;
    use std::str::FromStr as _;

    let mut out = String::new();
    for domain in search_domains {
        // Strip a single leading routing-domain `~` before validating/formatting.
        let domain = domain.strip_prefix('~').unwrap_or(domain);
        if !is_valid_dns_name(domain) {
            continue;
        }
        for srv in dns_servers {
            if IpAddr::from_str(srv).is_err() {
                continue;
            }
            out.push_str(&format!("server=/{domain}/{srv}\n"));
        }
    }
    out
}

/// Write `contents` to the dnsmasq servers-file and reload dnsmasq so the new
/// upstreams take effect. Used for both engage (corp lines) and disengage
/// (empty). Fallible; the caller decides how to handle failure (here: log only).
fn write_corp_servers_and_reload(contents: &str) -> anyhow::Result<()> {
    use anyhow::Context as _;
    std::fs::write(CORP_SERVERS_FILE, contents)
        .with_context(|| format!("write {CORP_SERVERS_FILE}"))?;
    reload_dnsmasq()
}

/// Reload dnsmasq by sending it SIGHUP, which makes it re-read its servers-file.
///
/// The target PID is read from the dnsmasq pidfile and signalled with `kill`
/// (busybox `kill` is always present in the Alpine base; this avoids depending
/// on `pkill`/`pgrep` being compiled into busybox). Signalling succeeds when the
/// server runs as the same user as dnsmasq (the MikroTik container runs both as
/// root, `SNX_EDGE_DROP_PRIVS=0`); under privilege-dropping it may fail, which is
/// why callers treat reload failures as non-fatal.
fn reload_dnsmasq() -> anyhow::Result<()> {
    use anyhow::Context as _;
    let pid = std::fs::read_to_string(DNSMASQ_PIDFILE)
        .with_context(|| format!("read {DNSMASQ_PIDFILE}"))?;
    let pid = pid.trim();
    if pid.is_empty() {
        anyhow::bail!("dnsmasq pidfile {DNSMASQ_PIDFILE} is empty (dnsmasq not running?)");
    }
    let out = std::process::Command::new("kill")
        .args(["-HUP", pid])
        .output()
        .with_context(|| "spawn kill -HUP for dnsmasq")?;
    if !out.status.success() {
        anyhow::bail!(
            "kill -HUP {pid} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Engage split-DNS: render the corp upstreams from the live tunnel
/// `ConnectionInfo` and reload dnsmasq. Non-fatal: any failure is logged and
/// swallowed so it never aborts the (more critical) MASQUERADE + route reconcile.
async fn engage_corp_dns(state: &AppState) {
    // Re-read the authoritative status; only a live `Connected` carries the
    // DNS servers / search domains. A race that flipped us out of `Connected`
    // leaves the servers-file untouched until the next event.
    let ConnectionStatus::Connected(info) = state.tunnel.status().await.connection else {
        return;
    };
    let contents = render_corp_dnsmasq(&info.dns_servers, &info.search_domains);
    // Surface drops: `render_corp_dnsmasq` stays pure, so detect rejected
    // (injection-unsafe or malformed) domain/server pairs here. Each valid pair
    // emits exactly one non-blank line; fewer than expected means the validator
    // dropped some — worth a warning since split-DNS for those domains is absent.
    let expected = info.dns_servers.len() * info.search_domains.len();
    let emitted = contents.lines().filter(|l| !l.trim().is_empty()).count();
    if emitted < expected {
        tracing::warn!(
            expected,
            emitted,
            dropped = expected - emitted,
            "dropped invalid corp DNS domain/server pair(s) from split-DNS forwarder"
        );
    }
    match write_corp_servers_and_reload(&contents) {
        Ok(()) => tracing::info!(
            domains = info.search_domains.len(),
            servers = info.dns_servers.len(),
            "corp split-DNS applied"
        ),
        Err(e) => tracing::warn!(error = %e, "failed to apply corp split-DNS; continuing"),
    }
}

/// Disengage split-DNS: truncate the corp servers-file and reload dnsmasq so corp
/// domains fall back to the default upstream. Non-fatal (logged, not propagated).
fn disengage_corp_dns() {
    match write_corp_servers_and_reload("") {
        Ok(()) => tracing::info!("corp split-DNS cleared"),
        Err(e) => tracing::warn!(error = %e, "failed to clear corp split-DNS; continuing"),
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
            // DNS step last and non-fatal: MASQUERADE + route are the critical
            // path, so a split-DNS write/reload failure is logged, never `?`-ed.
            engage_corp_dns(state).await;
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
            // DNS step last and non-fatal: clear corp upstreams so corp names
            // fall back to the default resolver once the tunnel is down.
            disengage_corp_dns();
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

    #[test]
    fn corp_dns_maps_each_domain_to_each_server() {
        let s = render_corp_dnsmasq(
            &["10.0.0.53".into()],
            &["corp.example".into(), "int.example".into()],
        );
        assert!(s.contains("server=/corp.example/10.0.0.53"));
        assert!(s.contains("server=/int.example/10.0.0.53"));
    }

    #[test]
    fn corp_dns_pairs_every_domain_with_every_server() {
        let s = render_corp_dnsmasq(
            &["10.0.0.53".into(), "10.0.0.54".into()],
            &["corp.example".into()],
        );
        assert!(s.contains("server=/corp.example/10.0.0.53"));
        assert!(s.contains("server=/corp.example/10.0.0.54"));
        // Two servers × one domain = two lines, no trailing blanks.
        assert_eq!(s.lines().count(), 2);
    }

    #[test]
    fn corp_dns_is_empty_without_domains_or_servers() {
        assert_eq!(render_corp_dnsmasq(&["10.0.0.53".into()], &[]), "");
        assert_eq!(render_corp_dnsmasq(&[], &["corp.example".into()]), "");
    }

    #[test]
    fn corp_dns_drops_newline_injection_domain() {
        // A newline-bearing domain from the gateway must not smuggle a second
        // directive into the servers-file (dnsmasq config injection → DNS hijack).
        let s = render_corp_dnsmasq(
            &["10.0.0.53".into()],
            &["corp.example\nserver=8.8.8.8".into()],
        );
        assert!(!s.contains("8.8.8.8"), "injected upstream leaked: {s:?}");
        assert!(
            !s.contains("corp.example\nserver=8.8.8.8"),
            "raw injection emitted: {s:?}"
        );
        assert_eq!(s, "", "the whole malformed pair must be dropped");
    }

    #[test]
    fn corp_dns_drops_domains_with_forbidden_chars() {
        for bad in ["corp/example", "corp#example", "corp example"] {
            let s = render_corp_dnsmasq(&["10.0.0.53".into()], &[bad.to_string()]);
            assert_eq!(s, "", "domain {bad:?} should be dropped, got {s:?}");
        }
    }

    #[test]
    fn corp_dns_drops_non_ip_servers() {
        for bad in ["1.2.3.4 evil", "not-an-ip"] {
            let s = render_corp_dnsmasq(&[bad.to_string()], &["corp.example".into()]);
            assert_eq!(s, "", "server {bad:?} should be dropped, got {s:?}");
        }
    }

    #[test]
    fn corp_dns_strips_routing_domain_tilde_prefix() {
        // snxcore's `SearchDomain` Display prepends `~` for routing domains; it
        // must be stripped so the line actually matches `corp.example`.
        let s = render_corp_dnsmasq(&["10.0.0.53".into()], &["~corp.example".into()]);
        assert_eq!(s, "server=/corp.example/10.0.0.53\n");
        assert!(!s.contains('~'));
    }

    #[test]
    fn corp_dns_accepts_ipv6_server() {
        let s = render_corp_dnsmasq(&["2001:db8::53".into()], &["corp.example".into()]);
        assert_eq!(s, "server=/corp.example/2001:db8::53\n");
    }
}
