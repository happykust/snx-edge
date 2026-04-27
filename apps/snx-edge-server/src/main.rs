mod api;
mod config;
mod db;
mod error;
mod log_layer;
mod routeros;
mod state;
mod tunnel;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::api::logs::new_log_buffer;
use crate::routeros::client::RouterOsClient;
use crate::routeros::provisioner::Provisioner;
use crate::state::AppState;

const IPTABLES_COMMENT_TAG: &str = "managed-by=snx-edge";

/// snx-edge-server — headless Check Point VPN client with management API.
#[derive(Parser, Debug)]
#[command(name = "snx-edge-server", version, about, long_about = None)]
struct Cli {
    /// Path to the TOML configuration file
    #[arg(long, default_value = "/etc/snx-edge/config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config;

    let config = config::AppConfig::load(&config_path)
        .with_context(|| format!("failed to load config from {config_path}"))?;

    // Create shared resources BEFORE tracing init so the Layer can capture from the start
    let log_buffer = new_log_buffer(config.logging.buffer_size);
    let (event_tx, _) = broadcast::channel(256);

    // Initialize tracing with our custom capture layer
    let capture_layer = log_layer::LogCaptureLayer::new(log_buffer.clone(), event_tx.clone());

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .with(capture_layer)
        .init();

    // Enable IP forwarding for VPN traffic routing (container → tun0 → VPN).
    // Cleanup pass first removes any stale managed rules from a prior run
    // (e.g. with a different interface name).
    enable_ip_forwarding();

    let listen_addr: SocketAddr = config.api.listen.parse()?;

    // Capture TLS paths before `config` is moved into AppState.
    let tls_cert = config.api.tls_cert.clone();
    let tls_key = config.api.tls_key.clone();
    let tls_client_ca = config.api.tls_client_ca.clone();

    // Single CancellationToken drives both the server's graceful-shutdown
    // future AND any background tasks (db cleanup, etc) that need to know
    // when to bail out.
    let shutdown = CancellationToken::new();

    let app_state =
        state::AppState::with_shared(config, config_path, log_buffer, event_tx, shutdown.clone())
            .await?;

    // Spawn the signal listener once: it cancels the shared token, which
    // every other shutdown-aware component observes.
    spawn_signal_listener(shutdown.clone());

    let router = api::router(app_state.clone());

    if let (Some(cert_path), Some(key_path)) = (&tls_cert, &tls_key) {
        let tls_config = build_tls_config(cert_path, key_path, tls_client_ca.as_deref())?;

        let rustls_config =
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config));

        if tls_client_ca.is_some() {
            tracing::info!("listening on {listen_addr} (TLS + mTLS)");
        } else {
            tracing::info!("listening on {listen_addr} (TLS)");
        }

        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        let shutdown_for_server = shutdown.clone();
        tokio::spawn(async move {
            shutdown_for_server.cancelled().await;
            tracing::info!("shutdown signal received, draining HTTPS connections");
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
        });

        // `into_make_service_with_connect_info::<SocketAddr>()` exposes the
        // peer address as `ConnectInfo<SocketAddr>` to handlers — required by
        // the auth layer's trusted-proxy check (`SecurityConfig.trusted_proxies`).
        axum_server::bind_rustls(listen_addr, rustls_config)
            .handle(handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        tracing::info!("listening on {listen_addr} (plain HTTP)");
        let listener = TcpListener::bind(listen_addr).await?;
        let shutdown_for_axum = shutdown.clone();
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move { shutdown_for_axum.cancelled().await })
        .await?;
    }

    // Server has stopped. Run the rest of the shutdown chain in order.
    run_shutdown_actions(&app_state).await;

    Ok(())
}

/// Listen for SIGINT (Ctrl-C) and SIGTERM in a background task. Whichever
/// arrives first cancels the shared shutdown token; subsequent signals are
/// ignored (the listener has already finished).
fn spawn_signal_listener(shutdown: CancellationToken) {
    tokio::spawn(async move {
        let ctrl_c = async {
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::error!(error = %e, "failed to install Ctrl-C handler");
            }
        };

        #[cfg(unix)]
        let terminate = async {
            use tokio::signal::unix::{SignalKind, signal};
            match signal(SignalKind::terminate()) {
                Ok(mut s) => {
                    s.recv().await;
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to install SIGTERM handler");
                    futures_util::future::pending::<()>().await;
                }
            }
        };

        #[cfg(not(unix))]
        let terminate = futures_util::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => tracing::info!("SIGINT received, initiating graceful shutdown"),
            _ = terminate => tracing::info!("SIGTERM received, initiating graceful shutdown"),
        }

        shutdown.cancel();
    });
}

/// Run shutdown actions in order after the server stops accepting new
/// connections. Order matters: tasks first, then VPN, then RouterOS, then
/// iptables. Each step is best-effort — failures are logged, never fatal.
async fn run_shutdown_actions(state: &AppState) {
    // 1. Cancel the token so any background task still observing it can exit
    //    cleanly. Idempotent — already cancelled by signal handler.
    state.shutdown.cancel();

    // 2. Disconnect VPN tunnel with a 10s timeout. The tunnel may need to
    //    talk to the Check Point gateway to sign out cleanly, but we cap the
    //    wait so a stuck server can't hang the entire shutdown.
    match tokio::time::timeout(Duration::from_secs(10), state.tunnel.disconnect()).await {
        Ok(Ok(())) => tracing::info!("vpn tunnel disconnected"),
        Ok(Err(e)) => tracing::warn!(error = %e, "vpn disconnect returned error"),
        Err(_) => tracing::warn!("vpn disconnect timed out after 10s"),
    }

    // 3. RouterOS teardown (gated behind config flag — defaults off so the
    //    kill-switch survives container restarts).
    let teardown_routeros = state.config.read().await.shutdown.teardown_routeros;
    if teardown_routeros {
        match teardown_routeros_pbr(state).await {
            Ok(removed) => tracing::info!(removed, "routeros teardown completed"),
            Err(e) => tracing::warn!(error = %e, "routeros teardown failed"),
        }
    }

    // 4. iptables cleanup — drop any rule we added for NAT masquerade.
    if let Err(e) = cleanup_managed_iptables_rules() {
        tracing::warn!(error = %e, "iptables cleanup failed");
    }

    tracing::info!("shutdown complete");
}

async fn teardown_routeros_pbr(state: &AppState) -> anyhow::Result<usize> {
    let config = state.config.read().await;
    let client = RouterOsClient::new(&config.routeros)?;
    let provisioner = Provisioner::new(&client, &config.routeros);
    let removed = provisioner.teardown().await?;
    Ok(removed)
}

/// Build a [`rustls::ServerConfig`] from PEM files.
///
/// * Always loads the server certificate chain + private key.
/// * When `client_ca_path` is `Some`, a [`WebPkiClientVerifier`] is attached
///   so the server requires and verifies client certificates (mTLS).
fn build_tls_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
) -> anyhow::Result<rustls::ServerConfig> {
    use rustls_pemfile::{certs, pkcs8_private_keys};
    use std::io::BufReader;

    // --- server cert chain ---
    let cert_file =
        std::fs::File::open(cert_path).with_context(|| format!("open TLS cert {cert_path}"))?;
    let server_certs: Vec<_> = certs(&mut BufReader::new(cert_file))
        .collect::<Result<_, _>>()
        .with_context(|| format!("parse TLS certs from {cert_path}"))?;

    // --- server private key ---
    let key_file =
        std::fs::File::open(key_path).with_context(|| format!("open TLS key {key_path}"))?;
    let server_key = pkcs8_private_keys(&mut BufReader::new(key_file))
        .next()
        .ok_or_else(|| anyhow::anyhow!("no PKCS8 private key found in {key_path}"))?
        .with_context(|| format!("parse TLS key from {key_path}"))?;

    let builder = rustls::ServerConfig::builder();

    let server_config = if let Some(ca_path) = client_ca_path {
        // --- mTLS: load CA for client-cert verification ---
        let ca_file =
            std::fs::File::open(ca_path).with_context(|| format!("open client CA {ca_path}"))?;
        let ca_certs: Vec<_> = certs(&mut BufReader::new(ca_file))
            .collect::<Result<_, _>>()
            .with_context(|| format!("parse client CA certs from {ca_path}"))?;

        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store
                .add(cert)
                .with_context(|| "add client CA cert to root store")?;
        }

        // allow_unauthenticated: client certs are verified if provided but not required.
        // This lets health checks work without a cert while still validating real clients.
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .allow_unauthenticated()
            .build()
            .with_context(|| "build WebPkiClientVerifier")?;

        builder
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                server_certs,
                rustls::pki_types::PrivateKeyDer::Pkcs8(server_key),
            )
            .with_context(|| "build TLS ServerConfig with mTLS")?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(
                server_certs,
                rustls::pki_types::PrivateKeyDer::Pkcs8(server_key),
            )
            .with_context(|| "build TLS ServerConfig")?
    };

    Ok(server_config)
}

/// Enable IPv4 forwarding and set up NAT masquerade for tun→eth0.
/// Failures are logged but not fatal — forwarding may already be enabled
/// or the container may lack permissions (tested on MikroTik).
fn enable_ip_forwarding() {
    // sysctl net.ipv4.ip_forward=1
    match std::fs::write("/proc/sys/net/ipv4/ip_forward", "1") {
        Ok(()) => tracing::info!("ip_forward enabled"),
        Err(e) => tracing::warn!("failed to enable ip_forward: {e} (may need CAP_NET_ADMIN)"),
    }

    // First, drop any stale managed rules. This handles the case where a
    // previous run added a MASQUERADE rule with a different spec (e.g.
    // interface name change after a config update). Without the cleanup,
    // the rule would leak.
    if let Err(e) = cleanup_managed_iptables_rules() {
        tracing::warn!(error = %e, "iptables pre-cleanup failed");
    }

    // iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE -m comment --comment "managed-by=snx-edge"
    match std::process::Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            "eth0",
            "-j",
            "MASQUERADE",
            "-m",
            "comment",
            "--comment",
            IPTABLES_COMMENT_TAG,
        ])
        .output()
    {
        Ok(output) if output.status.success() => {
            tracing::info!("NAT masquerade configured for eth0 (tagged {IPTABLES_COMMENT_TAG})");
        }
        Ok(output) => {
            tracing::warn!(
                "failed to configure NAT masquerade: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(e) => tracing::warn!("iptables not available: {e}"),
    }
}

/// Remove every POSTROUTING rule in the nat table that carries our
/// `managed-by=snx-edge` comment tag. Used both at startup (to drop stale
/// rules from a previous run) and at shutdown (to leave the host clean).
///
/// Strategy: list with `iptables -t nat -S POSTROUTING`, find lines that
/// contain the comment, then re-issue each as a `-D` (delete) by swapping
/// the `-A POSTROUTING` prefix. This is more robust than re-deriving the
/// args ourselves because it handles any historical variation in the rule
/// spec (interface name, ordering, etc.).
pub fn cleanup_managed_iptables_rules() -> anyhow::Result<()> {
    let output = std::process::Command::new("iptables")
        .args(["-t", "nat", "-S", "POSTROUTING"])
        .output()
        .with_context(|| "spawn iptables -S POSTROUTING")?;

    if !output.status.success() {
        anyhow::bail!(
            "iptables -S POSTROUTING failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut removed = 0usize;
    for line in stdout.lines() {
        if !line.contains(IPTABLES_COMMENT_TAG) {
            continue;
        }
        // `iptables -S` prints rules in the form `-A POSTROUTING ...args`.
        // Convert to `-D POSTROUTING ...args` for deletion. Anything that
        // doesn't start with `-A ` is skipped defensively (chain header,
        // policy line, etc.).
        let Some(rest) = line.strip_prefix("-A ") else {
            continue;
        };
        let mut args: Vec<&str> = vec!["-t", "nat", "-D"];
        args.extend(rest.split_whitespace());
        match std::process::Command::new("iptables").args(&args).output() {
            Ok(o) if o.status.success() => {
                removed += 1;
                tracing::info!("removed managed iptables rule: {line}");
            }
            Ok(o) => {
                tracing::warn!(
                    "failed to delete managed iptables rule `{line}`: {}",
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            Err(e) => {
                tracing::warn!("iptables -D spawn failed for `{line}`: {e}");
            }
        }
    }

    if removed > 0 {
        tracing::info!("removed {removed} managed iptables rule(s)");
    }
    Ok(())
}
