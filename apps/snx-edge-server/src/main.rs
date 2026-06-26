mod api;
mod config;
mod db;
mod db_secrets;
mod error;
mod log_layer;
mod reconciler;
mod routeros;
mod state;
mod supervisor;
mod tunnel;

use snx_edge_server::net;

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
    if let Err(e) = net::enable_ip_forwarding() {
        tracing::warn!(error = %e, "failed to enable ip_forward (may need CAP_NET_ADMIN)");
    }

    let listen_addr: SocketAddr = config.api.listen.parse()?;

    // Capture TLS paths before `config` is moved into AppState.
    let tls_cert = config.api.tls_cert.clone();
    let tls_key = config.api.tls_key.clone();
    let tls_client_ca_optional = config.api.tls_client_ca_optional.clone();
    let tls_require_client_cert = config.api.require_client_cert.clone();

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

    // Spawn the reconciler: it reacts to tunnel connection-state changes by
    // applying/clearing the dynamic SNAT (MASQUERADE on the VPN interface) and
    // the RouterOS default route. It exits on the shared shutdown token.
    tokio::spawn(reconciler::run(app_state.clone()));

    // Spawn the supervisor: on boot it optionally provisions the RouterOS PBR
    // layout and initiates the persisted desired profile (holding at MFA for
    // the operator's OTP); thereafter it re-initiates the connection with
    // backoff when the tunnel drops. It exits on the shared shutdown token.
    tokio::spawn(supervisor::run(app_state.clone()));

    let router = api::router(app_state.clone());

    if let (Some(cert_path), Some(key_path)) = (&tls_cert, &tls_key) {
        // mTLS mode resolution: `require_client_cert` wins over the optional
        // form when both are set (operators who want strict mTLS shouldn't
        // be silently downgraded). Loud-warn when only the optional form is
        // configured so it's not mistaken for real defence-in-depth.
        let tls_mode = if let Some(ca) = tls_require_client_cert.as_deref() {
            if tls_client_ca_optional.is_some() {
                tracing::warn!(
                    "both api.require_client_cert and api.tls_client_ca_optional are set; \
                     using require_client_cert (strict mTLS)"
                );
            }
            ClientAuthMode::Required(ca)
        } else if let Some(ca) = tls_client_ca_optional.as_deref() {
            tracing::warn!(
                "mTLS configured as optional — JWT is the only authentication gate. \
                 To require client certs, use api.require_client_cert instead."
            );
            ClientAuthMode::Optional(ca)
        } else {
            ClientAuthMode::None
        };

        let tls_config = build_tls_config(cert_path, key_path, tls_mode)?;

        let rustls_config =
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config));

        match tls_mode {
            ClientAuthMode::Required(_) => {
                tracing::info!("listening on {listen_addr} (TLS + mTLS, client cert required)");
            }
            ClientAuthMode::Optional(_) => {
                tracing::info!("listening on {listen_addr} (TLS + optional mTLS)");
            }
            ClientAuthMode::None => {
                tracing::info!("listening on {listen_addr} (TLS)");
            }
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
    if let Err(e) = net::cleanup_managed_iptables_rules() {
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

/// Client-cert verification mode for the TLS layer.
#[derive(Clone, Copy)]
enum ClientAuthMode<'a> {
    /// No mTLS — client certs are not verified.
    None,
    /// Verify presented client certs against the CA but do not require one.
    /// JWT is still the sole authentication gate. Useful only as a transport-
    /// level filter, not as defence-in-depth.
    Optional(&'a str),
    /// Require a valid client cert chained to the CA at handshake time.
    /// Provides defence-in-depth on top of JWT.
    Required(&'a str),
}

/// Build a [`rustls::ServerConfig`] from PEM files.
///
/// * Always loads the server certificate chain + private key.
/// * `client_auth` selects the mTLS posture; see [`ClientAuthMode`].
fn build_tls_config(
    cert_path: &str,
    key_path: &str,
    client_auth: ClientAuthMode<'_>,
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

    let server_config = match client_auth {
        ClientAuthMode::None => builder
            .with_no_client_auth()
            .with_single_cert(
                server_certs,
                rustls::pki_types::PrivateKeyDer::Pkcs8(server_key),
            )
            .with_context(|| "build TLS ServerConfig")?,
        ClientAuthMode::Optional(ca_path) => {
            let root_store = load_client_ca_store(ca_path)?;

            // allow_unauthenticated: presented client certs are verified, but
            // a missing cert still completes the handshake. JWT is the gate.
            let client_verifier =
                rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                    .allow_unauthenticated()
                    .build()
                    .with_context(|| "build WebPkiClientVerifier (optional)")?;

            builder
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(
                    server_certs,
                    rustls::pki_types::PrivateKeyDer::Pkcs8(server_key),
                )
                .with_context(|| "build TLS ServerConfig with optional mTLS")?
        }
        ClientAuthMode::Required(ca_path) => {
            let root_store = load_client_ca_store(ca_path)?;

            // No `allow_unauthenticated`: handshake fails when no client cert
            // is presented. Operator must serve `/health` via a separate
            // listener (or accept that it's behind the cert too).
            let client_verifier =
                rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                    .build()
                    .with_context(|| "build WebPkiClientVerifier (required)")?;

            builder
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(
                    server_certs,
                    rustls::pki_types::PrivateKeyDer::Pkcs8(server_key),
                )
                .with_context(|| "build TLS ServerConfig with required mTLS")?
        }
    };

    Ok(server_config)
}

/// Load a CA bundle from `path` into a [`rustls::RootCertStore`].
fn load_client_ca_store(path: &str) -> anyhow::Result<rustls::RootCertStore> {
    use rustls_pemfile::certs;
    use std::io::BufReader;

    let ca_file = std::fs::File::open(path).with_context(|| format!("open client CA {path}"))?;
    let ca_certs: Vec<_> = certs(&mut BufReader::new(ca_file))
        .collect::<Result<_, _>>()
        .with_context(|| format!("parse client CA certs from {path}"))?;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .with_context(|| "add client CA cert to root store")?;
    }
    Ok(root_store)
}
