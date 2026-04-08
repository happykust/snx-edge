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

use anyhow::Context;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::api::logs::new_log_buffer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = {
        let args: Vec<String> = std::env::args().collect();
        args.iter()
            .position(|a| a == "--config")
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| "/etc/snx-edge/config.toml".to_string())
    };

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

    // Enable IP forwarding for VPN traffic routing (container → tun0 → VPN)
    enable_ip_forwarding();

    let listen_addr: SocketAddr = config.api.listen.parse()?;

    // Capture TLS paths before `config` is moved into AppState.
    let tls_cert = config.api.tls_cert.clone();
    let tls_key = config.api.tls_key.clone();
    let tls_client_ca = config.api.tls_client_ca.clone();

    let app_state = state::AppState::with_shared(config, config_path, log_buffer, event_tx).await?;
    let router = api::router(app_state);

    if let (Some(cert_path), Some(key_path)) = (&tls_cert, &tls_key) {
        let tls_config = build_tls_config(cert_path, key_path, tls_client_ca.as_deref())?;

        let rustls_config =
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config));

        if tls_client_ca.is_some() {
            tracing::info!("listening on {listen_addr} (TLS + mTLS)");
        } else {
            tracing::info!("listening on {listen_addr} (TLS)");
        }

        axum_server::bind_rustls(listen_addr, rustls_config)
            .serve(router.into_make_service())
            .await?;
    } else {
        tracing::info!("listening on {listen_addr} (plain HTTP)");
        let listener = TcpListener::bind(listen_addr).await?;
        axum::serve(listener, router).await?;
    }

    Ok(())
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

    // iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    match std::process::Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-o",
            "eth0",
            "-j",
            "MASQUERADE",
        ])
        .output()
    {
        Ok(output) if output.status.success() => {
            tracing::info!("NAT masquerade already configured");
        }
        _ => {
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
                ])
                .output()
            {
                Ok(output) if output.status.success() => {
                    tracing::info!("NAT masquerade configured for eth0");
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
    }
}
