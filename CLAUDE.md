# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**snx-edge** — a Cargo workspace (Rust 2024 edition) that moves Check Point VPN termination off the workstation onto a MikroTik router. Three crates in `apps/`:

| Crate | Role | Runtime |
|---|---|---|
| `snx-edge-server` | Headless VPN client (`snxcore`) + Axum management API | Alpine container on MikroTik (ARM64/x86_64, musl) |
| `snx-edge-client` | GTK4/libadwaita tray app for desktop management | Linux desktop (x86_64) |
| `snx-edge-ctl` | CLI client (clap + tabled) for the same management API | Linux desktop |

Client and ctl share the same `~/.config/snx-edge/client.toml` (multi-server, JWT in keyring) and talk to the server over the same REST + SSE API.

## Common commands

```bash
# Build/test/lint the entire workspace
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings   # CI gate
cargo fmt --all -- --check

# Per-crate
cargo build --release -p snx-edge-server
cargo build --release -p snx-edge-client     # needs gtk4-devel libadwaita-devel dbus-devel
cargo build --release -p snx-edge-ctl

# Run server tests only (matches CONTRIBUTING.md and the bulk of test coverage)
cargo test -p snx-edge-server

# Single integration test by name
cargo test -p snx-edge-server --test api_tests <test_name>

# Run the server locally against a TOML config
cargo run -p snx-edge-server -- --config docker/config.toml

# Local container build
cd docker && docker compose up --build
```

### Cross-compilation for MikroTik (ARM64 / x86_64 musl)

CI uses `cross` (pinned to v0.2.5) — native `cargo build --target ...` will not work because `snxcore` pulls OpenSSL and SQLite that need a full musl toolchain. The `vendored-openssl` feature on `snx-edge-server` is required:

```bash
cargo install cross@0.2.5 --locked
cross build --release -p snx-edge-server \
  --target aarch64-unknown-linux-musl \
  --features snx-edge-server/vendored-openssl
```

`Cross.toml` injects `perl` + `make` into the cross images so OpenSSL builds.

## Architecture

### Server (`apps/snx-edge-server`)

`main.rs` wires startup in this order, and the order matters:

1. Load TOML config (path from `--config`, default `/etc/snx-edge/config.toml`).
2. Create the **shared log ring buffer** and the **`broadcast::Sender<ServerEvent>`** *before* `tracing` init.
3. Install `LogCaptureLayer` (`log_layer.rs`) so every `tracing` event from that point on lands in the ring buffer **and** is fanned out to SSE listeners as `ServerEvent::LogEntry`. Anything emitted before this layer registers is lost.
4. `enable_ip_forwarding()` writes `/proc/sys/net/ipv4/ip_forward` and adds an `iptables -t nat MASQUERADE` rule on `eth0`. Failures are logged, not fatal — the container may already have it set up.
5. Build `AppState` (clones into all handlers): config behind `RwLock`, `UserDb` (SQLite, bundled), `TunnelManager`, JWT secret, log buffer, event broadcaster.
6. Bind axum-server with rustls if `[api].tls_cert/tls_key` are set; mTLS adds `tls_client_ca` (uses `WebPkiClientVerifier::allow_unauthenticated` so health checks still work without a cert). Otherwise plain HTTP.

API layout (`api/mod.rs`): every route is nested under `/api/v1`. Public routes are `health` + `auth`; everything else is wrapped by `auth::require_auth` middleware which validates a JWT and injects `Claims` into request extensions. Errors are uniformly `AppError` (`error.rs`) → RFC 7807 `ProblemDetails` JSON.

VPN profiles are **not** in `config.toml` — they live in SQLite and are managed entirely through the API. `AppConfig::save` rewrites the TOML and **drops comments**; treat the config file as machine-managed.

The `TunnelManager` (`tunnel.rs`) wraps `snxcore::tunnel::CheckPointTunnelConnectorFactory`. Connect requests carry a `VpnConfig` payload per call, so the server itself is stateless w.r.t. VPN credentials — only the active session is held in memory.

### RouterOS provisioner (`apps/snx-edge-server/src/routeros/`)

`Provisioner::setup` creates the full PBR layout (routing table, mangle connection-mark, mangle routing-mark, default route, kill switch, DNS dst-nat, DoT block, FastTrack exclusion, default RFC1918 bypass). Every managed object carries the `comment_tag` (default `managed-by=snx-edge`). `teardown()` greps that tag to clean up — **never remove the tag from anything you create or it will leak on teardown**. RouterOS host/user/password come from env vars whose names are configured in `[routeros]`.

### Client (`apps/snx-edge-client`)

GTK4 with `glib::clone` for callbacks; async work runs on a tokio runtime started by `#[tokio::main]` in `main.rs`. UI windows live in `windows/` and are tracked in a `thread_local! WINDOWS` map (single-instance per name). `tray.rs` uses `ksni`. SSE log streaming uses `reqwest-eventsource`. Tokens go to the OS keyring via the `keyring` crate (sync-secret-service on Linux). `dbus.rs` handles desktop integration via `zbus`.

### CTL (`apps/snx-edge-ctl`)

Clap subcommand router in `main.rs` over a thin `ApiClient` (`api.rs`). Output mode is global: default tabled, `--json`, or `--quiet`. Reads server list from the same `client.toml` as the tray; `--server <name|url>` selects.

## Conventions

- **Errors**: server uses `thiserror` for the typed `AppError` enum and `anyhow::Result` only at the binary entry / startup. New API endpoints should map their failures into `AppError` variants — do not return raw `anyhow::Error` from handlers.
- **Logging**: never `println!` / `eprintln!` in server code — `tracing` is required so the capture layer sees the event. The default filter is `info` (override via `RUST_LOG`).
- **Release profile** is size-optimized (`opt-level='z'`, LTO, strip, panic=abort). Don't expect useful unwind traces from prod binaries; rely on logs.
- **Idempotency on RouterOS**: any new managed rule must be both created with the comment tag *and* checked-before-create (see existing `ensure_*` methods in `provisioner.rs`).
- **Secrets** never go in `config.toml` — JWT secret + RouterOS credentials are env-only, configured by *name* in TOML (`jwt_secret_env`, `host_env`, etc.).
- The auto-managed `MEMORY.md` notes that this fork's working dir is `snx-edge-proxy/` even though the project is named `snx-edge`; treat them as the same project.
