# snx-edge

[![CI](https://github.com/happykust/snx-edge/actions/workflows/ci.yml/badge.svg)](https://github.com/happykust/snx-edge/actions/workflows/ci.yml)
[![Docker](https://github.com/happykust/snx-edge/actions/workflows/docker.yml/badge.svg)](https://github.com/happykust/snx-edge/actions/workflows/docker.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

Headless Check Point VPN client running inside a MikroTik container with a remote management API and a GTK4 tray application for Linux desktops.

## Overview

**snx-edge** moves the VPN termination point from your workstation to a MikroTik router. The VPN tunnel runs inside a lightweight Docker container on the router, and selective traffic routing is handled by RouterOS policy-based routing (PBR). You manage everything from a system tray app on your desktop.

```
  Workstation              MikroTik Router                 Check Point
  ┌──────────┐    REST     ┌──────────────────────┐        VPN Gateway
  │ snx-edge │───/SSE────>│ Container            │        ┌──────────┐
  │ -client  │            │  ┌────────┐ ┌──────┐ │ ESP/   │          │
  │ (tray)   │            │  │ axum   │ │snx-  │ │ TCPT   │          │
  └──────────┘            │  │ API    │ │core  │─┼───────>│          │
                          │  └────┬───┘ └──────┘ │        └──────────┘
                          │       │ RouterOS REST │
                          └───────┼──────────────┘
                                  v
                          Firewall / Mangle / PBR
```

### Key Features

- **Headless VPN** — runs `snxcore` in a Docker container (Alpine, ~25 MB image)
- **Management REST API** — full control over VPN lifecycle, configuration, routing
- **Server-Sent Events** — real-time status updates pushed to all connected clients
- **RouterOS Integration** — automated PBR setup via RouterOS REST API (mangle, routes, NAT, DNS protection)
- **Multi-user RBAC** — admin / operator / viewer roles with granular permissions
- **GTK4 Tray Client** — libadwaita-based desktop app with profile editor, routing management, log viewer
- **Cross-compilation** — ARM64, ARMv7, x86_64 targets for MikroTik hardware
- **MFA Support** — challenge-response flow for multi-factor authentication
- **Kill Switch** — firewall rules prevent traffic leaks if the tunnel drops

## Components

| Component | Description | Runtime |
|---|---|---|
| **snx-edge-server** | Headless VPN client + Management API | Docker on MikroTik (Alpine, ARM64) |
| **snx-edge-client** | Tray app for remote management | Linux desktop (x86_64, GTK4/libadwaita) |

## Quick Start (Docker)

### Prerequisites

- MikroTik router with RouterOS 7.4+ and container support
- Check Point VPN gateway credentials
- Docker (for local testing) or MikroTik container package

### 1. Clone the repository

```bash
git clone --recurse-submodules https://github.com/happykust/snx-edge.git
cd snx-edge-proxy
```

### 2. Configure

```bash
cp docker/config.toml.example docker/config.toml
# Edit docker/config.toml with your VPN and RouterOS settings
```

### 3. Set environment variables

```bash
export SNX_EDGE_JWT_SECRET="your-secret-at-least-32-characters-long"
export ROUTEROS_HOST="172.19.0.1"
export ROUTEROS_USER="snx-edge"
export ROUTEROS_PASSWORD="changeme"
```

### 4. Run

```bash
cd docker
docker compose up -d
```

The server will be available at `http://localhost:8080`. The default admin account is created from `SNX_EDGE_ADMIN_USER` / `SNX_EDGE_ADMIN_PASSWORD` environment variables.

## Building from Source

### Requirements

- Rust 1.85+ (edition 2024)
- For snx-edge-client: GTK4 4.12+, libadwaita 1.4+, D-Bus development libraries

### Server

```bash
cargo build --release -p snx-edge-server
```

### Client

```bash
# Install GTK4/libadwaita dev packages first:
# Fedora: dnf install gtk4-devel libadwaita-devel dbus-devel
# Ubuntu: apt install libgtk-4-dev libadwaita-1-dev libdbus-1-dev

cargo build --release -p snx-edge-client
```

### Cross-compilation (ARM64 for MikroTik)

```bash
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl -p snx-edge-server \
  --features snxcore/vendored-openssl,snxcore/vendored-sqlite
```

## Configuration

Server configuration is done via a TOML file. See [`docker/config.toml.example`](docker/config.toml.example) for all options.

| Section | Key settings |
|---|---|
| `[api]` | Listen address, TLS certificates, mTLS |
| `[auth]` | JWT secret (env), token TTLs, lockout policy |
| `[routeros]` | RouterOS host/credentials (env), address lists, routing table names |
| `[logging]` | Log level, ring buffer size, optional file output |

VPN profiles are managed through the API, not the config file.

## API Overview

All endpoints are prefixed with `/api/v1`. Authentication uses JWT Bearer tokens.

| Category | Endpoints |
|---|---|
| **Auth** | `POST /auth/login`, `POST /auth/refresh` |
| **Tunnel** | `POST /tunnel/connect`, `POST /tunnel/disconnect`, `GET /tunnel/status` |
| **Profiles** | CRUD on `/profiles`, cert upload, import/export |
| **Routing** | `/routing/clients`, `/routing/bypass`, `/routing/setup`, `/routing/diagnostics` |
| **Users** | CRUD on `/users`, `/users/me`, `/users/sessions` |
| **Events** | `GET /events` (SSE stream) |
| **Logs** | `GET /logs` (SSE stream), `GET /logs/history` |
| **Health** | `GET /health` (no auth) |

### Roles & Permissions

| Role | Capabilities |
|---|---|
| **admin** | Full access: VPN, config, routing setup/teardown, user management |
| **operator** | VPN connect/disconnect, routing client/bypass management, logs |
| **viewer** | Read-only: status, config, routes, logs |

## RouterOS Integration

snx-edge-server manages MikroTik routing rules via the RouterOS REST API:

- **Address lists** — `vpn-clients` (hosts routed through VPN) and `vpn-bypass` (exceptions)
- **Mangle rules** — mark connections and routes for policy-based routing
- **Routing table** — dedicated `vpn-route` table with gateway pointing to the container
- **Kill switch** — firewall rules to prevent traffic leaks
- **DNS protection** — redirect DNS queries from VPN clients, block DoT

All managed rules are tagged with `managed-by=snx-edge` comments for safe cleanup.

## Client Application

The GTK4 tray application provides:

- System tray icon with connection status
- VPN profile editor (connection settings, DNS, routing, security, IKE)
- Routing management (add/remove VPN clients and bypass addresses)
- User management (admin only)
- Real-time log viewer with level filtering
- Multi-server support with server picker

### Running the Client

```bash
snx-edge-client
```

Configuration is stored in `~/.config/snx-edge/client.toml`.

## Project Structure

```
snx-edge-proxy/
├── apps/
│   ├── snx-edge-server/       # Headless VPN server + API
│   │   ├── src/
│   │   │   ├── api/           # Axum route handlers
│   │   │   ├── routeros/      # RouterOS REST client & PBR provisioner
│   │   │   ├── config.rs      # TOML configuration
│   │   │   ├── db.rs          # SQLite user/session storage
│   │   │   ├── tunnel.rs      # VPN tunnel manager (snxcore wrapper)
│   │   │   └── ...
│   │   └── tests/
│   └── snx-edge-client/       # GTK4 tray application
│       └── src/
│           ├── ui/            # GTK4/libadwaita windows
│           ├── api.rs         # HTTP client for server API
│           ├── auth.rs        # JWT + keyring management
│           ├── sse.rs         # SSE event stream
│           ├── tray.rs        # System tray (ksni)
│           └── ...
├── docker/                    # Dockerfile, compose, config example
├── vendor/snx-rs/             # Upstream VPN library (git submodule)
└── Cargo.toml                 # Workspace root
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## Security

For responsible disclosure of security vulnerabilities, see [SECURITY.md](SECURITY.md).

## Acknowledgments

- [snx-rs](https://github.com/ancwrd1/snx-rs) — the upstream Check Point VPN client library that powers the VPN core
- [MikroTik](https://mikrotik.com/) — RouterOS container support makes this project possible

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).
