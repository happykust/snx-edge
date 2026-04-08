# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-09

### Added

- **snx-edge-server**: Headless VPN client with Management REST API
  - Check Point VPN tunnel via snxcore (UDP, TCPT transport)
  - JWT authentication with RBAC (admin/operator/viewer)
  - VPN profile management with TOML import/export
  - RouterOS PBR provisioning (mangle, routes, NAT, DNS, kill switch)
  - SSE streaming for real-time events and logs
  - TLS/mTLS support
  - SQLite storage for users, sessions, profiles
  - Address validation for routing entries
  - Account lockout after failed login attempts

- **snx-edge-client**: GTK4 tray application
  - System tray with connection status icons
  - VPN profile editor (30+ parameters)
  - Routing management (vpn-clients, vpn-bypass, PBR setup/teardown)
  - User management (admin-only)
  - Real-time log viewer with SSE streaming
  - Multi-server support
  - Role-based UI adaptation
  - Routing health indicator

- **snx-edge-ctl**: CLI client
  - All server management commands (tunnel, profiles, routing, users, logs)
  - Multi-server support (shared config with tray client)
  - Table/JSON/quiet output modes
  - SSE log streaming
  - Keyring token storage

- **Docker**: Alpine container for MikroTik
  - OpenRC init system
  - iptables-legacy (MikroTik compatible)
  - ip_forward enabled
  - Health check endpoint
  - Auto-create config on first boot

- **CI/CD**: GitHub Actions
  - Clippy + rustfmt + cargo audit
  - Cross-compilation for ARM64 and x86_64
  - Multi-arch Docker image (ghcr.io)
  - GitHub Release with binary artifacts

- **RouterOS**: Setup scripts and documentation

[0.1.0]: https://github.com/happykust/snx-edge/releases/tag/v0.1.0
