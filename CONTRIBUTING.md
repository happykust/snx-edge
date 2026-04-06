# Contributing to snx-edge

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

- Rust 1.85+ (edition 2024)
- GTK4 4.12+ and libadwaita 1.4+ development libraries (for the client)
- Docker (for running the server locally)
- A MikroTik router with RouterOS 7.4+ (for end-to-end testing)

### Clone & Build

```bash
git clone --recurse-submodules https://github.com/happykust/snx-edge.git
cd snx-edge-proxy
cargo build
```

### Running Tests

```bash
cargo test -p snx-edge-server
```

## How to Contribute

### Reporting Bugs

Open an issue using the **Bug Report** template. Include:

- Steps to reproduce
- Expected vs. actual behavior
- RouterOS version, target architecture, and OS
- Relevant logs (use `RUST_LOG=debug`)

### Suggesting Features

Open an issue using the **Feature Request** template. Describe:

- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

### Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run `cargo test` and `cargo clippy`
5. Submit a PR with a clear description of the changes

#### PR Guidelines

- Keep PRs focused — one logical change per PR
- Follow existing code style and patterns
- Add tests for new functionality
- Update documentation if needed
- Do not include unrelated formatting changes

## Architecture Notes

- **Server** uses Axum with shared `AppState` (config, DB, tunnel manager, event broadcaster)
- **Client** is GTK4/libadwaita with async operations via `tokio` runtime on a background thread
- RouterOS rules are managed idempotently with comment-based tracking (`managed-by=snx-edge`)
- All API errors follow RFC 7807 Problem Details format

## Code Style

- Rust edition 2024
- Use `thiserror` for error types, `anyhow` for application-level errors
- Prefer `tracing` over `println!` / `eprintln!`
- Keep module files focused — split large modules into submodules

## License

By contributing, you agree that your contributions will be licensed under the [AGPL-3.0 License](LICENSE).
