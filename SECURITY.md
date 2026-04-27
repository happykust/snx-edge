# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| latest on `main` | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly. **Do not** open a public issue.

### Preferred channel: GitHub Security Advisories

Open a private advisory at <https://github.com/happykust/snx-edge/security/advisories/new>. This channel is end-to-end private, allows the maintainer and reporter to collaborate on a fix in a private fork, and produces a CVE on disclosure.

### Fallback: email

If you cannot access GitHub Security Advisories, email **me@happykust.dev**. PGP key on request. Do not include exploit details in the subject line.

### What to include

- Affected version / commit SHA
- Description of the vulnerability and an attack scenario
- Steps to reproduce (or a proof-of-concept)
- Potential impact
- Suggested fix or mitigation, if any

### Response timeline

| Stage | Target |
|---|---|
| Initial acknowledgment | within 72 hours |
| Triage and severity assessment | within 7 days |
| Fix and coordinated disclosure | within 90 days, with extension on request |

For complex issues that require upstream coordination (for example, a vulnerability in `snxcore`, `axum-server`, or `rustls`), the 90-day clock may be paused while we coordinate with the upstream maintainer. We will keep you informed.

## Security Considerations

snx-edge handles sensitive data (VPN credentials, JWT tokens, RouterOS credentials). When deploying:

- **Always** set a strong `SNX_EDGE_JWT_SECRET` (minimum 32 characters; generate with `openssl rand -base64 32`).
- **Enable TLS** for the management API in production (`[api].tls_cert` / `[api].tls_key`).
- **Use mTLS** if the management API is exposed beyond the local network (`[api].tls_client_ca`).
- **Store RouterOS credentials** via environment variables, not in config files (`[routeros].host_env`, `password_env`, etc.).
- **Restrict network access** to the management API port (8080/8443).
- **Encrypt profile credentials at rest** by setting `[security].profile_encryption_key_env` and providing a 32-byte key in that env var.
- Passwords are hashed with **bcrypt** before storage.
- Account lockout activates after 5 failed login attempts (15 min cooldown).
- JWT refresh tokens are tracked in the database and can be revoked.
- The container runs with `cap_drop: ALL` and only `NET_ADMIN` + `NET_RAW` granted, plus `no-new-privileges:true`.
