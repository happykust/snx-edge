# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| latest on `main` | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Email the maintainer at **me@happykust.dev** or use [GitHub Security Advisories](https://github.com/happykust/snx-edge/security/advisories/new)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

You should receive an initial response within 72 hours.

## Security Considerations

snx-edge handles sensitive data (VPN credentials, JWT tokens, RouterOS credentials). When deploying:

- **Always** set a strong `SNX_EDGE_JWT_SECRET` (minimum 32 characters)
- **Enable TLS** for the management API in production (`[api]` section in config)
- **Use mTLS** if the management API is exposed beyond the local network
- **Store RouterOS credentials** via environment variables, not in config files
- **Restrict network access** to the management API port (8080/8443)
- Passwords are hashed with **bcrypt** before storage
- Account lockout activates after 5 failed login attempts (15 min cooldown)
- JWT refresh tokens are tracked in the database and can be revoked
