# Security Policy

## Supported Versions

Plystra Core `0.0.1` is the current alpha release. Security fixes are applied to the active release line.

## Reporting a Vulnerability

Please do not report security vulnerabilities in public GitHub issues.

Use GitHub private vulnerability reporting for this repository when available. If that is not available, contact the maintainers privately and include:

- affected version or commit
- affected endpoint, CLI command, or deployment mode
- reproduction steps
- expected and actual behavior
- impact assessment
- any relevant logs with secrets removed

We will acknowledge valid reports as soon as practical, investigate the impact, and coordinate fixes before public disclosure.

## Security Expectations

Production deployments should:

- set strong `PLYSTRA_SESSION_SECRET` and `PLYSTRA_API_KEY_SECRET`
- use explicit `CORS_ALLOWED_ORIGINS`
- run behind TLS and a trusted reverse proxy
- keep `DATA_CONSOLE_ENABLED=false` unless explicitly needed
- keep `METRICS_ENABLED=false` unless the endpoint is protected
- run versioned migrations before serving traffic
- store API keys and session tokens only in trusted secret storage
- keep user registration disabled unless explicitly needed; when enabled, prefer registration tokens and use a separate bootstrap token for the first instance super admin. If public user-only registration is enabled, treat it as account creation only: it must not create personal Spaces, Members, UserMember bindings, Space admin grants, or sessions.
