# Plystra Core

[![CI](https://github.com/plystra/plystra/actions/workflows/ci.yml/badge.svg)](https://github.com/plystra/plystra/actions/workflows/ci.yml)

Plystra Core is a self-hosted identity and authorization service for applications that need account-identity separation, scoped permissions, explainable decisions, and append-only audit trails.

```text
User -> UserMember -> Member -> Space
```

Core provides:

- HTTP API for users, spaces, groups, members, roles, permissions, resources, admin grants, API keys, and audit logs.
- Native auth flows for password login, email verification codes, and magic-link sign-in. Email delivery runs through an external capability contract so SMTP, Cloudflare Email Sending, and future providers stay outside Core.
- Authorization checks with explainable allow/deny traces.
- Context Mode for protecting one existing application action without syncing users, organizations, or resources first.
- Ent-managed PostgreSQL schema with versioned Atlas migrations.
- Production guardrails for sessions, API keys, CORS, metrics, data console access, and audit logging.
- CLI tooling through `plystractl` for migrations, schema drift checks, health checks, and super-admin bootstrap.

## Quick Start

Requirements:

- Go 1.25.10+ (required for current Go standard-library security fixes)
- Docker or a local PostgreSQL 16+ instance

Start PostgreSQL and run the local release gate:

```powershell
cp .env.example .env
docker compose up -d postgres
go run entgo.io/ent/cmd/ent generate ./ent/schema
go run ./cmd/plystractl migrate up
go run ./cmd/plystractl migrate verify
go run ./cmd/plystractl ent check
go run ./cmd/plystractl doctor
go test ./...
```

Run Core:

```powershell
go run ./cmd/plystrad
```

The API listens on `http://localhost:8080` by default.

## Minimal API Example

Production migrations never create an instance super admin automatically. For the local demo flow, run `make seed-demo` before logging in as Alice.

```powershell
$login = Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:8080/api/v1/auth/login `
  -ContentType "application/json" `
  -Body '{"email":"alice@example.com","password":"plystra-demo"}'

$token = $login.data.access_token

Invoke-RestMethod `
  -Headers @{ Authorization = "Bearer $token" } `
  -Uri http://localhost:8080/api/v1/admin/me
```

Non-public routes require either:

- a Bearer session for a user with an active admin grant, or
- a scoped API key with matching permission keys.

## Protect One Existing Action

For first integrations, call `/api/v1/authz/check` from your backend with trusted inline context. This keeps your app as the source of truth and avoids first-day data migration:

```json
{
  "actor": {
    "user_id": "user_external_alice",
    "member_id": "member_finance_reviewer",
    "binding_id": "binding_external_alice_finance",
    "space_id": "space_acme"
  },
  "resource": {
    "type": "invoice",
    "external_id": "invoice_001",
    "space_id": "space_acme",
    "group_path": "finance.apac"
  },
  "grants": [{
    "role_key": "finance_approver",
    "resource": "invoice",
    "action": "approve",
    "scope": "group_tree",
    "space_id": "space_acme",
    "scope_anchor_group_path": "finance"
  }],
  "action": "approve"
}
```

Inline actor, resource, and grant context is API-key-only. Never accept those fields directly from a browser request body; derive them from trusted server-side session and database state.

Registration is disabled by default. For production, keep it closed unless your onboarding flow needs it. Token-protected ordinary registration requires `PLYSTRA_AUTH_REGISTRATION_TOKEN` and creates a User plus personal Space/Member/UserMember and a Space admin grant. Public user-only registration can be enabled with `PLYSTRA_AUTH_PUBLIC_USER_REGISTRATION_ENABLED=true`; it creates only a User and does not create a personal Space, Member, UserMember binding, Space admin grant, or session. Use `PLYSTRA_BOOTSTRAP_REGISTRATION_TOKEN` only for controlled first-super-admin bootstrap.

Email verification codes and magic links are available through:

- `POST /api/v1/auth/email-code`
- `POST /api/v1/auth/email-code/verify`
- `POST /api/v1/auth/magic-link`
- `POST /api/v1/auth/magic-link/consume`

Production must set `PLYSTRA_EMAIL_CAPABILITY_URL`, `PLYSTRA_EMAIL_CAPABILITY_TOKEN`, and `PLYSTRA_AUTH_EMAIL_FROM`. Core stores only HMAC hashes for challenge tokens/codes and sends mail through the independent email capability contract. Challenge send and verification attempts are rate-limited by normalized email and source IP. Magic-link `redirect_url` values must use HTTPS and match `PLYSTRA_PUBLIC_APP_URL`, `SERVER_PUBLIC_URL`, or an origin listed in `PLYSTRA_AUTH_ALLOWED_REDIRECT_ORIGINS`. Local development can omit the capability URL and use log mode; production rejects log mode at startup.

## Documentation

Full installation, integration, operations, SDK, security, and release documentation lives at [docs.plystra.com](https://docs.plystra.com).

Use the docs when you need detailed guidance for:

- production configuration
- creating the first instance super admin
- integrating `authz.check`
- creating scoped API keys
- using the JavaScript, Python, and Go SDKs
- running migrations and release checks
- operating Plystra behind a reverse proxy

## Related Repositories

- Documentation: [plystra/plystra-docs](https://github.com/plystra/plystra-docs)
- Admin Console: [plystra/console](https://github.com/plystra/console)
- JavaScript SDK: [plystra/js-sdk](https://github.com/plystra/js-sdk)
- Python SDK: [plystra/python-sdk](https://github.com/plystra/python-sdk)
- Go SDK: [plystra/go-plystra](https://github.com/plystra/go-plystra)

## Development

Useful commands:

```powershell
go generate ./ent
go test ./...
go run ./cmd/plystractl migrate verify
go run ./cmd/plystractl ent check
go run ./cmd/plystractl doctor
```

Before opening a pull request, run the same checks as CI.

## Security

Please do not report security issues in public GitHub issues. See [SECURITY.md](SECURITY.md) for reporting guidance and production security expectations.

## License

Apache-2.0
