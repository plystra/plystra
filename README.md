# Plystra Core

[![CI](https://github.com/plystra/plystra/actions/workflows/ci.yml/badge.svg)](https://github.com/plystra/plystra/actions/workflows/ci.yml)

Plystra Core is a self-hosted identity and authorization service for applications that need account-identity separation, scoped permissions, explainable decisions, and append-only audit trails.

```text
User -> UserMember -> Member -> Space
```

Core provides:

- HTTP API for users, spaces, groups, members, roles, permissions, resources, admin grants, API keys, and audit logs.
- Minimal native auth for password login, protected registration, session refresh, and logout. Email codes, magic links, MFA, and enterprise authentication extensions live in the dedicated auth plugin.
- Authorization checks with explainable allow/deny traces.
- Context Mode for protecting one existing application action without syncing users, organizations, or resources first.
- Ent-managed PostgreSQL schema with versioned Atlas migrations.
- Production guardrails for sessions, API keys, CORS, metrics, data console access, and audit logging.
- CLI tooling through `plystractl` for migrations, schema drift checks, health checks, and super-admin bootstrap.

## Quick Start

Requirements:

- Go 1.25.11+ (required for current Go standard-library security fixes)
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

Registration is disabled by default. For production, keep it closed unless your onboarding flow needs it. Token-protected ordinary registration requires `PLYSTRA_AUTH_REGISTRATION_TOKEN` and creates a User plus that user's default Member/UserMember inside the deployment-level Simple Mode default Space, then grants space admin access for that default Space. Public user-only registration can be enabled with `PLYSTRA_AUTH_PUBLIC_USER_REGISTRATION_ENABLED=true`; it creates only a User and does not create a Member, UserMember binding, admin grant, or session. Use `PLYSTRA_BOOTSTRAP_REGISTRATION_TOKEN` only for controlled first-super-admin bootstrap.

Core intentionally keeps authentication minimal: password login, protected registration, session refresh, logout, and actor context. Full authentication flows such as email verification codes, magic links, MFA, and external identity-provider integrations belong in the separate full-auth plugin repository. That plugin pulls email delivery contracts only when email delivery is enabled.

## Generic App Data

Backend OS Alpha can store ordinary application data in Plystra Core when a project does not want a separate business database for structured records. Create a space-scoped model under `/api/v1/spaces/{space_id}/data/models`; Core registers a model-specific resource type such as `data_customer`, creates read/create/update/archive/delete permission definitions, and returns those permission IDs in the model response.

Applications then bind those generated permissions to roles through `/api/v1/spaces/{space_id}/role-permissions` and assign roles to Members with `/api/v1/spaces/{space_id}/member-role-grants`. Record endpoints under `/api/v1/spaces/{space_id}/data/models/{model_key}/records` are governed by the normal Plystra authorization engine. Record, revision, and mutation-audit writes commit atomically for single-record and batch mutations. Audit logs include model, record, and changed key names for explainability, but do not copy business field values by default.

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

## Backend OS Alpha Operations

The alpha backend assembly flow is intentionally transparent:

```powershell
go run ./cmd/plystractl templates list
go run ./cmd/plystractl templates describe auth-ready-saas
go run ./cmd/plystractl templates create --template auth-ready-saas --name "Acme SaaS" --out ./acme-saas
go run ./cmd/plystractl backup manifest --out plystra-backup-manifest.json
go run ./cmd/plystractl backup pg-dump-command
go run ./cmd/plystractl upgrade plan
go run ./cmd/plystractl upgrade verify
```

`templates create` writes an inspectable application directory with `README.md`, `.env.example`, `docker-compose.yml`, `plystra/template-installation.json`, and `plystra/install-explanation.md`. The generated scaffold never writes real secrets and never creates the first instance super admin automatically.

`/api/v1/ready` reports Core readiness, migration state, system capabilities, and plugin status counts. Production alpha still requires external PostgreSQL and versioned migrations; cloud hosting and marketplace behavior are outside this phase.

Plugin manifests are governed contracts, not route-only metadata. Core validates declared resources, permissions, audit event types, routes, jobs, events, health checks, required secrets, external network access, settings, and capability profiles before storing a plugin manifest. Capability levels follow the product specification: `declared` for discovery-only profiles, `standard` for implemented contracts, and `certified` for providers that pass a conformance suite. Capability audit enforcement gates the allowed data plane: direct provider database access is limited to grant-only/reported-event paths, observed mutation requires a mutation journal or Action Gateway, and Core Data API must be explicitly declared for providers that store records through Core App Data.

Routes may declare either static `resource_type`/`action` authorization or an `authorization.mode=dynamic_resource` resolver for generic CRUD-style routes. Dynamic route authorization must name the path parameter, resource-key strategy, action, and covered resources so Core can still validate the plugin governance surface without knowing plugin business semantics.

## Security

Please do not report security issues in public GitHub issues. See [SECURITY.md](SECURITY.md) for reporting guidance and production security expectations.

## License

Apache-2.0
