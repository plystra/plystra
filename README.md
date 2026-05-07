# Plystra

Self-hosted identity and authorization core for applications that need account-identity separation, resource permissions, and audit logs.

Plystra separates the login account from the identity acting inside a business space:

```text
User -> UserMember -> Member -> Space
```

The v1.0 milestone is a stable self-hosted Core. It proves that Plystra can explain who acted, through which identity, in which space, against which resource, under which permission, and why the decision was allowed or denied.

## Current Status

This repository implements the Core side of `PRD-v1.0-stable-self-hosted-core-complete.md`:

- `internal/authz`: reusable authorization engine, deny codes, scope resolver, trace types
- `ent/schema`: Ent schemas for required Core entities
- `internal/store/entstore`: Ent-backed authorization context loading and audit writing
- `internal/store`: PostgreSQL data access using pgx for compatibility paths
- `internal/resources`: Resource Registry registration service
- `internal/plugins`: plugin manifest structs and validation
- `internal/api`: `/api/v1` HTTP handlers for health, authz, audit, Resource Registry, Core CRUD, plugin metadata, template metadata, and data preview surfaces
- `cmd/plystrad`: Core HTTP API server
- `cmd/plystractl`: migration-aware admin CLI
- `cmd/explain-demo`: CLI that prints the four PRD traces
- `migrations/001` through `012`: Finance Reviewer seed data, Resource Registry, Core API support tables, Ent integration guardrails, required v1.0 fields, and empty-database Ent drift closure
- `docs/identity-trace-demo.md`: invariants, scope matrix, deny codes, and non-goals
- `docs/explainable-identity-core.md`: v0.1 package boundary and integration contract
- `docs/resource-registry.md`: v0.3 Resource Registry concept and invoice metadata
- `docs/core-api.md`: pre-1.0 `/api/v1` Core API envelope and endpoint overview
- `docs/ent-database-management.md`: Ent schema management workflow
- `docs/v1.0-readiness.md`: current v1.0 Core readiness notes
- `docs/release/v1.0-readiness-checklist.md`: v1.0 release gate checklist
- `docs/release/v1.0-rc-test-plan.md`: v1.0 RC execution plan
- `docs/release/v1.0-release-notes.md`: v1.0 release notes
- `docs/operations/migration-and-upgrade-guide.md`: migration, upgrade, and production Ent safety guide
- `docs/compatibility/request-id-envelope.md`: request ID envelope compatibility policy

## Quick Start

```bash
git clone https://github.com/plystra/plystra.git
cd plystra
cp .env.example .env
docker compose up -d
go run ./cmd/plystractl migrate up
go run ./cmd/plystractl migrate verify
go run ./cmd/plystractl doctor
go test ./...
go run ./cmd/explain-demo
```

The Compose baseline starts `postgres` and `plystra-core`. Compose reads `.env`, passes `DOCKER_DATABASE_URL` to Core so it can reach PostgreSQL inside Compose, and reports readiness after migrations are applied.

If you prefer `make`:

```bash
make migrate
make ent-check
make demo
make run
```

Equivalent commands without `make`:

```bash
go run ./cmd/plystractl migrate up
go run ./cmd/plystractl migrate verify
go run ./cmd/plystractl doctor
go run ./cmd/explain-demo
go run ./cmd/plystrad
```

On PowerShell:

```powershell
$env:PLYSTRA_DATABASE_URL = "postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable"
go run .\cmd\plystractl migrate up
go run .\cmd\plystractl migrate verify
go run .\cmd\plystractl ent check
go run .\cmd\plystractl doctor
go run .\cmd\explain-demo
```

Run the Core API:

```powershell
go run .\cmd\plystrad
```

Then serve the Console from the sibling repository:

```powershell
cd ..\console
python -m http.server 5173
```

Open `http://localhost:5173` and sign in with `alice@example.com / plystra-demo`.

Core health endpoints:

```bash
curl http://localhost:8080/api/v1/health
curl http://localhost:8080/api/v1/ready
curl http://localhost:8080/api/v1/version
curl http://localhost:8080/system/health
curl http://localhost:8080/system/ready
curl http://localhost:8080/system/version
```

All non-public Core API routes require the admin bootstrap token. Set `PLYSTRA_ADMIN_TOKEN` in `.env` and pass it as `X-Plystra-Admin-Token`:

```bash
curl -H "X-Plystra-Admin-Token: $PLYSTRA_ADMIN_TOKEN" \
  http://localhost:8080/api/v1/audit-logs
```

Session endpoints such as login and actor context use their own bearer-token flow. Health, readiness, and version endpoints remain public for operations.

## Demo Cases

| Case | Actor | Target | Decision | What it proves |
|---|---|---|---|---|
| 1 | Alice via Finance Reviewer | Finance / APAC invoice | `allow` | `group_tree` scope works |
| 2 | Alice via Finance Reviewer | Legal / EMEA invoice | `deny: SCOPE_OUT_OF_BOUNDS` | scope boundaries are enforced |
| 3 | Bob via the same Finance Reviewer | Finance / APAC invoice | `allow` | multiple Users can use the same Member identity |
| 4 | Alice via revoked UserMember binding | Finance / APAC invoice | `deny: USER_MEMBER_REVOKED` | UserMember is an active authorization bridge |

## Example Trace Excerpt

```yaml
case: 1
name: Alice approves Finance APAC invoice
decision: allow
deny_code: null

actor:
  user:
    id: user_alice
    email: alice@example.com
  member:
    id: member_finance_reviewer
    display_name: Finance Reviewer
  user_member:
    id: um_alice_finance_reviewer
    relation_type: delegate
    status: active

space:
  id: space_acme
  name: Acme

target:
  resource:
    id: invoice_001
    type: invoice
  group:
    id: group_finance_apac
    path: finance.apac

matched_candidates:
  - role:
      id: role_finance_approver
      key: finance_approver
    permission:
      resource: invoice
      action: approve
      scope: group_tree
    scope_anchor:
      group_id: group_finance
      path: finance
    scope_check:
      covered: true
      rule: target_path = anchor_path OR target_path LIKE anchor_path || '.%'

audit:
  actor_user_id: user_alice
  actor_member_id: member_finance_reviewer
  actor_user_member_id: um_alice_finance_reviewer
  space_id: space_acme
  action: invoice.approve
  resource_type: invoice
  resource_id: invoice_001
  decision: allow
```

## Development

```bash
go test ./...
DATABASE_URL="postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable" go test ./...
go run ./cmd/explain-demo
go run ./cmd/plystrad
```

The demo writes audit logs for both `allow` and `deny` decisions. `audit_logs.trace` stores the full decision-time snapshot as JSONB.

## Production Notes

- Run `make migrate` before starting or upgrading `plystrad`.
- Use `SERVER_MODE=production`, `DATABASE_URL`, a strong `PLYSTRA_SESSION_SECRET` (or compatibility alias `JWT_SECRET`), a strong `PLYSTRA_ADMIN_TOKEN`, explicit `CORS_ALLOWED_ORIGINS`, and a stable non-localhost `SERVER_PUBLIC_URL`.
- Plystra v1.0 uses opaque bearer sessions; the session secret HMACs stored token hashes and is not used to issue JWT claims.
- Put Plystra Core behind a reverse proxy such as Caddy, Nginx, or a managed load balancer for TLS termination.
- Back up PostgreSQL regularly; audit logs are append-only and should have an explicit retention/export plan.
- Do not run Ent auto migration in production. Use versioned migrations through `plystractl migrate up`.
- Keep `AUDIT_WRITE_MODE=always` in production unless a documented operational exception exists.
- Set `TRUSTED_PROXIES` only when Plystra Core is behind trusted reverse proxies; forwarded IP headers are ignored unless this is configured.
- `DATA_CONSOLE_ENABLED=false` and `METRICS_ENABLED=false` by default; enable them only for deployments that explicitly need those surfaces.

## Integration Shape

Applications pass an explicit actor tuple into the core:

```go
decision, err := authz.Check(ctx, store, authz.CheckInput{
    ActorUserID:       userID,
    ActorMemberID:     memberID,
    ActorUserMemberID: userMemberID,
    SpaceID:           spaceID,
    ResourceType:      "invoice",
    ResourceID:        "invoice_001",
    Action:            "approve",
})
```

The business API should execute the operation only when `decision.IsAllowed()` returns true.
