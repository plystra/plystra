# Plystra

Self-hosted identity and authorization core for applications that need account-identity separation, resource permissions, and audit logs.

Plystra separates the login account from the identity acting inside a business space:

```text
User -> UserMember -> Member -> Space
```

The first milestone is the Finance Reviewer Identity Trace Demo. It proves that Plystra can explain who acted, through which identity, in which space, against which resource, under which permission, and why the decision was allowed or denied.

## Current Status

This repository implements the v0.1-pre identity trace prototype and the v0.1 internal package boundary:

- `internal/authz`: reusable authorization engine, deny codes, scope resolver, trace types
- `internal/store`: PostgreSQL data access using pgx and raw SQL
- `cmd/explain-demo`: CLI that prints the four PRD traces
- `migrations/001_finance_demo.sql`: schema and Finance Reviewer seed data
- `docs/identity-trace-demo.md`: invariants, scope matrix, deny codes, and non-goals
- `docs/explainable-identity-core.md`: v0.1 package boundary and integration contract

## Quick Start

```bash
docker compose up -d
make migrate
make demo
```

Equivalent commands without `make`:

```bash
docker compose exec -T postgres psql -U plystra -d plystra < migrations/001_finance_demo.sql
go run ./cmd/explain-demo
```

On PowerShell:

```powershell
$env:DATABASE_URL = "postgres://plystra:plystra@localhost:5432/plystra?sslmode=disable"
Get-Content .\migrations\001_finance_demo.sql | docker compose exec -T postgres psql -U plystra -d plystra
go run .\cmd\explain-demo
```

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
go run ./cmd/explain-demo
```

The demo writes audit logs for both `allow` and `deny` decisions. `audit_logs.trace` stores the full decision-time snapshot as JSONB.

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
