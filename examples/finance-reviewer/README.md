# Finance Reviewer Example

This example is a development-only regression scenario. Core production
migrations do not create these users, roles, resources, or permissions.

Run it from the repository root:

```bash
docker compose -f docker-compose.dev.yml up -d postgres
make migrate
docker compose exec -T postgres psql -U plystra -d plystra < examples/finance-reviewer/seed.sql
go run ./cmd/explain-demo
```

Without `make`:

```bash
docker compose exec -T postgres psql -U plystra -d plystra < examples/finance-reviewer/seed.sql
go run ./cmd/explain-demo
```

Expected decisions:

```text
case 1 -> allow
case 2 -> deny SCOPE_OUT_OF_BOUNDS
case 3 -> allow
case 4 -> deny USER_MEMBER_REVOKED
```
