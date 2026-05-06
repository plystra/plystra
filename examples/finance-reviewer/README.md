# Finance Reviewer Example

This example is the canonical v0.1-pre regression scenario.

Run it from the repository root:

```bash
docker compose up -d
make migrate
make demo
```

Without `make`:

```bash
docker compose exec -T postgres psql -U plystra -d plystra < migrations/001_finance_demo.sql
go run ./cmd/explain-demo
```

Expected decisions:

```text
case 1 -> allow
case 2 -> deny SCOPE_OUT_OF_BOUNDS
case 3 -> allow
case 4 -> deny USER_MEMBER_REVOKED
```
