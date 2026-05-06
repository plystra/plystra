# Plystra Migration and Upgrade Guide

## Document Status

| Field | Value |
|---|---|
| Product | Plystra |
| Version | v1.0 |
| Document Type | Operations guide |
| Scope | Migrations, upgrades, Ent drift, production safety |
| Status | Active guide |

---

## 1. Purpose

This guide explains how to apply migrations, verify schema state, and upgrade Plystra Core safely.

Plystra v1.0 uses Ent inside the Core repository, but production upgrades must use versioned migrations.

Production must not rely on Ent auto migration.

The primary goals are:

```text
avoid schema drift
avoid accidental destructive changes
ensure Core code matches database schema
ensure upgrades are repeatable
ensure operators can recover from failed upgrades
```

---

## 2. Core Rules

### Rule 1: Use Versioned Migrations in Production

Production upgrades must use:

```bash
plystractl migrate up
```

Do not use Ent auto migration as the production upgrade mechanism.

### Rule 2: Verify After Migration

Always run:

```bash
plystractl migrate verify
plystractl ent check
plystractl doctor
```

### Rule 3: Backup Before Upgrade

Always back up PostgreSQL before applying production migrations.

### Rule 4: Do Not Skip Migrations

Do not manually edit schema to match the latest code.

Use project-provided migrations.

### Rule 5: Treat AuditLog Carefully

AuditLog is append-only.

Never manually mutate audit records unless following an emergency recovery procedure approved by maintainers.

---

## 3. Migration Commands

## 3.1 Apply Migrations

```bash
plystractl migrate up
```

Expected behavior:

```text
connects to configured database
detects current migration version
applies pending migrations in order
records applied migration versions
returns clear success or failure result
```

## 3.2 Verify Migrations

```bash
plystractl migrate verify
```

Expected behavior:

```text
checks migration table
checks expected schema state
checks migration integrity where supported
reports missing or failed migrations
```

## 3.3 Check Ent Drift

```bash
plystractl ent check
```

Expected behavior:

```text
compares Ent schema expectations with database schema
reports drift if schema and code are inconsistent
returns zero only when no drift exists
```

## 3.4 Doctor

```bash
plystractl doctor
```

Expected behavior:

```text
checks configuration
checks database connectivity
checks migration state
checks schema readiness
checks runtime readiness
returns actionable diagnostics
```

---

## 4. Development Migration Workflow

In development, maintainers may use Ent tools to iterate.

Recommended workflow:

```text
1. Modify ent/schema.
2. Generate Ent code.
3. Generate versioned migration.
4. Apply migration to local database.
5. Run tests.
6. Run ent check.
7. Commit schema, generated code, and migration together.
```

Example:

```bash
go generate ./ent
plystractl migrate diff
plystractl migrate up
plystractl ent check
go test ./...
```

Exact commands may differ depending on project tooling.

The invariant remains:

```text
Ent schema, generated code, and migrations must be committed together.
```

---

## 5. CI Migration Workflow

CI must validate:

```text
generated Ent code is current
migrations are current
migrations apply to empty database
migrations apply from previous release schema
authz conformance tests pass after migration
```

Recommended CI jobs:

```text
codegen-check
migration-diff-check
migration-apply-empty-db
migration-apply-upgrade-db
authz-conformance-test
```

### 5.1 Codegen Check

Example:

```bash
go generate ./ent
git diff --exit-code
```

### 5.2 Migration Diff Check

Example:

```bash
plystractl migrate diff --check
```

or equivalent Atlas/Ent command.

Expected:

```text
no uncommitted migration diff
```

### 5.3 Empty DB Migration Test

Example:

```bash
createdb plystra_empty_test
PLYSTRA_DATABASE_URL=... plystractl migrate up
PLYSTRA_DATABASE_URL=... plystractl migrate verify
```

### 5.4 Upgrade DB Migration Test

Example:

```bash
restore previous release schema
PLYSTRA_DATABASE_URL=... plystractl migrate up
PLYSTRA_DATABASE_URL=... plystractl migrate verify
PLYSTRA_DATABASE_URL=... go test ./...
```

---

## 6. Production Upgrade Procedure

Follow this procedure for production upgrades.

## 6.1 Before Upgrade

### Step 1: Read Release Notes

Review:

```text
release notes
migration notes
breaking changes
compatibility notes
known limitations
```

### Step 2: Check Current Version

```bash
curl -s http://localhost:8080/api/v1/version
```

Record:

```text
Core version
schema version
trace version
build metadata
```

### Step 3: Run Doctor

```bash
plystractl doctor
```

Do not upgrade if doctor reports critical issues.

### Step 4: Backup PostgreSQL

Example:

```bash
pg_dump "$DATABASE_URL" > plystra-backup-before-v1.0.sql
```

Recommended:

```text
store backup outside the server
encrypt backup if it contains sensitive data
verify backup file is non-empty
record backup timestamp
record current app version
record current schema version
```

### Step 5: Optional Restore Test

For production-critical deployments, test restore on a staging database.

```bash
createdb plystra_restore_test
psql plystra_restore_test < plystra-backup-before-v1.0.sql
```

---

## 6.2 During Upgrade

### Step 1: Stop or Quiesce Core

Depending on deployment:

```bash
docker compose stop plystra-core
```

or put the application in maintenance mode.

### Step 2: Pull New Version

```bash
git fetch --tags
git checkout v1.0.0
```

or update Docker image tag.

### Step 3: Apply Migrations

```bash
plystractl migrate up
```

### Step 4: Verify Migrations

```bash
plystractl migrate verify
plystractl ent check
```

### Step 5: Start Core

```bash
docker compose up -d plystra-core
```

### Step 6: Run Doctor

```bash
plystractl doctor
```

---

## 6.3 After Upgrade

Run smoke tests:

```bash
curl -s http://localhost:8080/api/v1/health
curl -s http://localhost:8080/api/v1/ready
curl -s http://localhost:8080/api/v1/version
```

Run authorization smoke tests:

```text
authz/check allow case
authz/check deny case
authz/explain allow case
authz/explain deny case
```

Check logs:

```bash
docker compose logs --tail=200 plystra-core
```

Check AuditLog:

```text
recent allow decision
recent deny decision
request_id correlation
trace snapshot shape
```

---

## 7. Production Ent Apply Rejection

Plystra production mode intentionally rejects unsafe Ent auto apply behavior.

This is not a bug.

## 7.1 Why It Is Rejected

Ent auto migration can be useful in development, but production upgrades require:

```text
reviewable migration files
repeatable upgrade process
CI validation
backup planning
rollback planning
operator visibility
```

Therefore production should use:

```bash
plystractl migrate up
```

not automatic schema mutation.

## 7.2 Expected Error Behavior

If an unsafe Ent apply command is attempted in production, the system should return a clear error:

```text
Ent auto migration is disabled in production.
Use versioned migrations through plystractl migrate up.
```

## 7.3 Documentation Requirement

Release notes and upgrade docs must mention this behavior.

---

## 8. Rollback Guidance

Rollback depends on migration type.

## 8.1 Application Rollback

If migrations are backward-compatible:

```bash
docker compose stop plystra-core
git checkout previous-version
docker compose up -d plystra-core
```

or use previous Docker image.

## 8.2 Database Rollback

If migrations are not backward-compatible, restore from backup.

Example:

```bash
dropdb plystra
createdb plystra
psql plystra < plystra-backup-before-upgrade.sql
```

## 8.3 Rollback Checklist

Before rollback:

```text
identify failed component
preserve logs
preserve error output
preserve current database snapshot if useful
confirm backup availability
stop write traffic if possible
restore app and DB consistently
run doctor after rollback
```

## 8.4 AuditLog Consideration

AuditLog records created during failed upgrade windows should be preserved if possible.

If database restore removes them, document the operational event outside Plystra.

---

## 9. Migration Safety Requirements

Each migration should document:

```text
purpose
affected tables
new columns
removed columns if any
indexes
constraints
data backfill if any
rollback strategy
compatibility notes
```

Migrations that affect these areas require extra review:

```text
UserMember
MemberRole
Permission
Resource
AuditLog
Group path
Deny code fields
Trace schema fields
```

---

## 10. Data Migration Guidance

Data migrations must be separate from schema migrations when practical.

Examples:

```text
backfill UserMember.is_primary
backfill Resource.status
backfill AuditLog.deny_code
normalize Group paths
seed system permissions
```

Data migrations should be:

```text
idempotent where possible
logged
tested on staging data
safe to retry when possible
documented
```

---

## 11. Schema Drift Troubleshooting

## 11.1 Symptom: `ent check` Fails

Possible causes:

```text
migration not applied
migration file missing
manual DB change
generated Ent code stale
wrong database URL
wrong environment
```

Recommended steps:

```bash
echo $PLYSTRA_DATABASE_URL
plystractl migrate verify
plystractl ent check
go generate ./ent
git diff
```

## 11.2 Symptom: Core Starts But API Fails

Possible causes:

```text
schema version mismatch
missing column
old migration state
wrong database
stale Docker image
```

Recommended steps:

```bash
curl -s /api/v1/version
plystractl doctor
plystractl migrate verify
docker compose logs --tail=200 plystra-core
```

## 11.3 Symptom: Authz Results Are Wrong After Upgrade

Possible causes:

```text
seed data changed
RolePermission missing
MemberRole scope anchor missing
Resource group_id missing
UserMember revoked/expired
Group path changed
candidate permission filtering bug
```

Recommended checks:

```text
verify actor context
verify Resource record
verify MemberRole.scope_anchor_group_id
verify Permission resource/action/scope
verify Group path
run Finance Reviewer demo
run authz/explain
```

---

## 12. Backup Guidance

Minimum backup:

```bash
pg_dump "$DATABASE_URL" > plystra-backup.sql
```

Recommended production backup strategy:

```text
scheduled PostgreSQL backups
off-server storage
encrypted backups
restore tests
retention policy
pre-upgrade backup
post-upgrade verification
```

Backup should include:

```text
Core tables
AuditLog
Resource Registry records
migration version table
plugin metadata if present
```

If future plugins own separate tables, plugin-owned data must also be included.

---

## 13. Upgrade Smoke Test Checklist

After every production upgrade, run:

```text
health endpoint
ready endpoint
version endpoint
doctor command
migrate verify
ent check
authz/check allow
authz/check deny
authz/explain
Resource Registry query
AuditLog query
request ID correlation
```

Minimum command examples:

```bash
curl -s http://localhost:8080/api/v1/health
curl -s http://localhost:8080/api/v1/ready
curl -s http://localhost:8080/api/v1/version
plystractl doctor
plystractl migrate verify
plystractl ent check
```

---

## 14. Release Maintainer Checklist

Before publishing a release:

```text
all migrations committed
generated Ent code committed
migration tests pass
ent drift check passes
doctor passes
authz conformance tests pass
OpenAPI updated
release notes updated
upgrade guide updated
Docker image built
tag created
clean install verified
upgrade install verified
```

---

## 15. Summary

Plystra v1.0 treats migrations as a production safety boundary.

Use Ent for schema modeling and code generation inside Core.

Use versioned migrations for production upgrades.

Always verify:

```text
migration state
Ent drift
doctor output
authz correctness
AuditLog correctness
```

Never rely on production Ent auto apply.
