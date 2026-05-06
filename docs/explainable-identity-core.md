# Explainable Identity Core

Plystra v0.1 turns the Finance Reviewer prototype into a reusable internal authorization core.

## Package Boundary

The core package is `internal/authz`.

It accepts an explicit actor context and returns a decision-time trace:

```go
decision, err := authz.Check(ctx, store, authz.CheckInput{
    ActorUserID:       "user_alice",
    ActorMemberID:     "member_finance_reviewer",
    ActorUserMemberID: "um_alice_finance_reviewer",
    SpaceID:           "space_acme",
    ResourceType:      "invoice",
    ResourceID:        "invoice_001",
    Action:            "approve",
})
```

`authz.Explain` currently uses the same path as `authz.Check`. Both return the full trace and persist audit logs for allows and denies.

## Store Boundary

The authorization engine depends on the `authz.Store` interface:

```go
type Store interface {
    LoadActor(ctx context.Context, actor ActorContext) (ActorSnapshot, error)
    LoadTarget(ctx context.Context, resourceType, resourceID string) (TargetSnapshot, error)
    LoadPermissionCandidates(ctx context.Context, query CandidateQuery) ([]PermissionCandidate, error)
    WriteAuditLog(ctx context.Context, decision Decision) error
}
```

The PostgreSQL implementation lives in `internal/store` and uses pgx with raw SQL. Raw SQL remains the right fit for v0.1 because the model is still being proven and the demo seed data should stay easy to read.

## Session To Actor Contract

Production applications should resolve actor context before calling Plystra:

1. Login authenticates a real User.
2. The application establishes an active Member context through a UserMember binding.
3. The request/session/token carries `user_id`, `space_id`, `member_id`, and `user_member_id`.
4. Business APIs pass that actor context to `authz.Check`.
5. Plystra returns allow/deny plus a trace.
6. Business APIs execute or reject the action.
7. Plystra writes an audit log snapshot.

The exact token or session format is intentionally deferred. The required contract is the explicit actor tuple:

```text
user_id
space_id
member_id
user_member_id
```

## Decision Semantics

Plystra evaluates matching grants with union semantics:

- resource and action must match before scope is considered
- every matching grant is included in the trace
- the decision allows if any matching grant covers the target scope
- the decision denies if no matching grant covers the target scope

UserMember state is enforced independently from role grants. A revoked or expired UserMember binding denies authorization even when the Member still has a role that would otherwise cover the target resource.

## Audit Snapshot

`audit_logs.trace` is JSONB and stores the decision context at decision time:

- User email
- Member display name
- UserMember status and relation type
- Space
- Resource and Group
- Role and Permission candidates
- Scope checks
- Decision, deny code, and reason

Historical logs should remain explainable even after live roles, groups, permissions, or bindings change later.

## Ent Evaluation

Ent is deferred for v0.1.

Reasons to keep raw SQL now:

- the schema is small and readable
- migrations are part of the demo artifact
- the authorization query shape is still stabilizing
- adopting an ORM too early would add more framework surface than product learning

Ent can be reconsidered when the Resource Registry and Console require richer schema metadata, generated queries, and relationship traversal.

## v0.1 Acceptance Status

| Requirement | Status |
|---|---|
| Authorization engine separated from CLI | done |
| Store layer separated from authorization engine | done |
| Finance Reviewer demo still runs | done |
| Four v0.1-pre demo cases still pass | done |
| Audit logs are persisted | done |
| Trace output includes matched candidates | done |
| Deny codes are machine-readable | done |
| Revoked and expired UserMember behavior is enforced | done |
| Documentation explains application integration | done |
| No Admin Console, Plugin, Template, or Cloud scope | done |

## v0.2 Notes

The core already has resolver behavior for `self`, `group`, `group_tree`, `space`, and disabled `global`. v0.2 should continue by hardening these paths with database-backed fixtures, a clearer error model, and the first small policy-layer preview.
