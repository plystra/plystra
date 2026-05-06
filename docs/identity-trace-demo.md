# Identity Trace Demo

The v0.1-pre demo proves Plystra's core actor model:

```text
User -> UserMember -> Member -> Space
```

The demo uses an Acme finance approval scenario. A Finance Reviewer Member has the `finance_approver` role, which grants `invoice:approve:group_tree` from the `finance` group anchor.

## Demo Cases

| Case | Actor | Target | Decision |
|---|---|---|---|
| 1 | Alice via Finance Reviewer | Finance / APAC invoice | `allow` |
| 2 | Alice via Finance Reviewer | Legal / EMEA invoice | `deny: SCOPE_OUT_OF_BOUNDS` |
| 3 | Bob via the same Finance Reviewer | Finance / APAC invoice | `allow` |
| 4 | Alice via revoked UserMember | Finance / APAC invoice | `deny: USER_MEMBER_REVOKED` |

Case 3 proves that multiple Users can act through the same in-space Member while audit logs still preserve the real login account. Case 4 proves that UserMember is an active authorization bridge, not a redundant join table.

## Scope Matrix

| Scope | Meaning | Required target field | Required grant anchor | v0.1 behavior |
|---|---|---|---|---|
| `self` | resource owned by active Member | `owner_member_id` | none | implemented |
| `group` | resource directly belongs to anchored Group | `group_id` | `scope_anchor_group_id` | implemented |
| `group_tree` | resource belongs to anchor Group or descendant | `group_id` | `scope_anchor_group_id` | implemented |
| `space` | resource belongs to active Space | `space_id` | none | implemented |
| `global` | system-level scope outside normal Space boundaries | none | none | disabled |

`group_tree` uses the safe materialized-path rule:

```sql
target_path = anchor_path
OR target_path LIKE anchor_path || '.%'
```

It intentionally does not use `target_path LIKE anchor_path || '%'`, because that could match unrelated paths such as `finance-old`.

## Authorization Flow

1. Load actor context.
2. Load target resource.
3. Load permission grants matching resource and action.
4. Resolve scope for every matched grant.
5. Validate User, Member, UserMember, Space, and expiration state.
6. Validate same-space invariants.
7. Apply union semantics: allow if any matched grant covers the target.
8. Build a decision-time trace snapshot.
9. Persist an audit log for both allows and denies.

## Deny Codes

```text
ACTOR_USER_INACTIVE
ACTOR_MEMBER_INACTIVE
USER_MEMBER_REVOKED
USER_MEMBER_EXPIRED
SPACE_INACTIVE
CROSS_SPACE_VIOLATION
NO_MATCHING_PERMISSION
SCOPE_ANCHOR_MISSING
TARGET_GROUP_MISSING
SCOPE_OUT_OF_BOUNDS
GLOBAL_SCOPE_DISABLED
```

## Security Invariants

1. A User does not directly own permissions inside a Space.
2. A protected action must be performed through an active Member context.
3. A User can act as a Member only through an active UserMember binding.
4. UserMember, Member, Role, Resource, and actor context must refer to the same Space.
5. A Member cannot act across Space boundaries in v0.1.
6. A revoked or expired UserMember binding always denies authorization.
7. Permissions are evaluated after resource and action matching.
8. Scope resolution never widens beyond the matched permission grant.
9. Audit traces record `actor_user_id`, `actor_member_id`, `actor_user_member_id`, and `space_id`.
10. Audit traces snapshot the decision context at decision time.

## Non-goals

v0.1-pre and v0.1 do not include a login system, HTTP API, Admin Console, Data Console, plugin runtime, template system, hosted cloud, billing, marketplace, or Ent migration.
