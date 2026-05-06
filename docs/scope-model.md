# Scope Model

Plystra v0.2 supports four normal scopes and reserves `global`.

| Scope | Rule | Result |
|---|---|---|
| `self` | `resource.owner_member_id == actor.member_id` | allowed only for resources owned by the active Member |
| `group` | `resource.group_id == scope_anchor_group_id` | allowed only for the exact anchor Group |
| `group_tree` | target path equals anchor path or starts with `anchor_path + "."` | allowed for the anchor Group and descendants |
| `space` | `resource.space_id == actor.space_id` | allowed inside the active Space |
| `global` | disabled for normal Members | always denies with `GLOBAL_SCOPE_DISABLED` |

The `group_tree` rule is intentionally strict:

```text
target_path = anchor_path OR target_path LIKE anchor_path || '.%'
```

This avoids matching unrelated paths such as `finance-old`.
