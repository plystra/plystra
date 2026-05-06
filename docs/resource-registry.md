# Resource Registry

Resource Registry turns permission strings into governed resource metadata.

Instead of treating `invoice:approve:group_tree` as only text, Plystra records:

- what `invoice` is
- which actions belong to `invoice`
- which action risk level should appear in traces
- how invoice instances map to `space_id`, `group_id`, `owner_member_id`, and visibility
- whether allow and deny decisions should be audited

## v0.3 Tables

`resource_types` stores registered resource kinds such as `invoice`.

`resource_actions` stores allowed actions such as `read`, `create`, `update`, `approve`, `reject`, and `delete`.

`resource_mappings` describes how resource rows expose authorization fields. v0.3 supports the internal `resources` table mapping:

```text
id_field = id
space_field = space_id
group_field = group_id
owner_member_field = owner_member_id
visibility_field = visibility
metadata_field = metadata
```

## Authorization Integration

Before evaluating permissions, the authorization engine validates that:

1. the requested ResourceType is registered
2. the requested action exists for that ResourceType
3. a ResourceMapping exists

Unknown resource types deny with:

```text
INVALID_RESOURCE_TYPE
```

Unknown actions deny with:

```text
INVALID_RESOURCE_ACTION
```

The decision trace includes a `resource_registry` snapshot. Audit logs keep this snapshot, so historical traces remain readable even if the display name or risk level changes later.

## Invoice Demo Registry

The demo migration registers:

```text
ResourceType: invoice
Actions: read, create, approve, reject, delete
Mapping: resources table
```

`approve` and `reject` are high-risk actions. `delete` is critical.

## Deferred

v0.3 does not implement Plugin API, Data Console, external table mapping, dynamic SQL from registry metadata, or automatic permission grants.
