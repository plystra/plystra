# Audit Trace

Plystra writes audit logs for both allow and deny decisions.

Each `audit_logs.trace` value is a decision-time JSONB snapshot containing:

- actor User email and status
- active Member display name and status
- UserMember relation type, status, and expiration
- Space id and name
- target Resource, Group, owner, visibility, and metadata
- Resource Registry metadata
- every matched Role/Permission candidate
- scope anchor and scope check
- final decision, deny code, and reason
- request metadata when provided

Audit snapshots must remain explainable after live roles, bindings, groups, resources, or registry display names change later.
