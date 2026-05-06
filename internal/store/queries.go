package store

const loadActorSQL = `
SELECT
	u.id, u.email, u.status,
	um.id, um.user_id, um.member_id, um.space_id, um.relation_type, um.status, um.is_primary, um.expires_at,
	m.id, m.space_id, m.display_name, m.status,
	s.id, s.name, s.status
FROM users u, user_members um, members m, spaces s
WHERE u.id = $1
	AND um.id = $2
	AND m.id = $3
	AND s.id = $4
`

const loadTargetSQL = `
SELECT
	r.id, r.resource_type, r.space_id, COALESCE(r.group_id, ''), COALESCE(r.owner_member_id, ''), r.metadata,
	g.id, g.space_id, g.path, g.status
FROM resources r
LEFT JOIN groups g ON g.id = r.group_id
WHERE r.resource_type = $1
	AND r.id = $2
`

const loadCandidatesSQL = `
SELECT
	r.id, r.key, r.space_id,
	p.id, p.resource, p.action, p.scope,
	mr.space_id,
	g.id, g.space_id, g.path, g.status
FROM member_roles mr
JOIN roles r ON r.id = mr.role_id
JOIN role_permissions rp ON rp.role_id = r.id
JOIN permissions p ON p.id = rp.permission_id
LEFT JOIN groups g ON g.id = mr.scope_anchor_group_id
WHERE mr.member_id = $1
	AND p.resource = $2
	AND p.action = $3
ORDER BY r.key, p.resource, p.action, p.scope
`

const insertAuditLogSQL = `
INSERT INTO audit_logs (
	id,
	space_id,
	actor_user_id,
	actor_member_id,
	actor_user_member_id,
	action,
	resource_type,
	resource_id,
	decision,
	deny_code,
	trace
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)
`
