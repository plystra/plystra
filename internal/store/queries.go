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
	AND u.deleted_at IS NULL
	AND um.deleted_at IS NULL
	AND m.deleted_at IS NULL
	AND s.deleted_at IS NULL
`

const loadTargetSQL = `
SELECT
	r.id, r.resource_type, r.space_id, COALESCE(r.group_id, ''), COALESCE(r.owner_member_id, ''),
	COALESCE(r.display_name, ''), COALESCE(r.visibility, ''), COALESCE(r.status, ''), r.metadata,
	g.id, g.space_id, g.path, g.status
FROM resources r
LEFT JOIN groups g ON g.id = r.group_id AND g.deleted_at IS NULL
WHERE r.resource_type = $1
	AND r.id = $2
	AND r.deleted_at IS NULL
`

const loadResourceRegistrationSQL = `
SELECT
	rt.id, rt.key, rt.display_name, COALESCE(rt.description, ''), rt.status, rt.source, rt.metadata,
	ra.id, ra.resource_type_id, ra.key, ra.display_name, COALESCE(ra.description, ''), ra.risk_level, ra.audit_default, ra.metadata,
	rm.id, rm.resource_type_id, rm.storage_kind, COALESCE(rm.table_name, ''), rm.id_field, rm.space_field,
	COALESCE(rm.group_field, ''), COALESCE(rm.owner_member_field, ''), COALESCE(rm.visibility_field, ''),
	COALESCE(rm.metadata_field, ''), rm.status, rm.metadata
FROM resource_types rt
JOIN resource_actions ra ON ra.resource_type_id = rt.id
JOIN resource_mappings rm ON rm.resource_type_id = rt.id
WHERE rt.key = $1
	AND ra.key = $2
`

const resourceTypeExistsSQL = `
SELECT EXISTS (SELECT 1 FROM resource_types WHERE key = $1)
`

const upsertResourceTypeSQL = `
INSERT INTO resource_types (id, key, display_name, description, source, metadata)
VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6::jsonb)
ON CONFLICT (key) DO UPDATE SET
	display_name = EXCLUDED.display_name,
	description = EXCLUDED.description,
	source = EXCLUDED.source,
	metadata = EXCLUDED.metadata,
	updated_at = now()
RETURNING id, key, display_name, COALESCE(description, ''), status, source, metadata
`

const upsertResourceActionSQL = `
WITH rt AS (
	SELECT id FROM resource_types WHERE key = $1
)
INSERT INTO resource_actions (id, resource_type_id, key, display_name, description, risk_level, audit_default, metadata)
SELECT $2, rt.id, $3, $4, NULLIF($5, ''), $6, $7, $8::jsonb
FROM rt
ON CONFLICT (resource_type_id, key) DO UPDATE SET
	display_name = EXCLUDED.display_name,
	description = EXCLUDED.description,
	risk_level = EXCLUDED.risk_level,
	audit_default = EXCLUDED.audit_default,
	metadata = EXCLUDED.metadata,
	updated_at = now()
RETURNING id, resource_type_id, key, display_name, COALESCE(description, ''), risk_level, audit_default, metadata
`

const upsertResourceMappingSQL = `
WITH rt AS (
	SELECT id FROM resource_types WHERE key = $1
)
INSERT INTO resource_mappings (
	id,
	resource_type_id,
	storage_kind,
	table_name,
	id_field,
	space_field,
	group_field,
	owner_member_field,
	visibility_field,
	metadata_field,
	metadata
)
SELECT $2, rt.id, $3, NULLIF($4, ''), $5, $6, NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), NULLIF($10, ''), $11::jsonb
FROM rt
ON CONFLICT (resource_type_id) DO UPDATE SET
	storage_kind = EXCLUDED.storage_kind,
	table_name = EXCLUDED.table_name,
	id_field = EXCLUDED.id_field,
	space_field = EXCLUDED.space_field,
	group_field = EXCLUDED.group_field,
	owner_member_field = EXCLUDED.owner_member_field,
	visibility_field = EXCLUDED.visibility_field,
	metadata_field = EXCLUDED.metadata_field,
	metadata = EXCLUDED.metadata,
	updated_at = now()
RETURNING
	id, resource_type_id, storage_kind, COALESCE(table_name, ''), id_field, space_field,
	COALESCE(group_field, ''), COALESCE(owner_member_field, ''), COALESCE(visibility_field, ''),
	COALESCE(metadata_field, ''), status, metadata
`

const getResourceTypeSQL = `
SELECT id, key, display_name, COALESCE(description, ''), status, source, metadata
FROM resource_types
WHERE key = $1
`

const listResourceActionsSQL = `
SELECT ra.id, ra.resource_type_id, ra.key, ra.display_name, COALESCE(ra.description, ''), ra.risk_level, ra.audit_default, ra.metadata
FROM resource_actions ra
JOIN resource_types rt ON rt.id = ra.resource_type_id
WHERE rt.key = $1
ORDER BY ra.key
`

const getResourceMappingSQL = `
SELECT
	rm.id, rm.resource_type_id, rm.storage_kind, COALESCE(rm.table_name, ''), rm.id_field, rm.space_field,
	COALESCE(rm.group_field, ''), COALESCE(rm.owner_member_field, ''), COALESCE(rm.visibility_field, ''),
	COALESCE(rm.metadata_field, ''), rm.status, rm.metadata
FROM resource_mappings rm
JOIN resource_types rt ON rt.id = rm.resource_type_id
WHERE rt.key = $1
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
LEFT JOIN groups g ON g.id = mr.scope_anchor_group_id AND g.deleted_at IS NULL
WHERE mr.member_id = $1
	AND p.resource = $2
	AND p.action = $3
	AND mr.status = 'active'
	AND mr.deleted_at IS NULL
	AND r.status = 'active'
	AND r.deleted_at IS NULL
	AND rp.deleted_at IS NULL
	AND p.status = 'active'
	AND p.deleted_at IS NULL
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
	trace,
	request_id,
	ip_address,
	user_agent
) VALUES (
	$1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''), $6, $7, $8, $9, $10, $11, NULLIF($12, ''), NULLIF($13, ''), NULLIF($14, '')
)
`
