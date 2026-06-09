INSERT INTO spaces (id, name, slug, type, status, metadata) VALUES
	('space_acme', 'Acme', 'acme-finance-reviewer-example', 'custom', 'active', '{"example": "finance-reviewer"}')
ON CONFLICT (id) DO UPDATE SET
	name = EXCLUDED.name,
	slug = EXCLUDED.slug,
	type = EXCLUDED.type,
	status = EXCLUDED.status,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO users (id, email, status, password_hash, metadata) VALUES
	('user_alice', 'alice@example.com', 'active', 'argon2id$v=19$m=65536,t=3,p=2$cGx5c3RyYS1hbGljZS12MQ$ChTdO8Md0I+wjbQpSbWY+0dkIjCUtkCEQ4taCPbznTU', '{"example": "finance-reviewer"}'),
	('user_bob', 'bob@example.com', 'active', 'argon2id$v=19$m=65536,t=3,p=2$cGx5c3RyYS1ib2ItdjEhIQ$s4mmVEjf6+Q97qeutYCUbmlbfrB+8QT/iVc0mUCTU0s', '{"example": "finance-reviewer"}')
ON CONFLICT (id) DO UPDATE SET
	email = EXCLUDED.email,
	status = EXCLUDED.status,
	password_hash = EXCLUDED.password_hash,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO groups (id, space_id, parent_group_id, name, path, depth, display_name, status, metadata) VALUES
	('group_finance', 'space_acme', NULL, 'finance', 'finance', 0, 'Finance', 'active', '{"example": "finance-reviewer"}'),
	('group_finance_apac', 'space_acme', 'group_finance', 'apac', 'finance.apac', 1, 'APAC', 'active', '{"example": "finance-reviewer"}'),
	('group_finance_emea', 'space_acme', 'group_finance', 'emea', 'finance.emea', 1, 'EMEA', 'active', '{"example": "finance-reviewer"}'),
	('group_legal', 'space_acme', NULL, 'legal', 'legal', 0, 'Legal', 'active', '{"example": "finance-reviewer"}'),
	('group_legal_emea', 'space_acme', 'group_legal', 'emea', 'legal.emea', 1, 'EMEA', 'active', '{"example": "finance-reviewer"}')
ON CONFLICT (id) DO UPDATE SET
	space_id = EXCLUDED.space_id,
	parent_group_id = EXCLUDED.parent_group_id,
	name = EXCLUDED.name,
	path = EXCLUDED.path,
	depth = EXCLUDED.depth,
	display_name = EXCLUDED.display_name,
	status = EXCLUDED.status,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO members (id, space_id, display_name, member_type, status, metadata) VALUES
	('member_finance_reviewer', 'space_acme', 'Finance Reviewer', 'human', 'active', '{"example": "finance-reviewer"}'),
	('member_invoice_creator', 'space_acme', 'APAC Invoice Creator', 'human', 'active', '{"example": "finance-reviewer"}')
ON CONFLICT (id) DO UPDATE SET
	space_id = EXCLUDED.space_id,
	display_name = EXCLUDED.display_name,
	member_type = EXCLUDED.member_type,
	status = EXCLUDED.status,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO user_members (id, user_id, member_id, space_id, relation_type, status, is_primary, expires_at, revoked_at, metadata) VALUES
	('um_alice_finance_reviewer', 'user_alice', 'member_finance_reviewer', 'space_acme', 'delegate', 'active', true, NULL, NULL, '{"example": "finance-reviewer"}'),
	('um_bob_finance_reviewer', 'user_bob', 'member_finance_reviewer', 'space_acme', 'login', 'active', true, NULL, NULL, '{"example": "finance-reviewer"}'),
	('um_alice_finance_reviewer_revoked', 'user_alice', 'member_finance_reviewer', 'space_acme', 'delegate', 'revoked', false, NULL, now(), '{"example": "finance-reviewer"}'),
	('um_alice_finance_reviewer_expired', 'user_alice', 'member_finance_reviewer', 'space_acme', 'temporary', 'active', false, '2020-01-01T00:00:00Z', NULL, '{"example": "finance-reviewer"}')
ON CONFLICT (id) DO UPDATE SET
	user_id = EXCLUDED.user_id,
	member_id = EXCLUDED.member_id,
	space_id = EXCLUDED.space_id,
	relation_type = EXCLUDED.relation_type,
	status = EXCLUDED.status,
	is_primary = EXCLUDED.is_primary,
	expires_at = EXCLUDED.expires_at,
	revoked_at = EXCLUDED.revoked_at,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO roles (id, space_id, key, name, status, metadata) VALUES
	('role_finance_approver', 'space_acme', 'finance_approver', 'Finance Approver', 'active', '{"example": "finance-reviewer"}')
ON CONFLICT (id) DO UPDATE SET
	space_id = EXCLUDED.space_id,
	key = EXCLUDED.key,
	name = EXCLUDED.name,
	status = EXCLUDED.status,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO resource_types (id, key, display_name, description, status, source, metadata) VALUES
	('rt_invoice', 'invoice', 'Invoice', 'Example invoice requiring approval or rejection.', 'active', 'example:finance-reviewer', '{"example": "finance-reviewer"}')
ON CONFLICT (key) DO UPDATE SET
	display_name = EXCLUDED.display_name,
	description = EXCLUDED.description,
	status = EXCLUDED.status,
	source = EXCLUDED.source,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO resource_actions (id, resource_type_id, key, display_name, description, risk_level, audit_default, metadata) VALUES
	('ra_invoice_read', 'rt_invoice', 'read', 'Read', 'Read invoice details.', 'low', true, '{}'),
	('ra_invoice_create', 'rt_invoice', 'create', 'Create', 'Create a new invoice.', 'normal', true, '{}'),
	('ra_invoice_approve', 'rt_invoice', 'approve', 'Approve', 'Approve an invoice.', 'high', true, '{}'),
	('ra_invoice_reject', 'rt_invoice', 'reject', 'Reject', 'Reject an invoice.', 'high', true, '{}'),
	('ra_invoice_update', 'rt_invoice', 'update', 'Update', 'Update invoice fields.', 'normal', true, '{}'),
	('ra_invoice_delete', 'rt_invoice', 'delete', 'Delete', 'Delete an invoice.', 'critical', true, '{}')
ON CONFLICT (resource_type_id, key) DO UPDATE SET
	display_name = EXCLUDED.display_name,
	description = EXCLUDED.description,
	risk_level = EXCLUDED.risk_level,
	audit_default = EXCLUDED.audit_default,
	metadata = EXCLUDED.metadata,
	updated_at = now();

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
	status,
	metadata
) VALUES (
	'rm_invoice_resources',
	'rt_invoice',
	'internal_table',
	'resources',
	'id',
	'space_id',
	'group_id',
	'owner_member_id',
	'visibility',
	'metadata',
	'active',
	'{"example": "finance-reviewer"}'
)
ON CONFLICT (resource_type_id) DO UPDATE SET
	storage_kind = EXCLUDED.storage_kind,
	table_name = EXCLUDED.table_name,
	id_field = EXCLUDED.id_field,
	space_field = EXCLUDED.space_field,
	group_field = EXCLUDED.group_field,
	owner_member_field = EXCLUDED.owner_member_field,
	visibility_field = EXCLUDED.visibility_field,
	metadata_field = EXCLUDED.metadata_field,
	status = EXCLUDED.status,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO permissions (id, resource, action, scope, status, metadata) VALUES
	('perm_invoice_approve_group_tree', 'invoice', 'approve', 'group_tree', 'active', '{"example": "finance-reviewer"}'),
	('perm_invoice_read_self', 'invoice', 'read', 'self', 'active', '{"example": "finance-reviewer"}'),
	('perm_invoice_read_group_tree', 'invoice', 'read', 'group_tree', 'active', '{"example": "finance-reviewer"}'),
	('perm_invoice_create_group_tree', 'invoice', 'create', 'group_tree', 'active', '{"example": "finance-reviewer"}'),
	('perm_invoice_reject_group_tree', 'invoice', 'reject', 'group_tree', 'active', '{"example": "finance-reviewer"}'),
	('perm_invoice_update_group_tree', 'invoice', 'update', 'group_tree', 'active', '{"example": "finance-reviewer"}'),
	('perm_invoice_delete_group_tree', 'invoice', 'delete', 'group_tree', 'active', '{"example": "finance-reviewer"}'),
	('perm_invoice_delete_space', 'invoice', 'delete', 'space', 'active', '{"example": "finance-reviewer"}')
ON CONFLICT (id) DO UPDATE SET
	resource = EXCLUDED.resource,
	action = EXCLUDED.action,
	scope = EXCLUDED.scope,
	status = EXCLUDED.status,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO member_roles (id, member_id, role_id, space_id, scope_anchor_group_id, status, metadata) VALUES
	('mr_finance_reviewer_approver_finance', 'member_finance_reviewer', 'role_finance_approver', 'space_acme', 'group_finance', 'active', '{"example": "finance-reviewer"}')
ON CONFLICT (id) DO UPDATE SET
	member_id = EXCLUDED.member_id,
	role_id = EXCLUDED.role_id,
	space_id = EXCLUDED.space_id,
	scope_anchor_group_id = EXCLUDED.scope_anchor_group_id,
	status = EXCLUDED.status,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO role_permissions (id, role_id, permission_id, metadata) VALUES
	('rp_finance_approver_invoice_approve_group_tree', 'role_finance_approver', 'perm_invoice_approve_group_tree', '{"example": "finance-reviewer"}'),
	('rp_finance_approver_invoice_read_group_tree', 'role_finance_approver', 'perm_invoice_read_group_tree', '{"example": "finance-reviewer"}'),
	('rp_finance_approver_invoice_create_group_tree', 'role_finance_approver', 'perm_invoice_create_group_tree', '{"example": "finance-reviewer"}'),
	('rp_finance_approver_invoice_update_group_tree', 'role_finance_approver', 'perm_invoice_update_group_tree', '{"example": "finance-reviewer"}'),
	('rp_finance_approver_invoice_delete_group_tree', 'role_finance_approver', 'perm_invoice_delete_group_tree', '{"example": "finance-reviewer"}')
ON CONFLICT (role_id, permission_id) DO UPDATE SET
	id = EXCLUDED.id,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO resources (id, resource_type, space_id, group_id, owner_member_id, metadata, display_name, visibility, status) VALUES
	('invoice_001', 'invoice', 'space_acme', 'group_finance_apac', 'member_invoice_creator', '{"number": "INV-001", "region": "APAC"}', 'APAC Invoice INV-001', 'private', 'active'),
	('invoice_002', 'invoice', 'space_acme', 'group_legal_emea', 'member_invoice_creator', '{"number": "INV-002", "region": "EMEA"}', 'Legal EMEA Invoice INV-002', 'private', 'active')
ON CONFLICT (id) DO UPDATE SET
	resource_type = EXCLUDED.resource_type,
	space_id = EXCLUDED.space_id,
	group_id = EXCLUDED.group_id,
	owner_member_id = EXCLUDED.owner_member_id,
	metadata = EXCLUDED.metadata,
	display_name = EXCLUDED.display_name,
	visibility = EXCLUDED.visibility,
	status = EXCLUDED.status,
	updated_at = now();
