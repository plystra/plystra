ALTER TABLE user_members ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE resources ADD COLUMN IF NOT EXISTS display_name TEXT NULL;
ALTER TABLE resources ADD COLUMN IF NOT EXISTS visibility TEXT NOT NULL DEFAULT 'private';
ALTER TABLE resources ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE groups ADD COLUMN IF NOT EXISTS display_name TEXT NULL;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS request_id TEXT NULL;

UPDATE groups SET display_name = 'Finance' WHERE id = 'group_finance' AND display_name IS NULL;
UPDATE groups SET display_name = 'APAC' WHERE id = 'group_finance_apac' AND display_name IS NULL;
UPDATE groups SET display_name = 'EMEA' WHERE id = 'group_finance_emea' AND display_name IS NULL;
UPDATE groups SET display_name = 'Legal' WHERE id = 'group_legal' AND display_name IS NULL;
UPDATE groups SET display_name = 'EMEA' WHERE id = 'group_legal_emea' AND display_name IS NULL;

UPDATE resources SET display_name = 'APAC Invoice INV-001', visibility = 'private' WHERE id = 'invoice_001';
UPDATE resources SET display_name = 'Legal EMEA Invoice INV-002', visibility = 'private' WHERE id = 'invoice_002';

CREATE TABLE IF NOT EXISTS resource_types (
	id TEXT PRIMARY KEY,
	key TEXT NOT NULL UNIQUE,
	display_name TEXT NOT NULL,
	description TEXT NULL,
	status TEXT NOT NULL DEFAULT 'active',
	source TEXT NOT NULL DEFAULT 'core',
	metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS resource_actions (
	id TEXT PRIMARY KEY,
	resource_type_id TEXT NOT NULL REFERENCES resource_types(id),
	key TEXT NOT NULL,
	display_name TEXT NOT NULL,
	description TEXT NULL,
	risk_level TEXT NOT NULL DEFAULT 'normal',
	audit_default BOOLEAN NOT NULL DEFAULT true,
	metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE(resource_type_id, key)
);

CREATE TABLE IF NOT EXISTS resource_mappings (
	id TEXT PRIMARY KEY,
	resource_type_id TEXT NOT NULL REFERENCES resource_types(id),
	storage_kind TEXT NOT NULL DEFAULT 'internal_table',
	table_name TEXT NULL,
	id_field TEXT NOT NULL DEFAULT 'id',
	space_field TEXT NOT NULL DEFAULT 'space_id',
	group_field TEXT NULL DEFAULT 'group_id',
	owner_member_field TEXT NULL DEFAULT 'owner_member_id',
	visibility_field TEXT NULL DEFAULT 'visibility',
	metadata_field TEXT NULL DEFAULT 'metadata',
	status TEXT NOT NULL DEFAULT 'active',
	metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE(resource_type_id)
);

INSERT INTO resource_types (id, key, display_name, description, status, source, metadata) VALUES
	('rt_invoice', 'invoice', 'Invoice', 'Financial invoice requiring approval or rejection.', 'active', 'core', '{"demo": true}')
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
	'{"demo": true}'
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

INSERT INTO permissions (id, resource, action, scope) VALUES
	('perm_invoice_read_self', 'invoice', 'read', 'self'),
	('perm_invoice_read_group_tree', 'invoice', 'read', 'group_tree'),
	('perm_invoice_create_group_tree', 'invoice', 'create', 'group_tree'),
	('perm_invoice_reject_group_tree', 'invoice', 'reject', 'group_tree'),
	('perm_invoice_delete_space', 'invoice', 'delete', 'space')
ON CONFLICT (id) DO UPDATE SET
	resource = EXCLUDED.resource,
	action = EXCLUDED.action,
	scope = EXCLUDED.scope;

INSERT INTO user_members (id, user_id, member_id, space_id, relation_type, status, is_primary, expires_at) VALUES
	('um_alice_finance_reviewer_expired', 'user_alice', 'member_finance_reviewer', 'space_acme', 'temporary', 'active', false, '2020-01-01T00:00:00Z')
ON CONFLICT (id) DO UPDATE SET
	user_id = EXCLUDED.user_id,
	member_id = EXCLUDED.member_id,
	space_id = EXCLUDED.space_id,
	relation_type = EXCLUDED.relation_type,
	status = EXCLUDED.status,
	is_primary = EXCLUDED.is_primary,
	expires_at = EXCLUDED.expires_at,
	updated_at = now();
