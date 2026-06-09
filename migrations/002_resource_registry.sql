ALTER TABLE user_members ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE resources ADD COLUMN IF NOT EXISTS display_name TEXT NULL;
ALTER TABLE resources ADD COLUMN IF NOT EXISTS visibility TEXT NOT NULL DEFAULT 'private';
ALTER TABLE resources ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE groups ADD COLUMN IF NOT EXISTS display_name TEXT NULL;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS request_id TEXT NULL;

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
