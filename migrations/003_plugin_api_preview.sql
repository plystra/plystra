CREATE TABLE IF NOT EXISTS plugins (
	id TEXT PRIMARY KEY,
	key TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL,
	description TEXT NULL,
	version TEXT NOT NULL,
	source TEXT NOT NULL DEFAULT 'official',
	status TEXT NOT NULL DEFAULT 'installed',
	manifest JSONB NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS plugin_admin_menus (
	id TEXT PRIMARY KEY,
	plugin_id TEXT NOT NULL REFERENCES plugins(id),
	label TEXT NOT NULL,
	path TEXT NOT NULL,
	icon TEXT NULL,
	required_permission TEXT NULL,
	sort_order INT NOT NULL DEFAULT 1000,
	metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS plugin_settings_definitions (
	id TEXT PRIMARY KEY,
	plugin_id TEXT NOT NULL REFERENCES plugins(id),
	key TEXT NOT NULL,
	value_type TEXT NOT NULL,
	default_value JSONB NULL,
	description TEXT NULL,
	scope TEXT NOT NULL DEFAULT 'space',
	metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE(plugin_id, key, scope)
);

CREATE TABLE IF NOT EXISTS audit_event_types (
	id TEXT PRIMARY KEY,
	key TEXT NOT NULL UNIQUE,
	plugin_id TEXT NULL REFERENCES plugins(id),
	display_name TEXT NOT NULL,
	description TEXT NULL,
	risk_level TEXT NOT NULL DEFAULT 'normal',
	default_audit BOOLEAN NOT NULL DEFAULT true,
	metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
