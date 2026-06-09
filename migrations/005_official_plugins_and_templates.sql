CREATE TABLE IF NOT EXISTS plugin_settings_values (
	id TEXT PRIMARY KEY,
	plugin_id TEXT NOT NULL REFERENCES plugins(id),
	space_id TEXT NOT NULL DEFAULT '',
	key TEXT NOT NULL,
	value JSONB NOT NULL,
	updated_by_user_id TEXT NULL REFERENCES users(id),
	updated_by_member_id TEXT NULL REFERENCES members(id),
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE(plugin_id, space_id, key)
);
