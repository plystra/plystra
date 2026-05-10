-- purpose: add scoped machine credentials for production server-to-server
-- access to Plystra Core without reusing user passwords.
-- affected tables: api_keys.
-- rollback strategy: revoke/export keys first, then drop api_keys and remove
-- migration record after restoring from backup.

CREATE TABLE IF NOT EXISTS api_keys (
	id character varying NOT NULL,
	name character varying NOT NULL,
	key_prefix character varying NOT NULL,
	key_hash character varying NOT NULL,
	level character varying NOT NULL,
	space_id character varying NULL,
	group_id character varying NULL,
	permission_keys jsonb NOT NULL DEFAULT '[]'::jsonb,
	status character varying NOT NULL DEFAULT 'active',
	expires_at timestamptz NULL,
	last_used_at timestamptz NULL,
	created_by_user_id character varying NULL,
	created_by_member_id character varying NULL,
	revoked_at timestamptz NULL,
	revoked_by_user_id character varying NULL,
	revoked_reason character varying NULL,
	metadata jsonb NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	deleted_at timestamptz NULL,
	PRIMARY KEY (id)
);

CREATE UNIQUE INDEX IF NOT EXISTS apikey_key_hash ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS apikey_key_prefix ON api_keys (key_prefix);
CREATE INDEX IF NOT EXISTS apikey_status ON api_keys (status);
CREATE INDEX IF NOT EXISTS apikey_level_status ON api_keys (level, status);
CREATE INDEX IF NOT EXISTS apikey_space_id ON api_keys (space_id);
CREATE INDEX IF NOT EXISTS apikey_group_id ON api_keys (group_id);
CREATE INDEX IF NOT EXISTS apikey_created_by_user_id ON api_keys (created_by_user_id);
