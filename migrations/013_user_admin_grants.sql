-- purpose: add user/session-backed admin grant storage for Core management
-- authorization.
-- affected tables: admin_grants.
-- rollback strategy: restore from backup before applying this control-plane
-- authorization migration.

CREATE TABLE IF NOT EXISTS admin_grants (
	id character varying NOT NULL,
	user_id character varying NOT NULL,
	member_id character varying NULL,
	space_id character varying NULL,
	group_id character varying NULL,
	level character varying NOT NULL,
	permission_key character varying NOT NULL,
	status character varying NOT NULL DEFAULT 'active',
	granted_by_user_id character varying NULL,
	granted_by_member_id character varying NULL,
	expires_at timestamptz NULL,
	revoked_at timestamptz NULL,
	revoked_reason character varying NULL,
	metadata jsonb NULL DEFAULT '{}'::jsonb,
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now(),
	deleted_at timestamptz NULL,
	PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS admingrant_user_id ON admin_grants (user_id);
CREATE INDEX IF NOT EXISTS admingrant_user_id_status ON admin_grants (user_id, status);
CREATE INDEX IF NOT EXISTS admingrant_level_status ON admin_grants (level, status);
CREATE INDEX IF NOT EXISTS admingrant_space_id ON admin_grants (space_id);
CREATE INDEX IF NOT EXISTS admingrant_group_id ON admin_grants (group_id);
CREATE INDEX IF NOT EXISTS admingrant_permission_key ON admin_grants (permission_key);
