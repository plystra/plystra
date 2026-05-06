-- purpose: align the v1.0 database with the Ent integration guidelines.
-- affected tables: users, spaces, groups, members, user_members, roles, permissions,
-- member_roles, role_permissions, resources, audit_logs.
-- rollback strategy: additive columns/indexes/triggers are reversible by dropping the
-- named triggers, functions, indexes, and columns; role_permissions primary-key
-- migration is irreversible without restoring the previous composite primary key.
-- data compatibility: existing rows receive deterministic role_permission IDs and
-- nullable deleted_at values.
-- plugin compatibility: plugin-owned schema extension remains deferred; plugins
-- continue referencing Core entities by stable public IDs only.

ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

ALTER TABLE spaces ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE spaces ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

ALTER TABLE groups ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE groups ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

ALTER TABLE members ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE members ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

ALTER TABLE user_members ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

ALTER TABLE roles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE roles ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

ALTER TABLE permissions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

ALTER TABLE member_roles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE member_roles ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

ALTER TABLE role_permissions ADD COLUMN IF NOT EXISTS id TEXT;
ALTER TABLE role_permissions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE role_permissions ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

UPDATE role_permissions
SET id = 'rp_' || md5(role_id || ':' || permission_id)
WHERE id IS NULL OR id = '';

ALTER TABLE role_permissions ALTER COLUMN id SET NOT NULL;

DO $$
DECLARE
	current_pk TEXT;
BEGIN
	SELECT c.conname INTO current_pk
	FROM pg_constraint c
	WHERE c.conrelid = 'role_permissions'::regclass
		AND c.contype = 'p'
		AND NOT EXISTS (
			SELECT 1
			FROM unnest(c.conkey) AS key(attnum)
			JOIN pg_attribute a
				ON a.attrelid = c.conrelid
				AND a.attnum = key.attnum
			WHERE a.attname = 'id'
		);

	IF current_pk IS NOT NULL THEN
		EXECUTE format('ALTER TABLE role_permissions DROP CONSTRAINT %I', current_pk);
	END IF;

	IF NOT EXISTS (
		SELECT 1
		FROM pg_constraint
		WHERE conrelid = 'role_permissions'::regclass
			AND contype = 'p'
	) THEN
		ALTER TABLE role_permissions ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (id);
	END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS role_permissions_role_id_permission_id_key
	ON role_permissions(role_id, permission_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id
	ON role_permissions(permission_id);

ALTER TABLE resources ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_user_members_user_id ON user_members(user_id);
CREATE INDEX IF NOT EXISTS idx_user_members_member_id ON user_members(member_id);
CREATE INDEX IF NOT EXISTS idx_user_members_space_id ON user_members(space_id);
CREATE INDEX IF NOT EXISTS idx_user_members_status ON user_members(status);
CREATE INDEX IF NOT EXISTS idx_user_members_expires_at ON user_members(expires_at);

CREATE INDEX IF NOT EXISTS idx_member_roles_space_id ON member_roles(space_id);
CREATE INDEX IF NOT EXISTS idx_member_roles_member_id ON member_roles(member_id);
CREATE INDEX IF NOT EXISTS idx_member_roles_role_id ON member_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_member_roles_scope_anchor_group_id ON member_roles(scope_anchor_group_id);

CREATE INDEX IF NOT EXISTS idx_resources_space_id ON resources(space_id);
CREATE INDEX IF NOT EXISTS idx_resources_resource_type ON resources(resource_type);
CREATE INDEX IF NOT EXISTS idx_resources_group_id ON resources(group_id);
CREATE INDEX IF NOT EXISTS idx_resources_owner_member_id ON resources(owner_member_id);
CREATE INDEX IF NOT EXISTS idx_resources_space_type ON resources(space_id, resource_type);
CREATE INDEX IF NOT EXISTS idx_resources_space_type_group ON resources(space_id, resource_type, group_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_space_created_at ON audit_logs(space_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_user_id ON audit_logs(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_member_id ON audit_logs(actor_member_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_user_member_id ON audit_logs(actor_user_member_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_decision ON audit_logs(decision);
CREATE INDEX IF NOT EXISTS idx_audit_logs_deny_code ON audit_logs(deny_code);

CREATE OR REPLACE FUNCTION plystra_enforce_user_member_same_space()
RETURNS trigger AS $$
DECLARE
	member_space TEXT;
BEGIN
	SELECT space_id INTO member_space FROM members WHERE id = NEW.member_id;
	IF member_space IS NULL OR member_space <> NEW.space_id THEN
		RAISE EXCEPTION 'user_members.member_id must belong to user_members.space_id';
	END IF;
	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_user_members_same_space ON user_members;
CREATE TRIGGER trg_user_members_same_space
BEFORE INSERT OR UPDATE OF member_id, space_id
ON user_members
FOR EACH ROW
EXECUTE FUNCTION plystra_enforce_user_member_same_space();

CREATE OR REPLACE FUNCTION plystra_enforce_member_role_same_space()
RETURNS trigger AS $$
DECLARE
	member_space TEXT;
	role_space TEXT;
	anchor_space TEXT;
BEGIN
	SELECT space_id INTO member_space FROM members WHERE id = NEW.member_id;
	SELECT space_id INTO role_space FROM roles WHERE id = NEW.role_id;

	IF member_space IS NULL OR member_space <> NEW.space_id THEN
		RAISE EXCEPTION 'member_roles.member_id must belong to member_roles.space_id';
	END IF;
	IF role_space IS NULL OR role_space <> NEW.space_id THEN
		RAISE EXCEPTION 'member_roles.role_id must belong to member_roles.space_id';
	END IF;

	IF NEW.scope_anchor_group_id IS NOT NULL THEN
		SELECT space_id INTO anchor_space FROM groups WHERE id = NEW.scope_anchor_group_id;
		IF anchor_space IS NULL OR anchor_space <> NEW.space_id THEN
			RAISE EXCEPTION 'member_roles.scope_anchor_group_id must belong to member_roles.space_id';
		END IF;
	END IF;

	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_member_roles_same_space ON member_roles;
CREATE TRIGGER trg_member_roles_same_space
BEFORE INSERT OR UPDATE OF member_id, role_id, space_id, scope_anchor_group_id
ON member_roles
FOR EACH ROW
EXECUTE FUNCTION plystra_enforce_member_role_same_space();

CREATE OR REPLACE FUNCTION plystra_enforce_resource_same_space()
RETURNS trigger AS $$
DECLARE
	group_space TEXT;
	owner_space TEXT;
BEGIN
	IF NEW.group_id IS NOT NULL THEN
		SELECT space_id INTO group_space FROM groups WHERE id = NEW.group_id;
		IF group_space IS NULL OR group_space <> NEW.space_id THEN
			RAISE EXCEPTION 'resources.group_id must belong to resources.space_id';
		END IF;
	END IF;

	IF NEW.owner_member_id IS NOT NULL THEN
		SELECT space_id INTO owner_space FROM members WHERE id = NEW.owner_member_id;
		IF owner_space IS NULL OR owner_space <> NEW.space_id THEN
			RAISE EXCEPTION 'resources.owner_member_id must belong to resources.space_id';
		END IF;
	END IF;

	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_resources_same_space ON resources;
CREATE TRIGGER trg_resources_same_space
BEFORE INSERT OR UPDATE OF space_id, group_id, owner_member_id
ON resources
FOR EACH ROW
EXECUTE FUNCTION plystra_enforce_resource_same_space();
