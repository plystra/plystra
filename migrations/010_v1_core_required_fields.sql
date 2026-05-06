-- purpose: complete the v1.0 Core entity fields required by the stable self-hosted PRD.
-- affected tables: users, spaces, groups, members, user_members, roles,
-- permissions, member_roles, role_permissions, resources, audit_logs.
-- rollback strategy: additive columns and indexes can be dropped; audit actor
-- nullable changes can be reversed only after backfilling non-null actor values.
-- data compatibility: existing rows are backfilled from stable public IDs,
-- display names, paths, keys, or safe v1.0 defaults.
-- plugin compatibility: plugin-owned schemas remain external; plugins continue
-- referencing Core entities through public IDs and public APIs only.

ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE spaces ADD COLUMN IF NOT EXISTS slug TEXT NULL;
ALTER TABLE spaces ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'custom';
ALTER TABLE spaces ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

UPDATE spaces
SET slug = regexp_replace(lower(name), '[^a-z0-9]+', '-', 'g')
WHERE slug IS NULL OR slug = '';

CREATE UNIQUE INDEX IF NOT EXISTS spaces_slug_key
	ON spaces(slug)
	WHERE slug IS NOT NULL AND slug <> '';

ALTER TABLE groups ADD COLUMN IF NOT EXISTS name TEXT;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS depth INT NOT NULL DEFAULT 0;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS sort_order INT NOT NULL DEFAULT 1000;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

UPDATE groups
SET name = COALESCE(NULLIF(display_name, ''), regexp_replace(path, '^.*\.', ''))
WHERE name IS NULL OR name = '';

UPDATE groups
SET depth = array_length(string_to_array(path, '.'), 1) - 1
WHERE path IS NOT NULL AND path <> '';

ALTER TABLE groups ALTER COLUMN name SET NOT NULL;

ALTER TABLE members ADD COLUMN IF NOT EXISTS member_type TEXT NOT NULL DEFAULT 'human';
ALTER TABLE members ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE user_members ADD COLUMN IF NOT EXISTS linked_by_member_id TEXT NULL REFERENCES members(id);
ALTER TABLE user_members ADD COLUMN IF NOT EXISTS linked_at TIMESTAMPTZ NULL;
ALTER TABLE user_members ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ NULL;
ALTER TABLE user_members ADD COLUMN IF NOT EXISTS revoked_reason TEXT NULL;
ALTER TABLE user_members ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

UPDATE user_members
SET revoked_at = COALESCE(revoked_at, updated_at, created_at)
WHERE status = 'revoked' AND revoked_at IS NULL;

ALTER TABLE roles ADD COLUMN IF NOT EXISTS name TEXT;
ALTER TABLE roles ADD COLUMN IF NOT EXISTS description TEXT NULL;
ALTER TABLE roles ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE roles ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

UPDATE roles
SET name = initcap(replace(key, '_', ' '))
WHERE name IS NULL OR name = '';

ALTER TABLE roles ALTER COLUMN name SET NOT NULL;

ALTER TABLE permissions ADD COLUMN IF NOT EXISTS description TEXT NULL;
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE member_roles ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE member_roles ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE role_permissions ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE resources ADD COLUMN IF NOT EXISTS external_id TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_resources_external_id ON resources(external_id);
CREATE INDEX IF NOT EXISTS idx_roles_status ON roles(status);
CREATE INDEX IF NOT EXISTS idx_permissions_status ON permissions(status);
CREATE INDEX IF NOT EXISTS idx_member_roles_status ON member_roles(status);

ALTER TABLE audit_logs ALTER COLUMN actor_user_id DROP NOT NULL;
ALTER TABLE audit_logs ALTER COLUMN actor_member_id DROP NOT NULL;
ALTER TABLE audit_logs ALTER COLUMN actor_user_member_id DROP NOT NULL;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_address TEXT NULL;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_agent TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);
