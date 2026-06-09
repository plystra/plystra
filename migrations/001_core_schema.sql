CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	email TEXT NOT NULL UNIQUE,
	status TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS spaces (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	status TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS groups (
	id TEXT PRIMARY KEY,
	space_id TEXT NOT NULL REFERENCES spaces(id),
	parent_group_id TEXT NULL REFERENCES groups(id),
	path TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'active',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE(space_id, path)
);

CREATE TABLE IF NOT EXISTS members (
	id TEXT PRIMARY KEY,
	space_id TEXT NOT NULL REFERENCES spaces(id),
	display_name TEXT NOT NULL,
	status TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_members (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES users(id),
	member_id TEXT NOT NULL REFERENCES members(id),
	space_id TEXT NOT NULL REFERENCES spaces(id),
	relation_type TEXT NOT NULL,
	status TEXT NOT NULL,
	is_primary BOOLEAN NOT NULL DEFAULT false,
	expires_at TIMESTAMPTZ NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS roles (
	id TEXT PRIMARY KEY,
	space_id TEXT NOT NULL REFERENCES spaces(id),
	key TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE(space_id, key)
);

CREATE TABLE IF NOT EXISTS permissions (
	id TEXT PRIMARY KEY,
	resource TEXT NOT NULL,
	action TEXT NOT NULL,
	scope TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE(resource, action, scope)
);

CREATE TABLE IF NOT EXISTS member_roles (
	id TEXT PRIMARY KEY,
	member_id TEXT NOT NULL REFERENCES members(id),
	role_id TEXT NOT NULL REFERENCES roles(id),
	space_id TEXT NOT NULL REFERENCES spaces(id),
	scope_anchor_group_id TEXT NULL REFERENCES groups(id),
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE(member_id, role_id, scope_anchor_group_id)
);

CREATE TABLE IF NOT EXISTS role_permissions (
	role_id TEXT NOT NULL REFERENCES roles(id),
	permission_id TEXT NOT NULL REFERENCES permissions(id),
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY(role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS resources (
	id TEXT PRIMARY KEY,
	resource_type TEXT NOT NULL,
	space_id TEXT NOT NULL REFERENCES spaces(id),
	group_id TEXT NULL REFERENCES groups(id),
	owner_member_id TEXT NULL REFERENCES members(id),
	metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
	status TEXT NOT NULL DEFAULT 'active',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
	id TEXT PRIMARY KEY,
	space_id TEXT NOT NULL REFERENCES spaces(id),
	actor_user_id TEXT NOT NULL REFERENCES users(id),
	actor_member_id TEXT NOT NULL REFERENCES members(id),
	actor_user_member_id TEXT NOT NULL REFERENCES user_members(id),
	action TEXT NOT NULL,
	resource_type TEXT NOT NULL,
	resource_id TEXT NOT NULL,
	decision TEXT NOT NULL,
	deny_code TEXT NULL,
	trace JSONB NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
