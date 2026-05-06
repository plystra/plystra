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

INSERT INTO spaces (id, name, status) VALUES
	('space_acme', 'Acme', 'active')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, status = EXCLUDED.status;

INSERT INTO users (id, email, status) VALUES
	('user_alice', 'alice@example.com', 'active'),
	('user_bob', 'bob@example.com', 'active')
ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email, status = EXCLUDED.status;

INSERT INTO groups (id, space_id, parent_group_id, path, status) VALUES
	('group_finance', 'space_acme', NULL, 'finance', 'active'),
	('group_finance_apac', 'space_acme', 'group_finance', 'finance.apac', 'active'),
	('group_finance_emea', 'space_acme', 'group_finance', 'finance.emea', 'active'),
	('group_legal', 'space_acme', NULL, 'legal', 'active'),
	('group_legal_emea', 'space_acme', 'group_legal', 'legal.emea', 'active')
ON CONFLICT (id) DO UPDATE SET
	space_id = EXCLUDED.space_id,
	parent_group_id = EXCLUDED.parent_group_id,
	path = EXCLUDED.path,
	status = EXCLUDED.status;

INSERT INTO members (id, space_id, display_name, status) VALUES
	('member_finance_reviewer', 'space_acme', 'Finance Reviewer', 'active'),
	('member_invoice_creator', 'space_acme', 'APAC Invoice Creator', 'active')
ON CONFLICT (id) DO UPDATE SET
	space_id = EXCLUDED.space_id,
	display_name = EXCLUDED.display_name,
	status = EXCLUDED.status;

INSERT INTO user_members (id, user_id, member_id, space_id, relation_type, status, is_primary, expires_at) VALUES
	('um_alice_finance_reviewer', 'user_alice', 'member_finance_reviewer', 'space_acme', 'delegate', 'active', true, NULL),
	('um_bob_finance_reviewer', 'user_bob', 'member_finance_reviewer', 'space_acme', 'login', 'active', true, NULL),
	('um_alice_finance_reviewer_revoked', 'user_alice', 'member_finance_reviewer', 'space_acme', 'delegate', 'revoked', false, NULL)
ON CONFLICT (id) DO UPDATE SET
	user_id = EXCLUDED.user_id,
	member_id = EXCLUDED.member_id,
	space_id = EXCLUDED.space_id,
	relation_type = EXCLUDED.relation_type,
	status = EXCLUDED.status,
	is_primary = EXCLUDED.is_primary,
	expires_at = EXCLUDED.expires_at;

INSERT INTO roles (id, space_id, key) VALUES
	('role_finance_approver', 'space_acme', 'finance_approver')
ON CONFLICT (id) DO UPDATE SET space_id = EXCLUDED.space_id, key = EXCLUDED.key;

INSERT INTO permissions (id, resource, action, scope) VALUES
	('perm_invoice_approve_group_tree', 'invoice', 'approve', 'group_tree')
ON CONFLICT (id) DO UPDATE SET
	resource = EXCLUDED.resource,
	action = EXCLUDED.action,
	scope = EXCLUDED.scope;

INSERT INTO member_roles (id, member_id, role_id, space_id, scope_anchor_group_id) VALUES
	('mr_finance_reviewer_approver_finance', 'member_finance_reviewer', 'role_finance_approver', 'space_acme', 'group_finance')
ON CONFLICT (id) DO UPDATE SET
	member_id = EXCLUDED.member_id,
	role_id = EXCLUDED.role_id,
	space_id = EXCLUDED.space_id,
	scope_anchor_group_id = EXCLUDED.scope_anchor_group_id;

INSERT INTO role_permissions (role_id, permission_id) VALUES
	('role_finance_approver', 'perm_invoice_approve_group_tree')
ON CONFLICT (role_id, permission_id) DO NOTHING;

INSERT INTO resources (id, resource_type, space_id, group_id, owner_member_id, metadata, status) VALUES
	('invoice_001', 'invoice', 'space_acme', 'group_finance_apac', 'member_invoice_creator', '{"number": "INV-001", "region": "APAC"}', 'active'),
	('invoice_002', 'invoice', 'space_acme', 'group_legal_emea', 'member_invoice_creator', '{"number": "INV-002", "region": "EMEA"}', 'active')
ON CONFLICT (id) DO UPDATE SET
	resource_type = EXCLUDED.resource_type,
	space_id = EXCLUDED.space_id,
	group_id = EXCLUDED.group_id,
	owner_member_id = EXCLUDED.owner_member_id,
	metadata = EXCLUDED.metadata,
	status = EXCLUDED.status;
