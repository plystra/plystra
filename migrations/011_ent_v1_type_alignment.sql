-- purpose: align v1.0 additive columns with Ent's generated PostgreSQL schema.
-- affected tables: users, spaces, groups, members, user_members, roles,
-- permissions, member_roles, role_permissions, resources, audit_logs.
-- rollback strategy: type changes between text and unlimited varchar are
-- semantically compatible; JSONB nullability can be restored with backfill.
-- data compatibility: no data rewrite except compatible metadata nullability
-- and int-to-bigint widening.
-- plugin compatibility: no plugin-owned table changes.

ALTER TABLE audit_logs
	ALTER COLUMN ip_address TYPE character varying,
	ALTER COLUMN user_agent TYPE character varying;

ALTER TABLE groups
	ALTER COLUMN name TYPE character varying,
	ALTER COLUMN depth TYPE bigint,
	ALTER COLUMN sort_order TYPE bigint,
	ALTER COLUMN metadata DROP NOT NULL;

ALTER TABLE member_roles
	ALTER COLUMN status TYPE character varying,
	ALTER COLUMN metadata DROP NOT NULL;

ALTER TABLE members
	ALTER COLUMN member_type TYPE character varying,
	ALTER COLUMN metadata DROP NOT NULL;

ALTER TABLE permissions
	ALTER COLUMN description TYPE character varying,
	ALTER COLUMN status TYPE character varying,
	ALTER COLUMN metadata DROP NOT NULL;

ALTER TABLE resources
	ALTER COLUMN external_id TYPE character varying;

ALTER TABLE role_permissions
	ALTER COLUMN metadata DROP NOT NULL;

ALTER TABLE roles
	ALTER COLUMN name TYPE character varying,
	ALTER COLUMN description TYPE character varying,
	ALTER COLUMN status TYPE character varying,
	ALTER COLUMN metadata DROP NOT NULL;

ALTER TABLE spaces
	ALTER COLUMN slug TYPE character varying,
	ALTER COLUMN type TYPE character varying,
	ALTER COLUMN metadata DROP NOT NULL;

ALTER TABLE user_members
	DROP CONSTRAINT IF EXISTS user_members_linked_by_member_id_fkey,
	ALTER COLUMN linked_by_member_id TYPE character varying,
	ALTER COLUMN revoked_reason TYPE character varying,
	ALTER COLUMN metadata DROP NOT NULL;

ALTER TABLE users
	ALTER COLUMN username TYPE character varying,
	ALTER COLUMN phone TYPE character varying,
	ALTER COLUMN metadata DROP NOT NULL;
