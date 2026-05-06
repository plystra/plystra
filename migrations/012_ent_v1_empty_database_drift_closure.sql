-- purpose: close Ent drift after applying v1.0 migrations to a clean database.
-- affected tables: all Ent-managed Core, registry, plugin metadata, template,
-- session, background job, and audit tables.
-- rollback strategy: restore from backup; the changes are compatible type
-- normalizations, nullable JSONB alignment, Ent index creation, and removal of
-- database FKs that are not modeled by the v1 Core Ent schemas.
-- compatibility notes: application-level same-space invariants remain enforced
-- by Ent hooks, API validation, and authz checks.

DROP TRIGGER IF EXISTS trg_user_members_same_space ON user_members;
DROP TRIGGER IF EXISTS trg_member_roles_same_space ON member_roles;
DROP TRIGGER IF EXISTS trg_resources_same_space ON resources;

ALTER TABLE audit_event_types
	DROP CONSTRAINT IF EXISTS audit_event_types_plugin_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN key TYPE character varying,
	ALTER COLUMN plugin_id TYPE character varying,
	ALTER COLUMN display_name TYPE character varying,
	ALTER COLUMN description TYPE character varying,
	ALTER COLUMN risk_level TYPE character varying,
	ALTER COLUMN metadata DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS auditeventtype_key ON audit_event_types (key);

ALTER TABLE audit_logs
	DROP CONSTRAINT IF EXISTS audit_logs_actor_member_id_fkey,
	DROP CONSTRAINT IF EXISTS audit_logs_actor_user_id_fkey,
	DROP CONSTRAINT IF EXISTS audit_logs_actor_user_member_id_fkey,
	DROP CONSTRAINT IF EXISTS audit_logs_space_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN space_id TYPE character varying,
	ALTER COLUMN actor_user_id TYPE character varying,
	ALTER COLUMN actor_member_id TYPE character varying,
	ALTER COLUMN actor_user_member_id TYPE character varying,
	ALTER COLUMN action TYPE character varying,
	ALTER COLUMN resource_type TYPE character varying,
	ALTER COLUMN resource_id TYPE character varying,
	ALTER COLUMN decision TYPE character varying,
	ALTER COLUMN deny_code TYPE character varying,
	ALTER COLUMN request_id TYPE character varying;

ALTER TABLE background_jobs
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN job_type TYPE character varying,
	ALTER COLUMN status TYPE character varying,
	ALTER COLUMN status SET DEFAULT 'pending',
	ALTER COLUMN attempts TYPE bigint,
	ALTER COLUMN max_attempts TYPE bigint,
	ALTER COLUMN last_error TYPE character varying;

ALTER TABLE groups
	DROP CONSTRAINT IF EXISTS groups_parent_group_id_fkey,
	DROP CONSTRAINT IF EXISTS groups_space_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN space_id TYPE character varying,
	ALTER COLUMN parent_group_id TYPE character varying,
	ALTER COLUMN path TYPE character varying,
	ALTER COLUMN status TYPE character varying,
	ALTER COLUMN display_name TYPE character varying;
CREATE UNIQUE INDEX IF NOT EXISTS group_space_id_path ON groups (space_id, path);

ALTER TABLE member_roles
	DROP CONSTRAINT IF EXISTS member_roles_member_id_fkey,
	DROP CONSTRAINT IF EXISTS member_roles_role_id_fkey,
	DROP CONSTRAINT IF EXISTS member_roles_scope_anchor_group_id_fkey,
	DROP CONSTRAINT IF EXISTS member_roles_space_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN member_id TYPE character varying,
	ALTER COLUMN role_id TYPE character varying,
	ALTER COLUMN space_id TYPE character varying,
	ALTER COLUMN scope_anchor_group_id TYPE character varying;
CREATE UNIQUE INDEX IF NOT EXISTS memberrole_member_id_role_id_scope_anchor_group_id ON member_roles (member_id, role_id, scope_anchor_group_id);

ALTER TABLE members
	DROP CONSTRAINT IF EXISTS members_space_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN space_id TYPE character varying,
	ALTER COLUMN display_name TYPE character varying,
	ALTER COLUMN status TYPE character varying;

ALTER TABLE permissions
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN resource TYPE character varying,
	ALTER COLUMN action TYPE character varying,
	ALTER COLUMN scope TYPE character varying;
CREATE UNIQUE INDEX IF NOT EXISTS permission_resource_action_scope ON permissions (resource, action, scope);

ALTER TABLE plugin_admin_menus
	DROP CONSTRAINT IF EXISTS plugin_admin_menus_plugin_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN plugin_id TYPE character varying,
	ALTER COLUMN label TYPE character varying,
	ALTER COLUMN path TYPE character varying,
	ALTER COLUMN icon TYPE character varying,
	ALTER COLUMN required_permission TYPE character varying,
	ALTER COLUMN sort_order TYPE bigint,
	ALTER COLUMN metadata DROP NOT NULL;

ALTER TABLE plugin_settings_definitions
	DROP CONSTRAINT IF EXISTS plugin_settings_definitions_plugin_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN plugin_id TYPE character varying,
	ALTER COLUMN key TYPE character varying,
	ALTER COLUMN value_type TYPE character varying,
	ALTER COLUMN description TYPE character varying,
	ALTER COLUMN scope TYPE character varying,
	ALTER COLUMN metadata DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS pluginsettingsdefinition_plugin_id_key_scope ON plugin_settings_definitions (plugin_id, key, scope);

ALTER TABLE plugin_settings_values
	DROP CONSTRAINT IF EXISTS plugin_settings_values_plugin_id_fkey,
	DROP CONSTRAINT IF EXISTS plugin_settings_values_updated_by_member_id_fkey,
	DROP CONSTRAINT IF EXISTS plugin_settings_values_updated_by_user_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN plugin_id TYPE character varying,
	ALTER COLUMN space_id TYPE character varying,
	ALTER COLUMN key TYPE character varying,
	ALTER COLUMN updated_by_user_id TYPE character varying,
	ALTER COLUMN updated_by_member_id TYPE character varying;
CREATE UNIQUE INDEX IF NOT EXISTS pluginsettingsvalue_plugin_id_space_id_key ON plugin_settings_values (plugin_id, space_id, key);

ALTER TABLE plugins
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN key TYPE character varying,
	ALTER COLUMN name TYPE character varying,
	ALTER COLUMN description TYPE character varying,
	ALTER COLUMN version TYPE character varying,
	ALTER COLUMN source TYPE character varying,
	ALTER COLUMN status TYPE character varying;
CREATE UNIQUE INDEX IF NOT EXISTS plugin_key ON plugins (key);

ALTER TABLE resource_actions
	DROP CONSTRAINT IF EXISTS resource_actions_resource_type_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN resource_type_id TYPE character varying,
	ALTER COLUMN key TYPE character varying,
	ALTER COLUMN display_name TYPE character varying,
	ALTER COLUMN description TYPE character varying,
	ALTER COLUMN risk_level TYPE character varying,
	ALTER COLUMN metadata DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS resourceaction_resource_type_id_key ON resource_actions (resource_type_id, key);

ALTER TABLE resource_mappings
	DROP CONSTRAINT IF EXISTS resource_mappings_resource_type_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN resource_type_id TYPE character varying,
	ALTER COLUMN storage_kind TYPE character varying,
	ALTER COLUMN table_name TYPE character varying,
	ALTER COLUMN id_field TYPE character varying,
	ALTER COLUMN space_field TYPE character varying,
	ALTER COLUMN group_field TYPE character varying,
	ALTER COLUMN group_field DROP DEFAULT,
	ALTER COLUMN owner_member_field TYPE character varying,
	ALTER COLUMN owner_member_field DROP DEFAULT,
	ALTER COLUMN visibility_field TYPE character varying,
	ALTER COLUMN visibility_field DROP DEFAULT,
	ALTER COLUMN metadata_field TYPE character varying,
	ALTER COLUMN metadata_field DROP DEFAULT,
	ALTER COLUMN status TYPE character varying,
	ALTER COLUMN metadata DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS resourcemapping_resource_type_id ON resource_mappings (resource_type_id);

ALTER TABLE resource_types
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN key TYPE character varying,
	ALTER COLUMN display_name TYPE character varying,
	ALTER COLUMN description TYPE character varying,
	ALTER COLUMN status TYPE character varying,
	ALTER COLUMN source TYPE character varying,
	ALTER COLUMN metadata DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS resourcetype_key ON resource_types (key);

ALTER TABLE resources
	DROP CONSTRAINT IF EXISTS resources_group_id_fkey,
	DROP CONSTRAINT IF EXISTS resources_owner_member_id_fkey,
	DROP CONSTRAINT IF EXISTS resources_space_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN resource_type TYPE character varying,
	ALTER COLUMN space_id TYPE character varying,
	ALTER COLUMN group_id TYPE character varying,
	ALTER COLUMN owner_member_id TYPE character varying,
	ALTER COLUMN metadata DROP NOT NULL,
	ALTER COLUMN status TYPE character varying,
	ALTER COLUMN display_name TYPE character varying,
	ALTER COLUMN visibility TYPE character varying;

ALTER TABLE role_permissions
	DROP CONSTRAINT IF EXISTS role_permissions_permission_id_fkey,
	DROP CONSTRAINT IF EXISTS role_permissions_role_id_fkey,
	ALTER COLUMN role_id TYPE character varying,
	ALTER COLUMN permission_id TYPE character varying,
	ALTER COLUMN id TYPE character varying;
CREATE UNIQUE INDEX IF NOT EXISTS rolepermission_role_id_permission_id ON role_permissions (role_id, permission_id);
CREATE INDEX IF NOT EXISTS rolepermission_permission_id ON role_permissions (permission_id);

ALTER TABLE roles
	DROP CONSTRAINT IF EXISTS roles_space_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN space_id TYPE character varying,
	ALTER COLUMN key TYPE character varying;
CREATE UNIQUE INDEX IF NOT EXISTS role_space_id_key ON roles (space_id, key);

ALTER TABLE sessions
	DROP CONSTRAINT IF EXISTS sessions_active_member_id_fkey,
	DROP CONSTRAINT IF EXISTS sessions_active_space_id_fkey,
	DROP CONSTRAINT IF EXISTS sessions_active_user_member_id_fkey,
	DROP CONSTRAINT IF EXISTS sessions_user_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN user_id TYPE character varying,
	ALTER COLUMN active_space_id TYPE character varying,
	ALTER COLUMN active_member_id TYPE character varying,
	ALTER COLUMN active_user_member_id TYPE character varying,
	ALTER COLUMN access_token_hash TYPE character varying,
	ALTER COLUMN refresh_token_hash TYPE character varying,
	ALTER COLUMN ip TYPE character varying,
	ALTER COLUMN user_agent TYPE character varying;
CREATE INDEX IF NOT EXISTS session_user_id ON sessions (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS session_access_token_hash ON sessions (access_token_hash);
CREATE UNIQUE INDEX IF NOT EXISTS session_refresh_token_hash ON sessions (refresh_token_hash);

ALTER TABLE spaces
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN name TYPE character varying,
	ALTER COLUMN status TYPE character varying;

ALTER TABLE template_installations
	DROP CONSTRAINT IF EXISTS template_installations_installed_by_member_id_fkey,
	DROP CONSTRAINT IF EXISTS template_installations_installed_by_user_id_fkey,
	DROP CONSTRAINT IF EXISTS template_installations_space_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN template_id TYPE character varying,
	ALTER COLUMN template_version TYPE character varying,
	ALTER COLUMN space_id TYPE character varying,
	ALTER COLUMN status TYPE character varying,
	ALTER COLUMN installed_by_user_id TYPE character varying,
	ALTER COLUMN installed_by_member_id TYPE character varying;

ALTER TABLE user_members
	DROP CONSTRAINT IF EXISTS user_members_member_id_fkey,
	DROP CONSTRAINT IF EXISTS user_members_space_id_fkey,
	DROP CONSTRAINT IF EXISTS user_members_user_id_fkey,
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN user_id TYPE character varying,
	ALTER COLUMN member_id TYPE character varying,
	ALTER COLUMN space_id TYPE character varying,
	ALTER COLUMN relation_type TYPE character varying,
	ALTER COLUMN status TYPE character varying;

ALTER TABLE users
	ALTER COLUMN id TYPE character varying,
	ALTER COLUMN email TYPE character varying,
	ALTER COLUMN status TYPE character varying,
	ALTER COLUMN status SET DEFAULT 'active',
	ALTER COLUMN password_hash TYPE character varying;
CREATE UNIQUE INDEX IF NOT EXISTS user_email ON users (email);

CREATE TRIGGER trg_user_members_same_space
BEFORE INSERT OR UPDATE OF member_id, space_id
ON user_members
FOR EACH ROW
EXECUTE FUNCTION plystra_enforce_user_member_same_space();

CREATE TRIGGER trg_member_roles_same_space
BEFORE INSERT OR UPDATE OF member_id, role_id, space_id, scope_anchor_group_id
ON member_roles
FOR EACH ROW
EXECUTE FUNCTION plystra_enforce_member_role_same_space();

CREATE TRIGGER trg_resources_same_space
BEFORE INSERT OR UPDATE OF space_id, group_id, owner_member_id
ON resources
FOR EACH ROW
EXECUTE FUNCTION plystra_enforce_resource_same_space();
