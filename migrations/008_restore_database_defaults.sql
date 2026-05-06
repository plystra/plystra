ALTER TABLE users ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE users ALTER COLUMN updated_at SET DEFAULT now();

ALTER TABLE spaces ALTER COLUMN status SET DEFAULT 'active';
ALTER TABLE spaces ALTER COLUMN created_at SET DEFAULT now();

ALTER TABLE groups ALTER COLUMN status SET DEFAULT 'active';
ALTER TABLE groups ALTER COLUMN created_at SET DEFAULT now();

ALTER TABLE members ALTER COLUMN status SET DEFAULT 'active';
ALTER TABLE members ALTER COLUMN created_at SET DEFAULT now();

ALTER TABLE user_members ALTER COLUMN status SET DEFAULT 'active';
ALTER TABLE user_members ALTER COLUMN is_primary SET DEFAULT false;
ALTER TABLE user_members ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE user_members ALTER COLUMN updated_at SET DEFAULT now();

ALTER TABLE roles ALTER COLUMN created_at SET DEFAULT now();

ALTER TABLE permissions ALTER COLUMN created_at SET DEFAULT now();

ALTER TABLE member_roles ALTER COLUMN created_at SET DEFAULT now();

ALTER TABLE resources ALTER COLUMN metadata SET DEFAULT '{}'::jsonb;
ALTER TABLE resources ALTER COLUMN status SET DEFAULT 'active';
ALTER TABLE resources ALTER COLUMN visibility SET DEFAULT 'private';
ALTER TABLE resources ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE resources ALTER COLUMN updated_at SET DEFAULT now();

ALTER TABLE audit_logs ALTER COLUMN created_at SET DEFAULT now();

ALTER TABLE resource_types ALTER COLUMN status SET DEFAULT 'active';
ALTER TABLE resource_types ALTER COLUMN source SET DEFAULT 'core';
ALTER TABLE resource_types ALTER COLUMN metadata SET DEFAULT '{}'::jsonb;
ALTER TABLE resource_types ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE resource_types ALTER COLUMN updated_at SET DEFAULT now();

ALTER TABLE resource_actions ALTER COLUMN risk_level SET DEFAULT 'normal';
ALTER TABLE resource_actions ALTER COLUMN audit_default SET DEFAULT true;
ALTER TABLE resource_actions ALTER COLUMN metadata SET DEFAULT '{}'::jsonb;
ALTER TABLE resource_actions ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE resource_actions ALTER COLUMN updated_at SET DEFAULT now();

ALTER TABLE resource_mappings ALTER COLUMN storage_kind SET DEFAULT 'internal_table';
ALTER TABLE resource_mappings ALTER COLUMN id_field SET DEFAULT 'id';
ALTER TABLE resource_mappings ALTER COLUMN space_field SET DEFAULT 'space_id';
ALTER TABLE resource_mappings ALTER COLUMN status SET DEFAULT 'active';
ALTER TABLE resource_mappings ALTER COLUMN metadata SET DEFAULT '{}'::jsonb;
ALTER TABLE resource_mappings ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE resource_mappings ALTER COLUMN updated_at SET DEFAULT now();

ALTER TABLE plugins ALTER COLUMN source SET DEFAULT 'official';
ALTER TABLE plugins ALTER COLUMN status SET DEFAULT 'installed';
ALTER TABLE plugins ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE plugins ALTER COLUMN updated_at SET DEFAULT now();

ALTER TABLE plugin_admin_menus ALTER COLUMN sort_order SET DEFAULT 1000;
ALTER TABLE plugin_admin_menus ALTER COLUMN metadata SET DEFAULT '{}'::jsonb;
ALTER TABLE plugin_admin_menus ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE plugin_admin_menus ALTER COLUMN updated_at SET DEFAULT now();

ALTER TABLE plugin_settings_definitions ALTER COLUMN scope SET DEFAULT 'space';
ALTER TABLE plugin_settings_definitions ALTER COLUMN metadata SET DEFAULT '{}'::jsonb;
ALTER TABLE plugin_settings_definitions ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE plugin_settings_definitions ALTER COLUMN updated_at SET DEFAULT now();

ALTER TABLE plugin_settings_values ALTER COLUMN space_id SET DEFAULT '';
ALTER TABLE plugin_settings_values ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE plugin_settings_values ALTER COLUMN updated_at SET DEFAULT now();

ALTER TABLE audit_event_types ALTER COLUMN risk_level SET DEFAULT 'normal';
ALTER TABLE audit_event_types ALTER COLUMN default_audit SET DEFAULT true;
ALTER TABLE audit_event_types ALTER COLUMN metadata SET DEFAULT '{}'::jsonb;
ALTER TABLE audit_event_types ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE audit_event_types ALTER COLUMN updated_at SET DEFAULT now();

ALTER TABLE background_jobs ALTER COLUMN attempts SET DEFAULT 0;
ALTER TABLE background_jobs ALTER COLUMN max_attempts SET DEFAULT 5;
ALTER TABLE background_jobs ALTER COLUMN run_after SET DEFAULT now();
ALTER TABLE background_jobs ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE background_jobs ALTER COLUMN updated_at SET DEFAULT now();

ALTER TABLE template_installations ALTER COLUMN status SET DEFAULT 'installed';
ALTER TABLE template_installations ALTER COLUMN created_at SET DEFAULT now();

ALTER TABLE sessions ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE sessions ALTER COLUMN updated_at SET DEFAULT now();
