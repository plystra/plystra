-- Add a generic application data store for Backend OS Alpha.
--
-- Resource Binding remains an authorization context index. These tables are
-- the generic, space-scoped business data substrate governed by Plystra authz,
-- audit, members, groups, and roles.

CREATE TABLE IF NOT EXISTS app_data_models (
  id TEXT PRIMARY KEY,
  space_id TEXT NOT NULL REFERENCES spaces(id),
  key TEXT NOT NULL,
  display_name TEXT NOT NULL,
  description TEXT NULL,
  source TEXT NOT NULL DEFAULT 'app',
  status TEXT NOT NULL DEFAULT 'active',
  schema JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ NULL,
  CONSTRAINT app_data_models_key_format CHECK (key ~ '^[a-z][a-z0-9_]*$')
);

CREATE UNIQUE INDEX IF NOT EXISTS appdatamodel_space_id_key
  ON app_data_models(space_id, key);
CREATE INDEX IF NOT EXISTS appdatamodel_space_id_status
  ON app_data_models(space_id, status);
CREATE INDEX IF NOT EXISTS appdatamodel_key
  ON app_data_models(key);

CREATE TABLE IF NOT EXISTS app_data_records (
  id TEXT PRIMARY KEY,
  space_id TEXT NOT NULL REFERENCES spaces(id),
  model_id TEXT NOT NULL REFERENCES app_data_models(id),
  model_key TEXT NOT NULL,
  group_id TEXT NULL REFERENCES groups(id),
  owner_member_id TEXT NULL REFERENCES members(id),
  display_name TEXT NULL,
  visibility TEXT NOT NULL DEFAULT 'private',
  status TEXT NOT NULL DEFAULT 'active',
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ NULL,
  CONSTRAINT app_data_records_model_key_format CHECK (model_key ~ '^[a-z][a-z0-9_]*$')
);

CREATE UNIQUE INDEX IF NOT EXISTS appdatarecord_space_id_model_key_id
  ON app_data_records(space_id, model_key, id);
CREATE INDEX IF NOT EXISTS appdatarecord_model_id
  ON app_data_records(model_id);
CREATE INDEX IF NOT EXISTS appdatarecord_space_id_model_key_status
  ON app_data_records(space_id, model_key, status);
CREATE INDEX IF NOT EXISTS appdatarecord_space_id_group_id
  ON app_data_records(space_id, group_id);
CREATE INDEX IF NOT EXISTS appdatarecord_space_id_owner_member_id
  ON app_data_records(space_id, owner_member_id);

CREATE TABLE IF NOT EXISTS app_data_record_revisions (
  id TEXT PRIMARY KEY,
  record_id TEXT NOT NULL REFERENCES app_data_records(id),
  space_id TEXT NOT NULL REFERENCES spaces(id),
  model_id TEXT NOT NULL REFERENCES app_data_models(id),
  model_key TEXT NOT NULL,
  revision INT NOT NULL,
  operation TEXT NOT NULL,
  actor_user_id TEXT NULL REFERENCES users(id),
  actor_member_id TEXT NULL REFERENCES members(id),
  actor_user_member_id TEXT NULL REFERENCES user_members(id),
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT app_data_record_revisions_revision_positive CHECK (revision > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS appdatarecordrevision_record_id_revision
  ON app_data_record_revisions(record_id, revision);
CREATE INDEX IF NOT EXISTS appdatarecordrevision_space_id_model_key_record_id
  ON app_data_record_revisions(space_id, model_key, record_id);
CREATE INDEX IF NOT EXISTS appdatarecordrevision_created_at
  ON app_data_record_revisions(created_at);

INSERT INTO resource_types (id, key, display_name, description, source, status, metadata, created_at, updated_at)
VALUES (
  'rt_app_data_record',
  'app_data_record',
  'Application Data Record',
  'Generic space-scoped business data record governed by Plystra authorization.',
  'core',
  'active',
  '{"capability":"backend_os_alpha.app_data"}'::jsonb,
  now(),
  now()
)
ON CONFLICT (key) DO UPDATE SET
  display_name = EXCLUDED.display_name,
  description = EXCLUDED.description,
  source = EXCLUDED.source,
  status = EXCLUDED.status,
  metadata = EXCLUDED.metadata,
  updated_at = now();

INSERT INTO resource_actions (id, resource_type_id, key, display_name, description, risk_level, audit_default, metadata, created_at, updated_at)
VALUES
  ('ra_app_data_record_read', (SELECT id FROM resource_types WHERE key = 'app_data_record'), 'read', 'Read Application Data Record', 'Read generic app-owned data records.', 'normal', true, '{}'::jsonb, now(), now()),
  ('ra_app_data_record_create', (SELECT id FROM resource_types WHERE key = 'app_data_record'), 'create', 'Create Application Data Record', 'Create generic app-owned data records.', 'normal', true, '{}'::jsonb, now(), now()),
  ('ra_app_data_record_update', (SELECT id FROM resource_types WHERE key = 'app_data_record'), 'update', 'Update Application Data Record', 'Update generic app-owned data records.', 'high', true, '{}'::jsonb, now(), now()),
  ('ra_app_data_record_delete', (SELECT id FROM resource_types WHERE key = 'app_data_record'), 'delete', 'Delete Application Data Record', 'Soft-delete generic app-owned data records.', 'high', true, '{}'::jsonb, now(), now()),
  ('ra_app_data_record_archive', (SELECT id FROM resource_types WHERE key = 'app_data_record'), 'archive', 'Archive Application Data Record', 'Archive generic app-owned data records.', 'normal', true, '{}'::jsonb, now(), now())
ON CONFLICT (resource_type_id, key) DO UPDATE SET
  display_name = EXCLUDED.display_name,
  description = EXCLUDED.description,
  risk_level = EXCLUDED.risk_level,
  audit_default = EXCLUDED.audit_default,
  metadata = EXCLUDED.metadata,
  updated_at = now();

INSERT INTO resource_mappings (
  id,
  resource_type_id,
  storage_kind,
  table_name,
  id_field,
  space_field,
  group_field,
  owner_member_field,
  visibility_field,
  metadata_field,
  status,
  metadata,
  created_at,
  updated_at
)
VALUES (
  'rm_app_data_record',
  (SELECT id FROM resource_types WHERE key = 'app_data_record'),
  'internal_table',
  'app_data_records',
  'id',
  'space_id',
  'group_id',
  'owner_member_id',
  'visibility',
  'metadata',
  'active',
  '{"model_field":"model_key","data_field":"data"}'::jsonb,
  now(),
  now()
)
ON CONFLICT (resource_type_id) DO UPDATE SET
  storage_kind = EXCLUDED.storage_kind,
  table_name = EXCLUDED.table_name,
  id_field = EXCLUDED.id_field,
  space_field = EXCLUDED.space_field,
  group_field = EXCLUDED.group_field,
  owner_member_field = EXCLUDED.owner_member_field,
  visibility_field = EXCLUDED.visibility_field,
  metadata_field = EXCLUDED.metadata_field,
  status = EXCLUDED.status,
  metadata = EXCLUDED.metadata,
  updated_at = now();

CREATE OR REPLACE FUNCTION plystra_register_app_data_model_resource()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  resource_type_key TEXT := 'data_' || NEW.key;
  resource_type_id TEXT;
BEGIN
  INSERT INTO resource_types (id, key, display_name, description, source, status, metadata, created_at, updated_at)
  VALUES (
    'rt_data_' || NEW.id,
    resource_type_key,
    NEW.display_name,
    'Application data model: ' || NEW.key,
    'core.app_data',
    NEW.status,
    jsonb_build_object(
      'app_data_model_id', NEW.id,
      'app_data_model_key', NEW.key,
      'base_resource_type', 'app_data_record'
    ),
    now(),
    now()
  )
  ON CONFLICT (key) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    source = EXCLUDED.source,
    status = EXCLUDED.status,
    metadata = EXCLUDED.metadata,
    updated_at = now()
  RETURNING id INTO resource_type_id;

  INSERT INTO resource_actions (id, resource_type_id, key, display_name, description, risk_level, audit_default, metadata, created_at, updated_at)
  VALUES
    ('ra_' || resource_type_id || '_read', resource_type_id, 'read', 'Read ' || NEW.display_name, 'Read app data records for model ' || NEW.key, 'normal', true, jsonb_build_object('app_data_model_key', NEW.key), now(), now()),
    ('ra_' || resource_type_id || '_create', resource_type_id, 'create', 'Create ' || NEW.display_name, 'Create app data records for model ' || NEW.key, 'normal', true, jsonb_build_object('app_data_model_key', NEW.key), now(), now()),
    ('ra_' || resource_type_id || '_update', resource_type_id, 'update', 'Update ' || NEW.display_name, 'Update app data records for model ' || NEW.key, 'high', true, jsonb_build_object('app_data_model_key', NEW.key), now(), now()),
    ('ra_' || resource_type_id || '_delete', resource_type_id, 'delete', 'Delete ' || NEW.display_name, 'Delete app data records for model ' || NEW.key, 'high', true, jsonb_build_object('app_data_model_key', NEW.key), now(), now()),
    ('ra_' || resource_type_id || '_archive', resource_type_id, 'archive', 'Archive ' || NEW.display_name, 'Archive app data records for model ' || NEW.key, 'normal', true, jsonb_build_object('app_data_model_key', NEW.key), now(), now())
  ON CONFLICT (resource_type_id, key) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    risk_level = EXCLUDED.risk_level,
    audit_default = EXCLUDED.audit_default,
    metadata = EXCLUDED.metadata,
    updated_at = now();

  INSERT INTO resource_mappings (
    id,
    resource_type_id,
    storage_kind,
    table_name,
    id_field,
    space_field,
    group_field,
    owner_member_field,
    visibility_field,
    metadata_field,
    status,
    metadata,
    created_at,
    updated_at
  )
  VALUES (
    'rm_' || resource_type_id,
    resource_type_id,
    'internal_table',
    'app_data_records',
    'id',
    'space_id',
    'group_id',
    'owner_member_id',
    'visibility',
    'metadata',
    'active',
    jsonb_build_object('app_data_model_key', NEW.key, 'model_field', 'model_key', 'data_field', 'data'),
    now(),
    now()
  )
  ON CONFLICT (resource_type_id) DO UPDATE SET
    storage_kind = EXCLUDED.storage_kind,
    table_name = EXCLUDED.table_name,
    id_field = EXCLUDED.id_field,
    space_field = EXCLUDED.space_field,
    group_field = EXCLUDED.group_field,
    owner_member_field = EXCLUDED.owner_member_field,
    visibility_field = EXCLUDED.visibility_field,
    metadata_field = EXCLUDED.metadata_field,
    status = EXCLUDED.status,
    metadata = EXCLUDED.metadata,
    updated_at = now();

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_register_app_data_model_resource ON app_data_models;
CREATE TRIGGER trg_register_app_data_model_resource
AFTER INSERT OR UPDATE OF display_name, status, metadata ON app_data_models
FOR EACH ROW
EXECUTE FUNCTION plystra_register_app_data_model_resource();
