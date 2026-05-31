-- Align app data tables with the Ent-managed schema used by doctor/readiness.
--
-- API validation and Ent hooks enforce same-space and lifecycle invariants.
-- These constraints were introduced manually in the initial app data migration
-- and caused schema drift in the production readiness check.

DROP TRIGGER IF EXISTS trg_register_app_data_model_resource ON app_data_models;
DROP FUNCTION IF EXISTS plystra_register_app_data_model_resource();

ALTER TABLE app_data_models
  DROP CONSTRAINT IF EXISTS app_data_models_key_format,
  DROP CONSTRAINT IF EXISTS app_data_models_space_id_fkey,
  ALTER COLUMN id TYPE character varying,
  ALTER COLUMN space_id TYPE character varying,
  ALTER COLUMN key TYPE character varying,
  ALTER COLUMN display_name TYPE character varying,
  ALTER COLUMN description TYPE character varying,
  ALTER COLUMN source TYPE character varying,
  ALTER COLUMN status TYPE character varying,
  ALTER COLUMN metadata DROP NOT NULL;

ALTER TABLE app_data_records
  DROP CONSTRAINT IF EXISTS app_data_records_model_key_format,
  DROP CONSTRAINT IF EXISTS app_data_records_group_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_records_model_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_records_owner_member_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_records_space_id_fkey,
  ALTER COLUMN id TYPE character varying,
  ALTER COLUMN space_id TYPE character varying,
  ALTER COLUMN model_id TYPE character varying,
  ALTER COLUMN model_key TYPE character varying,
  ALTER COLUMN group_id TYPE character varying,
  ALTER COLUMN owner_member_id TYPE character varying,
  ALTER COLUMN display_name TYPE character varying,
  ALTER COLUMN visibility TYPE character varying,
  ALTER COLUMN status TYPE character varying,
  ALTER COLUMN metadata DROP NOT NULL;

ALTER TABLE app_data_record_revisions
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_revision_positive,
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_actor_member_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_actor_user_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_actor_user_member_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_model_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_record_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_space_id_fkey,
  ALTER COLUMN id TYPE character varying,
  ALTER COLUMN record_id TYPE character varying,
  ALTER COLUMN space_id TYPE character varying,
  ALTER COLUMN model_id TYPE character varying,
  ALTER COLUMN model_key TYPE character varying,
  ALTER COLUMN revision TYPE bigint,
  ALTER COLUMN operation TYPE character varying,
  ALTER COLUMN actor_user_id TYPE character varying,
  ALTER COLUMN actor_member_id TYPE character varying,
  ALTER COLUMN actor_user_member_id TYPE character varying,
  ALTER COLUMN metadata DROP NOT NULL;

CREATE OR REPLACE FUNCTION plystra_register_app_data_model_resource()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  rt_key TEXT := 'data_' || NEW.key;
  rt_id TEXT;
BEGIN
  INSERT INTO resource_types (id, key, display_name, description, source, status, metadata, created_at, updated_at)
  VALUES (
    'rt_data_' || NEW.id,
    rt_key,
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
  RETURNING id INTO rt_id;

  INSERT INTO resource_actions (id, resource_type_id, key, display_name, description, risk_level, audit_default, metadata, created_at, updated_at)
  VALUES
    ('ra_' || rt_id || '_read', rt_id, 'read', 'Read ' || NEW.display_name, 'Read app data records for model ' || NEW.key, 'normal', true, jsonb_build_object('app_data_model_key', NEW.key), now(), now()),
    ('ra_' || rt_id || '_create', rt_id, 'create', 'Create ' || NEW.display_name, 'Create app data records for model ' || NEW.key, 'normal', true, jsonb_build_object('app_data_model_key', NEW.key), now(), now()),
    ('ra_' || rt_id || '_update', rt_id, 'update', 'Update ' || NEW.display_name, 'Update app data records for model ' || NEW.key, 'high', true, jsonb_build_object('app_data_model_key', NEW.key), now(), now()),
    ('ra_' || rt_id || '_delete', rt_id, 'delete', 'Delete ' || NEW.display_name, 'Delete app data records for model ' || NEW.key, 'high', true, jsonb_build_object('app_data_model_key', NEW.key), now(), now()),
    ('ra_' || rt_id || '_archive', rt_id, 'archive', 'Archive ' || NEW.display_name, 'Archive app data records for model ' || NEW.key, 'normal', true, jsonb_build_object('app_data_model_key', NEW.key), now(), now())
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
    'rm_' || rt_id,
    rt_id,
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

CREATE TRIGGER trg_register_app_data_model_resource
AFTER INSERT OR UPDATE OF display_name, status, metadata ON app_data_models
FOR EACH ROW
EXECUTE FUNCTION plystra_register_app_data_model_resource();
