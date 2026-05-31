-- Fix app data model registration trigger variable naming so PostgreSQL does
-- not confuse PL/pgSQL variables with resource_actions.resource_type_id.

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
