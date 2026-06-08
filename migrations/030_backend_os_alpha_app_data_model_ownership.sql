-- purpose: make Core App Data model ownership first-class for governed Plugin/App Module service identities.
-- rollback: export owner_plugin_key and declared_resource_key, then drop the columns and indexes.

ALTER TABLE app_data_models
  ADD COLUMN IF NOT EXISTS owner_plugin_key varchar NULL,
  ADD COLUMN IF NOT EXISTS declared_resource_key varchar NULL;

UPDATE app_data_models
SET
  owner_plugin_key = substring(source from '^plugin:(.+)$'),
  declared_resource_key = key,
  metadata = COALESCE(metadata, '{}'::jsonb)
    || jsonb_build_object(
      'owner_plugin_key', substring(source from '^plugin:(.+)$'),
      'declared_resource_key', key,
      'ownership_source', 'plugin_manifest'
    )
WHERE source ~ '^plugin:.+$'
  AND owner_plugin_key IS NULL;

UPDATE app_data_models AS adm
SET
  owner_plugin_key = p.key,
  declared_resource_key = adm.key,
  source = 'plugin:' || p.key,
  metadata = COALESCE(adm.metadata, '{}'::jsonb)
    || jsonb_build_object(
      'owner_plugin_key', p.key,
      'declared_resource_key', adm.key,
      'ownership_source', 'plugin_manifest'
    )
FROM plugins AS p
WHERE adm.owner_plugin_key IS NULL
  AND adm.source = p.key
  AND p.status IN ('validated', 'installed', 'migrated', 'enabled');

CREATE INDEX IF NOT EXISTS appdatamodel_space_id_owner_plugin_key
  ON app_data_models(space_id, owner_plugin_key);

CREATE INDEX IF NOT EXISTS appdatamodel_owner_plugin_key_declared_resource_key
  ON app_data_models(owner_plugin_key, declared_resource_key);
