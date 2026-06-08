-- purpose: make Core App Data governance identity first-class for Plugin/App Module-owned models.
-- rollback: export governance columns, then drop the columns and indexes if reverting.

ALTER TABLE app_data_models
  ADD COLUMN IF NOT EXISTS owner_plugin_type varchar NULL,
  ADD COLUMN IF NOT EXISTS app_id varchar NULL,
  ADD COLUMN IF NOT EXISTS trust_bundle_id varchar NULL,
  ADD COLUMN IF NOT EXISTS owner_module_key varchar NULL,
  ADD COLUMN IF NOT EXISTS tenant_scoped boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS audit_enforcement varchar NOT NULL DEFAULT 'reported_event';

UPDATE app_data_models AS adm
SET
  owner_plugin_type = COALESCE(NULLIF(p.type, ''), NULLIF(p.manifest->>'type', ''), 'plugin'),
  app_id = COALESCE(NULLIF(p.app_id, ''), NULLIF(p.manifest->>'app_id', '')),
  trust_bundle_id = COALESCE(NULLIF(p.trust_bundle_id, ''), NULLIF(p.manifest->>'trust_bundle_id', '')),
  owner_module_key = CASE
    WHEN COALESCE(NULLIF(p.type, ''), NULLIF(p.manifest->>'type', ''), 'plugin') = 'app_module'
    THEN p.key
    ELSE NULL
  END,
  tenant_scoped = true,
  audit_enforcement = CASE
    WHEN EXISTS (
      SELECT 1
      FROM jsonb_array_elements(
        COALESCE(p.manifest->'capabilities', '[]'::jsonb)
        || COALESCE(p.manifest->'local_capabilities', '[]'::jsonb)
      ) AS cap
      WHERE COALESCE(cap->'data_plane'->'allowed', '[]'::jsonb) ? 'core_data_api'
        AND cap->'audit'->>'enforcement' = 'controlled_action'
    )
    THEN 'controlled_action'
    WHEN EXISTS (
      SELECT 1
      FROM jsonb_array_elements(
        COALESCE(p.manifest->'capabilities', '[]'::jsonb)
        || COALESCE(p.manifest->'local_capabilities', '[]'::jsonb)
      ) AS cap
      WHERE COALESCE(cap->'data_plane'->'allowed', '[]'::jsonb) ? 'core_data_api'
        AND cap->'audit'->>'enforcement' = 'observed_mutation'
    )
    THEN 'observed_mutation'
    WHEN EXISTS (
      SELECT 1
      FROM jsonb_array_elements(
        COALESCE(p.manifest->'capabilities', '[]'::jsonb)
        || COALESCE(p.manifest->'local_capabilities', '[]'::jsonb)
      ) AS cap
      WHERE COALESCE(cap->'data_plane'->'allowed', '[]'::jsonb) ? 'core_data_api'
        AND cap->'audit'->>'enforcement' = 'reported_event'
    )
    THEN 'reported_event'
    ELSE 'reported_event'
  END,
  metadata = COALESCE(adm.metadata, '{}'::jsonb)
    - 'owner_plugin_type'
    - 'app_id'
    - 'trust_bundle_id'
    - 'owner_module_key'
    - 'tenant_scoped'
    - 'audit_enforcement'
    || jsonb_strip_nulls(jsonb_build_object(
      'owner_plugin_type', COALESCE(NULLIF(p.type, ''), NULLIF(p.manifest->>'type', ''), 'plugin'),
      'app_id', COALESCE(NULLIF(p.app_id, ''), NULLIF(p.manifest->>'app_id', '')),
      'trust_bundle_id', COALESCE(NULLIF(p.trust_bundle_id, ''), NULLIF(p.manifest->>'trust_bundle_id', '')),
      'owner_module_key', CASE
        WHEN COALESCE(NULLIF(p.type, ''), NULLIF(p.manifest->>'type', ''), 'plugin') = 'app_module'
        THEN p.key
        ELSE NULL
      END,
      'tenant_scoped', true,
      'audit_enforcement', CASE
        WHEN EXISTS (
          SELECT 1
          FROM jsonb_array_elements(
            COALESCE(p.manifest->'capabilities', '[]'::jsonb)
            || COALESCE(p.manifest->'local_capabilities', '[]'::jsonb)
          ) AS cap
          WHERE COALESCE(cap->'data_plane'->'allowed', '[]'::jsonb) ? 'core_data_api'
            AND cap->'audit'->>'enforcement' = 'controlled_action'
        )
        THEN 'controlled_action'
        WHEN EXISTS (
          SELECT 1
          FROM jsonb_array_elements(
            COALESCE(p.manifest->'capabilities', '[]'::jsonb)
            || COALESCE(p.manifest->'local_capabilities', '[]'::jsonb)
          ) AS cap
          WHERE COALESCE(cap->'data_plane'->'allowed', '[]'::jsonb) ? 'core_data_api'
            AND cap->'audit'->>'enforcement' = 'observed_mutation'
        )
        THEN 'observed_mutation'
        ELSE 'reported_event'
      END
    ))
FROM plugins AS p
WHERE adm.owner_plugin_key = p.key
  AND EXISTS (
    SELECT 1
    FROM jsonb_array_elements(
      COALESCE(p.manifest->'capabilities', '[]'::jsonb)
      || COALESCE(p.manifest->'local_capabilities', '[]'::jsonb)
    ) AS cap
    WHERE COALESCE(cap->'data_plane'->'allowed', '[]'::jsonb) ? 'core_data_api'
  );

CREATE INDEX IF NOT EXISTS appdatamodel_space_id_app_id
  ON app_data_models(space_id, app_id);

CREATE INDEX IF NOT EXISTS appdatamodel_space_id_trust_bundle_id
  ON app_data_models(space_id, trust_bundle_id);

CREATE INDEX IF NOT EXISTS appdatamodel_owner_module_key
  ON app_data_models(owner_module_key);

CREATE INDEX IF NOT EXISTS appdatamodel_audit_enforcement
  ON app_data_models(audit_enforcement);
