-- purpose: make App Module Trust Bundle identity a governed Plugin field.
-- rollback: keep manifest snapshots, then drop plugins.trust_bundle_id and related index if reverting.

ALTER TABLE plugins
  ADD COLUMN IF NOT EXISTS trust_bundle_id varchar NULL;

UPDATE plugins
SET trust_bundle_id = COALESCE(
      NULLIF(manifest->>'trust_bundle_id', ''),
      CASE
        WHEN COALESCE(NULLIF(app_id, ''), NULLIF(manifest->>'app_id', '')) IS NOT NULL
        THEN COALESCE(NULLIF(app_id, ''), NULLIF(manifest->>'app_id', '')) || '.default'
        ELSE NULL
      END
    ),
    updated_at = now()
WHERE COALESCE(NULLIF(trust_bundle_id, ''), '') = ''
  AND (
    type = 'app_module'
    OR scope = 'app'
    OR manifest->>'type' = 'app_module'
    OR manifest->>'scope' = 'app'
    OR NULLIF(manifest->>'app_id', '') IS NOT NULL
  );

CREATE INDEX IF NOT EXISTS plugin_trust_bundle_id_status
  ON plugins(trust_bundle_id, status);
