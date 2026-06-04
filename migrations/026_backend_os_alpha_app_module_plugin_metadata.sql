-- purpose: store App Module and plugin visibility metadata as governed Plugin fields, not only manifest JSON.
-- rollback: keep manifest snapshots, then drop plugins.type/scope/app_id if reverting to pre-App-Module metadata.

ALTER TABLE plugins
  ADD COLUMN IF NOT EXISTS type varchar NOT NULL DEFAULT 'plugin',
  ADD COLUMN IF NOT EXISTS scope varchar NOT NULL DEFAULT 'public',
  ADD COLUMN IF NOT EXISTS app_id varchar NULL;

UPDATE plugins
SET type = COALESCE(NULLIF(manifest->>'type', ''), type, 'plugin'),
    scope = COALESCE(NULLIF(manifest->>'scope', ''), scope, 'public'),
    app_id = NULLIF(manifest->>'app_id', ''),
    updated_at = now()
WHERE manifest ? 'type'
   OR manifest ? 'scope'
   OR manifest ? 'app_id';

CREATE INDEX IF NOT EXISTS plugin_type_scope_status
  ON plugins(type, scope, status);

CREATE INDEX IF NOT EXISTS plugin_app_id_status
  ON plugins(app_id, status);
