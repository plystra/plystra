-- purpose: make provider runtime API-key identity a Core-owned field instead of
-- caller-controlled metadata.
-- rollback: restore from backup before applying this identity-hardening change.

ALTER TABLE api_keys
  ADD COLUMN IF NOT EXISTS provider_runtime_plugin_id varchar NULL;

UPDATE api_keys
SET metadata = metadata
  - 'provider_runtime_plugin_id'
  - 'provider_plugin_id'
  - 'plugin_id'
  - 'provider_id'
WHERE metadata IS NOT NULL
  AND (
    metadata ? 'provider_runtime_plugin_id'
    OR metadata ? 'provider_plugin_id'
    OR metadata ? 'plugin_id'
    OR metadata ? 'provider_id'
  );

CREATE INDEX IF NOT EXISTS apikey_provider_runtime_plugin_id
  ON api_keys(provider_runtime_plugin_id);
