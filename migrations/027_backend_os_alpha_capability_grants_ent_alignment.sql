-- purpose: close Ent drift for the capability_grants ledger introduced in Backend OS Alpha.
-- rollback: keep the widened binding_epoch type and Ent-aligned index names; they are non-destructive compatibility changes.

ALTER TABLE capability_grants
  ALTER COLUMN binding_epoch TYPE bigint,
  ALTER COLUMN metadata DROP NOT NULL;

DROP INDEX IF EXISTS capabilitygrant_space_caller_capability_operation_idempotency_key;
DROP INDEX IF EXISTS capabilitygrant_space_target_capability_operation_target_idempotency_key;
DROP INDEX IF EXISTS capabilitygrant_space_capability_operation;

CREATE UNIQUE INDEX IF NOT EXISTS capabilitygrant_space_id_calle_212eaa9b84b75dee3bc246bf5eb2d6d7
  ON capability_grants(space_id, caller_plugin_id, capability, operation, idempotency_key);

CREATE UNIQUE INDEX IF NOT EXISTS capabilitygrant_space_id_targe_d17b039988a8faeadf28ab4f5969302a
  ON capability_grants(space_id, target_provider_id, capability, operation, target_idempotency_key);

CREATE INDEX IF NOT EXISTS capabilitygrant_space_id_capability_operation
  ON capability_grants(space_id, capability, operation);
