-- purpose: add Core-tracked capability grant ledger for governed plugin communication.
-- rollback: export capability_grants for audit retention, then drop the table.

CREATE TABLE IF NOT EXISTS capability_grants (
  id varchar NOT NULL PRIMARY KEY,
  token_hash varchar NOT NULL,
  space_id varchar NOT NULL,
  capability varchar NOT NULL,
  operation varchar NOT NULL,
  principal_user_id varchar NULL,
  principal_member_id varchar NULL,
  principal_user_member_id varchar NULL,
  caller_plugin_id varchar NOT NULL,
  target_provider_id varchar NOT NULL,
  parent_grant_id varchar NULL,
  decision_id varchar NULL,
  correlation_id varchar NOT NULL,
  idempotency_key varchar NOT NULL,
  target_idempotency_key varchar NOT NULL,
  binding_epoch integer NOT NULL DEFAULT 1,
  status varchar NOT NULL DEFAULT 'active',
  outcome_status varchar NOT NULL DEFAULT 'pending',
  expected_outcome_by timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL,
  revoked_reason varchar NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS capabilitygrant_token_hash
  ON capability_grants(token_hash);

CREATE UNIQUE INDEX IF NOT EXISTS capabilitygrant_space_caller_capability_operation_idempotency_key
  ON capability_grants(space_id, caller_plugin_id, capability, operation, idempotency_key);

CREATE UNIQUE INDEX IF NOT EXISTS capabilitygrant_space_target_capability_operation_target_idempotency_key
  ON capability_grants(space_id, target_provider_id, capability, operation, target_idempotency_key);

CREATE INDEX IF NOT EXISTS capabilitygrant_space_capability_operation
  ON capability_grants(space_id, capability, operation);

CREATE INDEX IF NOT EXISTS capabilitygrant_target_provider_id_status
  ON capability_grants(target_provider_id, status);

CREATE INDEX IF NOT EXISTS capabilitygrant_parent_grant_id
  ON capability_grants(parent_grant_id);

CREATE INDEX IF NOT EXISTS capabilitygrant_status_expires_at
  ON capability_grants(status, expires_at);

CREATE INDEX IF NOT EXISTS capabilitygrant_outcome_status_expected_outcome_by
  ON capability_grants(outcome_status, expected_outcome_by);
