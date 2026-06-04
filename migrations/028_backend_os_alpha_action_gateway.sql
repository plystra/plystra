-- purpose: add the Action Gateway execution journal for brokered controlled_action invocations.
-- rollback: export action_executions for audit retention, then drop the table.

CREATE TABLE IF NOT EXISTS action_executions (
  id varchar NOT NULL PRIMARY KEY,
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
  status varchar NOT NULL DEFAULT 'invoking',
  handler_endpoint varchar NULL,
  idempotency_expires_at timestamptz NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS actionexecution_space_id_capability_operation_idempotency_key
  ON action_executions(space_id, capability, operation, idempotency_key);

CREATE INDEX IF NOT EXISTS actionexecution_space_id_status
  ON action_executions(space_id, status);

CREATE INDEX IF NOT EXISTS actionexecution_correlation_id
  ON action_executions(correlation_id);

CREATE INDEX IF NOT EXISTS actionexecution_status_idempotency_expires_at
  ON action_executions(status, idempotency_expires_at);
