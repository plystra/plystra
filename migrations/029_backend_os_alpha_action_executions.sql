-- purpose: add the Core Action Gateway execution ledger for controlled_action capability operations.
-- rollback: export action_executions for reconciliation, then drop the table.

CREATE TABLE IF NOT EXISTS action_executions (
  id varchar NOT NULL PRIMARY KEY,
  space_id varchar NOT NULL,
  capability varchar NOT NULL,
  operation varchar NOT NULL,
  resource_type varchar NOT NULL,
  resource_id varchar NOT NULL,
  resource_action varchar NOT NULL,
  principal_user_id varchar NULL,
  principal_member_id varchar NULL,
  principal_user_member_id varchar NULL,
  executor_plugin_id varchar NOT NULL,
  provider_plugin_id varchar NOT NULL,
  decision_id varchar NULL,
  correlation_id varchar NOT NULL,
  idempotency_key varchar NOT NULL,
  status varchar NOT NULL DEFAULT 'running',
  started_at timestamptz NOT NULL,
  completed_at timestamptz NULL,
  resource jsonb NOT NULL DEFAULT '{}'::jsonb,
  input_summary jsonb NULL,
  result_ref jsonb NULL,
  error_code varchar NULL,
  error_message varchar NULL,
  metadata jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS actionexecution_space_id_execu_d82e44fdcab45b5a3a30b7c299ee9cb0
  ON action_executions(space_id, executor_plugin_id, capability, operation, idempotency_key);

CREATE UNIQUE INDEX IF NOT EXISTS actionexecution_space_id_provi_88fa7022cc83a6b7d4d4ba58bcf5f61d
  ON action_executions(space_id, provider_plugin_id, capability, operation, idempotency_key);

CREATE INDEX IF NOT EXISTS actionexecution_space_id_resource_type_resource_id
  ON action_executions(space_id, resource_type, resource_id);

CREATE INDEX IF NOT EXISTS actionexecution_space_id_capability_operation_status
  ON action_executions(space_id, capability, operation, status);

CREATE INDEX IF NOT EXISTS actionexecution_status_started_at
  ON action_executions(status, started_at);

CREATE INDEX IF NOT EXISTS actionexecution_correlation_id
  ON action_executions(correlation_id);
