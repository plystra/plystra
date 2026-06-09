-- purpose: add explicit Action Gateway reconciliation deadlines for result_unknown timeout handling.
-- rollback: export pending action_executions for reconciliation, then drop the timeout indexes and column.

ALTER TABLE action_executions
  ADD COLUMN IF NOT EXISTS timeout_at timestamptz;

UPDATE action_executions
  SET timeout_at = started_at + interval '10 seconds'
  WHERE timeout_at IS NULL;

ALTER TABLE action_executions
  ALTER COLUMN timeout_at SET NOT NULL;

CREATE INDEX IF NOT EXISTS actionexecution_status_timeout_at
  ON action_executions(status, timeout_at);
