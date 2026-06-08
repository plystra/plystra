-- purpose: add Core-governed provider bindings for Space-scoped capability resolution.
-- rollback: export active capability_provider_bindings for operator review, then drop the table.

CREATE TABLE IF NOT EXISTS capability_provider_bindings (
  id varchar NOT NULL PRIMARY KEY,
  space_id varchar NOT NULL,
  capability varchar NOT NULL,
  operation varchar NOT NULL,
  provider_plugin_id varchar NOT NULL,
  endpoint varchar NOT NULL,
  operation_path varchar NULL,
  binding_epoch bigint NOT NULL DEFAULT 1,
  status varchar NOT NULL DEFAULT 'active',
  identity jsonb NOT NULL DEFAULT '{}'::jsonb,
  metadata jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS capabilityproviderbinding_space_id_capability_operation
  ON capability_provider_bindings(space_id, capability, operation);

CREATE INDEX IF NOT EXISTS capabilityproviderbinding_space_id_provider_plugin_id_status
  ON capability_provider_bindings(space_id, provider_plugin_id, status);

CREATE INDEX IF NOT EXISTS capabilityproviderbinding_capability_operation_status
  ON capability_provider_bindings(capability, operation, status);
