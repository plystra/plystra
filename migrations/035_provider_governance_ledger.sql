-- purpose: add Core-owned provider installation and migration governance ledgers.
-- rollback: export provider_installations/provider_migration_revisions/provider_migration_steps before dropping.

CREATE TABLE IF NOT EXISTS provider_installations (
  id varchar PRIMARY KEY,
  provider_plugin_id varchar NOT NULL,
  plugin_type varchar NOT NULL,
  plugin_scope varchar NOT NULL,
  app_id varchar NULL,
  trust_bundle_id varchar NULL,
  schema_name varchar NOT NULL,
  migrator_role varchar NOT NULL,
  runtime_role varchar NOT NULL,
  schema_version bigint NOT NULL DEFAULT 0,
  runtime_schema_min bigint NOT NULL DEFAULT 0,
  runtime_schema_max bigint NOT NULL DEFAULT 0,
  runtime_schema_preferred bigint NOT NULL DEFAULT 0,
  rls_required boolean NOT NULL DEFAULT true,
  zero_ddl_runtime boolean NOT NULL DEFAULT true,
  mutation_journal_required boolean NOT NULL DEFAULT false,
  status varchar NOT NULL DEFAULT 'planned',
  metadata jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS providerinstallation_provider_plugin_id
  ON provider_installations(provider_plugin_id);

CREATE INDEX IF NOT EXISTS providerinstallation_schema_name
  ON provider_installations(schema_name);

CREATE UNIQUE INDEX IF NOT EXISTS providerinstallation_runtime_role
  ON provider_installations(runtime_role);

CREATE UNIQUE INDEX IF NOT EXISTS providerinstallation_migrator_role
  ON provider_installations(migrator_role);

CREATE INDEX IF NOT EXISTS providerinstallation_plugin_type_plugin_scope_status
  ON provider_installations(plugin_type, plugin_scope, status);

CREATE INDEX IF NOT EXISTS providerinstallation_app_id_status
  ON provider_installations(app_id, status);

CREATE INDEX IF NOT EXISTS providerinstallation_trust_bundle_id_status
  ON provider_installations(trust_bundle_id, status);

CREATE TABLE IF NOT EXISTS provider_migration_revisions (
  id varchar PRIMARY KEY,
  provider_plugin_id varchar NOT NULL,
  installation_id varchar NOT NULL,
  revision varchar NOT NULL,
  bundle_hash varchar NOT NULL,
  schema_name varchar NOT NULL,
  from_schema_version bigint NOT NULL DEFAULT 0,
  to_schema_version bigint NOT NULL DEFAULT 0,
  status varchar NOT NULL DEFAULT 'planned',
  destructive boolean NOT NULL DEFAULT false,
  rls_bypass boolean NOT NULL DEFAULT false,
  requires_manual_review boolean NOT NULL DEFAULT false,
  reviewed_by_user_id varchar NULL,
  reviewed_at timestamptz NULL,
  started_at timestamptz NULL,
  finished_at timestamptz NULL,
  last_error varchar NULL,
  metadata jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS providermigrationrevision_provider_plugin_id_revision
  ON provider_migration_revisions(provider_plugin_id, revision);

CREATE INDEX IF NOT EXISTS providermigrationrevision_installation_id_status
  ON provider_migration_revisions(installation_id, status);

CREATE INDEX IF NOT EXISTS providermigrationrevision_provider_plugin_id_status
  ON provider_migration_revisions(provider_plugin_id, status);

CREATE INDEX IF NOT EXISTS providermigrationrevision_bundle_hash
  ON provider_migration_revisions(bundle_hash);

CREATE TABLE IF NOT EXISTS provider_migration_steps (
  id varchar PRIMARY KEY,
  revision_id varchar NOT NULL,
  provider_plugin_id varchar NOT NULL,
  step_index bigint NOT NULL,
  statement_hash varchar NOT NULL,
  statement_kind varchar NOT NULL,
  status varchar NOT NULL DEFAULT 'planned',
  destructive boolean NOT NULL DEFAULT false,
  backfill boolean NOT NULL DEFAULT false,
  tenant_scope_reviewed boolean NOT NULL DEFAULT false,
  rls_bypass boolean NOT NULL DEFAULT false,
  precondition varchar NULL,
  recovery_action varchar NULL,
  started_at timestamptz NULL,
  finished_at timestamptz NULL,
  error varchar NULL,
  metadata jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS providermigrationstep_revision_id_step_index
  ON provider_migration_steps(revision_id, step_index);

CREATE INDEX IF NOT EXISTS providermigrationstep_provider_plugin_id_status
  ON provider_migration_steps(provider_plugin_id, status);

CREATE INDEX IF NOT EXISTS providermigrationstep_statement_hash
  ON provider_migration_steps(statement_hash);

INSERT INTO provider_installations (
  id,
  provider_plugin_id,
  plugin_type,
  plugin_scope,
  app_id,
  trust_bundle_id,
  schema_name,
  migrator_role,
  runtime_role,
  runtime_schema_min,
  runtime_schema_max,
  runtime_schema_preferred,
  rls_required,
  zero_ddl_runtime,
  mutation_journal_required,
  status,
  metadata
)
SELECT
  'pinst_' || regexp_replace(key, '[^a-zA-Z0-9]+', '_', 'g'),
  key,
  COALESCE(NULLIF(type, ''), 'plugin'),
  COALESCE(NULLIF(scope, ''), 'public'),
  app_id,
  trust_bundle_id,
  CASE
    WHEN COALESCE(NULLIF(type, ''), 'plugin') = 'app_module' AND app_id IS NOT NULL
      THEN 'app_' || regexp_replace(app_id, '[^a-zA-Z0-9]+', '_', 'g')
    ELSE 'plg_' || regexp_replace(key, '[^a-zA-Z0-9]+', '_', 'g')
  END,
  CASE
    WHEN COALESCE(NULLIF(type, ''), 'plugin') = 'app_module' AND app_id IS NOT NULL
      THEN 'app_' || regexp_replace(app_id, '[^a-zA-Z0-9]+', '_', 'g') || '_' || regexp_replace(key, '[^a-zA-Z0-9]+', '_', 'g') || '_migrator_owner'
    ELSE 'plg_' || regexp_replace(key, '[^a-zA-Z0-9]+', '_', 'g') || '_migrator_owner'
  END,
  CASE
    WHEN COALESCE(NULLIF(type, ''), 'plugin') = 'app_module' AND app_id IS NOT NULL
      THEN 'app_' || regexp_replace(app_id, '[^a-zA-Z0-9]+', '_', 'g') || '_' || regexp_replace(key, '[^a-zA-Z0-9]+', '_', 'g') || '_runtime'
    ELSE 'plg_' || regexp_replace(key, '[^a-zA-Z0-9]+', '_', 'g') || '_runtime'
  END,
  COALESCE((manifest->'runtime'->'schema_compatibility'->>'min')::int, 0),
  COALESCE((manifest->'runtime'->'schema_compatibility'->>'max')::int, 0),
  COALESCE((manifest->'runtime'->'schema_compatibility'->>'preferred')::int, 0),
  true,
  true,
  EXISTS (
    SELECT 1
    FROM jsonb_array_elements(COALESCE(manifest->'capabilities', '[]'::jsonb)) AS cap
    WHERE cap->'audit'->>'enforcement' = 'observed_mutation'
  )
    OR EXISTS (
      SELECT 1
      FROM jsonb_array_elements(COALESCE(manifest->'local_capabilities', '[]'::jsonb)) AS cap
      WHERE cap->'audit'->>'enforcement' = 'observed_mutation'
    ),
  'planned',
  jsonb_build_object(
    'source', 'migration_035_backfill',
    'data_planes', jsonb_build_object(
      'capabilities', COALESCE(manifest->'capabilities', '[]'::jsonb),
      'local_capabilities', COALESCE(manifest->'local_capabilities', '[]'::jsonb)
    )
  )
FROM plugins
WHERE (
    EXISTS (
      SELECT 1
      FROM jsonb_array_elements(COALESCE(manifest->'capabilities', '[]'::jsonb)) AS cap
      WHERE COALESCE(cap->'data_plane'->'allowed', '[]'::jsonb) ?| ARRAY['direct_db', 'direct_db_with_mutation_journal']
    )
    OR EXISTS (
      SELECT 1
      FROM jsonb_array_elements(COALESCE(manifest->'local_capabilities', '[]'::jsonb)) AS cap
      WHERE COALESCE(cap->'data_plane'->'allowed', '[]'::jsonb) ?| ARRAY['direct_db', 'direct_db_with_mutation_journal']
    )
  )
ON CONFLICT (provider_plugin_id) DO NOTHING;
