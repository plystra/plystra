-- Align app data tables with the Ent-managed schema used by doctor/readiness.
--
-- API validation and Ent hooks enforce same-space and lifecycle invariants.
-- These constraints were introduced manually in the initial app data migration
-- and caused schema drift in the production readiness check.

DROP TRIGGER IF EXISTS trg_register_app_data_model_resource ON app_data_models;
DROP FUNCTION IF EXISTS plystra_register_app_data_model_resource();

ALTER TABLE app_data_models
  DROP CONSTRAINT IF EXISTS app_data_models_key_format,
  DROP CONSTRAINT IF EXISTS app_data_models_space_id_fkey,
  ALTER COLUMN id TYPE character varying,
  ALTER COLUMN space_id TYPE character varying,
  ALTER COLUMN key TYPE character varying,
  ALTER COLUMN display_name TYPE character varying,
  ALTER COLUMN description TYPE character varying,
  ALTER COLUMN source TYPE character varying,
  ALTER COLUMN status TYPE character varying,
  ALTER COLUMN metadata DROP NOT NULL;

ALTER TABLE app_data_records
  DROP CONSTRAINT IF EXISTS app_data_records_model_key_format,
  DROP CONSTRAINT IF EXISTS app_data_records_group_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_records_model_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_records_owner_member_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_records_space_id_fkey,
  ALTER COLUMN id TYPE character varying,
  ALTER COLUMN space_id TYPE character varying,
  ALTER COLUMN model_id TYPE character varying,
  ALTER COLUMN model_key TYPE character varying,
  ALTER COLUMN group_id TYPE character varying,
  ALTER COLUMN owner_member_id TYPE character varying,
  ALTER COLUMN display_name TYPE character varying,
  ALTER COLUMN visibility TYPE character varying,
  ALTER COLUMN status TYPE character varying,
  ALTER COLUMN metadata DROP NOT NULL;

ALTER TABLE app_data_record_revisions
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_revision_positive,
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_actor_member_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_actor_user_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_actor_user_member_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_model_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_record_id_fkey,
  DROP CONSTRAINT IF EXISTS app_data_record_revisions_space_id_fkey,
  ALTER COLUMN id TYPE character varying,
  ALTER COLUMN record_id TYPE character varying,
  ALTER COLUMN space_id TYPE character varying,
  ALTER COLUMN model_id TYPE character varying,
  ALTER COLUMN model_key TYPE character varying,
  ALTER COLUMN revision TYPE bigint,
  ALTER COLUMN operation TYPE character varying,
  ALTER COLUMN actor_user_id TYPE character varying,
  ALTER COLUMN actor_member_id TYPE character varying,
  ALTER COLUMN actor_user_member_id TYPE character varying,
  ALTER COLUMN metadata DROP NOT NULL;
