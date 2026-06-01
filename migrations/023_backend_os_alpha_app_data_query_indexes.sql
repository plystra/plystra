-- Add production query indexes for Backend OS Alpha App Data list views.

CREATE INDEX IF NOT EXISTS appdatarecord_space_model_updated_id
  ON app_data_records(space_id, model_key, updated_at DESC, id DESC)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS appdatarecord_space_model_created_id
  ON app_data_records(space_id, model_key, created_at DESC, id DESC)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS appdatarecord_space_model_status_updated_id
  ON app_data_records(space_id, model_key, status, updated_at DESC, id DESC)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS appdatarecord_space_model_visibility_updated_id
  ON app_data_records(space_id, model_key, visibility, updated_at DESC, id DESC)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS appdatarecord_space_model_group_updated_id
  ON app_data_records(space_id, model_key, group_id, updated_at DESC, id DESC)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS appdatarecord_space_model_owner_updated_id
  ON app_data_records(space_id, model_key, owner_member_id, updated_at DESC, id DESC)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS appdatarecord_data_gin
  ON app_data_records USING GIN (data jsonb_path_ops)
  WHERE deleted_at IS NULL;
