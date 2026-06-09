-- purpose: remove the app-data model trigger that mutated Core resource registry tables outside Ent.
-- rollback: intentionally unavailable; app-data model resource registration is Core-owned application logic.

DROP TRIGGER IF EXISTS trg_register_app_data_model_resource ON app_data_models;
DROP FUNCTION IF EXISTS plystra_register_app_data_model_resource();
