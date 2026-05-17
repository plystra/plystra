-- purpose: ensure production migrations do not leave behind the historical
-- demo instance super admin grant.
-- affected tables: admin_grants.
-- rollback strategy: recreate the first instance super admin through
-- plystractl admin bootstrap-super-admin or the protected bootstrap
-- registration flow.

DELETE FROM admin_grants
WHERE id = 'ag_alice_instance_super_admin'
	AND user_id = 'user_alice'
	AND level = 'instance_super_admin'
	AND permission_key = '*'
	AND status = 'active'
	AND metadata = '{"source":"migration_013","reason":"demo bootstrap super admin"}'::jsonb;
