-- Remove legacy finance demo business fixtures from Core.
--
-- Backend OS Alpha keeps Core as the governance/kernel layer. Real business
-- data belongs in governed business plugins with plugin-owned tables.

DELETE FROM audit_logs
WHERE resource_type = 'invoice'
  AND resource_id IN ('invoice_001', 'invoice_002')
  AND actor_user_id IN ('user_alice', 'user_bob');

DELETE FROM resources
WHERE id IN ('invoice_001', 'invoice_002')
  AND resource_type = 'invoice';

DELETE FROM role_permissions
WHERE role_id = 'role_finance_approver'
   OR permission_id IN (
    'perm_invoice_approve_group_tree',
    'perm_invoice_read_self',
    'perm_invoice_read_group_tree',
    'perm_invoice_create_group_tree',
    'perm_invoice_reject_group_tree',
    'perm_invoice_delete_space',
    'perm_invoice_update_group_tree',
    'perm_invoice_delete_group_tree'
  );

DELETE FROM member_roles
WHERE id = 'mr_finance_reviewer_approver_finance'
   OR role_id = 'role_finance_approver';

DELETE FROM roles
WHERE id = 'role_finance_approver';

DELETE FROM permissions
WHERE resource = 'invoice'
  AND id IN (
    'perm_invoice_approve_group_tree',
    'perm_invoice_read_self',
    'perm_invoice_read_group_tree',
    'perm_invoice_create_group_tree',
    'perm_invoice_reject_group_tree',
    'perm_invoice_delete_space',
    'perm_invoice_update_group_tree',
    'perm_invoice_delete_group_tree'
  );

DELETE FROM resource_actions
WHERE resource_type_id = 'rt_invoice';

DELETE FROM resource_mappings
WHERE resource_type_id = 'rt_invoice';

DELETE FROM resource_types
WHERE id = 'rt_invoice'
  AND key = 'invoice';

DELETE FROM sessions
WHERE user_id IN ('user_alice', 'user_bob');

DELETE FROM user_members
WHERE id IN (
  'um_alice_finance_reviewer',
  'um_bob_finance_reviewer',
  'um_alice_finance_reviewer_revoked',
  'um_alice_finance_reviewer_expired'
);

DELETE FROM admin_grants
WHERE user_id IN ('user_alice', 'user_bob')
  AND metadata->>'source' IN ('migration_013', 'auth.register.bootstrap', 'auth.register');

DELETE FROM users
WHERE id IN ('user_alice', 'user_bob')
  AND NOT EXISTS (
    SELECT 1 FROM audit_logs
    WHERE audit_logs.actor_user_id = users.id
  );

DELETE FROM members
WHERE id IN ('member_finance_reviewer', 'member_invoice_creator')
  AND NOT EXISTS (
    SELECT 1 FROM audit_logs
    WHERE audit_logs.actor_member_id = members.id
  );

DELETE FROM groups
WHERE id IN ('group_finance_apac', 'group_finance_emea', 'group_legal_emea');

DELETE FROM groups
WHERE id IN ('group_finance', 'group_legal')
  AND NOT EXISTS (
    SELECT 1 FROM groups child
    WHERE child.parent_group_id = groups.id
  );

DELETE FROM spaces
WHERE id = 'space_acme'
  AND NOT EXISTS (
    SELECT 1 FROM resources
    WHERE resources.space_id = spaces.id
  )
  AND NOT EXISTS (
    SELECT 1 FROM audit_logs
    WHERE audit_logs.space_id = spaces.id
  )
  AND NOT EXISTS (
    SELECT 1 FROM members
    WHERE members.space_id = spaces.id
  )
  AND NOT EXISTS (
    SELECT 1 FROM groups
    WHERE groups.space_id = spaces.id
  );
