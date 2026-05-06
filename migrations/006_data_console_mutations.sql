INSERT INTO resource_actions (id, resource_type_id, key, display_name, description, risk_level, audit_default, metadata) VALUES
	('ra_invoice_update', 'rt_invoice', 'update', 'Update', 'Update invoice fields through the Data Console.', 'normal', true, '{}')
ON CONFLICT (resource_type_id, key) DO UPDATE SET
	display_name = EXCLUDED.display_name,
	description = EXCLUDED.description,
	risk_level = EXCLUDED.risk_level,
	audit_default = EXCLUDED.audit_default,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO permissions (id, resource, action, scope) VALUES
	('perm_invoice_update_group_tree', 'invoice', 'update', 'group_tree'),
	('perm_invoice_delete_group_tree', 'invoice', 'delete', 'group_tree')
ON CONFLICT (id) DO UPDATE SET
	resource = EXCLUDED.resource,
	action = EXCLUDED.action,
	scope = EXCLUDED.scope;

INSERT INTO role_permissions (role_id, permission_id) VALUES
	('role_finance_approver', 'perm_invoice_read_group_tree'),
	('role_finance_approver', 'perm_invoice_create_group_tree'),
	('role_finance_approver', 'perm_invoice_update_group_tree'),
	('role_finance_approver', 'perm_invoice_delete_group_tree')
ON CONFLICT (role_id, permission_id) DO NOTHING;
