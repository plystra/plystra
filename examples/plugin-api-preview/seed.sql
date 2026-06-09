-- Example fixture only.
-- This installs the old Moderation Lite preview plugin catalog rows into a
-- development database. It is intentionally outside Core production migrations:
-- Core owns the plugin registry substrate, not concrete reusable plugin content.

INSERT INTO plugins (id, key, name, description, version, source, status, manifest) VALUES (
	'plugin_moderation_lite',
	'plystra.moderation_lite',
	'Moderation Lite',
	'Preview plugin metadata for reports, review actions, and moderation audit events.',
	'0.1.0',
	'official',
	'enabled',
	'{
		"id": "plystra.moderation_lite",
		"name": "Moderation Lite",
		"description": "Preview plugin metadata for reports, review actions, and moderation audit events.",
		"version": "0.1.0",
		"source": "official",
		"status": "preview",
		"resources": [
			{
				"key": "report",
				"display_name": "Report",
				"actions": [
					{"key": "read", "risk_level": "normal"},
					{"key": "create", "risk_level": "normal"},
					{"key": "resolve", "risk_level": "high"},
					{"key": "dismiss", "risk_level": "high"}
				]
			}
		],
		"permissions": [
			{"resource": "report", "action": "read", "scopes": ["group_tree", "space"]},
			{"resource": "report", "action": "resolve", "scopes": ["group_tree", "space"]},
			{"resource": "report", "action": "dismiss", "scopes": ["group_tree", "space"]}
		],
		"audit_events": [
			{"key": "report.created", "risk_level": "normal"},
			{"key": "report.resolved", "risk_level": "high"},
			{"key": "report.dismissed", "risk_level": "high"}
		],
		"admin_menu": [
			{"label": "Moderation", "path": "/plugins/moderation", "required_permission": "report:read:group_tree"}
		],
		"settings": [
			{"key": "auto_hide_threshold", "type": "integer", "scope": "space", "description": "Hide content after this many open reports."}
		]
	}'::jsonb
)
ON CONFLICT (key) DO UPDATE SET
	name = EXCLUDED.name,
	description = EXCLUDED.description,
	version = EXCLUDED.version,
	source = EXCLUDED.source,
	status = EXCLUDED.status,
	manifest = EXCLUDED.manifest,
	updated_at = now();

INSERT INTO resource_types (id, key, display_name, description, status, source, metadata) VALUES
	('rt_report', 'report', 'Report', 'Moderation report registered by Moderation Lite.', 'active', 'plugin:plystra.moderation_lite', '{"plugin": "plystra.moderation_lite"}')
ON CONFLICT (key) DO UPDATE SET
	display_name = EXCLUDED.display_name,
	description = EXCLUDED.description,
	status = EXCLUDED.status,
	source = EXCLUDED.source,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO resource_actions (id, resource_type_id, key, display_name, description, risk_level, audit_default, metadata) VALUES
	('ra_report_read', 'rt_report', 'read', 'Read', 'Read reports.', 'normal', true, '{}'),
	('ra_report_create', 'rt_report', 'create', 'Create', 'Create reports.', 'normal', true, '{}'),
	('ra_report_resolve', 'rt_report', 'resolve', 'Resolve', 'Resolve reports.', 'high', true, '{}'),
	('ra_report_dismiss', 'rt_report', 'dismiss', 'Dismiss', 'Dismiss reports.', 'high', true, '{}')
ON CONFLICT (resource_type_id, key) DO UPDATE SET
	display_name = EXCLUDED.display_name,
	description = EXCLUDED.description,
	risk_level = EXCLUDED.risk_level,
	audit_default = EXCLUDED.audit_default,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO resource_mappings (
	id, resource_type_id, storage_kind, table_name, id_field, space_field, group_field, owner_member_field, visibility_field, metadata_field, status, metadata
) VALUES (
	'rm_report_plugin_managed', 'rt_report', 'plugin_managed', NULL, 'id', 'space_id', 'group_id', 'reporter_member_id', NULL, 'metadata', 'active', '{"plugin": "plystra.moderation_lite"}'
)
ON CONFLICT (resource_type_id) DO UPDATE SET
	storage_kind = EXCLUDED.storage_kind,
	table_name = EXCLUDED.table_name,
	id_field = EXCLUDED.id_field,
	space_field = EXCLUDED.space_field,
	group_field = EXCLUDED.group_field,
	owner_member_field = EXCLUDED.owner_member_field,
	visibility_field = EXCLUDED.visibility_field,
	metadata_field = EXCLUDED.metadata_field,
	status = EXCLUDED.status,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO permissions (id, resource, action, scope) VALUES
	('perm_report_read_group_tree', 'report', 'read', 'group_tree'),
	('perm_report_read_space', 'report', 'read', 'space'),
	('perm_report_resolve_group_tree', 'report', 'resolve', 'group_tree'),
	('perm_report_resolve_space', 'report', 'resolve', 'space'),
	('perm_report_dismiss_group_tree', 'report', 'dismiss', 'group_tree'),
	('perm_report_dismiss_space', 'report', 'dismiss', 'space')
ON CONFLICT (id) DO UPDATE SET
	resource = EXCLUDED.resource,
	action = EXCLUDED.action,
	scope = EXCLUDED.scope;

INSERT INTO audit_event_types (id, key, plugin_id, display_name, description, risk_level, default_audit, metadata) VALUES
	('aet_report_created', 'report.created', 'plugin_moderation_lite', 'Report Created', 'A moderation report was created.', 'normal', true, '{}'),
	('aet_report_resolved', 'report.resolved', 'plugin_moderation_lite', 'Report Resolved', 'A moderation report was resolved.', 'high', true, '{}'),
	('aet_report_dismissed', 'report.dismissed', 'plugin_moderation_lite', 'Report Dismissed', 'A moderation report was dismissed.', 'high', true, '{}')
ON CONFLICT (key) DO UPDATE SET
	plugin_id = EXCLUDED.plugin_id,
	display_name = EXCLUDED.display_name,
	description = EXCLUDED.description,
	risk_level = EXCLUDED.risk_level,
	default_audit = EXCLUDED.default_audit,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO plugin_admin_menus (id, plugin_id, label, path, icon, required_permission, sort_order, metadata) VALUES
	('pam_moderation_lite', 'plugin_moderation_lite', 'Moderation', '/plugins/moderation', 'shield', 'report:read:group_tree', 200, '{}')
ON CONFLICT (id) DO UPDATE SET
	label = EXCLUDED.label,
	path = EXCLUDED.path,
	icon = EXCLUDED.icon,
	required_permission = EXCLUDED.required_permission,
	sort_order = EXCLUDED.sort_order,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO plugin_settings_definitions (id, plugin_id, key, value_type, default_value, description, scope, metadata) VALUES
	('psd_moderation_auto_hide_threshold', 'plugin_moderation_lite', 'auto_hide_threshold', 'integer', '5'::jsonb, 'Hide content after this many open reports.', 'space', '{}')
ON CONFLICT (plugin_id, key, scope) DO UPDATE SET
	value_type = EXCLUDED.value_type,
	default_value = EXCLUDED.default_value,
	description = EXCLUDED.description,
	metadata = EXCLUDED.metadata,
	updated_at = now();
