-- Example fixture only.
-- Concrete reusable plugin catalog content belongs in plugin repos. This file
-- preserves the old demo catalog for local development without seeding it into
-- Core production migrations.

INSERT INTO plugins (id, key, name, description, version, source, status, manifest) VALUES
	(
		'plugin_webhooks',
		'plystra.webhooks',
		'Webhooks',
		'Send signed HTTP requests for Plystra events.',
		'0.0.1',
		'official',
		'enabled',
		'{"id":"plystra.webhooks","name":"Webhooks","description":"Send signed HTTP requests for Plystra events.","version":"0.0.1","source":"official","status":"enabled","manifest_version":"1.0","plugin_api_version":"1.0","requires_core":">=0.0.1 <0.1.0","resources":[{"key":"webhook_endpoint","display_name":"Webhook Endpoint","actions":[{"key":"read","risk_level":"normal"},{"key":"create","risk_level":"normal"},{"key":"update","risk_level":"normal"},{"key":"delete","risk_level":"high"}]},{"key":"webhook_delivery","display_name":"Webhook Delivery","actions":[{"key":"read","risk_level":"normal"},{"key":"retry","risk_level":"high"}]}],"permissions":[{"resource":"webhook_endpoint","action":"read","scopes":["space"]},{"resource":"webhook_endpoint","action":"create","scopes":["space"]},{"resource":"webhook_endpoint","action":"update","scopes":["space"]},{"resource":"webhook_endpoint","action":"delete","scopes":["space"]},{"resource":"webhook_delivery","action":"read","scopes":["space"]},{"resource":"webhook_delivery","action":"retry","scopes":["space"]}],"audit_events":[{"key":"webhook.delivery.created","risk_level":"normal"},{"key":"webhook.delivery.failed","risk_level":"high"}],"admin_menu":[{"label":"Webhooks","path":"/plugins/webhooks","required_permission":"webhook_endpoint:read:space"}],"settings":[{"key":"delivery_timeout_ms","type":"integer","scope":"space","description":"Webhook delivery timeout."}]}'::jsonb
	),
	(
		'plugin_api_keys',
		'plystra.api_keys',
		'API Keys',
		'Issue and revoke scoped API keys.',
		'0.0.1',
		'official',
		'enabled',
		'{"id":"plystra.api_keys","name":"API Keys","description":"Issue and revoke scoped API keys.","version":"0.0.1","source":"official","status":"enabled","manifest_version":"1.0","plugin_api_version":"1.0","requires_core":">=0.0.1 <0.1.0","resources":[{"key":"api_key","display_name":"API Key","actions":[{"key":"read","risk_level":"normal"},{"key":"create","risk_level":"high"},{"key":"revoke","risk_level":"high"}]}],"permissions":[{"resource":"api_key","action":"read","scopes":["space"]},{"resource":"api_key","action":"create","scopes":["space"]},{"resource":"api_key","action":"revoke","scopes":["space"]}],"audit_events":[{"key":"api_key.created","risk_level":"high"},{"key":"api_key.revoked","risk_level":"high"}],"admin_menu":[{"label":"API Keys","path":"/plugins/api-keys","required_permission":"api_key:read:space"}],"settings":[{"key":"max_key_ttl_days","type":"integer","scope":"space","description":"Maximum API key lifetime in days."}],"capabilities":[{"id":"api_key.credential","version":"0.0.1","level":"standard","description":"Issues and revokes scoped API keys governed by Plystra Core.","audit":{"enforcement":"controlled_action"},"data_plane":{"allowed":["core_data_api"]},"operations":[{"name":"create","invocation":{"mode":"brokered_action_gateway","idempotency":"required","timeout_ms":10000,"result_unknown_reconciliation":"required"},"delegation":{"mode":"preserve_principal"},"call_graph":{"max_depth":2,"reentrant":false}},{"name":"revoke","invocation":{"mode":"brokered_action_gateway","idempotency":"required","timeout_ms":10000,"result_unknown_reconciliation":"required"},"delegation":{"mode":"preserve_principal"},"call_graph":{"max_depth":2,"reentrant":false}}]}]}'::jsonb
	),
	(
		'plugin_notifications',
		'plystra.notifications',
		'Notifications',
		'Manage notification channels and delivery records.',
		'0.0.1',
		'official',
		'enabled',
		'{"id":"plystra.notifications","name":"Notifications","description":"Manage notification channels and delivery records.","version":"0.0.1","source":"official","status":"enabled","manifest_version":"1.0","plugin_api_version":"1.0","requires_core":">=0.0.1 <0.1.0","resources":[{"key":"notification_channel","display_name":"Notification Channel","actions":[{"key":"read","risk_level":"normal"},{"key":"create","risk_level":"normal"},{"key":"update","risk_level":"normal"},{"key":"delete","risk_level":"high"}]},{"key":"notification_delivery","display_name":"Notification Delivery","actions":[{"key":"read","risk_level":"normal"}]}],"permissions":[{"resource":"notification_channel","action":"read","scopes":["space"]},{"resource":"notification_channel","action":"create","scopes":["space"]},{"resource":"notification_channel","action":"update","scopes":["space"]},{"resource":"notification_channel","action":"delete","scopes":["space"]},{"resource":"notification_delivery","action":"read","scopes":["space"]}],"audit_events":[{"key":"notification.sent","risk_level":"normal"},{"key":"notification.failed","risk_level":"normal"}],"admin_menu":[{"label":"Notifications","path":"/plugins/notifications","required_permission":"notification_channel:read:space"}],"settings":[{"key":"default_channel","type":"string","scope":"space","description":"Default notification channel key."}]}'::jsonb
	),
	(
		'plugin_moderation',
		'plystra.moderation',
		'Moderation',
		'Moderation primitives for reports and review actions.',
		'0.0.1',
		'official',
		'enabled',
		'{"id":"plystra.moderation","name":"Moderation","description":"Moderation primitives for reports and review actions.","version":"0.0.1","source":"official","status":"enabled","manifest_version":"1.0","plugin_api_version":"1.0","requires_core":">=0.0.1 <0.1.0","resources":[{"key":"report","display_name":"Report","actions":[{"key":"read","risk_level":"normal"},{"key":"create","risk_level":"normal"},{"key":"resolve","risk_level":"high"},{"key":"dismiss","risk_level":"high"}]}],"permissions":[{"resource":"report","action":"read","scopes":["group_tree","space"]},{"resource":"report","action":"create","scopes":["group_tree","space"]},{"resource":"report","action":"resolve","scopes":["group_tree","space"]},{"resource":"report","action":"dismiss","scopes":["group_tree","space"]}],"audit_events":[{"key":"report.created","risk_level":"normal"},{"key":"report.resolved","risk_level":"high"},{"key":"report.dismissed","risk_level":"high"}],"admin_menu":[{"label":"Moderation","path":"/plugins/moderation","required_permission":"report:read:group_tree"}],"settings":[{"key":"auto_hide_threshold","type":"integer","scope":"space","description":"Hide content after this many open reports."}]}'::jsonb
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
	('rt_webhook_endpoint', 'webhook_endpoint', 'Webhook Endpoint', 'Configured webhook endpoint.', 'active', 'plugin:plystra.webhooks', '{"plugin":"plystra.webhooks"}'),
	('rt_webhook_delivery', 'webhook_delivery', 'Webhook Delivery', 'Webhook delivery attempt.', 'active', 'plugin:plystra.webhooks', '{"plugin":"plystra.webhooks"}'),
	('rt_api_key', 'api_key', 'API Key', 'Scoped API key.', 'active', 'plugin:plystra.api_keys', '{"plugin":"plystra.api_keys"}'),
	('rt_notification_channel', 'notification_channel', 'Notification Channel', 'Notification channel.', 'active', 'plugin:plystra.notifications', '{"plugin":"plystra.notifications"}'),
	('rt_notification_delivery', 'notification_delivery', 'Notification Delivery', 'Notification delivery.', 'active', 'plugin:plystra.notifications', '{"plugin":"plystra.notifications"}'),
	('rt_report', 'report', 'Report', 'Moderation report.', 'active', 'plugin:plystra.moderation', '{"plugin":"plystra.moderation"}')
ON CONFLICT (key) DO UPDATE SET
	display_name = EXCLUDED.display_name,
	description = EXCLUDED.description,
	status = EXCLUDED.status,
	source = EXCLUDED.source,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO resource_actions (id, resource_type_id, key, display_name, description, risk_level, audit_default, metadata) VALUES
	('ra_webhook_endpoint_read', 'rt_webhook_endpoint', 'read', 'Read', 'Read webhook endpoints.', 'normal', true, '{}'),
	('ra_webhook_endpoint_create', 'rt_webhook_endpoint', 'create', 'Create', 'Create webhook endpoints.', 'normal', true, '{}'),
	('ra_webhook_endpoint_update', 'rt_webhook_endpoint', 'update', 'Update', 'Update webhook endpoints.', 'normal', true, '{}'),
	('ra_webhook_endpoint_delete', 'rt_webhook_endpoint', 'delete', 'Delete', 'Delete webhook endpoints.', 'high', true, '{}'),
	('ra_webhook_delivery_read', 'rt_webhook_delivery', 'read', 'Read', 'Read webhook deliveries.', 'normal', true, '{}'),
	('ra_webhook_delivery_retry', 'rt_webhook_delivery', 'retry', 'Retry', 'Retry webhook deliveries.', 'high', true, '{}'),
	('ra_api_key_read', 'rt_api_key', 'read', 'Read', 'Read API keys.', 'normal', true, '{}'),
	('ra_api_key_create', 'rt_api_key', 'create', 'Create', 'Create API keys.', 'high', true, '{}'),
	('ra_api_key_revoke', 'rt_api_key', 'revoke', 'Revoke', 'Revoke API keys.', 'high', true, '{}'),
	('ra_notification_channel_read', 'rt_notification_channel', 'read', 'Read', 'Read notification channels.', 'normal', true, '{}'),
	('ra_notification_channel_create', 'rt_notification_channel', 'create', 'Create', 'Create notification channels.', 'normal', true, '{}'),
	('ra_notification_channel_update', 'rt_notification_channel', 'update', 'Update', 'Update notification channels.', 'normal', true, '{}'),
	('ra_notification_channel_delete', 'rt_notification_channel', 'delete', 'Delete', 'Delete notification channels.', 'high', true, '{}'),
	('ra_notification_delivery_read', 'rt_notification_delivery', 'read', 'Read', 'Read notification deliveries.', 'normal', true, '{}'),
	('ra_report_create', 'rt_report', 'create', 'Create', 'Create reports.', 'normal', true, '{}')
ON CONFLICT (resource_type_id, key) DO UPDATE SET
	display_name = EXCLUDED.display_name,
	description = EXCLUDED.description,
	risk_level = EXCLUDED.risk_level,
	audit_default = EXCLUDED.audit_default,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO resource_mappings (
	id, resource_type_id, storage_kind, table_name, id_field, space_field, group_field, owner_member_field, visibility_field, metadata_field, status, metadata
) VALUES
	('rm_webhook_endpoint_plugin', 'rt_webhook_endpoint', 'plugin_managed', NULL, 'id', 'space_id', NULL, 'owner_member_id', NULL, 'metadata', 'active', '{"plugin":"plystra.webhooks"}'),
	('rm_webhook_delivery_plugin', 'rt_webhook_delivery', 'plugin_managed', NULL, 'id', 'space_id', NULL, NULL, NULL, 'metadata', 'active', '{"plugin":"plystra.webhooks"}'),
	('rm_api_key_plugin', 'rt_api_key', 'plugin_managed', NULL, 'id', 'space_id', NULL, 'owner_member_id', NULL, 'metadata', 'active', '{"plugin":"plystra.api_keys"}'),
	('rm_notification_channel_plugin', 'rt_notification_channel', 'plugin_managed', NULL, 'id', 'space_id', NULL, 'owner_member_id', NULL, 'metadata', 'active', '{"plugin":"plystra.notifications"}'),
	('rm_notification_delivery_plugin', 'rt_notification_delivery', 'plugin_managed', NULL, 'id', 'space_id', NULL, NULL, NULL, 'metadata', 'active', '{"plugin":"plystra.notifications"}')
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
	('perm_webhook_endpoint_read_space', 'webhook_endpoint', 'read', 'space'),
	('perm_webhook_endpoint_create_space', 'webhook_endpoint', 'create', 'space'),
	('perm_webhook_endpoint_update_space', 'webhook_endpoint', 'update', 'space'),
	('perm_webhook_endpoint_delete_space', 'webhook_endpoint', 'delete', 'space'),
	('perm_webhook_delivery_read_space', 'webhook_delivery', 'read', 'space'),
	('perm_webhook_delivery_retry_space', 'webhook_delivery', 'retry', 'space'),
	('perm_api_key_read_space', 'api_key', 'read', 'space'),
	('perm_api_key_create_space', 'api_key', 'create', 'space'),
	('perm_api_key_revoke_space', 'api_key', 'revoke', 'space'),
	('perm_notification_channel_read_space', 'notification_channel', 'read', 'space'),
	('perm_notification_channel_create_space', 'notification_channel', 'create', 'space'),
	('perm_notification_channel_update_space', 'notification_channel', 'update', 'space'),
	('perm_notification_channel_delete_space', 'notification_channel', 'delete', 'space'),
	('perm_notification_delivery_read_space', 'notification_delivery', 'read', 'space'),
	('perm_report_create_group_tree', 'report', 'create', 'group_tree'),
	('perm_report_create_space', 'report', 'create', 'space')
ON CONFLICT (id) DO UPDATE SET
	resource = EXCLUDED.resource,
	action = EXCLUDED.action,
	scope = EXCLUDED.scope;

INSERT INTO audit_event_types (id, key, plugin_id, display_name, description, risk_level, default_audit, metadata) VALUES
	('aet_webhook_delivery_created', 'webhook.delivery.created', 'plugin_webhooks', 'Webhook Delivery Created', 'A webhook delivery was queued.', 'normal', true, '{}'),
	('aet_webhook_delivery_failed', 'webhook.delivery.failed', 'plugin_webhooks', 'Webhook Delivery Failed', 'A webhook delivery failed.', 'high', true, '{}'),
	('aet_api_key_created', 'api_key.created', 'plugin_api_keys', 'API Key Created', 'An API key was created.', 'high', true, '{}'),
	('aet_api_key_revoked', 'api_key.revoked', 'plugin_api_keys', 'API Key Revoked', 'An API key was revoked.', 'high', true, '{}'),
	('aet_notification_sent', 'notification.sent', 'plugin_notifications', 'Notification Sent', 'A notification was sent.', 'normal', true, '{}'),
	('aet_notification_failed', 'notification.failed', 'plugin_notifications', 'Notification Failed', 'A notification failed.', 'normal', true, '{}')
ON CONFLICT (key) DO UPDATE SET
	plugin_id = EXCLUDED.plugin_id,
	display_name = EXCLUDED.display_name,
	description = EXCLUDED.description,
	risk_level = EXCLUDED.risk_level,
	default_audit = EXCLUDED.default_audit,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO plugin_admin_menus (id, plugin_id, label, path, icon, required_permission, sort_order, metadata) VALUES
	('pam_webhooks', 'plugin_webhooks', 'Webhooks', '/plugins/webhooks', 'webhook', 'webhook_endpoint:read:space', 210, '{}'),
	('pam_api_keys', 'plugin_api_keys', 'API Keys', '/plugins/api-keys', 'key', 'api_key:read:space', 220, '{}'),
	('pam_notifications', 'plugin_notifications', 'Notifications', '/plugins/notifications', 'bell', 'notification_channel:read:space', 230, '{}'),
	('pam_moderation', 'plugin_moderation', 'Moderation', '/plugins/moderation', 'shield', 'report:read:group_tree', 200, '{}')
ON CONFLICT (id) DO UPDATE SET
	label = EXCLUDED.label,
	path = EXCLUDED.path,
	icon = EXCLUDED.icon,
	required_permission = EXCLUDED.required_permission,
	sort_order = EXCLUDED.sort_order,
	metadata = EXCLUDED.metadata,
	updated_at = now();

INSERT INTO plugin_settings_definitions (id, plugin_id, key, value_type, default_value, description, scope, metadata) VALUES
	('psd_webhooks_delivery_timeout_ms', 'plugin_webhooks', 'delivery_timeout_ms', 'integer', '{"value":5000}'::jsonb, 'Webhook delivery timeout.', 'space', '{}'),
	('psd_api_keys_max_key_ttl_days', 'plugin_api_keys', 'max_key_ttl_days', 'integer', '{"value":90}'::jsonb, 'Maximum API key lifetime in days.', 'space', '{}'),
	('psd_notifications_default_channel', 'plugin_notifications', 'default_channel', 'string', '{"value":null}'::jsonb, 'Default notification channel key.', 'space', '{}'),
	('psd_moderation_auto_hide_threshold_v1', 'plugin_moderation', 'auto_hide_threshold', 'integer', '{"value":5}'::jsonb, 'Hide content after this many open reports.', 'space', '{}')
ON CONFLICT (plugin_id, key, scope) DO UPDATE SET
	value_type = EXCLUDED.value_type,
	default_value = EXCLUDED.default_value,
	description = EXCLUDED.description,
	metadata = EXCLUDED.metadata,
	updated_at = now();
