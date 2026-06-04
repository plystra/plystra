-- purpose: align official plugin metadata with Backend OS Alpha versioning and governed capability contracts.
-- rollback: restore previous plugin manifest snapshots from backup if required.

UPDATE plugins
SET version = '0.0.1',
	manifest = jsonb_set(
		jsonb_set(manifest, '{version}', '"0.0.1"'::jsonb, true),
		'{requires_core}',
		'">=0.0.1 <0.1.0"'::jsonb,
		true
	),
	updated_at = now()
WHERE key IN ('plystra.webhooks', 'plystra.api_keys', 'plystra.notifications', 'plystra.moderation');

UPDATE plugins
SET manifest = jsonb_set(
	manifest,
	'{capabilities}',
	'[
		{
			"id": "api_key.credential",
			"version": "0.0.1",
			"level": "standard",
			"description": "Issues and revokes scoped API keys governed by Plystra Core.",
			"audit": {"enforcement": "controlled_action"},
			"data_plane": {"allowed": ["core_data_api"]},
			"operations": [
				{
					"name": "create",
					"invocation": {
						"mode": "brokered_action_gateway",
						"idempotency": "required",
						"timeout_ms": 10000,
						"result_unknown_reconciliation": "required"
					},
					"delegation": {"mode": "preserve_principal"},
					"call_graph": {"max_depth": 2, "reentrant": false}
				},
				{
					"name": "revoke",
					"invocation": {
						"mode": "brokered_action_gateway",
						"idempotency": "required",
						"timeout_ms": 10000,
						"result_unknown_reconciliation": "required"
					},
					"delegation": {"mode": "preserve_principal"},
					"call_graph": {"max_depth": 2, "reentrant": false}
				}
			]
		}
	]'::jsonb,
	true
),
updated_at = now()
WHERE key = 'plystra.api_keys';

UPDATE plugin_settings_definitions
SET default_value = jsonb_build_object('value', default_value),
	updated_at = now()
WHERE plugin_id IN ('plugin_webhooks', 'plugin_api_keys', 'plugin_notifications', 'plugin_moderation')
  AND default_value <> '{}'::jsonb
  AND jsonb_typeof(default_value) <> 'object';
