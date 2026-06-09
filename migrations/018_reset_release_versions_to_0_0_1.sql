UPDATE template_installations
SET template_version = '0.0.1',
	manifest_snapshot = jsonb_set(
		jsonb_set(manifest_snapshot, '{version}', to_jsonb('0.0.1'::text), true),
		'{requires_core}',
		to_jsonb('>=0.0.1 <0.1.0'::text),
		true
	)
WHERE template_version IN ('1.0.0', '1.0.0-rc121');
