CREATE TABLE IF NOT EXISTS background_jobs (
	id TEXT PRIMARY KEY,
	job_type TEXT NOT NULL,
	payload JSONB NOT NULL,
	status TEXT NOT NULL,
	attempts INT NOT NULL DEFAULT 0,
	max_attempts INT NOT NULL DEFAULT 5,
	run_after TIMESTAMPTZ NOT NULL DEFAULT now(),
	last_error TEXT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS template_installations (
	id TEXT PRIMARY KEY,
	template_id TEXT NOT NULL,
	template_version TEXT NOT NULL,
	space_id TEXT NULL REFERENCES spaces(id),
	status TEXT NOT NULL,
	manifest_snapshot JSONB NOT NULL,
	installed_by_user_id TEXT REFERENCES users(id),
	installed_by_member_id TEXT REFERENCES members(id),
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
