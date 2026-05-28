-- purpose: add email verification-code and magic-link authentication challenges.
-- affected tables: users, auth_challenges.
-- rollback strategy: drop auth_challenges after exporting active challenge audit
-- data, then drop users.email_verified_at if no longer needed.

ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ NULL;

CREATE TABLE IF NOT EXISTS auth_challenges (
	id VARCHAR NOT NULL PRIMARY KEY,
	purpose VARCHAR NOT NULL,
	delivery_method VARCHAR NOT NULL,
	email VARCHAR NOT NULL,
	user_id VARCHAR NULL,
	secret_hash VARCHAR NOT NULL,
	code_hash VARCHAR NULL,
	redirect_url VARCHAR NULL,
	request_ip VARCHAR NULL,
	request_user_agent VARCHAR NULL,
	attempts BIGINT NOT NULL DEFAULT 0,
	max_attempts BIGINT NOT NULL DEFAULT 5,
	status VARCHAR NOT NULL DEFAULT 'pending',
	expires_at TIMESTAMPTZ NOT NULL,
	consumed_at TIMESTAMPTZ NULL,
	revoked_at TIMESTAMPTZ NULL,
	email_provider_message_id VARCHAR NULL,
	metadata JSONB NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	deleted_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS authchallenge_email_purpose_status ON auth_challenges (email, purpose, status);
CREATE UNIQUE INDEX IF NOT EXISTS authchallenge_secret_hash ON auth_challenges (secret_hash);
CREATE INDEX IF NOT EXISTS authchallenge_code_hash ON auth_challenges (code_hash);
CREATE INDEX IF NOT EXISTS authchallenge_expires_at ON auth_challenges (expires_at);
