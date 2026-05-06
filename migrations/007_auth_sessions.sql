ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES users(id),
	active_space_id TEXT NULL REFERENCES spaces(id),
	active_member_id TEXT NULL REFERENCES members(id),
	active_user_member_id TEXT NULL REFERENCES user_members(id),
	access_token_hash TEXT NOT NULL UNIQUE,
	refresh_token_hash TEXT NOT NULL UNIQUE,
	expires_at TIMESTAMPTZ NOT NULL,
	refresh_expires_at TIMESTAMPTZ NOT NULL,
	revoked_at TIMESTAMPTZ NULL,
	ip TEXT NULL,
	user_agent TEXT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_access_token_hash ON sessions(access_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_hash ON sessions(refresh_token_hash);

UPDATE users
SET password_hash = 'pbkdf2_sha256$120000$plystra_alice_salt$1d9f64c0d0dec791cf427c5849331ff669f6cec43e9ef5a90e7795cd76d41c28',
	updated_at = now()
WHERE id = 'user_alice' AND password_hash IS NULL;

UPDATE users
SET password_hash = 'pbkdf2_sha256$120000$plystra_bob_salt$84136c607b8cfb02a3e98eac9b215e476a40dc72a159accd4166c69f0241c30c',
	updated_at = now()
WHERE id = 'user_bob' AND password_hash IS NULL;
