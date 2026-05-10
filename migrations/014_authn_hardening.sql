-- purpose: add native authentication hardening metadata for production-ready
-- password lifecycle and login auditing.
-- affected tables: users.
-- rollback strategy: columns are additive and may be dropped after exporting
-- any required security audit data.

ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ NULL;
