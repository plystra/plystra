-- purpose: add Core-issued provider request contexts and PostgreSQL helper functions for RLS-driven provider data planes.
-- rollback: export provider_request_contexts, then drop plystra helper functions and the table if reverting.

CREATE TABLE IF NOT EXISTS provider_request_contexts (
  id varchar PRIMARY KEY,
  token_hash varchar NOT NULL,
  provider_plugin_id varchar NOT NULL,
  space_id varchar NOT NULL,
  actor_user_id varchar NULL,
  actor_member_id varchar NULL,
  actor_user_member_id varchar NULL,
  authorization_decision_id varchar NULL,
  request_id varchar NULL,
  purpose varchar NULL,
  status varchar NOT NULL DEFAULT 'active',
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL,
  revoked_reason varchar NULL,
  metadata jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS providerrequestcontext_token_hash
  ON provider_request_contexts(token_hash);

CREATE INDEX IF NOT EXISTS providerrequestcontext_provider_plugin_id_status
  ON provider_request_contexts(provider_plugin_id, status);

CREATE INDEX IF NOT EXISTS providerrequestcontext_space_id_status
  ON provider_request_contexts(space_id, status);

CREATE INDEX IF NOT EXISTS providerrequestcontext_expires_at
  ON provider_request_contexts(expires_at);

CREATE INDEX IF NOT EXISTS providerrequestcontext_authorization_decision_id
  ON provider_request_contexts(authorization_decision_id);

CREATE SCHEMA IF NOT EXISTS plystra;

-- The sha256 helper relies on pgcrypto. It is created separately so operators can audit the extension requirement.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION plystra.set_verified_context(context_token text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  ctx record;
BEGIN
  IF context_token IS NULL OR btrim(context_token) = '' THEN
    RAISE EXCEPTION 'provider request context token is required'
      USING ERRCODE = '28000';
  END IF;

  SELECT id, provider_plugin_id, space_id, actor_user_id, actor_member_id,
         actor_user_member_id, authorization_decision_id
  INTO ctx
  FROM public.provider_request_contexts
  WHERE token_hash = encode(public.digest(context_token, 'sha256'), 'hex')
    AND status = 'active'
    AND deleted_at IS NULL
    AND revoked_at IS NULL
    AND expires_at > now()
  LIMIT 1;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'provider request context token is invalid or expired'
      USING ERRCODE = '28000';
  END IF;

  PERFORM set_config('plystra.request_context_id', ctx.id, true);
  PERFORM set_config('plystra.provider_plugin_id', ctx.provider_plugin_id, true);
  PERFORM set_config('plystra.space_id', ctx.space_id, true);
  PERFORM set_config('plystra.actor_user_id', COALESCE(ctx.actor_user_id, ''), true);
  PERFORM set_config('plystra.actor_member_id', COALESCE(ctx.actor_member_id, ''), true);
  PERFORM set_config('plystra.actor_user_member_id', COALESCE(ctx.actor_user_member_id, ''), true);
  PERFORM set_config('plystra.authorization_decision_id', COALESCE(ctx.authorization_decision_id, ''), true);
END;
$$;

REVOKE ALL ON FUNCTION plystra.set_verified_context(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION plystra.current_request_context_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('plystra.request_context_id', true), '')
$$;

CREATE OR REPLACE FUNCTION plystra.current_provider_plugin_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('plystra.provider_plugin_id', true), '')
$$;

CREATE OR REPLACE FUNCTION plystra.current_space_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('plystra.space_id', true), '')
$$;

CREATE OR REPLACE FUNCTION plystra.current_actor_user_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('plystra.actor_user_id', true), '')
$$;

CREATE OR REPLACE FUNCTION plystra.current_actor_member_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('plystra.actor_member_id', true), '')
$$;

CREATE OR REPLACE FUNCTION plystra.current_actor_user_member_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('plystra.actor_user_member_id', true), '')
$$;

CREATE OR REPLACE FUNCTION plystra.current_authorization_decision_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('plystra.authorization_decision_id', true), '')
$$;
