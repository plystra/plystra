-- purpose: bind provider request contexts to a Core-authorized capability grant or Action Gateway execution.
-- rollback: export provider_request_contexts before dropping binding columns if reverting.

ALTER TABLE provider_request_contexts
  ADD COLUMN IF NOT EXISTS capability varchar NULL,
  ADD COLUMN IF NOT EXISTS operation varchar NULL,
  ADD COLUMN IF NOT EXISTS capability_grant_id varchar NULL,
  ADD COLUMN IF NOT EXISTS action_execution_id varchar NULL;

CREATE INDEX IF NOT EXISTS providerrequestcontext_capability_grant_id
  ON provider_request_contexts(capability_grant_id);

CREATE INDEX IF NOT EXISTS providerrequestcontext_action_execution_id
  ON provider_request_contexts(action_execution_id);

UPDATE provider_request_contexts
SET
  status = 'revoked',
  revoked_at = COALESCE(revoked_at, now()),
  revoked_reason = COALESCE(revoked_reason, 'missing_core_authorization_binding'),
  updated_at = now()
WHERE status = 'active'
  AND deleted_at IS NULL
  AND revoked_at IS NULL
  AND capability_grant_id IS NULL
  AND action_execution_id IS NULL;

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
         actor_user_member_id, capability, operation, capability_grant_id,
         action_execution_id, authorization_decision_id
  INTO ctx
  FROM public.provider_request_contexts
  WHERE token_hash = encode(public.digest(context_token, 'sha256'), 'hex')
    AND status = 'active'
    AND deleted_at IS NULL
    AND revoked_at IS NULL
    AND expires_at > now()
    AND (capability_grant_id IS NOT NULL OR action_execution_id IS NOT NULL)
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
  PERFORM set_config('plystra.capability', COALESCE(ctx.capability, ''), true);
  PERFORM set_config('plystra.operation', COALESCE(ctx.operation, ''), true);
  PERFORM set_config('plystra.capability_grant_id', COALESCE(ctx.capability_grant_id, ''), true);
  PERFORM set_config('plystra.action_execution_id', COALESCE(ctx.action_execution_id, ''), true);
  PERFORM set_config('plystra.authorization_decision_id', COALESCE(ctx.authorization_decision_id, ''), true);
END;
$$;

REVOKE ALL ON FUNCTION plystra.set_verified_context(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION plystra.current_capability()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('plystra.capability', true), '')
$$;

CREATE OR REPLACE FUNCTION plystra.current_operation()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('plystra.operation', true), '')
$$;

CREATE OR REPLACE FUNCTION plystra.current_capability_grant_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('plystra.capability_grant_id', true), '')
$$;

CREATE OR REPLACE FUNCTION plystra.current_action_execution_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting('plystra.action_execution_id', true), '')
$$;
