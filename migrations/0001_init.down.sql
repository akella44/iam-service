BEGIN;

SET search_path = iam, public;

-- --------------------------------------------------------------------------
-- Revert namespace additions on permissions
-- --------------------------------------------------------------------------
DROP INDEX IF EXISTS iam.idx_permissions__service_namespace;

ALTER TABLE permissions
  DROP CONSTRAINT IF EXISTS permissions_name_format_chk;
ALTER TABLE permissions
  DROP CONSTRAINT IF EXISTS permissions_service_namespace_action_unique;

ALTER TABLE permissions
  DROP COLUMN IF EXISTS service_namespace;
ALTER TABLE permissions
  DROP COLUMN IF EXISTS action;

-- --------------------------------------------------------------------------
-- Remove session/token enhancements
-- --------------------------------------------------------------------------
DROP INDEX IF EXISTS iam.idx_revoked_atj__recent;
DROP INDEX IF EXISTS iam.idx_atj__user_issued;

DROP INDEX IF EXISTS iam.idx_refresh_tokens__session_id;
DROP INDEX IF EXISTS iam.idx_refresh_tokens__family_id;
DROP INDEX IF EXISTS iam.idx_sessions__user_id;
DROP INDEX IF EXISTS iam.idx_sessions__family_id;

ALTER TABLE refresh_tokens
  ALTER COLUMN family_id DROP DEFAULT;
ALTER TABLE refresh_tokens
  DROP COLUMN IF EXISTS session_id;
ALTER TABLE refresh_tokens
  DROP COLUMN IF EXISTS family_id;
ALTER TABLE refresh_tokens
  DROP COLUMN IF EXISTS used_at;

ALTER TABLE sessions
  DROP COLUMN IF EXISTS family_id;

-- --------------------------------------------------------------------------
-- Drop triggers, functions, tables, schema, extensions
-- --------------------------------------------------------------------------
DROP TRIGGER IF EXISTS users_password_to_history ON users;
DROP FUNCTION IF EXISTS iam.trg_users_password_to_history();
DROP FUNCTION IF EXISTS iam.session_touch(UUID, INET, TEXT);
DROP FUNCTION IF EXISTS iam.session_revoke(UUID, TEXT);
DROP FUNCTION IF EXISTS iam.session_revoke_all_for_user(UUID, TEXT);
DROP FUNCTION IF EXISTS iam.revoke_session_access_tokens(UUID, TEXT);

DROP TABLE IF EXISTS iam.verification_tokens;
DROP TABLE IF EXISTS iam.password_reset_tokens;
DROP TABLE IF EXISTS iam.session_events;
DROP TABLE IF EXISTS iam.sessions;
DROP TABLE IF EXISTS iam.refresh_tokens;
DROP TABLE IF EXISTS iam.revoked_access_token_jti;
DROP TABLE IF EXISTS iam.access_token_jti;
DROP TABLE IF EXISTS iam.login_attempts;
DROP TABLE IF EXISTS iam.user_password_history;
DROP TABLE IF EXISTS iam.user_roles;
DROP TABLE IF EXISTS iam.role_permissions;
DROP TABLE IF EXISTS iam.permissions;
DROP TABLE IF EXISTS iam.roles;
DROP TABLE IF EXISTS iam.users;

DROP TYPE IF EXISTS iam.user_status;

DROP SCHEMA IF EXISTS iam CASCADE;

DROP EXTENSION IF EXISTS citext;
DROP EXTENSION IF EXISTS pgcrypto;

COMMIT;
