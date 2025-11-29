BEGIN;

SET search_path = iam, public;

DROP TRIGGER IF EXISTS users_password_to_history ON users;
DROP FUNCTION IF EXISTS iam.trg_users_password_to_history();
DROP FUNCTION IF EXISTS iam.session_touch(UUID, INET, TEXT);
DROP FUNCTION IF EXISTS iam.session_revoke(UUID, TEXT);
DROP FUNCTION IF EXISTS iam.session_revoke_all_for_user(UUID, TEXT);
DROP FUNCTION IF EXISTS iam.session_bump_version(UUID, TEXT);

DROP TABLE IF EXISTS iam.verification_tokens;
DROP TABLE IF EXISTS iam.password_reset_tokens;
DROP TABLE IF EXISTS iam.session_events;
DROP TABLE IF EXISTS iam.sessions;
DROP TABLE IF EXISTS iam.refresh_tokens;
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
