BEGIN;

-- ==========================================================================
-- IAM Service Initial Schema (combined from prior incrementals)
-- ==========================================================================

DROP SCHEMA IF EXISTS iam CASCADE;
CREATE SCHEMA iam;
SET search_path = iam, public;

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;     -- case-insensitive email/username

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_status') THEN
    CREATE TYPE user_status AS ENUM ('pending','active','locked','disabled');
  END IF;
END$$;

-- ==========================================================================
-- 1) TABLES
-- ==========================================================================

CREATE TABLE IF NOT EXISTS users (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username               CITEXT NOT NULL UNIQUE,
  email                  CITEXT UNIQUE,
  phone                  TEXT UNIQUE,
  password_hash          TEXT   NOT NULL,
  password_algo          TEXT   NOT NULL DEFAULT 'argon2id',
  status                 user_status NOT NULL DEFAULT 'pending',
  is_active              BOOLEAN NOT NULL DEFAULT TRUE,
  registered_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login             TIMESTAMPTZ,
  last_password_change   TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT users_contact_required CHECK (email IS NOT NULL OR phone IS NOT NULL),
  CONSTRAINT users_email_format CHECK (email IS NULL OR position('@' in email) > 1)
);

CREATE TABLE IF NOT EXISTS roles (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL UNIQUE,
  description TEXT
);

CREATE TABLE IF NOT EXISTS permissions (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name              TEXT NOT NULL,
  description       TEXT,
  service_namespace TEXT NOT NULL,
  action            TEXT NOT NULL,
  CONSTRAINT permissions_name_unique UNIQUE (name),
  CONSTRAINT permissions_service_namespace_action_unique UNIQUE (service_namespace, action),
  CONSTRAINT permissions_name_format_chk CHECK (name = service_namespace || ':' || action)
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS user_password_history (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  set_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS login_attempts (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           UUID REFERENCES users(id) ON DELETE SET NULL,
  username_or_email TEXT NOT NULL,
  succeeded         BOOLEAN NOT NULL,
  ip                INET,
  user_agent        TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,
  client_id   TEXT,
  ip          INET,
  user_agent  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL,
  revoked_at  TIMESTAMPTZ,
  session_id  UUID,
  family_id   UUID NOT NULL DEFAULT gen_random_uuid(),
  used_at     TIMESTAMPTZ,
  metadata    JSONB
);

CREATE TABLE IF NOT EXISTS sessions (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_token_id UUID REFERENCES refresh_tokens(id) ON DELETE SET NULL,
  family_id        UUID NOT NULL DEFAULT gen_random_uuid(),
  device_id        TEXT,
  device_label     TEXT,
  ip_first         INET,
  ip_last          INET,
  user_agent       TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at       TIMESTAMPTZ NOT NULL,
  revoked_at       TIMESTAMPTZ,
  revoke_reason    TEXT
);

CREATE TABLE IF NOT EXISTS session_events (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id  UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip          INET,
  user_agent  TEXT,
  details     JSONB
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash   TEXT NOT NULL UNIQUE,
  ip           INET,
  user_agent   TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,
  used_at      TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ,
  metadata     JSONB,
  CONSTRAINT chk_pwdreset_times CHECK (expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS verification_tokens (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash    TEXT NOT NULL UNIQUE,
  purpose       TEXT NOT NULL DEFAULT 'email_verification',
  new_email     CITEXT,
  ip            INET,
  user_agent    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ NOT NULL,
  used_at       TIMESTAMPTZ,
  revoked_at    TIMESTAMPTZ,
  metadata      JSONB,
  CONSTRAINT chk_verify_times CHECK (expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS access_token_jti (
  jti         TEXT PRIMARY KEY,
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id  UUID REFERENCES sessions(id) ON DELETE CASCADE,
  issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_access_token_jti (
  jti        TEXT PRIMARY KEY,
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reason     TEXT
);

-- ==========================================================================
-- 2) FUNCTIONS / TRIGGERS
-- ==========================================================================

CREATE OR REPLACE FUNCTION trg_users_password_to_history()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN
    INSERT INTO user_password_history(user_id, password_hash, set_at)
    VALUES (OLD.id, OLD.password_hash, now());
    NEW.last_password_change := now();
  END IF;
  RETURN NEW;
END$$;

DROP TRIGGER IF EXISTS users_password_to_history ON users;
CREATE TRIGGER users_password_to_history
BEFORE UPDATE OF password_hash ON users
FOR EACH ROW EXECUTE FUNCTION trg_users_password_to_history();

CREATE OR REPLACE FUNCTION session_touch(p_session_id UUID, p_ip INET, p_user_agent TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
  UPDATE sessions
     SET last_seen = now(),
         ip_last   = COALESCE(p_ip, ip_last),
         user_agent= COALESCE(p_user_agent, user_agent)
   WHERE id = p_session_id
     AND revoked_at IS NULL
     AND expires_at > now();
END$$;

CREATE OR REPLACE FUNCTION revoke_session_access_tokens(p_session_id UUID, p_reason TEXT DEFAULT 'session_revoked')
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
  n INTEGER;
BEGIN
  INSERT INTO revoked_access_token_jti(jti, reason)
  SELECT jti, p_reason
    FROM access_token_jti
   WHERE session_id = p_session_id
     AND expires_at > now()
  ON CONFLICT (jti) DO NOTHING;

  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END$$;

CREATE OR REPLACE FUNCTION session_revoke(p_session_id UUID, p_reason TEXT DEFAULT 'manual_revoke')
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
  refreshed RECORD;
BEGIN
  UPDATE sessions
     SET revoked_at = now(),
         revoke_reason = p_reason
   WHERE id = p_session_id
     AND revoked_at IS NULL
  RETURNING id, family_id INTO refreshed;

  IF refreshed IS NULL THEN
    RETURN;
  END IF;

  UPDATE refresh_tokens
     SET revoked_at = COALESCE(revoked_at, now())
   WHERE session_id = refreshed.id
      OR family_id = refreshed.family_id;

  PERFORM revoke_session_access_tokens(refreshed.id, p_reason);

  INSERT INTO session_events(session_id, kind, details)
  VALUES (refreshed.id, 'logout', jsonb_build_object('reason', p_reason));
END$$;

CREATE OR REPLACE FUNCTION session_revoke_all_for_user(p_user_id UUID, p_reason TEXT DEFAULT 'global_signout')
RETURNS INTEGER LANGUAGE plpgsql AS $$
DECLARE
  sess RECORD;
  affected INTEGER := 0;
BEGIN
  FOR sess IN
    SELECT id
      FROM sessions
     WHERE user_id = p_user_id
       AND revoked_at IS NULL
  LOOP
    PERFORM session_revoke(sess.id, p_reason);
    affected := affected + 1;
  END LOOP;

  RETURN affected;
END$$;

-- ==========================================================================
-- 3) INDEXES & CONSTRAINTS
-- ==========================================================================

CREATE INDEX IF NOT EXISTS idx_permissions__service_namespace
  ON permissions(service_namespace);

CREATE INDEX IF NOT EXISTS idx_users__status         ON users(status);
CREATE INDEX IF NOT EXISTS idx_users__last_login     ON users(last_login);
CREATE INDEX IF NOT EXISTS idx_users__username_email ON users(username, email);

CREATE INDEX IF NOT EXISTS idx_roles__name           ON roles(name);
CREATE INDEX IF NOT EXISTS idx_permissions__name     ON permissions(name);
CREATE INDEX IF NOT EXISTS idx_role_permissions__perm  ON role_permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_user_roles__role         ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles__assigned_at  ON user_roles(assigned_at);

CREATE INDEX IF NOT EXISTS idx_user_password_history__user_time
  ON user_password_history(user_id, set_at DESC);

CREATE INDEX IF NOT EXISTS idx_login_attempts__user        ON login_attempts(user_id);
CREATE INDEX IF NOT EXISTS idx_login_attempts__created_at  ON login_attempts(created_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts__identity_ts ON login_attempts(username_or_email, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_attempts__ip_ts       ON login_attempts(ip, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens__user        ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens__expires     ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens__created     ON refresh_tokens(created_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens__active_user
  ON refresh_tokens(user_id, expires_at)
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens__family_id ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens__session_id ON refresh_tokens(session_id);

CREATE INDEX IF NOT EXISTS idx_sessions__user_lastseen ON sessions(user_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_sessions__active_user
  ON sessions(user_id, expires_at)
  WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions__device_active
  ON sessions(device_id)
  WHERE device_id IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions__refresh_id ON sessions(refresh_token_id);
CREATE INDEX IF NOT EXISTS idx_sessions__expires    ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions__family_id  ON sessions(family_id);
CREATE INDEX IF NOT EXISTS idx_sessions__user_id    ON sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_session_events__sess_at ON session_events(session_id, at DESC);

CREATE INDEX IF NOT EXISTS idx_pwdreset__user    ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_pwdreset__expires ON password_reset_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_pwdreset__active_user
  ON password_reset_tokens(user_id, expires_at)
  WHERE used_at IS NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_pwdreset__active_per_user
  ON password_reset_tokens(user_id)
  WHERE used_at IS NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_verify__user    ON verification_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_verify__expires ON verification_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_verify__purpose ON verification_tokens(purpose);
CREATE INDEX IF NOT EXISTS idx_verify__active_user_purpose
  ON verification_tokens(user_id, purpose, expires_at)
  WHERE used_at IS NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_verify__active_per_user_purpose
  ON verification_tokens(user_id, purpose)
  WHERE used_at IS NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_atj__user_exp       ON access_token_jti(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_atj__session        ON access_token_jti(session_id);
CREATE INDEX IF NOT EXISTS idx_atj__valid_fast     ON access_token_jti(expires_at);
CREATE INDEX IF NOT EXISTS idx_atj__user_issued    ON access_token_jti(user_id, issued_at DESC);
COMMIT;
