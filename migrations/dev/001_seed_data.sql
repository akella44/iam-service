-- Development seed data for manual end-to-end testing
-- Creates one regular user and one administrator account.

BEGIN;

CREATE SCHEMA IF NOT EXISTS iam;
SET search_path = iam, public;

-- Base roles
INSERT INTO roles (id, name, description)
VALUES
    ('c0a5d64a-22cd-44c5-b06b-7b2c58aed973', 'admin', 'Administrator role with full access'),
    ('a8edc611-6d9e-4fbc-ac9d-781da3d83c63', 'user', 'Regular user role with limited permissions'),
    ('d7c45f53-2a6b-49df-9b4d-e0e3f0c6c301', 'moderator', 'Moderator role with elevated viewing and publishing capabilities')
ON CONFLICT (name) DO UPDATE
SET description = EXCLUDED.description;

-- Base permissions (namespace + action)
INSERT INTO permissions (id, name, service_namespace, action, description)
VALUES
  ('33333333-0000-0000-0000-000000000001', 'iam:manage_users', 'iam', 'manage_users', 'Create, update, and deactivate user accounts'),
  ('33333333-0000-0000-0000-000000000002', 'iam:view_users', 'iam', 'view_users', 'View user directory and account details'),
  ('33333333-0000-0000-0000-000000000003', 'iam:manage_roles', 'iam', 'manage_roles', 'Create roles and assign permissions'),
  ('33333333-0000-0000-0000-000000000004', 'iam:view_profile', 'iam', 'view_profile', 'View own account details'),
  ('33333333-0000-0000-0000-000000000101', 'survey:create_survey', 'survey', 'create_survey', 'Create draft surveys for distribution'),
  ('33333333-0000-0000-0000-000000000102', 'survey:publish_survey', 'survey', 'publish_survey', 'Publish surveys to participants'),
  ('33333333-0000-0000-0000-000000000103', 'survey:view_survey', 'survey', 'view_survey', 'View survey results and metadata')
ON CONFLICT (service_namespace, action) DO UPDATE
SET name = EXCLUDED.name,
  description = EXCLUDED.description;

-- Role assignments
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN permissions p ON p.service_namespace = 'iam' AND p.action = 'manage_users'
 WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN permissions p ON p.service_namespace = 'iam' AND p.action = 'view_users'
 WHERE r.name IN ('admin', 'moderator')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN permissions p ON p.service_namespace = 'iam' AND p.action = 'manage_roles'
 WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN permissions p ON p.service_namespace = 'iam' AND p.action = 'view_profile'
 WHERE r.name IN ('admin', 'user', 'moderator')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN permissions p ON p.service_namespace = 'survey' AND p.action = 'create_survey'
 WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN permissions p ON p.service_namespace = 'survey' AND p.action = 'publish_survey'
 WHERE r.name IN ('admin', 'moderator')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
  FROM roles r
  JOIN permissions p ON p.service_namespace = 'survey' AND p.action = 'view_survey'
 WHERE r.name IN ('admin', 'user', 'moderator')
ON CONFLICT DO NOTHING;

-- Seed users
INSERT INTO users (
    id,
    username,
    email,
    phone,
    password_hash,
    password_algo,
    status,
    is_active,
    registered_at,
    last_login,
    last_password_change
)
VALUES
    (
        '11111111-1111-1111-1111-111111111111',
        'admin',
        'admin@example.com',
        NULL,
  'argon2id$v=19$m=65536,t=3,p=4$FE6wATk43UU11h3NQAC6wQ$ifqN2kQugi5SlL7FqyFcJFh4XR7ystUn5Tee0NAOn08',
        'argon2id',
        'active',
        TRUE,
        now(),
        NULL,
        now()
    ),
    (
        '22222222-2222-2222-2222-222222222222',
        'regular',
        'user@example.com',
        NULL,
  'argon2id$v=19$m=65536,t=3,p=4$kfcgjqLpxG8T5RnGK0YH1Q$BeuKZ7IXcVApoOeuGmbtx1RhTS0QHhom+6egBQGEXEE',
        'argon2id',
        'active',
        TRUE,
        now(),
        NULL,
        now()
    )
ON CONFLICT (username) DO UPDATE
SET email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    password_algo = EXCLUDED.password_algo,
    status = EXCLUDED.status,
    is_active = EXCLUDED.is_active,
    last_password_change = now();

-- Role memberships
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
  FROM users u
  JOIN roles r ON r.name = 'admin'
 WHERE u.username = 'admin'
ON CONFLICT (user_id, role_id) DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
  FROM users u
  JOIN roles r ON r.name = 'user'
 WHERE u.username = 'regular'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- Seed baseline password history to exercise reuse checks
INSERT INTO user_password_history (id, user_id, password_hash, set_at)
SELECT '66666666-6666-6666-6666-666666666666', u.id,
       'B+COJiy40CClvLXocpF02g==:4VUY93fg5BmGnJSflCUqGOd6kpoFyzRJl5WCJbit+Mk=',
       now() - interval '7 days'
  FROM users u
 WHERE u.username = 'admin'
ON CONFLICT (id) DO UPDATE
SET password_hash = EXCLUDED.password_hash,
    set_at = EXCLUDED.set_at;

-- Seed one canonical admin session for manual testing
WITH admin_user AS (
  SELECT id
    FROM users
   WHERE username = 'admin'
)
INSERT INTO sessions (
  id,
  user_id,
  family_id,
  session_version,
  device_id,
  device_label,
  ip_first,
  ip_last,
  user_agent,
  created_at,
  last_seen,
  expires_at
)
SELECT '44444444-4444-4444-4444-444444444444',
       u.id,
       '77777777-7777-7777-7777-777777777777',
       1,
       'dev-laptop',
       'Dev Laptop',
       '192.0.2.10',
       '192.0.2.10',
       'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)',
       now() - interval '15 minutes',
       now() - interval '5 minutes',
       now() + interval '7 days'
  FROM admin_user u
ON CONFLICT (id) DO UPDATE
SET device_label = EXCLUDED.device_label,
    ip_last = EXCLUDED.ip_last,
    user_agent = EXCLUDED.user_agent,
    last_seen = EXCLUDED.last_seen,
    expires_at = EXCLUDED.expires_at,
    family_id = EXCLUDED.family_id,
    session_version = EXCLUDED.session_version;

-- Issue refresh token bound to the seeded session
INSERT INTO refresh_tokens (
  id,
  user_id,
  session_id,
  family_id,
  issued_version,
  token_hash,
  client_id,
  ip,
  user_agent,
  created_at,
  expires_at,
  used_at,
  revoked_at,
  metadata
)
SELECT '55555555-5555-5555-5555-555555555555',
       s.user_id,
       s.id,
       s.family_id,
       1,
       'dev-refresh-token-hash',
       'dev-cli',
       '192.0.2.10',
       'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)',
       now() - interval '15 minutes',
       now() + interval '30 days',
       NULL,
       NULL,
       jsonb_build_object('seed', 'dev')
  FROM sessions s
 WHERE s.id = '44444444-4444-4444-4444-444444444444'
ON CONFLICT (token_hash) DO UPDATE
SET expires_at = EXCLUDED.expires_at,
    session_id = EXCLUDED.session_id,
    family_id = EXCLUDED.family_id,
    issued_version = EXCLUDED.issued_version,
    used_at = EXCLUDED.used_at,
    revoked_at = EXCLUDED.revoked_at,
    metadata = COALESCE(refresh_tokens.metadata, EXCLUDED.metadata);

UPDATE sessions
   SET refresh_token_id = rt.id,
       session_version = GREATEST(sessions.session_version, 1)
  FROM refresh_tokens rt
 WHERE sessions.id = '44444444-4444-4444-4444-444444444444'
   AND rt.token_hash = 'dev-refresh-token-hash';

COMMIT;
