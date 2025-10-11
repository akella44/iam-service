-- Development seed data for manual end-to-end testing
-- Creates one regular user and one administrator account.

BEGIN;

-- Ensure schema exists and set search path
CREATE SCHEMA IF NOT EXISTS iam;
SET search_path = iam, public;

-- Ensure baseline roles exist
INSERT INTO iam.roles (id, name, description)
VALUES
    ('c0a5d64a-22cd-44c5-b06b-7b2c58aed973'::uuid, 'admin', 'Administrator role with full access'),
    ('a8edc611-6d9e-4fbc-ac9d-781da3d83c63'::uuid, 'user', 'Regular user role with limited permissions')
ON CONFLICT (name) DO UPDATE
SET description = EXCLUDED.description;

-- Seed administrator account
INSERT INTO iam.users (
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
VALUES (
    '11111111-1111-1111-1111-111111111111'::uuid,
    'admin',
    'admin@example.com',
    NULL,
    'B+COJiy40CClvLXocpF02g==:4VUY93fg5BmGnJSflCUqGOd6kpoFyzRJl5WCJbit+Mk=',
    'argon2id',
    'active'::user_status,
    TRUE,
    NOW(),
    NULL,
    NOW()
)
ON CONFLICT (username) DO UPDATE
SET
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    password_algo = EXCLUDED.password_algo,
    status = EXCLUDED.status,
    is_active = EXCLUDED.is_active,
    last_password_change = NOW();

-- Seed regular user account
INSERT INTO iam.users (
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
VALUES (
    '22222222-2222-2222-2222-222222222222'::uuid,
    'regular',
    'user@example.com',
    NULL,
    'ZFxNGgQwJrFwkdo9K3gY4Q==:yYMgC+F61YKD5KFgZt17TkQYHbFajnFq0GjsUZy0AQk=',
    'argon2id',
    'active'::user_status,
    TRUE,
    NOW(),
    NULL,
    NOW()
)
ON CONFLICT (username) DO UPDATE
SET
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    password_algo = EXCLUDED.password_algo,
    status = EXCLUDED.status,
    is_active = EXCLUDED.is_active,
    last_password_change = NOW();

-- Apply role assignments
INSERT INTO iam.user_roles (user_id, role_id)
SELECT u.id, r.id
FROM iam.users u
CROSS JOIN iam.roles r
WHERE u.username = 'admin'
    AND r.name = 'admin'
ON CONFLICT (user_id, role_id) DO NOTHING;

INSERT INTO iam.user_roles (user_id, role_id)
SELECT u.id, r.id
FROM iam.users u
CROSS JOIN iam.roles r
WHERE u.username = 'regular'
    AND r.name = 'user'
ON CONFLICT (user_id, role_id) DO NOTHING;

COMMIT;
