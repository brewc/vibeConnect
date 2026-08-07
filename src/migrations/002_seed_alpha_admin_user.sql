CREATE TABLE alpha_users (
    username text PRIMARY KEY,
    password_hash text NOT NULL,
    roles jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT alpha_users_roles_array CHECK (jsonb_typeof(roles) = 'array')
);

INSERT INTO alpha_users(username, password_hash, roles)
VALUES (
    'admin',
    'sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    '["ssh-user", "admin"]'::jsonb
)
ON CONFLICT (username) DO NOTHING;
