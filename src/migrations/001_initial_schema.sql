CREATE TABLE IF NOT EXISTS schema_migrations (
    version integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE SEQUENCE user_cert_serials AS bigint;

CREATE TABLE agents (
    id uuid PRIMARY KEY,
    node_name text NOT NULL UNIQUE,
    hostname text,
    labels jsonb NOT NULL DEFAULT '[]'::jsonb,
    x509_public_key text NOT NULL,
    node_ssh_host_public_key text NOT NULL,
    tunnel_secret_hash text NOT NULL,
    enrolled_at timestamptz NOT NULL,
    last_seen timestamptz,
    revoked boolean NOT NULL DEFAULT false,
    cert_serial text NOT NULL UNIQUE,
    cert_expires_at timestamptz NOT NULL,
    CONSTRAINT agents_labels_array CHECK (jsonb_typeof(labels) = 'array')
);

CREATE TABLE enrollment_tokens (
    token_hash text PRIMARY KEY,
    node_name text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used boolean NOT NULL DEFAULT false,
    used_at timestamptz,
    disabled_at timestamptz,
    agent_id uuid REFERENCES agents(id)
);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    agent_id uuid NOT NULL REFERENCES agents(id),
    user_name text NOT NULL,
    user_cert_serial bigint NOT NULL DEFAULT nextval('user_cert_serials'),
    started_at timestamptz NOT NULL,
    ended_at timestamptz,
    replay_path text NOT NULL,
    replay_hmac text,
    status text NOT NULL,
    CONSTRAINT sessions_user_cert_serial_unique UNIQUE (user_cert_serial),
    CONSTRAINT sessions_status_known CHECK (
        status IN ('open', 'closed', 'failed', 'terminated')
    )
);

CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    event_type text NOT NULL,
    actor text NOT NULL,
    agent_id uuid REFERENCES agents(id),
    session_id uuid REFERENCES sessions(id),
    node_name text,
    created_at timestamptz NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT audit_events_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE TABLE key_rotation_events (
    id uuid PRIMARY KEY,
    key_name text NOT NULL,
    old_fingerprint text NOT NULL,
    new_fingerprint text NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz,
    status text NOT NULL,
    CONSTRAINT key_rotation_events_status_known CHECK (
        status IN ('started', 'completed', 'failed', 'rolled_back')
    )
);

CREATE UNIQUE INDEX enrollment_tokens_one_active_per_node
    ON enrollment_tokens(node_name)
    WHERE used = false AND disabled_at IS NULL;

CREATE INDEX agents_node_name_idx ON agents(node_name);
CREATE INDEX agents_last_seen_idx ON agents(last_seen);
CREATE INDEX enrollment_tokens_expires_at_idx ON enrollment_tokens(expires_at);
CREATE INDEX sessions_agent_id_idx ON sessions(agent_id);
