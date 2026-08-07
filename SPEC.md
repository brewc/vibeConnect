# VibeConnect — SSH Bastion with Agent Proxy & Replay

## 1. Purpose

A bastion SSH gateway letting users jump from a central **server** through an **agent** on remote nodes.

```
User --(SSH:22)--> Server --(mTLS tunnel)--> Agent --proxy--> sshd:2222 (on node)
```

- **Server**: SSH endpoint; LDAP/Azure AD auth; issues short-lived user certs; bridges
  sessions through the agent to node `sshd` on port 2222; captures terminal replay
  (`.cast`). It starts with only the privilege needed to bind configured ports and
  then runs session handling without long-term root privileges.
- **Agent** (non-root, user `vibe`): one-time enrollment → persistent identity; opens
  outbound TLS tunnel to server; **never** runs an SSH server; proxies the tunneled
  virtual TCP stream to `127.0.0.1:2222`.
- **sshd** (node): listens on port 2222; trusts the server's `user-ca`.

## 2. Language & libraries

- **Python 3.10+**
- `asyncssh` — SSH server (port 22), SSH client (server→sshd over tunnel), and
  OpenSSH user certificate creation/signing.
- `aiohttp` — HTTPS enrollment/API server and client using asyncio.
- `asyncpg` — PostgreSQL persistence.
- `cryptography` — X.509 agent mTLS certs and Ed25519 key material.
- `ldap3` — LDAP auth (server-side only).
- `msal` + Microsoft Graph — Azure AD auth (server-side only).
- `pyinstaller --onefile` — packaging.

Protocol choices:
- Enrollment/API on port 4443 is HTTPS with JSON request/response bodies served by
  `aiohttp`.
- The persistent tunnel on port 12345 is a custom framed virtual TCP protocol over
  mTLS.
- User-facing SSH on port 22 is implemented by `asyncssh`.
- Server-to-node SSH is also implemented by `asyncssh`, using a custom asyncio stream
  adapter backed by the framed tunnel. No local listening socket is created for this
  adapter.
- The agent never acts as an SSH client or server. It opens raw TCP connections to
  `127.0.0.1:2222` and shuttles bytes for server-owned SSH client sessions.
- `agent-ca` issues X.509 client certificates for mTLS. `user-ca` issues OpenSSH user
  certificates for sshd login.
- X.509 agent certificates include `clientAuth`, a subject CN equal to `node_name`, and
  a URI SAN of `urn:vibeconnect:agent:<agent_id>`.

## 2.1 Threat model and security posture

VibeConnect is security-sensitive infrastructure. Implementations MUST be fail-closed
and MUST treat all node-local state, replay files, database rows, enrollment tokens,
and auth provider responses as sensitive.

Threats in scope:
- Stolen enrollment token before first use.
- Duplicate enrollment attempts or token-consumption races.
- Stolen `identity.json` from an agent host.
- Revoked, stale, or cloned agent identities reconnecting to the tunnel endpoint.
- Malicious or compromised remote node attempting to impersonate another node.
- LDAP/Azure AD outage, partial response, pagination error, or group-mapping drift.
- Restricted-shell command injection or escape into arbitrary server-side commands.
- Replay tampering, replay disclosure, and secrets typed into terminal sessions.
- Database disclosure of token/secret hashes and session metadata.
- Server process compromise impact, especially where root is required for port 22.

Default posture:
- Deny access when identity, authorization, revocation, or tunnel state is uncertain.
- Never log private keys, enrollment tokens, tunnel secrets, bearer tokens, passwords,
  replay payloads, or raw auth provider responses containing credentials.
- Prefer explicit allowlists over parsing arbitrary user-provided shell commands.
- Emit audit events for security decisions without including secret material.

## 3. Core data model (PostgreSQL)

`schema_migrations(version int PK, applied_at timestamptz)`

`agents(id uuid PK, node_name text UNIQUE, hostname text, labels jsonb,
        x509_public_key text, node_ssh_host_public_key text,
        tunnel_secret_hash text, enrolled_at timestamptz, last_seen timestamptz,
        revoked bool, cert_serial text, cert_expires_at timestamptz)`

`enrollment_tokens(token_hash text PK, node_name text,
                   created_by text, created_at timestamptz, expires_at timestamptz,
                   used bool, used_at timestamptz, disabled_at timestamptz,
                   agent_id uuid FK)`

`sessions(id uuid PK, agent_id uuid FK, user_name text, user_cert_serial bigint,
          started_at timestamptz, ended_at timestamptz, replay_path text,
          replay_hmac text, status text)`

`audit_events(id uuid PK, event_type text, actor text, agent_id uuid, session_id uuid,
              node_name text, created_at timestamptz, metadata jsonb)`

`key_rotation_events(id uuid PK, key_name text, old_fingerprint text,
                     new_fingerprint text, started_at timestamptz, completed_at timestamptz,
                     status text)`

`alpha_users(username text PK, password_hash text, roles jsonb, created_at timestamptz)`

Startup bootstrap: server runs migrations in sorted order, skipping already-recorded versions.
Migration filenames MUST use `NNN_descriptive_slug.sql`, where `NNN` is the
zero-padded ordering number and `descriptive_slug` is lowercase ASCII words separated
by underscores. The ordering number is recorded as `schema_migrations.version`.
Migrations MUST run in a transaction where PostgreSQL supports it, record exactly
one `schema_migrations` row per successful migration, and fail startup on partial
or out-of-order migration state.

Required constraints:
- Security-critical columns are `NOT NULL` unless explicitly optional.
- Nullable columns are limited to: `agents.hostname`, `agents.last_seen`,
  `enrollment_tokens.used_at`, `enrollment_tokens.disabled_at`,
  `enrollment_tokens.agent_id`, `sessions.ended_at` while open,
  `sessions.replay_hmac` while open, and foreign-key context fields in `audit_events`
  when not applicable.
- `agents.revoked` defaults to `false`.
- `sessions.status` is constrained to known values (`open`, `closed`, `failed`,
  `terminated`).
- `key_rotation_events.status` is constrained to known values (`started`, `completed`,
  `failed`, `rolled_back`).
- User certificate serials are globally unique and DB-sequenced.
- Agent X.509 certificate serials are stored as normalized text and must be globally
  unique per `agent-ca`, including revoked and expired certificates.
- At most one active enrollment token may exist per `node_name`. Active means
  `used=false` and `disabled_at IS NULL`; expiry is checked during validation.
  Reissuing a token first disables any prior unused token for that node in the same
  transaction, then inserts the new token. Historical token rows remain for audit.
- Indexes exist for `agents.node_name`, `agents.last_seen`,
  `enrollment_tokens.expires_at`, and `sessions.agent_id`.
- Token and tunnel-secret hashes are acceptable only because their source values are
  high-entropy random secrets; low-entropy secrets MUST NOT use plain SHA-256.
- `agents.x509_public_key` and `agents.node_ssh_host_public_key` store normalized
  public-key material only. Private keys are never stored in PostgreSQL.
- Audit logs have retention independent of replay retention.
- Replay integrity uses HMAC-SHA-256 with a server-held replay integrity key, not a
  plain digest stored beside mutable replay metadata.
- `agents.labels` is a JSON array of exact label strings. Empty arrays are allowed.

Identifier constraints:
- `node_name`: `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`.
- Labels: `^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$`.
- Usernames used as SSH certificate principals must come from the authenticated identity
  provider, must not contain control characters, whitespace, `/`, `:`, shell
  metacharacters, or NUL, and must not be `root`.
- Identifier validation runs before database lookup, certificate issuance, logging, or
  audit metadata construction.

Minimum audit event types:
- `enrollment_token_created`, `enrollment_succeeded`, `enrollment_failed`.
- `agent_tunnel_connected`, `agent_tunnel_rejected`, `agent_tunnel_disconnected`.
- `agent_revoked`, `tunnel_secret_rotated`, `ca_rotation_started`,
  `ca_rotation_completed`, `node_host_key_updated`.
- `user_login_succeeded`, `user_login_failed`, `node_authorization_denied`.
- `session_started`, `session_closed`, `session_failed`, `replay_write_failed`,
  `replay_pruned`.

Audit metadata must be JSON, limited to 16 KiB per event, and scrubbed of tokens,
passwords, private keys, bearer tokens, replay payloads, and raw provider responses.

## 4. Enrollment (one-time, server-side)

```
vibeconnect-server create-agent --node-name NODE --label LABEL [--label LABEL ...]
```
- Generates a join key with at least 256 bits of CSPRNG entropy, stores `sha256(key)`
  in `enrollment_tokens` with `node_name`.
- Emits an agent config package (`agent.conf` + enrollment TLS CA bundle) shipped to
  the node.

Agent one-time enroll:
1. Reads config.
2. Generates an **Ed25519 X.509 client keypair locally** (private key never leaves node).
3. TLS-connects to `server:4443/enroll`, sends token, X.509 public key, and the
   node sshd host public key observed from `127.0.0.1:2222`.
4. Server validates token (hash-match, one-time, not-expired, node-name match).
5. Server signs the agent's public key with `agent-ca` -> X.509 client certificate.
6. Server persists agent row (`x509_public_key`, `node_ssh_host_public_key`,
   `sha256(tunnel_secret)`, `node_name`).
7. Server returns: `agent_id`, X.509 agent cert, tunnel TLS CA bundle,
   `tunnel_host:port`, and `tunnel_secret`.
8. Agent writes `identity.json` (mode 0600) containing `agent_id`, private key,
   X.509 cert, tunnel TLS CA bundle, and tunnel creds.
9. Agent exits; systemd/service starts it in tunnel mode.

Token semantics:
- Single-use — rejected on second attempt (logged + 400 to caller).
- Stored **hashed** at rest (`sha256_hex`).
- Server-configurable expiry (default 7 days).
- Hash comparisons use constant-time comparison.
- Token consumption is atomic: validation and marking `used=true` happen in one
  transaction using row locking or an equivalent single-statement update.
- Enrollment endpoint rate-limits failures per source address and token hash.
  Default: 10 failed attempts per 10 minutes per source address and 5 failed attempts
  per 10 minutes per token hash.
- Enrollment logs and audit events record outcome, `node_name`, and source address,
  but never the raw token or private key material.
- The agent validates the enrollment server certificate using the enrollment TLS CA
  bundle; insecure TLS verification bypasses are not allowed.

Enrollment API:
- `POST /enroll` accepts `node_name`, `token`, `agent_x509_public_key`, and
  `node_ssh_host_public_key`.
- Success returns `agent_id`, `agent_x509_cert`, `tunnel_ca_bundle`, `tunnel_host`,
  `tunnel_port`, and `tunnel_secret`.
- Error responses are JSON and do not distinguish enough detail to help brute-force
  tokens; detailed reason codes are audit-only.
- Enrollment is the only unauthenticated API route and still requires a valid one-time
  token plus TLS server certificate validation. No remote admin API exists in v1.
  Health/readiness endpoints are not part of the public API surface and must be
  loopback-only or protected by deployment-layer access control.

## 5. Tunnel (persistent, agent↔server)

Agent reconnects using `identity.json`:
1. mTLS to `server:tunnel_port` (default 12345).
2. **Both required**: X.509 agent cert (verified vs `agent-ca`) + `tunnel_secret`
   (verified vs hash).
3. Heartbeat every 30s; exponential backoff reconnect (cap 5 min).
4. On disconnect: server tears down in-flight user sessions for that agent, marks tunnel stale.

Tunnel hardening:
- TLS 1.2+ is required; TLS 1.3 is preferred. Certificate validation MUST include the
  configured `agent-ca`, validity window, and database revocation state.
- The agent MUST validate the tunnel server certificate using `tunnel.tls_ca_bundle`;
  insecure TLS verification bypasses are not allowed for tunnel reconnects.
- The server binds the X.509 certificate to the database agent row by certificate
  serial, public key, `agent_id`, and `node_name`; any mismatch denies the tunnel.
- Agent certificates are short-lived enough to force periodic renewal. Default
  lifetime: 90 days. Renewal requires an existing valid mTLS identity plus matching
  `tunnel_secret`.
- A revoked agent is rejected at tunnel authentication and any active tunnel for that
  agent is disconnected when revocation is observed.
- The server rejects a second concurrent tunnel for the same active `agent_id` unless
  it has first marked the prior tunnel stale and terminated its sessions.
- Heartbeats update `agents.last_seen`; missed heartbeats fail closed for new jumps.
- Tunnel secret verification uses constant-time comparison against the stored hash.

Tunnel framing:
- All frames include `type`, `request_id`, `channel_id` when session-scoped, and a
  bounded payload length.
- Required frame types: `auth`, `auth_ok`, `heartbeat`, `open_session`,
  `session_data`, `resize_pty`, `close_session`, `renew_agent_cert`, `error`.
- The first application frame after mTLS must be `auth` within 10 seconds. Its payload
  contains `agent_id`, `node_name`, certificate serial, and `tunnel_secret`; the server
  replies with `auth_ok` only after all certificate, database-binding, revocation, and
  secret checks pass.
- `open_session` asks the agent to open a raw TCP connection to `127.0.0.1:2222`.
- `session_data` carries raw SSH bytes between the server's `asyncssh` client and the
  agent's TCP socket. The agent MUST NOT parse SSH messages, user certs, usernames,
  terminal data, or commands.
- `resize_pty` carries PTY resize metadata for the server-side SSH session; it is not
  forwarded to the agent as terminal control logic.
- The server enforces `tunnel.max_sessions_per_agent` for each connected agent.
- Backpressure is mandatory: readers pause when downstream writes are blocked rather
  than buffering unbounded terminal data.
- Unknown frame types, oversized frames, malformed JSON metadata, and channel ID reuse
  terminate the tunnel.

Tunnel defaults and bounds:
- `tunnel.max_sessions_per_agent`: default 64, minimum 1, maximum 1024.
- `tunnel.heartbeat_seconds`: default 30, minimum 5, maximum 300.
- `tunnel.frame_max_bytes`: default 1048576, minimum 65536, maximum 16777216.
- Agent reconnect backoff starts at 1 second with jitter and caps at
  `tunnel.reconnect_backoff_max_seconds` (default 300, minimum 30, maximum 1800).

Key and secret rotation:
- `agent-ca`, `user-ca`, server TLS certificates, tunnel secrets, replay integrity
  keys, and replay storage encryption keys MUST have documented rotation procedures.
- CA rotation supports an overlap window with both old and new trust anchors so nodes
  and agents can roll gradually.
- Emergency CA compromise procedures revoke affected identities, publish new trust
  bundles, and deny new jumps until affected nodes trust the replacement CA.
- Tunnel secret rotation requires an existing valid tunnel identity and updates the
  stored hash atomically.
- Agent certificate renewal uses the `renew_agent_cert` tunnel frame. The agent sends a
  freshly generated X.509 public key before certificate expiry over an already
  authenticated tunnel; the server verifies the existing mTLS identity, matching
  `tunnel_secret`, non-revoked agent row, and node binding, then signs a replacement
  cert and atomically updates `x509_public_key`, `cert_serial`, and `cert_expires_at`.

## 6. User auth & authorization

User SSHes to `server:22` (asyncssh server). Auth methods:
- Public key (`validate_public_key`), or
- Keyboard-interactive LDAP password.

Alpha-stage local auth:
- Until LDAP/Azure AD development starts, migration `002_seed_alpha_admin_user.sql`
  creates `alpha_users` and seeds `admin` with password `password`.
- The seeded password MUST be stored as `sha256:<hex>` rather than plaintext, and
  the seed migration MUST be idempotent.
- `alpha_users` is an alpha-only development auth source and MUST be removed or
  replaced before any non-alpha deployment.

Keyboard-interactive scope:
- LDAP password auth is implemented as an LDAP bind over StartTLS/LDAPS.
- Azure AD password verification is not implemented in v1. Azure AD is used for group
  and public-key lookup only after identity is established by public key auth.
- MFA/second-factor workflows are out of scope for v1.

Public key authentication:
- Accepted user public keys MUST come from a configured identity source: LDAP
  `sshPublicKey`, Azure AD extension attribute, or a server-owned authorized-keys
  file.
- Public key auth still requires identity resolution and group authorization; a valid
  key alone never grants node access.
- Unknown keys and ambiguous username-to-key mappings deny login.
- The SSH login username MUST match the identity resolved for the accepted public key
  after canonicalization. A user-supplied SSH username is never trusted as the
  certificate principal unless it matches the resolved identity.

### 6.1 Identity resolution (server-side)

- **LDAP**: `ldap3.Connection`; StartTLS/LDAPS; bind via service account; search
  `(&(uid={username})({user_filter}))` for `memberOf` → internal groups.
- **Azure AD**: `msal` obtains Graph tokens using client credentials or managed
  identity; Graph `/users/{upn}/memberOf` resolves group OIDs.

Identity hardening:
- LDAP binds MUST validate the LDAP server certificate, hostname, and trust chain.
  StartTLS/LDAPS failures deny login.
- LDAP filters MUST escape user-controlled values, including `username`, before
  constructing the search filter.
- Azure AD group lookup MUST handle pagination. If transitive group membership is
  required by deployment policy, the implementation MUST use the transitive Graph
  endpoint consistently.
- Auth provider timeouts, partial responses, and mapping parse errors deny login.
- Token caches, service account credentials, and Graph/MSAL secrets use filesystem
  permissions equivalent to other server secrets.

### 6.2 Group→role mapping

`groups.yaml` (server config):
- LDAP group DN **or** Azure AD group OID → VibeConnect role.
- `ssh-user` role required. Additional roles select node labels the user may reach.

Authorization at connect-time: server checks user roles → allowed `node_name`s.
User drops into a restricted interactive shell accepting node-name jumps only.

Label semantics:
- Node labels are exact, case-sensitive strings.
- A user may access a node when they have `ssh-user` and at least one mapped role
  whose allowed label matches at least one label on the node.
- Users with `ssh-user` and no matching node labels authenticate successfully but see
  no reachable nodes.
- Negative labels, wildcards, and regex label matching are out of scope.

Restricted shell requirements:
- Accepted input is a node-name selection only; arbitrary shell commands are never
  executed server-side.
- Accepted grammar is exactly `NODE_NAME` followed by optional whitespace.
- Inputs such as `ssh NODE_NAME`, shell metacharacters, arguments, pipes, redirects,
  environment assignments, and quoted strings are rejected.
- Node names are matched against authorized database rows, not parsed as command
  fragments.
- Port forwarding, agent forwarding, X11 forwarding, SCP/SFTP, and arbitrary
  subsystem requests are out of scope for v1 and must be rejected.
- Root login through issued user certificates is denied in v1.

## 7. Jump flow (user→sshd, via server+agent)

1. User authenticates; server resolves allowed nodes.
2. User jumps by entering a node name (e.g. `web-01`).
3. Server looks up agent for `node_name`; confirms tunnel live.
4. **Server mints a short-lived SSH user cert**:
   - `SSHCertificate(cert_type=.user, public_key=<per-session-ephemeral>,
     serial=<db-sequence>,
     principals=[username], valid_before=now+ttl, critical_options={"source-address":"127.0.0.0/8"})`
   - Signed by the Ed25519 `user-ca`. Default user cert TTL = 4 h,
     server-configurable `certs.user_cert_ttl_hours`.
5. Server opens `asyncssh.SSHClient.connect` over the **agent's tunnel**, presenting
   the user cert + username, and validating the node sshd host key against the
   `agents.node_ssh_host_public_key` value for that `agent_id`.
6. Agent opens a raw TCP connection to `127.0.0.1:2222` and proxies encrypted SSH
   bytes through the tunnel. The SSH client handshake, user cert, and principal remain
   server-owned and opaque to the agent.
7. sshd@2222 validates cert vs `TrustedUserCAKeys /etc/ssh/vibeconnect-ca.pub`;
   principal matches target username → session starts as that UID.
8. `whoami` == the original username.

User certificate hardening:
- The cert public key is generated per session and discarded after the jump ends.
- `principals` MUST be exactly `[username]`; no aliases, groups, wildcards, or
  requested target usernames are added.
- Certificate serials are unique and auditable back to `sessions.id`.
- The server MUST reject a jump if the node sshd host key is missing, mismatched, or
  accepted only through a permissive unknown-host-key policy.
- The `source-address` critical option MUST be integration-tested against the real
  sshd path to prove sshd observes the agent-side `127.0.0.1` connection as expected.
- sshd on the node MUST be configured with `TrustedUserCAKeys`, principal matching,
  and disabled forwarding features consistent with the restricted-shell policy.
- The implementation MUST use AsyncSSH's OpenSSH certificate support for user cert
  serialization/signing; X.509 certificates are never presented to node sshd.

Node sshd prerequisites:
- Node-local user accounts must already exist for authorized usernames; account
  provisioning is outside VibeConnect v1.
- The node sshd host public key must be captured during enrollment and remain stable
  until an administrator intentionally updates the stored host key.
- `sshd` listens only on `127.0.0.1:2222`. IPv6 loopback is out of scope for v1 because
  the issued user certificate uses `source-address=127.0.0.0/8`.
- `TrustedUserCAKeys /etc/ssh/vibeconnect-ca.pub` trusts only the server `user-ca`.
- Principal matching uses `AuthorizedPrincipalsFile` or `AuthorizedPrincipalsCommand`
  and must require the certificate principal to equal the target local username.
- `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, and
  `PubkeyAuthentication yes` are required for the VibeConnect listener.
- `AllowTcpForwarding no`, `X11Forwarding no`, `AllowAgentForwarding no`, and SFTP
  subsystem access are disabled for VibeConnect sessions.
- Node setup must be validated by an integration test before a node is marked ready.

### 7.1 Replay capture

Server (the SSH-server endpoint) sees all PTY I/O. Writes asciinema `.cast` v2:
```
{"version": 2, "command": "web-01", "width": 228, "height": 50, "timestamp": <unix>}
[<seconds>, "o", <terminal output string>]
[<seconds>, "i", <terminal input string>]
```
- Storage: `$replay_dir/<session_id>.cast` on local disk.
- Retention: `replay.retention_days` (default 30) via nightly pruning job.
- `sessions` row closed with `ended_at`, `status=closed`, `replay_path`.

Replay hardening:
- Replay storage is sensitive. Disk backend uses a server-owned directory with mode
  `0700`; files are written atomically with mode `0600`.
- Remote object storage backends are out of scope for v1.
- Each replay records an HMAC-SHA-256 over the final `.cast` bytes using a server-held
  replay integrity key. The HMAC is stored in `sessions.replay_hmac` and audit
  metadata so object-only tampering is detectable.
- Deployments that need tamper evidence after database compromise MUST use an
  append-only external audit sink or a signing key kept outside the primary database
  trust boundary.
- Replay pruning deletes both object data and database pointers according to retention
  policy and emits an audit event.
- Documentation MUST warn operators that terminal replay may contain passwords,
  tokens, and other secrets typed by users.

Replay policy:
- Replay capture is mandatory in v1.
- Redaction is out of scope because terminal streams cannot be redacted reliably.
- If replay file creation fails before session start, the jump is denied.
- If replay storage fails mid-session, the server terminates the session, closes the
  replay with status `failed`, and emits an audit event.

## 8. Runtime / deployment

- Server: starts with enough privilege to listen on 22 (SSH), 12345 (mTLS tunnel),
  and 4443 (enrollment/API), then runs request/session handling without long-term
  root privileges.
- Agent: user `vibe` only; writes `identity.json` 0600; raw TCP proxy to
  `127.0.0.1:2222`.
- Packaging: two PyInstaller binaries (`vibeconnect-server`, `vibeconnect-agent`)
  from one repo; shared `src/vibeconnect_common/`.

Deployment hardening:
- The server MUST avoid long-term root: bind port 22 using `CAP_NET_BIND_SERVICE`,
  socket activation, or drop privileges immediately after binding.
- Server CA private keys, auth provider credentials, and PostgreSQL DSNs are readable
  only by the server runtime user.
- Agent `identity.json` is written under a `0700` directory, owned by `vibe`, with an
  atomic write and no world-readable backups.
- Recommended agent systemd hardening: `User=vibe`, `NoNewPrivileges=true`,
  `PrivateTmp=true`, `ProtectSystem=strict`, and a narrow `ReadWritePaths` for the
  identity/config directory.

Filesystem layout:
- Server config: `/etc/vibeconnectd/config.yaml`
- Server secrets: `/etc/vibeconnectd/secrets/`
- Server state: `/var/lib/vibeconnectd/`
- Server replay directory: `/var/lib/vibeconnectd/replay/`
- Server logs: `/var/log/vibeconnectd/`
- Agent config: `/etc/vibeconnect/agent.conf`
- Agent identity: `/var/lib/vibeconnect/identity.json`

Admin CLI:
- `vibeconnect-server create-agent --node-name NODE --label LABEL [--label LABEL ...]`
- `vibeconnect-server list-agents`
- `vibeconnect-server revoke-agent --node-name NODE`
- `vibeconnect-server rotate-tunnel-secret --node-name NODE`
- `vibeconnect-server update-node-host-key --node-name NODE --host-key-file PATH`
- `vibeconnect-server expire-token --node-name NODE`
- `vibeconnect-server list-sessions [--node-name NODE] [--user USER]`

Admin CLI hardening:
- Admin commands are local-only in v1 and run on the server host under OS-level admin
  control; they do not expose a network admin API.
- Commands that create, revoke, rotate, or expire credentials emit audit events.
- CLI output never prints stored hashes, private keys, tunnel secrets after enrollment,
  bearer tokens, database DSNs, or replay payloads.

Observability:
- Metrics include live tunnels, active sessions, failed enrollments, failed logins,
  issued certificates, replay write failures, and auth provider failures.
- Health/readiness endpoints expose only service state and dependency status; they
  MUST NOT expose secrets, DSNs, group mappings, tokens, or replay paths.
- Health/readiness endpoints bind to loopback by default. If exposed beyond loopback,
  deployment-layer authentication or network policy is mandatory.

## 9. Server config (`/etc/vibeconnectd/config.yaml`)

Minimum config schema:
- `server.listen_ssh`, `server.listen_tunnel`, `server.listen_api`.
- `server.run_user`, `server.run_group`, and privilege-drop mode.
- `postgres.dsn`.
- `certs.agent_ca_key_path`, `certs.agent_ca_cert_path`,
  `certs.user_ca_key_path`, `certs.user_ca_public_key_path`,
  `certs.agent_cert_lifetime_days`, and `certs.user_cert_ttl_hours`.
- `tunnel.max_sessions_per_agent`, `tunnel.heartbeat_seconds`,
  `tunnel.frame_max_bytes`, and `tunnel.tls_ca_bundle`.
- `auth.public_keys.source` (`ldap`, `azure_ad`, or `file`) and related source
  settings.
- `auth.public_keys.file_path` when `auth.public_keys.source = file`.
- File-based public-key auth entries must map one canonical username to one or more
  public keys; unscoped global key lists are invalid.
- `auth.ldap.*` for LDAP URL, bind DN, secret path, base DN, user filter,
  group attribute, and TLS trust settings.
- `auth.azure_ad.*` for tenant ID, client ID, authority, Graph endpoints, client
  secret or managed identity settings, and pagination mode.
- `groups` mapping list.
- `replay.{dir,retention_days,integrity_key_path}`.
- `audit.retention_days` and append-only audit sink settings when enabled.
- `metrics.listen` and health/readiness endpoint settings.

Config validation fails startup when:
- Required CA key paths or replay storage settings are missing.
- File or directory permissions are broader than required for secrets.
- `auth.public_keys.source = file` and the authorized-keys file is missing, writable by
  group/other, or not owned by the server runtime user or root.
- File-based public-key auth contains a key mapped to more than one username.
- `user_cert_ttl_hours` is less than 1 or greater than 12.
- LDAP is configured without StartTLS/LDAPS certificate validation.
- Keyboard-interactive password auth is configured with Azure AD as the verifier.
- Replay integrity key is missing.
- Tunnel frame size, heartbeat, or max-session settings are outside documented bounds.
- Required install directories do not exist or have unsafe ownership/modes.

## 9.1 Agent config (`/etc/vibeconnect/agent.conf`)

Minimum agent config schema:
- `enrollment.node_name`, `enrollment.token`, `enrollment.api_url`,
  `enrollment.tls_ca_bundle`.
- `identity.path`.
- `tunnel.host`, `tunnel.port`, `tunnel.tls_ca_bundle`, `tunnel.heartbeat_seconds`,
  and `tunnel.reconnect_backoff_max_seconds`.
- `proxy.target_host` defaulting to `127.0.0.1` and `proxy.target_port` defaulting to
  `2222`. VibeConnect v1 supports IPv4 loopback targets only because issued user
  certificates use `source-address=127.0.0.0/8`.

Agent config validation fails startup when:
- `agent.conf` is not owned by `root` or `vibe`, is readable by other users, or is not
  readable by the `vibe` runtime user.
- `identity.path` or its parent directory is not owned by `vibe` or has unsafe modes.
- TLS CA bundle paths are missing or unreadable.
- Proxy target host is not within `127.0.0.0/8`.
- Enrollment token remains in config after successful enrollment. The agent must rewrite
  `agent.conf` without the raw token when it creates `identity.json`; if it cannot
  rewrite the file, enrollment fails closed and does not start tunnel mode.
- `proxy.target_port`, heartbeat, or reconnect settings are outside documented bounds.

## 10. Testing (TDD mandatory)

- **Unit (pytest-asyncio)**: cert issuance + TTL enforcement; one-time token
  hash/consume/duplicate-reject; LDAP→groups (ldap3 mock); Azure AD→Graph mock
  with no live network; migration runner idempotency.
- **Integration (docker-compose)**: sshd real-instance on 2222 + LDAP replica;
  full enroll→tunnel→jump→whoami==real-user; verify `.cast` replayable.
- **Security assertions**: agent private key never logs; revoked agent rejected
  by tunnel; second token-use rejected; cert principal == resolved username; node sshd
  host-key mismatch rejects the jump.
- **Concurrency/security edge cases**: token double-spend race; duplicate active
  tunnel; stolen but revoked `identity.json`; missed heartbeat blocks new jumps.
- **Auth hardening**: LDAP filter escaping; LDAP TLS validation failure; Azure AD
  pagination; auth provider timeout fail-closed behavior.
- **Replay hardening**: file permissions; HMAC verification; retention pruning;
  no replay payloads in logs.
- **Protocol tests**: malformed tunnel frames; oversized frames; channel ID reuse;
  backpressure under slow downstream sshd; agent treats SSH bytes as opaque data.
- **Authorization tests**: `ssh-user` without matching labels sees no nodes; labels
  are exact and case-sensitive; root principal is denied.
- **Rotation tests**: overlapping CA trust bundles; tunnel secret rotation; revoked
  old CA/key material rejected after rotation completes; `renew_agent_cert` updates the
  stored public key and rejects revoked or mismatched agents.
- **Deployment/config tests**: node sshd listener is loopback-only; required sshd
  forwarding disables are present; agent removes enrollment token after successful
  enrollment; unsafe config permissions fail startup; permissive SSH host-key
  acceptance is impossible.

## 11. Repository layout

```
vibeconnect/
  SPEC.md                                    <-- this file
  src/vibeconnect_common/                     <-- shared: pg client, ca/cert, types, config
  src/server/                                 <-- server: ssh endpoint, tunnel broker, endpoints
  src/agent/                                  <-- agent: enroll + tunnel + proxy
  src/migrations/001_initial_schema.sql ...   <-- ordered migrations
  tests/unit/                                 <-- pytest
  tests/integration/                          <-- docker-compose suites
  pyproject.toml                              <-- build backend (setuptools); entry-points
          vibeconnect-server  -> server.main:main
          vibeconnect-agent   -> agent.main:main
```
