# VibeConnect Implementation Plan

Status: **Phase 5 complete. Unit tests green.**
- Targeted `ruff check` and `mypy` pass for the Phase 5 files;
  `pytest tests/unit -q` passes with 205 tests.
- This plan implements `SPEC.md` in small, testable phases. Each phase lands as reviewable commits with tests for the behavior introduced in that phase.

## Principles

- Build the security invariants first, then the happy-path product flow.
- Keep agent and server responsibilities sharply separated:
  - Server owns SSH auth, user certificates, authorization, replay, audit, database.
  - Agent owns enrollment, tunnel reconnect, and raw TCP proxy to `127.0.0.1:2222`.
- Prefer fail-closed behavior whenever identity, revocation, auth provider state,
  tunnel state, config validation, or replay storage is uncertain.
- Do not add v1-excluded features: remote admin API, MFA, Azure AD password
  verification, object replay storage, redaction, IPv6 node proxying, SFTP/SCP, or
  forwarding.
- Do not implement post-v1 account lifecycle reconciliation in v1 unless explicitly pulled forward.

## Completed phases

### Phase 0 — Foundation (done)
- `pyproject.toml` with entry points `vibeconnect-server` and `vibeconnect-agent`,
  async deps (asyncssh, asyncpg, cryptography, ldap3, msal, aiohttp), dev tooling
  (pytest, mypy, ruff, pyinstaller).
- `src/vibeconnect_common/`:
  - `models.py` — typed dataclasses for tunnel frames, session/audit records, config
    shapes (`ServerConfig`, `AgentConfig`, `TunnelFrameType` enum).
  - `crypto.py` — `SecretValue` redaction, enrollment/tunnel token generation
    (256-bit CSPRNG), sha256 hashing + constant-time verify, Ed25519 agent X.509
    cert issuance, OpenSSH user cert issuance (principals=[username], source-address
    127.0.0.0/8, no forwarding, 4h TTL default).
  - `identifiers.py` — node-name, label, and username-principal validation regexes
    with forbidden shell/metacharacter rejection.
  - `tunnel.py` — framed tunnel protocol encoder/decoder (length-prefixed JSON
    header + opaque payload), malformed/oversized/unknown-type rejection, channel
    ID reuse detection, secret-rotation frame encode/decode.
  - `db.py` — PostgreSQL connection + migration runner (`schema_migrations` tracker,
    ordered `NNN_slug.sql` files, transactional, idempotent).
  - `audit.py` — HMAC-SHA-256 audit writer with 16 KiB metadata cap, secret scrubbing.
  - `replay.py` — asciinema v2 `.cast` recorder, atomic temp-file write, mode 0600,
    HMAC integrity, retention pruning, fail-closed on write error.
- `src/migrations/001_initial_schema.sql` and `002_seed_alpha_admin_user.sql`:
  schema_migrations, agents, enrollment_tokens (single-use-per-node via partial
  unique index), sessions (DB-sequenced cert serials), audit_events,
  key_rotation_events; alpha_users seed with hashed password.
- Linting/formatting/typing gates: `scripts/check.sh` runs ruff + mypy + pytest.

### Phase 1 — Server admin + enrollment boundary (done)
- `src/server/admin.py` — local-only admin CLI commands: `create-agent`,
  `list-agents`, `revoke-agent`, `rotate-tunnel-secret`, `update-node-host-key`,
  `expire-token`, `list-sessions`; secret-scrubbed output, audit events for
  credential changes (`PostgresAdminStore` implementation).
- `src/server/enrollment.py` — `POST /enroll` aiohttp endpoint with rate limiting
  (per-IP and per-token-hash sliding windows), single-use token consumption under
  lock, mTLS agent-cert issuance, `tunnel_secret` generation + hashed persistence,
  `AgentEnrollmentError` if identity file or config rewrite fails.
- `src/server/main.py` — CLI entry point wiring migrate + admin subcommands.
- `src/server/main.py` — `connect-agent` OpenSSH helper for users connecting to
  a registered agent through the bastion.
- Tests: `test_server_admin.py`, `test_server_enrollment.py`, `test_crypto.py`,
  `test_migrations.py`, `test_identifiers.py`, `test_config_validation.py`.

### Phase 2 — SSH boundary + jump flow (done)
- `src/server/auth.py` — identity resolution (file/public-key path), LDAP filter
  escaping, TLS requirement enforcement, Azure AD group resolution with pagination,
  group→role→label authorization, restricted-shell command parser (exact node
  name only).
- `src/server/ssh.py` — `VibeConnectSshServer` (asyncssh server): public-key-only
  auth, no password, no keyboard-interactive, no subsystems/forwarding;
  `RestrictedShellJumpHandler` enforcing fail-closed policy.
- `src/server/jump.py` — `ServerJumpCoordinator` (issues user cert → creates session
  row → starts replay → opens tunnel channel → opens asyncssh client to
  `localhost:2222` over the tunnel connector), host-key pinning, heartbeat
  freshness check, `JumpPtyBridge` capturing PTY I/O to replay, `TunnelStreamAdapter`
  for backpressure-bounded byte streams.
- `src/server/tunnel.py` — `TunnelAuthenticator` (cert serial/key/revocation/expiry/
  node-binding/tunnel-secret checks), `ActiveTunnelRegistry` (one active per agent,
  duplicate rejection), `TunnelChannelRegistry` (max-sessions-per-agent, ID reuse),
  `HeartbeatState`, `AgentCertificateRenewer`.
- `src/server/health.py` — loopback-only health/readiness/metrics (secret-free).
- `docs/SERVERDEPLOY.md` and `docs/AGENTDEPLOY.md` — operator deployment guides
  covering install steps, firewall ports, enrollment, agent listing, and user
  connection flow through `ssh` or `vibeconnect-server connect-agent`.
- Tests: `test_server_ssh.py`, `test_server_jump.py`, `test_server_tunnel.py`,
  `test_server_health.py`, `test_auth.py`, `test_replay.py`, `test_audit.py`,
  `test_tunnel_protocol.py`, `test_agent_enrollment.py`, `test_agent_tunnel.py`,
  `test_deployment_artifacts.py`, `test_config_validation.py`,
  `test_entrypoints.py`.

### Phase 3 — Agent runtime (done / awaits Phase 5 listener)
- `src/agent/main.py` now dispatches `enroll --config` and `run --config` to real
  async runtime hooks with secret-free error reporting.
- `enroll --config` loads agent.conf, probes the node-local sshd host key from
  `127.0.0.1:2222`, posts the public enrollment payload over TLS, writes
  `identity.json`, and removes the raw one-time token.
- `run --config` validates agent config, opens a client-authenticated TLS tunnel,
  sends the initial auth frame, and reconnects with bounded backoff.
- `src/agent/enrollment.py` is implemented (payload builder, identity.json writer
  with atomic write + mode 0600, agent.conf token removal, TLS validation helper)
  and wired into `main.py`.
- `src/agent/tunnel.py` is implemented (proxy-target validation `127.0.0.1:2222`,
  reconnect backoff, heartbeat tracker, TLS-context helper, raw byte forwarder)
  and wired into `main.py`.
- Agent tunnel I/O loop decodes tunnel frames, dispatches
  `open_session`/`session_data`/`resize_pty`/`close_session`, opens a raw TCP
  socket to `127.0.0.1:2222` per channel, proxies bytes bidirectionally, and
  rejects live channel ID reuse. It does not parse SSH payloads.
- Tests: `test_agent_enrollment.py` covers helpers; `test_agent_tunnel.py` covers
  mocked tunnel stream dispatch and opaque bidirectional SSH byte forwarding.

### Phase 4 — Postgres-backed stores (done)
- `PostgresEnrollmentStore`, `PostgresAgentTunnelStore`, and `PostgresJumpStore`
  implement the remaining store protocols against the `001` schema tables.
- `PostgresJumpStore` also implements the terminal replay/session state close path.
- Tests cover the SQL predicates for single-use token consumption, revoked-agent
  tunnel denial, certificate renewal persistence, jump target lookup, session
  creation, and terminal session updates.

## Current status

### Phase 5 — Server bootstrap & runtime wiring (done)
- `server/main.py start --config ...` now loads SPEC-style YAML, validates via
  `config.py`, runs migrations during bootstrap, owns an asyncpg pool, loads agent
  CA material, starts the mTLS tunnel listener on 12345, enrollment HTTPS on 4443,
  health/metrics endpoints on loopback 9100, and the AsyncSSH listener on 22.
- `ServerTunnelBroker` now authenticates the agent's initial tunnel auth frame,
  verifies the auth frame certificate binding against the mTLS peer certificate,
  enforces one active tunnel per agent, tracks heartbeat freshness, opens bounded
  session channels, and routes `SESSION_DATA` / `CLOSE_SESSION` frames to the
  brokered stream used by the jump path.
- The AsyncSSH listener now uses configured file-backed public-key identity,
  label-based node authorization, the restricted-shell session handler,
  Postgres-backed jump/session state, runtime user certificate issuance, replay
  creation, and the authenticated tunnel opener. LDAP/Azure provider clients still
  fail closed until implemented behind their existing validation surfaces.
- `deploy/examples/server.config.yaml` and the integration fixture now use the
  runtime loader's `server`, `postgres`, `certs`, `tunnel`, `auth`, `replay`, and
  `metrics` sections.

## Remaining work (open)

### Phase 6 — Integration tests (TODO)
- `tests/integration/test_live_stack.py` is scaffolded (skipped unless
  `VIBECONNECT_RUN_INTEGRATION=1`). `docker-compose.yml` + LDAP/node/sshd fixtures
  exist. TODO: implement the real end-to-end test (enroll → tunnel → jump →
  whoami == real user → replay file non-empty & asciinema-valid).

## Post-v1 Backlog: Node Account Reconciliation

Tasks:
- Implement periodic account reconciliation across managed nodes and the VibeConnect
  server.
- Compare LDAP/Azure AD group membership and VibeConnect authorization state against
  local Unix account inventory.
- Use an hourly scan as the default cadence.
- Start with inventory/report-only mode. Disable-only mode must be explicitly
  configured.
- Treat delete mode as a separate destructive action requiring explicit configuration,
  policy controls, dry-run reporting, audit events, and operator approval.
- Never manage arbitrary local accounts. Require an ownership marker, configured
  username prefix, or configured allowlist before any action is eligible.
- Protect `root`, `vibe`, service users, database users, sshd users, and configured
  local administrators from disable and delete actions.
- Treat home directory deletion, mail spool deletion, crontab removal, SSH state
  cleanup, and passwd/shadow cleanup as destructive operations guarded by policy.

Verify:
- Unit tests detect unauthorized/stale users from mocked LDAP/Azure AD membership.
- Unit tests prove protected accounts are never disabled or deleted.
- Unit tests prove report-only mode makes no account changes.
- Unit tests prove delete mode requires explicit config and never deletes unowned
  accounts.
- Integration coverage eventually exercises one managed node with stale-user cleanup
  disabled by default.
