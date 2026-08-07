# VibeConnect Implementation Plan

This plan implements `SPEC.md` in small, testable phases. Each phase should land as
one or more reviewable commits with tests for the behavior introduced in that phase.

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

## Phase 8: Server SSH Jump Flow

Tasks:
- Implement AsyncSSH server on port 22.
- Implement authenticated restricted shell and node selection.
- Implement tunnel-backed asyncio stream adapter for AsyncSSH client.
- Implement server-to-node SSH connect over agent tunnel:
  - presents per-session user cert and username.
  - validates node sshd host key against `agents.node_ssh_host_public_key`.
  - rejects missing/mismatched host key and any permissive unknown-host-key policy.
- Implement session lifecycle:
  - create `sessions` row.
  - start replay before jump.
  - bridge PTY I/O through replay and tunnel.
  - close session with `closed`, `failed`, or `terminated`.
  - audit start, close, fail.

Verify:
- Unit tests cover host-key missing and mismatch rejection.
- Unit tests cover cert principal exactly matching resolved username.
- Unit tests cover replay creation failure denial.
- Integration test covers full enroll to tunnel to jump to `whoami`.
- Integration test verifies `.cast` replay is produced and HMAC verifies.

## Phase 9: Admin CLI, Rotation, and Operations

Tasks:
- Implement local-only admin commands:
  - `create-agent`
  - `list-agents`
  - `revoke-agent`
  - `rotate-tunnel-secret`
  - `update-node-host-key`
  - `expire-token`
  - `list-sessions`
- Ensure credential-changing commands emit audit events.
- Ensure CLI output never prints stored hashes, private keys, tunnel secrets after
  enrollment, bearer tokens, DSNs, or replay payloads.
- Implement CA rotation procedures:
  - overlap trust bundles.
  - emergency compromise path.
  - deny new jumps until affected nodes trust replacement CA.
- Implement tunnel secret rotation over authenticated tunnel.
- Implement server TLS and replay integrity key rotation procedures.

Verify:
- Unit tests cover CLI output redaction.
- Unit tests cover audit events for create, revoke, rotate, expire, and host-key update.
- Rotation tests cover overlapping CA trust bundles.
- Rotation tests cover old CA/key material rejection after rotation completes.
- Rotation tests cover tunnel secret rotation.

## Phase 10: Integration Environment

Tasks:
- Add `tests/integration/docker-compose.yml` with:
  - PostgreSQL.
  - LDAP test server.
  - node container running sshd on `127.0.0.1:2222`.
  - server and agent processes.
- Configure node sshd:
  - `TrustedUserCAKeys /etc/ssh/vibeconnect-ca.pub`.
  - principal must equal target local username.
  - `PasswordAuthentication no`.
  - `KbdInteractiveAuthentication no`.
  - `PubkeyAuthentication yes`.
  - `AllowTcpForwarding no`.
  - `X11Forwarding no`.
  - `AllowAgentForwarding no`.
  - SFTP disabled.
- Add integration fixtures for CA material, test users, labels, groups, and host keys.

Verify:
- Integration test validates node sshd listener is loopback-only.
- Integration test validates forwarding disables are present.
- Integration test validates `source-address=127.0.0.0/8` works through the real sshd
  path.
- Integration test validates host-key mismatch rejects the jump.
- Integration test validates revoked agent cannot reconnect and active tunnel is
  disconnected.

## Phase 11: Packaging and Runtime Hardening

Tasks:
- Implement PyInstaller onefile builds:
  - `vibeconnect-server`
  - `vibeconnect-agent`
- Add sample systemd units:
  - server with `CAP_NET_BIND_SERVICE`, socket activation, or immediate privilege drop.
  - agent with `User=vibe`, `NoNewPrivileges=true`, `PrivateTmp=true`,
    `ProtectSystem=strict`, and narrow `ReadWritePaths`.
- Add sample filesystem setup:
  - `/etc/vibeconnectd/config.yaml`
  - `/etc/vibeconnectd/secrets/`
  - `/var/lib/vibeconnectd/`
  - `/var/lib/vibeconnectd/replay/`
  - `/var/log/vibeconnectd/`
  - `/etc/vibeconnect/agent.conf`
  - `/var/lib/vibeconnect/identity.json`
- Add health/readiness and metrics endpoints:
  - loopback by default.
  - no secrets, DSNs, group mappings, tokens, or replay paths.

Verify:
- `python -m build` succeeds.
- PyInstaller builds both onefile binaries.
- Deployment/config tests reject unsafe ownership and modes.
- Health/readiness tests prove no secret-bearing fields are exposed.
- Agent systemd hardening settings are covered by config/render tests.

## Phase 12: Release Gate

Required commands:

```sh
ruff format --check src tests
ruff check src tests
mypy src tests
pytest -q
pytest --cov=vibeconnect_common --cov=server --cov=agent --cov-fail-under=85
docker-compose -f tests/integration/docker-compose.yml up --abort-on-container-exit
python -m build
pyinstaller --onefile -n vibeconnect-server src/server/main.py
pyinstaller --onefile -n vibeconnect-agent src/agent/main.py
```

Required manual review checklist:
- Agent private keys are never logged, printed, sent to server, or stored in DB.
- Enrollment tokens are single-use and stored only as `sha256_hex`.
- Tunnel auth requires both agent mTLS and matching `tunnel_secret`.
- User cert principals are exactly `[username]`.
- Agent runs as `vibe`; server avoids long-term root.
- Replay capture is mandatory and fail-closed.
- Node sshd host keys are pinned and permissive unknown-host-key behavior is impossible.
- Health/readiness and CLI output do not expose secrets.
- No v1 out-of-scope features slipped into implementation.

## Suggested Commit Sequence

1. `chore(spec): add project skeleton`
2. `feat(config): validate server and agent settings`
3. `feat(db): add migrations and migration runner`
4. `sec(crypto): add certificate and secret primitives`
5. `feat(audit): add audit and replay foundations`
6. `feat(server): add enrollment api and admin token flow`
7. `feat(agent): add enrollment command`
8. `feat(tunnel): add authenticated tunnel protocol`
9. `feat(auth): add identity providers and authorization`
10. `feat(server): add ssh jump flow`
11. `feat(server): add admin rotation commands`
12. `test(integration): add full enroll tunnel jump suite`
13. `chore(build): add packaging and systemd artifacts`
