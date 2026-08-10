# Operations And Deploy

This document is for alpha operators building and testing vibeConnect locally or
in a controlled lab. Do not expose this alpha build to production networks.

## Prerequisites

- Python 3.10 or newer.
- PostgreSQL reachable from the server process.
- Server key material for the user CA, agent CA, TLS, and replay integrity.
- Managed nodes with local `sshd` listening on `127.0.0.1:2222`.
- Local Unix accounts on managed nodes for users who should log in.
- LDAP or Azure AD configuration for non-alpha auth, once enabled.

## Build

Install the local development environment:

```sh
python -m venv .venv
.venv/bin/pip install -e '.[dev,package]'
```

Run checks:

```sh
bash scripts/check.sh
```

Build one-file binaries:

```sh
bash scripts/build_pyinstaller.sh
```

## Filesystem Layout

The packaged deployment should create:

| Path | Owner | Mode | Purpose |
| --- | --- | --- | --- |
| `/etc/vibeconnectd` | `root:vibeconnectd` | `0750` | Server config root |
| `/etc/vibeconnectd/config.yaml` | `root:vibeconnectd` | `0640` | Server config |
| `/etc/vibeconnectd/secrets` | `root:vibeconnectd` | `0750` | Server secrets |
| `/var/lib/vibeconnectd` | `vibeconnectd:vibeconnectd` | `0750` | Server state |
| `/var/lib/vibeconnectd/replay` | `vibeconnectd:vibeconnectd` | `0700` | Replay files |
| `/var/log/vibeconnectd` | `vibeconnectd:vibeconnectd` | `0750` | Server logs |
| `/etc/vibeconnect` | `root:vibe` | `0750` | Agent config root |
| `/etc/vibeconnect/agent.conf` | `vibe:vibe` | `0600` | Agent config |
| `/var/lib/vibeconnect` | `vibe:vibe` | `0700` | Agent state |
| `/var/lib/vibeconnect/identity.json` | `vibe:vibe` | `0600` | Agent identity |

## Database

Create a PostgreSQL role and database, then store a real loopback DSN in the
secret file referenced by `postgres.dsn_file`:

```sh
sudo install -o root -g vibeconnectd -m 0640 /dev/null /etc/vibeconnectd/secrets/postgres.dsn
sudo sh -c "printf '%s\n' 'postgresql://vibeconnect:password@127.0.0.1:5432/vibeconnect' > /etc/vibeconnectd/secrets/postgres.dsn"
```

Apply migrations:

```sh
vibeconnect-server migrate
```

Do not leave placeholder DSNs such as `USER`, `PASSWORD`, or `DBNAME`; PostgreSQL
will interpret them literally.

The alpha migrations seed `admin` with password `password`. Treat this only as a
local bootstrap account and rotate or remove it before any shared test system.

## Server

Example config lives at `deploy/examples/server.config.yaml`.

Important defaults:

- SSH user listener: `0.0.0.0:22`.
- Enrollment/API: `:4443` by spec.
- Tunnel listener: `:4444` by spec.
- Health and metrics: `127.0.0.1:9100`.
- Replay retention: 30 days.

The systemd unit in `deploy/systemd/vibeconnect-server.service` grants
`CAP_NET_BIND_SERVICE` so the server can bind port 22 without running all request
handling as long-term root. Keep secret files readable only by the intended
server account and root.

## Agent

Example config lives at `deploy/examples/agent.conf`.

The agent must run as user `vibe` and must proxy only to:

```text
127.0.0.1:2222
```

The current `src/agent/main.py` entry point is still a placeholder in this alpha
tree. Enrollment and tunnel primitives exist in modules, but the production-style
agent CLI still needs to be wired before a complete node deployment.

## Node sshd

Configure node `sshd` for certificate-based login through the server user CA:

```text
Port 2222
ListenAddress 127.0.0.1
TrustedUserCAKeys /etc/ssh/vibeconnect-ca.pub
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
```

Local Unix accounts are still required. vibeConnect certificates remove the need
for per-user `authorized_keys`; they do not create or own local accounts in v1.

## Enrollment Operations

Create an enrollment package:

```sh
vibeconnect-server create-agent --node-name node-01 --label env:dev
```

List agents:

```sh
vibeconnect-server list-agents
```

Expire an unused token:

```sh
vibeconnect-server expire-token --node-name node-01
```

Revoke a node:

```sh
vibeconnect-server revoke-agent --node-name node-01
```

Rotate an agent tunnel secret:

```sh
vibeconnect-server rotate-tunnel-secret --node-name node-01
```

Update a pinned node host key after a deliberate host key rotation:

```sh
vibeconnect-server update-node-host-key --node-name node-01 --host-key-file /etc/ssh/ssh_host_ed25519_key.pub
```

## Observability

Health, readiness, and metrics endpoints are intended for loopback scraping:

```sh
curl -fsS http://127.0.0.1:9100/health
curl -fsS http://127.0.0.1:9100/ready
curl -fsS http://127.0.0.1:9100/metrics
```

If these endpoints are exposed outside loopback, protect them with an explicit
local proxy, firewall, or service mesh policy. They are secret-free, but they
still reveal operational state.

## Backup And Rotation

Back up PostgreSQL, server CA material, replay integrity keys, and replay files
with the same sensitivity as production authentication material.

Recommended rotation procedures:

- Use `rotate-tunnel-secret` for agent tunnel secret rotation.
- Use `update-node-host-key` only after verifying a deliberate node host key
  change out of band.
- Use `revoke-agent` when a node is decommissioned or an agent identity is
  suspected compromised.
- Rotate alpha credentials before sharing a system with other users.

## Security Runbook

- Fail closed when database, auth provider, replay, tunnel, or host key state is
  uncertain.
- Preserve audit events for all admin actions and denied access attempts.
- Never paste private keys, one-time tokens, tunnel secrets, passwords, or replay
  integrity keys into logs, tickets, or chat.
- Disable accounts before destructive cleanup. Deleting home directories, mail
  spools, cron entries, or passwd/shadow entries requires explicit policy and is
  post-v1 work.
