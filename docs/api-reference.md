# API Reference

This reference covers the alpha public and operator-facing API surface. `SPEC.md`
remains authoritative where behavior is still specified but not fully wired into
the runtime entry points.

## Enrollment API

`POST /enroll`

Purpose: register a node agent using a one-time enrollment token, persist the
agent identity, and return tunnel credentials. The endpoint must be served over
HTTPS on the enrollment/API listener. Agents must validate the server TLS
certificate with the configured CA bundle.

Request JSON:

```json
{
  "node_name": "node-01",
  "token": "one-time-token",
  "agent_x509_public_key": "-----BEGIN PUBLIC KEY-----...",
  "node_ssh_host_public_key": "ssh-ed25519 AAAA..."
}
```

Response JSON:

```json
{
  "agent_id": "00000000-0000-0000-0000-000000000000",
  "agent_x509_cert": "-----BEGIN CERTIFICATE-----...",
  "tunnel_ca_bundle": "-----BEGIN CERTIFICATE-----...",
  "tunnel_host": "vibeconnect.example.test",
  "tunnel_port": 12345,
  "tunnel_secret": "generated-secret"
}
```

Security behavior:

- Enrollment tokens are single-use and stored as SHA-256 hashes.
- Failed enrollment responses are intentionally generic.
- Enrollment validates node names, token expiry, token ownership, public key
  syntax, node host key syntax, and replay-safe secret handling.
- Successful enrollment stores the node host key for later pinning.

## Health And Metrics

Health endpoints expose secret-free operational status only. They must bind to
loopback by default.

`GET /health`

Returns HTTP 200 with:

```json
{
  "status": "ok",
  "tunnel": "ready"
}
```

`GET /ready`

Returns HTTP 200 when database, replay storage, and tunnel state are ready;
otherwise HTTP 503.

```json
{
  "ready": true,
  "dependencies": {
    "database": true,
    "replay": true,
    "tunnel": true
  }
}
```

`GET /metrics`

Returns Prometheus text metrics without labels or secret-bearing values:

```text
vibeconnect_live_tunnels 0
vibeconnect_active_sessions 0
vibeconnect_failed_enrollments 0
vibeconnect_failed_logins 0
vibeconnect_issued_certificates 0
vibeconnect_replay_write_failures 0
vibeconnect_auth_provider_failures 0
```

## Agent Tunnel Protocol

The tunnel is an internal framed protocol over mutually authenticated TLS. It is
not a public HTTP API.

Required authentication:

- Agent client certificate signed by `agent-ca`.
- Matching `tunnel_secret` for the enrolled agent row.
- Non-revoked agent state.

Important frame families:

- Channel frames for opening, carrying, resizing, and closing proxied SSH streams.
- Heartbeat frames for liveness.
- Tunnel secret rotation frames carrying `node_name` and the replacement
  `tunnel_secret` over the already-authenticated control channel.

Tunnel secrets and private keys must never be logged or rendered through object
representations.

## Server Admin CLI

There is no remote admin API in v1. Administrative operations are local CLI calls
against PostgreSQL. All commands accept `--postgres-dsn`; if omitted, the CLI uses
`VIBECONNECT_POSTGRES_DSN`.

Apply migrations:

```sh
vibeconnect-server migrate --postgres-dsn postgresql://user:password@host:5432/db
```

Create an enrollment package:

```sh
vibeconnect-server create-agent --node-name node-01 --label env:dev
```

List agents:

```sh
vibeconnect-server list-agents
```

Revoke an agent:

```sh
vibeconnect-server revoke-agent --node-name node-01
```

Rotate an agent tunnel secret:

```sh
vibeconnect-server rotate-tunnel-secret --node-name node-01
```

Update a pinned node host key:

```sh
vibeconnect-server update-node-host-key --node-name node-01 --host-key-file /path/to/ssh_host_ed25519_key.pub
```

Expire an outstanding enrollment token:

```sh
vibeconnect-server expire-token --node-name node-01
```

List sessions:

```sh
vibeconnect-server list-sessions
vibeconnect-server list-sessions --node-name node-01
vibeconnect-server list-sessions --user admin
```

Admin commands write audit events with the supplied `--actor`, defaulting to
`local-admin`.

