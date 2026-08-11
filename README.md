# vibeConnect

vibeConnect is an alpha SSH bastion design and implementation for routing user SSH
sessions through an outbound agent tunnel to managed nodes. The server owns user
authentication, short-lived SSH user certificates, audit events, and terminal
replay. Agents run on managed nodes as the non-root `vibe` user and proxy only to
the local node `sshd` on `127.0.0.1:2222`.

Current status: v1 core scaffolding is implemented for migrations, admin
operations, enrollment logic, tunnel policy helpers, jump policy helpers, replay,
health endpoints, packaging checks, and tests. The agent CLI entry point is still
placeholder-level in this alpha tree.

## Architecture

```text
User SSH client -> vibeConnect server -> mTLS tunnel -> node agent -> sshd:2222
```

The server listens for user SSH on port 22, enrollment/API on port 4443, and the
agent tunnel on port 12345 by spec. Deploy examples currently show the tunnel on
4444 while the implementation is still being assembled; keep the final port choice
consistent before packaging a release.

Security defaults are intentionally conservative:

- Fail closed at every auth, tunnel, replay, and database boundary.
- Never log private keys, enrollment tokens, tunnel secrets, or password material.
- Store enrollment tokens hashed at rest and consume them once.
- Require both agent mTLS identity and the matching `tunnel_secret`.
- Issue user certificates with `principals = [username]`.
- Use `TrustedUserCAKeys` on nodes instead of per-user `authorized_keys`, while
  still requiring matching local Unix accounts.

## Quick Start

Create a development environment:

```sh
python -m venv .venv
.venv/bin/pip install -e '.[dev,package]'
```

Run database migrations against a real local PostgreSQL role and database:

```sh
export VIBECONNECT_POSTGRES_DSN='postgresql://vibeconnect:password@127.0.0.1:5432/vibeconnect'
PYTHONPATH=src .venv/bin/python -m server.main migrate
```

For alpha-only local development, migrations seed an `admin` user with password
`password`. Do not carry that account or password into any shared environment.

Use the local server admin CLI for node enrollment management:

```sh
PYTHONPATH=src .venv/bin/python -m server.main create-agent --node-name node-01 --node-host-key-file /etc/ssh/ssh_host_ed25519_key.pub --label env:dev
PYTHONPATH=src .venv/bin/python -m server.main list-agents
PYTHONPATH=src .venv/bin/python -m server.main list-sessions
```

Every admin command accepts `--postgres-dsn`; otherwise it reads
`VIBECONNECT_POSTGRES_DSN`.

Run the normal verification gate:

```sh
bash scripts/check.sh
```

Build distribution artifacts:

```sh
bash scripts/build_pyinstaller.sh
```

## Documentation

- [Specification](SPEC.md)
- [API Reference](docs/api-reference.md)
- [Reference Architecture](docs/reference-architecture.md)
- [Operations and Deploy](docs/ops-deploy.md)
- [Integration Test Notes](tests/integration/README.md)
