# Server Deploy

This guide installs the vibeConnect bastion server and covers the operator
commands used to enroll and inspect agents.

## Prerequisites

- Linux server with Python 3.10 or newer.
- PostgreSQL reachable from the server.
- OpenSSH client installed for the `connect-agent` helper.
- DNS name for the bastion, for example `vibeconnect.example.com`.
- Server key material under `/etc/vibeconnectd/secrets`.
- TLS certificate and key for the enrollment API and tunnel listeners.

## Firewall

Open only the ports needed by the configured deployment.

| Port | Direction | Source | Purpose |
| --- | --- | --- | --- |
| TCP 22 | inbound | SSH users | User SSH entry to the bastion |
| TCP 4443 | inbound | Agent nodes | HTTPS enrollment API |
| TCP 12345 | inbound | Agent nodes | Agent mTLS tunnel by spec |
| TCP 4444 | inbound | Agent nodes | Tunnel port used by bundled alpha examples |
| TCP 9100 | loopback only | local host | Health, readiness, and metrics |
| TCP 5432 | outbound | PostgreSQL | Database connection, if PostgreSQL is remote |
| TCP 389/636 | outbound | LDAP | LDAP auth, when enabled |
| TCP 443 | outbound | Microsoft Graph | Azure AD auth, when enabled |

Prefer `12345` for new tunnel deployments. If you use
`deploy/examples/server.config.yaml` unchanged, open `4444` instead or edit the
example config to `0.0.0.0:12345`.

## Install

Build and install from the repository:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -r dev-requirements.txt
.venv/bin/pip install -e .
bash scripts/build_pyinstaller.sh
sudo install -m 0755 dist/vibeconnect-server /usr/local/bin/vibeconnect-server
```

Create the runtime user and directories:

```sh
sudo useradd --system --home /var/lib/vibeconnectd --shell /usr/sbin/nologin vibeconnectd
sudo install -d -o root -g vibeconnectd -m 0750 /etc/vibeconnectd
sudo install -d -o root -g vibeconnectd -m 0750 /etc/vibeconnectd/secrets
sudo install -d -o vibeconnectd -g vibeconnectd -m 0750 /var/lib/vibeconnectd
sudo install -d -o vibeconnectd -g vibeconnectd -m 0700 /var/lib/vibeconnectd/replay
sudo install -d -o vibeconnectd -g vibeconnectd -m 0750 /var/log/vibeconnectd
```

Install and edit the server config:

```sh
sudo install -o root -g vibeconnectd -m 0640 deploy/examples/server.config.yaml /etc/vibeconnectd/config.yaml
sudo vi /etc/vibeconnectd/config.yaml
```

For file-backed SSH authentication, create the authorized-key map referenced by
`auth.public_keys.file_path`. User `groups` are matched directly against enrolled
agent labels:

```sh
sudo tee /etc/vibeconnectd/authorized_keys.yaml >/dev/null <<'EOF'
users:
  alice:
    public_keys:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample alice@example.com
    groups:
      - env:prod
EOF
sudo chown root:vibeconnectd /etc/vibeconnectd/authorized_keys.yaml
sudo chmod 0640 /etc/vibeconnectd/authorized_keys.yaml
```

Set the PostgreSQL DSN for migrations and admin commands:

```sh
export VIBECONNECT_POSTGRES_DSN='postgresql://vibeconnect:password@db.example.com:5432/vibeconnect'
vibeconnect-server migrate
```

Install the systemd unit:

```sh
sudo install -o root -g root -m 0644 deploy/systemd/vibeconnect-server.service /etc/systemd/system/vibeconnect-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now vibeconnect-server
```

The packaged unit runs `vibeconnect-server start --config
/etc/vibeconnectd/config.yaml`. Keep the unit, config, and actual listener port
choices aligned before exposing the service.

## Enroll An Agent

Create a one-time enrollment package on the server:

```sh
vibeconnect-server create-agent --node-name node-01 --label env:prod > node-01.agent.conf
```

Copy `node-01.agent.conf` securely to the node as
`/etc/vibeconnect/agent.conf`. The token is single-use and must not be logged.

After the agent enrolls, verify it is registered:

```sh
vibeconnect-server list-agents
```

Each row is JSON and omits enrollment tokens, tunnel secrets, and private keys.

## Connect To An Agent

Users connect to the server over SSH and pass the registered agent node name as
the remote command:

```sh
ssh alice@vibeconnect.example.com node-01
```

The server CLI also provides a local OpenSSH helper:

```sh
vibeconnect-server connect-agent --server vibeconnect.example.com --user alice --node-name node-01
```

Preview the exact SSH command without connecting:

```sh
vibeconnect-server connect-agent --server vibeconnect.example.com --user alice --node-name node-01 --dry-run
```

Use `--port` when the bastion SSH listener is not on TCP 22 and
`--identity-file` when the user must select a specific SSH identity.
