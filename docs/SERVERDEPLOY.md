# Server Deploy

This guide installs the vibeConnect bastion server and covers the operator
commands used to enroll and inspect agents.

## Prerequisites

- Linux server with Python 3.10 or newer.
- PostgreSQL reachable from the server. The local deployment below binds
  PostgreSQL to localhost only.
- OpenSSH client installed for the `connect-agent` helper.
- DNS name for the bastion, for example `vibeconnect.example.com`.
- Server key material under `/etc/vibeconnectd/secrets`.
- TLS certificate and key for the enrollment API and tunnel listeners.

## Firewall

Open only the ports needed by the configured deployment.

| Port | Direction | Source | Purpose |
| --- | --- | --- | --- |
| TCP 22 | inbound | Operators | Normal administrative SSH to the server |
| TCP 22 or 2222 | inbound | SSH users | User SSH entry to the bastion, matching `listen_ssh` |
| TCP 4443 | inbound | Agent nodes | HTTPS enrollment API |
| TCP 4444 | inbound | Agent nodes | Agent mTLS tunnel, matching `listen_tunnel` |
| TCP 9100 | loopback only | local host | Health, readiness, and metrics |
| TCP 5432 | loopback only | local host | PostgreSQL for the local server deployment |
| TCP 389/636 | outbound | LDAP | LDAP auth, when enabled |
| TCP 443 | outbound | Microsoft Graph | Azure AD auth, when enabled |

Keep administrative SSH separate from the vibeConnect SSH listener. Operators
usually keep OpenSSH on TCP 22 for maintenance and expose vibeConnect user SSH
on the configured `listen_ssh` port, for example TCP 2222 during testing. The
agent tunnel uses the configured tunnel port, not TCP 22.

All public listener ports are config values in `/etc/vibeconnectd/config.yaml`:
`server.listen_ssh`, `server.listen_api`, and `server.listen_tunnel`. The
server-to-agent node sshd target port is `tunnel.node_ssh_port`; the generated
agent package mirrors it in `[proxy].target`.

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

For a local PostgreSQL deployment, keep PostgreSQL bound to localhost and use a
loopback DSN stored in a root-readable secret file referenced by
`postgres.dsn_file` in `/etc/vibeconnectd/config.yaml`:

```sh
sudo sed -i "s/^#*listen_addresses.*/listen_addresses = 'localhost'/" /etc/postgresql/*/main/postgresql.conf
sudo systemctl restart postgresql
sudo ss -ltn | grep ':5432'
sudo install -o root -g vibeconnectd -m 0640 /dev/null /etc/vibeconnectd/secrets/postgres.dsn
sudo sh -c "printf '%s\n' 'postgresql://vibeconnect:password@127.0.0.1:5432/vibeconnect' > /etc/vibeconnectd/secrets/postgres.dsn"
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
vibeconnect-server create-agent \
  --node-name node-01 \
  --label env:prod \
  --server-host vibeconnect.example.com \
  --enrollment-port 4443 \
  --tunnel-port 4444 \
  --proxy-host 127.0.0.1 \
  --proxy-port 2222 \
  > node-01.agent.conf
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

When the vibeConnect SSH listener is on TCP 2222:

```sh
ssh -p 2222 alice@vibeconnect.example.com node-01
```

The server CLI also provides a local OpenSSH helper:

```sh
vibeconnect-server connect-agent --server vibeconnect.example.com --user alice --node-name node-01 --port 2222
```

Preview the exact SSH command without connecting:

```sh
vibeconnect-server connect-agent --server vibeconnect.example.com --user alice --node-name node-01 --port 2222 --dry-run
```

Use `--port` when the bastion SSH listener is not on TCP 22 and
`--identity-file` when the user must select a specific SSH identity.
