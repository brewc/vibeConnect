# Agent Deploy

This guide installs a managed-node agent and enrolls it with a vibeConnect
server.

## Prerequisites

- Linux node with Python 3.10 or newer.
- Local `sshd` installed.
- A non-root runtime user named `vibe`.
- Server enrollment CA bundle available as `/etc/vibeconnect/ca.crt`.
- One-time `agent.conf` package created by the server operator.

## Firewall

The agent does not require inbound firewall access for vibeConnect.

| Port | Direction | Destination | Purpose |
| --- | --- | --- | --- |
| TCP 4443 | outbound | Server | HTTPS enrollment API |
| TCP 12345 | outbound | Server | Agent mTLS tunnel by spec |
| TCP 4444 | outbound | Server | Tunnel port used by bundled alpha examples |
| TCP 2222 | loopback only | local host | Local sshd target for the agent proxy |

Prefer server tunnel port `12345` for new deployments. If the server is still
using the bundled alpha example config, the agent `server_url` must point to
`4444` until the server config is changed.

## Install

Build and install from the repository, or copy the packaged binary from a build
host:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -r dev-requirements.txt
.venv/bin/pip install -e .
bash scripts/build_pyinstaller.sh
sudo install -m 0755 dist/vibeconnect-agent /usr/local/bin/vibeconnect-agent
```

Create the runtime user and directories:

```sh
sudo useradd --system --home /var/lib/vibeconnect --shell /usr/sbin/nologin vibe
sudo install -d -o root -g vibe -m 0750 /etc/vibeconnect
sudo install -d -o vibe -g vibe -m 0700 /var/lib/vibeconnect
```

Install the enrollment package and CA bundle:

```sh
sudo install -o root -g vibe -m 0640 node-01.agent.conf /etc/vibeconnect/agent.conf
sudo install -o root -g vibe -m 0644 ca.crt /etc/vibeconnect/ca.crt
```

## Configure Local sshd

The agent proxies only to local sshd on loopback. Configure node sshd with a
dedicated listener:

```text
Port 2222
ListenAddress 127.0.0.1
TrustedUserCAKeys /etc/ssh/vibeconnect-user-ca.pub
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
```

Restart sshd and verify the loopback listener:

```sh
sudo systemctl restart sshd
ssh-keyscan -p 2222 127.0.0.1
```

Local Unix accounts must already exist for users who are allowed to log in.
vibeConnect issues user certificates; it does not create node accounts.

## Enroll

Run enrollment once:

```sh
sudo -u vibe vibeconnect-agent enroll --config /etc/vibeconnect/agent.conf
```

Enrollment validates the one-time token, records the node sshd host key, writes
`/var/lib/vibeconnect/identity.json`, and removes the token from
`/etc/vibeconnect/agent.conf`.

Start the long-running tunnel:

```sh
sudo install -o root -g root -m 0644 deploy/systemd/vibeconnect-agent.service /etc/systemd/system/vibeconnect-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now vibeconnect-agent
```

Check status:

```sh
sudo systemctl status vibeconnect-agent
```

## Operator Verification

From the server, confirm that the node is installed and enrolled:

```sh
vibeconnect-server list-agents
```

Expected output is one JSON row per agent, including `node_name`, `hostname`,
`labels`, `enrolled_at`, `last_seen`, and `revoked`.

## User Connection

Users connect to the server first, then the server routes the session to the
registered agent named by the SSH remote command:

```sh
ssh alice@vibeconnect.example.com node-01
```

The same connection can be launched through the server CLI helper:

```sh
vibeconnect-server connect-agent --server vibeconnect.example.com --user alice --node-name node-01
```

To see the exact command before connecting:

```sh
vibeconnect-server connect-agent --server vibeconnect.example.com --user alice --node-name node-01 --dry-run
```

