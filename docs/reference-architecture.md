# Reference Architecture

vibeConnect uses a server-controlled SSH certificate authority and node-local
agents to provide audited SSH access without opening inbound management ports on
managed nodes.

## Component Model

```text
                  admin CLI
                     |
                     v
User SSH -> Server -> PostgreSQL
             |  |
             |  +-> replay storage
             |
             +-> mTLS tunnel -> Agent -> 127.0.0.1:2222 sshd
```

Server responsibilities:

- Authenticate users through alpha local auth, LDAP, Azure AD, or configured file
  public keys.
- Authorize visible nodes from identity groups and node labels.
- Issue short-lived OpenSSH user certificates with exactly one principal:
  the authenticated username.
- Validate pinned node host keys before jump completion.
- Bridge SSH session bytes through an authenticated agent tunnel.
- Write audit events and terminal replay metadata.

Agent responsibilities:

- Generate and keep its private key locally.
- Enroll once with a one-time token.
- Maintain an outbound mTLS tunnel to the server.
- Proxy only to `127.0.0.1:2222`.
- Run as the non-root `vibe` user.

Node `sshd` responsibilities:

- Listen on `127.0.0.1:2222`.
- Trust only the server user CA through `TrustedUserCAKeys`.
- Match certificate principals to local Unix accounts.
- Avoid per-user `authorized_keys` for vibeConnect-issued access.

## Trust Boundaries

User boundary: The SSH server must reject unknown identities, invalid credentials,
unsupported SSH features, stale certificates, and users without node visibility.

Agent boundary: The tunnel must reject any connection missing either valid agent
mTLS identity or the matching `tunnel_secret`.

Node boundary: The agent must reject proxy targets other than
`127.0.0.1:2222`. The node `sshd` remains responsible for local Unix account
existence and principal matching.

Data boundary: PostgreSQL and replay storage are required dependencies. If their
state is unknown, session establishment fails closed.

## Ports

| Port | Listener | Purpose |
| --- | --- | --- |
| 22 | Server | User SSH entry point |
| 4443 | Server | HTTPS enrollment/API |
| 12345 | Server | Agent mTLS tunnel by spec |
| 2222 | Node loopback | Local node `sshd` target |
| 9100 | Server loopback | Health, readiness, metrics |

Deploy examples currently use `4444` for the tunnel URL while the spec names
`12345`. Treat that as an alpha configuration mismatch to resolve before release.

## Key Material

Server-held material:

- User CA private key for OpenSSH user certificates.
- Agent CA private key for agent mTLS certificates.
- Replay integrity key.
- Tunnel secrets stored hashed or otherwise protected according to the data model.

Agent-held material:

- Agent private key, generated locally and never sent to the server.
- Agent client certificate issued by the server.
- Server CA bundle used to validate enrollment and tunnel TLS.
- Current tunnel secret.

Node-held material:

- Node `sshd` host key.
- `TrustedUserCAKeys` public key file for the server user CA.
- Local Unix accounts for authorized users.

## Persistence

PostgreSQL stores migration state, agents, enrollment tokens, sessions, audit
events, key rotation events, and alpha users. Migrations are named
`NNN_descriptive_slug.sql` and are tracked by numeric version in
`schema_migrations`.

Replay files are written as asciicast-compatible `.cast` files with integrity
metadata. Replay write failure is a security event; new sessions must not proceed
when replay setup cannot be trusted.

## Failure Posture

The reference architecture is fail closed:

- Auth provider unavailable means no new user login.
- Database unavailable means no migration, admin operation, enrollment, or new
  auditable jump session.
- Replay storage unavailable means no new replay-required session.
- Tunnel heartbeat or channel uncertainty means no new jump through that tunnel.
- Host key mismatch means no jump completion.

## Post-v1 Account Reconciliation

vibeConnect user certificates replace per-user `authorized_keys`, but they do not
replace local Unix accounts. Post-v1 account reconciliation should periodically
compare LDAP or Azure AD membership to local accounts on managed nodes and the
server. The default posture is inventory/report-only or disable-only, never
delete-by-default, with protected account denylists and explicit ownership markers.

