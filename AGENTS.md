# AGENTS.md — vibeConnect

Behavioral guidelines for coding agents working in the **vibeConnect** repository (SSH bastion with agent proxy).

## 1. Think Before Coding

- State assumptions explicitly. If uncertain, ask before implementing.
- If multiple interpretations exist, present them — do not pick silently.
- If a simpler approach exists, propose it. Push back when the spec is over-engineered.
- If something is unclear, stop. Name what's confusing and ask.

## 2. Simplicity First

- Minimum code that solves the problem. Nothing speculative.
- No features beyond what the SPEC.md requires.
- No abstractions for single-use code.
- No "flexibility"/configurability that wasn't requested.
- If you can cut the line count in half without losing behavior, do it.

Would a senior Swift engineer say this is overcomplicated? If yes, simplify.

## 3. Surgical Changes

- Touch only what you must. Do not "improve" adjacent code, comments, or formatting.
- Do not refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice pre-existing dead code, mention it — do not delete it.

When your changes orphan imports/vars/functions: remove the ones **your** change made unused. Do not remove pre-existing unused code unless asked.

Every changed line should trace directly to a task in the current plan.

## 4. Goal-Driven Execution

Define success criteria and loop until verified.

| Task           | Verify                                                                 |
|---------------|------------------------------------------------------------------------|
| "Add validation" | pytest tests for invalid inputs exist and pass; no test = no feature |
| "Fix the bug"   | A regression test reproduces it, fails first, then passes            |
| "Refactor X"     | Full `pytest -q` green before and after                                |

For multi-step work, state a brief numbered plan with a verify step per step.

## 5. Project-Specific Guidelines

### Technology stack
- **Language:** Python 3.10+
- **Async I/O:** `asyncio` (stdlib) — no external async runtime.
- **SSH:** `asyncssh` (server role for port 22, client role for agent→sshd relay).
- **Database:** PostgreSQL via `asyncpg`.
- **Crypto:** `cryptography` (Ed25519 CA/keygen, certs).
- **Auth backends:** `ldap3` (LDAP), `msal` + Microsoft Graph (Azure AD).
- **Packaging:** PyInstaller `--onefile`, two entry-points: `vibeconnect-server`, `vibeconnect-agent`.

### Security invariants (hard constraints, test these explicitly)
1. Agent private keys MUST never be logged, printed, or sent to the server.
2. Enrollment tokens are **single-use** and stored **hashed** (sha256) at rest.
3. Agent tunnel auth requires BOTH an mTLS certificate (signed by `agent-ca`) **AND** a matching `tunnel_secret`.
4. User certs issued by the server MUST have `principals = [username]` so impersonation is impossible.
5. Agent process MUST run as a non-root user (`vibe`). Server MUST run as root (binds port 22).
6. Every connection boundary MUST fail closed. User SSH, enrollment HTTPS, tunnel mTLS,
   tunnel frames, server-to-node SSH, LDAP, Azure AD, PostgreSQL, replay storage, and
   health/metrics exposure must deny or terminate when authentication, authorization,
   certificate validation, host-key validation, revocation, freshness, policy lookup,
   or persistence is uncertain.

### Directory layout
```
src/vibeconnect_common/   # shared: config, pg client, CA/cert, types
src/server/               # server: SSH endpoint, tunnel broker, enroll API
src/agent/                # agent: enroll, tunnel, proxy-to-sshd
src/migrations/           # v001.sql, v002.sql, ... ordered, tracked by schema_migrations
tests/unit/               # pytest (pytest-asyncio + mocks)
tests/integration/        # docker-compose: real sshd:2222 + LDAP
docs/
pyproject.toml            # setuptools backend, two console_scripts
SPEC.md                   # this project's spec (authoritative)
```

### Code style
- ASCII only. UTF-8 source, but prefer explicit ASCII escapes if non-ASCII ever necessary.
- Docstrings on all public modules/functions/classes (Google or NumPy style — match surrounding code).
- Type hints everywhere; run `mypy src tests` before merge.
- Format with `ruff format`; check with `ruff check`.
- Async-by-default for I/O paths. No blocking calls inside async functions.

### Build & run
- Build locally: `python -m build && pyinstaller --onefile -n vibeconnect-server src/server/main.py`, likewise for agent.
- Server: `/usr/local/bin/vibeconnect-server start --config /etc/vibeconnectd/config.yaml`
- Agent: `/usr/local/bin/vibeconnect-agent run --config /etc/vibeconnect/agent.conf`
- Migrations: applied automatically at server bootstrap; `schema_migrations` row prevents re-runs.

### Testing rules
- TDD: write/verify the failing test first, then make it pass.
- Unit tests must run offline (no real LDAP/Network) — use mocks (ldap3 mocks, httpx mocks for Graph, asyncpg transaction rollback).
- Integration tests run via `docker-compose -f tests/integration/docker-compose.yml`.
- Coverage gate: `pytest --cov=vibeconnect_common --cov-server --cov-agent --cov-fail-under=85`.
- Security-assertion tests are not optional — they live under `tests/unit/test_security.py`.

### Commit message format
```
<type>(<scope>): <short imperative subject>

<body if needed, wrap 72 cols>
```
Types: `feat`, `fix`, `refactor`, `sec`, `test`, `chore`. Scope: `server`, `agent`, `db`, `spec`.

### Before asking the user
- Prefer proposing solutions; do not endlessly probe.
- If a design decision is revisitable, mark it with a comment (`TODO(issue)`) and move on.

These guidelines are working if commits are small, tests are green, and diffs are reviewable in <2 min.
