"""Local-only server admin commands and rotation controls."""

from __future__ import annotations

import datetime as dt
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from server.host_keys import validate_node_ssh_host_public_key
from vibeconnect_common.audit import AuditWriter
from vibeconnect_common.crypto import (
    SecretValue,
    generate_enrollment_token,
    generate_tunnel_secret,
    scrub_secret_metadata,
    sha256_hex,
)
from vibeconnect_common.identifiers import validate_label, validate_node_name
from vibeconnect_common.models import AuditEventType

ENROLLMENT_TOKEN_LIFETIME_DAYS = 7
SECRET_OUTPUT = "[not printed]"


class AdminError(ValueError):
    """Raised when an admin operation must fail closed."""


@dataclass(frozen=True, slots=True)
class CreatedAgentPackage:
    """One-time enrollment package returned to an operator."""

    node_name: str
    labels: tuple[str, ...]
    agent_conf: str


@dataclass(frozen=True, slots=True)
class AgentSummary:
    """Non-secret agent row shown by admin list commands."""

    node_name: str
    hostname: str | None
    labels: tuple[str, ...]
    enrolled_at: dt.datetime | None
    last_seen: dt.datetime | None
    revoked: bool


@dataclass(frozen=True, slots=True)
class SessionSummary:
    """Non-secret session row shown by admin list commands."""

    session_id: uuid.UUID
    node_name: str
    user_name: str
    started_at: dt.datetime
    ended_at: dt.datetime | None
    status: str


@dataclass(frozen=True, slots=True)
class RotationState:
    """CA rotation state used to enforce overlap before completion."""

    key_name: str
    old_fingerprint: str
    new_fingerprint: str
    trusted_fingerprints: tuple[str, ...]
    status: str


class AdminStore(Protocol):
    """Persistence surface used by local admin commands."""

    async def create_enrollment_token(
        self,
        *,
        token_hash: str,
        node_name: str,
        labels: Sequence[str],
        node_ssh_host_public_key: str,
        created_by: str,
        expires_at: dt.datetime,
        now: dt.datetime,
    ) -> None:
        """Disable old active tokens and create a new enrollment token."""

    async def list_agents(self) -> tuple[AgentSummary, ...]:
        """Return all agents without secret-bearing columns."""

    async def revoke_agent(self, *, node_name: str, now: dt.datetime) -> uuid.UUID:
        """Revoke one agent and return its ID."""

    async def rotate_tunnel_secret(
        self, *, node_name: str, tunnel_secret_hash: str, now: dt.datetime
    ) -> uuid.UUID:
        """Store a rotated tunnel secret hash and return the agent ID."""

    async def update_node_host_key(
        self, *, node_name: str, node_ssh_host_public_key: str, now: dt.datetime
    ) -> uuid.UUID:
        """Update one pinned node sshd host key and return the agent ID."""

    async def expire_token(self, *, node_name: str, now: dt.datetime) -> int:
        """Disable active enrollment tokens for one node."""

    async def list_sessions(
        self, *, node_name: str | None = None, user_name: str | None = None
    ) -> tuple[SessionSummary, ...]:
        """Return sessions without replay payloads."""

    async def start_ca_rotation(
        self,
        *,
        key_name: str,
        old_fingerprint: str,
        new_fingerprint: str,
        trusted_fingerprints: Sequence[str],
        now: dt.datetime,
    ) -> uuid.UUID:
        """Record a CA rotation start."""

    async def complete_ca_rotation(
        self,
        *,
        rotation_id: uuid.UUID,
        trusted_fingerprints: Sequence[str],
        now: dt.datetime,
    ) -> RotationState:
        """Complete a CA rotation after overlap validation."""

    async def get_ca_rotation(self, *, rotation_id: uuid.UUID) -> RotationState:
        """Return an active CA rotation without mutating it."""


class PostgresAdminStore:
    """PostgreSQL implementation of local admin persistence."""

    def __init__(self, connection: AdminConnection) -> None:
        """Store an asyncpg-compatible connection."""
        self._connection = connection

    async def create_enrollment_token(
        self,
        *,
        token_hash: str,
        node_name: str,
        labels: Sequence[str],
        created_by: str,
        node_ssh_host_public_key: str,
        expires_at: dt.datetime,
        now: dt.datetime,
    ) -> None:
        """Disable old active tokens and create a new enrollment token."""
        await self._connection.execute(
            """
            UPDATE enrollment_tokens
            SET disabled_at = $1
            WHERE node_name = $2 AND used = false AND disabled_at IS NULL
            """,
            now,
            node_name,
        )
        await self._connection.execute(
            """
            INSERT INTO enrollment_tokens(
                token_hash, node_name, labels, node_ssh_host_public_key,
                created_by, created_at, expires_at
            )
            VALUES($1, $2, $3::jsonb, $4, $5, $6, $7)
            """,
            token_hash,
            node_name,
            json.dumps(list(labels)),
            node_ssh_host_public_key,
            created_by,
            now,
            expires_at,
        )

    async def list_agents(self) -> tuple[AgentSummary, ...]:
        """Return all agents without secret-bearing columns."""
        rows = await self._connection.fetch(
            """
            SELECT node_name, hostname, labels, enrolled_at, last_seen, revoked
            FROM agents
            ORDER BY node_name
            """
        )
        return tuple(_agent_summary(row) for row in rows)

    async def revoke_agent(self, *, node_name: str, now: dt.datetime) -> uuid.UUID:
        """Revoke one agent and return its ID."""
        row = await self._connection.fetchrow(
            """
            UPDATE agents
            SET revoked = true,
                revoked_at = $2
            WHERE node_name = $1 AND revoked = false
            RETURNING id
            """,
            node_name,
            now,
        )
        if row is None:
            raise AdminError("agent not found or already revoked")
        return _row_uuid(row, "id")

    async def rotate_tunnel_secret(
        self, *, node_name: str, tunnel_secret_hash: str, now: dt.datetime
    ) -> uuid.UUID:
        """Store a rotated tunnel secret hash and return the agent ID."""
        row = await self._connection.fetchrow(
            """
            UPDATE agents
            SET tunnel_secret_hash = $2
            WHERE node_name = $1 AND revoked = false
            RETURNING id
            """,
            node_name,
            tunnel_secret_hash,
        )
        if row is None:
            raise AdminError("agent not found or revoked")
        return _row_uuid(row, "id")

    async def update_node_host_key(
        self, *, node_name: str, node_ssh_host_public_key: str, now: dt.datetime
    ) -> uuid.UUID:
        """Update one pinned node sshd host key and return the agent ID."""
        row = await self._connection.fetchrow(
            """
            UPDATE agents
            SET node_ssh_host_public_key = $2
            WHERE node_name = $1 AND revoked = false
            RETURNING id
            """,
            node_name,
            node_ssh_host_public_key,
        )
        if row is None:
            raise AdminError("agent not found or revoked")
        return _row_uuid(row, "id")

    async def expire_token(self, *, node_name: str, now: dt.datetime) -> int:
        """Disable active enrollment tokens for one node."""
        result = await self._connection.execute(
            """
            UPDATE enrollment_tokens
            SET disabled_at = $1
            WHERE node_name = $2 AND used = false AND disabled_at IS NULL
            """,
            now,
            node_name,
        )
        return _updated_count(result)

    async def list_sessions(
        self, *, node_name: str | None = None, user_name: str | None = None
    ) -> tuple[SessionSummary, ...]:
        """Return sessions without replay payloads."""
        rows = await self._connection.fetch(
            """
            SELECT s.id, a.node_name, s.user_name, s.started_at, s.ended_at, s.status
            FROM sessions s
            JOIN agents a ON a.id = s.agent_id
            WHERE ($1::text IS NULL OR a.node_name = $1)
              AND ($2::text IS NULL OR s.user_name = $2)
            ORDER BY s.started_at DESC
            """,
            node_name,
            user_name,
        )
        return tuple(_session_summary(row) for row in rows)

    async def start_ca_rotation(
        self,
        *,
        key_name: str,
        old_fingerprint: str,
        new_fingerprint: str,
        trusted_fingerprints: Sequence[str],
        now: dt.datetime,
    ) -> uuid.UUID:
        """Record a CA rotation start."""
        rotation_id = uuid.uuid4()
        await self._connection.execute(
            """
            INSERT INTO key_rotation_events(
                id, key_name, old_fingerprint, new_fingerprint, started_at, status
            )
            VALUES($1, $2, $3, $4, $5, 'started')
            """,
            rotation_id,
            key_name,
            old_fingerprint,
            new_fingerprint,
            now,
        )
        return rotation_id

    async def complete_ca_rotation(
        self,
        *,
        rotation_id: uuid.UUID,
        trusted_fingerprints: Sequence[str],
        now: dt.datetime,
    ) -> RotationState:
        """Complete a CA rotation after overlap validation."""
        row = await self._connection.fetchrow(
            """
            UPDATE key_rotation_events
            SET completed_at = $2, status = 'completed'
            WHERE id = $1 AND status = 'started'
            RETURNING key_name, old_fingerprint, new_fingerprint, status
            """,
            rotation_id,
            now,
        )
        if row is None:
            raise AdminError("CA rotation is not active")
        return RotationState(
            key_name=str(row["key_name"]),
            old_fingerprint=str(row["old_fingerprint"]),
            new_fingerprint=str(row["new_fingerprint"]),
            trusted_fingerprints=tuple(trusted_fingerprints),
            status=str(row["status"]),
        )

    async def get_ca_rotation(self, *, rotation_id: uuid.UUID) -> RotationState:
        """Return an active CA rotation without mutating it."""
        row = await self._connection.fetchrow(
            """
            SELECT key_name, old_fingerprint, new_fingerprint, status
            FROM key_rotation_events
            WHERE id = $1 AND status = 'started'
            """,
            rotation_id,
        )
        if row is None:
            raise AdminError("CA rotation is not active")
        return RotationState(
            key_name=str(row["key_name"]),
            old_fingerprint=str(row["old_fingerprint"]),
            new_fingerprint=str(row["new_fingerprint"]),
            trusted_fingerprints=(),
            status=str(row["status"]),
        )


class AdminConnection(Protocol):
    """asyncpg-compatible connection methods used by admin storage."""

    async def execute(self, query: str, *args: object) -> str:
        """Execute a SQL statement."""

    async def fetch(self, query: str, *args: object) -> Sequence[Mapping[str, object]]:
        """Fetch multiple rows."""

    async def fetchrow(self, query: str, *args: object) -> Mapping[str, object] | None:
        """Fetch one row."""


class AdminService:
    """Local-only admin service with secret-scrubbed outputs."""

    def __init__(self, *, store: AdminStore, audit_writer: AuditWriter | None) -> None:
        """Configure storage and optional audit output."""
        self._store = store
        self._audit_writer = audit_writer

    async def create_agent(
        self,
        *,
        node_name: str,
        labels: Sequence[str],
        actor: str,
        node_ssh_host_public_key: str,
        server_host: str = "server",
        enrollment_port: int = 4443,
        tunnel_port: int = 4444,
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 2222,
        heartbeat_seconds: int = 30,
        now: dt.datetime | None = None,
    ) -> CreatedAgentPackage:
        """Create a one-time enrollment package for an agent."""
        safe_node_name = validate_node_name(node_name)
        safe_labels = tuple(validate_label(label) for label in labels)
        safe_server_host = _validate_server_host(server_host)
        safe_node_host_key = _validate_node_host_key(node_ssh_host_public_key)
        _validate_port(enrollment_port, "enrollment_port")
        _validate_port(tunnel_port, "tunnel_port")
        _validate_port(proxy_port, "proxy_port")
        safe_proxy_host = _validate_proxy_host(proxy_host)
        if not 5 <= heartbeat_seconds <= 300:
            raise AdminError("heartbeat_seconds is outside documented bounds")
        actual_now = _utc_now() if now is None else _as_utc(now)
        token = generate_enrollment_token()
        token_hash = sha256_hex(token)
        await self._store.create_enrollment_token(
            token_hash=token_hash,
            node_name=safe_node_name,
            labels=safe_labels,
            node_ssh_host_public_key=safe_node_host_key,
            created_by=actor,
            expires_at=actual_now + dt.timedelta(days=ENROLLMENT_TOKEN_LIFETIME_DAYS),
            now=actual_now,
        )
        await self._audit(
            event_type=AuditEventType.ENROLLMENT_TOKEN_CREATED,
            actor=actor,
            node_name=safe_node_name,
            metadata={"labels": list(safe_labels), "token_hash": token_hash},
            now=actual_now,
        )
        return CreatedAgentPackage(
            node_name=safe_node_name,
            labels=safe_labels,
            agent_conf=_render_agent_conf(
                safe_node_name,
                token,
                server_host=safe_server_host,
                enrollment_port=enrollment_port,
                tunnel_port=tunnel_port,
                proxy_host=safe_proxy_host,
                proxy_port=proxy_port,
                heartbeat_seconds=heartbeat_seconds,
            ),
        )

    async def list_agents(self) -> tuple[AgentSummary, ...]:
        """Return agents safe for CLI display."""
        return await self._store.list_agents()

    async def revoke_agent(
        self, *, node_name: str, actor: str, now: dt.datetime | None = None
    ) -> uuid.UUID:
        """Revoke one agent and audit the credential change."""
        safe_node_name = validate_node_name(node_name)
        actual_now = _utc_now() if now is None else _as_utc(now)
        agent_id = await self._store.revoke_agent(
            node_name=safe_node_name, now=actual_now
        )
        await self._audit(
            event_type=AuditEventType.AGENT_REVOKED,
            actor=actor,
            agent_id=agent_id,
            node_name=safe_node_name,
            metadata={"status": "revoked"},
            now=actual_now,
        )
        return agent_id

    async def rotate_tunnel_secret(
        self, *, node_name: str, actor: str, now: dt.datetime | None = None
    ) -> uuid.UUID:
        """Rotate an agent tunnel secret hash without printing the raw secret."""
        safe_node_name = validate_node_name(node_name)
        actual_now = _utc_now() if now is None else _as_utc(now)
        tunnel_secret = generate_tunnel_secret()
        agent_id = await self._store.rotate_tunnel_secret(
            node_name=safe_node_name,
            tunnel_secret_hash=sha256_hex(tunnel_secret),
            now=actual_now,
        )
        await self._audit(
            event_type=AuditEventType.TUNNEL_SECRET_ROTATED,
            actor=actor,
            agent_id=agent_id,
            node_name=safe_node_name,
            metadata={"tunnel_secret": SECRET_OUTPUT},
            now=actual_now,
        )
        return agent_id

    async def update_node_host_key(
        self,
        *,
        node_name: str,
        node_ssh_host_public_key: str,
        actor: str,
        now: dt.datetime | None = None,
    ) -> uuid.UUID:
        """Update a pinned node sshd host key and audit the change."""
        safe_node_name = validate_node_name(node_name)
        safe_node_host_key = _validate_node_host_key(node_ssh_host_public_key)
        actual_now = _utc_now() if now is None else _as_utc(now)
        agent_id = await self._store.update_node_host_key(
            node_name=safe_node_name,
            node_ssh_host_public_key=safe_node_host_key,
            now=actual_now,
        )
        await self._audit(
            event_type=AuditEventType.NODE_HOST_KEY_UPDATED,
            actor=actor,
            agent_id=agent_id,
            node_name=safe_node_name,
            metadata={"node_ssh_host_public_key": "[pinned]"},
            now=actual_now,
        )
        return agent_id

    async def expire_token(
        self, *, node_name: str, actor: str, now: dt.datetime | None = None
    ) -> int:
        """Expire active enrollment tokens for a node."""
        safe_node_name = validate_node_name(node_name)
        actual_now = _utc_now() if now is None else _as_utc(now)
        count = await self._store.expire_token(node_name=safe_node_name, now=actual_now)
        await self._audit(
            event_type=AuditEventType.ENROLLMENT_TOKEN_EXPIRED,
            actor=actor,
            node_name=safe_node_name,
            metadata={"expired": count},
            now=actual_now,
        )
        return count

    async def list_sessions(
        self, *, node_name: str | None = None, user_name: str | None = None
    ) -> tuple[SessionSummary, ...]:
        """Return session summaries safe for CLI display."""
        safe_node_name = validate_node_name(node_name) if node_name else None
        return await self._store.list_sessions(
            node_name=safe_node_name, user_name=user_name
        )

    async def start_ca_rotation(
        self,
        *,
        key_name: str,
        old_fingerprint: str,
        new_fingerprint: str,
        trusted_fingerprints: Sequence[str],
        actor: str,
        now: dt.datetime | None = None,
    ) -> uuid.UUID:
        """Start CA rotation only when old and new CAs are both trusted."""
        if old_fingerprint == new_fingerprint:
            raise AdminError("CA rotation requires distinct fingerprints")
        _require_overlap(
            old_fingerprint=old_fingerprint,
            new_fingerprint=new_fingerprint,
            trusted_fingerprints=trusted_fingerprints,
        )
        actual_now = _utc_now() if now is None else _as_utc(now)
        rotation_id = await self._store.start_ca_rotation(
            key_name=key_name,
            old_fingerprint=old_fingerprint,
            new_fingerprint=new_fingerprint,
            trusted_fingerprints=trusted_fingerprints,
            now=actual_now,
        )
        await self._audit(
            event_type=AuditEventType.CA_ROTATION_STARTED,
            actor=actor,
            metadata={
                "key_name": key_name,
                "old_fingerprint": old_fingerprint,
                "new_fingerprint": new_fingerprint,
            },
            now=actual_now,
        )
        return rotation_id

    async def complete_ca_rotation(
        self,
        *,
        rotation_id: uuid.UUID,
        trusted_fingerprints: Sequence[str],
        actor: str,
        now: dt.datetime | None = None,
    ) -> RotationState:
        """Complete CA rotation and reject trust bundles retaining the old CA."""
        actual_now = _utc_now() if now is None else _as_utc(now)
        active = await self._store.get_ca_rotation(rotation_id=rotation_id)
        if active.old_fingerprint in trusted_fingerprints:
            raise AdminError("old CA fingerprint remains trusted")
        if active.new_fingerprint not in trusted_fingerprints:
            raise AdminError("new CA fingerprint is not trusted")
        state = await self._store.complete_ca_rotation(
            rotation_id=rotation_id,
            trusted_fingerprints=trusted_fingerprints,
            now=actual_now,
        )
        await self._audit(
            event_type=AuditEventType.CA_ROTATION_COMPLETED,
            actor=actor,
            metadata={"key_name": state.key_name, "status": state.status},
            now=actual_now,
        )
        return state

    async def _audit(
        self,
        *,
        event_type: AuditEventType,
        actor: str,
        metadata: Mapping[str, object],
        agent_id: uuid.UUID | None = None,
        node_name: str | None = None,
        now: dt.datetime | None = None,
    ) -> None:
        if self._audit_writer is None:
            return
        scrubbed_metadata = scrub_secret_metadata(metadata)
        if not isinstance(scrubbed_metadata, Mapping):
            raise AdminError("audit metadata must be an object")
        await self._audit_writer.write(
            event_type=event_type,
            actor=actor,
            agent_id=agent_id,
            node_name=node_name,
            metadata=scrubbed_metadata,
            now=now,
        )


def render_agents(agents: Sequence[AgentSummary]) -> str:
    """Render non-secret agent summaries for CLI output."""
    return "\n".join(
        json.dumps(
            {
                "node_name": agent.node_name,
                "hostname": agent.hostname,
                "labels": list(agent.labels),
                "enrolled_at": _format_datetime(agent.enrolled_at),
                "last_seen": _format_datetime(agent.last_seen),
                "revoked": agent.revoked,
            },
            sort_keys=True,
        )
        for agent in agents
    )


def render_sessions(sessions: Sequence[SessionSummary]) -> str:
    """Render non-secret session summaries for CLI output."""
    return "\n".join(
        json.dumps(
            {
                "session_id": str(session.session_id),
                "node_name": session.node_name,
                "user_name": session.user_name,
                "started_at": _format_datetime(session.started_at),
                "ended_at": _format_datetime(session.ended_at),
                "status": session.status,
            },
            sort_keys=True,
        )
        for session in sessions
    )


def _require_overlap(
    *,
    old_fingerprint: str,
    new_fingerprint: str,
    trusted_fingerprints: Sequence[str],
) -> None:
    trusted = set(trusted_fingerprints)
    if old_fingerprint not in trusted or new_fingerprint not in trusted:
        raise AdminError("CA rotation requires overlapping trust bundle")


def _render_agent_conf(
    node_name: str,
    token: SecretValue,
    *,
    server_host: str = "server",
    enrollment_port: int = 4443,
    tunnel_port: int = 4444,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 2222,
    heartbeat_seconds: int = 30,
) -> str:
    return "\n".join(
        [
            "[enrollment]",
            f"node_name = {node_name}",
            f"token = {token.reveal()}",
            f"api_url = https://{server_host}:{enrollment_port}/enroll",
            "tls_ca_bundle = /etc/vibeconnect/ca.crt",
            "",
            "[tunnel]",
            f"server_url = https://{server_host}:{tunnel_port}/tunnel",
            "tls_ca_bundle = /etc/vibeconnect/ca.crt",
            f"heartbeat_seconds = {heartbeat_seconds}",
            "",
            "[proxy]",
            f"target = {proxy_host}:{proxy_port}",
            "",
            "[identity]",
            "path = /var/lib/vibeconnect/identity.json",
            "",
        ]
    )


def _validate_server_host(value: str) -> str:
    if not value or value.startswith("-") or any(char.isspace() for char in value):
        raise AdminError("invalid server host")
    if "/" in value or ":" in value or "@" in value:
        raise AdminError("invalid server host")
    return value


def _validate_proxy_host(value: str) -> str:
    if not value.startswith("127.") or any(char.isspace() for char in value):
        raise AdminError("invalid proxy host")
    return value


def _validate_node_host_key(value: str) -> str:
    try:
        return validate_node_ssh_host_public_key(value)
    except ValueError as exc:
        raise AdminError(str(exc)) from exc


def _validate_port(value: int, label: str) -> None:
    if not 1 <= value <= 65535:
        raise AdminError(f"{label} is outside valid TCP port bounds")


def _agent_summary(row: Mapping[str, object]) -> AgentSummary:
    return AgentSummary(
        node_name=str(row["node_name"]),
        hostname=None if row["hostname"] is None else str(row["hostname"]),
        labels=_labels(row["labels"]),
        enrolled_at=_optional_datetime(row["enrolled_at"]),
        last_seen=_optional_datetime(row["last_seen"]),
        revoked=bool(row["revoked"]),
    )


def _session_summary(row: Mapping[str, object]) -> SessionSummary:
    session_id = row["id"]
    if not isinstance(session_id, uuid.UUID):
        raise AdminError("session ID must be a UUID")
    started_at = _optional_datetime(row["started_at"])
    if started_at is None:
        raise AdminError("session started_at is required")
    return SessionSummary(
        session_id=session_id,
        node_name=str(row["node_name"]),
        user_name=str(row["user_name"]),
        started_at=started_at,
        ended_at=_optional_datetime(row["ended_at"]),
        status=str(row["status"]),
    )


def _labels(value: object) -> tuple[str, ...]:
    loaded = json.loads(value) if isinstance(value, str) else value
    if not isinstance(loaded, Sequence) or isinstance(loaded, (bytes, bytearray, str)):
        raise AdminError("agent labels must be an array")
    return tuple(str(label) for label in loaded)


def _row_uuid(row: Mapping[str, object], key: str) -> uuid.UUID:
    value = row[key]
    if not isinstance(value, uuid.UUID):
        raise AdminError(f"{key} must be a UUID")
    return value


def _updated_count(result: str) -> int:
    parts = result.split()
    if len(parts) < 2 or not parts[-1].isdigit():
        return 0
    return int(parts[-1])


def _format_datetime(value: dt.datetime | None) -> str | None:
    if value is None:
        return None
    return _as_utc(value).isoformat()


def _optional_datetime(value: object) -> dt.datetime | None:
    if value is None:
        return None
    if not isinstance(value, dt.datetime):
        raise AdminError("timestamp value must be datetime")
    return _as_utc(value)


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)
