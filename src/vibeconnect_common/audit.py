"""Audit event writing with metadata limits and secret scrubbing."""

from __future__ import annotations

import datetime as dt
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from vibeconnect_common.crypto import scrub_secret_metadata
from vibeconnect_common.models import AuditEventType

AUDIT_METADATA_MAX_BYTES = 16 * 1024


class AuditError(ValueError):
    """Raised when an audit event is invalid or unsafe to persist."""


class AuditConnection(Protocol):
    """Database surface required by the audit writer."""

    async def execute(self, query: str, *args: object) -> str:
        """Execute a SQL statement."""


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Sanitized audit event ready for persistence."""

    id: uuid.UUID
    event_type: AuditEventType
    actor: str
    agent_id: uuid.UUID | None
    session_id: uuid.UUID | None
    node_name: str | None
    created_at: dt.datetime
    metadata: Mapping[str, object]


class AuditWriter:
    """Write scrubbed audit events to PostgreSQL."""

    def __init__(self, connection: AuditConnection) -> None:
        """Store the database connection used for audit inserts."""
        self._connection = connection

    async def write(
        self,
        *,
        event_type: AuditEventType,
        actor: str,
        metadata: Mapping[str, object],
        agent_id: uuid.UUID | None = None,
        session_id: uuid.UUID | None = None,
        node_name: str | None = None,
        now: dt.datetime | None = None,
    ) -> AuditEvent:
        """Scrub, size-check, and persist one audit event."""
        if not actor:
            raise AuditError("audit actor is required")
        sanitized = _sanitize_metadata(metadata)
        event = AuditEvent(
            id=uuid.uuid4(),
            event_type=event_type,
            actor=actor,
            agent_id=agent_id,
            session_id=session_id,
            node_name=node_name,
            created_at=_utc_now() if now is None else _as_utc(now),
            metadata=sanitized,
        )
        await self._connection.execute(
            """
            INSERT INTO audit_events(
                id, event_type, actor, agent_id, session_id, node_name,
                created_at, metadata
            )
            VALUES($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
            """,
            event.id,
            event.event_type.value,
            event.actor,
            event.agent_id,
            event.session_id,
            event.node_name,
            event.created_at,
            json.dumps(event.metadata, separators=(",", ":"), sort_keys=True),
        )
        return event


def _sanitize_metadata(metadata: Mapping[str, object]) -> Mapping[str, object]:
    scrubbed = scrub_secret_metadata(metadata)
    if not isinstance(scrubbed, dict):
        raise AuditError("audit metadata must be a JSON object")
    encoded = json.dumps(scrubbed, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    if len(encoded) > AUDIT_METADATA_MAX_BYTES:
        raise AuditError("audit metadata exceeds 16 KiB")
    return scrubbed


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)
