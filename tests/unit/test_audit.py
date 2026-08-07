"""Tests for audit event writing."""

from __future__ import annotations

import datetime as dt
import json
import uuid
from collections.abc import Mapping

import pytest

from vibeconnect_common.audit import AUDIT_METADATA_MAX_BYTES, AuditError, AuditWriter
from vibeconnect_common.crypto import SECRET_REDACTION
from vibeconnect_common.models import AuditEventType


class FakeAuditConnection:
    """Capture audit insert statements."""

    def __init__(self) -> None:
        """Initialize captured statements."""
        self.executed: list[tuple[str, tuple[object, ...]]] = []

    async def execute(self, query: str, *args: object) -> str:
        """Record executed SQL."""
        self.executed.append((query, args))
        return "INSERT 0 1"


@pytest.mark.asyncio
async def test_audit_writer_scrubs_metadata_before_insert() -> None:
    """Audit metadata is scrubbed of sensitive values before persistence."""
    connection = FakeAuditConnection()
    writer = AuditWriter(connection)

    event = await writer.write(
        event_type=AuditEventType.ENROLLMENT_FAILED,
        actor="server",
        node_name="node-01",
        metadata={
            "token": "raw-token",
            "nested": {"privateKey": "raw-private-key"},
            "safe": "value",
        },
    )

    inserted_metadata = _inserted_metadata(connection)
    assert event.metadata["token"] == SECRET_REDACTION
    assert inserted_metadata["token"] == SECRET_REDACTION
    assert inserted_metadata["nested"] == {"privateKey": SECRET_REDACTION}
    assert inserted_metadata["safe"] == "value"
    assert "raw-token" not in json.dumps(inserted_metadata)
    assert "raw-private-key" not in json.dumps(inserted_metadata)


@pytest.mark.asyncio
async def test_audit_writer_rejects_oversized_metadata() -> None:
    """Audit metadata is limited to 16 KiB."""
    writer = AuditWriter(FakeAuditConnection())

    with pytest.raises(AuditError, match="16 KiB"):
        await writer.write(
            event_type=AuditEventType.REPLAY_WRITE_FAILED,
            actor="server",
            metadata={"padding": "x" * AUDIT_METADATA_MAX_BYTES},
        )


@pytest.mark.asyncio
async def test_audit_writer_records_required_event_context() -> None:
    """Audit inserts include the required event fields."""
    connection = FakeAuditConnection()
    writer = AuditWriter(connection)
    agent_id = uuid.uuid4()
    session_id = uuid.uuid4()
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    event = await writer.write(
        event_type=AuditEventType.SESSION_STARTED,
        actor="alice",
        agent_id=agent_id,
        session_id=session_id,
        node_name="node-01",
        now=now,
        metadata={"ok": True},
    )

    _query, args = connection.executed[0]
    assert event.event_type == AuditEventType.SESSION_STARTED
    assert args[1] == "session_started"
    assert args[2] == "alice"
    assert args[3] == agent_id
    assert args[4] == session_id
    assert args[5] == "node-01"
    assert args[6] == now


def _inserted_metadata(connection: FakeAuditConnection) -> Mapping[str, object]:
    _query, args = connection.executed[0]
    metadata = args[7]
    assert isinstance(metadata, str)
    decoded = json.loads(metadata)
    assert isinstance(decoded, dict)
    return decoded
