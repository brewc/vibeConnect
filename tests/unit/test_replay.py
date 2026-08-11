"""Tests for asciinema replay recording."""

from __future__ import annotations

import datetime as dt
import os
import stat
import uuid
from collections.abc import Mapping
from pathlib import Path

import pytest

from vibeconnect_common.models import AuditEventType
from vibeconnect_common.replay import (
    ReplayError,
    ReplayWriter,
    prune_replays,
    replay_pruned_audit_metadata,
    verify_replay_hmac,
)


class FakeSessionStore:
    """Capture pruned replay pointers."""

    def __init__(self) -> None:
        """Initialize captured session updates."""
        self.pruned: list[uuid.UUID] = []

    def prune_replay_pointer(self, *, session_id: uuid.UUID) -> None:
        """Record pruned replay pointers."""
        self.pruned.append(session_id)


class FakeReplayAuditSink:
    """Capture replay audit events."""

    def __init__(self) -> None:
        """Initialize captured audit events."""
        self.events: list[dict[str, object]] = []

    def write_replay_event(
        self,
        *,
        event_type: AuditEventType,
        session_id: uuid.UUID | None,
        metadata: Mapping[str, object],
    ) -> None:
        """Record a replay audit event."""
        self.events.append(
            {
                "event_type": event_type,
                "session_id": session_id,
                "metadata": metadata,
            }
        )


def test_replay_writer_creates_asciinema_file_with_secure_permissions(
    tmp_path: Path,
) -> None:
    """Replay close publishes a 0600 asciinema file and stores its HMAC."""
    integrity_key = b"replay-integrity-key"
    session_id = uuid.uuid4()
    writer = ReplayWriter(
        directory=tmp_path,
        integrity_key=integrity_key,
    )

    recorder = writer.start(
        session_id=session_id,
        node_name="node-01",
        width=228,
        height=50,
        now=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc),
    )
    recorder.record_output(0.1, "hello")
    recorder.record_input(0.2, "whoami")
    result = recorder.close(now=dt.datetime(2026, 1, 1, 0, 1, tzinfo=dt.timezone.utc))

    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
    assert stat.S_IMODE(result.path.stat().st_mode) == 0o600
    assert result.path == tmp_path / f"{session_id}.cast"
    assert verify_replay_hmac(result.path, integrity_key, result.hmac_hex)
    assert result.ended_at == dt.datetime(2026, 1, 1, 0, 1, tzinfo=dt.timezone.utc)
    lines = result.path.read_text().splitlines()
    assert lines[0] == (
        '{"version":2,"command":"node-01","width":228,"height":50,'
        '"timestamp":1767225600}'
    )
    assert lines[1] == '[0.1,"o","hello"]'
    assert lines[2] == '[0.2,"i","whoami"]'


def test_replay_start_fails_before_session_when_file_cannot_be_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Replay creation failure denies the jump before session start."""
    writer = ReplayWriter(
        directory=tmp_path,
        integrity_key=b"key",
    )

    def fail_mkstemp(*_args: object, **_kwargs: object) -> tuple[int, str]:
        raise OSError("disk full")

    monkeypatch.setattr("tempfile.mkstemp", fail_mkstemp)

    with pytest.raises(ReplayError, match="cannot be created"):
        writer.start(
            session_id=uuid.uuid4(),
            node_name="node-01",
            width=80,
            height=24,
        )


def test_replay_write_failure_marks_session_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mid-session replay write failure marks the session failed."""
    audit_sink = FakeReplayAuditSink()
    session_id = uuid.uuid4()
    writer = ReplayWriter(
        directory=tmp_path,
        integrity_key=b"key",
        audit_sink=audit_sink,
    )
    recorder = writer.start(
        session_id=session_id,
        node_name="node-01",
        width=80,
        height=24,
    )

    def fail_write(_data: bytes) -> int:
        raise OSError("disk full")

    monkeypatch.setattr(recorder._file, "write", fail_write)

    with pytest.raises(ReplayError, match="write failed"):
        recorder.record_output(1.0, "lost")

    assert audit_sink.events == [
        {
            "event_type": AuditEventType.REPLAY_WRITE_FAILED,
            "session_id": session_id,
            "metadata": {
                "replay_path": str(tmp_path / f"{session_id}.cast"),
                "error": "disk full",
            },
        }
    ]


def test_prune_replays_deletes_expired_files_and_clears_pointers(
    tmp_path: Path,
) -> None:
    """Retention pruning deletes old replay data and records cleared pointers."""
    store = FakeSessionStore()
    audit_sink = FakeReplayAuditSink()
    old_session = uuid.uuid4()
    fresh_session = uuid.uuid4()
    old_path = tmp_path / f"{old_session}.cast"
    fresh_path = tmp_path / f"{fresh_session}.cast"
    old_path.write_text("old")
    fresh_path.write_text("fresh")
    now = dt.datetime(2026, 1, 10, tzinfo=dt.timezone.utc)
    old_time = now.timestamp() - 31 * 24 * 60 * 60
    fresh_time = now.timestamp()
    os.utime(old_path, (old_time, old_time))
    os.utime(fresh_path, (fresh_time, fresh_time))

    pruned = prune_replays(
        directory=tmp_path,
        retention_days=30,
        session_store=store,
        audit_sink=audit_sink,
        now=now,
    )

    assert pruned == [old_path]
    assert not old_path.exists()
    assert fresh_path.exists()
    assert store.pruned == [old_session]
    assert replay_pruned_audit_metadata(pruned) == {
        "event_type": "replay_pruned",
        "pruned_count": 1,
        "replay_paths": [str(old_path)],
    }
    assert audit_sink.events == [
        {
            "event_type": AuditEventType.REPLAY_PRUNED,
            "session_id": None,
            "metadata": replay_pruned_audit_metadata(pruned),
        }
    ]
