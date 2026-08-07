"""Asciinema replay recording with HMAC integrity."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import tempfile
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol

from vibeconnect_common.models import AuditEventType, SessionStatus


class ReplayError(RuntimeError):
    """Raised when replay capture cannot continue safely."""


class SessionStore(Protocol):
    """Persistence surface used by replay close/failure paths."""

    def close_session(
        self,
        *,
        session_id: uuid.UUID,
        status: SessionStatus,
        ended_at: dt.datetime,
        replay_path: Path,
        replay_hmac: str | None,
    ) -> None:
        """Persist the final replay session state."""

    def prune_replay_pointer(self, *, session_id: uuid.UUID) -> None:
        """Clear a pruned replay pointer from the session record."""


class ReplayAuditSink(Protocol):
    """Audit surface used by replay failure and pruning paths."""

    def write_replay_event(
        self,
        *,
        event_type: AuditEventType,
        session_id: uuid.UUID | None,
        metadata: Mapping[str, object],
    ) -> None:
        """Persist or enqueue a replay audit event."""


@dataclass(frozen=True, slots=True)
class ReplayCloseResult:
    """Final replay metadata returned after close."""

    path: Path
    hmac_hex: str
    ended_at: dt.datetime


class ReplayRecorder:
    """Write one asciinema v2 replay file atomically."""

    def __init__(
        self,
        *,
        session_id: uuid.UUID,
        node_name: str,
        path: Path,
        temp_path: Path,
        file: BinaryIO,
        integrity_key: bytes,
        session_store: SessionStore,
        audit_sink: ReplayAuditSink | None,
        started_at: dt.datetime,
        width: int,
        height: int,
    ) -> None:
        """Create a recorder around an already-open temporary file."""
        self._session_id = session_id
        self._path = path
        self._temp_path = temp_path
        self._file = file
        self._integrity_key = integrity_key
        self._session_store = session_store
        self._audit_sink = audit_sink
        self._closed = False
        header = {
            "version": 2,
            "command": node_name,
            "width": width,
            "height": height,
            "timestamp": int(started_at.timestamp()),
        }
        self._write_line(json.dumps(header, separators=(",", ":")))

    def record_output(self, seconds: float, data: str) -> None:
        """Record terminal output bytes decoded as text."""
        self._record(seconds, "o", data)

    def record_input(self, seconds: float, data: str) -> None:
        """Record terminal input bytes decoded as text."""
        self._record(seconds, "i", data)

    def fail(self, *, error: str, now: dt.datetime | None = None) -> None:
        """Close a failed replay and persist failed session state."""
        if self._closed:
            return
        ended_at = _utc_now() if now is None else _as_utc(now)
        self._closed = True
        self._close_file()
        self._session_store.close_session(
            session_id=self._session_id,
            status=SessionStatus.FAILED,
            ended_at=ended_at,
            replay_path=self._path,
            replay_hmac=None,
        )
        if self._audit_sink is not None:
            self._audit_sink.write_replay_event(
                event_type=AuditEventType.REPLAY_WRITE_FAILED,
                session_id=self._session_id,
                metadata={
                    "replay_path": str(self._path),
                    "error": error,
                },
            )
        _unlink_if_exists(self._temp_path)

    def close(self, *, now: dt.datetime | None = None) -> ReplayCloseResult:
        """Atomically publish the replay and persist the closed session state."""
        if self._closed:
            raise ReplayError("replay is already closed")
        ended_at = _utc_now() if now is None else _as_utc(now)
        self._closed = True
        self._file.flush()
        os.fsync(self._file.fileno())
        self._close_file()
        os.replace(self._temp_path, self._path)
        replay_bytes = self._path.read_bytes()
        hmac_hex = hmac.new(
            self._integrity_key, replay_bytes, hashlib.sha256
        ).hexdigest()
        self._session_store.close_session(
            session_id=self._session_id,
            status=SessionStatus.CLOSED,
            ended_at=ended_at,
            replay_path=self._path,
            replay_hmac=hmac_hex,
        )
        return ReplayCloseResult(path=self._path, hmac_hex=hmac_hex, ended_at=ended_at)

    def _record(self, seconds: float, stream: str, data: str) -> None:
        if self._closed:
            raise ReplayError("replay is already closed")
        try:
            self._write_line(json.dumps([seconds, stream, data], separators=(",", ":")))
        except OSError as exc:
            self.fail(error=str(exc))
            raise ReplayError("replay write failed") from exc

    def _write_line(self, line: str) -> None:
        self._file.write(line.encode("utf-8") + b"\n")

    def _close_file(self) -> None:
        if not self._file.closed:
            self._file.close()


class ReplayWriter:
    """Factory for sensitive replay recordings."""

    def __init__(
        self,
        *,
        directory: Path,
        integrity_key: bytes,
        session_store: SessionStore,
        audit_sink: ReplayAuditSink | None = None,
    ) -> None:
        """Configure replay storage."""
        if not integrity_key:
            raise ReplayError("replay integrity key is required")
        self._directory = directory
        self._integrity_key = integrity_key
        self._session_store = session_store
        self._audit_sink = audit_sink

    def start(
        self,
        *,
        session_id: uuid.UUID,
        node_name: str,
        width: int,
        height: int,
        now: dt.datetime | None = None,
    ) -> ReplayRecorder:
        """Start a replay or raise before session start if storage is unavailable."""
        _prepare_replay_directory(self._directory)
        path = self._directory / f"{session_id}.cast"
        started_at = _utc_now() if now is None else _as_utc(now)
        try:
            fd, temp_name = tempfile.mkstemp(
                prefix=f".{session_id}.", suffix=".tmp", dir=self._directory
            )
            os.chmod(temp_name, 0o600)
            file = os.fdopen(fd, "wb")
        except OSError as exc:
            raise ReplayError("replay file cannot be created") from exc

        try:
            return ReplayRecorder(
                session_id=session_id,
                node_name=node_name,
                path=path,
                temp_path=Path(temp_name),
                file=file,
                integrity_key=self._integrity_key,
                session_store=self._session_store,
                audit_sink=self._audit_sink,
                started_at=started_at,
                width=width,
                height=height,
            )
        except OSError as exc:
            file.close()
            _unlink_if_exists(Path(temp_name))
            raise ReplayError("replay file cannot be created") from exc


def verify_replay_hmac(path: Path, integrity_key: bytes, expected_hmac: str) -> bool:
    """Verify a replay file against its stored HMAC."""
    actual = hmac.new(integrity_key, path.read_bytes(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(actual, expected_hmac)


def prune_replays(
    *,
    directory: Path,
    retention_days: int,
    session_store: SessionStore,
    audit_sink: ReplayAuditSink | None = None,
    now: dt.datetime | None = None,
) -> list[Path]:
    """Delete expired replay files and clear their session pointers."""
    if retention_days < 1:
        raise ReplayError("retention_days must be positive")
    actual_now = _utc_now() if now is None else _as_utc(now)
    cutoff = actual_now.timestamp() - retention_days * 24 * 60 * 60
    pruned: list[Path] = []
    for path in sorted(directory.glob("*.cast")):
        if path.stat().st_mtime >= cutoff:
            continue
        session_id = uuid.UUID(path.stem)
        path.unlink()
        session_store.prune_replay_pointer(session_id=session_id)
        pruned.append(path)
    if pruned and audit_sink is not None:
        audit_sink.write_replay_event(
            event_type=AuditEventType.REPLAY_PRUNED,
            session_id=None,
            metadata=replay_pruned_audit_metadata(pruned),
        )
    return pruned


def replay_pruned_audit_metadata(paths: list[Path]) -> dict[str, object]:
    """Build metadata for a replay pruning audit event."""
    return {
        "event_type": AuditEventType.REPLAY_PRUNED.value,
        "pruned_count": len(paths),
        "replay_paths": [str(path) for path in paths],
    }


def _prepare_replay_directory(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    mode = directory.stat().st_mode & 0o777
    if mode != 0o700:
        raise ReplayError("replay directory must have mode 0700")


def _unlink_if_exists(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)
