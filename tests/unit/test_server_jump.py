"""Tests for server-side SSH jump orchestration."""

from __future__ import annotations

import datetime as dt
import uuid
from pathlib import Path
from typing import cast

import asyncssh
import pytest

from server.auth import NodeInventoryEntry, ResolvedIdentity
from server.jump import (
    AsyncSshJumpSessionLifecycle,
    AsyncSshNodeTunnelOpener,
    JumpError,
    JumpPtyBridge,
    JumpSession,
    JumpTarget,
    PostgresJumpStore,
    ServerJumpCoordinator,
    StartedJump,
    TunnelStreamAdapter,
    _decode_pty,
    validate_pinned_host_key,
)
from server.tunnel import HeartbeatState
from vibeconnect_common.crypto import IssuedUserCertificate
from vibeconnect_common.models import AuditEventType, SessionStatus
from vibeconnect_common.replay import ReplayCloseResult, ReplayError, ReplayRecorder

_NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


def test_pinned_host_key_rejects_missing_and_mismatched_keys() -> None:
    """Node sshd host keys must be pinned and match exactly."""
    assert (
        validate_pinned_host_key(
            expected_host_key="ssh-ed25519 AAAAhost",
            presented_host_key="ssh-ed25519 AAAAhost",
        )
        == "ssh-ed25519 AAAAhost"
    )
    with pytest.raises(JumpError, match="not pinned"):
        validate_pinned_host_key(
            expected_host_key=None,
            presented_host_key="ssh-ed25519 AAAAhost",
        )
    with pytest.raises(JumpError, match="not presented"):
        validate_pinned_host_key(
            expected_host_key="ssh-ed25519 AAAAhost",
            presented_host_key=None,
        )
    with pytest.raises(JumpError, match="mismatch"):
        validate_pinned_host_key(
            expected_host_key="ssh-ed25519 AAAAhost",
            presented_host_key="ssh-ed25519 AAAAother",
        )


def test_decode_pty_preserves_non_utf8_bytes_without_replacement() -> None:
    """Replay text decoding preserves arbitrary PTY bytes for round-trip."""
    decoded = _decode_pty(b"\x1b[31m\xff")

    assert "\ufffd" not in decoded
    assert decoded.encode("utf-8", errors="surrogateescape") == b"\x1b[31m\xff"


@pytest.mark.asyncio
async def test_jump_starts_replay_issues_bound_cert_and_opens_tunnel() -> None:
    """A valid jump creates session state before opening a tunnel channel."""
    store = FakeJumpStore()
    replay = FakeReplayStarter()
    issuer = FakeCertificateIssuer()
    tunnel = FakeTunnelOpener()
    audit = FakeAuditSink()

    started = await ServerJumpCoordinator(
        store=store,
        replay_starter=replay,
        certificate_issuer=issuer,
        tunnel_opener=tunnel,
        audit_sink=audit,
    ).start_jump(
        identity=_identity(),
        command="node-01",
        visible_nodes=(_node(),),
        presented_node_host_key="ssh-ed25519 AAAAhost",
        width=80,
        height=24,
        now=_NOW,
    )

    assert store.created == [("node-01", "alice")]
    assert replay.started == [(store.session.session_id, "node-01", 80, 24)]
    assert issuer.issued == [("alice", store.session.session_id, 42)]
    assert tunnel.opened == [
        (
            store.target.agent_id,
            started.channel_id,
            "node-01",
            "alice",
            started.user_certificate,
        )
    ]
    assert audit.events[-1]["event_type"] is AuditEventType.SESSION_STARTED


@pytest.mark.asyncio
async def test_asyncssh_node_tunnel_opener_uses_issued_cert_and_username() -> None:
    """The node SSH client authenticates with the server-issued user cert."""
    connector = object()
    resolver = FakeAgentTunnelConnectorResolver(connector=connector)
    connect = FakeAsyncSshConnect()
    certificate = _issued_certificate(username="alice")
    agent_id = uuid.uuid4()

    await AsyncSshNodeTunnelOpener(
        connector_resolver=resolver,
        connect=connect,
    ).open_session(
        agent_id=agent_id,
        channel_id="channel-01",
        node_name="node-01",
        node_ssh_host_public_key="ssh-ed25519 AAAAhost",
        username="alice",
        user_certificate=certificate,
    )

    assert resolver.requests == [(agent_id, "channel-01")]
    assert resolver.opened == [
        (
            agent_id,
            "channel-01",
            "node-01",
            "ssh-ed25519 AAAAhost",
            "alice",
            certificate,
        )
    ]
    assert connect.calls == [
        {
            "host": "node-01",
            "port": 2222,
            "tunnel": connector,
            "username": "alice",
            "client_keys": [(certificate.private_key, certificate.certificate)],
            "agent_path": None,
            "agent_forwarding": False,
            "x11_forwarding": False,
            "config": None,
        }
    ]
    assert connect.known_hosts is not None


@pytest.mark.asyncio
async def test_asyncssh_node_tunnel_opener_rejects_unpinned_host_key() -> None:
    """The node SSH client never opens with permissive host-key policy."""
    connect = FakeAsyncSshConnect()

    with pytest.raises(JumpError, match="not pinned"):
        await AsyncSshNodeTunnelOpener(
            connector_resolver=FakeAgentTunnelConnectorResolver(connector=object()),
            connect=connect,
        ).open_session(
            agent_id=uuid.uuid4(),
            channel_id="channel-01",
            node_name="node-01",
            node_ssh_host_public_key="",
            username="alice",
            user_certificate=_issued_certificate(username="alice"),
        )

    assert connect.calls == []


@pytest.mark.asyncio
async def test_asyncssh_node_tunnel_opener_rejects_cert_username_mismatch() -> None:
    """The node SSH client fails closed if the cert principal no longer matches."""
    connect = FakeAsyncSshConnect()

    with pytest.raises(JumpError, match="principal"):
        await AsyncSshNodeTunnelOpener(
            connector_resolver=FakeAgentTunnelConnectorResolver(connector=object()),
            connect=connect,
        ).open_session(
            agent_id=uuid.uuid4(),
            channel_id="channel-01",
            node_name="node-01",
            node_ssh_host_public_key="ssh-ed25519 AAAAhost",
            username="alice",
            user_certificate=_issued_certificate(username="bob"),
        )

    assert connect.calls == []


@pytest.mark.asyncio
async def test_asyncssh_node_tunnel_opener_closes_channel_on_connect_failure() -> None:
    """Failed node SSH connects close the brokered tunnel channel."""
    resolver = FakeAgentTunnelConnectorResolver(connector=object())

    with pytest.raises(JumpError, match="node SSH"):
        await AsyncSshNodeTunnelOpener(
            connector_resolver=resolver,
            connect=FailingAsyncSshConnect(),
        ).open_session(
            agent_id=uuid.uuid4(),
            channel_id="channel-01",
            node_name="node-01",
            node_ssh_host_public_key="ssh-ed25519 AAAAhost",
            username="alice",
            user_certificate=_issued_certificate(username="alice"),
        )

    assert resolver.closed == ["channel-01"]


@pytest.mark.asyncio
async def test_jump_denies_replay_creation_failure_before_tunnel_open() -> None:
    """Replay creation failure denies the jump and leaves the tunnel unopened."""
    store = FakeJumpStore()
    replay = FakeReplayStarter(fail=True)
    tunnel = FakeTunnelOpener()

    with pytest.raises(JumpError, match="replay"):
        await ServerJumpCoordinator(
            store=store,
            replay_starter=replay,
            certificate_issuer=FakeCertificateIssuer(),
            tunnel_opener=tunnel,
            audit_sink=FakeAuditSink(),
        ).start_jump(
            identity=_identity(),
            command="node-01",
            visible_nodes=(_node(),),
            presented_node_host_key="ssh-ed25519 AAAAhost",
            width=80,
            height=24,
            now=_NOW,
        )

    assert store.failed == [store.session.session_id]
    assert tunnel.opened == []


@pytest.mark.asyncio
async def test_jump_marks_session_failed_when_tunnel_open_fails() -> None:
    """Post-replay tunnel failures do not leave sessions open."""
    store = FakeJumpStore()
    replay = FakeReplayStarter()

    with pytest.raises(JumpError, match="node SSH"):
        await ServerJumpCoordinator(
            store=store,
            replay_starter=replay,
            certificate_issuer=FakeCertificateIssuer(),
            tunnel_opener=FakeTunnelOpener(fail=True),
            audit_sink=FakeAuditSink(),
        ).start_jump(
            identity=_identity(),
            command="node-01",
            visible_nodes=(_node(),),
            presented_node_host_key="ssh-ed25519 AAAAhost",
            width=80,
            height=24,
            now=_NOW,
        )

    assert replay.recorder.failed == ["node SSH connection failed"]
    assert store.failed == [store.session.session_id]


@pytest.mark.asyncio
async def test_jump_rejects_user_cert_principal_mismatch() -> None:
    """Issued user cert principals must exactly match the authenticated identity."""
    store = FakeJumpStore()
    replay = FakeReplayStarter()
    tunnel = FakeTunnelOpener()

    with pytest.raises(JumpError, match="principal"):
        await ServerJumpCoordinator(
            store=store,
            replay_starter=replay,
            certificate_issuer=FakeCertificateIssuer(username="bob"),
            tunnel_opener=tunnel,
        ).start_jump(
            identity=_identity(),
            command="node-01",
            visible_nodes=(_node(),),
            presented_node_host_key="ssh-ed25519 AAAAhost",
            width=80,
            height=24,
            now=_NOW,
        )

    assert replay.recorder.failed == ["certificate principal mismatch"]
    assert store.failed == [store.session.session_id]
    assert tunnel.opened == []


@pytest.mark.asyncio
async def test_jump_requires_fresh_tunnel_heartbeat() -> None:
    """Stale tunnels cannot accept new jumps."""
    store = FakeJumpStore(fresh=False)

    with pytest.raises(JumpError, match="fresh"):
        await ServerJumpCoordinator(
            store=store,
            replay_starter=FakeReplayStarter(),
            certificate_issuer=FakeCertificateIssuer(),
            tunnel_opener=FakeTunnelOpener(),
            audit_sink=FakeAuditSink(),
        ).start_jump(
            identity=_identity(),
            command="node-01",
            visible_nodes=(_node(),),
            presented_node_host_key="ssh-ed25519 AAAAhost",
            width=80,
            height=24,
            now=_NOW,
        )


@pytest.mark.asyncio
async def test_pty_bridge_records_and_forwards_raw_bytes() -> None:
    """PTY bridge records replay text without changing tunnel bytes."""
    started = _started_jump()
    tunnel = FakeTunnelPtyChannel()

    bridge = JumpPtyBridge(started_jump=started, tunnel_channel=tunnel)

    await bridge.send_user_input(seconds=0.1, payload=b"whoami\n")
    output = bridge.receive_node_output(seconds=0.2, payload=b"alice\n")
    await bridge.resize_pty(width=100, height=40)

    assert output == b"alice\n"
    recorder = cast(FakeReplayRecorder, started.replay)
    assert recorder.inputs == [(0.1, "whoami\n")]
    assert recorder.outputs == [(0.2, "alice\n")]
    assert tunnel.sent == [(started.channel_id, b"whoami\n")]
    assert tunnel.resized == [(started.channel_id, 100, 40)]


@pytest.mark.asyncio
async def test_pty_bridge_closes_replay_tunnel_and_audit() -> None:
    """Normal close publishes replay, closes tunnel channel, and audits closure."""
    started = _started_jump()
    tunnel = FakeTunnelPtyChannel()
    audit = FakeAuditSink()
    session_state = FakeJumpSessionStateStore()

    await JumpPtyBridge(
        started_jump=started,
        tunnel_channel=tunnel,
        audit_sink=audit,
        session_state_store=session_state,
    ).close(status=SessionStatus.CLOSED, now=_NOW)

    recorder = cast(FakeReplayRecorder, started.replay)
    assert recorder.closed == [_NOW]
    assert session_state.closed == [
        {
            "session_id": started.session.session_id,
            "status": SessionStatus.CLOSED,
            "ended_at": _NOW,
            "replay_path": Path("session.cast"),
            "replay_hmac": "abc123hmac",
            "error": None,
        }
    ]
    assert tunnel.closed == [started.channel_id]
    assert audit.events[-1]["event_type"] is AuditEventType.SESSION_CLOSED
    assert audit.events[-1]["metadata"] == {
        "status": "closed",
        "replay_path": "session.cast",
        "replay_hmac": "abc123hmac",
    }


@pytest.mark.asyncio
async def test_pty_bridge_failed_close_marks_replay_failed() -> None:
    """Failed jumps fail replay and audit the failure."""
    started = _started_jump()
    audit = FakeAuditSink()
    session_state = FakeJumpSessionStateStore()

    await JumpPtyBridge(
        started_jump=started,
        tunnel_channel=FakeTunnelPtyChannel(),
        audit_sink=audit,
        session_state_store=session_state,
    ).close(status=SessionStatus.FAILED, now=_NOW, error="node disconnected")

    recorder = cast(FakeReplayRecorder, started.replay)
    assert recorder.failed == ["node disconnected"]
    assert session_state.closed == [
        {
            "session_id": started.session.session_id,
            "status": SessionStatus.FAILED,
            "ended_at": _NOW,
            "replay_path": Path("session.cast"),
            "replay_hmac": None,
            "error": "node disconnected",
        }
    ]
    assert audit.events[-1]["event_type"] is AuditEventType.SESSION_FAILED
    assert audit.events[-1]["metadata"] == {
        "status": "failed",
        "error": "node disconnected",
    }


@pytest.mark.asyncio
async def test_pty_bridge_rejects_io_after_close() -> None:
    """Closed bridges cannot forward more PTY bytes."""
    bridge = JumpPtyBridge(
        started_jump=_started_jump(),
        tunnel_channel=FakeTunnelPtyChannel(),
    )

    await bridge.close(status=SessionStatus.CLOSED, now=_NOW)

    with pytest.raises(JumpError, match="closed"):
        await bridge.send_user_input(seconds=0.3, payload=b"id\n")


@pytest.mark.asyncio
async def test_tunnel_stream_adapter_queues_reads_and_writes() -> None:
    """Tunnel stream adapter preserves raw bytes across read/write operations."""
    tunnel = FakeTunnelPtyChannel()
    adapter = TunnelStreamAdapter(channel_id="channel-01", tunnel_channel=tunnel)

    adapter.feed_data(b"alice\n")
    assert await adapter.read() == b"alice\n"

    await adapter.write(b"whoami\n")
    await adapter.resize_pty(width=90, height=30)
    await adapter.close()

    assert tunnel.sent == [("channel-01", b"whoami\n")]
    assert tunnel.resized == [("channel-01", 90, 30)]
    assert tunnel.closed == ["channel-01"]
    with pytest.raises(JumpError, match="closed"):
        await adapter.write(b"id\n")


@pytest.mark.asyncio
async def test_tunnel_stream_adapter_returns_empty_bytes_after_eof() -> None:
    """EOF maps to empty bytes for AsyncSSH-style stream readers."""
    adapter = TunnelStreamAdapter(
        channel_id="channel-01",
        tunnel_channel=FakeTunnelPtyChannel(),
    )

    adapter.feed_eof()

    assert await adapter.read() == b""
    assert await adapter.read() == b""
    with pytest.raises(JumpError, match="EOF"):
        adapter.feed_data(b"late output")


@pytest.mark.asyncio
async def test_asyncssh_lifecycle_persists_normal_disconnect() -> None:
    """AsyncSSH normal close maps to a closed jump session."""
    started = _started_jump()
    session_state = FakeJumpSessionStateStore()
    bridge = JumpPtyBridge(
        started_jump=started,
        tunnel_channel=FakeTunnelPtyChannel(),
        session_state_store=session_state,
    )

    await AsyncSshJumpSessionLifecycle(bridge=bridge).connection_lost(
        exc=None,
        now=_NOW,
    )

    assert session_state.closed[-1]["status"] is SessionStatus.CLOSED
    assert session_state.closed[-1]["error"] is None


@pytest.mark.asyncio
async def test_asyncssh_lifecycle_persists_exception_disconnect() -> None:
    """AsyncSSH exceptional close maps to a failed jump session."""
    started = _started_jump()
    session_state = FakeJumpSessionStateStore()
    bridge = JumpPtyBridge(
        started_jump=started,
        tunnel_channel=FakeTunnelPtyChannel(),
        session_state_store=session_state,
    )

    await AsyncSshJumpSessionLifecycle(bridge=bridge).connection_lost(
        exc=ConnectionError("node reset"),
        now=_NOW,
    )

    assert session_state.closed[-1]["status"] is SessionStatus.FAILED
    assert session_state.closed[-1]["error"] == "node reset"


@pytest.mark.asyncio
async def test_asyncssh_lifecycle_persists_termination() -> None:
    """Explicit server termination maps to a terminated jump session."""
    started = _started_jump()
    session_state = FakeJumpSessionStateStore()
    bridge = JumpPtyBridge(
        started_jump=started,
        tunnel_channel=FakeTunnelPtyChannel(),
        session_state_store=session_state,
    )

    await AsyncSshJumpSessionLifecycle(bridge=bridge).terminate(
        reason="admin revoked agent",
        now=_NOW,
    )

    assert session_state.closed[-1]["status"] is SessionStatus.TERMINATED
    assert session_state.closed[-1]["error"] == "admin revoked agent"


@pytest.mark.asyncio
async def test_postgres_jump_store_maps_target_and_session_state() -> None:
    """The PostgreSQL jump store uses schema-backed target and session rows."""
    agent_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    session_id = uuid.UUID("00000000-0000-0000-0000-000000000002")
    connection = FakeJumpConnection(
        rows=[
            {
                "id": agent_id,
                "node_name": "node-01",
                "node_ssh_host_public_key": "ssh-ed25519 AAAAhost",
                "last_seen": _NOW,
            },
            {
                "id": session_id,
                "user_cert_serial": 42,
                "replay_path": "session.cast",
                "started_at": _NOW,
            },
        ]
    )
    store = PostgresJumpStore(connection, heartbeat_seconds=10)

    target = await store.get_jump_target("node-01")
    session = await store.create_session(
        agent_id=agent_id,
        username="alice",
        node_name="node-01",
        replay_path=Path("session.cast"),
        started_at=_NOW,
    )
    await store.close_session(
        session_id=session.session_id,
        status=SessionStatus.CLOSED,
        ended_at=_NOW + dt.timedelta(seconds=1),
        replay_path=Path("session.cast"),
        replay_hmac="abc123hmac",
        error=None,
    )

    assert target is not None
    assert target.heartbeat.allows_new_jump(_NOW)
    assert session.session_id == session_id
    assert "revoked = false" in connection.fetches[0][0]
    assert "INSERT INTO sessions" in connection.fetches[1][0]
    assert "status = 'open'" in connection.executed[0][0]


class FakeJumpStore:
    """In-memory jump store for coordinator tests."""

    def __init__(self, *, fresh: bool = True) -> None:
        """Create a store with one target and deterministic session."""
        heartbeat = HeartbeatState(heartbeat_seconds=10)
        if fresh:
            heartbeat.mark_seen(_NOW)
        self.target = JumpTarget(
            agent_id=uuid.uuid4(),
            node_name="node-01",
            node_ssh_host_public_key="ssh-ed25519 AAAAhost",
            heartbeat=heartbeat,
        )
        self.session = JumpSession(
            session_id=uuid.uuid4(),
            user_cert_serial=42,
            replay_path=Path("session.cast"),
            started_at=_NOW,
        )
        self.created: list[tuple[str, str]] = []
        self.failed: list[uuid.UUID] = []

    async def get_jump_target(self, node_name: str) -> JumpTarget | None:
        """Return the test target by node name."""
        if node_name == self.target.node_name:
            return self.target
        return None

    async def create_session(
        self,
        *,
        agent_id: uuid.UUID,
        username: str,
        node_name: str,
        replay_path: Path,
        started_at: dt.datetime,
    ) -> JumpSession:
        """Record session creation."""
        self.created.append((node_name, username))
        return self.session

    async def fail_session(
        self, *, session_id: uuid.UUID, ended_at: dt.datetime
    ) -> None:
        """Record session failure."""
        self.failed.append(session_id)


class FakeJumpConnection:
    """Capture PostgreSQL jump store calls."""

    def __init__(self, *, rows: list[dict[str, object]]) -> None:
        """Initialize queued fetch rows."""
        self.rows = rows
        self.fetches: list[tuple[str, tuple[object, ...]]] = []
        self.executed: list[tuple[str, tuple[object, ...]]] = []

    async def fetchrow(self, query: str, *args: object) -> dict[str, object] | None:
        """Record one fetchrow call."""
        self.fetches.append((query, args))
        return self.rows.pop(0) if self.rows else None

    async def execute(self, query: str, *args: object) -> str:
        """Record one execute call."""
        self.executed.append((query, args))
        return "OK"


class FakeReplayStarter:
    """Replay factory fake."""

    def __init__(self, *, fail: bool = False) -> None:
        """Configure whether replay start fails."""
        self.fail = fail
        self.started: list[tuple[uuid.UUID, str, int, int]] = []
        self.recorder = FakeReplayRecorder()

    def start(
        self,
        *,
        session_id: uuid.UUID,
        node_name: str,
        width: int,
        height: int,
        now: dt.datetime | None = None,
    ) -> ReplayRecorder:
        """Start or fail replay capture."""
        if self.fail:
            raise ReplayError("boom")
        self.started.append((session_id, node_name, width, height))
        return cast(ReplayRecorder, self.recorder)


class FakeReplayRecorder:
    """Minimal replay recorder fake."""

    def __init__(self) -> None:
        """Create an empty failure log."""
        self.inputs: list[tuple[float, str]] = []
        self.outputs: list[tuple[float, str]] = []
        self.closed: list[dt.datetime] = []
        self.failed: list[str] = []

    def record_input(self, seconds: float, data: str) -> None:
        """Record user input."""
        self.inputs.append((seconds, data))

    def record_output(self, seconds: float, data: str) -> None:
        """Record node output."""
        self.outputs.append((seconds, data))

    def close(self, *, now: dt.datetime | None = None) -> ReplayCloseResult:
        """Record normal replay close."""
        assert now is not None
        self.closed.append(now)
        return ReplayCloseResult(
            path=Path("session.cast"),
            hmac_hex="abc123hmac",
            ended_at=now,
        )

    def fail(self, *, error: str, now: dt.datetime | None = None) -> None:
        """Record replay failure."""
        self.failed.append(error)


class FakeCertificateIssuer:
    """Certificate issuer fake."""

    def __init__(self, *, username: str = "alice") -> None:
        """Configure the principal returned in issued certs."""
        self.username = username
        self.issued: list[tuple[str, uuid.UUID, int]] = []

    def issue(
        self,
        *,
        username: str,
        session_id: uuid.UUID,
        serial: int,
        now: dt.datetime,
    ) -> IssuedUserCertificate:
        """Return a deterministic certificate object."""
        self.issued.append((username, session_id, serial))
        return IssuedUserCertificate(
            private_key=asyncssh.generate_private_key("ssh-ed25519"),
            certificate=b"cert",
            serial=serial,
            username=self.username,
            valid_after=now,
            valid_before=now + dt.timedelta(hours=4),
        )


class FakeTunnelOpener:
    """Tunnel opener fake."""

    def __init__(self, *, fail: bool = False) -> None:
        """Create an empty open-session log."""
        self.opened: list[tuple[uuid.UUID, str, str, str, IssuedUserCertificate]] = []
        self.connection = object()
        self.fail = fail

    async def open_session(
        self,
        *,
        agent_id: uuid.UUID,
        channel_id: str,
        node_name: str,
        node_ssh_host_public_key: str,
        username: str,
        user_certificate: IssuedUserCertificate,
    ) -> object:
        """Record an opened tunnel session."""
        if self.fail:
            raise JumpError("node SSH connection failed")
        self.opened.append(
            (agent_id, channel_id, node_name, username, user_certificate)
        )
        return self.connection


class FakeTunnelPtyChannel:
    """Tunnel PTY channel fake."""

    def __init__(self) -> None:
        """Create empty tunnel event logs."""
        self.sent: list[tuple[str, bytes]] = []
        self.resized: list[tuple[str, int, int]] = []
        self.closed: list[str] = []

    async def send_data(self, *, channel_id: str, payload: bytes) -> None:
        """Record sent channel data."""
        self.sent.append((channel_id, payload))

    async def resize_pty(self, *, channel_id: str, width: int, height: int) -> None:
        """Record channel resize."""
        self.resized.append((channel_id, width, height))

    async def close_session(self, *, channel_id: str) -> None:
        """Record channel close."""
        self.closed.append(channel_id)


class FakeJumpSessionStateStore:
    """Session state store fake."""

    def __init__(self) -> None:
        """Create an empty terminal-state log."""
        self.closed: list[dict[str, object]] = []

    async def close_session(
        self,
        *,
        session_id: uuid.UUID,
        status: SessionStatus,
        ended_at: dt.datetime,
        replay_path: Path,
        replay_hmac: str | None,
        error: str | None,
    ) -> None:
        """Record terminal session state."""
        self.closed.append(
            {
                "session_id": session_id,
                "status": status,
                "ended_at": ended_at,
                "replay_path": replay_path,
                "replay_hmac": replay_hmac,
                "error": error,
            }
        )


class FakeAuditSink:
    """Audit fake."""

    def __init__(self) -> None:
        """Create an empty audit log."""
        self.events: list[dict[str, object]] = []

    async def write(
        self,
        *,
        event_type: AuditEventType,
        actor: str,
        metadata: dict[str, object],
        agent_id: uuid.UUID | None = None,
        session_id: uuid.UUID | None = None,
        node_name: str | None = None,
        now: dt.datetime | None = None,
    ) -> object:
        """Record an audit event."""
        self.events.append(
            {
                "event_type": event_type,
                "actor": actor,
                "metadata": metadata,
                "agent_id": agent_id,
                "session_id": session_id,
                "node_name": node_name,
                "now": now,
            }
        )
        return object()


class FakeAgentTunnelConnectorResolver:
    """Resolve one deterministic AsyncSSH tunnel connector."""

    def __init__(self, *, connector: object) -> None:
        """Configure the connector to return."""
        self.connector = connector
        self.requests: list[tuple[uuid.UUID, str]] = []
        self.closed: list[str] = []
        self.opened: list[
            tuple[uuid.UUID, str, str, str, str, IssuedUserCertificate]
        ] = []

    async def open_session(
        self,
        *,
        agent_id: uuid.UUID,
        channel_id: str,
        node_name: str,
        node_ssh_host_public_key: str,
        username: str,
        user_certificate: IssuedUserCertificate,
    ) -> None:
        """Record one broker channel open."""
        self.opened.append(
            (
                agent_id,
                channel_id,
                node_name,
                node_ssh_host_public_key,
                username,
                user_certificate,
            )
        )

    def connector_for_agent(self, *, agent_id: uuid.UUID, channel_id: str) -> object:
        """Record and return the configured connector."""
        self.requests.append((agent_id, channel_id))
        return self.connector

    async def close_session(self, *, channel_id: str) -> None:
        """Record broker channel close."""
        self.closed.append(channel_id)


class FakeAsyncSshConnect:
    """Capture AsyncSSH connect calls without opening a network connection."""

    def __init__(self) -> None:
        """Create an empty call log."""
        self.calls: list[dict[str, object]] = []
        self.known_hosts: object | None = None

    async def __call__(self, **kwargs: object) -> object:
        """Record sanitized AsyncSSH connection kwargs."""
        self.known_hosts = kwargs.pop("known_hosts")
        self.calls.append(kwargs)
        return object()


class FailingAsyncSshConnect:
    """Fail node SSH connection attempts."""

    async def __call__(self, **kwargs: object) -> object:
        """Raise a deterministic connection failure."""
        raise OSError("connection refused")


def _identity() -> ResolvedIdentity:
    return ResolvedIdentity(
        username="alice",
        public_key="ssh-ed25519 AAAAalice",
        groups=frozenset({"group-a"}),
    )


def _node() -> NodeInventoryEntry:
    return NodeInventoryEntry(node_name="node-01", labels=frozenset({"prod"}))


def _started_jump() -> StartedJump:
    target = JumpTarget(
        agent_id=uuid.uuid4(),
        node_name="node-01",
        node_ssh_host_public_key="ssh-ed25519 AAAAhost",
        heartbeat=HeartbeatState(heartbeat_seconds=10),
    )
    session = JumpSession(
        session_id=uuid.uuid4(),
        user_cert_serial=42,
        replay_path=Path("session.cast"),
        started_at=_NOW,
    )
    certificate = _issued_certificate(username="alice")
    return StartedJump(
        session=session,
        target=target,
        user_certificate=certificate,
        replay=cast(ReplayRecorder, FakeReplayRecorder()),
        channel_id="channel-01",
        node_connection=object(),
    )


def _issued_certificate(*, username: str) -> IssuedUserCertificate:
    return IssuedUserCertificate(
        private_key=asyncssh.generate_private_key("ssh-ed25519"),
        certificate=b"cert",
        serial=42,
        username=username,
        valid_after=_NOW,
        valid_before=_NOW + dt.timedelta(hours=4),
    )
