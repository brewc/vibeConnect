"""Server-side SSH jump orchestration and hardening checks."""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

import asyncssh

from server.auth import (
    AuthError,
    NodeInventoryEntry,
    ResolvedIdentity,
    parse_restricted_shell_command,
)
from server.tunnel import HeartbeatState
from vibeconnect_common.crypto import IssuedUserCertificate
from vibeconnect_common.models import AuditEventType, SessionStatus
from vibeconnect_common.replay import ReplayError, ReplayRecorder


class JumpError(PermissionError):
    """Raised when a jump must fail closed."""


@dataclass(frozen=True, slots=True)
class JumpTarget:
    """Authorized node and active agent tunnel selected for a jump."""

    agent_id: uuid.UUID
    node_name: str
    node_ssh_host_public_key: str
    heartbeat: HeartbeatState


@dataclass(frozen=True, slots=True)
class JumpSession:
    """Database session row metadata needed before opening a node channel."""

    session_id: uuid.UUID
    user_cert_serial: int
    replay_path: Path
    started_at: dt.datetime


@dataclass(frozen=True, slots=True)
class StartedJump:
    """Jump resources created after all fail-closed checks pass."""

    session: JumpSession
    target: JumpTarget
    user_certificate: IssuedUserCertificate
    replay: ReplayRecorder
    channel_id: str
    node_connection: object


class JumpStore(Protocol):
    """Persistence surface required by jump setup."""

    async def get_jump_target(self, node_name: str) -> JumpTarget | None:
        """Return the active jump target for an authorized node."""

    async def create_session(
        self,
        *,
        agent_id: uuid.UUID,
        username: str,
        node_name: str,
        replay_path: Path,
        started_at: dt.datetime,
    ) -> JumpSession:
        """Create an open session row and allocate a user cert serial."""

    async def fail_session(
        self,
        *,
        session_id: uuid.UUID,
        ended_at: dt.datetime,
    ) -> None:
        """Persist failed session state before returning a denied jump."""


class JumpAuditSink(Protocol):
    """Audit surface used by jump setup."""

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
        """Write one audit event."""


class JumpSessionStateStore(Protocol):
    """Persistence surface used by terminal jump session close paths."""

    async def close_session(
        self,
        *,
        session_id: uuid.UUID,
        status: SessionStatus,
        ended_at: dt.datetime,
        error: str | None,
    ) -> None:
        """Persist one terminal jump session state."""


class JumpConnection(Protocol):
    """Database surface used by the PostgreSQL jump store."""

    async def execute(self, query: str, *args: object) -> str:
        """Execute a statement without returning rows."""

    async def fetchrow(self, query: str, *args: object) -> object | None:
        """Execute a statement and return one row."""


class PostgresJumpStore:
    """PostgreSQL-backed jump and session state store."""

    def __init__(self, connection: JumpConnection, *, heartbeat_seconds: int) -> None:
        """Configure database and heartbeat freshness settings."""
        self._connection = connection
        self._heartbeat_seconds = heartbeat_seconds

    async def get_jump_target(self, node_name: str) -> JumpTarget | None:
        """Return the active jump target for an authorized node."""
        row = await self._connection.fetchrow(
            """
            SELECT id, node_name, node_ssh_host_public_key, last_seen
              FROM agents
             WHERE node_name = $1
               AND revoked = false
            """,
            node_name,
        )
        if row is None:
            return None
        values = cast(dict[str, object], row)
        heartbeat = HeartbeatState(heartbeat_seconds=self._heartbeat_seconds)
        last_seen = values["last_seen"]
        if isinstance(last_seen, dt.datetime):
            heartbeat.mark_seen(last_seen)
        return JumpTarget(
            agent_id=uuid.UUID(str(values["id"])),
            node_name=str(values["node_name"]),
            node_ssh_host_public_key=str(values["node_ssh_host_public_key"]),
            heartbeat=heartbeat,
        )

    async def create_session(
        self,
        *,
        agent_id: uuid.UUID,
        username: str,
        node_name: str,
        replay_path: Path,
        started_at: dt.datetime,
    ) -> JumpSession:
        """Create an open session row and allocate a user cert serial."""
        session_id = uuid.uuid4()
        row = await self._connection.fetchrow(
            """
            INSERT INTO sessions
                (id, agent_id, user_name, started_at, replay_path, status)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, user_cert_serial, replay_path, started_at
            """,
            session_id,
            agent_id,
            username,
            _as_utc(started_at),
            str(replay_path),
            SessionStatus.OPEN.value,
        )
        if row is None:
            raise JumpError("session row was not created")
        values = cast(dict[str, object], row)
        return JumpSession(
            session_id=uuid.UUID(str(values["id"])),
            user_cert_serial=int(str(values["user_cert_serial"])),
            replay_path=Path(str(values["replay_path"])),
            started_at=_datetime_value(values["started_at"]),
        )

    async def fail_session(
        self,
        *,
        session_id: uuid.UUID,
        ended_at: dt.datetime,
    ) -> None:
        """Persist failed session state before returning a denied jump."""
        await self.close_session(
            session_id=session_id,
            status=SessionStatus.FAILED,
            ended_at=ended_at,
            error=None,
        )

    async def close_session(
        self,
        *,
        session_id: uuid.UUID,
        status: SessionStatus,
        ended_at: dt.datetime,
        error: str | None,
    ) -> None:
        """Persist one terminal jump session state."""
        await self._connection.execute(
            """
            UPDATE sessions
               SET status = $2,
                   ended_at = $3
             WHERE id = $1
               AND status = 'open'
            """,
            session_id,
            status.value,
            _as_utc(ended_at),
        )


class ReplayStarter(Protocol):
    """Replay factory surface used by jump setup."""

    def start(
        self,
        *,
        session_id: uuid.UUID,
        node_name: str,
        width: int,
        height: int,
        now: dt.datetime | None = None,
    ) -> ReplayRecorder:
        """Start mandatory replay capture."""


class UserCertificateIssuer(Protocol):
    """User certificate issuing surface."""

    def issue(
        self,
        *,
        username: str,
        session_id: uuid.UUID,
        serial: int,
        now: dt.datetime,
    ) -> IssuedUserCertificate:
        """Issue one short-lived user SSH certificate."""


class TunnelSessionOpener(Protocol):
    """Tunnel broker surface used to open an agent-backed node session."""

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
        """Open one channel over an authenticated agent tunnel."""


class AgentTunnelConnectorResolver(Protocol):
    """Resolve an authenticated agent tunnel connector for AsyncSSH."""

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
        """Open one brokered tunnel channel for an agent."""

    def connector_for_agent(self, *, agent_id: uuid.UUID, channel_id: str) -> object:
        """Return an AsyncSSH tunnel connector for one jump channel."""

    async def close_session(self, *, channel_id: str) -> None:
        """Close a brokered tunnel channel."""


class TunnelPtyChannel(Protocol):
    """Tunnel broker surface for an opened PTY channel."""

    async def send_data(self, *, channel_id: str, payload: bytes) -> None:
        """Send user PTY input to the agent-backed SSH client channel."""

    async def resize_pty(self, *, channel_id: str, width: int, height: int) -> None:
        """Send a PTY resize request to the agent-backed SSH client channel."""

    async def close_session(self, *, channel_id: str) -> None:
        """Close the agent-backed SSH client channel."""


class ServerJumpCoordinator:
    """Coordinate restricted-shell node jumps without weakening SSH invariants."""

    def __init__(
        self,
        *,
        store: JumpStore,
        replay_starter: ReplayStarter,
        certificate_issuer: UserCertificateIssuer,
        tunnel_opener: TunnelSessionOpener,
        audit_sink: JumpAuditSink | None = None,
    ) -> None:
        """Configure jump-flow dependencies."""
        self._store = store
        self._replay_starter = replay_starter
        self._certificate_issuer = certificate_issuer
        self._tunnel_opener = tunnel_opener
        self._audit_sink = audit_sink

    async def start_jump(
        self,
        *,
        identity: ResolvedIdentity,
        command: str,
        visible_nodes: tuple[NodeInventoryEntry, ...],
        presented_node_host_key: str | None,
        width: int,
        height: int,
        now: dt.datetime,
    ) -> StartedJump:
        """Validate and start one node jump or fail before opening the tunnel."""
        allowed_node_names = tuple(node.node_name for node in visible_nodes)
        try:
            node_name = parse_restricted_shell_command(command, allowed_node_names)
        except AuthError as exc:
            await self._audit_denial(identity.username, None, None, str(exc), now)
            raise JumpError("node command is not authorized") from exc

        target = await self._store.get_jump_target(node_name)
        if target is None:
            await self._audit_denial(identity.username, None, node_name, "missing", now)
            raise JumpError("authorized node has no active tunnel")
        validate_pinned_host_key(
            expected_host_key=target.node_ssh_host_public_key,
            presented_host_key=presented_node_host_key,
        )
        if not target.heartbeat.allows_new_jump(now):
            await self._audit_denial(
                identity.username, target.agent_id, node_name, "stale tunnel", now
            )
            raise JumpError("agent tunnel is not fresh enough for new jumps")

        session_id = uuid.uuid4()
        replay_path = Path(f"{session_id}.cast")
        session = await self._store.create_session(
            agent_id=target.agent_id,
            username=identity.username,
            node_name=node_name,
            replay_path=replay_path,
            started_at=now,
        )
        try:
            replay = self._replay_starter.start(
                session_id=session.session_id,
                node_name=node_name,
                width=width,
                height=height,
                now=session.started_at,
            )
        except ReplayError as exc:
            await self._store.fail_session(session_id=session.session_id, ended_at=now)
            await self._audit_denial(
                identity.username,
                target.agent_id,
                node_name,
                "replay start failed",
                now,
                session_id=session.session_id,
            )
            raise JumpError("replay capture is required") from exc

        user_certificate = self._certificate_issuer.issue(
            username=identity.username,
            session_id=session.session_id,
            serial=session.user_cert_serial,
            now=now,
        )
        if user_certificate.username != identity.username:
            replay.fail(error="certificate principal mismatch", now=now)
            await self._store.fail_session(session_id=session.session_id, ended_at=now)
            raise JumpError("user certificate principal mismatch")

        channel_id = str(uuid.uuid4())
        try:
            node_connection = await self._tunnel_opener.open_session(
                agent_id=target.agent_id,
                channel_id=channel_id,
                node_name=node_name,
                node_ssh_host_public_key=target.node_ssh_host_public_key,
                username=identity.username,
                user_certificate=user_certificate,
            )
        except JumpError as exc:
            replay.fail(error="node SSH connection failed", now=now)
            await self._store.fail_session(session_id=session.session_id, ended_at=now)
            await self._audit_denial(
                identity.username,
                target.agent_id,
                node_name,
                "node SSH connection failed",
                now,
                session_id=session.session_id,
            )
            raise JumpError("node SSH connection failed") from exc
        if self._audit_sink is not None:
            await self._audit_sink.write(
                event_type=AuditEventType.SESSION_STARTED,
                actor=identity.username,
                agent_id=target.agent_id,
                session_id=session.session_id,
                node_name=node_name,
                metadata={"status": SessionStatus.OPEN.value},
                now=now,
            )
        return StartedJump(
            session=session,
            target=target,
            user_certificate=user_certificate,
            replay=replay,
            channel_id=channel_id,
            node_connection=node_connection,
        )

    async def _audit_denial(
        self,
        actor: str,
        agent_id: uuid.UUID | None,
        node_name: str | None,
        reason: str,
        now: dt.datetime,
        *,
        session_id: uuid.UUID | None = None,
    ) -> None:
        if self._audit_sink is None:
            return
        await self._audit_sink.write(
            event_type=AuditEventType.NODE_AUTHORIZATION_DENIED,
            actor=actor,
            agent_id=agent_id,
            session_id=session_id,
            node_name=node_name,
            metadata={"reason": reason},
            now=now,
        )


def validate_pinned_host_key(
    *, expected_host_key: str | None, presented_host_key: str | None
) -> str:
    """Require exact node sshd host-key pinning before any node SSH connection."""
    if not expected_host_key:
        raise JumpError("node sshd host key is not pinned")
    if not presented_host_key:
        raise JumpError("node sshd host key was not presented")
    if presented_host_key != expected_host_key:
        raise JumpError("node sshd host key mismatch")
    return presented_host_key


class AsyncSshNodeTunnelOpener:
    """Open server-owned SSH client connections through authenticated agent tunnels."""

    def __init__(
        self,
        *,
        connector_resolver: AgentTunnelConnectorResolver,
        connect: Callable[..., Awaitable[object]] | None = None,
        node_port: int = 2222,
    ) -> None:
        """Configure AsyncSSH connection dependencies."""
        if not 1 <= node_port <= 65535:
            raise JumpError("node sshd port is outside valid TCP port bounds")
        self._connector_resolver = connector_resolver
        self._connect = (
            cast(Callable[..., Awaitable[object]], asyncssh.connect)
            if (connect is None)
            else connect
        )
        self._node_port = node_port

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
        """Open one AsyncSSH client connection to node sshd through the agent tunnel."""
        if user_certificate.username != username:
            raise JumpError("user certificate principal mismatch")
        if not node_ssh_host_public_key:
            raise JumpError("node sshd host key is not pinned")

        await self._connector_resolver.open_session(
            agent_id=agent_id,
            channel_id=channel_id,
            node_name=node_name,
            node_ssh_host_public_key=node_ssh_host_public_key,
            username=username,
            user_certificate=user_certificate,
        )
        connector = self._connector_resolver.connector_for_agent(
            agent_id=agent_id,
            channel_id=channel_id,
        )
        known_hosts = _known_hosts_for_node(
            node_name=node_name,
            port=self._node_port,
            host_public_key=node_ssh_host_public_key,
        )
        try:
            return await self._connect(
                host=node_name,
                port=self._node_port,
                tunnel=connector,
                username=username,
                client_keys=[
                    (user_certificate.private_key, user_certificate.certificate)
                ],
                known_hosts=known_hosts,
                agent_path=None,
                agent_forwarding=False,
                x11_forwarding=False,
                config=None,
            )
        except (OSError, asyncssh.Error) as exc:
            await self._connector_resolver.close_session(channel_id=channel_id)
            raise JumpError("node SSH connection failed") from exc


def _known_hosts_for_node(
    *,
    node_name: str,
    port: int,
    host_public_key: str,
) -> asyncssh.SSHKnownHosts:
    host_pattern = f"[{node_name}]:{port}" if port != 22 else node_name
    try:
        return asyncssh.import_known_hosts(
            f"{host_pattern} {host_public_key.strip()}\n"
        )
    except asyncssh.Error as exc:
        raise JumpError("node sshd host key is invalid") from exc


class JumpPtyBridge:
    """Bridge PTY bytes between the user SSH session, replay, and tunnel."""

    def __init__(
        self,
        *,
        started_jump: StartedJump,
        tunnel_channel: TunnelPtyChannel,
        audit_sink: JumpAuditSink | None = None,
        session_state_store: JumpSessionStateStore | None = None,
    ) -> None:
        """Configure an opened jump channel."""
        self._jump = started_jump
        self._tunnel_channel = tunnel_channel
        self._audit_sink = audit_sink
        self._session_state_store = session_state_store
        self._closed = False

    async def send_user_input(self, *, seconds: float, payload: bytes) -> None:
        """Record and forward user PTY input."""
        self._ensure_open()
        self._jump.replay.record_input(seconds, _decode_pty(payload))
        await self._tunnel_channel.send_data(
            channel_id=self._jump.channel_id,
            payload=payload,
        )

    def receive_node_output(self, *, seconds: float, payload: bytes) -> bytes:
        """Record node PTY output and return it for the user SSH session."""
        self._ensure_open()
        self._jump.replay.record_output(seconds, _decode_pty(payload))
        return payload

    async def resize_pty(self, *, width: int, height: int) -> None:
        """Forward a PTY resize over the tunnel."""
        self._ensure_open()
        if width <= 0 or height <= 0:
            raise JumpError("PTY size must be positive")
        await self._tunnel_channel.resize_pty(
            channel_id=self._jump.channel_id,
            width=width,
            height=height,
        )

    async def close(
        self,
        *,
        status: SessionStatus = SessionStatus.CLOSED,
        now: dt.datetime,
        error: str | None = None,
    ) -> None:
        """Close replay and tunnel resources with the requested session status."""
        if self._closed:
            return
        self._closed = True
        if status is SessionStatus.CLOSED:
            self._jump.replay.close(now=now)
            event_type = AuditEventType.SESSION_CLOSED
            metadata: dict[str, object] = {"status": status.value}
        elif status in {SessionStatus.FAILED, SessionStatus.TERMINATED}:
            self._jump.replay.fail(error=error or status.value, now=now)
            event_type = AuditEventType.SESSION_FAILED
            metadata = {"status": status.value, "error": error or status.value}
        else:
            raise JumpError("unsupported terminal session status")
        if self._session_state_store is not None:
            await self._session_state_store.close_session(
                session_id=self._jump.session.session_id,
                status=status,
                ended_at=now,
                error=error,
            )
        await self._tunnel_channel.close_session(channel_id=self._jump.channel_id)
        if self._audit_sink is not None:
            await self._audit_sink.write(
                event_type=event_type,
                actor=self._jump.user_certificate.username,
                agent_id=self._jump.target.agent_id,
                session_id=self._jump.session.session_id,
                node_name=self._jump.target.node_name,
                metadata=metadata,
                now=now,
            )

    def _ensure_open(self) -> None:
        if self._closed:
            raise JumpError("jump channel is closed")


class AsyncSshJumpSessionLifecycle:
    """Map AsyncSSH session lifecycle callbacks to jump terminal state."""

    def __init__(self, *, bridge: JumpPtyBridge) -> None:
        """Configure the lifecycle wrapper for one opened jump."""
        self._bridge = bridge

    async def connection_lost(
        self,
        *,
        exc: BaseException | None,
        now: dt.datetime,
    ) -> None:
        """Handle AsyncSSH connection loss."""
        if exc is None:
            await self._bridge.close(status=SessionStatus.CLOSED, now=now)
            return
        await self._bridge.close(
            status=SessionStatus.FAILED,
            now=now,
            error=str(exc) or exc.__class__.__name__,
        )

    async def terminate(self, *, reason: str, now: dt.datetime) -> None:
        """Handle explicit server-side session termination."""
        await self._bridge.close(
            status=SessionStatus.TERMINATED,
            now=now,
            error=reason,
        )


class TunnelStreamAdapter:
    """Queue-backed byte stream adapter for an opened agent tunnel channel."""

    def __init__(
        self,
        *,
        channel_id: str,
        tunnel_channel: TunnelPtyChannel,
    ) -> None:
        """Configure the stream adapter for one tunnel channel."""
        if not channel_id:
            raise JumpError("channel_id is required")
        self._channel_id = channel_id
        self._tunnel_channel = tunnel_channel
        self._incoming: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._closed = False
        self._eof = False

    async def read(self) -> bytes:
        """Read the next node-output payload, or empty bytes after EOF."""
        if self._eof and self._incoming.empty():
            return b""
        payload = await self._incoming.get()
        if payload is None:
            self._eof = True
            return b""
        return payload

    async def write(self, payload: bytes) -> None:
        """Write user-input bytes to the tunnel channel."""
        self._ensure_open()
        await self._tunnel_channel.send_data(
            channel_id=self._channel_id,
            payload=payload,
        )

    async def resize_pty(self, *, width: int, height: int) -> None:
        """Forward PTY resize requests to the tunnel channel."""
        self._ensure_open()
        if width <= 0 or height <= 0:
            raise JumpError("PTY size must be positive")
        await self._tunnel_channel.resize_pty(
            channel_id=self._channel_id,
            width=width,
            height=height,
        )

    def feed_data(self, payload: bytes) -> None:
        """Queue node-output bytes for the AsyncSSH-facing reader."""
        self._ensure_open()
        if self._eof:
            raise JumpError("jump channel has reached EOF")
        self._incoming.put_nowait(payload)

    def feed_eof(self) -> None:
        """Queue EOF for the AsyncSSH-facing reader."""
        if not self._eof:
            self._incoming.put_nowait(None)
            self._eof = True

    async def close(self) -> None:
        """Close the tunnel channel and release blocked readers."""
        if self._closed:
            return
        self._closed = True
        self.feed_eof()
        await self._tunnel_channel.close_session(channel_id=self._channel_id)

    def _ensure_open(self) -> None:
        if self._closed:
            raise JumpError("jump channel is closed")


def _decode_pty(payload: bytes) -> str:
    return payload.decode("utf-8", errors="replace")


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def _datetime_value(value: object) -> dt.datetime:
    if not isinstance(value, dt.datetime):
        raise JumpError("stored session timestamp is invalid")
    return _as_utc(value)
