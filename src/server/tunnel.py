"""Server-side tunnel authentication and session state."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import ssl
import struct
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vibeconnect_common.crypto import (
    IssuedUserCertificate,
    SecretError,
    SecretValue,
    issue_agent_client_certificate,
    verify_secret_hash,
)
from vibeconnect_common.models import TunnelFrameType
from vibeconnect_common.tunnel import (
    FRAME_HEADER_MAX_BYTES,
    DecodedTunnelFrame,
    TunnelProtocolError,
    decode_frame,
    encode_frame,
)

TUNNEL_AUTH_TIMEOUT_SECONDS = 10


class TunnelAuthError(PermissionError):
    """Raised when tunnel authentication fails closed."""


class TunnelStateError(RuntimeError):
    """Raised when tunnel session state is invalid."""


class TunnelStreamReader(Protocol):
    """Reader surface for framed tunnel streams."""

    async def readexactly(self, n: int) -> bytes:
        """Read exactly `n` bytes or raise EOFError."""


class TunnelStreamWriter(Protocol):
    """Writer surface for framed tunnel streams."""

    def write(self, data: bytes) -> None:
        """Write bytes to the tunnel stream."""

    async def drain(self) -> None:
        """Flush pending writes."""

    def close(self) -> None:
        """Close the tunnel stream."""

    async def wait_closed(self) -> None:
        """Wait for stream closure."""


@dataclass(frozen=True, slots=True)
class AgentTunnelRecord:
    """Stored agent state required to authenticate a tunnel."""

    agent_id: uuid.UUID
    node_name: str
    x509_public_key: str
    tunnel_secret_hash: str
    cert_serial: str
    cert_expires_at: dt.datetime
    revoked_at: dt.datetime | None


@dataclass(frozen=True, slots=True)
class TunnelAuthRequest:
    """Agent-provided values from mTLS and the initial auth frame."""

    agent_id: uuid.UUID
    node_name: str
    cert_serial: str
    cert_public_key: str
    tunnel_secret: str


@dataclass(frozen=True, slots=True)
class PeerCertificateBinding:
    """Client certificate identity proven by the mTLS layer."""

    cert_serial: str
    cert_public_key: str


@dataclass(frozen=True, slots=True)
class RenewedAgentCertificate:
    """Certificate renewal result persisted for an agent."""

    public_key_pem: str
    certificate_pem: str
    cert_serial: str
    cert_expires_at: dt.datetime


@dataclass(slots=True)
class _BrokerTunnelConnection:
    agent: AgentTunnelRecord
    connection_id: str
    writer: TunnelStreamWriter
    channels: TunnelChannelRegistry
    heartbeat: HeartbeatState
    adapters: dict[str, BrokerTunnelStream] = field(default_factory=dict)


class BrokerTunnelStream:
    """Bidirectional byte stream for one brokered agent session."""

    def __init__(
        self,
        *,
        broker: ServerTunnelBroker,
        agent_id: uuid.UUID,
        channel_id: str,
    ) -> None:
        """Bind stream writes to one broker channel."""
        self._broker = broker
        self._agent_id = agent_id
        self._channel_id = channel_id
        self._buffer = bytearray()
        self._closed = False
        self._data_ready = asyncio.Event()

    async def read(self, n: int = -1) -> bytes:
        """Read data received from the agent for this channel."""
        if not self._buffer and not self._closed:
            while not self._buffer and not self._closed:
                await self._data_ready.wait()
                self._data_ready.clear()
        if n < 0 or n >= len(self._buffer):
            data = bytes(self._buffer)
            self._buffer.clear()
            return data
        data = bytes(self._buffer[:n])
        del self._buffer[:n]
        return data

    async def write(self, data: bytes) -> None:
        """Send data to the agent for this channel."""
        await self._broker.send_data(channel_id=self._channel_id, payload=data)

    async def resize_pty(self, width: int, height: int) -> None:
        """Send a PTY resize request to the agent."""
        await self._broker.resize_pty(
            channel_id=self._channel_id, width=width, height=height
        )

    async def close(self) -> None:
        """Close this brokered session."""
        if not self._closed:
            self._closed = True
            await self._broker.close_session(channel_id=self._channel_id)

    async def create_connection(
        self,
        protocol_factory: Any,
        host: str,
        port: int,
    ) -> tuple[asyncio.Transport, Any]:
        """Create an AsyncSSH-compatible transport over this brokered stream."""
        protocol = protocol_factory()
        transport = _BrokerTunnelTransport(
            stream=self,
            protocol=protocol,
            peername=("127.0.0.1", port),
        )
        protocol.connection_made(transport)
        transport.start()
        return transport, protocol

    def feed_data(self, payload: bytes) -> None:
        """Buffer bytes received from the agent."""
        self._buffer.extend(payload)
        self._data_ready.set()

    def feed_eof(self) -> None:
        """Mark the stream closed by the agent."""
        self._closed = True
        self._data_ready.set()


class _BrokerTunnelTransport(asyncio.Transport):
    """AsyncIO transport which carries AsyncSSH bytes over broker frames."""

    def __init__(
        self,
        *,
        stream: BrokerTunnelStream,
        protocol: asyncio.Protocol,
        peername: tuple[str, int],
    ) -> None:
        """Bind one protocol instance to one broker stream."""
        super().__init__()
        self._stream = stream
        self._protocol = protocol
        self._peername = peername
        self._closing = False
        self._read_task: asyncio.Task[None] | None = None
        self._write_tasks: set[asyncio.Task[None]] = set()
        self._close_task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Start forwarding brokered bytes into the protocol."""
        self._read_task = asyncio.create_task(self._read_loop())

    def write(self, data: bytes | bytearray | memoryview[Any]) -> None:
        """Send protocol bytes into the brokered tunnel."""
        if self._closing or not data:
            return
        task = asyncio.create_task(self._stream.write(bytes(data)))
        self._write_tasks.add(task)
        task.add_done_callback(self._write_done)

    def close(self) -> None:
        """Close the brokered stream and notify the protocol."""
        if self._closing:
            return
        self._closing = True
        self._close_task = asyncio.create_task(self._stream.close())
        self._close_task.add_done_callback(self._close_done)
        if self._read_task is not None:
            self._read_task.cancel()
        for task in tuple(self._write_tasks):
            task.cancel()
        self._protocol.connection_lost(None)

    def _write_done(self, task: asyncio.Task[None]) -> None:
        self._write_tasks.discard(task)
        if task.cancelled():
            return
        if task.exception() is not None:
            self.close()

    def _close_done(self, task: asyncio.Task[None]) -> None:
        if not task.cancelled():
            task.exception()

    def abort(self) -> None:
        """Abort the brokered stream."""
        self.close()

    def is_closing(self) -> bool:
        """Return whether close has been requested."""
        return self._closing

    def can_write_eof(self) -> bool:
        """Report that half-close is not supported by tunnel frames."""
        return False

    def get_extra_info(self, name: str, default: object = None) -> object:
        """Return minimal peer metadata expected by AsyncSSH."""
        if name == "peername":
            return self._peername
        if name == "sockname":
            return ("127.0.0.1", 0)
        return default

    def set_write_buffer_limits(
        self, high: int | None = None, low: int | None = None
    ) -> None:
        """Accept AsyncSSH buffer-limit configuration."""
        return

    def get_write_buffer_size(self) -> int:
        """Return the queued write-buffer size."""
        return 0

    async def _read_loop(self) -> None:
        try:
            while not self._closing:
                data = await self._stream.read(32768)
                if not data:
                    break
                self._protocol.data_received(data)
            if not self._closing:
                self._closing = True
                eof_handled = self._protocol.eof_received()
                if not eof_handled:
                    self._protocol.connection_lost(None)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if not self._closing:
                self._closing = True
                self._protocol.connection_lost(exc)


class AgentTunnelStore(Protocol):
    """Persistence operations required by tunnel authentication."""

    async def get_agent(self, agent_id: uuid.UUID) -> AgentTunnelRecord | None:
        """Return the stored agent row."""

    async def update_agent_certificate(
        self,
        agent_id: uuid.UUID,
        public_key_pem: str,
        cert_serial: str,
        expires_at: dt.datetime,
    ) -> None:
        """Atomically persist a renewed agent cert binding."""

    async def update_last_seen(self, agent_id: uuid.UUID, now: dt.datetime) -> None:
        """Persist tunnel heartbeat freshness for jump authorization."""


class AgentTunnelConnection(Protocol):
    """Database surface used by the PostgreSQL tunnel store."""

    async def execute(self, query: str, *args: object) -> str:
        """Execute a statement without returning rows."""

    async def fetchrow(self, query: str, *args: object) -> Mapping[str, object] | None:
        """Execute a statement and return one row."""


class PostgresAgentTunnelStore:
    """PostgreSQL-backed tunnel authentication store."""

    def __init__(self, connection: AgentTunnelConnection) -> None:
        """Configure the database connection."""
        self._connection = connection

    async def get_agent(self, agent_id: uuid.UUID) -> AgentTunnelRecord | None:
        """Return the stored agent row."""
        row = await self._connection.fetchrow(
            """
            SELECT id,
                   node_name,
                   x509_public_key,
                   tunnel_secret_hash,
                   cert_serial,
                   cert_expires_at,
                   revoked,
                   revoked_at
              FROM agents
             WHERE id = $1
            """,
            agent_id,
        )
        if row is None:
            return None
        return AgentTunnelRecord(
            agent_id=uuid.UUID(str(row["id"])),
            node_name=str(row["node_name"]),
            x509_public_key=str(row["x509_public_key"]),
            tunnel_secret_hash=str(row["tunnel_secret_hash"]),
            cert_serial=str(row["cert_serial"]),
            cert_expires_at=_as_utc(_datetime_value(row["cert_expires_at"])),
            revoked_at=_optional_datetime_value(row["revoked_at"]),
        )

    async def update_agent_certificate(
        self,
        agent_id: uuid.UUID,
        public_key_pem: str,
        cert_serial: str,
        expires_at: dt.datetime,
    ) -> None:
        """Atomically persist a renewed agent cert binding."""
        await self._connection.execute(
            """
            UPDATE agents
               SET x509_public_key = $2,
                   cert_serial = $3,
                   cert_expires_at = $4
             WHERE id = $1
               AND revoked = false
            """,
            agent_id,
            public_key_pem,
            cert_serial,
            _as_utc(expires_at),
        )

    async def update_last_seen(self, agent_id: uuid.UUID, now: dt.datetime) -> None:
        """Persist tunnel heartbeat freshness for jump authorization."""
        await self._connection.execute(
            """
            UPDATE agents
               SET last_seen = $2
             WHERE id = $1
               AND revoked = false
            """,
            agent_id,
            _as_utc(now),
        )


class InMemoryAgentTunnelStore:
    """Lock-free in-memory store for unit tests and early wiring."""

    def __init__(self, records: Mapping[uuid.UUID, AgentTunnelRecord]) -> None:
        """Initialize from known records."""
        self.records = dict(records)
        self.last_seen: dict[uuid.UUID, dt.datetime] = {}

    async def get_agent(self, agent_id: uuid.UUID) -> AgentTunnelRecord | None:
        """Return the stored agent row."""
        return self.records.get(agent_id)

    async def update_agent_certificate(
        self,
        agent_id: uuid.UUID,
        public_key_pem: str,
        cert_serial: str,
        expires_at: dt.datetime,
    ) -> None:
        """Atomically persist a renewed agent cert binding."""
        record = self.records[agent_id]
        self.records[agent_id] = replace(
            record,
            x509_public_key=public_key_pem,
            cert_serial=cert_serial,
            cert_expires_at=expires_at,
        )

    async def update_last_seen(self, agent_id: uuid.UUID, now: dt.datetime) -> None:
        """Persist tunnel heartbeat freshness for jump authorization."""
        self.last_seen[agent_id] = _as_utc(now)


class TunnelAuthenticator:
    """Validate the server-side tunnel auth invariants."""

    def __init__(self, store: AgentTunnelStore) -> None:
        """Configure store dependency."""
        self._store = store

    async def authenticate(
        self, request: TunnelAuthRequest, *, now: dt.datetime
    ) -> AgentTunnelRecord:
        """Return the authenticated agent row or fail closed."""
        record = await self._store.get_agent(request.agent_id)
        if record is None:
            raise TunnelAuthError("agent is unknown")
        if record.revoked_at is not None:
            raise TunnelAuthError("agent is revoked")
        if _as_utc(record.cert_expires_at) <= _as_utc(now):
            raise TunnelAuthError("agent certificate is expired")
        if record.node_name != request.node_name:
            raise TunnelAuthError("node binding mismatch")
        if record.cert_serial != request.cert_serial:
            raise TunnelAuthError("certificate serial mismatch")
        if record.x509_public_key != request.cert_public_key:
            raise TunnelAuthError("certificate public key mismatch")
        try:
            secret_matches = verify_secret_hash(
                SecretValue(request.tunnel_secret), record.tunnel_secret_hash
            )
        except SecretError as exc:
            raise TunnelAuthError("tunnel secret mismatch") from exc
        if not secret_matches:
            raise TunnelAuthError("tunnel secret mismatch")
        return record

    async def update_last_seen(self, agent_id: uuid.UUID, now: dt.datetime) -> None:
        """Persist tunnel heartbeat freshness for jump authorization."""
        await self._store.update_last_seen(agent_id, now)


class ActiveTunnelRegistry:
    """Track one active tunnel per agent."""

    def __init__(self) -> None:
        """Initialize empty active tunnel state."""
        self._active: dict[uuid.UUID, str] = {}

    def connect(self, *, agent_id: uuid.UUID, connection_id: str) -> None:
        """Register an active tunnel and reject duplicate connections."""
        current = self._active.get(agent_id)
        if current is not None and current != connection_id:
            raise TunnelStateError("duplicate active tunnel")
        self._active[agent_id] = connection_id

    def disconnect(self, *, agent_id: uuid.UUID, connection_id: str) -> None:
        """Remove a tunnel only when it still owns the active slot."""
        if self._active.get(agent_id) == connection_id:
            del self._active[agent_id]

    def revoke(self, *, agent_id: uuid.UUID) -> str | None:
        """Disconnect and return the active connection ID for a revoked agent."""
        return self._active.pop(agent_id, None)


class TunnelChannelRegistry:
    """Track channel IDs and session limits for one tunnel."""

    def __init__(self, *, max_sessions: int) -> None:
        """Configure the maximum number of concurrent sessions."""
        if max_sessions <= 0:
            raise TunnelStateError("max_sessions must be positive")
        self._max_sessions = max_sessions
        self._open_channels: set[str] = set()
        self._retired_channels: set[str] = set()

    def open_channel(self, channel_id: str) -> None:
        """Open a new channel and reject reuse."""
        if not channel_id:
            raise TunnelStateError("channel_id is required")
        if channel_id in self._open_channels or channel_id in self._retired_channels:
            raise TunnelStateError("channel_id reuse")
        if len(self._open_channels) >= self._max_sessions:
            raise TunnelStateError("max sessions exceeded")
        self._open_channels.add(channel_id)

    def close_channel(self, channel_id: str) -> None:
        """Close a known channel and permanently retire its ID."""
        if channel_id not in self._open_channels:
            raise TunnelStateError("unknown channel")
        self._open_channels.remove(channel_id)
        self._retired_channels.add(channel_id)

    def require_open(self, channel_id: str) -> None:
        """Require an existing channel for data, resize, or close frames."""
        if channel_id not in self._open_channels:
            raise TunnelStateError("unknown channel")


class HeartbeatState:
    """Track heartbeat freshness for one tunnel."""

    def __init__(self, *, heartbeat_seconds: int) -> None:
        """Configure missed-heartbeat threshold."""
        if heartbeat_seconds <= 0:
            raise TunnelStateError("heartbeat_seconds must be positive")
        self._heartbeat_seconds = heartbeat_seconds
        self._last_seen: dt.datetime | None = None

    def mark_seen(self, now: dt.datetime) -> None:
        """Record a heartbeat or authenticated frame."""
        self._last_seen = _as_utc(now)

    def allows_new_jump(self, now: dt.datetime) -> bool:
        """Return whether the tunnel is fresh enough to open a new jump."""
        if self._last_seen is None:
            return False
        deadline = self._last_seen + dt.timedelta(seconds=self._heartbeat_seconds * 2)
        return deadline > _as_utc(now)


class TunnelBackpressure:
    """Bound pending bytes for a slow downstream channel."""

    def __init__(self, *, max_pending_bytes: int) -> None:
        """Configure pending byte limit."""
        if max_pending_bytes <= 0:
            raise TunnelStateError("max_pending_bytes must be positive")
        self._max_pending_bytes = max_pending_bytes
        self._pending_bytes = 0

    def queue(self, payload: bytes) -> None:
        """Account for queued bytes and fail closed on overflow."""
        if self._pending_bytes + len(payload) > self._max_pending_bytes:
            raise TunnelStateError("downstream backpressure limit exceeded")
        self._pending_bytes += len(payload)

    def drain(self, byte_count: int) -> None:
        """Account for flushed bytes."""
        if byte_count < 0:
            raise TunnelStateError("byte_count cannot be negative")
        self._pending_bytes = max(0, self._pending_bytes - byte_count)


class AgentCertificateRenewer:
    """Issue and persist renewed agent certificates."""

    def __init__(
        self,
        *,
        store: AgentTunnelStore,
        agent_ca_private_key: Ed25519PrivateKey,
        agent_ca_certificate: x509.Certificate,
    ) -> None:
        """Configure renewal dependencies."""
        self._store = store
        self._agent_ca_private_key = agent_ca_private_key
        self._agent_ca_certificate = agent_ca_certificate

    async def renew(
        self,
        *,
        agent_id: uuid.UUID,
        node_name: str,
        new_public_key_pem: str,
        now: dt.datetime,
    ) -> RenewedAgentCertificate:
        """Renew a non-revoked agent cert with a fresh public key."""
        record = await self._store.get_agent(agent_id)
        if (
            record is None
            or record.revoked_at is not None
            or record.node_name != node_name
        ):
            raise TunnelAuthError("agent cannot renew certificate")
        public_key = _load_ed25519_public_key(new_public_key_pem)
        issued = issue_agent_client_certificate(
            ca_private_key=self._agent_ca_private_key,
            ca_certificate=self._agent_ca_certificate,
            agent_public_key=public_key,
            node_name=node_name,
            agent_id=agent_id,
            now=now,
        )
        await self._store.update_agent_certificate(
            agent_id, new_public_key_pem, issued.serial, issued.expires_at
        )
        return RenewedAgentCertificate(
            public_key_pem=new_public_key_pem,
            certificate_pem=issued.certificate_pem.decode("ascii"),
            cert_serial=issued.serial,
            cert_expires_at=issued.expires_at,
        )


class ServerTunnelBroker:
    """Authenticate agent tunnel streams and broker session frames."""

    def __init__(
        self,
        *,
        authenticator: TunnelAuthenticator,
        max_sessions_per_agent: int,
        heartbeat_seconds: int,
        max_frame_bytes: int,
        registry: ActiveTunnelRegistry | None = None,
    ) -> None:
        """Configure broker dependencies and fail-closed bounds."""
        if max_frame_bytes <= 0:
            raise TunnelStateError("max_frame_bytes must be positive")
        self._authenticator = authenticator
        self._max_sessions_per_agent = max_sessions_per_agent
        self._heartbeat_seconds = heartbeat_seconds
        self._max_frame_bytes = max_frame_bytes
        self._registry = registry or ActiveTunnelRegistry()
        self._connections: dict[uuid.UUID, _BrokerTunnelConnection] = {}
        self._channel_agents: dict[str, uuid.UUID] = {}

    async def handle_stream(
        self,
        *,
        reader: TunnelStreamReader,
        writer: TunnelStreamWriter,
        peer_certificate: PeerCertificateBinding,
        now: dt.datetime | None = None,
    ) -> None:
        """Authenticate one mTLS tunnel stream and dispatch frames until close."""
        authenticated: AgentTunnelRecord | None = None
        connection_id = str(uuid.uuid4())
        try:
            first = await asyncio.wait_for(
                _read_one_frame(reader, max_frame_bytes=self._max_frame_bytes),
                timeout=TUNNEL_AUTH_TIMEOUT_SECONDS,
            )
            if first.frame.type is not TunnelFrameType.AUTH:
                raise TunnelAuthError("tunnel must start with auth")
            auth_request = _decode_auth_payload(first.payload)
            _verify_peer_certificate_binding(
                auth_request=auth_request,
                peer_certificate=peer_certificate,
            )
            authenticated = await self._authenticator.authenticate(
                auth_request, now=_utc_now() if now is None else now
            )
            connection = _BrokerTunnelConnection(
                agent=authenticated,
                connection_id=connection_id,
                writer=writer,
                channels=TunnelChannelRegistry(
                    max_sessions=self._max_sessions_per_agent
                ),
                heartbeat=HeartbeatState(heartbeat_seconds=self._heartbeat_seconds),
            )
            seen_at = _utc_now()
            connection.heartbeat.mark_seen(seen_at)
            await self._authenticator.update_last_seen(authenticated.agent_id, seen_at)
            self._registry.connect(
                agent_id=authenticated.agent_id, connection_id=connection_id
            )
            self._connections[authenticated.agent_id] = connection
            await _write_frame(
                writer,
                frame_type=TunnelFrameType.AUTH_OK,
                request_id=first.frame.request_id,
                channel_id=None,
                max_frame_bytes=self._max_frame_bytes,
            )
            while True:
                decoded = await _read_one_frame(
                    reader, max_frame_bytes=self._max_frame_bytes
                )
                seen_at = _utc_now()
                connection.heartbeat.mark_seen(seen_at)
                await self._authenticator.update_last_seen(
                    authenticated.agent_id, seen_at
                )
                self._handle_agent_frame(connection, decoded)
        except (EOFError, asyncio.IncompleteReadError, TimeoutError):
            return
        except (TunnelAuthError, TunnelProtocolError, TunnelStateError):
            await _best_effort_error(writer)
            return
        finally:
            if authenticated is not None:
                self._drop_connection(authenticated.agent_id, connection_id)
            writer.close()
            await writer.wait_closed()

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
        """Open one session channel on an authenticated agent tunnel."""
        if user_certificate.username != username:
            raise TunnelStateError("user certificate principal mismatch")
        if not node_ssh_host_public_key:
            raise TunnelStateError("node sshd host key is not pinned")
        connection = self._require_connection(agent_id=agent_id, channel_id=channel_id)
        if not connection.heartbeat.allows_new_jump(_utc_now()):
            raise TunnelStateError("agent heartbeat is stale")
        apply_channel_frame(
            channels=connection.channels,
            frame_type=TunnelFrameType.OPEN_SESSION,
            channel_id=channel_id,
        )
        adapter = BrokerTunnelStream(
            broker=self, agent_id=agent_id, channel_id=channel_id
        )
        connection.adapters[channel_id] = adapter
        self._channel_agents[channel_id] = agent_id
        payload = json.dumps(
            {"node_name": node_name, "username": username},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        await _write_frame(
            connection.writer,
            frame_type=TunnelFrameType.OPEN_SESSION,
            request_id=str(uuid.uuid4()),
            channel_id=channel_id,
            payload=payload,
            max_frame_bytes=self._max_frame_bytes,
        )

    def connector_for_agent(self, *, agent_id: uuid.UUID, channel_id: str) -> object:
        """Return the brokered stream for a previously opened channel."""
        connection = self._require_connection(agent_id=agent_id, channel_id=channel_id)
        try:
            return connection.adapters[channel_id]
        except KeyError as exc:
            raise TunnelStateError("channel is not open") from exc

    async def send_data(self, *, channel_id: str, payload: bytes) -> None:
        """Send SSH payload bytes to an agent-backed node session."""
        connection = self._require_channel_connection(channel_id)
        connection.channels.require_open(channel_id)
        await _write_frame(
            connection.writer,
            frame_type=TunnelFrameType.SESSION_DATA,
            request_id=str(uuid.uuid4()),
            channel_id=channel_id,
            payload=payload,
            max_frame_bytes=self._max_frame_bytes,
        )

    async def resize_pty(self, *, channel_id: str, width: int, height: int) -> None:
        """Send a PTY resize frame to the agent."""
        connection = self._require_channel_connection(channel_id)
        connection.channels.require_open(channel_id)
        payload = json.dumps(
            {"width": width, "height": height},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        await _write_frame(
            connection.writer,
            frame_type=TunnelFrameType.RESIZE_PTY,
            request_id=str(uuid.uuid4()),
            channel_id=channel_id,
            payload=payload,
            max_frame_bytes=self._max_frame_bytes,
        )

    async def close_session(self, *, channel_id: str) -> None:
        """Close one agent-backed node session."""
        connection = self._require_channel_connection(channel_id)
        connection.channels.require_open(channel_id)
        await _write_frame(
            connection.writer,
            frame_type=TunnelFrameType.CLOSE_SESSION,
            request_id=str(uuid.uuid4()),
            channel_id=channel_id,
            max_frame_bytes=self._max_frame_bytes,
        )
        self._retire_channel(connection, channel_id)

    def _handle_agent_frame(
        self,
        connection: _BrokerTunnelConnection,
        decoded: DecodedTunnelFrame,
    ) -> None:
        frame = decoded.frame
        payload = decoded.payload
        if frame.type is TunnelFrameType.HEARTBEAT:
            return
        if frame.type is TunnelFrameType.SESSION_DATA:
            if frame.channel_id is None:
                raise TunnelStateError("channel_id is required")
            connection.channels.require_open(frame.channel_id)
            connection.adapters[frame.channel_id].feed_data(payload)
            return
        if frame.type is TunnelFrameType.CLOSE_SESSION:
            if frame.channel_id is None:
                raise TunnelStateError("channel_id is required")
            connection.channels.require_open(frame.channel_id)
            connection.adapters[frame.channel_id].feed_eof()
            self._retire_channel(connection, frame.channel_id)
            return
        raise TunnelProtocolError("agent frame type is not accepted")

    def _require_connection(
        self, *, agent_id: uuid.UUID, channel_id: str
    ) -> _BrokerTunnelConnection:
        if not channel_id:
            raise TunnelStateError("channel_id is required")
        try:
            return self._connections[agent_id]
        except KeyError as exc:
            raise TunnelStateError("agent tunnel is not connected") from exc

    def _require_channel_connection(self, channel_id: str) -> _BrokerTunnelConnection:
        agent_id = self._channel_agents.get(channel_id)
        if agent_id is None:
            raise TunnelStateError("channel is not open")
        return self._connections[agent_id]

    def _retire_channel(
        self, connection: _BrokerTunnelConnection, channel_id: str
    ) -> None:
        apply_channel_frame(
            channels=connection.channels,
            frame_type=TunnelFrameType.CLOSE_SESSION,
            channel_id=channel_id,
        )
        connection.adapters.pop(channel_id, None)
        self._channel_agents.pop(channel_id, None)

    def _drop_connection(self, agent_id: uuid.UUID, connection_id: str) -> None:
        connection = self._connections.get(agent_id)
        if connection is not None and connection.connection_id != connection_id:
            self._registry.disconnect(agent_id=agent_id, connection_id=connection_id)
            return
        connection = self._connections.pop(agent_id, None)
        if connection is not None:
            for adapter in connection.adapters.values():
                adapter.feed_eof()
            for channel_id in tuple(connection.adapters):
                self._channel_agents.pop(channel_id, None)
        self._registry.disconnect(agent_id=agent_id, connection_id=connection_id)


def build_tunnel_server_ssl_context(
    *,
    cert_path: str,
    key_path: str,
    ca_bundle_path: str,
) -> ssl.SSLContext:
    """Build an mTLS server context for authenticated agent tunnels."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    context.load_verify_locations(cafile=ca_bundle_path)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    return context


async def start_tunnel_listener(
    *,
    host: str,
    port: int,
    broker: ServerTunnelBroker,
    ssl_context: ssl.SSLContext,
) -> asyncio.AbstractServer:
    """Start the server-side mTLS tunnel listener."""
    if not host:
        raise TunnelStateError("tunnel listener host is required")
    if not 1 <= port <= 65535:
        raise TunnelStateError("tunnel listener port is outside valid TCP bounds")
    if ssl_context.verify_mode != ssl.CERT_REQUIRED:
        raise TunnelStateError("tunnel listener requires client certificates")
    return await asyncio.start_server(
        lambda reader, writer: broker.handle_stream(
            reader=reader,
            writer=writer,
            peer_certificate=_peer_certificate_binding(writer),
        ),
        host,
        port,
        ssl=ssl_context,
    )


def apply_channel_frame(
    *,
    channels: TunnelChannelRegistry,
    frame_type: TunnelFrameType,
    channel_id: str | None,
) -> None:
    """Apply channel state transitions for a decoded frame."""
    if frame_type is TunnelFrameType.OPEN_SESSION:
        if channel_id is None:
            raise TunnelStateError("channel_id is required")
        channels.open_channel(channel_id)
        return
    if frame_type in {
        TunnelFrameType.SESSION_DATA,
        TunnelFrameType.RESIZE_PTY,
        TunnelFrameType.CLOSE_SESSION,
    }:
        if channel_id is None:
            raise TunnelStateError("channel_id is required")
        channels.require_open(channel_id)
        if frame_type is TunnelFrameType.CLOSE_SESSION:
            channels.close_channel(channel_id)


async def _read_one_frame(
    reader: TunnelStreamReader, *, max_frame_bytes: int
) -> DecodedTunnelFrame:
    header_prefix = await reader.readexactly(4)
    header_length = struct.unpack("!I", header_prefix)[0]
    if header_length == 0 or header_length > FRAME_HEADER_MAX_BYTES:
        raise TunnelProtocolError("frame header length is invalid")
    header = await reader.readexactly(header_length)
    try:
        values = json.loads(header.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TunnelProtocolError("frame header is not valid JSON") from exc
    if not isinstance(values, Mapping):
        raise TunnelProtocolError("frame header must be an object")
    payload_length = values.get("payload_length")
    if not isinstance(payload_length, int) or isinstance(payload_length, bool):
        raise TunnelProtocolError("payload_length must be an integer")
    if payload_length < 0 or payload_length > max_frame_bytes:
        raise TunnelProtocolError("frame payload is too large")
    payload = await reader.readexactly(payload_length)
    return decode_frame(
        header_prefix + header + payload, max_frame_bytes=max_frame_bytes
    )


async def _write_frame(
    writer: TunnelStreamWriter,
    *,
    frame_type: TunnelFrameType,
    request_id: str,
    channel_id: str | None,
    payload: bytes = b"",
    max_frame_bytes: int,
) -> None:
    writer.write(
        encode_frame(
            frame_type=frame_type,
            request_id=request_id,
            channel_id=channel_id,
            payload=payload,
            max_frame_bytes=max_frame_bytes,
        )
    )
    await writer.drain()


async def _best_effort_error(writer: TunnelStreamWriter) -> None:
    try:
        await _write_frame(
            writer,
            frame_type=TunnelFrameType.ERROR,
            request_id=str(uuid.uuid4()),
            channel_id=None,
            max_frame_bytes=1024 * 1024,
        )
    except Exception:
        return


def _decode_auth_payload(payload: bytes) -> TunnelAuthRequest:
    try:
        values = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TunnelProtocolError("auth payload is invalid") from exc
    if not isinstance(values, Mapping):
        raise TunnelProtocolError("auth payload must be an object")
    try:
        return TunnelAuthRequest(
            agent_id=uuid.UUID(str(values["agent_id"])),
            node_name=str(values["node_name"]),
            cert_serial=str(values["cert_serial"]),
            cert_public_key=str(values["cert_public_key"]),
            tunnel_secret=str(values["tunnel_secret"]),
        )
    except (KeyError, ValueError) as exc:
        raise TunnelProtocolError("auth payload is incomplete") from exc


def _verify_peer_certificate_binding(
    *,
    auth_request: TunnelAuthRequest,
    peer_certificate: PeerCertificateBinding,
) -> None:
    if auth_request.cert_serial != peer_certificate.cert_serial:
        raise TunnelAuthError("mTLS certificate serial mismatch")
    if auth_request.cert_public_key != peer_certificate.cert_public_key:
        raise TunnelAuthError("mTLS certificate public key mismatch")


def _peer_certificate_binding(writer: TunnelStreamWriter) -> PeerCertificateBinding:
    get_extra_info = getattr(writer, "get_extra_info", None)
    if not callable(get_extra_info):
        raise TunnelAuthError("mTLS peer certificate is unavailable")
    ssl_object = get_extra_info("ssl_object")
    getpeercert = getattr(ssl_object, "getpeercert", None)
    if not callable(getpeercert):
        raise TunnelAuthError("mTLS peer certificate is unavailable")
    cert_der = getpeercert(binary_form=True)
    if not isinstance(cert_der, bytes) or not cert_der:
        raise TunnelAuthError("mTLS peer certificate is unavailable")
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except ValueError as exc:
        raise TunnelAuthError("mTLS peer certificate is invalid") from exc
    now = dt.datetime.now(dt.timezone.utc)
    if cert.not_valid_before_utc > now or cert.not_valid_after_utc <= now:
        raise TunnelAuthError("mTLS peer certificate is outside its validity window")
    public_key_pem = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return PeerCertificateBinding(
        cert_serial=format(cert.serial_number, "x"),
        cert_public_key=public_key_pem.decode("ascii"),
    )


def _load_ed25519_public_key(public_key_pem: str) -> Ed25519PublicKey:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(public_key, Ed25519PublicKey):
        raise TunnelAuthError("agent public key must be Ed25519")
    return public_key


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def _datetime_value(value: object) -> dt.datetime:
    if isinstance(value, dt.datetime):
        return value
    raise TunnelAuthError("stored agent timestamp is invalid")


def _optional_datetime_value(value: object) -> dt.datetime | None:
    if value is None:
        return None
    return _as_utc(_datetime_value(value))


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)
