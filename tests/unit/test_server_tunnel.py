"""Tests for server-side tunnel authentication and state."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid
from typing import Any, cast

import asyncssh
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from server.tunnel import (
    ActiveTunnelRegistry,
    AgentCertificateRenewer,
    AgentTunnelRecord,
    HeartbeatState,
    InMemoryAgentTunnelStore,
    PeerCertificateBinding,
    PostgresAgentTunnelStore,
    ServerTunnelBroker,
    TunnelAuthenticator,
    TunnelAuthError,
    TunnelAuthRequest,
    TunnelBackpressure,
    TunnelChannelRegistry,
    TunnelStateError,
    apply_channel_frame,
    build_tunnel_server_ssl_context,
)
from vibeconnect_common.crypto import (
    IssuedUserCertificate,
    SecretValue,
    generate_agent_private_key,
    sha256_hex,
)
from vibeconnect_common.models import TunnelFrame, TunnelFrameType
from vibeconnect_common.tunnel import (
    DecodedTunnelFrame,
    decode_frame,
    encode_frame,
)

_NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
_RAW_SECRET = "s" * 43


@pytest.mark.asyncio
async def test_tunnel_auth_success_binds_agent_cert_and_secret() -> None:
    """Tunnel auth requires the stored cert binding and matching secret."""
    agent_id = uuid.uuid4()
    secret = SecretValue(_RAW_SECRET)
    record = _record(agent_id=agent_id, tunnel_secret_hash=sha256_hex(secret))
    store = InMemoryAgentTunnelStore({agent_id: record})

    authenticated = await TunnelAuthenticator(store).authenticate(
        _auth_request(agent_id=agent_id, tunnel_secret=secret.reveal()),
        now=_NOW,
    )

    assert authenticated == record


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "record_update,request_update,match",
    [
        ({"revoked_at": _NOW}, {}, "revoked"),
        ({"cert_expires_at": _NOW}, {}, "expired"),
        ({}, {"node_name": "other-01"}, "node binding"),
        ({}, {"cert_serial": "bad"}, "serial"),
        ({}, {"cert_public_key": "different"}, "public key"),
        ({}, {"tunnel_secret": "wrong"}, "secret"),
    ],
)
async def test_tunnel_auth_denials_fail_closed(
    record_update: dict[str, object],
    request_update: dict[str, object],
    match: str,
) -> None:
    """Cert mismatch, revocation, expiry, and wrong secret deny the tunnel."""
    agent_id = uuid.uuid4()
    secret = SecretValue(_RAW_SECRET)
    record = _record(agent_id=agent_id, tunnel_secret_hash=sha256_hex(secret))
    record = _replace_record(record, record_update)
    request = _auth_request(agent_id=agent_id, tunnel_secret=secret.reveal())
    request = _replace_request(request, request_update)

    with pytest.raises(TunnelAuthError, match=match):
        await TunnelAuthenticator(
            InMemoryAgentTunnelStore({agent_id: record})
        ).authenticate(
            request,
            now=_NOW,
        )


def test_duplicate_active_tunnel_is_rejected_and_revocation_disconnects() -> None:
    """Only one active tunnel per agent is allowed."""
    agent_id = uuid.uuid4()
    registry = ActiveTunnelRegistry()

    registry.connect(agent_id=agent_id, connection_id="conn-01")
    registry.connect(agent_id=agent_id, connection_id="conn-01")
    with pytest.raises(TunnelStateError, match="duplicate"):
        registry.connect(agent_id=agent_id, connection_id="conn-02")

    assert registry.revoke(agent_id=agent_id) == "conn-01"
    registry.connect(agent_id=agent_id, connection_id="conn-02")
    registry.disconnect(agent_id=agent_id, connection_id="conn-02")
    assert registry.revoke(agent_id=agent_id) is None


def test_channel_registry_rejects_reuse_unknown_and_session_limit() -> None:
    """Channel IDs cannot be reused and session limits are enforced."""
    channels = TunnelChannelRegistry(max_sessions=1)

    apply_channel_frame(
        channels=channels,
        frame_type=TunnelFrameType.OPEN_SESSION,
        channel_id="chan-01",
    )
    with pytest.raises(TunnelStateError, match="max sessions"):
        apply_channel_frame(
            channels=channels,
            frame_type=TunnelFrameType.OPEN_SESSION,
            channel_id="chan-02",
        )
    apply_channel_frame(
        channels=channels,
        frame_type=TunnelFrameType.CLOSE_SESSION,
        channel_id="chan-01",
    )
    with pytest.raises(TunnelStateError, match="reuse"):
        apply_channel_frame(
            channels=channels,
            frame_type=TunnelFrameType.OPEN_SESSION,
            channel_id="chan-01",
        )
    with pytest.raises(TunnelStateError, match="unknown"):
        apply_channel_frame(
            channels=channels,
            frame_type=TunnelFrameType.SESSION_DATA,
            channel_id="missing",
        )


def test_missed_heartbeat_blocks_new_jumps() -> None:
    """New jumps require a fresh heartbeat."""
    heartbeat = HeartbeatState(heartbeat_seconds=10)

    assert not heartbeat.allows_new_jump(_NOW)
    heartbeat.mark_seen(_NOW)
    assert heartbeat.allows_new_jump(_NOW + dt.timedelta(seconds=19))
    assert not heartbeat.allows_new_jump(_NOW + dt.timedelta(seconds=20))


def test_backpressure_fails_closed_for_slow_downstream() -> None:
    """Pending downstream data is bounded."""
    backpressure = TunnelBackpressure(max_pending_bytes=5)

    backpressure.queue(b"abc")
    backpressure.drain(1)
    backpressure.queue(b"abc")
    with pytest.raises(TunnelStateError, match="backpressure"):
        backpressure.queue(b"z")


@pytest.mark.asyncio
async def test_renew_agent_cert_success_and_revoked_denial() -> None:
    """Certificate renewal persists fresh cert binding and denies revoked agents."""
    agent_id = uuid.uuid4()
    record = _record(
        agent_id=agent_id,
        tunnel_secret_hash=sha256_hex(SecretValue(_RAW_SECRET)),
    )
    store = InMemoryAgentTunnelStore({agent_id: record})
    ca_key, ca_cert = _agent_ca()
    renewer = AgentCertificateRenewer(
        store=store,
        agent_ca_private_key=ca_key,
        agent_ca_certificate=ca_cert,
    )
    new_public_key = _public_key_pem()

    renewed = await renewer.renew(
        agent_id=agent_id,
        node_name="node-01",
        new_public_key_pem=new_public_key,
        now=_NOW,
    )

    assert renewed.public_key_pem == new_public_key
    assert renewed.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert store.records[agent_id].x509_public_key == new_public_key
    assert store.records[agent_id].cert_serial == renewed.cert_serial

    store.records[agent_id] = _replace_record(
        store.records[agent_id], {"revoked_at": _NOW}
    )
    with pytest.raises(TunnelAuthError, match="cannot renew"):
        await renewer.renew(
            agent_id=agent_id,
            node_name="node-01",
            new_public_key_pem=_public_key_pem(),
            now=_NOW,
        )


@pytest.mark.asyncio
async def test_postgres_agent_tunnel_store_maps_schema_rows() -> None:
    """The PostgreSQL tunnel store maps agent rows and renewal updates."""
    agent_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    connection = FakeAgentTunnelConnection(
        rows=[
            {
                "id": agent_id,
                "node_name": "node-01",
                "x509_public_key": _PUBLIC_KEY,
                "tunnel_secret_hash": "secret-hash",
                "cert_serial": "cert-01",
                "cert_expires_at": _NOW + dt.timedelta(hours=1),
                "revoked": False,
                "revoked_at": None,
            }
        ]
    )
    store = PostgresAgentTunnelStore(connection)

    record = await store.get_agent(agent_id)
    await store.update_agent_certificate(
        agent_id=agent_id,
        public_key_pem="new-pub",
        cert_serial="cert-02",
        expires_at=_NOW + dt.timedelta(hours=2),
    )
    await store.update_last_seen(agent_id, _NOW)

    assert record is not None
    assert record.agent_id == agent_id
    assert record.revoked_at is None
    assert "FROM agents" in connection.fetches[0][0]
    assert "revoked_at" in connection.fetches[0][0]
    assert "revoked = false" in connection.executed[0][0]
    assert "last_seen = $2" in connection.executed[1][0]
    assert connection.executed[1][1] == (agent_id, _NOW)


@pytest.mark.asyncio
async def test_server_tunnel_broker_authenticates_stream_and_sends_auth_ok() -> None:
    """The server tunnel broker accepts only a valid initial auth frame."""
    agent_id = uuid.uuid4()
    secret = SecretValue(_RAW_SECRET)
    store = InMemoryAgentTunnelStore(
        {agent_id: _record(agent_id=agent_id, tunnel_secret_hash=sha256_hex(secret))}
    )
    broker = ServerTunnelBroker(
        authenticator=TunnelAuthenticator(store),
        max_sessions_per_agent=4,
        heartbeat_seconds=30,
        max_frame_bytes=1024 * 1024,
    )
    reader = FakeTunnelReader(
        _auth_frame(agent_id=agent_id, tunnel_secret=secret.reveal())
    )
    writer = FakeTunnelWriter()

    await broker.handle_stream(
        reader=reader,
        writer=writer,
        peer_certificate=_peer_binding(),
        now=_NOW,
    )

    response = decode_frame(writer.data)
    assert response.frame.type is TunnelFrameType.AUTH_OK
    assert agent_id in store.last_seen
    assert writer.closed


@pytest.mark.asyncio
async def test_server_tunnel_broker_requires_auth_frame_to_match_mtls_peer() -> None:
    """Agent auth values must match the certificate proven by TLS."""
    agent_id = uuid.uuid4()
    secret = SecretValue(_RAW_SECRET)
    broker = _broker(agent_id=agent_id, secret=secret)
    reader = FakeTunnelReader(
        _auth_frame(agent_id=agent_id, tunnel_secret=secret.reveal())
    )
    writer = FakeTunnelWriter()

    await broker.handle_stream(
        reader=reader,
        writer=writer,
        peer_certificate=_peer_binding(cert_public_key="different"),
        now=_NOW,
    )

    response = decode_frame(writer.data)
    assert response.frame.type is TunnelFrameType.ERROR
    with pytest.raises(TunnelStateError, match="not connected"):
        broker.connector_for_agent(agent_id=agent_id, channel_id="channel-01")


@pytest.mark.asyncio
async def test_server_tunnel_broker_open_session_sends_agent_frame() -> None:
    """Opening a jump channel sends an OPEN_SESSION frame to the agent tunnel."""
    agent_id = uuid.uuid4()
    secret = SecretValue(_RAW_SECRET)
    broker = _broker(agent_id=agent_id, secret=secret)
    reader = BlockingTunnelReader()
    writer = FakeTunnelWriter()
    task = asyncio.create_task(
        broker.handle_stream(
            reader=reader,
            writer=writer,
            peer_certificate=_peer_binding(),
            now=_NOW,
        )
    )
    reader.feed(_auth_frame(agent_id=agent_id, tunnel_secret=secret.reveal()))
    await writer.wait_for_writes(1)

    await broker.open_session(
        agent_id=agent_id,
        channel_id="channel-01",
        node_name="node-01",
        node_ssh_host_public_key="ssh-ed25519 AAAATEST",
        username="alice",
        user_certificate=IssuedUserCertificate(
            private_key=cast(asyncssh.SSHKey, None),
            certificate=b"cert",
            serial=1,
            username="alice",
            valid_after=_NOW,
            valid_before=_NOW + dt.timedelta(hours=1),
        ),
    )

    frames = _decode_frames(writer.data)
    assert frames[0].frame.type is TunnelFrameType.AUTH_OK
    assert frames[1].frame.type is TunnelFrameType.OPEN_SESSION
    assert frames[1].frame.channel_id == "channel-01"
    assert json.loads(frames[1].payload.decode("utf-8")) == {
        "node_name": "node-01",
        "username": "alice",
    }

    reader.feed_eof()
    await task


@pytest.mark.asyncio
async def test_broker_tunnel_stream_is_asyncssh_tunnel_transport() -> None:
    """The broker stream exposes AsyncSSH's tunnel create_connection surface."""
    agent_id = uuid.uuid4()
    secret = SecretValue(_RAW_SECRET)
    broker = _broker(agent_id=agent_id, secret=secret)
    reader = BlockingTunnelReader()
    writer = FakeTunnelWriter()
    task = asyncio.create_task(
        broker.handle_stream(
            reader=reader,
            writer=writer,
            peer_certificate=_peer_binding(),
            now=_NOW,
        )
    )
    reader.feed(_auth_frame(agent_id=agent_id, tunnel_secret=secret.reveal()))
    await writer.wait_for_writes(1)
    channel_id = "channel-01"
    await broker.open_session(
        agent_id=agent_id,
        channel_id=channel_id,
        node_name="node-01",
        node_ssh_host_public_key="ssh-ed25519 AAAATEST",
        username="alice",
        user_certificate=_issued_user_certificate(username="alice"),
    )
    connector = broker.connector_for_agent(agent_id=agent_id, channel_id=channel_id)
    protocol = FakeTunnelProtocol()

    transport, returned_protocol = await cast(Any, connector).create_connection(
        lambda: protocol, "node-01", 2222
    )
    transport.write(b"client-bytes")
    await writer.wait_for_writes(3)
    broker._handle_agent_frame(
        broker._connections[agent_id],
        DecodedTunnelFrame(
            frame=TunnelFrame(
                type=TunnelFrameType.SESSION_DATA,
                request_id="response-01",
                channel_id=channel_id,
                payload_length=len(b"server-bytes"),
            ),
            payload=b"server-bytes",
        ),
    )
    await protocol.wait_for_data()

    assert returned_protocol is protocol
    assert protocol.transport is transport
    assert transport.get_extra_info("peername") == ("127.0.0.1", 2222)
    assert protocol.received == b"server-bytes"
    frames = _decode_frames(writer.data)
    assert frames[2].frame.type is TunnelFrameType.SESSION_DATA
    assert frames[2].payload == b"client-bytes"

    transport.close()
    reader.feed_eof()
    await task


@pytest.mark.asyncio
async def test_duplicate_tunnel_does_not_drop_existing_connection() -> None:
    """A rejected duplicate tunnel cannot evict the active tunnel."""
    agent_id = uuid.uuid4()
    secret = SecretValue(_RAW_SECRET)
    broker = _broker(agent_id=agent_id, secret=secret)
    first_reader = BlockingTunnelReader()
    first_writer = FakeTunnelWriter()
    first_task = asyncio.create_task(
        broker.handle_stream(
            reader=first_reader,
            writer=first_writer,
            peer_certificate=_peer_binding(),
            now=_NOW,
        )
    )
    first_reader.feed(_auth_frame(agent_id=agent_id, tunnel_secret=secret.reveal()))
    await first_writer.wait_for_writes(1)

    duplicate_reader = FakeTunnelReader(
        _auth_frame(agent_id=agent_id, tunnel_secret=secret.reveal())
    )
    duplicate_writer = FakeTunnelWriter()
    await broker.handle_stream(
        reader=duplicate_reader,
        writer=duplicate_writer,
        peer_certificate=_peer_binding(),
        now=_NOW,
    )

    await broker.open_session(
        agent_id=agent_id,
        channel_id="channel-01",
        node_name="node-01",
        node_ssh_host_public_key="ssh-ed25519 AAAATEST",
        username="alice",
        user_certificate=_issued_user_certificate(username="alice"),
    )

    assert (
        _decode_frames(first_writer.data)[1].frame.type is TunnelFrameType.OPEN_SESSION
    )

    first_reader.feed_eof()
    await first_task


def test_tunnel_server_ssl_context_requires_client_certs() -> None:
    """The tunnel SSL helper fails closed when certificate files are missing."""
    with pytest.raises(FileNotFoundError):
        build_tunnel_server_ssl_context(
            cert_path="/missing/server.crt",
            key_path="/missing/server.key",
            ca_bundle_path="/missing/ca.crt",
        )


def _record(
    *,
    agent_id: uuid.UUID,
    tunnel_secret_hash: str,
    revoked_at: dt.datetime | None = None,
    cert_expires_at: dt.datetime | None = None,
) -> AgentTunnelRecord:
    return AgentTunnelRecord(
        agent_id=agent_id,
        node_name="node-01",
        x509_public_key=_PUBLIC_KEY,
        tunnel_secret_hash=tunnel_secret_hash,
        cert_serial="abc123",
        cert_expires_at=cert_expires_at or (_NOW + dt.timedelta(hours=1)),
        revoked_at=revoked_at,
    )


def _auth_request(*, agent_id: uuid.UUID, tunnel_secret: str) -> TunnelAuthRequest:
    return TunnelAuthRequest(
        agent_id=agent_id,
        node_name="node-01",
        cert_serial="abc123",
        cert_public_key=_PUBLIC_KEY,
        tunnel_secret=tunnel_secret,
    )


def _replace_record(
    record: AgentTunnelRecord, values: dict[str, object]
) -> AgentTunnelRecord:
    return AgentTunnelRecord(
        agent_id=record.agent_id,
        node_name=str(values.get("node_name", record.node_name)),
        x509_public_key=str(values.get("x509_public_key", record.x509_public_key)),
        tunnel_secret_hash=str(
            values.get("tunnel_secret_hash", record.tunnel_secret_hash)
        ),
        cert_serial=str(values.get("cert_serial", record.cert_serial)),
        cert_expires_at=_datetime_value(
            values.get("cert_expires_at", record.cert_expires_at)
        ),
        revoked_at=_optional_datetime_value(
            values.get("revoked_at", record.revoked_at)
        ),
    )


def _replace_request(
    request: TunnelAuthRequest, values: dict[str, object]
) -> TunnelAuthRequest:
    return TunnelAuthRequest(
        agent_id=request.agent_id,
        node_name=str(values.get("node_name", request.node_name)),
        cert_serial=str(values.get("cert_serial", request.cert_serial)),
        cert_public_key=str(values.get("cert_public_key", request.cert_public_key)),
        tunnel_secret=str(values.get("tunnel_secret", request.tunnel_secret)),
    )


class FakeAgentTunnelConnection:
    """Capture PostgreSQL tunnel store calls."""

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


class FakeTunnelReader:
    """Read a fixed byte stream and then raise EOF."""

    def __init__(self, data: bytes) -> None:
        """Initialize the stream buffer."""
        self._buffer = bytearray(data)

    async def readexactly(self, n: int) -> bytes:
        """Return exactly `n` bytes or raise EOF."""
        if len(self._buffer) < n:
            raise asyncio.IncompleteReadError(bytes(self._buffer), n)
        data = bytes(self._buffer[:n])
        del self._buffer[:n]
        return data


class BlockingTunnelReader:
    """Queue-backed tunnel reader for long-lived broker tests."""

    def __init__(self) -> None:
        """Initialize an empty stream."""
        self._buffer = bytearray()
        self._event = asyncio.Event()
        self._eof = False

    def feed(self, data: bytes) -> None:
        """Append stream bytes and wake readers."""
        self._buffer.extend(data)
        self._event.set()

    def feed_eof(self) -> None:
        """Mark the stream EOF and wake readers."""
        self._eof = True
        self._event.set()

    async def readexactly(self, n: int) -> bytes:
        """Return exactly `n` bytes or raise EOF."""
        while len(self._buffer) < n:
            if self._eof:
                raise asyncio.IncompleteReadError(bytes(self._buffer), n)
            await self._event.wait()
            self._event.clear()
        data = bytes(self._buffer[:n])
        del self._buffer[:n]
        return data


class FakeTunnelWriter:
    """Capture framed tunnel writes."""

    def __init__(self) -> None:
        """Initialize captured bytes."""
        self.data = b""
        self.closed = False
        self._write_count = 0
        self._event = asyncio.Event()

    def write(self, data: bytes) -> None:
        """Capture a write."""
        self.data += data
        self._write_count += 1
        self._event.set()

    async def drain(self) -> None:
        """No-op drain for tests."""

    def close(self) -> None:
        """Mark closed."""
        self.closed = True

    async def wait_closed(self) -> None:
        """No-op wait for tests."""

    async def wait_for_writes(self, count: int) -> None:
        """Wait until at least `count` writes have been captured."""
        while self._write_count < count:
            await self._event.wait()
            self._event.clear()


class FakeTunnelProtocol(asyncio.Protocol):
    """Capture transport lifecycle and bytes from a broker transport."""

    def __init__(self) -> None:
        """Initialize captured protocol state."""
        self.transport: asyncio.BaseTransport | None = None
        self.received = b""
        self.lost: Exception | None = None
        self._data_event = asyncio.Event()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Capture the transport."""
        self.transport = transport

    def data_received(self, data: bytes) -> None:
        """Capture bytes from the transport."""
        self.received += data
        self._data_event.set()

    def connection_lost(self, exc: Exception | None) -> None:
        """Capture transport closure."""
        self.lost = exc

    async def wait_for_data(self) -> None:
        """Wait until at least one byte has been received."""
        while not self.received:
            await self._data_event.wait()
            self._data_event.clear()


def _datetime_value(value: object) -> dt.datetime:
    assert isinstance(value, dt.datetime)
    return value


def _optional_datetime_value(value: object) -> dt.datetime | None:
    assert value is None or isinstance(value, dt.datetime)
    return value


def _broker(*, agent_id: uuid.UUID, secret: SecretValue) -> ServerTunnelBroker:
    record = _record(agent_id=agent_id, tunnel_secret_hash=sha256_hex(secret))
    return ServerTunnelBroker(
        authenticator=TunnelAuthenticator(InMemoryAgentTunnelStore({agent_id: record})),
        max_sessions_per_agent=4,
        heartbeat_seconds=30,
        max_frame_bytes=1024 * 1024,
    )


def _auth_frame(*, agent_id: uuid.UUID, tunnel_secret: str) -> bytes:
    payload = json.dumps(
        {
            "agent_id": str(agent_id),
            "node_name": "node-01",
            "cert_serial": "abc123",
            "cert_public_key": _PUBLIC_KEY,
            "tunnel_secret": tunnel_secret,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return encode_frame(
        frame_type=TunnelFrameType.AUTH,
        request_id="auth-01",
        channel_id=None,
        payload=payload,
    )


def _peer_binding(
    *,
    cert_serial: str = "abc123",
    cert_public_key: str | None = None,
) -> PeerCertificateBinding:
    return PeerCertificateBinding(
        cert_serial=cert_serial,
        cert_public_key=_PUBLIC_KEY if cert_public_key is None else cert_public_key,
    )


def _decode_frames(data: bytes) -> list[DecodedTunnelFrame]:
    frames: list[DecodedTunnelFrame] = []
    buffer = data
    while buffer:
        header_length = int.from_bytes(buffer[:4], "big")
        header_end = 4 + header_length
        header = json.loads(buffer[4:header_end].decode("utf-8"))
        payload_end = header_end + int(header["payload_length"])
        frames.append(decode_frame(buffer[:payload_end]))
        buffer = buffer[payload_end:]
    return frames


def _issued_user_certificate(*, username: str) -> IssuedUserCertificate:
    return IssuedUserCertificate(
        private_key=cast(asyncssh.SSHKey, None),
        certificate=b"cert",
        serial=1,
        username=username,
        valid_after=_NOW,
        valid_before=_NOW + dt.timedelta(hours=1),
    )


def _public_key_pem() -> str:
    return (
        generate_agent_private_key()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


def _agent_ca() -> tuple[Ed25519PrivateKey, x509.Certificate]:
    key = Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - dt.timedelta(days=1))
        .not_valid_after(_NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=None)
    )
    return key, cert


_PUBLIC_KEY = _public_key_pem()
