"""Tests for server-side tunnel authentication and state."""

from __future__ import annotations

import datetime as dt
import uuid

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
    TunnelAuthenticator,
    TunnelAuthError,
    TunnelAuthRequest,
    TunnelBackpressure,
    TunnelChannelRegistry,
    TunnelStateError,
    apply_channel_frame,
)
from vibeconnect_common.crypto import (
    SecretValue,
    generate_agent_private_key,
    sha256_hex,
)
from vibeconnect_common.models import TunnelFrameType

_NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


@pytest.mark.asyncio
async def test_tunnel_auth_success_binds_agent_cert_and_secret() -> None:
    """Tunnel auth requires the stored cert binding and matching secret."""
    agent_id = uuid.uuid4()
    secret = SecretValue("super-secret")
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
    secret = SecretValue("super-secret")
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
        tunnel_secret_hash=sha256_hex(SecretValue("super-secret")),
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


def _datetime_value(value: object) -> dt.datetime:
    assert isinstance(value, dt.datetime)
    return value


def _optional_datetime_value(value: object) -> dt.datetime | None:
    assert value is None or isinstance(value, dt.datetime)
    return value


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
