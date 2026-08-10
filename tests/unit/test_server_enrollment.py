"""Tests for server-side enrollment behavior."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import uuid
from collections.abc import Mapping
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from server.enrollment import (
    ENROLLMENT_TOKEN_LIFETIME_DAYS,
    EnrollmentError,
    EnrollmentRateLimiter,
    EnrollmentRequest,
    EnrollmentService,
    InMemoryEnrollmentStore,
    PostgresEnrollmentStore,
    StoredAgent,
)
from vibeconnect_common.audit import AuditWriter
from vibeconnect_common.crypto import (
    SECRET_REDACTION,
    generate_agent_private_key,
    verify_secret_hash,
)
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
async def test_create_agent_disables_prior_unused_token() -> None:
    """Creating a new token disables older active tokens for the same node."""
    store = InMemoryEnrollmentStore()
    service = _service(store)
    first = await service.create_agent(
        node_name="node-01", labels=["prod"], created_by="admin"
    )
    second = await service.create_agent(
        node_name="node-01", labels=["prod"], created_by="admin"
    )

    assert first.token_hash != second.token_hash
    assert store.tokens[first.token_hash]["disabled_at"] is not None
    assert store.tokens[second.token_hash]["disabled_at"] is None
    assert first.token.reveal() in first.agent_conf
    assert first.token_hash not in first.agent_conf


@pytest.mark.asyncio
async def test_enroll_success_persists_agent_and_response_shape() -> None:
    """Successful enrollment consumes the token and persists agent identity."""
    store = InMemoryEnrollmentStore()
    service = _service(store)
    package = await service.create_agent(
        node_name="node-01", labels=(), created_by="admin"
    )

    response = await service.enroll(
        _request(node_name="node-01", token=package.token.reveal())
    )
    response_json = response.to_json()

    assert set(response_json) == {
        "agent_id",
        "agent_x509_cert",
        "tunnel_ca_bundle",
        "tunnel_host",
        "tunnel_port",
        "tunnel_secret",
    }
    assert store.tokens[package.token_hash]["used"] is True
    stored_agent = next(iter(store.agents.values()))
    assert stored_agent.node_name == "node-01"
    assert stored_agent.node_ssh_host_public_key == _NODE_HOST_KEY
    assert stored_agent.tunnel_secret_hash != response.tunnel_secret.reveal()
    assert verify_secret_hash(response.tunnel_secret, stored_agent.tunnel_secret_hash)


@pytest.mark.asyncio
async def test_enroll_rejects_expired_duplicate_and_mismatched_tokens() -> None:
    """Token failures use one generic public error."""
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    service = _service(InMemoryEnrollmentStore())
    expired = await service.create_agent(
        node_name="expired-01",
        labels=(),
        created_by="admin",
        now=now - dt.timedelta(days=ENROLLMENT_TOKEN_LIFETIME_DAYS + 1),
    )
    duplicate = await service.create_agent(
        node_name="node-01", labels=(), created_by="admin", now=now
    )

    await service.enroll(
        _request(node_name="node-01", token=duplicate.token.reveal()), now=now
    )

    for request in (
        _request(node_name="expired-01", token=expired.token.reveal()),
        _request(node_name="node-01", token=duplicate.token.reveal()),
        _request(node_name="other-01", token=duplicate.token.reveal()),
    ):
        with pytest.raises(EnrollmentError, match="enrollment failed"):
            await service.enroll(request, now=now)


@pytest.mark.asyncio
async def test_enroll_token_consumption_race_allows_one_winner() -> None:
    """Concurrent duplicate consumption leaves only one enrolled agent."""
    store = InMemoryEnrollmentStore()
    service = _service(store)
    package = await service.create_agent(
        node_name="node-01", labels=(), created_by="admin"
    )
    request = _request(node_name="node-01", token=package.token.reveal())

    results = await asyncio.gather(
        service.enroll(request),
        service.enroll(request),
        return_exceptions=True,
    )

    assert sum(not isinstance(result, Exception) for result in results) == 1
    assert sum(isinstance(result, EnrollmentError) for result in results) == 1
    assert len(store.agents) == 1


@pytest.mark.asyncio
async def test_rate_limit_keeps_generic_public_error() -> None:
    """Rate-limited failures do not reveal whether a token exists."""
    rate_limiter = EnrollmentRateLimiter(max_source_failures=1, max_token_failures=1)
    service = _service(InMemoryEnrollmentStore(), rate_limiter=rate_limiter)
    request = _request(node_name="node-01", token="wrong-token")

    with pytest.raises(EnrollmentError, match="enrollment failed"):
        await service.enroll(request)
    with pytest.raises(EnrollmentError, match="enrollment failed"):
        await service.enroll(request)


@pytest.mark.asyncio
async def test_enrollment_audit_never_stores_raw_secrets(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Failed enrollment audit metadata excludes raw tokens and private keys."""
    connection = FakeAuditConnection()
    service = _service(InMemoryEnrollmentStore(), audit_writer=AuditWriter(connection))
    raw_token = "wrong-token"
    private_key = (
        generate_agent_private_key()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode("ascii")
    )

    with (
        caplog.at_level(logging.INFO),
        pytest.raises(EnrollmentError, match="enrollment failed"),
    ):
        await service.enroll(
            EnrollmentRequest(
                node_name="node-01",
                token=raw_token,
                agent_x509_public_key=private_key,
                node_ssh_host_public_key=_NODE_HOST_KEY,
                source_address="198.51.100.10",
            )
        )

    inserted_metadata = _last_inserted_metadata(connection)
    audit_json = json.dumps(inserted_metadata)
    assert raw_token not in audit_json
    assert private_key not in audit_json
    assert SECRET_REDACTION in audit_json
    assert raw_token not in caplog.text
    assert private_key not in caplog.text
    assert connection.executed[-1][1][1] == AuditEventType.ENROLLMENT_FAILED.value


def _service(
    store: InMemoryEnrollmentStore,
    *,
    audit_writer: AuditWriter | None = None,
    rate_limiter: EnrollmentRateLimiter | None = None,
) -> EnrollmentService:
    ca_key, ca_cert = _agent_ca()
    return EnrollmentService(
        store=store,
        agent_ca_private_key=ca_key,
        agent_ca_certificate=ca_cert,
        tunnel_ca_bundle="tunnel-ca",
        tunnel_host="tunnel.example.test",
        tunnel_port=443,
        enrollment_tls_ca_bundle="enrollment-ca",
        audit_writer=audit_writer,
        rate_limiter=rate_limiter,
    )


def _request(*, node_name: str, token: str) -> EnrollmentRequest:
    return EnrollmentRequest(
        node_name=node_name,
        token=token,
        agent_x509_public_key=_agent_public_key_pem(),
        node_ssh_host_public_key=_NODE_HOST_KEY,
        source_address="198.51.100.10",
    )


def _agent_public_key_pem() -> str:
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
    now = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=None)
    )
    return key, cert


@pytest.mark.asyncio
async def test_postgres_enrollment_store_uses_single_use_token_updates() -> None:
    """The PostgreSQL enrollment store atomically consumes active tokens."""
    connection = FakeEnrollmentConnection(
        rows=[{"token_hash": "hash-01", "node_name": "node-01"}]
    )
    store = PostgresEnrollmentStore(connection)
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    await store.create_enrollment_token(
        token_hash="hash-01",
        node_name="node-01",
        labels=("prod",),
        created_by="admin",
        expires_at=now + dt.timedelta(days=7),
    )
    consumed = await store.consume_enrollment_token(
        token_hash="hash-01", node_name="node-01", now=now
    )
    await store.persist_agent(
        StoredAgent(
            agent_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            node_name="node-01",
            x509_public_key="agent-pub",
            node_ssh_host_public_key=_NODE_HOST_KEY,
            tunnel_secret_hash="secret-hash",
            cert_serial="cert-01",
            cert_expires_at=now + dt.timedelta(hours=1),
        )
    )

    assert consumed is not None
    assert consumed.node_name == "node-01"
    assert len(connection.executed) == 4
    assert "disabled_at IS NULL" in connection.executed[0][0]
    assert "INSERT INTO enrollment_tokens" in connection.executed[1][0]
    assert "INSERT INTO agents" in connection.executed[2][0]
    assert "used = false" in connection.fetches[0][0]
    assert "expires_at > $3" in connection.fetches[0][0]


def _last_inserted_metadata(connection: FakeAuditConnection) -> Mapping[str, Any]:
    _query, args = connection.executed[-1]
    metadata = args[7]
    assert isinstance(metadata, str)
    decoded = json.loads(metadata)
    assert isinstance(decoded, dict)
    return decoded


class FakeEnrollmentConnection:
    """Capture PostgreSQL enrollment store calls."""

    def __init__(self, *, rows: list[Mapping[str, object]]) -> None:
        """Initialize queued fetch rows."""
        self.rows = rows
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.fetches: list[tuple[str, tuple[object, ...]]] = []

    async def execute(self, query: str, *args: object) -> str:
        """Record an execute call."""
        self.executed.append((query, args))
        return "OK"

    async def fetchrow(self, query: str, *args: object) -> Mapping[str, object] | None:
        """Record a fetchrow call."""
        self.fetches.append((query, args))
        return self.rows.pop(0) if self.rows else None


_NODE_HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINodeHostKey node-01"
