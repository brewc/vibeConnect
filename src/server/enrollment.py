"""Server-side enrollment token and API handling."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vibeconnect_common.audit import AuditWriter
from vibeconnect_common.crypto import (
    SecretValue,
    generate_enrollment_token,
    generate_tunnel_secret,
    issue_agent_client_certificate,
    scrub_secret_metadata,
    sha256_hex,
)
from vibeconnect_common.identifiers import validate_label, validate_node_name
from vibeconnect_common.models import AuditEventType

ENROLLMENT_TOKEN_LIFETIME_DAYS = 7
GENERIC_ENROLLMENT_ERROR = {"error": "enrollment failed"}


class EnrollmentError(ValueError):
    """Raised when enrollment cannot continue."""


@dataclass(frozen=True, slots=True)
class EnrollmentConfigPackage:
    """Server-created agent configuration package."""

    node_name: str
    labels: tuple[str, ...]
    token: SecretValue
    token_hash: str
    agent_conf: str
    enrollment_tls_ca_bundle: str


@dataclass(frozen=True, slots=True)
class EnrollmentTokenRecord:
    """A validated enrollment token ready to consume."""

    token_hash: str
    node_name: str
    labels: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EnrollmentRequest:
    """Enrollment request submitted by an agent."""

    node_name: str
    token: str
    agent_x509_public_key: str
    node_ssh_host_public_key: str
    source_address: str


@dataclass(frozen=True, slots=True)
class EnrollmentResponse:
    """Successful enrollment response returned to the agent."""

    agent_id: uuid.UUID
    agent_x509_cert: str
    tunnel_ca_bundle: str
    tunnel_host: str
    tunnel_port: int
    tunnel_secret: SecretValue

    def to_json(self) -> dict[str, object]:
        """Serialize the response for the enrollment API."""
        return {
            "agent_id": str(self.agent_id),
            "agent_x509_cert": self.agent_x509_cert,
            "tunnel_ca_bundle": self.tunnel_ca_bundle,
            "tunnel_host": self.tunnel_host,
            "tunnel_port": self.tunnel_port,
            "tunnel_secret": self.tunnel_secret.reveal(),
        }


@dataclass(frozen=True, slots=True)
class StoredAgent:
    """Agent row values persisted at enrollment completion."""

    agent_id: uuid.UUID
    node_name: str
    labels: tuple[str, ...]
    x509_public_key: str
    node_ssh_host_public_key: str
    tunnel_secret_hash: str
    cert_serial: str
    cert_expires_at: dt.datetime


class EnrollmentStore(Protocol):
    """Persistence operations required by enrollment."""

    async def create_enrollment_token(
        self,
        *,
        token_hash: str,
        node_name: str,
        labels: Sequence[str],
        created_by: str,
        expires_at: dt.datetime,
    ) -> None:
        """Disable prior active tokens for the node and insert a new token."""

    async def consume_enrollment_token(
        self, *, token_hash: str, node_name: str, now: dt.datetime
    ) -> EnrollmentTokenRecord | None:
        """Atomically consume a matching active token."""

    async def persist_agent(self, agent: StoredAgent) -> None:
        """Persist an enrolled agent row."""


class EnrollmentConnection(Protocol):
    """Database surface used by the PostgreSQL enrollment store."""

    async def execute(self, query: str, *args: object) -> str:
        """Execute a statement without returning rows."""

    async def fetchrow(self, query: str, *args: object) -> Mapping[str, object] | None:
        """Execute a statement and return one row."""


class PostgresEnrollmentStore:
    """PostgreSQL-backed enrollment store."""

    def __init__(self, connection: EnrollmentConnection) -> None:
        """Configure the database connection."""
        self._connection = connection

    async def create_enrollment_token(
        self,
        *,
        token_hash: str,
        node_name: str,
        labels: Sequence[str],
        created_by: str,
        expires_at: dt.datetime,
    ) -> None:
        """Disable prior active tokens for the node and insert a new token."""
        now = _utc_now()
        await self._connection.execute(
            """
            UPDATE enrollment_tokens
               SET disabled_at = $1
             WHERE node_name = $2
               AND used = false
               AND disabled_at IS NULL
            """,
            now,
            node_name,
        )
        await self._connection.execute(
            """
            INSERT INTO enrollment_tokens
                (token_hash, node_name, labels, created_by, created_at, expires_at)
            VALUES ($1, $2, $3::jsonb, $4, $5, $6)
            """,
            token_hash,
            node_name,
            json.dumps(list(labels)),
            created_by,
            now,
            _as_utc(expires_at),
        )

    async def consume_enrollment_token(
        self, *, token_hash: str, node_name: str, now: dt.datetime
    ) -> EnrollmentTokenRecord | None:
        """Atomically consume a matching active token."""
        row = await self._connection.fetchrow(
            """
            UPDATE enrollment_tokens
               SET used = true, used_at = $3
             WHERE token_hash = $1
               AND node_name = $2
               AND used = false
               AND disabled_at IS NULL
               AND expires_at > $3
            RETURNING token_hash, node_name, labels
            """,
            token_hash,
            node_name,
            _as_utc(now),
        )
        if row is None:
            return None
        return EnrollmentTokenRecord(
            token_hash=str(row["token_hash"]),
            node_name=str(row["node_name"]),
            labels=_labels(row["labels"]),
        )

    async def persist_agent(self, agent: StoredAgent) -> None:
        """Persist an enrolled agent row."""
        await self._connection.execute(
            """
            INSERT INTO agents
                (
                    id,
                    node_name,
                    labels,
                    x509_public_key,
                    node_ssh_host_public_key,
                    tunnel_secret_hash,
                    enrolled_at,
                    cert_serial,
                    cert_expires_at
                )
            VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8, $9)
            """,
            agent.agent_id,
            agent.node_name,
            json.dumps(list(agent.labels)),
            agent.x509_public_key,
            agent.node_ssh_host_public_key,
            agent.tunnel_secret_hash,
            _utc_now(),
            agent.cert_serial,
            _as_utc(agent.cert_expires_at),
        )
        await self._connection.execute(
            """
            UPDATE enrollment_tokens
               SET agent_id = $1
             WHERE node_name = $2
               AND used = true
               AND agent_id IS NULL
            """,
            agent.agent_id,
            agent.node_name,
        )


class InMemoryEnrollmentStore:
    """Locking in-memory store used by unit tests and early wiring."""

    def __init__(self) -> None:
        """Initialize empty token and agent state."""
        self._lock = asyncio.Lock()
        self.tokens: dict[str, dict[str, object]] = {}
        self.agents: dict[uuid.UUID, StoredAgent] = {}

    async def create_enrollment_token(
        self,
        *,
        token_hash: str,
        node_name: str,
        labels: Sequence[str],
        created_by: str,
        expires_at: dt.datetime,
    ) -> None:
        """Disable prior active tokens for the node and insert a new token."""
        async with self._lock:
            for row in self.tokens.values():
                if (
                    row["node_name"] == node_name
                    and row["used"] is False
                    and row["disabled_at"] is None
                ):
                    row["disabled_at"] = _utc_now()
            self.tokens[token_hash] = {
                "node_name": node_name,
                "labels": tuple(labels),
                "created_by": created_by,
                "expires_at": expires_at,
                "used": False,
                "disabled_at": None,
            }

    async def consume_enrollment_token(
        self, *, token_hash: str, node_name: str, now: dt.datetime
    ) -> EnrollmentTokenRecord | None:
        """Atomically consume a matching active token."""
        async with self._lock:
            row = self.tokens.get(token_hash)
            if row is None:
                return None
            if row["node_name"] != node_name:
                return None
            if row["used"] is True or row["disabled_at"] is not None:
                return None
            expires_at = row["expires_at"]
            if not isinstance(expires_at, dt.datetime) or expires_at <= now:
                return None
            row["used"] = True
            row["used_at"] = now
            labels = row["labels"]
            if not isinstance(labels, tuple):
                labels = tuple(labels) if isinstance(labels, list) else ()
            return EnrollmentTokenRecord(
                token_hash=token_hash,
                node_name=node_name,
                labels=tuple(str(label) for label in labels),
            )

    async def persist_agent(self, agent: StoredAgent) -> None:
        """Persist an enrolled agent row."""
        async with self._lock:
            self.agents[agent.agent_id] = agent


class EnrollmentRateLimiter:
    """Sliding-window limiter for failed enrollment attempts."""

    def __init__(
        self,
        *,
        max_source_failures: int = 10,
        max_token_failures: int = 5,
        window_seconds: int = 600,
    ) -> None:
        """Configure failure thresholds."""
        self._max_source_failures = max_source_failures
        self._max_token_failures = max_token_failures
        self._window_seconds = window_seconds
        self._source_failures: dict[str, deque[dt.datetime]] = defaultdict(deque)
        self._token_failures: dict[str, deque[dt.datetime]] = defaultdict(deque)

    def is_limited(
        self, *, source_address: str, token_hash: str, now: dt.datetime
    ) -> bool:
        """Return whether a source or token hash is currently limited."""
        return self._count(self._source_failures[source_address], now) >= (
            self._max_source_failures
        ) or self._count(self._token_failures[token_hash], now) >= (
            self._max_token_failures
        )

    def record_failure(
        self, *, source_address: str, token_hash: str, now: dt.datetime
    ) -> None:
        """Record a failed enrollment attempt."""
        self._source_failures[source_address].append(now)
        self._token_failures[token_hash].append(now)

    def _count(self, failures: deque[dt.datetime], now: dt.datetime) -> int:
        cutoff = now - dt.timedelta(seconds=self._window_seconds)
        while failures and failures[0] <= cutoff:
            failures.popleft()
        return len(failures)


class EnrollmentService:
    """Create tokens and complete agent enrollment."""

    def __init__(
        self,
        *,
        store: EnrollmentStore,
        agent_ca_private_key: Ed25519PrivateKey,
        agent_ca_certificate: x509.Certificate,
        tunnel_ca_bundle: str,
        tunnel_host: str,
        tunnel_port: int,
        enrollment_tls_ca_bundle: str,
        audit_writer: AuditWriter | None = None,
        rate_limiter: EnrollmentRateLimiter | None = None,
    ) -> None:
        """Configure enrollment dependencies."""
        self._store = store
        self._agent_ca_private_key = agent_ca_private_key
        self._agent_ca_certificate = agent_ca_certificate
        self._tunnel_ca_bundle = tunnel_ca_bundle
        self._tunnel_host = tunnel_host
        self._tunnel_port = tunnel_port
        self._enrollment_tls_ca_bundle = enrollment_tls_ca_bundle
        self._audit_writer = audit_writer
        self._rate_limiter = rate_limiter or EnrollmentRateLimiter()

    async def create_agent(
        self,
        *,
        node_name: str,
        labels: Sequence[str],
        created_by: str,
        now: dt.datetime | None = None,
    ) -> EnrollmentConfigPackage:
        """Create a single-use enrollment token and agent config package."""
        safe_node_name = validate_node_name(node_name)
        safe_labels = tuple(validate_label(label) for label in labels)
        token = generate_enrollment_token()
        token_hash = sha256_hex(token)
        actual_now = _utc_now() if now is None else _as_utc(now)
        await self._store.create_enrollment_token(
            token_hash=token_hash,
            node_name=safe_node_name,
            labels=safe_labels,
            created_by=created_by,
            expires_at=actual_now + dt.timedelta(days=ENROLLMENT_TOKEN_LIFETIME_DAYS),
        )
        if self._audit_writer is not None:
            await self._audit_writer.write(
                event_type=AuditEventType.ENROLLMENT_TOKEN_CREATED,
                actor=created_by,
                node_name=safe_node_name,
                metadata={"labels": list(safe_labels), "token_hash": token_hash},
            )
        return EnrollmentConfigPackage(
            node_name=safe_node_name,
            labels=safe_labels,
            token=token,
            token_hash=token_hash,
            agent_conf=_render_agent_conf(safe_node_name, token),
            enrollment_tls_ca_bundle=self._enrollment_tls_ca_bundle,
        )

    async def enroll(
        self, request: EnrollmentRequest, *, now: dt.datetime | None = None
    ) -> EnrollmentResponse:
        """Validate an enrollment request and persist a new agent identity."""
        actual_now = _utc_now() if now is None else _as_utc(now)
        try:
            safe_node_name = validate_node_name(request.node_name)
            token = SecretValue(request.token)
            token_hash = sha256_hex(token)
            if self._rate_limiter.is_limited(
                source_address=request.source_address,
                token_hash=token_hash,
                now=actual_now,
            ):
                raise EnrollmentError("rate_limited")
            record = await self._store.consume_enrollment_token(
                token_hash=token_hash,
                node_name=safe_node_name,
                now=actual_now,
            )
            if record is None:
                raise EnrollmentError("invalid_token")
            agent_public_key = _load_agent_public_key(request.agent_x509_public_key)
            agent_id = uuid.uuid4()
            tunnel_secret = generate_tunnel_secret()
            issued_cert = issue_agent_client_certificate(
                ca_private_key=self._agent_ca_private_key,
                ca_certificate=self._agent_ca_certificate,
                agent_public_key=agent_public_key,
                node_name=safe_node_name,
                agent_id=agent_id,
                now=actual_now,
            )
            await self._store.persist_agent(
                StoredAgent(
                    agent_id=agent_id,
                    node_name=safe_node_name,
                    labels=record.labels,
                    x509_public_key=request.agent_x509_public_key,
                    node_ssh_host_public_key=request.node_ssh_host_public_key,
                    tunnel_secret_hash=sha256_hex(tunnel_secret),
                    cert_serial=issued_cert.serial,
                    cert_expires_at=issued_cert.expires_at,
                )
            )
            if self._audit_writer is not None:
                await self._audit_writer.write(
                    event_type=AuditEventType.ENROLLMENT_SUCCEEDED,
                    actor="enrollment-api",
                    agent_id=agent_id,
                    node_name=safe_node_name,
                    metadata={"source_address": request.source_address},
                )
            return EnrollmentResponse(
                agent_id=agent_id,
                agent_x509_cert=issued_cert.certificate_pem.decode("ascii"),
                tunnel_ca_bundle=self._tunnel_ca_bundle,
                tunnel_host=self._tunnel_host,
                tunnel_port=self._tunnel_port,
                tunnel_secret=tunnel_secret,
            )
        except Exception as exc:
            await self._record_enrollment_failure(request, actual_now, exc)
            raise EnrollmentError("enrollment failed") from exc

    async def _record_enrollment_failure(
        self, request: EnrollmentRequest, now: dt.datetime, exc: Exception
    ) -> None:
        token_hash = _best_effort_token_hash(request.token)
        self._rate_limiter.record_failure(
            source_address=request.source_address, token_hash=token_hash, now=now
        )
        if self._audit_writer is not None:
            metadata: Mapping[str, object] = {
                "source_address": request.source_address,
                "reason": exc.__class__.__name__,
                "token_hash": token_hash,
            }
            await self._audit_writer.write(
                event_type=AuditEventType.ENROLLMENT_FAILED,
                actor="enrollment-api",
                node_name=request.node_name,
                metadata=cast(Mapping[str, object], scrub_secret_metadata(metadata)),
            )


async def enroll_handler(request: web.Request) -> web.Response:
    """Handle `POST /enroll` with generic JSON failures."""
    service = request.app["enrollment_service"]
    if not isinstance(service, EnrollmentService):
        raise RuntimeError("enrollment service is not configured")
    body = await request.json()
    if not isinstance(body, Mapping):
        return web.json_response(GENERIC_ENROLLMENT_ERROR, status=400)
    try:
        response = await service.enroll(
            EnrollmentRequest(
                node_name=str(body.get("node_name", "")),
                token=str(body.get("token", "")),
                agent_x509_public_key=str(body.get("agent_x509_public_key", "")),
                node_ssh_host_public_key=str(body.get("node_ssh_host_public_key", "")),
                source_address=request.remote or "unknown",
            )
        )
    except EnrollmentError:
        return web.json_response(GENERIC_ENROLLMENT_ERROR, status=400)
    return web.json_response(response.to_json())


def make_enrollment_app(service: EnrollmentService) -> web.Application:
    """Create an aiohttp app exposing only the enrollment route."""
    app = web.Application()
    app["enrollment_service"] = service
    app.router.add_post("/enroll", enroll_handler)
    return app


def _render_agent_conf(node_name: str, token: SecretValue) -> str:
    return "\n".join(
        [
            "[enrollment]",
            f"node_name = {node_name}",
            f"token = {token.reveal()}",
            "api_url = https://server:4443/enroll",
            "tls_ca_bundle = /etc/vibeconnect/ca.crt",
            "",
            "[tunnel]",
            "server_url = https://server:4444/tunnel",
            "tls_ca_bundle = /etc/vibeconnect/ca.crt",
            "heartbeat_seconds = 30",
            "",
            "[proxy]",
            "target = 127.0.0.1:2222",
            "",
            "[identity]",
            "path = /var/lib/vibeconnect/identity.json",
            "",
        ]
    )


def _load_agent_public_key(public_key_pem: str) -> Ed25519PublicKey:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(public_key, Ed25519PublicKey):
        raise EnrollmentError("agent public key must be Ed25519")
    return public_key


def _labels(value: object) -> tuple[str, ...]:
    loaded = json.loads(value) if isinstance(value, str) else value
    if not isinstance(loaded, Sequence) or isinstance(loaded, (bytes, bytearray, str)):
        raise EnrollmentError("enrollment labels must be an array")
    return tuple(validate_label(str(label)) for label in loaded)


def _best_effort_token_hash(token: str) -> str:
    if not token:
        return "empty"
    return sha256_hex(SecretValue(token))


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)
