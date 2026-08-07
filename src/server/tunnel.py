"""Server-side tunnel authentication and session state."""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Protocol

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vibeconnect_common.crypto import (
    SecretValue,
    issue_agent_client_certificate,
    verify_secret_hash,
)
from vibeconnect_common.models import TunnelFrameType

TUNNEL_AUTH_TIMEOUT_SECONDS = 10


class TunnelAuthError(PermissionError):
    """Raised when tunnel authentication fails closed."""


class TunnelStateError(RuntimeError):
    """Raised when tunnel session state is invalid."""


@dataclass(frozen=True, slots=True)
class AgentTunnelRecord:
    """Stored agent state required to authenticate a tunnel."""

    agent_id: uuid.UUID
    node_name: str
    x509_public_key: str
    tunnel_secret_hash: str
    cert_serial: str
    cert_expires_at: dt.datetime
    revoked_at: dt.datetime | None = None


@dataclass(frozen=True, slots=True)
class TunnelAuthRequest:
    """Agent-provided values from mTLS and the initial auth frame."""

    agent_id: uuid.UUID
    node_name: str
    cert_serial: str
    cert_public_key: str
    tunnel_secret: str


@dataclass(frozen=True, slots=True)
class RenewedAgentCertificate:
    """Certificate renewal result persisted for an agent."""

    public_key_pem: str
    certificate_pem: str
    cert_serial: str
    cert_expires_at: dt.datetime


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


class InMemoryAgentTunnelStore:
    """Lock-free in-memory store for unit tests and early wiring."""

    def __init__(self, records: Mapping[uuid.UUID, AgentTunnelRecord]) -> None:
        """Initialize from known records."""
        self.records = dict(records)

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
        if not verify_secret_hash(
            SecretValue(request.tunnel_secret), record.tunnel_secret_hash
        ):
            raise TunnelAuthError("tunnel secret mismatch")
        return record


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


def _load_ed25519_public_key(public_key_pem: str) -> Ed25519PublicKey:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(public_key, Ed25519PublicKey):
        raise TunnelAuthError("agent public key must be Ed25519")
    return public_key


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)
