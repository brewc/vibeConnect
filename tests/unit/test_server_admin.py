"""Tests for local-only server admin commands and rotation controls."""

from __future__ import annotations

import datetime as dt
import json
import uuid
from collections.abc import Mapping, Sequence

import pytest

from server.admin import (
    AdminError,
    AdminService,
    AgentSummary,
    CreatedAgentPackage,
    RotationState,
    SessionSummary,
    render_agents,
    render_sessions,
)
from vibeconnect_common.audit import AuditWriter
from vibeconnect_common.models import AuditEventType

_NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


@pytest.mark.asyncio
async def test_create_agent_returns_one_time_config_and_audits_hash_only() -> None:
    """Agent creation returns a token once and stores only its hash in audit."""
    store = FakeAdminStore()
    audit = FakeAuditConnection()

    package = await AdminService(
        store=store, audit_writer=AuditWriter(audit)
    ).create_agent(
        node_name="node-01",
        labels=["prod"],
        actor="admin",
        now=_NOW,
    )

    assert isinstance(package, CreatedAgentPackage)
    assert "token =" in package.agent_conf
    raw_token = package.agent_conf.split("token = ", 1)[1].splitlines()[0]
    assert raw_token
    assert store.created_tokens[0]["token_hash"] != raw_token
    metadata = _last_audit_metadata(audit)
    stored_token_hash = store.created_tokens[0]["token_hash"]
    assert isinstance(stored_token_hash, str)
    assert metadata["token_hash"] == "[REDACTED]"
    assert raw_token not in json.dumps(metadata)
    assert stored_token_hash not in json.dumps(metadata)


@pytest.mark.asyncio
async def test_credential_changing_commands_emit_audit_events() -> None:
    """Create, revoke, rotate, expire, and host-key update are audited."""
    store = FakeAdminStore()
    audit = FakeAuditConnection()
    service = AdminService(store=store, audit_writer=AuditWriter(audit))

    await service.create_agent(node_name="node-01", labels=[], actor="admin", now=_NOW)
    await service.revoke_agent(node_name="node-01", actor="admin", now=_NOW)
    await service.rotate_tunnel_secret(node_name="node-01", actor="admin", now=_NOW)
    await service.update_node_host_key(
        node_name="node-01",
        node_ssh_host_public_key="ssh-ed25519 AAAAnewhost",
        actor="admin",
        now=_NOW,
    )
    await service.expire_token(node_name="node-01", actor="admin", now=_NOW)

    event_types = [args[1] for _query, args in audit.executed]
    assert event_types == [
        AuditEventType.ENROLLMENT_TOKEN_CREATED.value,
        AuditEventType.AGENT_REVOKED.value,
        AuditEventType.TUNNEL_SECRET_ROTATED.value,
        AuditEventType.NODE_HOST_KEY_UPDATED.value,
        AuditEventType.ENROLLMENT_TOKEN_EXPIRED.value,
    ]


@pytest.mark.asyncio
async def test_admin_output_does_not_render_stored_secrets() -> None:
    """List output excludes hashes, DSNs, replay paths, and replay payloads."""
    store = FakeAdminStore()
    service = AdminService(store=store, audit_writer=None)

    agents_output = render_agents(await service.list_agents())
    sessions_output = render_sessions(await service.list_sessions())

    combined = agents_output + sessions_output
    assert "tunnel_secret_hash" not in combined
    assert "token_hash" not in combined
    assert "postgresql://" not in combined
    assert ".cast" not in combined
    assert "replay_payload" not in combined


@pytest.mark.asyncio
async def test_rotate_tunnel_secret_never_exposes_raw_secret() -> None:
    """Tunnel rotation stores a new hash and audits a non-secret placeholder."""
    store = FakeAdminStore()
    audit = FakeAuditConnection()

    await AdminService(
        store=store, audit_writer=AuditWriter(audit)
    ).rotate_tunnel_secret(node_name="node-01", actor="admin", now=_NOW)

    assert store.rotated_hashes
    metadata = _last_audit_metadata(audit)
    assert metadata["tunnel_secret"] == "[REDACTED]"
    assert store.rotated_hashes[-1] not in json.dumps(metadata)


@pytest.mark.asyncio
async def test_ca_rotation_requires_overlap_before_start() -> None:
    """A CA rotation cannot start unless old and new CAs are both trusted."""
    service = AdminService(store=FakeAdminStore(), audit_writer=None)

    with pytest.raises(AdminError, match="overlapping"):
        await service.start_ca_rotation(
            key_name="user-ca",
            old_fingerprint="old",
            new_fingerprint="new",
            trusted_fingerprints=["old"],
            actor="admin",
            now=_NOW,
        )


@pytest.mark.asyncio
async def test_ca_rotation_rejects_old_ca_after_completion() -> None:
    """A completed rotation cannot leave old CA material trusted."""
    store = FakeAdminStore()
    service = AdminService(store=store, audit_writer=None)
    rotation_id = await service.start_ca_rotation(
        key_name="user-ca",
        old_fingerprint="old",
        new_fingerprint="new",
        trusted_fingerprints=["old", "new"],
        actor="admin",
        now=_NOW,
    )

    with pytest.raises(AdminError, match="old CA"):
        await service.complete_ca_rotation(
            rotation_id=rotation_id,
            trusted_fingerprints=["old", "new"],
            actor="admin",
            now=_NOW,
        )

    state = await service.complete_ca_rotation(
        rotation_id=rotation_id,
        trusted_fingerprints=["new"],
        actor="admin",
        now=_NOW,
    )
    assert state.status == "completed"


class FakeAdminStore:
    """In-memory admin store for service tests."""

    def __init__(self) -> None:
        """Create deterministic admin state."""
        self.agent_id = uuid.uuid4()
        self.created_tokens: list[dict[str, object]] = []
        self.rotated_hashes: list[str] = []
        self.rotations: dict[uuid.UUID, RotationState] = {}

    async def create_enrollment_token(
        self,
        *,
        token_hash: str,
        node_name: str,
        labels: Sequence[str],
        created_by: str,
        expires_at: dt.datetime,
        now: dt.datetime,
    ) -> None:
        """Record token creation."""
        self.created_tokens.append(
            {
                "token_hash": token_hash,
                "node_name": node_name,
                "labels": tuple(labels),
                "created_by": created_by,
                "expires_at": expires_at,
                "now": now,
            }
        )

    async def list_agents(self) -> tuple[AgentSummary, ...]:
        """Return a row with only display-safe fields."""
        return (
            AgentSummary(
                node_name="node-01",
                hostname="node-01.example.test",
                labels=("prod",),
                enrolled_at=_NOW,
                last_seen=None,
                revoked=False,
            ),
        )

    async def revoke_agent(self, *, node_name: str, now: dt.datetime) -> uuid.UUID:
        """Return the deterministic agent ID."""
        return self.agent_id

    async def rotate_tunnel_secret(
        self, *, node_name: str, tunnel_secret_hash: str, now: dt.datetime
    ) -> uuid.UUID:
        """Record the rotated secret hash."""
        self.rotated_hashes.append(tunnel_secret_hash)
        return self.agent_id

    async def update_node_host_key(
        self, *, node_name: str, node_ssh_host_public_key: str, now: dt.datetime
    ) -> uuid.UUID:
        """Return the deterministic agent ID."""
        return self.agent_id

    async def expire_token(self, *, node_name: str, now: dt.datetime) -> int:
        """Return one expired token."""
        return 1

    async def list_sessions(
        self, *, node_name: str | None = None, user_name: str | None = None
    ) -> tuple[SessionSummary, ...]:
        """Return a row with only display-safe fields."""
        return (
            SessionSummary(
                session_id=uuid.uuid4(),
                node_name="node-01",
                user_name="alice",
                started_at=_NOW,
                ended_at=None,
                status="open",
            ),
        )

    async def start_ca_rotation(
        self,
        *,
        key_name: str,
        old_fingerprint: str,
        new_fingerprint: str,
        trusted_fingerprints: Sequence[str],
        now: dt.datetime,
    ) -> uuid.UUID:
        """Record started rotation state."""
        rotation_id = uuid.uuid4()
        self.rotations[rotation_id] = RotationState(
            key_name=key_name,
            old_fingerprint=old_fingerprint,
            new_fingerprint=new_fingerprint,
            trusted_fingerprints=tuple(trusted_fingerprints),
            status="started",
        )
        return rotation_id

    async def complete_ca_rotation(
        self,
        *,
        rotation_id: uuid.UUID,
        trusted_fingerprints: Sequence[str],
        now: dt.datetime,
    ) -> RotationState:
        """Return completion state with caller-provided trust bundle."""
        state = self.rotations[rotation_id]
        return RotationState(
            key_name=state.key_name,
            old_fingerprint=state.old_fingerprint,
            new_fingerprint=state.new_fingerprint,
            trusted_fingerprints=tuple(trusted_fingerprints),
            status="completed",
        )

    async def get_ca_rotation(self, *, rotation_id: uuid.UUID) -> RotationState:
        """Return active rotation state."""
        return self.rotations[rotation_id]


class FakeAuditConnection:
    """Capture audit inserts."""

    def __init__(self) -> None:
        """Create an empty audit log."""
        self.executed: list[tuple[str, tuple[object, ...]]] = []

    async def execute(self, query: str, *args: object) -> str:
        """Capture an executed audit insert."""
        self.executed.append((query, args))
        return "INSERT 0 1"


def _last_audit_metadata(connection: FakeAuditConnection) -> Mapping[str, object]:
    _query, args = connection.executed[-1]
    metadata = json.loads(str(args[7]))
    assert isinstance(metadata, dict)
    return metadata
