"""Tests for database schema and migration execution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from types import TracebackType

import pytest

from vibeconnect_common.db import (
    Migration,
    MigrationError,
    load_migrations,
    run_migrations,
)

MIGRATION_SQL = Path("src/migrations/001_initial_schema.sql").read_text()
ALPHA_USER_MIGRATION_SQL = Path(
    "src/migrations/002_seed_alpha_admin_user.sql"
).read_text()


class FakeTransaction:
    """Transaction context manager that records transaction boundaries."""

    def __init__(self, connection: FakeConnection) -> None:
        """Store the connection receiving transaction events."""
        self._connection = connection

    async def __aenter__(self) -> FakeTransaction:
        """Record transaction start."""
        self._connection.events.append("begin")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Record transaction end."""
        self._connection.events.append("rollback" if exc_type else "commit")
        return None


class FakeConnection:
    """Minimal connection fake for migration runner tests."""

    def __init__(self, applied_versions: Sequence[int] = ()) -> None:
        """Create the fake with already-applied migration versions."""
        self.applied_versions = list(applied_versions)
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.events: list[str] = []

    def transaction(self) -> FakeTransaction:
        """Return a transaction recorder."""
        return FakeTransaction(self)

    async def execute(self, query: str, *args: object) -> str:
        """Record executed SQL and simulate schema_migrations inserts."""
        self.executed.append((query, args))
        if query.startswith("INSERT INTO schema_migrations"):
            version = args[0]
            if isinstance(version, int):
                self.applied_versions.append(version)
        return "OK"

    async def fetch(self, query: str, *args: object) -> Sequence[Mapping[str, object]]:
        """Return applied migration rows."""
        self.executed.append((query, args))
        return [{"version": version} for version in self.applied_versions]


def test_schema_defines_required_tables() -> None:
    """The initial migration creates the core schema tables."""
    for table_name in (
        "schema_migrations",
        "agents",
        "enrollment_tokens",
        "sessions",
        "audit_events",
        "key_rotation_events",
    ):
        assert f"CREATE TABLE {table_name}" in MIGRATION_SQL


def test_schema_enforces_security_constraints() -> None:
    """The initial migration includes required security-sensitive constraints."""
    assert "CREATE SEQUENCE user_cert_serials AS bigint" in MIGRATION_SQL
    assert "DEFAULT nextval('user_cert_serials')" in MIGRATION_SQL
    assert "sessions_user_cert_serial_unique UNIQUE (user_cert_serial)" in MIGRATION_SQL
    assert "cert_serial text NOT NULL UNIQUE" in MIGRATION_SQL
    assert "revoked boolean NOT NULL DEFAULT false" in MIGRATION_SQL
    assert "status IN ('open', 'closed', 'failed', 'terminated')" in MIGRATION_SQL
    assert (
        "status IN ('started', 'completed', 'failed', 'rolled_back')" in MIGRATION_SQL
    )
    assert "CONSTRAINT agents_labels_array CHECK" in MIGRATION_SQL


def test_schema_rejects_duplicate_active_enrollment_tokens() -> None:
    """A partial unique index prevents duplicate active node enrollment tokens."""
    assert "CREATE UNIQUE INDEX enrollment_tokens_one_active_per_node" in MIGRATION_SQL
    assert "ON enrollment_tokens(node_name)" in MIGRATION_SQL
    assert "WHERE used = false AND disabled_at IS NULL" in MIGRATION_SQL


def test_schema_defines_required_indexes() -> None:
    """The initial migration creates the indexes required by SPEC.md."""
    for index_name in (
        "agents_node_name_idx",
        "agents_last_seen_idx",
        "enrollment_tokens_expires_at_idx",
        "sessions_agent_id_idx",
    ):
        assert f"CREATE INDEX {index_name}" in MIGRATION_SQL


def test_alpha_admin_seed_uses_hashed_password() -> None:
    """The alpha admin seed is local-only and does not store plaintext passwords."""
    assert "CREATE TABLE alpha_users" in ALPHA_USER_MIGRATION_SQL
    assert "username text PRIMARY KEY" in ALPHA_USER_MIGRATION_SQL
    assert "password_hash text NOT NULL" in ALPHA_USER_MIGRATION_SQL
    assert "'admin'" in ALPHA_USER_MIGRATION_SQL
    assert (
        "'sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'"
        in ALPHA_USER_MIGRATION_SQL
    )
    assert "ON CONFLICT (username) DO NOTHING" in ALPHA_USER_MIGRATION_SQL
    assert "'password'" not in ALPHA_USER_MIGRATION_SQL


def test_load_migrations_accepts_descriptive_names(tmp_path: Path) -> None:
    """Descriptive suffixes keep migration files readable without losing order."""
    (tmp_path / "002_add_replay_indexes.sql").write_text("SELECT 2")
    (tmp_path / "001_initial_schema.sql").write_text("SELECT 1")

    migrations = load_migrations(tmp_path)

    assert [migration.version for migration in migrations] == [1, 2]
    assert [migration.path.name for migration in migrations] == [
        "001_initial_schema.sql",
        "002_add_replay_indexes.sql",
    ]


def test_load_migrations_rejects_ambiguous_names(tmp_path: Path) -> None:
    """Migration names must keep a numeric prefix and lowercase slug."""
    (tmp_path / "initial_schema.sql").write_text("SELECT 1")

    with pytest.raises(MigrationError, match="invalid migration filename"):
        load_migrations(tmp_path)


@pytest.mark.asyncio
async def test_migration_runner_is_idempotent() -> None:
    """Already-applied migrations are skipped on later runs."""
    connection = FakeConnection()
    migration = Migration(
        version=1, path=Path("001_initial_schema.sql"), sql="SELECT 1"
    )

    await run_migrations(connection, [migration])
    await run_migrations(connection, [migration])

    migration_statements = [
        query for query, _args in connection.executed if query == migration.sql
    ]
    assert migration_statements == [migration.sql]
    assert connection.events == ["begin", "commit"]


@pytest.mark.asyncio
async def test_migration_runner_rejects_out_of_order_state() -> None:
    """A recorded version cannot skip an earlier available migration."""
    connection = FakeConnection(applied_versions=[2])
    migrations = [
        Migration(version=1, path=Path("001_initial_schema.sql"), sql="SELECT 1"),
        Migration(version=2, path=Path("002_next_change.sql"), sql="SELECT 2"),
    ]

    with pytest.raises(MigrationError, match="partial or out of order"):
        await run_migrations(connection, migrations)


@pytest.mark.asyncio
async def test_migration_runner_rejects_partial_state() -> None:
    """A gap in recorded versions fails startup."""
    connection = FakeConnection(applied_versions=[1, 3])
    migrations = [
        Migration(version=1, path=Path("001_initial_schema.sql"), sql="SELECT 1"),
        Migration(version=2, path=Path("002_next_change.sql"), sql="SELECT 2"),
        Migration(version=3, path=Path("003_later_change.sql"), sql="SELECT 3"),
    ]

    with pytest.raises(MigrationError, match="partial or out of order"):
        await run_migrations(connection, migrations)
