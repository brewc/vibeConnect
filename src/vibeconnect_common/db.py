"""PostgreSQL connection helpers and schema migration runner."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Protocol, cast

import asyncpg  # type: ignore[import-untyped]

MIGRATION_FILENAME_RE = re.compile(
    r"^(?P<version>\d{3})(?:_[a-z0-9]+(?:_[a-z0-9]+)*)?$"
)


class MigrationError(RuntimeError):
    """Raised when database migrations cannot be applied safely."""


class TransactionLike(Protocol):
    """Async context manager returned by a database transaction."""

    async def __aenter__(self) -> TransactionLike:
        """Enter the database transaction."""

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Exit the database transaction."""


class ConnectionLike(Protocol):
    """Small asyncpg-compatible connection surface used by migrations."""

    def transaction(self) -> TransactionLike:
        """Create a transaction context manager."""

    async def execute(self, query: str, *args: object) -> str:
        """Execute a SQL statement."""

    async def fetch(self, query: str, *args: object) -> Sequence[Mapping[str, object]]:
        """Fetch rows from the database."""


@dataclass(frozen=True, slots=True)
class Migration:
    """A single versioned SQL migration."""

    version: int
    path: Path
    sql: str


SCHEMA_MIGRATIONS_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
)
"""


async def connect(dsn: str) -> ConnectionLike:
    """Open an asyncpg connection."""
    return cast(ConnectionLike, await asyncpg.connect(dsn))


def transaction(connection: ConnectionLike) -> TransactionLike:
    """Return a transaction context manager for a connection."""
    return connection.transaction()


def load_migrations(directory: Path) -> list[Migration]:
    """Load `NNN_name.sql` files from a directory in ascending version order."""
    migrations: list[Migration] = []
    seen_versions: set[int] = set()
    for path in sorted(directory.glob("*.sql")):
        version = _parse_migration_version(path)
        if version in seen_versions:
            raise MigrationError(f"duplicate migration version: {version}")
        seen_versions.add(version)
        migrations.append(Migration(version=version, path=path, sql=path.read_text()))
    return sorted(migrations, key=lambda migration: migration.version)


async def run_migrations(
    connection: ConnectionLike, migrations: Sequence[Migration]
) -> None:
    """Apply pending migrations after validating existing migration state."""
    expected_versions = [migration.version for migration in migrations]
    await connection.execute(SCHEMA_MIGRATIONS_SQL)
    applied_versions = await _fetch_applied_versions(connection)
    _validate_applied_versions(applied_versions, expected_versions)

    applied = set(applied_versions)
    for migration in migrations:
        if migration.version in applied:
            continue
        async with transaction(connection):
            await connection.execute(migration.sql)
            await connection.execute(
                "INSERT INTO schema_migrations(version) VALUES($1)",
                migration.version,
            )


def _parse_migration_version(path: Path) -> int:
    match = MIGRATION_FILENAME_RE.match(path.stem)
    if match is None:
        raise MigrationError(f"invalid migration filename: {path.name}")
    return int(match.group("version"))


async def _fetch_applied_versions(connection: ConnectionLike) -> list[int]:
    rows = await connection.fetch(
        "SELECT version FROM schema_migrations ORDER BY version"
    )
    versions: list[int] = []
    for row in rows:
        version = row["version"]
        if not isinstance(version, int):
            raise MigrationError("schema_migrations.version must be an integer")
        versions.append(version)
    return versions


def _validate_applied_versions(
    applied_versions: Sequence[int], expected_versions: Sequence[int]
) -> None:
    if len(set(applied_versions)) != len(applied_versions):
        raise MigrationError("schema_migrations contains duplicate versions")
    if list(applied_versions) != sorted(applied_versions):
        raise MigrationError("schema_migrations is out of order")

    expected_applied = list(expected_versions[: len(applied_versions)])
    if list(applied_versions) != expected_applied:
        raise MigrationError("schema_migrations is partial or out of order")
