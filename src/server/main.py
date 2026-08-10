"""Command-line entry point for the VibeConnect server."""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
import shlex
import ssl
import subprocess
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

import asyncpg  # type: ignore[import-untyped]
import asyncssh
import yaml
from aiohttp import web
from cryptography import x509

from server.admin import (
    AdminConnection,
    AdminError,
    AdminService,
    PostgresAdminStore,
    render_agents,
    render_sessions,
)
from server.auth import (
    AuthError,
    NodeInventoryEntry,
    ResolvedIdentity,
    resolve_file_public_key_identity,
)
from server.enrollment import (
    EnrollmentConnection,
    EnrollmentService,
    PostgresEnrollmentStore,
    make_enrollment_app,
)
from server.health import HealthSnapshot, build_health_app
from server.jump import (
    AsyncSshNodeTunnelOpener,
    JumpConnection,
    PostgresJumpStore,
    ServerJumpCoordinator,
)
from server.ssh import (
    RestrictedShellJumpHandler,
    RestrictedShellSession,
    SshIdentityResolver,
    VibeConnectSshServer,
    start_asyncssh_server,
)
from server.tunnel import (
    AgentTunnelConnection,
    PostgresAgentTunnelStore,
    ServerTunnelBroker,
    TunnelAuthenticator,
    build_tunnel_server_ssl_context,
    start_tunnel_listener,
)
from vibeconnect_common.audit import AuditConnection, AuditWriter
from vibeconnect_common.config import (
    ConfigError,
    load_server_config,
    validate_server_config,
)
from vibeconnect_common.crypto import (
    IssuedUserCertificate,
    issue_user_ssh_certificate,
    load_ed25519_private_key,
)
from vibeconnect_common.db import (
    ConnectionLike,
    connect,
    load_migrations,
    run_migrations,
)
from vibeconnect_common.identifiers import (
    validate_label,
    validate_node_name,
    validate_username_principal,
)
from vibeconnect_common.models import ServerConfig, SessionStatus
from vibeconnect_common.replay import ReplayWriter

DEFAULT_MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"


@dataclass(frozen=True, slots=True)
class ServerRuntimeSettings:
    """Runtime listener and database settings loaded from YAML."""

    postgres_dsn: str
    ssh_listen: tuple[str, int]
    tunnel_listen: tuple[str, int]
    api_listen: tuple[str, int]
    metrics_listen: tuple[str, int]
    tunnel_public_host: str
    ssh_host_key_path: Path
    tls_cert_path: Path
    tls_key_path: Path


def main(argv: list[str] | None = None) -> int:
    """Run the server CLI.

    Args:
        argv: Optional argument list for tests.

    Returns:
        Process exit status.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        return 0
    if args.command == "start":
        try:
            asyncio.run(_run_server_start(config_path=args.config))
        except (
            ConfigError,
            OSError,
            RuntimeError,
            asyncpg.PostgresError,
        ) as exc:
            print(f"server start failed: {exc}", file=sys.stderr)
            return 1
        return 0
    if args.command == "migrate":
        dsn = args.postgres_dsn or os.environ.get("VIBECONNECT_POSTGRES_DSN")
        if not dsn:
            parser.error("migrate requires --postgres-dsn or VIBECONNECT_POSTGRES_DSN")
        try:
            asyncio.run(_run_migrations(dsn=dsn, migrations_dir=args.migrations_dir))
        except (OSError, asyncpg.PostgresError) as exc:
            print(f"migration failed: {exc}", file=sys.stderr)
            return 1
        return 0
    if args.command == "connect-agent":
        try:
            command = _build_connect_command(args)
        except ValueError as exc:
            parser.error(str(exc))
        if args.dry_run:
            print(_render_shell_command(command))
            return 0
        try:
            return _run_connect_command(command)
        except OSError as exc:
            print(f"connect command failed: {exc}", file=sys.stderr)
            return 1
    dsn = args.postgres_dsn or os.environ.get("VIBECONNECT_POSTGRES_DSN")
    if not dsn:
        parser.error(
            f"{args.command} requires --postgres-dsn or VIBECONNECT_POSTGRES_DSN"
        )
    try:
        output = asyncio.run(_run_admin_command(dsn=dsn, args=args))
    except (AdminError, OSError, asyncpg.PostgresError) as exc:
        print(f"admin command failed: {exc}", file=sys.stderr)
        return 1
    if output:
        print(output)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vibeconnect-server")
    subcommands = parser.add_subparsers(dest="command")
    start = subcommands.add_parser("start")
    start.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/vibeconnectd/config.yaml"),
    )
    migrate = subcommands.add_parser("migrate")
    migrate.add_argument("--postgres-dsn")
    migrate.add_argument(
        "--migrations-dir",
        type=Path,
        default=DEFAULT_MIGRATIONS_DIR,
    )
    connect_agent = subcommands.add_parser("connect-agent")
    connect_agent.add_argument("--server", required=True)
    connect_agent.add_argument("--node-name", required=True)
    connect_agent.add_argument("--user")
    connect_agent.add_argument("--port", type=int, default=22)
    connect_agent.add_argument("--identity-file", type=Path)
    connect_agent.add_argument("--dry-run", action="store_true")
    for command in (
        "create-agent",
        "list-agents",
        "revoke-agent",
        "rotate-tunnel-secret",
        "update-node-host-key",
        "expire-token",
        "list-sessions",
    ):
        admin = subcommands.add_parser(command)
        admin.add_argument("--postgres-dsn")
        admin.add_argument("--actor", default="local-admin")
        if command in {
            "create-agent",
            "revoke-agent",
            "rotate-tunnel-secret",
            "update-node-host-key",
            "expire-token",
        }:
            admin.add_argument("--node-name", required=True)
        if command == "create-agent":
            admin.add_argument("--label", action="append", default=[])
        if command == "update-node-host-key":
            admin.add_argument("--host-key-file", type=Path, required=True)
        if command == "list-sessions":
            admin.add_argument("--node-name")
            admin.add_argument("--user")
    return parser


def _build_connect_command(args: argparse.Namespace) -> tuple[str, ...]:
    """Build an OpenSSH command for connecting through the bastion."""
    node_name = validate_node_name(args.node_name)
    server = _validate_ssh_target_part(args.server, "server")
    user = validate_username_principal(args.user) if args.user is not None else None
    port = int(args.port)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    target = server if user is None else f"{user}@{server}"
    command = [
        "ssh",
        "-p",
        str(port),
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
    ]
    if args.identity_file is not None:
        command.extend(("-i", str(args.identity_file)))
    command.extend((target, node_name))
    return tuple(command)


def _validate_ssh_target_part(value: str, field: str) -> str:
    """Reject SSH target fields that could be parsed as options."""
    if not value or value.startswith("-") or any(char.isspace() for char in value):
        raise ValueError(f"invalid {field}")
    return value


def _render_shell_command(command: Sequence[str]) -> str:
    """Render a command safely for copy/paste and dry-run output."""
    return " ".join(shlex.quote(part) for part in command)


def _run_connect_command(command: Sequence[str]) -> int:
    """Execute the OpenSSH command."""
    return subprocess.run(list(command), check=False).returncode


async def _run_migrations(*, dsn: str, migrations_dir: Path) -> None:
    connection = await connect(dsn)
    await run_migrations(connection, load_migrations(migrations_dir))


async def _run_server_start(*, config_path: Path) -> None:
    config = load_server_config(config_path)
    validate_server_config(config)
    settings = _load_runtime_settings(config_path)
    await _run_server_runtime(config=config, settings=settings)


async def _run_server_runtime(
    *, config: ServerConfig, settings: ServerRuntimeSettings
) -> None:
    pool = await asyncpg.create_pool(settings.postgres_dsn)
    if pool is None:
        raise RuntimeError("database pool was not created")
    listeners: list[object] = []
    enrollment_runner: web.AppRunner | None = None
    metrics_runner: web.AppRunner | None = None
    try:
        async with pool.acquire() as connection:
            await run_migrations(
                cast(ConnectionLike, connection),
                load_migrations(DEFAULT_MIGRATIONS_DIR),
            )
        agent_ca_key = load_ed25519_private_key(config.certs.agent_ca_key_path)
        agent_ca_cert = x509.load_pem_x509_certificate(
            config.certs.agent_ca_cert_path.read_bytes()
        )
        broker = ServerTunnelBroker(
            authenticator=TunnelAuthenticator(
                PostgresAgentTunnelStore(cast(AgentTunnelConnection, pool))
            ),
            max_sessions_per_agent=config.tunnel.max_sessions_per_agent,
            heartbeat_seconds=config.tunnel.heartbeat_seconds,
            max_frame_bytes=config.tunnel.frame_max_bytes,
        )
        tunnel_ssl = build_tunnel_server_ssl_context(
            cert_path=str(settings.tls_cert_path),
            key_path=str(settings.tls_key_path),
            ca_bundle_path=str(config.tunnel.tls_ca_bundle),
        )
        listeners.append(
            await start_tunnel_listener(
                host=settings.tunnel_listen[0],
                port=settings.tunnel_listen[1],
                broker=broker,
                ssl_context=tunnel_ssl,
            )
        )
        enrollment_service = EnrollmentService(
            store=PostgresEnrollmentStore(cast(EnrollmentConnection, pool)),
            agent_ca_private_key=agent_ca_key,
            agent_ca_certificate=agent_ca_cert,
            tunnel_ca_bundle=config.tunnel.tls_ca_bundle.read_text(encoding="utf-8"),
            tunnel_host=settings.tunnel_public_host,
            tunnel_port=settings.tunnel_listen[1],
            enrollment_tls_ca_bundle=settings.tls_cert_path.read_text(encoding="utf-8"),
            audit_writer=AuditWriter(cast(AuditConnection, pool)),
        )
        enrollment_runner = await _start_aiohttp_site(
            app=make_enrollment_app(enrollment_service),
            host=settings.api_listen[0],
            port=settings.api_listen[1],
            ssl_context=_build_https_server_ssl_context(
                cert_path=settings.tls_cert_path,
                key_path=settings.tls_key_path,
            ),
        )
        audit_writer = AuditWriter(cast(AuditConnection, pool))
        jump_store = PostgresJumpStore(
            cast(JumpConnection, pool),
            heartbeat_seconds=config.tunnel.heartbeat_seconds,
        )
        user_certificate_issuer = _RuntimeUserCertificateIssuer(
            user_ca_key_path=config.certs.user_ca_key_path,
            ttl_hours=config.certs.user_cert_ttl_hours,
        )
        replay_writer = ReplayWriter(
            directory=config.replay.directory,
            integrity_key=config.replay.integrity_key_path.read_bytes(),
            session_store=_NoopReplaySessionStore(),
            audit_sink=None,
        )
        jump_coordinator = ServerJumpCoordinator(
            store=jump_store,
            replay_starter=replay_writer,
            certificate_issuer=user_certificate_issuer,
            tunnel_opener=AsyncSshNodeTunnelOpener(connector_resolver=broker),
            audit_sink=audit_writer,
        )
        node_store = _PostgresNodeInventoryStore(cast(_NodeInventoryConnection, pool))
        identity_resolver = _build_identity_resolver(config)
        metrics_runner = await _start_aiohttp_site(
            app=build_health_app(
                HealthSnapshot(
                    database_ready=True,
                    replay_ready=config.replay.directory.is_dir(),
                    tunnel_ready=True,
                    live_tunnels=0,
                    active_sessions=0,
                    failed_enrollments=0,
                    failed_logins=0,
                    issued_certificates=0,
                    replay_write_failures=0,
                    auth_provider_failures=0,
                )
            ),
            host=settings.metrics_listen[0],
            port=settings.metrics_listen[1],
            ssl_context=None,
        )
        listeners.append(
            await start_asyncssh_server(
                host=settings.ssh_listen[0],
                port=settings.ssh_listen[1],
                server_host_keys=[settings.ssh_host_key_path],
                server_factory=lambda: VibeConnectSshServer(
                    identity_resolver=identity_resolver,
                    session_factory=lambda server: RestrictedShellSession(
                        server=server,
                        audit_sink=audit_writer,
                        session_state_store=jump_store,
                        clock=_utc_now,
                        handler_factory=lambda ssh_server: RestrictedShellJumpHandler(
                            server=ssh_server,
                            node_authorizer=node_store,
                            host_key_lookup=node_store,
                            jump_coordinator=jump_coordinator,
                            clock=_utc_now,
                        ),
                    ),
                ),
            )
        )
        await asyncio.Event().wait()
    finally:
        for listener in listeners:
            close = getattr(listener, "close", None)
            wait_closed = getattr(listener, "wait_closed", None)
            if callable(close):
                close()
            if callable(wait_closed):
                await wait_closed()
        if enrollment_runner is not None:
            await enrollment_runner.cleanup()
        if metrics_runner is not None:
            await metrics_runner.cleanup()
        await pool.close()


async def _run_admin_command(*, dsn: str, args: argparse.Namespace) -> str:
    connection = await connect(dsn)
    service = AdminService(
        store=PostgresAdminStore(cast(AdminConnection, connection)),
        audit_writer=AuditWriter(connection),
    )
    if args.command == "create-agent":
        package = await service.create_agent(
            node_name=args.node_name,
            labels=args.label,
            actor=args.actor,
        )
        return package.agent_conf
    if args.command == "list-agents":
        return render_agents(await service.list_agents())
    if args.command == "revoke-agent":
        await service.revoke_agent(node_name=args.node_name, actor=args.actor)
        return f"revoked {args.node_name}"
    if args.command == "rotate-tunnel-secret":
        await service.rotate_tunnel_secret(node_name=args.node_name, actor=args.actor)
        return f"rotated tunnel secret for {args.node_name}; secret not printed"
    if args.command == "update-node-host-key":
        host_key = args.host_key_file.read_text(encoding="utf-8").strip()
        await service.update_node_host_key(
            node_name=args.node_name,
            node_ssh_host_public_key=host_key,
            actor=args.actor,
        )
        return f"updated node host key for {args.node_name}"
    if args.command == "expire-token":
        expired = await service.expire_token(node_name=args.node_name, actor=args.actor)
        return f"expired {expired} active token(s) for {args.node_name}"
    if args.command == "list-sessions":
        return render_sessions(
            await service.list_sessions(node_name=args.node_name, user_name=args.user)
        )
    raise AssertionError(f"unhandled admin command: {args.command}")


class _FailClosedIdentityResolver:
    """Deny SSH auth until a production auth provider is configured."""

    async def resolve_public_key(
        self,
        *,
        username: str,
        public_key: str,
    ) -> ResolvedIdentity:
        """Deny every public key authentication request."""
        raise AuthError("SSH identity resolver is not configured")


class _FilePublicKeyIdentityResolver:
    """Resolve public-key SSH identities from a local YAML file."""

    def __init__(self, path: Path) -> None:
        """Configure the authorized-key mapping path."""
        self._path = path

    async def resolve_public_key(
        self,
        *,
        username: str,
        public_key: str,
    ) -> ResolvedIdentity:
        """Resolve one presented SSH public key."""
        entries = _load_authorized_key_entries(self._path)
        key_map = {entry.username: entry.public_keys for entry in entries}
        identity = resolve_file_public_key_identity(
            login_username=username,
            presented_public_key=public_key,
            authorized_keys=key_map,
        )
        groups = next(
            (entry.groups for entry in entries if entry.username == identity.username),
            frozenset(),
        )
        return ResolvedIdentity(
            username=identity.username,
            public_key=identity.public_key,
            groups=groups,
        )


@dataclass(frozen=True, slots=True)
class _AuthorizedKeyEntry:
    username: str
    public_keys: tuple[str, ...]
    groups: frozenset[str]


class _NodeInventoryConnection(Protocol):
    async def fetch(self, query: str, *args: object) -> Sequence[Mapping[str, object]]:
        """Execute a statement and return rows."""

    async def fetchrow(self, query: str, *args: object) -> Mapping[str, object] | None:
        """Execute a statement and return one row."""


class _PostgresNodeInventoryStore:
    """Read authorized node labels and pinned host keys from Postgres."""

    def __init__(self, connection: _NodeInventoryConnection) -> None:
        """Configure database access."""
        self._connection = connection

    async def visible_nodes(
        self,
        *,
        identity: ResolvedIdentity,
    ) -> tuple[NodeInventoryEntry, ...]:
        """Return unrevoked nodes whose labels intersect identity groups."""
        if not identity.groups:
            return ()
        rows = await self._connection.fetch(
            """
            SELECT node_name, labels
              FROM agents
             WHERE revoked = false
            """
        )
        nodes: list[NodeInventoryEntry] = []
        for row in rows:
            labels = _row_labels(row["labels"])
            if labels & identity.groups:
                nodes.append(
                    NodeInventoryEntry(
                        node_name=validate_node_name(str(row["node_name"])),
                        labels=labels,
                    )
                )
        return tuple(sorted(nodes, key=lambda node: node.node_name))

    async def presented_host_key(self, *, node_name: str) -> str | None:
        """Return the pinned node host key for one unrevoked node."""
        row = await self._connection.fetchrow(
            """
            SELECT node_ssh_host_public_key
              FROM agents
             WHERE node_name = $1
               AND revoked = false
            """,
            validate_node_name(node_name),
        )
        if row is None:
            return None
        return str(row["node_ssh_host_public_key"])


class _RuntimeUserCertificateIssuer:
    """Issue short-lived OpenSSH user certificates from the configured CA key."""

    def __init__(self, *, user_ca_key_path: Path, ttl_hours: int) -> None:
        """Load the user CA private key once during server bootstrap."""
        self._user_ca_key = asyncssh.read_private_key(str(user_ca_key_path))
        self._ttl_hours = ttl_hours

    def issue(
        self,
        *,
        username: str,
        session_id: uuid.UUID,
        serial: int,
        now: dt.datetime,
    ) -> IssuedUserCertificate:
        """Issue one principal-bound user certificate."""
        return issue_user_ssh_certificate(
            user_ca_key=self._user_ca_key,
            username=username,
            session_id=session_id,
            serial=serial,
            now=now,
            ttl_hours=self._ttl_hours,
        )


class _NoopReplaySessionStore:
    """Replay session store used when async DB close is handled elsewhere."""

    def close_session(
        self,
        *,
        session_id: uuid.UUID,
        status: SessionStatus,
        ended_at: dt.datetime,
        replay_path: Path,
        replay_hmac: str | None,
    ) -> None:
        """No-op close hook for synchronous replay recorder callbacks."""

    def prune_replay_pointer(self, *, session_id: uuid.UUID) -> None:
        """No-op prune hook for runtime replay writer."""


def _build_identity_resolver(config: ServerConfig) -> SshIdentityResolver:
    public_keys = config.auth.public_keys
    if public_keys.source != "file" or public_keys.file_path is None:
        return _FailClosedIdentityResolver()
    return _FilePublicKeyIdentityResolver(public_keys.file_path)


def _load_authorized_key_entries(path: Path) -> tuple[_AuthorizedKeyEntry, ...]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise AuthError("authorized-keys file is invalid YAML") from exc
    if not isinstance(raw, Mapping):
        raise AuthError("authorized-keys file must be a mapping")
    users = raw.get("users", raw)
    if not isinstance(users, Mapping):
        raise AuthError("authorized-keys users must be a mapping")
    entries: list[_AuthorizedKeyEntry] = []
    for username, value in users.items():
        safe_username = validate_username_principal(str(username))
        public_keys, groups = _authorized_key_value(value)
        entries.append(
            _AuthorizedKeyEntry(
                username=safe_username,
                public_keys=public_keys,
                groups=groups,
            )
        )
    return tuple(entries)


def _authorized_key_value(value: object) -> tuple[tuple[str, ...], frozenset[str]]:
    if isinstance(value, Sequence) and not isinstance(value, str):
        public_keys = tuple(str(item) for item in value)
        groups = frozenset[str]()
    elif isinstance(value, Mapping):
        key_values = value.get("public_keys")
        if not isinstance(key_values, Sequence) or isinstance(key_values, str):
            raise AuthError("authorized-key public_keys must be a list")
        public_keys = tuple(str(item) for item in key_values)
        group_values = value.get("groups", ())
        if not isinstance(group_values, Sequence) or isinstance(group_values, str):
            raise AuthError("authorized-key groups must be a list")
        groups = frozenset(validate_label(str(group)) for group in group_values)
    else:
        raise AuthError("authorized-key entry must be a list or mapping")
    if not public_keys:
        raise AuthError("authorized-key entry must include at least one public key")
    return public_keys, groups


def _row_labels(value: object) -> frozenset[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise AuthError("agent labels must be valid JSON") from exc
    if not isinstance(value, Sequence) or isinstance(value, str):
        raise AuthError("agent labels must be a list")
    return frozenset(validate_label(str(label)) for label in value)


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


async def _start_aiohttp_site(
    *,
    app: web.Application,
    host: str,
    port: int,
    ssl_context: ssl.SSLContext | None,
) -> web.AppRunner:
    if not host:
        raise ConfigError("HTTP listener host is required")
    if not 1 <= port <= 65535:
        raise ConfigError("HTTP listener port is outside valid TCP bounds")
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host=host, port=port, ssl_context=ssl_context)
    await site.start()
    return runner


def _build_https_server_ssl_context(
    *, cert_path: Path, key_path: Path
) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context


def _load_runtime_settings(path: Path) -> ServerRuntimeSettings:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError("server config YAML is invalid") from exc
    if not isinstance(raw, dict):
        raise ConfigError("server config must be a YAML mapping")
    server = _runtime_mapping(raw, "server")
    postgres = _runtime_mapping(raw, "postgres")
    return ServerRuntimeSettings(
        postgres_dsn=_postgres_dsn(postgres),
        ssh_listen=_host_port(str(server.get("listen_ssh", "0.0.0.0:22"))),
        tunnel_listen=_host_port(str(server.get("listen_tunnel", "0.0.0.0:12345"))),
        api_listen=_host_port(str(server.get("listen_api", "0.0.0.0:4443"))),
        metrics_listen=_host_port(
            str(_runtime_mapping(raw, "metrics").get("listen", "127.0.0.1:9100"))
        ),
        tunnel_public_host=str(server.get("tunnel_public_host", "localhost")),
        ssh_host_key_path=_runtime_path(server, "ssh_host_key_path"),
        tls_cert_path=_runtime_path(server, "tls_cert_path"),
        tls_key_path=_runtime_path(server, "tls_key_path"),
    )


def _postgres_dsn(postgres: dict[str, object]) -> str:
    dsn = postgres.get("dsn")
    if isinstance(dsn, str) and dsn:
        return dsn
    dsn_env = postgres.get("dsn_env")
    if isinstance(dsn_env, str) and dsn_env:
        env_value = os.environ.get(dsn_env)
        if env_value:
            return env_value
        raise ConfigError(f"{dsn_env} is not set")
    raise ConfigError("postgres.dsn or postgres.dsn_env is required")


def _runtime_mapping(raw: dict[str, object], key: str) -> dict[str, object]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"{key} section is required")
    return value


def _runtime_path(mapping: dict[str, object], key: str) -> Path:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"server.{key} is required")
    return Path(value).expanduser()


def _host_port(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text.isdigit():
        raise ConfigError("listener value must be host:port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ConfigError("listener port is outside valid TCP bounds")
    return host, port


if __name__ == "__main__":
    raise SystemExit(main())
