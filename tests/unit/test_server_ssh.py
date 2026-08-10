"""Tests for the user-facing AsyncSSH server boundary."""

from __future__ import annotations

import asyncio
import datetime as dt
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

import asyncssh
import pytest

from server.auth import AuthError, NodeInventoryEntry, ResolvedIdentity
from server.jump import JumpSession, JumpTarget, ServerJumpCoordinator
from server.ssh import (
    AsyncSshListener,
    RestrictedShellJumpHandler,
    RestrictedShellSession,
    SshServerError,
    VibeConnectSshServer,
    start_asyncssh_server,
)
from server.tunnel import HeartbeatState
from vibeconnect_common.crypto import IssuedUserCertificate
from vibeconnect_common.models import AuditEventType
from vibeconnect_common.replay import ReplayRecorder

_NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


@pytest.mark.asyncio
async def test_start_asyncssh_server_requires_host_key_and_valid_port() -> None:
    """The SSH listener fails closed without a host key or valid TCP port."""
    with pytest.raises(SshServerError, match="host key"):
        await start_asyncssh_server(
            host="0.0.0.0",
            port=22,
            server_host_keys=(),
            server_factory=lambda: VibeConnectSshServer(
                identity_resolver=FakeIdentityResolver(),
            ),
            listen=FakeAsyncSshListen(),
        )
    with pytest.raises(SshServerError, match="port"):
        await start_asyncssh_server(
            host="0.0.0.0",
            port=0,
            server_host_keys=("ssh_host_ed25519_key",),
            server_factory=lambda: VibeConnectSshServer(
                identity_resolver=FakeIdentityResolver(),
            ),
            listen=FakeAsyncSshListen(),
        )


@pytest.mark.asyncio
async def test_start_asyncssh_server_calls_asyncssh_listen() -> None:
    """The listener wrapper passes the configured bind surface to AsyncSSH."""
    listen = FakeAsyncSshListen()

    def factory() -> VibeConnectSshServer:
        return VibeConnectSshServer(identity_resolver=FakeIdentityResolver())

    listener = await start_asyncssh_server(
        host="127.0.0.1",
        port=2222,
        server_host_keys=("ssh_host_ed25519_key",),
        server_factory=factory,
        listen=listen,
    )

    assert listener is listen.listener
    assert listen.calls == [
        {
            "host": "127.0.0.1",
            "port": 2222,
            "server_factory": factory,
            "server_host_keys": ("ssh_host_ed25519_key",),
        }
    ]


@pytest.mark.asyncio
async def test_start_asyncssh_server_defaults_to_port_22() -> None:
    """The user-facing SSH listener defaults to port 22."""
    listen = FakeAsyncSshListen()

    def factory() -> VibeConnectSshServer:
        return VibeConnectSshServer(identity_resolver=FakeIdentityResolver())

    await start_asyncssh_server(
        server_host_keys=("ssh_host_ed25519_key",),
        server_factory=factory,
        listen=listen,
    )

    assert listen.calls[0]["host"] == "0.0.0.0"
    assert listen.calls[0]["port"] == 22


@pytest.mark.asyncio
async def test_ssh_server_public_key_auth_resolves_identity() -> None:
    """Public-key auth binds the AsyncSSH connection to one identity."""
    key = asyncssh.generate_private_key("ssh-ed25519")
    public_key = key.export_public_key().decode("ascii").strip()
    resolver = FakeIdentityResolver(public_key=public_key)
    server = VibeConnectSshServer(identity_resolver=resolver)

    assert await server.validate_public_key("alice", key)

    assert server.identity == _identity(public_key=public_key)
    assert not server.password_auth_supported()
    assert not server.kbdint_auth_supported()
    assert server.public_key_auth_supported()
    assert server.begin_auth("alice")


@pytest.mark.asyncio
async def test_ssh_server_public_key_auth_denies_unresolved_identity() -> None:
    """Unresolved public keys fail closed and do not leave identity state behind."""
    server = VibeConnectSshServer(identity_resolver=FakeIdentityResolver(deny=True))

    assert not await server.validate_public_key(
        "alice",
        asyncssh.generate_private_key("ssh-ed25519"),
    )
    assert server.identity is None


@pytest.mark.asyncio
async def test_restricted_shell_handler_starts_authorized_jump() -> None:
    """An authenticated exact node command starts a coordinated jump."""
    key = asyncssh.generate_private_key("ssh-ed25519")
    public_key = key.export_public_key().decode("ascii").strip()
    server = VibeConnectSshServer(
        identity_resolver=FakeIdentityResolver(public_key=public_key),
    )
    assert await server.validate_public_key("alice", key)
    store = FakeJumpStore()
    tunnel = FakeTunnelOpener()

    started = await RestrictedShellJumpHandler(
        server=server,
        node_authorizer=FakeNodeAuthorizer(),
        host_key_lookup=FakeHostKeyLookup(),
        jump_coordinator=ServerJumpCoordinator(
            store=store,
            replay_starter=FakeReplayStarter(),
            certificate_issuer=FakeCertificateIssuer(),
            tunnel_opener=tunnel,
            audit_sink=FakeAuditSink(),
        ),
        clock=lambda: _NOW,
    ).start_exec(command="node-01", width=80, height=24)

    assert started.session == store.session
    assert tunnel.opened[0][2:] == (
        "node-01",
        "ssh-ed25519 AAAAhost",
        "alice",
        started.user_certificate,
    )


@pytest.mark.asyncio
async def test_restricted_shell_handler_requires_authenticated_identity() -> None:
    """Exec requests without authenticated identity fail before jump setup."""
    handler = _handler(
        server=VibeConnectSshServer(identity_resolver=FakeIdentityResolver()),
    )

    with pytest.raises(SshServerError, match="not authenticated"):
        await handler.start_exec(command="node-01", width=80, height=24)


@pytest.mark.asyncio
async def test_restricted_shell_handler_denies_unauthorized_command() -> None:
    """Non-node commands fail closed before any jump session is opened."""
    server = await _authenticated_server()
    tunnel = FakeTunnelOpener()
    handler = _handler(server=server, tunnel=tunnel)

    with pytest.raises(SshServerError, match="denied"):
        await handler.start_exec(command="node-01;whoami", width=80, height=24)

    assert tunnel.opened == []


@pytest.mark.asyncio
async def test_restricted_shell_handler_denies_unknown_host_key() -> None:
    """Unknown node host-key state fails closed before opening a tunnel session."""
    server = await _authenticated_server()
    tunnel = FakeTunnelOpener()
    handler = _handler(
        server=server,
        host_key_lookup=FakeHostKeyLookup(host_key=None),
        tunnel=tunnel,
    )

    with pytest.raises(SshServerError, match="denied"):
        await handler.start_exec(command="node-01", width=80, height=24)

    assert tunnel.opened == []


def test_restricted_shell_handler_denies_forwarding_and_subsystems() -> None:
    """Unsupported SSH features are denied at the AsyncSSH boundary."""
    handler = _handler(
        server=VibeConnectSshServer(identity_resolver=FakeIdentityResolver()),
    )

    with pytest.raises(SshServerError, match="subsystem"):
        handler.subsystem_requested("sftp")
    with pytest.raises(SshServerError, match="direct TCP"):
        handler.direct_tcpip_requested()
    with pytest.raises(SshServerError, match="agent forwarding"):
        handler.agent_forwarding_requested()
    with pytest.raises(SshServerError, match="X11"):
        handler.x11_forwarding_requested()


@pytest.mark.asyncio
async def test_restricted_shell_session_relays_user_and_node_pty_bytes() -> None:
    """An accepted exec bridges user input, node output, replay, and close."""
    server = await _authenticated_server()
    node_connection = FakeNodeConnection()
    tunnel = FakeTunnelOpener(node_connection=node_connection)
    session = RestrictedShellSession(
        server=server,
        handler_factory=lambda _: _handler(server=server, tunnel=tunnel),
    )
    user_channel = FakeUserChannel()
    session.connection_made(user_channel)
    assert session.pty_requested("xterm", (100, 40, 0, 0), {})

    assert session.exec_requested("node-01")
    await node_connection.wait_for_process()

    session.data_received("whoami\n", None)
    node_connection.process.stdout.feed(b"alice\n")
    await user_channel.wait_for_writes(1)

    node_connection.process.finish()
    await user_channel.wait_for_exit()

    assert node_connection.process.stdin.writes == [b"whoami\n"]
    assert user_channel.writes == ["alice\n"]
    assert user_channel.exits == [0]
    assert user_channel.closed


@pytest.mark.asyncio
async def test_restricted_shell_session_buffers_input_until_jump_is_ready() -> None:
    """Early client input is not dropped while the node SSH process starts."""
    server = await _authenticated_server()
    node_connection = FakeNodeConnection()
    tunnel = FakeTunnelOpener(node_connection=node_connection)
    session = RestrictedShellSession(
        server=server,
        handler_factory=lambda _: _handler(server=server, tunnel=tunnel),
    )
    user_channel = FakeUserChannel()
    session.connection_made(user_channel)

    assert session.exec_requested("node-01")
    session.data_received(b"whoami\n", None)
    await node_connection.wait_for_process()
    await _wait_for_stdin(node_connection.process, count=1)

    node_connection.process.finish()
    await user_channel.wait_for_exit()

    assert node_connection.process.stdin.writes == [b"whoami\n"]


@pytest.mark.asyncio
async def test_restricted_shell_session_buffers_eof_until_jump_is_ready() -> None:
    """Early client EOF is forwarded after the node SSH process exists."""
    server = await _authenticated_server()
    node_connection = FakeNodeConnection()
    tunnel = FakeTunnelOpener(node_connection=node_connection)
    session = RestrictedShellSession(
        server=server,
        handler_factory=lambda _: _handler(server=server, tunnel=tunnel),
    )
    user_channel = FakeUserChannel()
    session.connection_made(user_channel)

    assert session.exec_requested("node-01")
    assert not session.eof_received()
    await node_connection.wait_for_process()

    node_connection.process.finish()
    await user_channel.wait_for_exit()

    assert node_connection.process.stdin.eof


class FakeAsyncSshListen:
    """Fake AsyncSSH listen callable."""

    def __init__(self) -> None:
        """Create an empty listen log."""
        self.listener = FakeAsyncSshListener()
        self.calls: list[dict[str, object]] = []

    async def __call__(
        self,
        *,
        host: str,
        port: int,
        server_factory: Callable[[], asyncssh.SSHServer],
        server_host_keys: Sequence[str | Path],
    ) -> AsyncSshListener:
        """Record listen arguments."""
        self.calls.append(
            {
                "host": host,
                "port": port,
                "server_factory": server_factory,
                "server_host_keys": tuple(server_host_keys),
            }
        )
        return self.listener


class FakeAsyncSshListener:
    """Fake closeable AsyncSSH listener."""

    def __init__(self) -> None:
        """Create an open listener."""
        self.closed = False

    def close(self) -> None:
        """Record closure."""
        self.closed = True

    async def wait_closed(self) -> None:
        """No-op wait."""


class FakeUserChannel:
    """Capture writes and terminal exit for a user SSH channel."""

    def __init__(self) -> None:
        """Initialize channel event state."""
        self.writes: list[bytes | str] = []
        self.exits: list[int] = []
        self.closed = False
        self._write_event = asyncio.Event()
        self._exit_event = asyncio.Event()

    def write(self, data: bytes | str) -> None:
        """Record user-visible output."""
        self.writes.append(data)
        self._write_event.set()

    def exit(self, status: int = 0) -> None:
        """Record exit status."""
        self.exits.append(status)
        self._exit_event.set()

    def close(self) -> None:
        """Record close."""
        self.closed = True

    async def wait_for_writes(self, count: int) -> None:
        """Wait until enough output has been written."""
        while len(self.writes) < count:
            await self._write_event.wait()
            self._write_event.clear()

    async def wait_for_exit(self) -> None:
        """Wait for the channel to exit."""
        await self._exit_event.wait()


class FakeProcessWriter:
    """Capture process stdin writes."""

    def __init__(self) -> None:
        """Initialize write log."""
        self.writes: list[bytes] = []
        self.eof = False

    def write(self, data: bytes) -> None:
        """Record process input."""
        self.writes.append(data)

    def write_eof(self) -> None:
        """Record EOF."""
        self.eof = True


class FakeProcessReader:
    """Queue-backed process reader."""

    def __init__(self) -> None:
        """Initialize queue state."""
        self._queue: asyncio.Queue[bytes | None] = asyncio.Queue()

    def feed(self, data: bytes) -> None:
        """Queue process output."""
        self._queue.put_nowait(data)

    def feed_eof(self) -> None:
        """Queue EOF."""
        self._queue.put_nowait(None)

    async def read(self, n: int = -1) -> bytes:
        """Read queued process output."""
        payload = await self._queue.get()
        return b"" if payload is None else payload


class FakeNodeProcess:
    """Interactive node process fake."""

    def __init__(self) -> None:
        """Initialize stdin/stdout/stderr and close event."""
        self.stdin = FakeProcessWriter()
        self.stdout = FakeProcessReader()
        self.stderr = FakeProcessReader()
        self._closed = asyncio.Event()

    async def wait_closed(self) -> None:
        """Wait until the process is marked closed."""
        await self._closed.wait()

    def finish(self) -> None:
        """Mark output streams and process closed."""
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self._closed.set()


class FakeNodeConnection:
    """Node SSH connection fake."""

    def __init__(self) -> None:
        """Initialize deterministic process."""
        self.process = FakeNodeProcess()
        self.create_calls: list[dict[str, object]] = []
        self.closed = False
        self._created = asyncio.Event()

    async def create_process(self, **kwargs: object) -> FakeNodeProcess:
        """Record process creation and return the fake."""
        self.create_calls.append(kwargs)
        self._created.set()
        return self.process

    def close(self) -> None:
        """Record connection close."""
        self.closed = True

    async def wait_closed(self) -> None:
        """No-op close wait."""

    async def wait_for_process(self) -> None:
        """Wait until process creation."""
        await self._created.wait()


class FakeIdentityResolver:
    """Fake public-key identity resolver."""

    def __init__(
        self, *, public_key: str = "ssh-ed25519 AAAAalice", deny: bool = False
    ):
        """Configure resolved key material."""
        self.public_key = public_key
        self.deny = deny

    async def resolve_public_key(
        self,
        *,
        username: str,
        public_key: str,
    ) -> ResolvedIdentity:
        """Resolve one deterministic identity."""
        if self.deny or username != "alice" or public_key != self.public_key:
            raise AuthError("public key identity mismatch")
        return _identity(public_key=public_key)


class FakeNodeAuthorizer:
    """Fake node authorization surface."""

    async def visible_nodes(
        self,
        *,
        identity: ResolvedIdentity,
    ) -> tuple[NodeInventoryEntry, ...]:
        """Return one visible node."""
        return (NodeInventoryEntry(node_name="node-01", labels=frozenset({"prod"})),)


class FakeHostKeyLookup:
    """Fake node host-key lookup."""

    def __init__(self, *, host_key: str | None = "ssh-ed25519 AAAAhost") -> None:
        """Configure the presented host key."""
        self.host_key = host_key

    async def presented_host_key(self, *, node_name: str) -> str | None:
        """Return the configured host key."""
        return self.host_key


class FakeJumpStore:
    """In-memory jump store for SSH boundary tests."""

    def __init__(self) -> None:
        """Create one fresh target and deterministic session."""
        heartbeat = HeartbeatState(heartbeat_seconds=10)
        heartbeat.mark_seen(_NOW)
        self.target = JumpTarget(
            agent_id=uuid.uuid4(),
            node_name="node-01",
            node_ssh_host_public_key="ssh-ed25519 AAAAhost",
            heartbeat=heartbeat,
        )
        self.session = JumpSession(
            session_id=uuid.uuid4(),
            user_cert_serial=42,
            replay_path=Path("session.cast"),
            started_at=_NOW,
        )
        self.failed: list[uuid.UUID] = []

    async def get_jump_target(self, node_name: str) -> JumpTarget | None:
        """Return the target by node name."""
        if node_name == self.target.node_name:
            return self.target
        return None

    async def create_session(
        self,
        *,
        agent_id: uuid.UUID,
        username: str,
        node_name: str,
        replay_path: Path,
        started_at: dt.datetime,
    ) -> JumpSession:
        """Return deterministic session metadata."""
        return self.session

    async def fail_session(
        self,
        *,
        session_id: uuid.UUID,
        ended_at: dt.datetime,
    ) -> None:
        """Record failed setup."""
        self.failed.append(session_id)


class FakeReplayStarter:
    """Replay starter fake."""

    def __init__(self) -> None:
        """Create one recorder."""
        self.recorder = FakeReplayRecorder()

    def start(
        self,
        *,
        session_id: uuid.UUID,
        node_name: str,
        width: int,
        height: int,
        now: dt.datetime | None = None,
    ) -> ReplayRecorder:
        """Return a replay recorder fake."""
        return cast(ReplayRecorder, self.recorder)


class FakeReplayRecorder:
    """Minimal replay recorder fake."""

    def record_input(self, seconds: float, data: str) -> None:
        """No-op input record."""

    def record_output(self, seconds: float, data: str) -> None:
        """No-op output record."""

    def close(self, *, now: dt.datetime | None = None) -> object:
        """Return a fake close result."""
        return object()

    def fail(self, *, error: str, now: dt.datetime | None = None) -> None:
        """No-op failure record."""


class FakeCertificateIssuer:
    """Certificate issuer fake."""

    def issue(
        self,
        *,
        username: str,
        session_id: uuid.UUID,
        serial: int,
        now: dt.datetime,
    ) -> IssuedUserCertificate:
        """Issue a deterministic certificate object."""
        return IssuedUserCertificate(
            private_key=asyncssh.generate_private_key("ssh-ed25519"),
            certificate=b"cert",
            serial=serial,
            username=username,
            valid_after=now,
            valid_before=now + dt.timedelta(hours=4),
        )


class FakeTunnelOpener:
    """Tunnel opener fake."""

    def __init__(self, *, node_connection: object | None = None) -> None:
        """Create an empty open log."""
        self.node_connection = object() if node_connection is None else node_connection
        self.opened: list[
            tuple[uuid.UUID, str, str, str, str, IssuedUserCertificate]
        ] = []

    async def open_session(
        self,
        *,
        agent_id: uuid.UUID,
        channel_id: str,
        node_name: str,
        node_ssh_host_public_key: str,
        username: str,
        user_certificate: IssuedUserCertificate,
    ) -> object:
        """Record an opened tunnel session."""
        self.opened.append(
            (
                agent_id,
                channel_id,
                node_name,
                node_ssh_host_public_key,
                username,
                user_certificate,
            )
        )
        return self.node_connection


class FakeAuditSink:
    """Audit sink fake."""

    async def write(
        self,
        *,
        event_type: AuditEventType,
        actor: str,
        metadata: dict[str, object],
        agent_id: uuid.UUID | None = None,
        session_id: uuid.UUID | None = None,
        node_name: str | None = None,
        now: dt.datetime | None = None,
    ) -> object:
        """Ignore audit writes."""
        return object()


async def _authenticated_server() -> VibeConnectSshServer:
    key = asyncssh.generate_private_key("ssh-ed25519")
    public_key = key.export_public_key().decode("ascii").strip()
    server = VibeConnectSshServer(
        identity_resolver=FakeIdentityResolver(public_key=public_key),
    )
    assert await server.validate_public_key("alice", key)
    return server


def _handler(
    *,
    server: VibeConnectSshServer,
    host_key_lookup: FakeHostKeyLookup | None = None,
    tunnel: FakeTunnelOpener | None = None,
) -> RestrictedShellJumpHandler:
    return RestrictedShellJumpHandler(
        server=server,
        node_authorizer=FakeNodeAuthorizer(),
        host_key_lookup=FakeHostKeyLookup()
        if host_key_lookup is None
        else host_key_lookup,
        jump_coordinator=ServerJumpCoordinator(
            store=FakeJumpStore(),
            replay_starter=FakeReplayStarter(),
            certificate_issuer=FakeCertificateIssuer(),
            tunnel_opener=FakeTunnelOpener() if tunnel is None else tunnel,
            audit_sink=FakeAuditSink(),
        ),
        clock=lambda: _NOW,
    )


async def _wait_for_stdin(process: FakeNodeProcess, *, count: int) -> None:
    for _attempt in range(100):
        if len(process.stdin.writes) >= count:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("timed out waiting for process stdin")


def _identity(*, public_key: str) -> ResolvedIdentity:
    return ResolvedIdentity(
        username="alice",
        public_key=public_key,
        groups=frozenset({"group-a"}),
    )
