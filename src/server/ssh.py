"""AsyncSSH server boundary for user-facing jump sessions."""

from __future__ import annotations

import asyncio
import datetime as dt
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol, cast

import asyncssh

from server.auth import (
    AuthError,
    NodeInventoryEntry,
    ResolvedIdentity,
    validate_ssh_request_policy,
)
from server.jump import (
    AsyncSshJumpSessionLifecycle,
    JumpAuditSink,
    JumpError,
    JumpPtyBridge,
    JumpSessionStateStore,
    ServerJumpCoordinator,
    StartedJump,
)
from vibeconnect_common.models import AuditEventType, SessionStatus


class SshIdentityResolver(Protocol):
    """Public-key identity resolver used by the SSH server."""

    async def resolve_public_key(
        self,
        *,
        username: str,
        public_key: str,
    ) -> ResolvedIdentity:
        """Resolve an authenticated identity or fail closed."""


class SshNodeAuthorizer(Protocol):
    """Node authorization surface for one resolved SSH identity."""

    async def visible_nodes(
        self,
        *,
        identity: ResolvedIdentity,
    ) -> tuple[NodeInventoryEntry, ...]:
        """Return nodes visible to this identity."""


class SshNodeHostKeyLookup(Protocol):
    """Node host-key lookup surface used before opening a jump."""

    async def presented_host_key(self, *, node_name: str) -> str | None:
        """Return the node sshd host key observed through the tunnel."""


class AsyncSshListener(Protocol):
    """Closeable AsyncSSH listener returned by `asyncssh.listen`."""

    def close(self) -> None:
        """Stop accepting new SSH connections."""

    async def wait_closed(self) -> None:
        """Wait until the listener has fully closed."""


class AsyncSshListen(Protocol):
    """Callable surface compatible with `asyncssh.listen`."""

    def __call__(
        self,
        *,
        host: str,
        port: int,
        server_factory: Callable[[], asyncssh.SSHServer],
        server_host_keys: Sequence[str | Path],
    ) -> Awaitable[AsyncSshListener]:
        """Start listening for SSH connections."""


class SshChannel(Protocol):
    """Writable AsyncSSH server channel surface used by restricted sessions."""

    def write(self, data: bytes | str) -> None:
        """Write data to the user SSH channel."""

    def exit(self, status: int = 0) -> None:
        """Send an exit status."""

    def close(self) -> None:
        """Close the channel."""


class NodeSshConnection(Protocol):
    """Node-side AsyncSSH connection returned by the jump opener."""

    async def create_process(self, **kwargs: object) -> object:
        """Create an interactive node shell process."""

    def close(self) -> None:
        """Close the node SSH connection."""

    async def wait_closed(self) -> None:
        """Wait until the node SSH connection is closed."""


class ProcessReader(Protocol):
    """Readable process stream surface."""

    async def read(self, n: int = -1) -> bytes | str:
        """Read process output."""


class ProcessWriter(Protocol):
    """Writable process stream surface."""

    def write(self, data: bytes) -> None:
        """Write process input."""

    def write_eof(self) -> None:
        """Send EOF to the process."""


class NodeSshProcess(Protocol):
    """Interactive node process surface."""

    stdin: ProcessWriter
    stdout: ProcessReader
    stderr: ProcessReader

    async def wait_closed(self) -> None:
        """Wait until the process closes."""


SshSessionFactory = Callable[["VibeConnectSshServer"], asyncssh.SSHServerSession[bytes]]


async def start_asyncssh_server(
    *,
    host: str = "0.0.0.0",
    port: int = 22,
    server_host_keys: Sequence[str | Path],
    server_factory: Callable[[], asyncssh.SSHServer],
    listen: AsyncSshListen | None = None,
) -> AsyncSshListener:
    """Start the user-facing AsyncSSH server listener."""
    if not server_host_keys:
        raise SshServerError("server host key is required")
    if not 1 <= port <= 65535:
        raise SshServerError("SSH listen port is outside valid TCP port bounds")
    actual_listen = asyncssh.listen if listen is None else listen
    return await actual_listen(
        host=host,
        port=port,
        server_factory=server_factory,
        server_host_keys=server_host_keys,
    )


class SshServerError(PermissionError):
    """Raised when the SSH boundary must fail closed."""


class VibeConnectSshServer(asyncssh.SSHServer):
    """AsyncSSH server which authenticates users before restricted jumps."""

    def __init__(
        self,
        *,
        identity_resolver: SshIdentityResolver,
        session_factory: SshSessionFactory | None = None,
    ) -> None:
        """Configure authentication dependencies for one SSH connection."""
        self._identity_resolver = identity_resolver
        self._session_factory = session_factory
        self._identity: ResolvedIdentity | None = None

    @property
    def identity(self) -> ResolvedIdentity | None:
        """Return the authenticated identity for this connection."""
        return self._identity

    def begin_auth(self, username: str) -> bool:
        """Require authentication for every SSH connection."""
        return True

    def public_key_auth_supported(self) -> bool:
        """Enable public-key authentication."""
        return True

    def password_auth_supported(self) -> bool:
        """Disable password auth at this boundary."""
        return False

    def kbdint_auth_supported(self) -> bool:
        """Disable keyboard-interactive auth until a verifier is wired."""
        return False

    async def validate_public_key(
        self,
        username: str,
        key: asyncssh.SSHKey,
    ) -> bool:
        """Resolve the SSH public key into a canonical identity."""
        try:
            public_key = key.export_public_key().decode("ascii").strip()
            self._identity = await self._identity_resolver.resolve_public_key(
                username=username,
                public_key=public_key,
            )
        except (AuthError, UnicodeDecodeError):
            self._identity = None
            return False
        return True

    def session_requested(self) -> asyncssh.SSHServerSession[bytes] | bool:
        """Create the restricted command session after authentication."""
        if self._session_factory is None:
            return False
        return self._session_factory(self)


class RestrictedShellJumpHandler:
    """Handle authenticated restricted-shell exec requests."""

    def __init__(
        self,
        *,
        server: VibeConnectSshServer,
        node_authorizer: SshNodeAuthorizer,
        host_key_lookup: SshNodeHostKeyLookup,
        jump_coordinator: ServerJumpCoordinator,
        clock: Callable[[], dt.datetime],
    ) -> None:
        """Configure jump request dependencies."""
        self._server = server
        self._node_authorizer = node_authorizer
        self._host_key_lookup = host_key_lookup
        self._jump_coordinator = jump_coordinator
        self._clock = clock

    async def start_exec(
        self,
        *,
        command: str,
        width: int,
        height: int,
    ) -> StartedJump:
        """Start one restricted-shell node jump or fail before opening a channel."""
        identity = self._server.identity
        if identity is None:
            raise SshServerError("SSH connection is not authenticated")
        try:
            validate_ssh_request_policy(username=identity.username, command=command)
            visible_nodes = await self._node_authorizer.visible_nodes(
                identity=identity,
            )
            node_name = _single_requested_node(command, visible_nodes)
            presented_host_key = await self._host_key_lookup.presented_host_key(
                node_name=node_name,
            )
            return await self._jump_coordinator.start_jump(
                identity=identity,
                command=command,
                visible_nodes=visible_nodes,
                presented_node_host_key=presented_host_key,
                width=width,
                height=height,
                now=self._clock(),
            )
        except (AuthError, JumpError) as exc:
            raise SshServerError("restricted SSH request denied") from exc

    def subsystem_requested(self, subsystem: str) -> None:
        """Deny subsystem requests such as SFTP."""
        raise SshServerError(f"subsystem denied: {subsystem}")

    def direct_tcpip_requested(self) -> None:
        """Deny direct TCP forwarding."""
        raise SshServerError("direct TCP forwarding denied")

    def agent_forwarding_requested(self) -> None:
        """Deny SSH agent forwarding."""
        raise SshServerError("agent forwarding denied")

    def x11_forwarding_requested(self) -> None:
        """Deny X11 forwarding."""
        raise SshServerError("X11 forwarding denied")


class RestrictedShellSession(asyncssh.SSHServerSession[bytes]):
    """AsyncSSH server session which accepts only one node-name exec request."""

    def __init__(
        self,
        *,
        handler_factory: Callable[[VibeConnectSshServer], RestrictedShellJumpHandler],
        server: VibeConnectSshServer,
        audit_sink: JumpAuditSink | None = None,
        session_state_store: JumpSessionStateStore | None = None,
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        """Configure the handler factory for one SSH channel."""
        self._handler = handler_factory(server)
        self._audit_sink = audit_sink
        self._session_state_store = session_state_store
        self._clock: Callable[[], dt.datetime] = _utc_now if clock is None else clock
        self._channel: SshChannel | None = None
        self._started: StartedJump | None = None
        self._process: NodeSshProcess | None = None
        self._bridge: JumpPtyBridge | None = None
        self._lifecycle: AsyncSshJumpSessionLifecycle | None = None
        self._term_type = "xterm"
        self._term_size = (80, 24, 0, 0)
        self._pump_tasks: set[asyncio.Task[None]] = set()
        self._pending_input: list[bytes] = []
        self._pending_eof = False

    def connection_made(self, chan: object) -> None:
        """Capture the AsyncSSH channel for terminal status replies."""
        self._channel = cast(SshChannel, chan) if _is_channel(chan) else None

    def pty_requested(
        self,
        term_type: str,
        term_size: tuple[int, int, int, int],
        term_modes: Mapping[int, int],
    ) -> bool:
        """Accept PTY allocation for the restricted jump."""
        self._term_type = term_type
        self._term_size = term_size
        return True

    def exec_requested(self, command: str) -> bool:
        """Start the restricted jump for the exact requested node name."""
        asyncio.create_task(self._start_exec(command))
        return True

    async def _start_exec(self, command: str) -> None:
        width = self._term_size[0]
        height = self._term_size[1]
        try:
            self._started = await self._handler.start_exec(
                command=command,
                width=width,
                height=height,
            )
            connection = cast(NodeSshConnection, self._started.node_connection)
            self._process = cast(
                NodeSshProcess,
                await connection.create_process(
                    term_type=self._term_type,
                    term_size=self._term_size,
                    encoding=None,
                ),
            )
            self._bridge = JumpPtyBridge(
                started_jump=self._started,
                tunnel_channel=_NodeProcessPtyChannel(
                    process=self._process,
                    connection=connection,
                ),
                audit_sink=self._audit_sink,
                session_state_store=self._session_state_store,
            )
            self._lifecycle = AsyncSshJumpSessionLifecycle(bridge=self._bridge)
            await self._flush_pending_input()
            self._create_pump(self._pump_output(self._process.stdout))
            self._create_pump(self._pump_output(self._process.stderr))
            self._create_pump(self._wait_for_process())
        except SshServerError:
            _exit(self._channel, 1)
        except (OSError, asyncssh.Error):
            await self._fail_started_jump("node process start failed")
            _exit(self._channel, 1)

    def data_received(self, data: bytes | str, datatype: object) -> None:
        """Forward user PTY input to the node process and replay recorder."""
        payload = data.encode("utf-8") if isinstance(data, str) else data
        if self._bridge is None:
            self._pending_input.append(payload)
            return
        self._create_pump(
            self._bridge.send_user_input(
                seconds=self._elapsed_seconds(),
                payload=payload,
            )
        )

    async def _flush_pending_input(self) -> None:
        assert self._bridge is not None
        for payload in self._pending_input:
            await self._bridge.send_user_input(
                seconds=self._elapsed_seconds(),
                payload=payload,
            )
        self._pending_input.clear()
        if self._pending_eof and self._process is not None:
            self._process.stdin.write_eof()
            self._pending_eof = False

    def eof_received(self) -> bool:
        """Forward user EOF to the node process."""
        process = self._process
        if process is None:
            self._pending_eof = True
        else:
            process.stdin.write_eof()
        return False

    def terminal_size_changed(
        self,
        width: int,
        height: int,
        pixwidth: int,
        pixheight: int,
    ) -> None:
        """Forward PTY resize requests to the node process."""
        self._term_size = (width, height, pixwidth, pixheight)
        if self._bridge is not None:
            self._create_pump(self._bridge.resize_pty(width=width, height=height))

    def connection_lost(self, exc: BaseException | None) -> None:
        """Persist terminal state when the user SSH channel closes."""
        close_task: asyncio.Task[None] | None = None
        if self._lifecycle is not None:
            close_task = self._create_pump(
                self._lifecycle.connection_lost(exc=exc, now=self._clock())
            )
        for task in tuple(self._pump_tasks):
            if task is close_task:
                continue
            task.cancel()

    async def _pump_output(self, reader: ProcessReader) -> None:
        while True:
            chunk = await reader.read(32768)
            if not chunk:
                return
            payload = chunk.encode("utf-8") if isinstance(chunk, str) else chunk
            if self._bridge is not None:
                payload = self._bridge.receive_node_output(
                    seconds=self._elapsed_seconds(),
                    payload=payload,
                )
            if self._channel is not None:
                self._channel.write(payload.decode("utf-8", errors="replace"))

    async def _wait_for_process(self) -> None:
        assert self._process is not None
        await self._process.wait_closed()
        if self._lifecycle is not None:
            await self._lifecycle.connection_lost(exc=None, now=self._clock())
        _exit(self._channel, 0)

    async def _fail_started_jump(self, error: str) -> None:
        if self._started is None:
            return
        now = self._clock()
        self._started.replay.fail(error=error, now=now)
        if self._session_state_store is not None:
            await self._session_state_store.close_session(
                session_id=self._started.session.session_id,
                status=SessionStatus.FAILED,
                ended_at=now,
                error=error,
            )
        if self._audit_sink is not None:
            await self._audit_sink.write(
                event_type=AuditEventType.SESSION_FAILED,
                actor=self._started.user_certificate.username,
                agent_id=self._started.target.agent_id,
                session_id=self._started.session.session_id,
                node_name=self._started.target.node_name,
                metadata={"status": SessionStatus.FAILED.value, "error": error},
                now=now,
            )

    def _create_pump(self, awaitable: Coroutine[Any, Any, None]) -> asyncio.Task[None]:
        task: asyncio.Task[None] = asyncio.create_task(awaitable)
        self._pump_tasks.add(task)
        task.add_done_callback(lambda done: self._pump_tasks.discard(done))
        return task

    def _elapsed_seconds(self) -> float:
        if self._started is None:
            return 0.0
        return max(
            0.0,
            (self._clock() - self._started.session.started_at).total_seconds(),
        )

    def subsystem_requested(self, subsystem: str) -> bool:
        """Deny subsystems such as SFTP."""
        self._handler.subsystem_requested(subsystem)
        return False

    def direct_tcpip_requested(self, *args: object) -> bool:
        """Deny direct TCP forwarding."""
        self._handler.direct_tcpip_requested()
        return False

    def auth_agent_requested(self) -> bool:
        """Deny SSH agent forwarding."""
        self._handler.agent_forwarding_requested()
        return False

    def x11_requested(self, *args: object) -> bool:
        """Deny X11 forwarding."""
        self._handler.x11_forwarding_requested()
        return False


def _single_requested_node(
    command: str,
    visible_nodes: tuple[NodeInventoryEntry, ...],
) -> str:
    allowed = {node.node_name for node in visible_nodes}
    requested = command.strip()
    if requested not in allowed:
        raise AuthError("restricted shell accepts only an exact node name")
    return requested


def _is_channel(chan: object) -> bool:
    return (
        callable(getattr(chan, "write", None))
        and callable(getattr(chan, "exit", None))
        and callable(getattr(chan, "close", None))
    )


def _exit(channel: SshChannel | None, status: int) -> None:
    if channel is None:
        return
    channel.exit(status)
    channel.close()


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class _NodeProcessPtyChannel:
    """JumpPtyBridge tunnel facade backed by an AsyncSSH node process."""

    def __init__(
        self,
        *,
        process: NodeSshProcess,
        connection: NodeSshConnection,
    ) -> None:
        self._process = process
        self._connection = connection

    async def send_data(self, *, channel_id: str, payload: bytes) -> None:
        """Write user bytes to the node process."""
        self._process.stdin.write(payload)

    async def resize_pty(self, *, channel_id: str, width: int, height: int) -> None:
        """Resize the node PTY when AsyncSSH exposes a resize method."""
        resize = getattr(self._process, "change_terminal_size", None)
        if callable(resize):
            resize(width, height)

    async def close_session(self, *, channel_id: str) -> None:
        """Close the node SSH connection."""
        self._connection.close()
        await self._connection.wait_closed()
