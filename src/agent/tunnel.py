"""Agent-side tunnel runtime guardrails."""

from __future__ import annotations

import asyncio
import contextlib
import json
import random
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from ssl import SSLContext
from typing import Protocol, cast

from vibeconnect_common.models import TunnelFrameType
from vibeconnect_common.tunnel import (
    DEFAULT_FRAME_MAX_BYTES,
    FRAME_HEADER_MAX_BYTES,
    decode_frame,
    encode_frame,
)


class AgentTunnelError(RuntimeError):
    """Raised when the agent tunnel cannot proceed safely."""


class TunnelReconnectLimitError(AgentTunnelError):
    """Raised when the agent exhausts its configured reconnect attempts."""


@dataclass(frozen=True, slots=True)
class ProxyTarget:
    """Validated local sshd proxy target."""

    host: str
    port: int


def require_tunnel_tls_context(context: SSLContext | None) -> SSLContext:
    """Reject insecure tunnel TLS bypasses."""
    if context is None:
        raise AgentTunnelError("tunnel TLS validation is required")
    if not context.check_hostname:
        raise AgentTunnelError("tunnel TLS hostname validation is required")
    return context


def validate_proxy_target(host: str, port: int) -> ProxyTarget:
    """Allow raw TCP proxying only to the local node sshd."""
    if not host.startswith("127."):
        raise AgentTunnelError("agent proxy target must be IPv4 loopback")
    if not 1 <= port <= 65535:
        raise AgentTunnelError("agent proxy target port is outside TCP bounds")
    return ProxyTarget(host=host, port=port)


def next_reconnect_delay(
    *,
    attempt: int,
    base_seconds: float = 1.0,
    max_seconds: float = 60.0,
    jitter: float | None = None,
) -> float:
    """Return capped exponential backoff with jitter."""
    if attempt < 0:
        raise AgentTunnelError("attempt cannot be negative")
    if base_seconds <= 0 or max_seconds <= 0:
        raise AgentTunnelError("backoff values must be positive")
    actual_jitter = float(random.random() if jitter is None else jitter)
    if actual_jitter < 0 or actual_jitter > 1:
        raise AgentTunnelError("jitter must be between 0 and 1")
    exponential = min(max_seconds, base_seconds * (2**attempt))
    return cast(float, min(max_seconds, exponential * (0.5 + actual_jitter)))


class MissedHeartbeatTracker:
    """Track missed tunnel heartbeats on the agent."""

    def __init__(self, *, max_missed: int) -> None:
        """Configure the missed-heartbeat threshold."""
        if max_missed <= 0:
            raise AgentTunnelError("max_missed must be positive")
        self._max_missed = max_missed
        self._missed = 0

    def mark_seen(self) -> None:
        """Reset missed heartbeat count after any heartbeat response."""
        self._missed = 0

    def mark_missed(self) -> None:
        """Increment missed heartbeat count."""
        self._missed += 1

    def should_reconnect(self) -> bool:
        """Return whether the tunnel should reconnect."""
        return self._missed >= self._max_missed


def forward_ssh_payload(payload: bytes) -> bytes:
    """Return SSH payload bytes unchanged for raw TCP forwarding."""
    return bytes(payload)


class AsyncReader(Protocol):
    """Subset of asyncio reader APIs used by the tunnel loop."""

    async def read(self, n: int = -1) -> bytes:
        """Read up to n bytes."""

    async def readexactly(self, n: int) -> bytes:
        """Read exactly n bytes or raise EOF."""


class AsyncWriter(Protocol):
    """Subset of asyncio writer APIs used by the tunnel loop."""

    def write(self, data: bytes) -> None:
        """Write bytes to the stream."""

    async def drain(self) -> None:
        """Flush pending bytes."""

    def close(self) -> None:
        """Close the stream."""

    async def wait_closed(self) -> None:
        """Wait for the stream to close."""


ConnectLocal = Callable[[ProxyTarget], Awaitable[tuple[AsyncReader, AsyncWriter]]]


@dataclass(slots=True)
class _LocalChannel:
    reader: AsyncReader
    writer: AsyncWriter
    task: asyncio.Task[None]


async def connect_local_sshd(target: ProxyTarget) -> tuple[AsyncReader, AsyncWriter]:
    """Open the constrained local sshd TCP connection."""
    return await asyncio.open_connection(target.host, target.port)


async def handle_agent_tunnel_stream(
    *,
    tunnel_reader: AsyncReader,
    tunnel_writer: AsyncWriter,
    proxy_target: ProxyTarget,
    connect_local: ConnectLocal = connect_local_sshd,
    max_frame_bytes: int = DEFAULT_FRAME_MAX_BYTES,
) -> None:
    """Dispatch tunnel frames between the server and local sshd.

    The agent never parses SSH. Payloads are copied as opaque byte strings between
    framed tunnel channels and the node-local sshd connection.
    """
    channels: dict[str, _LocalChannel] = {}
    try:
        while True:
            data = await _read_one_frame(tunnel_reader, max_frame_bytes=max_frame_bytes)
            if data is None:
                return
            decoded = decode_frame(data, max_frame_bytes=max_frame_bytes)
            frame = decoded.frame
            if frame.type is TunnelFrameType.AUTH_OK:
                continue
            if frame.type is TunnelFrameType.HEARTBEAT:
                await _write_frame(
                    tunnel_writer,
                    frame_type=TunnelFrameType.HEARTBEAT,
                    request_id=frame.request_id,
                    channel_id=None,
                )
                continue
            if frame.type is TunnelFrameType.OPEN_SESSION:
                channel_id = _require_channel_id(frame.channel_id)
                if channel_id in channels:
                    raise AgentTunnelError("tunnel channel reuse rejected")
                local_reader, local_writer = await connect_local(proxy_target)
                task = asyncio.create_task(
                    _forward_local_to_tunnel(
                        local_reader=local_reader,
                        tunnel_writer=tunnel_writer,
                        channel_id=channel_id,
                        max_frame_bytes=max_frame_bytes,
                    )
                )
                channels[channel_id] = _LocalChannel(
                    reader=local_reader, writer=local_writer, task=task
                )
                await asyncio.sleep(0)
                continue
            if frame.type is TunnelFrameType.SESSION_DATA:
                channel = channels.get(_require_channel_id(frame.channel_id))
                if channel is None:
                    raise AgentTunnelError("session_data for unknown tunnel channel")
                channel.writer.write(forward_ssh_payload(decoded.payload))
                await channel.writer.drain()
                continue
            if frame.type is TunnelFrameType.RESIZE_PTY:
                if _require_channel_id(frame.channel_id) not in channels:
                    raise AgentTunnelError("resize_pty for unknown tunnel channel")
                continue
            if frame.type is TunnelFrameType.CLOSE_SESSION:
                channel_id = _require_channel_id(frame.channel_id)
                channel = channels.pop(channel_id, None)
                if channel is not None:
                    await _close_channel(channel)
                continue
            raise AgentTunnelError(
                f"unsupported agent tunnel frame: {frame.type.value}"
            )
    finally:
        for channel in list(channels.values()):
            await _close_channel(channel)


async def _read_one_frame(reader: AsyncReader, *, max_frame_bytes: int) -> bytes | None:
    try:
        header_length_bytes = await reader.readexactly(4)
    except asyncio.IncompleteReadError as exc:
        if exc.partial:
            raise AgentTunnelError("partial tunnel frame header") from exc
        return None
    header_length = struct.unpack("!I", header_length_bytes)[0]
    if header_length == 0 or header_length > FRAME_HEADER_MAX_BYTES:
        raise AgentTunnelError("tunnel frame header length is invalid")
    header_bytes = await reader.readexactly(header_length)
    payload_length = _payload_length_from_header(header_length_bytes + header_bytes)
    if payload_length > max_frame_bytes:
        raise AgentTunnelError("tunnel frame payload is too large")
    payload = await reader.readexactly(payload_length)
    return header_length_bytes + header_bytes + payload


def _payload_length_from_header(header_data: bytes) -> int:
    header_length = struct.unpack("!I", header_data[:4])[0]
    try:
        header = json.loads(header_data[4 : 4 + header_length].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentTunnelError("tunnel frame header is not valid JSON") from exc
    if not isinstance(header, dict):
        raise AgentTunnelError("tunnel frame header must be an object")
    payload_length = header.get("payload_length")
    if not isinstance(payload_length, int) or isinstance(payload_length, bool):
        raise AgentTunnelError("tunnel frame payload_length must be an integer")
    if payload_length < 0:
        raise AgentTunnelError("tunnel frame payload_length cannot be negative")
    return payload_length


async def _forward_local_to_tunnel(
    *,
    local_reader: AsyncReader,
    tunnel_writer: AsyncWriter,
    channel_id: str,
    max_frame_bytes: int,
) -> None:
    while True:
        payload = await local_reader.read(65536)
        if not payload:
            return
        await _write_frame(
            tunnel_writer,
            frame_type=TunnelFrameType.SESSION_DATA,
            request_id=f"{channel_id}:data",
            channel_id=channel_id,
            payload=forward_ssh_payload(payload),
            max_frame_bytes=max_frame_bytes,
        )


async def _write_frame(
    writer: AsyncWriter,
    *,
    frame_type: TunnelFrameType,
    request_id: str,
    channel_id: str | None,
    payload: bytes = b"",
    max_frame_bytes: int = DEFAULT_FRAME_MAX_BYTES,
) -> None:
    writer.write(
        encode_frame(
            frame_type=frame_type,
            request_id=request_id,
            channel_id=channel_id,
            payload=payload,
            max_frame_bytes=max_frame_bytes,
        )
    )
    await writer.drain()


def _require_channel_id(channel_id: str | None) -> str:
    if not channel_id:
        raise AgentTunnelError("tunnel channel_id is required")
    return channel_id


async def _close_channel(channel: _LocalChannel) -> None:
    channel.task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await channel.task
    channel.writer.close()
    await channel.writer.wait_closed()
