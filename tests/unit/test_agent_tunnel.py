"""Tests for agent-side tunnel guardrails."""

from __future__ import annotations

import asyncio
import ssl

import pytest

from agent.tunnel import (
    AgentTunnelError,
    AsyncReader,
    AsyncWriter,
    MissedHeartbeatTracker,
    ProxyTarget,
    forward_ssh_payload,
    handle_agent_tunnel_stream,
    next_reconnect_delay,
    require_tunnel_tls_context,
    validate_proxy_target,
)
from vibeconnect_common.models import TunnelFrameType
from vibeconnect_common.tunnel import decode_frame, encode_frame


def test_require_tunnel_tls_context_rejects_insecure_tls() -> None:
    """Tunnel mode cannot run without cert and hostname validation."""
    secure_context = ssl.create_default_context()
    insecure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure_context.check_hostname = False

    assert require_tunnel_tls_context(secure_context) is secure_context
    with pytest.raises(AgentTunnelError, match="TLS validation"):
        require_tunnel_tls_context(None)
    with pytest.raises(AgentTunnelError, match="hostname"):
        require_tunnel_tls_context(insecure_context)


def test_validate_proxy_target_allows_only_local_sshd() -> None:
    """Agent raw TCP proxying is constrained to configured IPv4 loopback."""
    assert validate_proxy_target("127.0.0.1", 2222).host == "127.0.0.1"
    assert validate_proxy_target("127.0.0.2", 2200).port == 2200
    with pytest.raises(AgentTunnelError, match="IPv4 loopback"):
        validate_proxy_target("localhost", 2222)
    with pytest.raises(AgentTunnelError, match="TCP bounds"):
        validate_proxy_target("127.0.0.1", 0)


def test_reconnect_delay_is_exponential_capped_and_jittered() -> None:
    """Reconnect backoff is bounded and jitter-capable."""
    assert next_reconnect_delay(attempt=0, jitter=0.0) == 0.5
    assert next_reconnect_delay(attempt=2, jitter=0.5) == 4.0
    assert next_reconnect_delay(attempt=10, max_seconds=10, jitter=1.0) == 10.0
    with pytest.raises(AgentTunnelError, match="attempt"):
        next_reconnect_delay(attempt=-1)
    with pytest.raises(AgentTunnelError, match="jitter"):
        next_reconnect_delay(attempt=0, jitter=2.0)


def test_agent_missed_heartbeats_trigger_reconnect() -> None:
    """Agent reconnects after configured missed heartbeats."""
    tracker = MissedHeartbeatTracker(max_missed=2)

    assert not tracker.should_reconnect()
    tracker.mark_missed()
    assert not tracker.should_reconnect()
    tracker.mark_missed()
    assert tracker.should_reconnect()
    tracker.mark_seen()
    assert not tracker.should_reconnect()


def test_forward_ssh_payload_treats_bytes_as_opaque() -> None:
    """The agent does not inspect or transform SSH payload bytes."""
    payload = b"\x00ssh-user-data\xff\r\n"

    forwarded = forward_ssh_payload(payload)

    assert forwarded == payload
    assert isinstance(forwarded, bytes)


async def test_agent_tunnel_dispatches_session_data_to_local_sshd() -> None:
    """Session frames are proxied as opaque bytes to the local sshd stream."""
    tunnel_reader = asyncio.StreamReader()
    tunnel_writer = MemoryWriter()
    local_reader = asyncio.StreamReader()
    local_writer = MemoryWriter()
    target = validate_proxy_target("127.0.0.1", 2222)
    opened_targets = []

    async def connect(
        proxy_target: ProxyTarget,
    ) -> tuple[AsyncReader, AsyncWriter]:
        opened_targets.append(proxy_target)
        return local_reader, local_writer

    tunnel_reader.feed_data(
        encode_frame(
            frame_type=TunnelFrameType.OPEN_SESSION,
            request_id="req-1",
            channel_id="chan-1",
        )
    )
    tunnel_reader.feed_data(
        encode_frame(
            frame_type=TunnelFrameType.SESSION_DATA,
            request_id="req-2",
            channel_id="chan-1",
            payload=b"\x00ssh-user-data\xff",
        )
    )
    tunnel_reader.feed_data(
        encode_frame(
            frame_type=TunnelFrameType.CLOSE_SESSION,
            request_id="req-3",
            channel_id="chan-1",
        )
    )
    tunnel_reader.feed_eof()

    await handle_agent_tunnel_stream(
        tunnel_reader=tunnel_reader,
        tunnel_writer=tunnel_writer,
        proxy_target=target,
        connect_local=connect,
    )

    assert opened_targets == [target]
    assert local_writer.data == b"\x00ssh-user-data\xff"
    assert local_writer.closed


async def test_agent_tunnel_accepts_auth_ok_before_session_open() -> None:
    """The server auth acknowledgement keeps the tunnel open for later sessions."""
    tunnel_reader = asyncio.StreamReader()
    tunnel_writer = MemoryWriter()
    local_reader = asyncio.StreamReader()
    local_writer = MemoryWriter()
    target = validate_proxy_target("127.0.0.1", 2222)
    opened_targets = []

    async def connect(
        proxy_target: ProxyTarget,
    ) -> tuple[AsyncReader, AsyncWriter]:
        opened_targets.append(proxy_target)
        return local_reader, local_writer

    tunnel_reader.feed_data(
        encode_frame(
            frame_type=TunnelFrameType.AUTH_OK,
            request_id="auth",
            channel_id=None,
        )
    )
    tunnel_reader.feed_data(
        encode_frame(
            frame_type=TunnelFrameType.OPEN_SESSION,
            request_id="req-1",
            channel_id="chan-1",
        )
    )
    tunnel_reader.feed_data(
        encode_frame(
            frame_type=TunnelFrameType.CLOSE_SESSION,
            request_id="req-2",
            channel_id="chan-1",
        )
    )
    tunnel_reader.feed_eof()

    await handle_agent_tunnel_stream(
        tunnel_reader=tunnel_reader,
        tunnel_writer=tunnel_writer,
        proxy_target=target,
        connect_local=connect,
    )

    assert opened_targets == [target]
    assert local_writer.closed


async def test_agent_tunnel_forwards_local_sshd_bytes_to_tunnel() -> None:
    """Bytes from local sshd are emitted as tunnel session_data frames."""
    tunnel_reader = asyncio.StreamReader()
    tunnel_writer = MemoryWriter()
    local_reader = asyncio.StreamReader()
    local_writer = MemoryWriter()
    target = validate_proxy_target("127.0.0.1", 2222)

    async def connect(
        _proxy_target: ProxyTarget,
    ) -> tuple[AsyncReader, AsyncWriter]:
        return local_reader, local_writer

    tunnel_reader.feed_data(
        encode_frame(
            frame_type=TunnelFrameType.OPEN_SESSION,
            request_id="req-1",
            channel_id="chan-1",
        )
    )
    local_reader.feed_data(b"ssh-response")
    local_reader.feed_eof()
    await asyncio.sleep(0)
    tunnel_reader.feed_eof()

    await handle_agent_tunnel_stream(
        tunnel_reader=tunnel_reader,
        tunnel_writer=tunnel_writer,
        proxy_target=target,
        connect_local=connect,
    )

    decoded = decode_frame(tunnel_writer.data)
    assert decoded.frame.type is TunnelFrameType.SESSION_DATA
    assert decoded.frame.channel_id == "chan-1"
    assert decoded.payload == b"ssh-response"


async def test_agent_tunnel_rejects_channel_reuse() -> None:
    """A server cannot reuse a live channel id."""
    tunnel_reader = asyncio.StreamReader()
    tunnel_writer = MemoryWriter()
    local_reader = asyncio.StreamReader()
    local_writer = MemoryWriter()

    async def connect(
        _proxy_target: ProxyTarget,
    ) -> tuple[AsyncReader, AsyncWriter]:
        return local_reader, local_writer

    for request_id in ("req-1", "req-2"):
        tunnel_reader.feed_data(
            encode_frame(
                frame_type=TunnelFrameType.OPEN_SESSION,
                request_id=request_id,
                channel_id="chan-1",
            )
        )
    tunnel_reader.feed_eof()

    with pytest.raises(AgentTunnelError, match="reuse"):
        await handle_agent_tunnel_stream(
            tunnel_reader=tunnel_reader,
            tunnel_writer=tunnel_writer,
            proxy_target=validate_proxy_target("127.0.0.1", 2222),
            connect_local=connect,
        )


class MemoryWriter:
    """Small async stream writer test double."""

    def __init__(self) -> None:
        """Initialize captured writes."""
        self.data = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        """Capture bytes written by the tunnel loop."""
        self.data += data

    async def drain(self) -> None:
        """Match the StreamWriter drain API."""

    def close(self) -> None:
        """Record close calls."""
        self.closed = True

    async def wait_closed(self) -> None:
        """Match the StreamWriter close API."""
