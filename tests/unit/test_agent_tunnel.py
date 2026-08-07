"""Tests for agent-side tunnel guardrails."""

from __future__ import annotations

import ssl

import pytest

from agent.tunnel import (
    AgentTunnelError,
    MissedHeartbeatTracker,
    forward_ssh_payload,
    next_reconnect_delay,
    require_tunnel_tls_context,
    validate_proxy_target,
)


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
    """Agent raw TCP proxying is constrained to 127.0.0.1:2222."""
    assert validate_proxy_target("127.0.0.1", 2222).host == "127.0.0.1"
    with pytest.raises(AgentTunnelError, match="127.0.0.1:2222"):
        validate_proxy_target("localhost", 2222)
    with pytest.raises(AgentTunnelError, match="127.0.0.1:2222"):
        validate_proxy_target("127.0.0.1", 22)


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
