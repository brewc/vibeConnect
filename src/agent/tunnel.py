"""Agent-side tunnel runtime guardrails."""

from __future__ import annotations

import random
from dataclasses import dataclass
from ssl import SSLContext
from typing import cast


class AgentTunnelError(RuntimeError):
    """Raised when the agent tunnel cannot proceed safely."""


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
    if host != "127.0.0.1" or port != 2222:
        raise AgentTunnelError("agent proxy target must be 127.0.0.1:2222")
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
