"""Server-side SSH host-key validation helpers."""

from __future__ import annotations

import asyncssh


def validate_node_ssh_host_public_key(value: str) -> str:
    """Validate and normalize an OpenSSH public host key."""
    host_key = value.strip()
    if not host_key:
        raise ValueError("node sshd host key is required")
    try:
        asyncssh.import_public_key(host_key)
    except (asyncssh.Error, ValueError) as exc:
        raise ValueError("node sshd host key is invalid") from exc
    key_parts = host_key.split()
    if len(key_parts) < 2:
        raise ValueError("node sshd host key is invalid")
    return " ".join(key_parts[:2])
