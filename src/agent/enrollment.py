"""Agent-side one-time enrollment helpers."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from ssl import SSLContext

from cryptography.hazmat.primitives import serialization

from vibeconnect_common.crypto import generate_agent_private_key
from vibeconnect_common.identifiers import validate_node_name


class AgentEnrollmentError(RuntimeError):
    """Raised when agent enrollment cannot complete safely."""


@dataclass(frozen=True, slots=True)
class AgentEnrollmentConfig:
    """Minimum config required for one-time enrollment."""

    node_name: str
    token: str
    api_url: str
    enrollment_tls_ca_bundle: Path
    expected_node_ssh_host_public_key: str
    identity_path: Path
    agent_conf_path: Path
    proxy_target_host: str = "127.0.0.1"
    proxy_target_port: int = 2222


@dataclass(frozen=True, slots=True)
class AgentEnrollmentPayload:
    """Payload the agent sends to the server enrollment endpoint."""

    node_name: str
    token: str
    agent_x509_public_key: str
    node_ssh_host_public_key: str
    private_key_pem: str

    def to_json(self) -> dict[str, str]:
        """Serialize the public enrollment payload."""
        return {
            "node_name": self.node_name,
            "token": self.token,
            "agent_x509_public_key": self.agent_x509_public_key,
            "node_ssh_host_public_key": self.node_ssh_host_public_key,
        }


def build_enrollment_payload(
    *, config: AgentEnrollmentConfig, node_ssh_host_public_key: str
) -> AgentEnrollmentPayload:
    """Generate local agent key material and build the enrollment request."""
    safe_node_name = validate_node_name(config.node_name)
    private_key = generate_agent_private_key()
    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return AgentEnrollmentPayload(
        node_name=safe_node_name,
        token=config.token,
        agent_x509_public_key=public_key_pem,
        node_ssh_host_public_key=node_ssh_host_public_key,
        private_key_pem=private_key_pem,
    )


def require_enrollment_tls_context(context: SSLContext | None) -> SSLContext:
    """Reject insecure enrollment TLS bypasses."""
    if context is None:
        raise AgentEnrollmentError("enrollment TLS validation is required")
    if not context.check_hostname:
        raise AgentEnrollmentError("enrollment TLS hostname validation is required")
    return context


def write_identity_json(
    *,
    identity_path: Path,
    agent_id: str,
    private_key_pem: str,
    agent_x509_cert: str,
    tunnel_ca_bundle: str,
    tunnel_host: str,
    tunnel_port: int,
    tunnel_secret: str,
) -> None:
    """Atomically write `identity.json` with mode 0600."""
    identity_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(identity_path.parent, 0o700)
    data = {
        "agent_id": agent_id,
        "private_key": private_key_pem,
        "agent_x509_cert": agent_x509_cert,
        "tunnel_ca_bundle": tunnel_ca_bundle,
        "tunnel_host": tunnel_host,
        "tunnel_port": tunnel_port,
        "tunnel_secret": tunnel_secret,
    }
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{identity_path.name}.", suffix=".tmp", dir=identity_path.parent
    )
    try:
        os.chmod(temp_name, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(data, file, separators=(",", ":"), sort_keys=True)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_name, identity_path)
        os.chmod(identity_path, 0o600)
    except Exception:
        with suppress(OSError):
            os.close(fd)
        with suppress(FileNotFoundError):
            Path(temp_name).unlink()
        raise


def complete_enrollment(
    *,
    config: AgentEnrollmentConfig,
    payload: AgentEnrollmentPayload,
    response: dict[str, object],
) -> None:
    """Persist enrollment identity and remove the one-time token from config."""
    if not isinstance(response, dict):
        raise AgentEnrollmentError("enrollment response must be a JSON object")
    tunnel_port = _validate_response_int(response, "tunnel_port")
    agent_id = _validate_response_str(response, "agent_id")
    agent_x509_cert = _validate_response_str(response, "agent_x509_cert")
    tunnel_ca_bundle = _validate_response_str(response, "tunnel_ca_bundle")
    tunnel_host = _validate_response_str(response, "tunnel_host")
    tunnel_secret = _validate_response_str(response, "tunnel_secret")
    try:
        write_identity_json(
            identity_path=config.identity_path,
            agent_id=agent_id,
            private_key_pem=payload.private_key_pem,
            agent_x509_cert=agent_x509_cert,
            tunnel_ca_bundle=tunnel_ca_bundle,
            tunnel_host=tunnel_host,
            tunnel_port=tunnel_port,
            tunnel_secret=tunnel_secret,
        )
        rewrite_agent_conf_without_token(config.agent_conf_path)
    except Exception as exc:
        with suppress(FileNotFoundError):
            config.identity_path.unlink()
        raise AgentEnrollmentError("enrollment did not complete safely") from exc


def _validate_response_str(response: dict[str, object], key: str) -> str:
    """Validate one string field from the enrollment response."""
    value = response.get(key)
    if not isinstance(value, str) or not value:
        raise AgentEnrollmentError(
            f"enrollment response field {key} must be a non-empty string"
        )
    return value


def _validate_response_int(response: dict[str, object], key: str) -> int:
    """Validate one integer field from the enrollment response."""
    value = response.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise AgentEnrollmentError(
            f"enrollment response field {key} must be an integer"
        )
    return value


def rewrite_agent_conf_without_token(path: Path) -> None:
    """Rewrite agent config without the raw enrollment token."""
    original = path.read_text()
    rewritten_lines = [
        line
        for line in original.splitlines()
        if not line.strip().lower().startswith("token")
    ]
    if len(rewritten_lines) == len(original.splitlines()):
        raise AgentEnrollmentError("agent.conf did not contain enrollment token")
    temp_path = path.with_name(f".{path.name}.tmp")
    temp_path.write_text("\n".join(rewritten_lines) + "\n")
    os.chmod(temp_path, 0o600)
    os.replace(temp_path, path)


def capture_node_ssh_host_public_key(
    *,
    probe: Callable[[str, int], str],
    expected_node_ssh_host_public_key: str,
    host: str = "127.0.0.1",
    port: int = 2222,
) -> str:
    """Capture and verify the local sshd host public key."""
    if not host.startswith("127."):
        raise AgentEnrollmentError("node sshd host key must be read from IPv4 loopback")
    if not 1 <= port <= 65535:
        raise AgentEnrollmentError("node sshd host key port is outside TCP bounds")
    public_key = probe(host, port).strip()
    if not public_key:
        raise AgentEnrollmentError("node sshd host public key is empty")
    if public_key != expected_node_ssh_host_public_key.strip():
        raise AgentEnrollmentError("node sshd host key does not match pinned key")
    return public_key
