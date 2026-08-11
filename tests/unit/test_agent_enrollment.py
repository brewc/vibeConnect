"""Tests for agent-side enrollment behavior."""

from __future__ import annotations

import json
import os
import ssl
import uuid
from pathlib import Path

import pytest

from agent import enrollment
from agent.enrollment import (
    AgentEnrollmentConfig,
    AgentEnrollmentError,
    build_enrollment_payload,
    capture_node_ssh_host_public_key,
    complete_enrollment,
    require_enrollment_tls_context,
    rewrite_agent_conf_without_token,
    write_identity_json,
)


def test_build_payload_keeps_private_key_out_of_json(tmp_path: Path) -> None:
    """Enrollment JSON never includes the generated private key."""
    config = _config(tmp_path)
    payload = build_enrollment_payload(
        config=config, node_ssh_host_public_key=_NODE_HOST_KEY
    )

    assert "PRIVATE KEY" in payload.private_key_pem
    assert payload.token == "raw-token"
    assert payload.agent_x509_public_key.startswith("-----BEGIN PUBLIC KEY-----")
    assert payload.to_json() == {
        "node_name": "node-01",
        "token": "raw-token",
        "agent_x509_public_key": payload.agent_x509_public_key,
        "node_ssh_host_public_key": _NODE_HOST_KEY,
    }
    assert payload.private_key_pem not in json.dumps(payload.to_json())


def test_require_enrollment_tls_context_rejects_insecure_tls() -> None:
    """Enrollment cannot run without certificate and hostname validation."""
    secure_context = ssl.create_default_context()
    insecure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure_context.check_hostname = False

    assert require_enrollment_tls_context(secure_context) is secure_context
    with pytest.raises(AgentEnrollmentError, match="TLS validation"):
        require_enrollment_tls_context(None)
    with pytest.raises(AgentEnrollmentError, match="hostname"):
        require_enrollment_tls_context(insecure_context)


def test_write_identity_json_uses_restrictive_permissions(tmp_path: Path) -> None:
    """Identity material is written atomically as owner-only."""
    identity_path = tmp_path / "state" / "identity.json"

    write_identity_json(
        identity_path=identity_path,
        agent_id="agent-01",
        private_key_pem="private",
        agent_x509_cert="cert",
        tunnel_ca_bundle="ca",
        tunnel_host="server.example.test",
        tunnel_port=443,
        tunnel_secret="secret",
    )

    assert stat_mode(identity_path.parent) == 0o700
    assert stat_mode(identity_path) == 0o600
    assert json.loads(identity_path.read_text()) == {
        "agent_id": "agent-01",
        "agent_x509_cert": "cert",
        "private_key": "private",
        "tunnel_ca_bundle": "ca",
        "tunnel_host": "server.example.test",
        "tunnel_port": 443,
        "tunnel_secret": "secret",
    }


def test_complete_enrollment_removes_raw_token_from_agent_conf(tmp_path: Path) -> None:
    """A successful enrollment commit removes the one-time token."""
    config = _config(tmp_path)
    config.agent_conf_path.write_text(
        "[enrollment]\nnode_name = node-01\ntoken = raw-token\n"
    )
    payload = build_enrollment_payload(
        config=config, node_ssh_host_public_key=_NODE_HOST_KEY
    )

    complete_enrollment(config=config, payload=payload, response=_response())

    assert "raw-token" not in config.agent_conf_path.read_text()
    assert config.identity_path.exists()
    assert stat_mode(config.identity_path) == 0o600


def test_complete_enrollment_fails_closed_if_config_rewrite_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Identity is removed when token removal from config fails."""
    config = _config(tmp_path)
    config.agent_conf_path.write_text(
        "[enrollment]\nnode_name = node-01\ntoken = raw-token\n"
    )
    payload = build_enrollment_payload(
        config=config, node_ssh_host_public_key=_NODE_HOST_KEY
    )

    def fail_rewrite(_path: Path) -> None:
        raise AgentEnrollmentError("disk full")

    monkeypatch.setattr(enrollment, "rewrite_agent_conf_without_token", fail_rewrite)

    with pytest.raises(AgentEnrollmentError, match="safely"):
        complete_enrollment(config=config, payload=payload, response=_response())

    assert not config.identity_path.exists()
    assert "raw-token" in config.agent_conf_path.read_text()


def test_rewrite_agent_conf_requires_a_token_line(tmp_path: Path) -> None:
    """Config rewrites fail when there is no token to remove."""
    path = tmp_path / "agent.conf"
    path.write_text("[enrollment]\nnode_name = node-01\n")

    with pytest.raises(AgentEnrollmentError, match="did not contain"):
        rewrite_agent_conf_without_token(path)


def test_capture_node_ssh_host_public_key_requires_loopback_target() -> None:
    """Host key capture is constrained to the local sshd proxy target."""
    calls: list[tuple[str, int]] = []

    def probe(host: str, port: int) -> str:
        calls.append((host, port))
        return f"  {_NODE_HOST_KEY}  "

    assert (
        capture_node_ssh_host_public_key(
            probe=probe, expected_node_ssh_host_public_key=_NODE_HOST_KEY
        )
        == _NODE_HOST_KEY
    )
    assert calls == [("127.0.0.1", 2222)]
    assert (
        capture_node_ssh_host_public_key(
            probe=probe,
            expected_node_ssh_host_public_key=_NODE_HOST_KEY,
            host="127.0.0.2",
            port=2200,
        )
        == _NODE_HOST_KEY
    )
    with pytest.raises(AgentEnrollmentError, match="IPv4 loopback"):
        capture_node_ssh_host_public_key(
            probe=probe,
            expected_node_ssh_host_public_key=_NODE_HOST_KEY,
            host="localhost",
        )
    with pytest.raises(AgentEnrollmentError, match="TCP bounds"):
        capture_node_ssh_host_public_key(
            probe=probe, expected_node_ssh_host_public_key=_NODE_HOST_KEY, port=0
        )
    with pytest.raises(AgentEnrollmentError, match="pinned"):
        capture_node_ssh_host_public_key(
            probe=probe,
            expected_node_ssh_host_public_key="ssh-ed25519 AAAAother",
        )


def stat_mode(path: Path) -> int:
    """Return the POSIX permission bits for a path."""
    return os.stat(path).st_mode & 0o777


def test_complete_enrollment_rejects_non_string_response_fields(tmp_path: Path) -> None:
    """Malformed enrollment response fields are rejected before file creation."""
    config = _config(tmp_path)
    payload = build_enrollment_payload(
        config=config, node_ssh_host_public_key=_NODE_HOST_KEY
    )

    for field, bad_value in (
        ("agent_id", None),
        ("agent_x509_cert", 123),
        ("tunnel_ca_bundle", None),
        ("tunnel_host", ""),
        ("tunnel_secret", None),
    ):
        response = _response()
        response[field] = bad_value
        with pytest.raises(AgentEnrollmentError, match="enrollment response field"):
            complete_enrollment(config=config, payload=payload, response=response)

    assert not config.identity_path.exists()


def test_complete_enrollment_rejects_non_dict_response(tmp_path: Path) -> None:
    """A non-dict enrollment response is rejected."""
    config = _config(tmp_path)
    payload = build_enrollment_payload(
        config=config, node_ssh_host_public_key=_NODE_HOST_KEY
    )

    with pytest.raises(AgentEnrollmentError, match="JSON object"):
        complete_enrollment(
            config=config,
            payload=payload,
            response=f"not a dict: {uuid.uuid4()}",  # type: ignore[arg-type]
        )


def _config(tmp_path: Path) -> AgentEnrollmentConfig:
    return AgentEnrollmentConfig(
        node_name="node-01",
        token="raw-token",
        api_url="https://server.example.test/enroll",
        enrollment_tls_ca_bundle=tmp_path / "enrollment-ca.pem",
        expected_node_ssh_host_public_key=_NODE_HOST_KEY,
        identity_path=tmp_path / "state" / "identity.json",
        agent_conf_path=tmp_path / "agent.conf",
    )


def _response() -> dict[str, object]:
    return {
        "agent_id": "agent-01",
        "agent_x509_cert": "cert",
        "tunnel_ca_bundle": "ca",
        "tunnel_host": "server.example.test",
        "tunnel_port": 443,
        "tunnel_secret": "secret",
    }


_NODE_HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINodeHostKey node-01"
