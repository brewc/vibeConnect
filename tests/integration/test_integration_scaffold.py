"""Static integration-environment checks."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent


def test_compose_defines_required_services() -> None:
    """The integration compose stack includes all required services."""
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    for service in ("postgres:", "ldap:", "node:", "server:", "agent:"):
        assert service in compose
    assert "postgresql://vibeconnect:vibeconnect@postgres:5432/vibeconnect" in compose
    assert "127.0.0.1:2222:2222" in compose
    assert "ldap/Dockerfile" in compose
    assert "tests/integration/server.Dockerfile" in compose
    assert "tests/integration/agent.Dockerfile" in compose


def test_node_sshd_config_is_hardened_for_cert_jumps() -> None:
    """The node sshd fixture enforces cert auth and disables forwarding."""
    sshd_config = (ROOT / "node" / "sshd_config").read_text(encoding="utf-8")

    required_directives = {
        "ListenAddress 127.0.0.1",
        "TrustedUserCAKeys /etc/ssh/vibeconnect-ca.pub",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "PubkeyAuthentication yes",
        "AllowTcpForwarding no",
        "X11Forwarding no",
        "AllowAgentForwarding no",
        "Subsystem sftp disabled",
    }
    for directive in required_directives:
        assert directive in sshd_config


def test_integration_fixtures_include_user_node_and_group() -> None:
    """The fixtures include one LDAP user and one local-node account target."""
    ldif = (ROOT / "fixtures" / "users.ldif").read_text(encoding="utf-8")
    node_dockerfile = (ROOT / "node" / "Dockerfile").read_text(encoding="utf-8")
    agent_conf = (ROOT / "fixtures" / "agent.conf").read_text(encoding="utf-8")

    assert "uid=alice,ou=users,dc=example,dc=test" in ldif
    assert "cn=vibeconnect-users" in ldif
    assert "useradd --create-home --shell /bin/bash alice" in node_dockerfile
    assert "node_name = node-01" in agent_conf
    assert "target = 127.0.0.1:2222" in agent_conf


@pytest.mark.integration
def test_live_integration_command_is_documented() -> None:
    """The live integration command remains explicit and opt-in."""
    compose_path = ROOT / "docker-compose.yml"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert compose_path.exists()
    assert (
        "docker compose -f tests/integration/docker-compose.yml up "
        "--abort-on-container-exit"
    ) in readme
