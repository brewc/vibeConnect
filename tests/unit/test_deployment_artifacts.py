"""Tests for packaging and runtime hardening artifacts."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_pyinstaller_build_script_builds_both_entrypoints() -> None:
    """The package build script includes both onefile binaries."""
    script = (ROOT / "scripts" / "build_pyinstaller.sh").read_text(encoding="utf-8")

    assert "python -m build" in script
    assert "PYINSTALLER_CONFIG_DIR" in script
    assert (
        "pyinstaller --onefile --specpath build/pyinstaller "
        "-n vibeconnect-server src/server/main.py"
    ) in script
    assert (
        "pyinstaller --onefile --specpath build/pyinstaller "
        "-n vibeconnect-agent src/agent/main.py"
    ) in script


def test_agent_systemd_unit_contains_hardening_settings() -> None:
    """The sample agent unit runs as vibe with systemd hardening."""
    unit = (ROOT / "deploy" / "systemd" / "vibeconnect-agent.service").read_text(
        encoding="utf-8"
    )

    for required in (
        "User=vibe",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=strict",
        "ReadWritePaths=/var/lib/vibeconnect",
    ):
        assert required in unit


def test_server_systemd_unit_avoids_long_term_root() -> None:
    """The sample server unit binds port 22 without running as root."""
    unit = (ROOT / "deploy" / "systemd" / "vibeconnect-server.service").read_text(
        encoding="utf-8"
    )

    assert "User=vibeconnectd" in unit
    assert "AmbientCapabilities=CAP_NET_BIND_SERVICE" in unit
    assert "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in unit
    assert "NoNewPrivileges=true" in unit


def test_filesystem_manifest_contains_required_paths_and_modes() -> None:
    """The filesystem manifest records safe defaults for config and state."""
    manifest = (ROOT / "deploy" / "filesystem.manifest").read_text(encoding="utf-8")

    for required in (
        "/etc/vibeconnectd/config.yaml root vibeconnectd 0640 file",
        "/etc/vibeconnectd/secrets root vibeconnectd 0750 dir",
        "/var/lib/vibeconnectd/replay vibeconnectd vibeconnectd 0700 dir",
        "/etc/vibeconnect/agent.conf root vibe 0640 file",
        "/var/lib/vibeconnect/identity.json vibe vibe 0600 file",
    ):
        assert required in manifest
