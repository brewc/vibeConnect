"""Smoke tests for Phase 0 package entry points."""

from agent.main import main as agent_main
from server.main import main as server_main
from vibeconnect_common import __version__


def test_common_package_has_version() -> None:
    """The shared package exposes a version string."""
    assert __version__ == "0.0.0"


def test_server_entrypoint_returns_success() -> None:
    """The server placeholder entry point exits successfully."""
    assert server_main() == 0


def test_agent_entrypoint_returns_success() -> None:
    """The agent placeholder entry point exits successfully."""
    assert agent_main() == 0
