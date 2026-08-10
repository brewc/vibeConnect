"""Opt-in live integration stack execution."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_live_compose_stack() -> None:
    """Run the full Docker integration stack when explicitly enabled."""
    if os.environ.get("VIBECONNECT_RUN_INTEGRATION") != "1":
        pytest.skip("set VIBECONNECT_RUN_INTEGRATION=1 to run Docker integration")

    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "tests/integration/docker-compose.yml",
            "up",
            "--abort-on-container-exit",
        ],
        cwd=ROOT,
        check=True,
    )
