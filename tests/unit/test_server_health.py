"""Tests for secret-free health, readiness, and metrics output."""

from __future__ import annotations

import json

import pytest
from aiohttp.test_utils import make_mocked_request

from server import health as health_module
from server.health import (
    HealthSnapshot,
    build_health_app,
    health_payload,
    readiness_payload,
    render_metrics,
)


def test_health_app_registers_loopback_safe_routes() -> None:
    """The app exposes only health, readiness, and metrics routes."""
    app = build_health_app(_snapshot())
    routes: set[str] = set()
    for route in app.router.routes():
        assert route.resource is not None
        routes.add(route.resource.canonical)

    assert routes == {"/health", "/ready", "/metrics"}


def test_health_outputs_do_not_expose_secrets() -> None:
    """Health, readiness, and metrics omit secret-bearing operational details."""
    snapshot = _snapshot()

    combined = "\n".join(
        [
            json.dumps(health_payload(snapshot), sort_keys=True),
            json.dumps(readiness_payload(snapshot), sort_keys=True),
            render_metrics(snapshot),
        ]
    )

    for forbidden in (
        "postgresql://",
        "password",
        "token",
        "secret",
        "dsn",
        "group",
        ".cast",
        "/var/lib",
    ):
        assert forbidden not in combined.lower()


def test_readiness_reports_dependency_state_without_details() -> None:
    """Readiness exposes dependency booleans without names or paths."""
    payload = readiness_payload(_snapshot(replay_ready=False))

    assert payload == {
        "ready": False,
        "dependencies": {
            "database": True,
            "replay": False,
            "tunnel": True,
        },
    }


@pytest.mark.asyncio
async def test_health_route_handlers_return_expected_statuses() -> None:
    """The aiohttp handlers render the same secret-free payloads."""
    app = build_health_app(_snapshot(replay_ready=False))

    health_response = await health_module._health(
        make_mocked_request("GET", "/health", app=app)
    )
    ready_response = await health_module._ready(
        make_mocked_request("GET", "/ready", app=app)
    )
    metrics_response = await health_module._metrics(
        make_mocked_request("GET", "/metrics", app=app)
    )

    assert health_response.status == 200
    assert ready_response.status == 503
    assert metrics_response.status == 200
    assert metrics_response.text is not None
    assert "vibeconnect_live_tunnels 1" in metrics_response.text


def _snapshot(
    *,
    database_ready: bool = True,
    replay_ready: bool = True,
    tunnel_ready: bool = True,
) -> HealthSnapshot:
    return HealthSnapshot(
        database_ready=database_ready,
        replay_ready=replay_ready,
        tunnel_ready=tunnel_ready,
        live_tunnels=1,
        active_sessions=2,
        failed_enrollments=3,
        failed_logins=4,
        issued_certificates=5,
        replay_write_failures=6,
        auth_provider_failures=7,
    )
