"""Loopback health, readiness, and metrics endpoints."""

from __future__ import annotations

from dataclasses import dataclass

from aiohttp import web

DEFAULT_HEALTH_BIND = "127.0.0.1"
DEFAULT_HEALTH_PORT = 9100


@dataclass(frozen=True, slots=True)
class HealthSnapshot:
    """Secret-free service state exposed by health endpoints."""

    database_ready: bool
    replay_ready: bool
    tunnel_ready: bool
    live_tunnels: int
    active_sessions: int
    failed_enrollments: int
    failed_logins: int
    issued_certificates: int
    replay_write_failures: int
    auth_provider_failures: int


HEALTH_SNAPSHOT_KEY = web.AppKey("health_snapshot", HealthSnapshot)


def build_health_app(snapshot: HealthSnapshot) -> web.Application:
    """Build an aiohttp app exposing only secret-free operational state."""
    app = web.Application()
    app[HEALTH_SNAPSHOT_KEY] = snapshot
    app.router.add_get("/health", _health)
    app.router.add_get("/ready", _ready)
    app.router.add_get("/metrics", _metrics)
    return app


async def _health(request: web.Request) -> web.Response:
    snapshot = _snapshot(request)
    return web.json_response(health_payload(snapshot))


async def _ready(request: web.Request) -> web.Response:
    snapshot = _snapshot(request)
    ready = snapshot.database_ready and snapshot.replay_ready and snapshot.tunnel_ready
    return web.json_response(readiness_payload(snapshot), status=200 if ready else 503)


async def _metrics(request: web.Request) -> web.Response:
    snapshot = _snapshot(request)
    return web.Response(text=render_metrics(snapshot), content_type="text/plain")


def health_payload(snapshot: HealthSnapshot) -> dict[str, str]:
    """Return the public health payload."""
    return {
        "status": "ok",
        "tunnel": "ready" if snapshot.tunnel_ready else "degraded",
    }


def readiness_payload(snapshot: HealthSnapshot) -> dict[str, object]:
    """Return the public readiness payload."""
    ready = snapshot.database_ready and snapshot.replay_ready and snapshot.tunnel_ready
    return {
        "ready": ready,
        "dependencies": {
            "database": snapshot.database_ready,
            "replay": snapshot.replay_ready,
            "tunnel": snapshot.tunnel_ready,
        },
    }


def render_metrics(snapshot: HealthSnapshot) -> str:
    """Render Prometheus text metrics without labels or secret-bearing values."""
    lines = [
        f"vibeconnect_live_tunnels {snapshot.live_tunnels}",
        f"vibeconnect_active_sessions {snapshot.active_sessions}",
        f"vibeconnect_failed_enrollments {snapshot.failed_enrollments}",
        f"vibeconnect_failed_logins {snapshot.failed_logins}",
        f"vibeconnect_issued_certificates {snapshot.issued_certificates}",
        f"vibeconnect_replay_write_failures {snapshot.replay_write_failures}",
        f"vibeconnect_auth_provider_failures {snapshot.auth_provider_failures}",
    ]
    return "\n".join(lines) + "\n"


def _snapshot(request: web.Request) -> HealthSnapshot:
    snapshot = request.app[HEALTH_SNAPSHOT_KEY]
    if not isinstance(snapshot, HealthSnapshot):
        raise RuntimeError("health snapshot is not configured")
    return snapshot
