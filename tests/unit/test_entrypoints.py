"""Smoke tests for Phase 0 package entry points."""

import argparse
from collections.abc import Sequence
from pathlib import Path

import pytest
from asyncpg import PostgresError  # type: ignore[import-untyped]

from agent import main as agent_main_module
from server import main as server_main_module
from vibeconnect_common import __version__


def test_common_package_has_version() -> None:
    """The shared package exposes a version string."""
    assert __version__ == "0.0.0"


def test_server_entrypoint_returns_success() -> None:
    """The server placeholder entry point exits successfully."""
    assert server_main_module.main([]) == 0


def test_server_help_describes_subcommands(capsys: pytest.CaptureFixture[str]) -> None:
    """Top-level server help explains each positional subcommand."""
    with pytest.raises(SystemExit) as exc_info:
        server_main_module.main(["--help"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    normalized = " ".join(output.split())
    assert "Manage and run the vibeConnect bastion server." in normalized
    assert "start" in normalized
    assert "run the bastion server listeners from config.yaml" in normalized
    assert "connect-agent" in normalized
    assert "launch OpenSSH to connect through the bastion to one agent" in normalized
    assert "list-agents" in normalized
    assert "list enrolled agents and their registration status" in normalized


def test_server_migrate_requires_postgres_dsn() -> None:
    """Migration bootstrap needs an explicit Postgres DSN."""
    with pytest.raises(SystemExit):
        server_main_module.main(["migrate", "--config", "/tmp/missing.yaml"])


def test_server_migrate_uses_env_dsn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Migration bootstrap accepts a local Postgres DSN from the environment."""
    calls: list[tuple[str, str]] = []

    async def run_migrations(*, dsn: str, migrations_dir: object) -> None:
        calls.append((dsn, str(migrations_dir)))

    monkeypatch.setenv(
        "VIBECONNECT_POSTGRES_DSN",
        "postgresql://vibeconnect:vibeconnect@127.0.0.1:5432/vibeconnect",
    )
    monkeypatch.setattr(server_main_module, "_run_migrations", run_migrations)

    assert server_main_module.main(["migrate"]) == 0
    assert calls == [
        (
            "postgresql://vibeconnect:vibeconnect@127.0.0.1:5432/vibeconnect",
            str(server_main_module.DEFAULT_MIGRATIONS_DIR),
        )
    ]


def test_server_migrate_uses_config_dsn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Migration bootstrap uses the configured Postgres DSN by default."""
    calls: list[tuple[str, str]] = []
    config_path = _write_server_config(tmp_path)

    async def run_migrations(*, dsn: str, migrations_dir: object) -> None:
        calls.append((dsn, str(migrations_dir)))

    monkeypatch.delenv("VIBECONNECT_POSTGRES_DSN", raising=False)
    monkeypatch.setattr(server_main_module, "_run_migrations", run_migrations)

    assert server_main_module.main(["migrate", "--config", str(config_path)]) == 0
    assert calls == [
        (
            "postgresql://vibeconnect:from-config@127.0.0.1:5432/vibeconnect",
            str(server_main_module.DEFAULT_MIGRATIONS_DIR),
        )
    ]


def test_server_migrate_reports_connection_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Migration bootstrap reports database failures without a traceback."""

    async def run_migrations(*, dsn: str, migrations_dir: object) -> None:
        raise PostgresError("role does not exist")

    monkeypatch.setattr(server_main_module, "_run_migrations", run_migrations)

    assert (
        server_main_module.main(["migrate", "--postgres-dsn", "postgresql://bad"]) == 1
    )
    assert "migration failed: role does not exist" in capsys.readouterr().err


def test_server_start_uses_config_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Server start dispatches through the configured YAML path."""
    calls: list[str] = []

    async def run_server_start(*, config_path: object) -> None:
        calls.append(str(config_path))

    monkeypatch.setattr(server_main_module, "_run_server_start", run_server_start)

    assert server_main_module.main(["start", "--config", "/tmp/server.yaml"]) == 0
    assert calls == ["/tmp/server.yaml"]


def test_server_start_reports_runtime_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Server start reports bootstrap failures without a traceback."""

    async def run_server_start(*, config_path: object) -> None:
        raise RuntimeError(f"failed {config_path}")

    monkeypatch.setattr(server_main_module, "_run_server_start", run_server_start)

    assert server_main_module.main(["start", "--config", "/tmp/server.yaml"]) == 1
    assert "server start failed: failed /tmp/server.yaml" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("argv", "command"),
    [
        (
            [
                "create-agent",
                "--node-name",
                "node-01",
                "--node-host-key-file",
                "host.pub",
            ],
            "create-agent",
        ),
        (["list-agents"], "list-agents"),
        (["revoke-agent", "--node-name", "node-01"], "revoke-agent"),
        (["rotate-tunnel-secret", "--node-name", "node-01"], "rotate-tunnel-secret"),
        (
            [
                "update-node-host-key",
                "--node-name",
                "node-01",
                "--host-key-file",
                "host.pub",
            ],
            "update-node-host-key",
        ),
        (["expire-token", "--node-name", "node-01"], "expire-token"),
        (
            ["list-sessions", "--node-name", "node-01", "--user", "alice"],
            "list-sessions",
        ),
    ],
)
def test_server_admin_commands_use_local_runner(
    argv: list[str],
    command: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Local admin CLI commands use the PostgreSQL-backed local runner."""
    calls: list[tuple[str, str]] = []

    async def run_admin_command(*, dsn: str, args: argparse.Namespace) -> str:
        calls.append((dsn, args.command))
        return "ok"

    config_path = _write_server_config(tmp_path)
    monkeypatch.delenv("VIBECONNECT_POSTGRES_DSN", raising=False)
    monkeypatch.setattr(server_main_module, "_run_admin_command", run_admin_command)

    assert server_main_module.main([*argv, "--config", str(config_path)]) == 0
    assert calls == [
        (
            "postgresql://vibeconnect:from-config@127.0.0.1:5432/vibeconnect",
            command,
        )
    ]
    assert capsys.readouterr().out == "ok\n"


def test_create_agent_cli_accepts_server_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Create-agent forwards selected public server and proxy settings."""
    calls: list[tuple[str, str, int, int, str, int]] = []

    async def run_admin_command(*, dsn: str, args: argparse.Namespace) -> str:
        calls.append(
            (
                dsn,
                args.server_host,
                args.enrollment_port,
                args.tunnel_port,
                args.proxy_host,
                args.proxy_port,
            )
        )
        return "ok"

    monkeypatch.setenv(
        "VIBECONNECT_POSTGRES_DSN",
        "postgresql://vibeconnect:vibeconnect@127.0.0.1:5432/vibeconnect",
    )
    monkeypatch.setattr(server_main_module, "_run_admin_command", run_admin_command)

    assert (
        server_main_module.main(
            [
                "create-agent",
                "--node-name",
                "node-01",
                "--node-host-key-file",
                "host.pub",
                "--server-host",
                "bastion.example.test",
                "--enrollment-port",
                "8443",
                "--tunnel-port",
                "9444",
                "--proxy-host",
                "127.0.0.2",
                "--proxy-port",
                "2200",
            ]
        )
        == 0
    )
    assert calls == [
        (
            "postgresql://vibeconnect:vibeconnect@127.0.0.1:5432/vibeconnect",
            "bastion.example.test",
            8443,
            9444,
            "127.0.0.2",
            2200,
        )
    ]


def test_server_connect_agent_prints_dry_run_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The connect helper renders the exact OpenSSH command without a DB."""
    assert (
        server_main_module.main(
            [
                "connect-agent",
                "--server",
                "vibeconnect.example.test",
                "--node-name",
                "node-01",
                "--user",
                "alice",
                "--dry-run",
            ]
        )
        == 0
    )

    assert capsys.readouterr().out == (
        "ssh -p 22 -o ForwardAgent=no -o ClearAllForwardings=yes "
        "alice@vibeconnect.example.test node-01\n"
    )


def test_server_connect_agent_runs_openssh_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The connect helper executes OpenSSH with the selected agent node name."""
    calls: list[tuple[str, ...]] = []
    identity_file = tmp_path / "user-cert-key"
    identity_file.write_text("key", encoding="utf-8")

    def run_connect_command(command: Sequence[str]) -> int:
        calls.append(tuple(str(part) for part in command))
        return 23

    monkeypatch.setattr(server_main_module, "_run_connect_command", run_connect_command)

    assert (
        server_main_module.main(
            [
                "connect-agent",
                "--server",
                "vibeconnect.example.test",
                "--node-name",
                "node-01",
                "--port",
                "2222",
                "--identity-file",
                str(identity_file),
            ]
        )
        == 23
    )
    assert calls == [
        (
            "ssh",
            "-p",
            "2222",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-i",
            str(identity_file),
            "vibeconnect.example.test",
            "node-01",
        )
    ]


def test_agent_entrypoint_returns_success() -> None:
    """The agent placeholder entry point exits successfully."""
    assert agent_main_module.main([]) == 0


def test_agent_entrypoint_reads_console_script_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installed agent console scripts dispatch using process arguments."""
    calls: list[str] = []

    async def run_enroll(config_path: object) -> None:
        calls.append(str(config_path))

    monkeypatch.setattr(
        "sys.argv",
        ["vibeconnect-agent", "enroll", "--config", "/tmp/agent.conf"],
    )
    monkeypatch.setattr("agent.main._run_enroll", run_enroll)

    assert agent_main_module.main() == 0
    assert calls == ["/tmp/agent.conf"]


def test_agent_enroll_command_uses_config_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Agent enrollment mode dispatches through the configured path."""
    calls: list[str] = []

    async def run_enroll(config_path: object) -> None:
        calls.append(str(config_path))

    monkeypatch.setattr("agent.main._run_enroll", run_enroll)

    assert agent_main_module.main(["enroll", "--config", "/tmp/agent.conf"]) == 0
    assert calls == ["/tmp/agent.conf"]


def test_agent_run_command_uses_config_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Agent tunnel mode dispatches through the configured path."""
    calls: list[str] = []

    async def run_tunnel(config_path: object) -> None:
        calls.append(str(config_path))

    monkeypatch.setattr("agent.main._run_tunnel", run_tunnel)

    assert agent_main_module.main(["run", "--config", "/tmp/agent.conf"]) == 0
    assert calls == ["/tmp/agent.conf"]


def test_agent_command_reports_runtime_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Agent runtime failures are reported without printing secrets or tracebacks."""

    async def run_enroll(config_path: object) -> None:
        raise RuntimeError(f"failed {config_path}")

    monkeypatch.setattr("agent.main._run_enroll", run_enroll)

    assert agent_main_module.main(["enroll", "--config", "/tmp/agent.conf"]) == 1
    assert "agent command failed: failed /tmp/agent.conf" in capsys.readouterr().err


def test_agent_keyscan_prefers_ed25519_host_key() -> None:
    """Agent enrollment pins the strongest stable host key from keyscan output."""
    keyscan = "\n".join(
        [
            "# 127.0.0.1:2222 SSH-2.0-OpenSSH",
            "127.0.0.1 ssh-rsa AAAARsaKey",
            "127.0.0.1 ecdsa-sha2-nistp256 AAAAEcdsaKey",
            "127.0.0.1 ssh-ed25519 AAAAEd25519Key",
        ]
    )

    assert (
        agent_main_module._host_key_from_keyscan(keyscan)
        == "ssh-ed25519 AAAAEd25519Key"
    )


def _write_server_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "server.config.yaml"
    dsn_path = tmp_path / "postgres.dsn"
    dsn_path.write_text(
        "postgresql://vibeconnect:from-config@127.0.0.1:5432/vibeconnect\n",
        encoding="utf-8",
    )
    config_path.write_text(
        "\n".join(
            [
                "server:",
                "  listen_ssh: 0.0.0.0:2222",
                "  listen_tunnel: 0.0.0.0:4444",
                "  listen_api: 0.0.0.0:4443",
                "  tunnel_public_host: vibeconnect.example.test",
                "  ssh_host_key_path: /etc/vibeconnectd/ssh_host_ed25519_key",
                "  tls_cert_path: /etc/vibeconnectd/server.crt",
                "  tls_key_path: /etc/vibeconnectd/server.key",
                "  enrollment_tls_ca_bundle_path: /etc/vibeconnectd/enrollment-ca.crt",
                "postgres:",
                f"  dsn_file: {dsn_path}",
                "metrics:",
                "  listen: 127.0.0.1:9100",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return config_path
