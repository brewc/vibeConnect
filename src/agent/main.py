"""Command-line entry point for the VibeConnect agent."""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
import tempfile
from configparser import ConfigParser, SectionProxy
from pathlib import Path

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from agent.enrollment import (
    AgentEnrollmentConfig,
    AgentEnrollmentError,
    build_enrollment_payload,
    complete_enrollment,
    require_enrollment_tls_context,
)
from agent.tunnel import (
    AgentTunnelError,
    handle_agent_tunnel_stream,
    next_reconnect_delay,
    require_tunnel_tls_context,
    validate_proxy_target,
)
from vibeconnect_common.config import (
    ConfigError,
    load_agent_config,
    validate_agent_config,
)
from vibeconnect_common.models import AgentConfig, TunnelFrameType
from vibeconnect_common.tunnel import DEFAULT_FRAME_MAX_BYTES, encode_frame

DEFAULT_CONFIG_PATH = Path("/etc/vibeconnect/agent.conf")


def main(argv: list[str] | None = None) -> int:
    """Run the agent CLI.

    Returns:
        Process exit status.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        return 0
    try:
        if args.command == "enroll":
            asyncio.run(_run_enroll(args.config))
            return 0
        if args.command == "run":
            asyncio.run(_run_tunnel(args.config))
            return 0
    except (
        aiohttp.ClientError,
        AgentEnrollmentError,
        AgentTunnelError,
        ConfigError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        print(f"agent command failed: {exc}", file=sys.stderr)
        return 1
    raise AssertionError(f"unhandled agent command: {args.command}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vibeconnect-agent")
    subcommands = parser.add_subparsers(dest="command")
    for command in ("enroll", "run"):
        subcommand = subcommands.add_parser(command)
        subcommand.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    return parser


async def _run_enroll(config_path: Path) -> None:
    """Run one-time enrollment from an agent config file."""
    config = _load_enrollment_config(config_path)
    host_key = _host_key_from_keyscan(
        await _run_ssh_keyscan(config.proxy_target_host, config.proxy_target_port)
    )
    payload = build_enrollment_payload(
        config=config,
        node_ssh_host_public_key=host_key,
    )
    context = require_enrollment_tls_context(
        ssl.create_default_context(cafile=str(config.enrollment_tls_ca_bundle))
    )
    async with (
        aiohttp.ClientSession() as session,
        session.post(
            config.api_url,
            json=payload.to_json(),
            ssl=context,
        ) as response,
    ):
        if response.status != 200:
            raise AgentEnrollmentError("enrollment request failed")
        body = await response.json()
    if not isinstance(body, dict):
        raise AgentEnrollmentError("enrollment response must be a JSON object")
    complete_enrollment(config=config, payload=payload, response=body)


async def _run_tunnel(config_path: Path) -> None:
    """Run persistent tunnel mode from an agent config file."""
    config = load_agent_config(config_path)
    validate_agent_config(config)
    attempt = 0
    while True:
        try:
            await _run_tunnel_once(config)
            attempt = 0
        except (AgentTunnelError, OSError, asyncio.IncompleteReadError):
            delay = next_reconnect_delay(
                attempt=attempt,
                max_seconds=float(config.reconnect_backoff_max_seconds),
            )
            attempt += 1
            await asyncio.sleep(delay)


async def _run_tunnel_once(config: AgentConfig) -> None:
    """Open one authenticated tunnel connection and proxy frames until EOF."""
    identity = _load_identity(config.identity_path)
    target = validate_proxy_target(config.proxy_target_host, config.proxy_target_port)
    context = _build_tunnel_tls_context(config=config, identity=identity)
    reader, writer = await asyncio.open_connection(
        str(identity["tunnel_host"]),
        int(str(identity["tunnel_port"])),
        ssl=context,
        server_hostname=str(identity["tunnel_host"]),
    )
    try:
        writer.write(_auth_frame(config=config, identity=identity))
        await writer.drain()
        await handle_agent_tunnel_stream(
            tunnel_reader=reader,
            tunnel_writer=writer,
            proxy_target=target,
            max_frame_bytes=DEFAULT_FRAME_MAX_BYTES,
        )
    finally:
        writer.close()
        await writer.wait_closed()


def _load_enrollment_config(path: Path) -> AgentEnrollmentConfig:
    parser = _read_parser(path)
    enrollment = _section(parser, "enrollment")
    identity = parser["identity"] if parser.has_section("identity") else {}
    proxy = _section(parser, "proxy")
    proxy_host, proxy_port = _parse_host_port(_require(proxy, "target", "proxy.target"))
    return AgentEnrollmentConfig(
        node_name=_require(enrollment, "node_name", "enrollment.node_name"),
        token=_require(enrollment, "token", "enrollment.token"),
        api_url=_require(enrollment, "api_url", "enrollment.api_url"),
        enrollment_tls_ca_bundle=Path(
            _require(enrollment, "tls_ca_bundle", "enrollment.tls_ca_bundle")
        ).expanduser(),
        identity_path=Path(
            identity.get("path", "/var/lib/vibeconnect/identity.json")
        ).expanduser(),
        agent_conf_path=path,
        proxy_target_host=proxy_host,
        proxy_target_port=proxy_port,
    )


def _read_parser(path: Path) -> ConfigParser:
    parser = ConfigParser()
    if not parser.read(path):
        raise ConfigError("agent.conf is missing")
    return parser


def _section(parser: ConfigParser, name: str) -> SectionProxy:
    if not parser.has_section(name):
        raise ConfigError(f"{name} section is required")
    return parser[name]


def _require(section: SectionProxy, key: str, label: str) -> str:
    value = section.get(key)
    if not value:
        raise ConfigError(f"{label} is required")
    return value


def _parse_host_port(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text.isdigit():
        raise ConfigError("proxy.target must be host:port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ConfigError("proxy target_port is outside valid TCP port bounds")
    return host, port


def _load_identity(path: Path) -> dict[str, object]:
    with path.open(encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise AgentTunnelError("identity.json must contain an object")
    for key in (
        "agent_id",
        "private_key",
        "agent_x509_cert",
        "tunnel_ca_bundle",
        "tunnel_host",
        "tunnel_port",
        "tunnel_secret",
    ):
        if key not in data:
            raise AgentTunnelError(f"identity.json missing {key}")
    return data


def _build_tunnel_tls_context(
    *, config: AgentConfig, identity: dict[str, object]
) -> ssl.SSLContext:
    context = require_tunnel_tls_context(
        ssl.create_default_context(cafile=str(config.tunnel_tls_ca_bundle))
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        cert_path = Path(temp_dir) / "agent.crt"
        key_path = Path(temp_dir) / "agent.key"
        cert_path.write_text(str(identity["agent_x509_cert"]), encoding="utf-8")
        key_path.write_text(str(identity["private_key"]), encoding="utf-8")
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context


def _auth_frame(*, config: AgentConfig, identity: dict[str, object]) -> bytes:
    cert = x509.load_pem_x509_certificate(str(identity["agent_x509_cert"]).encode())
    public_key_pem = (
        cert.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    parser = _read_parser(config.config_path)
    enrollment = _section(parser, "enrollment")
    payload = {
        "agent_id": str(identity["agent_id"]),
        "node_name": _require(enrollment, "node_name", "enrollment.node_name"),
        "cert_serial": format(cert.serial_number, "x"),
        "cert_public_key": public_key_pem,
        "tunnel_secret": str(identity["tunnel_secret"]),
    }
    return encode_frame(
        frame_type=TunnelFrameType.AUTH,
        request_id="agent-auth",
        channel_id=None,
        payload=json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        ),
    )


def _host_key_from_keyscan(result: str) -> str:
    keys = [
        " ".join(line.split()[1:3])
        for line in result.splitlines()
        if line and not line.startswith("#") and "ssh-" in line
    ]
    if not keys:
        raise AgentEnrollmentError("node sshd host public key is empty")
    for key in keys:
        if key.startswith("ssh-ed25519 "):
            return key
    return keys[0]


async def _run_ssh_keyscan(host: str, port: int) -> str:
    process = await asyncio.create_subprocess_exec(
        "ssh-keyscan",
        "-p",
        str(port),
        host,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _stderr = await process.communicate()
    if process.returncode != 0:
        raise AgentEnrollmentError("node sshd host key probe failed")
    return stdout.decode("utf-8", errors="replace")


if __name__ == "__main__":
    raise SystemExit(main())
