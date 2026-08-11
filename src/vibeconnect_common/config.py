"""Configuration validation for VibeConnect server and agent processes."""

from __future__ import annotations

import ipaddress
import os
import stat
from collections.abc import Mapping
from configparser import ConfigParser, SectionProxy
from pathlib import Path
from urllib.parse import urlparse

import yaml

from vibeconnect_common.identifiers import validate_username_principal
from vibeconnect_common.models import (
    AgentConfig,
    AuthConfig,
    AzureAdConfig,
    CertConfig,
    FilePublicKeyEntry,
    LdapConfig,
    MetricsConfig,
    PublicKeyAuthConfig,
    ReplayConfig,
    ServerConfig,
    TunnelConfig,
)


class ConfigError(ValueError):
    """Raised when configuration is unsafe or incomplete."""


def load_agent_config(path: Path) -> AgentConfig:
    """Load an agent config file into the typed config model."""
    parser = ConfigParser()
    if not parser.read(path):
        raise ConfigError("agent.conf is missing")
    enrollment = parser["enrollment"] if parser.has_section("enrollment") else {}
    tunnel = parser["tunnel"] if parser.has_section("tunnel") else {}
    identity = parser["identity"] if parser.has_section("identity") else {}
    proxy = parser["proxy"] if parser.has_section("proxy") else {}
    target_host, target_port = _parse_host_port(
        _require_config_value(proxy, "target", "proxy.target")
    )
    enrollment_token = enrollment.get("token")
    identity_path = Path(
        identity.get("path", "/var/lib/vibeconnect/identity.json")
    ).expanduser()
    return AgentConfig(
        config_path=path,
        identity_path=identity_path,
        enrollment_token=enrollment_token,
        enrollment_completed=identity_path.exists(),
        enrollment_tls_ca_bundle=Path(
            _require_config_value(
                enrollment, "tls_ca_bundle", "enrollment.tls_ca_bundle"
            )
        ).expanduser(),
        tunnel_tls_ca_bundle=Path(
            _require_config_value(tunnel, "tls_ca_bundle", "tunnel.tls_ca_bundle")
        ).expanduser(),
        proxy_target_host=target_host,
        proxy_target_port=target_port,
        heartbeat_seconds=int(tunnel.get("heartbeat_seconds", "30")),
        reconnect_backoff_max_seconds=int(
            tunnel.get("reconnect_backoff_max_seconds", "300")
        ),
        max_reconnect_attempts=int(tunnel.get("max_reconnect_attempts", "0")),
    )


def load_server_config(path: Path) -> ServerConfig:
    """Load a server YAML config file into the typed config model."""
    raw = _load_simple_yaml(path)
    certs = _mapping(raw, "certs")
    tunnel = _mapping(raw, "tunnel")
    auth = _mapping(raw, "auth")
    public_keys = _mapping(auth, "public_keys", default={})
    ldap = _mapping(auth, "ldap", default={})
    azure_ad = _mapping(auth, "azure_ad", default={})
    replay = _mapping(raw, "replay")
    metrics = _mapping(raw, "metrics")
    return ServerConfig(
        certs=CertConfig(
            agent_ca_key_path=_path(certs, "agent_ca_key_path"),
            agent_ca_cert_path=_path(certs, "agent_ca_cert_path"),
            user_ca_key_path=_path(certs, "user_ca_key_path"),
            user_ca_public_key_path=_path(certs, "user_ca_public_key_path"),
            agent_cert_lifetime_days=_int(certs, "agent_cert_lifetime_days", 30),
            user_cert_ttl_hours=_int(certs, "user_cert_ttl_hours", 4),
        ),
        tunnel=TunnelConfig(
            max_sessions_per_agent=_int(tunnel, "max_sessions_per_agent", 64),
            heartbeat_seconds=_int(tunnel, "heartbeat_seconds", 30),
            frame_max_bytes=_int(tunnel, "frame_max_bytes", 1048576),
            tls_ca_bundle=_path(tunnel, "tls_ca_bundle"),
            node_ssh_port=_int(tunnel, "node_ssh_port", 2222),
        ),
        auth=AuthConfig(
            public_keys=PublicKeyAuthConfig(
                source=str(public_keys.get("source", "file")),
                file_path=(
                    Path(str(public_keys["file_path"])).expanduser()
                    if public_keys.get("file_path")
                    else None
                ),
                file_entries=(),
            ),
            ldap=LdapConfig(
                enabled=_bool(ldap, "enabled", False),
                use_tls=_bool(ldap, "use_tls", False),
                validate_tls=_bool(ldap, "validate_tls", False),
            ),
            azure_ad=AzureAdConfig(
                enabled=_bool(azure_ad, "enabled", False),
                client_secret_path=(
                    Path(str(azure_ad["client_secret_path"])).expanduser()
                    if azure_ad.get("client_secret_path")
                    else None
                ),
                use_managed_identity=_bool(azure_ad, "use_managed_identity", False),
            ),
            keyboard_interactive_verifier=(
                str(auth["keyboard_interactive_verifier"])
                if auth.get("keyboard_interactive_verifier")
                else None
            ),
        ),
        replay=ReplayConfig(
            directory=_path(replay, "directory"),
            retention_days=_int(replay, "retention_days", 90),
            integrity_key_path=_path(replay, "integrity_key_path"),
        ),
        metrics=MetricsConfig(listen=str(metrics.get("listen", "127.0.0.1:9100"))),
        install_dirs=tuple(_paths(raw, "install_dirs")),
        secret_paths=tuple(_paths(raw, "secret_paths")),
    )


def validate_server_config(config: ServerConfig) -> None:
    """Validate server configuration and filesystem safety.

    Args:
        config: Server configuration model.

    Raises:
        ConfigError: If configuration is incomplete or unsafe.
    """
    _require_file(config.certs.agent_ca_key_path, "agent CA key")
    _require_file(config.certs.agent_ca_cert_path, "agent CA certificate")
    _require_file(config.certs.user_ca_key_path, "user CA key")
    _require_file(config.certs.user_ca_public_key_path, "user CA public key")
    _require_file(config.tunnel.tls_ca_bundle, "tunnel TLS CA bundle")
    _require_dir(config.replay.directory, "replay directory")
    _require_file(config.replay.integrity_key_path, "replay integrity key")

    for path in config.install_dirs:
        _require_dir(path, "install directory")
        _reject_group_or_other_writable(path, "install directory")

    for path in config.secret_paths:
        _require_file(path, "secret")
        _reject_group_or_other_accessible(path, "secret")

    if not 1 <= config.certs.user_cert_ttl_hours <= 12:
        raise ConfigError("user_cert_ttl_hours must be between 1 and 12")
    _validate_tunnel_bounds(config)
    _validate_auth_config(config)
    _validate_metrics_listen(config.metrics.listen)


def validate_agent_config(
    config: AgentConfig,
    *,
    runtime_uid: int | None = None,
    allowed_owner_uids: frozenset[int] | None = None,
) -> None:
    """Validate agent configuration and filesystem safety.

    Args:
        config: Agent configuration model.
        runtime_uid: UID expected to read runtime files. Defaults to current UID.
        allowed_owner_uids: Allowed owners for `agent.conf`. Defaults to the runtime
            UID.

    Raises:
        ConfigError: If configuration is incomplete or unsafe.
    """
    actual_runtime_uid = os.getuid() if runtime_uid is None else runtime_uid
    actual_allowed_owners = (
        frozenset({actual_runtime_uid})
        if allowed_owner_uids is None
        else allowed_owner_uids
    )

    _require_file(config.config_path, "agent.conf")
    _require_owner(config.config_path, actual_allowed_owners, "agent.conf")
    _reject_other_readable(config.config_path, "agent.conf")
    _require_readable_by_uid(config.config_path, actual_runtime_uid, "agent.conf")

    identity_parent = config.identity_path.parent
    _require_dir(identity_parent, "identity directory")
    _require_owner(
        identity_parent, frozenset({actual_runtime_uid}), "identity directory"
    )
    _reject_group_or_other_accessible(identity_parent, "identity directory")

    _require_file(config.enrollment_tls_ca_bundle, "enrollment TLS CA bundle")
    _require_file(config.tunnel_tls_ca_bundle, "tunnel TLS CA bundle")

    if not _is_ipv4_loopback(config.proxy_target_host):
        raise ConfigError("proxy target host must be within 127.0.0.0/8")
    if not 1 <= config.proxy_target_port <= 65535:
        raise ConfigError("proxy target_port is outside valid TCP port bounds")
    if not 5 <= config.heartbeat_seconds <= 300:
        raise ConfigError("heartbeat_seconds is outside documented bounds")
    if not 30 <= config.reconnect_backoff_max_seconds <= 1800:
        raise ConfigError("reconnect_backoff_max_seconds is outside documented bounds")
    if config.max_reconnect_attempts < 0:
        raise ConfigError("max_reconnect_attempts cannot be negative")
    if config.enrollment_completed and config.enrollment_token:
        raise ConfigError("enrollment token remains after successful enrollment")


def _validate_tunnel_bounds(config: ServerConfig) -> None:
    if not 1 <= config.tunnel.max_sessions_per_agent <= 1024:
        raise ConfigError("max_sessions_per_agent is outside documented bounds")
    if not 5 <= config.tunnel.heartbeat_seconds <= 300:
        raise ConfigError("heartbeat_seconds is outside documented bounds")
    if not 65536 <= config.tunnel.frame_max_bytes <= 16777216:
        raise ConfigError("frame_max_bytes is outside documented bounds")
    if not 1 <= config.tunnel.node_ssh_port <= 65535:
        raise ConfigError("node_ssh_port is outside valid TCP port bounds")


def _validate_auth_config(config: ServerConfig) -> None:
    if config.auth.ldap.enabled and (
        not config.auth.ldap.use_tls or not config.auth.ldap.validate_tls
    ):
        raise ConfigError("LDAP requires StartTLS/LDAPS certificate validation")
    if config.auth.keyboard_interactive_verifier == "azure_ad":
        raise ConfigError("Azure AD cannot verify keyboard-interactive passwords")
    if config.auth.public_keys.source == "file":
        if config.auth.public_keys.file_path is None:
            raise ConfigError("file public-key auth requires file_path")
        _require_file(config.auth.public_keys.file_path, "authorized-keys file")
        _reject_group_or_other_writable(
            config.auth.public_keys.file_path, "authorized-keys file"
        )
        _validate_file_public_key_entries(config.auth.public_keys.file_entries)


def _validate_metrics_listen(listen: str) -> None:
    host, separator, port_text = listen.rpartition(":")
    if not separator or not host or not port_text.isdigit():
        raise ConfigError("metrics.listen must be host:port")
    if not _is_ipv4_loopback(host):
        raise ConfigError("metrics.listen must bind to IPv4 loopback by default")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ConfigError("metrics.listen port is outside valid TCP port bounds")


def _validate_file_public_key_entries(entries: tuple[FilePublicKeyEntry, ...]) -> None:
    seen: dict[str, str] = {}
    for entry in entries:
        username = validate_username_principal(entry.username)
        if not entry.public_keys:
            raise ConfigError("file public-key entry must include at least one key")
        for public_key in entry.public_keys:
            prior = seen.get(public_key)
            if prior is not None and prior != username:
                raise ConfigError("file public-key auth maps a key to multiple users")
            seen[public_key] = username


def _require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise ConfigError(f"{label} is missing")


def _require_dir(path: Path, label: str) -> None:
    if not path.is_dir():
        raise ConfigError(f"{label} is missing")


def _require_owner(path: Path, allowed_uids: frozenset[int], label: str) -> None:
    if path.stat().st_uid not in allowed_uids:
        raise ConfigError(f"{label} has unsafe owner")


def _require_readable_by_uid(path: Path, uid: int, label: str) -> None:
    file_stat = path.stat()
    mode = stat.S_IMODE(file_stat.st_mode)
    if file_stat.st_uid == uid and mode & stat.S_IRUSR:
        return
    if mode & stat.S_IROTH:
        return
    raise ConfigError(f"{label} is not readable by runtime user")


def _reject_group_or_other_accessible(path: Path, label: str) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"{label} has permissions broader than required")


def _reject_group_or_other_writable(path: Path, label: str) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigError(f"{label} is writable by group or other")


def _reject_other_readable(path: Path, label: str) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & stat.S_IROTH:
        raise ConfigError(f"{label} is readable by other users")


def _is_ipv4_loopback(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and address.is_loopback


def _require_config_value(
    section: Mapping[str, str] | SectionProxy, key: str, display_name: str
) -> str:
    value = section.get(key)
    if not value:
        raise ConfigError(f"{display_name} is required")
    return str(value)


def _parse_host_port(value: str) -> tuple[str, int]:
    parsed = urlparse(f"//{value}")
    if not parsed.hostname or parsed.port is None:
        raise ConfigError("host:port value is required")
    return parsed.hostname, parsed.port


def _load_simple_yaml(path: Path) -> dict[str, object]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError("server config YAML is invalid") from exc
    if not isinstance(loaded, dict):
        raise ConfigError("server config must be a YAML mapping")
    return dict(loaded)


def _mapping(
    mapping: Mapping[str, object],
    key: str,
    *,
    default: Mapping[str, object] | None = None,
) -> Mapping[str, object]:
    value = mapping.get(key, default)
    if not isinstance(value, Mapping):
        raise ConfigError(f"{key} section is required")
    return value


def _path(mapping: Mapping[str, object], key: str) -> Path:
    value = mapping.get(key)
    if not value:
        raise ConfigError(f"{key} is required")
    return Path(str(value)).expanduser()


def _paths(mapping: Mapping[str, object], key: str) -> list[Path]:
    value = mapping.get(key, "")
    if not value:
        return []
    return [Path(item.strip()).expanduser() for item in str(value).split(",")]


def _int(mapping: Mapping[str, object], key: str, default: int) -> int:
    value = mapping.get(key, default)
    if isinstance(value, bool):
        raise ConfigError(f"{key} must be an integer")
    try:
        return int(str(value))
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{key} must be an integer") from exc


def _bool(mapping: Mapping[str, object], key: str, default: bool) -> bool:
    value = mapping.get(key, default)
    if isinstance(value, bool):
        return value
    if str(value).lower() in {"true", "yes", "1"}:
        return True
    if str(value).lower() in {"false", "no", "0"}:
        return False
    raise ConfigError(f"{key} must be a boolean")
