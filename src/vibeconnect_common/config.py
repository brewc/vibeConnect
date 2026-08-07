"""Configuration validation for VibeConnect server and agent processes."""

from __future__ import annotations

import ipaddress
import os
import stat
from pathlib import Path

from vibeconnect_common.identifiers import validate_username_principal
from vibeconnect_common.models import AgentConfig, FilePublicKeyEntry, ServerConfig


class ConfigError(ValueError):
    """Raised when configuration is unsafe or incomplete."""


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
        allowed_owner_uids: Allowed owners for `agent.conf`. Defaults to current UID
            and root, which keeps tests portable before a `vibe` user exists.

    Raises:
        ConfigError: If configuration is incomplete or unsafe.
    """
    actual_runtime_uid = os.getuid() if runtime_uid is None else runtime_uid
    actual_allowed_owners = (
        frozenset({0, actual_runtime_uid})
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
    if config.enrollment_completed and config.enrollment_token:
        raise ConfigError("enrollment token remains after successful enrollment")


def _validate_tunnel_bounds(config: ServerConfig) -> None:
    if not 1 <= config.tunnel.max_sessions_per_agent <= 1024:
        raise ConfigError("max_sessions_per_agent is outside documented bounds")
    if not 5 <= config.tunnel.heartbeat_seconds <= 300:
        raise ConfigError("heartbeat_seconds is outside documented bounds")
    if not 65536 <= config.tunnel.frame_max_bytes <= 16777216:
        raise ConfigError("frame_max_bytes is outside documented bounds")


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
