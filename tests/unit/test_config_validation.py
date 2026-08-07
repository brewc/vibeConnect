"""Tests for Phase 1 configuration validation."""

from pathlib import Path

import pytest

from vibeconnect_common.config import (
    ConfigError,
    validate_agent_config,
    validate_server_config,
)
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


def test_validate_server_config_accepts_safe_config(tmp_path: Path) -> None:
    """A complete server config with safe permissions validates."""
    config = _server_config(tmp_path)

    validate_server_config(config)


def test_validate_server_config_rejects_missing_ca(tmp_path: Path) -> None:
    """Required CA paths are mandatory."""
    config = _server_config(tmp_path)
    config.certs.agent_ca_key_path.unlink()

    with pytest.raises(ConfigError, match="agent CA key"):
        validate_server_config(config)


def test_validate_server_config_rejects_group_writable_secret(tmp_path: Path) -> None:
    """Server secrets cannot be group or world accessible."""
    config = _server_config(tmp_path)
    config.replay.integrity_key_path.chmod(0o640)

    with pytest.raises(ConfigError, match="secret"):
        validate_server_config(config)


def test_validate_server_config_rejects_bad_user_cert_ttl(tmp_path: Path) -> None:
    """User certificate TTL must stay within the documented bounds."""
    config = _server_config(tmp_path, user_cert_ttl_hours=13)

    with pytest.raises(ConfigError, match="user_cert_ttl_hours"):
        validate_server_config(config)


def test_validate_server_config_rejects_ldap_without_tls_validation(
    tmp_path: Path,
) -> None:
    """LDAP auth must validate StartTLS or LDAPS certificates."""
    config = _server_config(
        tmp_path, ldap=LdapConfig(enabled=True, use_tls=True, validate_tls=False)
    )

    with pytest.raises(ConfigError, match="LDAP"):
        validate_server_config(config)


def test_validate_server_config_rejects_azure_keyboard_interactive(
    tmp_path: Path,
) -> None:
    """Azure AD cannot be configured as a keyboard-interactive verifier."""
    config = _server_config(tmp_path, keyboard_interactive_verifier="azure_ad")

    with pytest.raises(ConfigError, match="Azure AD"):
        validate_server_config(config)


def test_validate_server_config_rejects_duplicate_file_public_key(
    tmp_path: Path,
) -> None:
    """A file-backed public key cannot map to more than one canonical username."""
    config = _server_config(
        tmp_path,
        public_key_entries=(
            FilePublicKeyEntry("alice", ("ssh-ed25519 AAAA",)),
            FilePublicKeyEntry("bob", ("ssh-ed25519 AAAA",)),
        ),
    )

    with pytest.raises(ConfigError, match="multiple users"):
        validate_server_config(config)


def test_validate_server_config_rejects_file_auth_root_user(tmp_path: Path) -> None:
    """Root principal is rejected before certificate issuance."""
    config = _server_config(
        tmp_path,
        public_key_entries=(FilePublicKeyEntry("root", ("ssh-ed25519 AAAA",)),),
    )

    with pytest.raises(ValueError, match="username principal"):
        validate_server_config(config)


def test_validate_agent_config_accepts_safe_config(tmp_path: Path) -> None:
    """A complete agent config with safe permissions validates."""
    config = _agent_config(tmp_path)

    validate_agent_config(config)


def test_validate_agent_config_rejects_other_readable_agent_conf(
    tmp_path: Path,
) -> None:
    """agent.conf cannot be readable by other users."""
    config = _agent_config(tmp_path)
    config.config_path.chmod(0o604)

    with pytest.raises(ConfigError, match="other users"):
        validate_agent_config(config)


def test_validate_agent_config_rejects_unsafe_identity_dir(tmp_path: Path) -> None:
    """The identity directory must not be group or world accessible."""
    config = _agent_config(tmp_path)
    config.identity_path.parent.chmod(0o750)

    with pytest.raises(ConfigError, match="identity directory"):
        validate_agent_config(config)


def test_validate_agent_config_rejects_non_loopback_proxy(tmp_path: Path) -> None:
    """The agent proxy target is restricted to IPv4 loopback."""
    config = _agent_config(tmp_path, proxy_target_host="::1")

    with pytest.raises(ConfigError, match="127.0.0.0/8"):
        validate_agent_config(config)


def test_validate_agent_config_rejects_token_after_enrollment(
    tmp_path: Path,
) -> None:
    """Enrollment fails closed if the raw token remains after identity creation."""
    config = _agent_config(
        tmp_path, enrollment_completed=True, enrollment_token="secret"
    )

    with pytest.raises(ConfigError, match="enrollment token"):
        validate_agent_config(config)


def _server_config(
    tmp_path: Path,
    *,
    user_cert_ttl_hours: int = 4,
    ldap: LdapConfig | None = None,
    keyboard_interactive_verifier: str | None = "ldap",
    public_key_entries: tuple[FilePublicKeyEntry, ...] | None = None,
) -> ServerConfig:
    server_dir = tmp_path / "server"
    secrets_dir = server_dir / "secrets"
    replay_dir = server_dir / "replay"
    state_dir = server_dir / "state"
    for directory in (server_dir, secrets_dir, replay_dir, state_dir):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)

    agent_ca_key = _touch_secret(secrets_dir / "agent_ca.key")
    agent_ca_cert = _touch_public(secrets_dir / "agent_ca.crt")
    user_ca_key = _touch_secret(secrets_dir / "user_ca.key")
    user_ca_public = _touch_public(secrets_dir / "user_ca.pub")
    tunnel_ca = _touch_public(secrets_dir / "tunnel_ca.crt")
    replay_key = _touch_secret(secrets_dir / "replay.key")
    authorized_keys = _touch_public(secrets_dir / "authorized_keys")

    entries = (
        public_key_entries
        if public_key_entries is not None
        else (FilePublicKeyEntry("alice", ("ssh-ed25519 AAAA",)),)
    )

    return ServerConfig(
        certs=CertConfig(
            agent_ca_key_path=agent_ca_key,
            agent_ca_cert_path=agent_ca_cert,
            user_ca_key_path=user_ca_key,
            user_ca_public_key_path=user_ca_public,
            agent_cert_lifetime_days=90,
            user_cert_ttl_hours=user_cert_ttl_hours,
        ),
        tunnel=TunnelConfig(
            max_sessions_per_agent=64,
            heartbeat_seconds=30,
            frame_max_bytes=1048576,
            tls_ca_bundle=tunnel_ca,
        ),
        auth=AuthConfig(
            public_keys=PublicKeyAuthConfig(
                source="file",
                file_path=authorized_keys,
                file_entries=entries,
            ),
            ldap=ldap
            if ldap is not None
            else LdapConfig(enabled=True, use_tls=True, validate_tls=True),
            azure_ad=AzureAdConfig(enabled=False),
            keyboard_interactive_verifier=keyboard_interactive_verifier,
        ),
        replay=ReplayConfig(
            directory=replay_dir,
            retention_days=30,
            integrity_key_path=replay_key,
        ),
        metrics=MetricsConfig(listen="127.0.0.1:9100"),
        install_dirs=(server_dir, state_dir, replay_dir),
        secret_paths=(agent_ca_key, user_ca_key, replay_key),
    )


def _agent_config(
    tmp_path: Path,
    *,
    proxy_target_host: str = "127.0.0.1",
    enrollment_completed: bool = False,
    enrollment_token: str | None = "token",
) -> AgentConfig:
    agent_dir = tmp_path / "agent"
    identity_dir = agent_dir / "identity"
    agent_dir.mkdir()
    agent_dir.chmod(0o700)
    identity_dir.mkdir()
    identity_dir.chmod(0o700)

    agent_conf = _touch_public(agent_dir / "agent.conf", mode=0o600)
    enrollment_ca = _touch_public(agent_dir / "enrollment-ca.crt")
    tunnel_ca = _touch_public(agent_dir / "tunnel-ca.crt")

    return AgentConfig(
        config_path=agent_conf,
        identity_path=identity_dir / "identity.json",
        enrollment_token=enrollment_token,
        enrollment_completed=enrollment_completed,
        enrollment_tls_ca_bundle=enrollment_ca,
        tunnel_tls_ca_bundle=tunnel_ca,
        proxy_target_host=proxy_target_host,
        proxy_target_port=2222,
        heartbeat_seconds=30,
        reconnect_backoff_max_seconds=300,
    )


def _touch_secret(path: Path) -> Path:
    return _touch_public(path, mode=0o600)


def _touch_public(path: Path, *, mode: int = 0o644) -> Path:
    path.write_text("placeholder\n", encoding="utf-8")
    path.chmod(mode)
    return path
