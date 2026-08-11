"""Shared typed models for VibeConnect configuration and protocol data."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class SessionStatus(str, Enum):
    """Known session lifecycle states."""

    OPEN = "open"
    CLOSED = "closed"
    FAILED = "failed"
    TERMINATED = "terminated"


class AuditEventType(str, Enum):
    """Minimum audit event types required by the specification."""

    ENROLLMENT_TOKEN_CREATED = "enrollment_token_created"
    ENROLLMENT_TOKEN_EXPIRED = "enrollment_token_expired"
    ENROLLMENT_SUCCEEDED = "enrollment_succeeded"
    ENROLLMENT_FAILED = "enrollment_failed"
    AGENT_TUNNEL_CONNECTED = "agent_tunnel_connected"
    AGENT_TUNNEL_REJECTED = "agent_tunnel_rejected"
    AGENT_TUNNEL_DISCONNECTED = "agent_tunnel_disconnected"
    AGENT_REVOKED = "agent_revoked"
    TUNNEL_SECRET_ROTATED = "tunnel_secret_rotated"
    CA_ROTATION_STARTED = "ca_rotation_started"
    CA_ROTATION_COMPLETED = "ca_rotation_completed"
    NODE_HOST_KEY_UPDATED = "node_host_key_updated"
    USER_LOGIN_SUCCEEDED = "user_login_succeeded"
    USER_LOGIN_FAILED = "user_login_failed"
    NODE_AUTHORIZATION_DENIED = "node_authorization_denied"
    SESSION_STARTED = "session_started"
    SESSION_CLOSED = "session_closed"
    SESSION_FAILED = "session_failed"
    REPLAY_WRITE_FAILED = "replay_write_failed"
    REPLAY_PRUNED = "replay_pruned"


class TunnelFrameType(str, Enum):
    """Tunnel protocol frame types."""

    AUTH = "auth"
    AUTH_OK = "auth_ok"
    HEARTBEAT = "heartbeat"
    OPEN_SESSION = "open_session"
    SESSION_DATA = "session_data"
    RESIZE_PTY = "resize_pty"
    CLOSE_SESSION = "close_session"
    RENEW_AGENT_CERT = "renew_agent_cert"
    ROTATE_TUNNEL_SECRET = "rotate_tunnel_secret"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class TunnelFrame:
    """Typed representation of a tunnel frame envelope."""

    type: TunnelFrameType
    request_id: str
    channel_id: str | None
    payload_length: int


@dataclass(frozen=True, slots=True)
class FilePublicKeyEntry:
    """File-backed public key mapping for one canonical username."""

    username: str
    public_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PublicKeyAuthConfig:
    """Public-key authentication source settings."""

    source: str
    file_path: Path | None = None
    file_entries: tuple[FilePublicKeyEntry, ...] = ()


@dataclass(frozen=True, slots=True)
class LdapConfig:
    """LDAP identity and password-auth settings."""

    enabled: bool
    use_tls: bool
    validate_tls: bool


@dataclass(frozen=True, slots=True)
class AzureAdConfig:
    """Azure AD identity lookup settings."""

    enabled: bool
    client_secret_path: Path | None = None
    use_managed_identity: bool = False


@dataclass(frozen=True, slots=True)
class AuthConfig:
    """Server authentication configuration."""

    public_keys: PublicKeyAuthConfig
    ldap: LdapConfig
    azure_ad: AzureAdConfig
    keyboard_interactive_verifier: str | None


@dataclass(frozen=True, slots=True)
class CertConfig:
    """Server certificate and CA configuration."""

    agent_ca_key_path: Path
    agent_ca_cert_path: Path
    user_ca_key_path: Path
    user_ca_public_key_path: Path
    agent_cert_lifetime_days: int
    user_cert_ttl_hours: int


@dataclass(frozen=True, slots=True)
class TunnelConfig:
    """Tunnel runtime limits."""

    max_sessions_per_agent: int
    heartbeat_seconds: int
    frame_max_bytes: int
    tls_ca_bundle: Path
    node_ssh_port: int


@dataclass(frozen=True, slots=True)
class ReplayConfig:
    """Replay storage settings."""

    directory: Path
    retention_days: int
    integrity_key_path: Path


@dataclass(frozen=True, slots=True)
class MetricsConfig:
    """Metrics and health endpoint settings."""

    listen: str


@dataclass(frozen=True, slots=True)
class ServerConfig:
    """Server configuration used by validation."""

    certs: CertConfig
    tunnel: TunnelConfig
    auth: AuthConfig
    replay: ReplayConfig
    metrics: MetricsConfig
    install_dirs: tuple[Path, ...]
    secret_paths: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class AgentConfig:
    """Agent configuration used by validation."""

    config_path: Path
    identity_path: Path
    enrollment_token: str | None
    enrollment_completed: bool
    enrollment_tls_ca_bundle: Path
    tunnel_tls_ca_bundle: Path
    proxy_target_host: str
    proxy_target_port: int
    heartbeat_seconds: int
    reconnect_backoff_max_seconds: int
    max_reconnect_attempts: int
