"""Cryptographic helpers for secrets and certificate issuance."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import secrets
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from vibeconnect_common.identifiers import (
    validate_node_name,
    validate_username_principal,
)

GENERATED_SECRET_BYTES = 32
AGENT_CERT_DEFAULT_LIFETIME_DAYS = 90
USER_CERT_DEFAULT_TTL_HOURS = 4
USER_CERT_SOURCE_ADDRESS = "127.0.0.0/8"
SECRET_REDACTION = "[REDACTED]"

SECRET_KEY_FRAGMENTS = (
    "token",
    "secret",
    "password",
    "private_key",
    "bearer",
    "authorization",
    "replay_payload",
    "provider_response",
    "dsn",
)


class SecretError(ValueError):
    """Raised when secret handling rules are violated."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretValue:
    """A high-entropy secret which redacts itself in logs and repr output."""

    _value: str = field(repr=False)

    def __post_init__(self) -> None:
        """Reject empty secret values."""
        if not self._value:
            raise SecretError("secret value cannot be empty")

    def __repr__(self) -> str:
        """Return a redacted representation."""
        return SECRET_REDACTION

    def __str__(self) -> str:
        """Return a redacted string."""
        return SECRET_REDACTION

    def reveal(self) -> str:
        """Return the underlying secret for storage or network exchange."""
        return self._value


@dataclass(frozen=True, slots=True)
class IssuedAgentCertificate:
    """Issued X.509 client certificate metadata."""

    certificate_pem: bytes
    serial: str
    expires_at: dt.datetime


@dataclass(frozen=True, slots=True)
class IssuedUserCertificate:
    """Issued OpenSSH user certificate and ephemeral private key."""

    private_key: asyncssh.SSHKey = field(repr=False)
    certificate: bytes
    serial: int
    username: str
    valid_after: dt.datetime
    valid_before: dt.datetime


def generate_enrollment_token() -> SecretValue:
    """Generate a CSPRNG enrollment token with at least 256 bits of entropy."""
    return SecretValue(secrets.token_urlsafe(GENERATED_SECRET_BYTES))


def generate_tunnel_secret() -> SecretValue:
    """Generate a CSPRNG tunnel secret with at least 256 bits of entropy."""
    return SecretValue(secrets.token_urlsafe(GENERATED_SECRET_BYTES))


def sha256_hex(secret: SecretValue) -> str:
    """Hash a generated high-entropy secret with SHA-256."""
    if not isinstance(secret, SecretValue):
        raise SecretError("sha256_hex requires a generated high-entropy secret")
    return hashlib.sha256(secret.reveal().encode("utf-8")).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    """Compare two strings without data-dependent early exit."""
    return hmac.compare_digest(left, right)


def verify_secret_hash(secret: SecretValue, expected_hash: str) -> bool:
    """Verify a generated secret against an expected SHA-256 hex digest."""
    return constant_time_equal(sha256_hex(secret), expected_hash)


def generate_agent_private_key() -> Ed25519PrivateKey:
    """Generate an Ed25519 private key for agent mTLS identity."""
    return Ed25519PrivateKey.generate()


def issue_agent_client_certificate(
    *,
    ca_private_key: Ed25519PrivateKey,
    ca_certificate: x509.Certificate,
    agent_public_key: Ed25519PublicKey,
    node_name: str,
    agent_id: uuid.UUID,
    now: dt.datetime | None = None,
    lifetime_days: int = AGENT_CERT_DEFAULT_LIFETIME_DAYS,
) -> IssuedAgentCertificate:
    """Issue an Ed25519 X.509 client certificate for an enrolled agent."""
    if lifetime_days <= 0:
        raise ValueError("agent certificate lifetime must be positive")
    safe_node_name = validate_node_name(node_name)
    actual_now = _utc_now() if now is None else _as_utc(now)
    expires_at = actual_now + dt.timedelta(days=lifetime_days)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, safe_node_name)])
        )
        .issuer_name(ca_certificate.subject)
        .public_key(agent_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(actual_now)
        .not_valid_after(expires_at)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(f"urn:vibeconnect:agent:{agent_id}")]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .sign(private_key=ca_private_key, algorithm=None)
    )
    serial = format(certificate.serial_number, "x")
    return IssuedAgentCertificate(
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
        serial=serial,
        expires_at=expires_at,
    )


def issue_user_ssh_certificate(
    *,
    user_ca_key: asyncssh.SSHKey,
    username: str,
    session_id: uuid.UUID,
    serial: int,
    now: dt.datetime | None = None,
    ttl_hours: int = USER_CERT_DEFAULT_TTL_HOURS,
) -> IssuedUserCertificate:
    """Issue an OpenSSH user certificate for one jump session."""
    if not 1 <= ttl_hours <= 12:
        raise ValueError("user certificate TTL must be between 1 and 12 hours")
    if serial < 1:
        raise ValueError("user certificate serial must be positive")

    safe_username = validate_username_principal(username)
    actual_now = _utc_now() if now is None else _as_utc(now)
    valid_before = actual_now + dt.timedelta(hours=ttl_hours)
    session_key = asyncssh.generate_private_key("ssh-ed25519")
    certificate = user_ca_key.generate_user_certificate(
        session_key,
        key_id=str(session_id),
        serial=serial,
        principals=[safe_username],
        valid_after=actual_now,
        valid_before=valid_before,
        source_address=[USER_CERT_SOURCE_ADDRESS],
        permit_x11_forwarding=False,
        permit_agent_forwarding=False,
        permit_port_forwarding=False,
        permit_pty=True,
        permit_user_rc=False,
    )
    return IssuedUserCertificate(
        private_key=session_key,
        certificate=certificate.export_certificate(),
        serial=serial,
        username=safe_username,
        valid_after=actual_now,
        valid_before=valid_before,
    )


def load_ed25519_private_key(path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from disk without logging key material."""
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SecretError("private key must be Ed25519")
    return key


def load_ssh_private_key(path: Path) -> asyncssh.SSHKey:
    """Load an OpenSSH private key from disk without logging key material."""
    return asyncssh.import_private_key(path.read_text())


def scrub_secret_metadata(value: object) -> object:
    """Return JSON-like metadata with known secret fields redacted."""
    if isinstance(value, Mapping):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            safe_key = str(key)
            if _is_secret_key(safe_key):
                redacted[safe_key] = SECRET_REDACTION
            else:
                redacted[safe_key] = scrub_secret_metadata(item)
        return redacted
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [scrub_secret_metadata(item) for item in value]
    if isinstance(value, SecretValue):
        return SECRET_REDACTION
    return value


def _is_secret_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    compact = normalized.replace("_", "")
    return any(
        fragment in normalized or fragment.replace("_", "") in compact
        for fragment in SECRET_KEY_FRAGMENTS
    )


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _as_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)
