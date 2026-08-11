"""Tests for secret handling and certificate issuance."""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import uuid
from pathlib import Path
from typing import Any, cast

import asyncssh
import pytest
from asyncssh.packet import SSHPacket
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from vibeconnect_common.crypto import (
    SECRET_REDACTION,
    SecretError,
    SecretValue,
    generate_agent_private_key,
    generate_enrollment_token,
    generate_tunnel_secret,
    issue_agent_client_certificate,
    issue_user_ssh_certificate,
    load_ed25519_private_key,
    scrub_secret_metadata,
    sha256_hex,
    verify_secret_hash,
)


def test_generated_secrets_are_high_entropy_and_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Generated tokens and tunnel secrets have entropy and redact in logs."""
    token = generate_enrollment_token()
    tunnel_secret = generate_tunnel_secret()

    assert isinstance(token, SecretValue)
    assert len(token.reveal()) >= 43
    assert len(tunnel_secret.reveal()) >= 43
    assert token.reveal() != tunnel_secret.reveal()
    assert repr(token) == SECRET_REDACTION
    assert str(tunnel_secret) == SECRET_REDACTION

    with caplog.at_level(logging.INFO):
        logging.getLogger("vibeconnect.test").info("created token %r", token)

    assert token.reveal() not in caplog.text
    assert SECRET_REDACTION in caplog.text


def test_sha256_hex_only_accepts_generated_secret_values() -> None:
    """Plain low-entropy strings are not accepted by the hashing helper."""
    token = generate_enrollment_token()

    assert verify_secret_hash(token, sha256_hex(token))
    with pytest.raises(SecretError, match="at least 256 bits"):
        SecretValue("password")
    with pytest.raises(SecretError, match="high-entropy secret"):
        sha256_hex("password")  # type: ignore[arg-type]


def test_scrub_secret_metadata_redacts_sensitive_fields() -> None:
    """Audit/log metadata scrubbing removes known secret values recursively."""
    metadata = {
        "node_name": "db-01",
        "token": "raw-token",
        "nested": {
            "bearerToken": "raw-bearer",
            "items": [{"privateKey": "raw-key"}, {"safe": "value"}],
        },
    }

    assert scrub_secret_metadata(metadata) == {
        "node_name": "db-01",
        "token": SECRET_REDACTION,
        "nested": {
            "bearerToken": SECRET_REDACTION,
            "items": [{"privateKey": SECRET_REDACTION}, {"safe": "value"}],
        },
    }


def test_issue_agent_certificate_contains_required_identity() -> None:
    """Agent X.509 certs include CN, URI SAN, clientAuth, serial, and expiry."""
    ca_key, ca_cert = _agent_ca()
    agent_key = generate_agent_private_key()
    agent_id = uuid.uuid4()
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    issued = issue_agent_client_certificate(
        ca_private_key=ca_key,
        ca_certificate=ca_cert,
        agent_public_key=agent_key.public_key(),
        node_name="node-01",
        agent_id=agent_id,
        now=now,
    )

    cert = x509.load_pem_x509_certificate(issued.certificate_pem)
    common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value

    assert common_name == "node-01"
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [
        f"urn:vibeconnect:agent:{agent_id}"
    ]
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert issued.serial == format(cert.serial_number, "x")
    assert issued.expires_at == now + dt.timedelta(days=90)


def test_issue_user_ssh_certificate_contains_principal_and_source_address() -> None:
    """OpenSSH user certs constrain principal, serial, TTL, and source address."""
    ca_key = asyncssh.generate_private_key("ssh-ed25519")
    session_id = uuid.uuid4()
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    issued = issue_user_ssh_certificate(
        user_ca_key=ca_key,
        username="alice",
        session_id=session_id,
        serial=42,
        now=now,
    )
    parsed = cast(Any, asyncssh.import_certificate(issued.certificate))

    assert parsed.principals == ["alice"]
    assert parsed.options["source-address"] == [ipaddress.ip_network("127.0.0.0/8")]
    assert parsed.options == {
        "source-address": [ipaddress.ip_network("127.0.0.0/8")],
        "permit-pty": True,
    }
    assert _openssh_cert_serial(parsed.public_data) == 42
    assert issued.valid_before - issued.valid_after == dt.timedelta(hours=4)


def test_issue_user_ssh_certificate_rejects_bad_ttl_and_root() -> None:
    """Unsafe certificate inputs fail before issuance."""
    ca_key = asyncssh.generate_private_key("ssh-ed25519")

    with pytest.raises(ValueError, match="TTL"):
        issue_user_ssh_certificate(
            user_ca_key=ca_key,
            username="alice",
            session_id=uuid.uuid4(),
            serial=1,
            ttl_hours=13,
        )
    with pytest.raises(ValueError, match="username principal"):
        issue_user_ssh_certificate(
            user_ca_key=ca_key,
            username="root",
            session_id=uuid.uuid4(),
            serial=1,
        )


def test_load_ed25519_private_key_does_not_log_key_material(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Safe key loading avoids logging private material."""
    private_key = generate_agent_private_key()
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path = tmp_path / "agent_ca.key"
    key_path.write_bytes(pem)

    with caplog.at_level(logging.INFO):
        loaded = load_ed25519_private_key(key_path)

    assert isinstance(loaded, Ed25519PrivateKey)
    assert pem.decode("ascii") not in caplog.text
    assert caplog.text == ""


def _agent_ca() -> tuple[Ed25519PrivateKey, x509.Certificate]:
    key = Ed25519PrivateKey.generate()
    now = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=key, algorithm=None)
    )
    return key, cert


def _openssh_cert_serial(public_data: bytes) -> int:
    packet = SSHPacket(public_data)
    packet.get_string()
    packet.get_string()
    packet.get_string()
    return packet.get_uint64()
