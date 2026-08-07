"""Tests for shared identifier validation."""

import pytest

from vibeconnect_common.identifiers import (
    IdentifierError,
    validate_label,
    validate_node_name,
    validate_username_principal,
)


@pytest.mark.parametrize("value", ["web-01", "node_1", "a.b", "A01"])
def test_validate_node_name_accepts_valid_names(value: str) -> None:
    """Valid node names are returned unchanged."""
    assert validate_node_name(value) == value


@pytest.mark.parametrize("value", ["", "-bad", "bad space", "x" * 64, "bad/node"])
def test_validate_node_name_rejects_invalid_names(value: str) -> None:
    """Invalid node names fail before any downstream lookup."""
    with pytest.raises(IdentifierError):
        validate_node_name(value)


@pytest.mark.parametrize("value", ["prod", "team:web", "env/prod", "a.b_c-1"])
def test_validate_label_accepts_valid_labels(value: str) -> None:
    """Valid labels are returned unchanged."""
    assert validate_label(value) == value


@pytest.mark.parametrize("value", ["", "-bad", "bad space", "x" * 129, "bad*label"])
def test_validate_label_rejects_invalid_labels(value: str) -> None:
    """Invalid labels are rejected."""
    with pytest.raises(IdentifierError):
        validate_label(value)


@pytest.mark.parametrize("value", ["alice", "alice@example.com", "svc_bot.1"])
def test_validate_username_principal_accepts_valid_usernames(value: str) -> None:
    """Safe username principals are returned unchanged."""
    assert validate_username_principal(value) == value


@pytest.mark.parametrize(
    "value",
    ["", "root", "alice bob", "alice/bob", "alice:bob", "bad;name", "bad\x00name"],
)
def test_validate_username_principal_rejects_unsafe_usernames(value: str) -> None:
    """Unsafe principals fail before certificate issuance."""
    with pytest.raises(IdentifierError):
        validate_username_principal(value)
