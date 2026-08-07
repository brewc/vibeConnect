"""Identifier validation for VibeConnect security boundaries."""

from __future__ import annotations

import re


class IdentifierError(ValueError):
    """Raised when an identifier is invalid for VibeConnect use."""


NODE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$")
_USERNAME_FORBIDDEN_CHARS = set("/:")
_USERNAME_FORBIDDEN_SHELL_CHARS = set("&;|<>$`\\\"'(){}[]*?!")


def validate_node_name(value: str) -> str:
    """Validate and return a node name.

    Args:
        value: Candidate node name.

    Returns:
        The validated node name.

    Raises:
        IdentifierError: If the node name is invalid.
    """
    if not NODE_NAME_PATTERN.fullmatch(value):
        raise IdentifierError("invalid node_name")
    return value


def validate_label(value: str) -> str:
    """Validate and return a node label.

    Args:
        value: Candidate label.

    Returns:
        The validated label.

    Raises:
        IdentifierError: If the label is invalid.
    """
    if not LABEL_PATTERN.fullmatch(value):
        raise IdentifierError("invalid label")
    return value


def validate_username_principal(value: str) -> str:
    """Validate and return an SSH certificate username principal.

    Args:
        value: Candidate username from an authenticated identity provider.

    Returns:
        The validated username.

    Raises:
        IdentifierError: If the username is unsafe for certificate issuance.
    """
    if value == "" or value == "root":
        raise IdentifierError("invalid username principal")
    for char in value:
        if (
            char == "\x00"
            or char.isspace()
            or ord(char) < 32
            or char in _USERNAME_FORBIDDEN_CHARS
            or char in _USERNAME_FORBIDDEN_SHELL_CHARS
        ):
            raise IdentifierError("invalid username principal")
    return value
