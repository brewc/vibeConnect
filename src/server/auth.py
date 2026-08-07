"""Authentication provider and authorization helpers."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from vibeconnect_common.identifiers import (
    IdentifierError,
    validate_label,
    validate_node_name,
    validate_username_principal,
)


class AuthError(PermissionError):
    """Raised when authentication or authorization fails closed."""


@dataclass(frozen=True, slots=True)
class ResolvedIdentity:
    """Authenticated identity bound to one canonical username."""

    username: str
    public_key: str
    groups: frozenset[str]


@dataclass(frozen=True, slots=True)
class NodeInventoryEntry:
    """Node authorization metadata."""

    node_name: str
    labels: frozenset[str]


@dataclass(frozen=True, slots=True)
class ProviderPublicKeyRecord:
    """Public-key record returned from LDAP or Azure AD."""

    username: str
    public_keys: tuple[str, ...]
    groups: frozenset[str] = frozenset()


class GraphClient(Protocol):
    """Minimal async Microsoft Graph client interface."""

    async def get_json(
        self, url: str, *, timeout_seconds: float
    ) -> Mapping[str, object]:
        """Return a decoded JSON object from Graph."""


def escape_ldap_filter_value(value: str) -> str:
    """Escape a value according to RFC 4515 LDAP filter rules."""
    escaped = []
    for char in value:
        if char == "\x00":
            escaped.append(r"\00")
        elif char == "*":
            escaped.append(r"\2a")
        elif char == "(":
            escaped.append(r"\28")
        elif char == ")":
            escaped.append(r"\29")
        elif char == "\\":
            escaped.append(r"\5c")
        else:
            escaped.append(char)
    return "".join(escaped)


def validate_ldap_tls(*, use_tls: bool, validate_tls: bool) -> None:
    """Require LDAP StartTLS/LDAPS with certificate validation."""
    if not use_tls or not validate_tls:
        raise AuthError("LDAP requires TLS certificate validation")


def verify_ldap_password_bind(
    *,
    username: str,
    password: str,
    use_tls: bool,
    validate_tls: bool,
    bind: Callable[[str, str], bool],
) -> str:
    """Verify a keyboard-interactive password through an LDAP bind callback."""
    validate_ldap_tls(use_tls=use_tls, validate_tls=validate_tls)
    safe_username = validate_username_principal(username)
    if not password:
        raise AuthError("password is required")
    if not bind(safe_username, password):
        raise AuthError("LDAP bind denied")
    return safe_username


def resolve_ldap_public_key_identity(
    *,
    login_username: str,
    presented_public_key: str,
    records: Sequence[ProviderPublicKeyRecord],
) -> ResolvedIdentity:
    """Resolve a user through LDAP `sshPublicKey` records."""
    return _resolve_provider_public_key_identity(
        login_username=login_username,
        presented_public_key=presented_public_key,
        records=records,
    )


def resolve_azure_public_key_identity(
    *,
    login_username: str,
    presented_public_key: str,
    records: Sequence[ProviderPublicKeyRecord],
) -> ResolvedIdentity:
    """Resolve a user through Azure AD extension-attribute key records."""
    return _resolve_provider_public_key_identity(
        login_username=login_username,
        presented_public_key=presented_public_key,
        records=records,
    )


def resolve_file_public_key_identity(
    *,
    login_username: str,
    presented_public_key: str,
    authorized_keys: Mapping[str, Sequence[str]],
) -> ResolvedIdentity:
    """Resolve identity from a server-owned authorized-keys mapping."""
    safe_login = validate_username_principal(login_username)
    matched_usernames = {
        validate_username_principal(username)
        for username, keys in authorized_keys.items()
        if presented_public_key in keys
    }
    if len(matched_usernames) > 1:
        raise AuthError("public key maps to multiple usernames")
    if matched_usernames != {safe_login}:
        raise AuthError("public key identity mismatch")
    return ResolvedIdentity(
        username=safe_login,
        public_key=presented_public_key,
        groups=frozenset(),
    )


def _resolve_provider_public_key_identity(
    *,
    login_username: str,
    presented_public_key: str,
    records: Sequence[ProviderPublicKeyRecord],
) -> ResolvedIdentity:
    safe_login = validate_username_principal(login_username)
    matches = [
        record for record in records if presented_public_key in record.public_keys
    ]
    matched_usernames = {
        validate_username_principal(record.username) for record in matches
    }
    if len(matched_usernames) > 1:
        raise AuthError("public key maps to multiple usernames")
    if matched_usernames != {safe_login} or len(matches) != 1:
        raise AuthError("public key identity mismatch")
    record = matches[0]
    return ResolvedIdentity(
        username=safe_login,
        public_key=presented_public_key,
        groups=record.groups,
    )


async def resolve_azure_ad_groups(
    *,
    graph_client: GraphClient,
    user_id: str,
    transitive: bool,
    timeout_seconds: float,
) -> frozenset[str]:
    """Resolve Azure AD group IDs with pagination and fail-closed parsing."""
    if timeout_seconds <= 0:
        raise AuthError("Graph timeout must be positive")
    endpoint = "transitiveMemberOf" if transitive else "memberOf"
    url = f"/users/{user_id}/{endpoint}?$select=id"
    groups: set[str] = set()
    try:
        while url:
            page = await graph_client.get_json(url, timeout_seconds=timeout_seconds)
            values = page.get("value")
            if not isinstance(values, list):
                raise AuthError("Graph response missing value list")
            for entry in values:
                if not isinstance(entry, Mapping) or not isinstance(
                    entry.get("id"), str
                ):
                    raise AuthError("Graph response contains partial group entry")
                groups.add(entry["id"])
            next_link = page.get("@odata.nextLink")
            if next_link is not None and not isinstance(next_link, str):
                raise AuthError("Graph nextLink is invalid")
            url = next_link or ""
    except TimeoutError as exc:
        raise AuthError("Graph lookup timed out") from exc
    except asyncio.TimeoutError as exc:
        raise AuthError("Graph lookup timed out") from exc
    return frozenset(groups)


def labels_for_groups(
    *,
    groups: frozenset[str],
    group_to_roles: Mapping[str, Sequence[str]],
    role_to_labels: Mapping[str, Sequence[str]],
) -> frozenset[str]:
    """Map provider groups to exact node labels through roles."""
    roles: set[str] = set()
    for group in groups:
        roles.update(group_to_roles.get(group, ()))
    labels: set[str] = set()
    for role in roles:
        labels.update(validate_label(label) for label in role_to_labels.get(role, ()))
    return frozenset(labels)


def visible_nodes_for_identity(
    *,
    identity: ResolvedIdentity,
    nodes: Sequence[NodeInventoryEntry],
    group_to_roles: Mapping[str, Sequence[str]],
    role_to_labels: Mapping[str, Sequence[str]],
) -> tuple[str, ...]:
    """Return node names authorized by exact, case-sensitive label matching."""
    allowed_labels = labels_for_groups(
        groups=identity.groups,
        group_to_roles=group_to_roles,
        role_to_labels=role_to_labels,
    )
    visible = [
        validate_node_name(node.node_name)
        for node in nodes
        if node.labels & allowed_labels
    ]
    return tuple(sorted(visible))


def parse_restricted_shell_command(command: str, allowed_nodes: Sequence[str]) -> str:
    """Accept only an exact node name plus optional surrounding whitespace."""
    stripped = command.strip()
    if stripped != command and stripped == "":
        raise AuthError("empty command")
    if stripped in {validate_node_name(node) for node in allowed_nodes}:
        return stripped
    raise AuthError("restricted shell accepts only an exact node name")


def validate_ssh_request_policy(
    *,
    username: str,
    command: str | None = None,
    subsystem: str | None = None,
    direct_tcpip: bool = False,
    agent_forwarding: bool = False,
    x11_forwarding: bool = False,
) -> None:
    """Reject SSH features outside the restricted shell contract."""
    try:
        validate_username_principal(username)
    except IdentifierError as exc:
        raise AuthError("username is denied") from exc
    if subsystem is not None:
        raise AuthError("subsystems are denied")
    if direct_tcpip:
        raise AuthError("forwarding is denied")
    if agent_forwarding:
        raise AuthError("agent forwarding is denied")
    if x11_forwarding:
        raise AuthError("X11 forwarding is denied")
    if command in {"scp", "sftp"}:
        raise AuthError("SCP and SFTP are denied")
