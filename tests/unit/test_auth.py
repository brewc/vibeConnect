"""Tests for auth provider and authorization helpers."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping

import pytest

from server.auth import (
    AuthError,
    GraphClient,
    NodeInventoryEntry,
    ProviderPublicKeyRecord,
    ResolvedIdentity,
    escape_ldap_filter_value,
    parse_restricted_shell_command,
    resolve_azure_ad_groups,
    resolve_azure_public_key_identity,
    resolve_file_public_key_identity,
    resolve_ldap_public_key_identity,
    validate_ldap_tls,
    validate_ssh_request_policy,
    verify_ldap_password_bind,
    visible_nodes_for_identity,
)


class FakeGraphClient:
    """Fake paginated Microsoft Graph client."""

    def __init__(self, pages: Mapping[str, Mapping[str, object]]) -> None:
        """Initialize fixed response pages."""
        self.pages = pages
        self.urls: list[str] = []

    async def get_json(
        self, url: str, *, timeout_seconds: float
    ) -> Mapping[str, object]:
        """Return a configured page."""
        self.urls.append(url)
        return self.pages[url]


class TimeoutGraphClient:
    """Fake Microsoft Graph timeout."""

    async def get_json(
        self, url: str, *, timeout_seconds: float
    ) -> Mapping[str, object]:
        """Raise an async timeout."""
        raise asyncio.TimeoutError


def test_ldap_filter_escaping_and_tls_validation() -> None:
    """LDAP filters are escaped and LDAP TLS validation is mandatory."""
    assert escape_ldap_filter_value(r"al*(ice)\x00\\") == (
        r"al\2a\28ice\29\5cx00\5c\5c"
    )
    validate_ldap_tls(use_tls=True, validate_tls=True)
    with pytest.raises(AuthError, match="TLS"):
        validate_ldap_tls(use_tls=False, validate_tls=True)
    with pytest.raises(AuthError, match="TLS"):
        validate_ldap_tls(use_tls=True, validate_tls=False)


def test_ldap_password_bind_requires_tls_and_valid_password() -> None:
    """Keyboard-interactive LDAP password auth binds over validated TLS."""
    calls: list[tuple[str, str]] = []

    def bind(username: str, password: str) -> bool:
        calls.append((username, password))
        return password == "correct"

    assert (
        verify_ldap_password_bind(
            username="alice",
            password="correct",
            use_tls=True,
            validate_tls=True,
            bind=bind,
        )
        == "alice"
    )
    assert calls == [("alice", "correct")]
    with pytest.raises(AuthError, match="denied"):
        verify_ldap_password_bind(
            username="alice",
            password="wrong",
            use_tls=True,
            validate_tls=True,
            bind=bind,
        )
    with pytest.raises(AuthError, match="TLS"):
        verify_ldap_password_bind(
            username="alice",
            password="correct",
            use_tls=False,
            validate_tls=True,
            bind=bind,
        )


@pytest.mark.asyncio
async def test_azure_ad_group_lookup_paginates_and_uses_transitive_endpoint() -> None:
    """Graph group lookup follows pagination and can use transitive membership."""
    first_url = "/users/user-01/transitiveMemberOf?$select=id"
    second_url = "/next"
    graph = FakeGraphClient(
        {
            first_url: {
                "value": [{"id": "group-a"}],
                "@odata.nextLink": second_url,
            },
            second_url: {"value": [{"id": "group-b"}]},
        }
    )

    groups = await resolve_azure_ad_groups(
        graph_client=graph,
        user_id="user-01",
        transitive=True,
        timeout_seconds=1,
    )

    assert groups == frozenset({"group-a", "group-b"})
    assert graph.urls == [first_url, second_url]


@pytest.mark.asyncio
async def test_azure_ad_group_lookup_fails_closed_on_timeout_and_partial_data() -> None:
    """Graph timeouts and partial responses deny authorization."""
    timeout_client: GraphClient = TimeoutGraphClient()
    partial_client = FakeGraphClient(
        {"/users/user-01/memberOf?$select=id": {"value": [{"displayName": "ops"}]}}
    )

    with pytest.raises(AuthError, match="timed out"):
        await resolve_azure_ad_groups(
            graph_client=timeout_client,
            user_id="user-01",
            transitive=False,
            timeout_seconds=1,
        )
    with pytest.raises(AuthError, match="partial"):
        await resolve_azure_ad_groups(
            graph_client=partial_client,
            user_id="user-01",
            transitive=False,
            timeout_seconds=1,
        )


def test_public_key_identity_resolution_and_mismatch_denial() -> None:
    """File, LDAP, and Azure key records bind to the login username."""
    key = "ssh-ed25519 AAAAalice"
    ldap_records = [
        ProviderPublicKeyRecord(
            username="alice",
            public_keys=(key,),
            groups=frozenset({"group-a"}),
        )
    ]

    file_identity = resolve_file_public_key_identity(
        login_username="alice",
        presented_public_key=key,
        authorized_keys={"alice": [key]},
    )
    ldap_identity = resolve_ldap_public_key_identity(
        login_username="alice",
        presented_public_key=key,
        records=ldap_records,
    )
    azure_identity = resolve_azure_public_key_identity(
        login_username="alice",
        presented_public_key=key,
        records=ldap_records,
    )

    assert file_identity.username == "alice"
    assert ldap_identity.groups == frozenset({"group-a"})
    assert azure_identity.username == "alice"
    with pytest.raises(AuthError, match="mismatch"):
        resolve_file_public_key_identity(
            login_username="bob",
            presented_public_key=key,
            authorized_keys={"alice": [key]},
        )


def test_duplicate_key_mapped_to_multiple_usernames_is_denied() -> None:
    """Ambiguous public-key mappings fail closed."""
    key = "ssh-ed25519 AAAAshared"

    with pytest.raises(AuthError, match="multiple usernames"):
        resolve_file_public_key_identity(
            login_username="alice",
            presented_public_key=key,
            authorized_keys={"alice": [key], "bob": [key]},
        )
    with pytest.raises(AuthError, match="multiple usernames"):
        resolve_ldap_public_key_identity(
            login_username="alice",
            presented_public_key=key,
            records=[
                ProviderPublicKeyRecord(username="alice", public_keys=(key,)),
                ProviderPublicKeyRecord(username="bob", public_keys=(key,)),
            ],
        )


def test_authorization_uses_exact_case_sensitive_label_matching() -> None:
    """Users see only nodes whose labels exactly match derived role labels."""
    identity = ResolvedIdentity(
        username="alice",
        public_key="ssh-ed25519 AAAAalice",
        groups=frozenset({"group-a"}),
    )
    nodes = [
        NodeInventoryEntry(node_name="node-01", labels=frozenset({"prod"})),
        NodeInventoryEntry(node_name="node-02", labels=frozenset({"Prod"})),
        NodeInventoryEntry(node_name="node-03", labels=frozenset({"dev"})),
    ]

    assert visible_nodes_for_identity(
        identity=identity,
        nodes=nodes,
        group_to_roles={"group-a": ["operator"]},
        role_to_labels={"operator": ["prod"]},
    ) == ("node-01",)
    assert (
        visible_nodes_for_identity(
            identity=ResolvedIdentity("bob", "ssh-ed25519 AAAAbob", frozenset()),
            nodes=nodes,
            group_to_roles={"group-a": ["operator"]},
            role_to_labels={"operator": ["prod"]},
        )
        == ()
    )


@pytest.mark.parametrize("command", ["node-01", " node-01 ", "\tnode-01\n"])
def test_restricted_shell_accepts_exact_node_name_with_whitespace(command: str) -> None:
    """Restricted shell accepts only one selected node name."""
    assert parse_restricted_shell_command(command, ["node-01"]) == "node-01"


@pytest.mark.parametrize(
    "command",
    [
        "",
        "ssh node-01",
        "node-01 --flag",
        '"node-01"',
        "node-01;whoami",
        "node-01 | cat",
        "NODE=1 node-01",
        "scp",
        "sftp",
    ],
)
def test_restricted_shell_rejects_commands_and_metacharacters(command: str) -> None:
    """Restricted shell denies everything except an exact node name."""
    with pytest.raises(AuthError, match="exact node name|empty command"):
        parse_restricted_shell_command(command, ["node-01"])


def test_ssh_request_policy_rejects_forwarding_subsystems_and_root() -> None:
    """SSH feature requests outside the product contract are denied."""
    validate_ssh_request_policy(username="alice", command="node-01")
    with pytest.raises(AuthError, match="root|username"):
        validate_ssh_request_policy(username="root", command="node-01")
    with pytest.raises(AuthError, match="subsystems"):
        validate_ssh_request_policy(username="alice", subsystem="sftp")
    with pytest.raises(AuthError, match="forwarding"):
        validate_ssh_request_policy(username="alice", direct_tcpip=True)
    with pytest.raises(AuthError, match="agent forwarding"):
        validate_ssh_request_policy(username="alice", agent_forwarding=True)
    with pytest.raises(AuthError, match="X11"):
        validate_ssh_request_policy(username="alice", x11_forwarding=True)
    with pytest.raises(AuthError, match="SCP"):
        validate_ssh_request_policy(username="alice", command="scp")
