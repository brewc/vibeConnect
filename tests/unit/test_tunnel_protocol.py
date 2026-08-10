"""Tests for the shared tunnel frame protocol."""

from __future__ import annotations

import json
import struct

import pytest

from vibeconnect_common.crypto import SecretValue
from vibeconnect_common.models import TunnelFrameType
from vibeconnect_common.tunnel import (
    TunnelProtocolError,
    decode_frame,
    decode_tunnel_secret_rotation,
    encode_frame,
    encode_tunnel_secret_rotation,
)


def test_tunnel_frame_round_trips_opaque_payload() -> None:
    """Frame encoding preserves binary SSH payload bytes exactly."""
    payload = b"\x00ssh\xffpayload\n"

    decoded = decode_frame(
        encode_frame(
            frame_type=TunnelFrameType.SESSION_DATA,
            request_id="req-01",
            channel_id="chan-01",
            payload=payload,
        )
    )

    assert decoded.frame.type is TunnelFrameType.SESSION_DATA
    assert decoded.frame.request_id == "req-01"
    assert decoded.frame.channel_id == "chan-01"
    assert decoded.frame.payload_length == len(payload)
    assert decoded.payload == payload


@pytest.mark.parametrize(
    "data,match",
    [
        (b"", "header length"),
        (struct.pack("!I", 0), "header length"),
        (struct.pack("!I", 2) + b"{}", "frame type"),
        (
            struct.pack("!I", len(b'{"type":"not-real"}')) + b'{"type":"not-real"}',
            "unknown frame type",
        ),
    ],
)
def test_tunnel_frame_rejects_malformed_frames(data: bytes, match: str) -> None:
    """Malformed frames are rejected before tunnel processing."""
    with pytest.raises(TunnelProtocolError, match=match):
        decode_frame(data)


def test_tunnel_frame_rejects_oversized_payload() -> None:
    """Oversized encoded or claimed payloads fail closed."""
    with pytest.raises(TunnelProtocolError, match="too large"):
        encode_frame(
            frame_type=TunnelFrameType.SESSION_DATA,
            request_id="req-01",
            channel_id="chan-01",
            payload=b"abc",
            max_frame_bytes=2,
        )

    header = json.dumps(
        {
            "type": TunnelFrameType.SESSION_DATA.value,
            "request_id": "req-01",
            "channel_id": "chan-01",
            "payload_length": 3,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    with pytest.raises(TunnelProtocolError, match="too large"):
        decode_frame(
            struct.pack("!I", len(header)) + header + b"abc", max_frame_bytes=2
        )


def test_tunnel_frame_rejects_unknown_type() -> None:
    """Unknown frame types are not ignored."""
    header = (
        b'{"type":"future","request_id":"req-01","channel_id":null,"payload_length":0}'
    )

    with pytest.raises(TunnelProtocolError, match="unknown frame type"):
        decode_frame(struct.pack("!I", len(header)) + header)


def test_tunnel_secret_rotation_round_trips_control_frame() -> None:
    """Tunnel secret rotation travels only as an authenticated control frame."""
    encoded = encode_tunnel_secret_rotation(
        request_id="rotate-01",
        node_name="node-01",
        tunnel_secret=SecretValue("new-secret"),
    )

    decoded_frame = decode_frame(encoded)
    decoded_payload = decode_tunnel_secret_rotation(encoded)

    assert decoded_frame.frame.type is TunnelFrameType.ROTATE_TUNNEL_SECRET
    assert decoded_frame.frame.channel_id is None
    assert decoded_payload.request_id == "rotate-01"
    assert decoded_payload.node_name == "node-01"
    assert decoded_payload.tunnel_secret.reveal() == "new-secret"


def test_tunnel_secret_rotation_rejects_session_channel_frames() -> None:
    """Secret rotation cannot be sent as session data or over a PTY channel."""
    bad_frame = encode_frame(
        frame_type=TunnelFrameType.ROTATE_TUNNEL_SECRET,
        request_id="rotate-01",
        channel_id="chan-01",
        payload=b'{"node_name":"node-01","tunnel_secret":"new-secret"}',
    )

    with pytest.raises(TunnelProtocolError, match="control frame"):
        decode_tunnel_secret_rotation(bad_frame)


@pytest.mark.parametrize(
    "payload,match",
    [
        (b"not-json", "payload is invalid"),
        (b"[]", "payload must be an object"),
        (b'{"tunnel_secret":"new-secret"}', "node_name"),
        (b'{"node_name":"node-01","tunnel_secret":""}', "tunnel_secret"),
    ],
)
def test_tunnel_secret_rotation_rejects_malformed_payloads(
    payload: bytes, match: str
) -> None:
    """Malformed secret-rotation payloads fail before state changes."""
    frame = encode_frame(
        frame_type=TunnelFrameType.ROTATE_TUNNEL_SECRET,
        request_id="rotate-01",
        channel_id=None,
        payload=payload,
    )

    with pytest.raises(TunnelProtocolError, match=match):
        decode_tunnel_secret_rotation(frame)
