"""Shared framed tunnel protocol helpers."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass

from vibeconnect_common.models import TunnelFrame, TunnelFrameType

FRAME_HEADER_MAX_BYTES = 16 * 1024
DEFAULT_FRAME_MAX_BYTES = 1024 * 1024


class TunnelProtocolError(ValueError):
    """Raised when a tunnel frame is malformed or unsafe."""


@dataclass(frozen=True, slots=True)
class DecodedTunnelFrame:
    """A decoded tunnel frame and opaque payload bytes."""

    frame: TunnelFrame
    payload: bytes


def encode_frame(
    *,
    frame_type: TunnelFrameType,
    request_id: str,
    channel_id: str | None,
    payload: bytes = b"",
    max_frame_bytes: int = DEFAULT_FRAME_MAX_BYTES,
) -> bytes:
    """Encode a tunnel frame with a bounded JSON header and opaque payload."""
    _validate_frame_size(payload, max_frame_bytes)
    if not request_id:
        raise TunnelProtocolError("request_id is required")
    header = {
        "type": frame_type.value,
        "request_id": request_id,
        "channel_id": channel_id,
        "payload_length": len(payload),
    }
    header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    if len(header_bytes) > FRAME_HEADER_MAX_BYTES:
        raise TunnelProtocolError("frame header is too large")
    return struct.pack("!I", len(header_bytes)) + header_bytes + payload


def decode_frame(
    data: bytes, *, max_frame_bytes: int = DEFAULT_FRAME_MAX_BYTES
) -> DecodedTunnelFrame:
    """Decode one complete tunnel frame and reject malformed input."""
    if len(data) < 4:
        raise TunnelProtocolError("frame header length is missing")
    header_length = struct.unpack("!I", data[:4])[0]
    if header_length == 0 or header_length > FRAME_HEADER_MAX_BYTES:
        raise TunnelProtocolError("frame header length is invalid")
    header_end = 4 + header_length
    if len(data) < header_end:
        raise TunnelProtocolError("frame header is incomplete")
    try:
        header = json.loads(data[4:header_end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TunnelProtocolError("frame header is not valid JSON") from exc
    if not isinstance(header, dict):
        raise TunnelProtocolError("frame header must be an object")
    frame_type = _decode_frame_type(header.get("type"))
    request_id = header.get("request_id")
    channel_id = header.get("channel_id")
    payload_length = header.get("payload_length")
    if not isinstance(request_id, str) or not request_id:
        raise TunnelProtocolError("request_id is required")
    if channel_id is not None and not isinstance(channel_id, str):
        raise TunnelProtocolError("channel_id must be a string or null")
    if not isinstance(payload_length, int) or isinstance(payload_length, bool):
        raise TunnelProtocolError("payload_length must be an integer")
    if payload_length < 0:
        raise TunnelProtocolError("payload_length cannot be negative")
    _validate_payload_length(payload_length, max_frame_bytes)
    payload = data[header_end:]
    if len(payload) != payload_length:
        raise TunnelProtocolError("frame payload length mismatch")
    return DecodedTunnelFrame(
        frame=TunnelFrame(
            type=frame_type,
            request_id=request_id,
            channel_id=channel_id,
            payload_length=payload_length,
        ),
        payload=payload,
    )


def _decode_frame_type(value: object) -> TunnelFrameType:
    if not isinstance(value, str):
        raise TunnelProtocolError("frame type is required")
    try:
        return TunnelFrameType(value)
    except ValueError as exc:
        raise TunnelProtocolError("unknown frame type") from exc


def _validate_frame_size(payload: bytes, max_frame_bytes: int) -> None:
    _validate_payload_length(len(payload), max_frame_bytes)


def _validate_payload_length(payload_length: int, max_frame_bytes: int) -> None:
    if max_frame_bytes <= 0:
        raise TunnelProtocolError("max_frame_bytes must be positive")
    if payload_length > max_frame_bytes:
        raise TunnelProtocolError("frame payload is too large")
