"""Unit tests for the RLIF frame codec."""

from __future__ import annotations

import binascii
import json
import struct

from resource_lease.info import (
    HEADER_LEN,
    LeaseInfo,
    decode_frame,
    encode_frame,
)


def _sample_info() -> LeaseInfo:
    return LeaseInfo(
        resource_id="dev0",
        agent_name="alice",
        purpose="smoke",
        run_id="run-x",
        pid=12345,
        uid=1000,
        started_at=1700000000.5,
        cmdline="python -m foo",
        extra={"k": "v", "nested": {"a": 1}},
        status="allocated",
        namespace="ns.x",
        resource_hash="aabbccdd",
        owner_token="12345-99-deadbeef",
    )


def test_round_trip():
    info = _sample_info()
    buf = encode_frame(info)
    decoded = decode_frame(buf)
    assert decoded is not None
    for fld in (
        "resource_id", "agent_name", "purpose", "run_id",
        "pid", "uid", "started_at", "cmdline", "extra",
        "status", "namespace", "resource_hash", "owner_token",
    ):
        assert getattr(decoded, fld) == getattr(info, fld), fld


def test_odd_seq_rejected_by_default():
    info = _sample_info()
    buf = encode_frame(info, seq=3)
    assert decode_frame(buf) is None


def test_odd_seq_accepted_when_opted_in():
    info = _sample_info()
    buf = encode_frame(info, seq=3)
    decoded = decode_frame(buf, accept_odd_seq=True)
    assert decoded is not None
    assert decoded.resource_id == "dev0"


def test_even_seq_accepted():
    info = _sample_info()
    buf = encode_frame(info, seq=4)
    assert decode_frame(buf) is not None


def test_bad_magic():
    info = _sample_info()
    buf = bytearray(encode_frame(info))
    buf[0] = ord("X")
    assert decode_frame(bytes(buf)) is None


def test_bad_version():
    info = _sample_info()
    buf = bytearray(encode_frame(info))
    magic, _version, seq, json_len, crc = struct.unpack("<4sIQII", bytes(buf[:HEADER_LEN]))
    buf[:HEADER_LEN] = struct.pack("<4sIQII", magic, 99, seq, json_len, crc)
    assert decode_frame(bytes(buf)) is None


def test_bad_crc():
    info = _sample_info()
    buf = bytearray(encode_frame(info))
    # mutate the JSON payload but leave crc untouched
    buf[HEADER_LEN] = (buf[HEADER_LEN] + 1) & 0xFF
    assert decode_frame(bytes(buf)) is None


def test_truncated():
    info = _sample_info()
    buf = encode_frame(info)
    assert decode_frame(buf[:HEADER_LEN - 1]) is None
    # Header present but JSON truncated
    short = buf[: HEADER_LEN + 5]
    assert decode_frame(short) is None


def test_json_len_overflow():
    """A frame whose declared json_len exceeds the buffer must be rejected."""
    info = _sample_info()
    buf = bytearray(encode_frame(info))
    magic, version, seq, _json_len, crc = struct.unpack("<4sIQII", bytes(buf[:HEADER_LEN]))
    # Re-pack with absurd json_len
    buf[:HEADER_LEN] = struct.pack("<4sIQII", magic, version, seq, 10_000_000, crc)
    assert decode_frame(bytes(buf)) is None


def test_padding_ignored():
    info = _sample_info()
    buf = encode_frame(info)
    decoded = decode_frame(buf + b"\x00" * 1024)
    assert decoded is not None
    assert decoded.agent_name == "alice"


def test_unknown_kind_rejected():
    """Frames whose JSON 'kind' is not 'resource_lease.info' must be rejected."""
    import json
    body = json.dumps({"kind": "something_else", "version": 1}).encode("utf-8")
    crc = binascii.crc32(body) & 0xFFFFFFFF
    header = struct.pack("<4sIQII", b"RLIF", 1, 0, len(body), crc)
    assert decode_frame(header + body) is None


def test_malformed_json_rejected_with_valid_crc():
    body = b"{not-json"
    crc = binascii.crc32(body) & 0xFFFFFFFF
    header = struct.pack("<4sIQII", b"RLIF", 1, 0, len(body), crc)
    assert decode_frame(header + body) is None


def test_defaults_when_json_fields_missing():
    body = json.dumps({
        "kind": "resource_lease.info",
        "version": 1,
        "resource_id": "r0",
    }).encode("utf-8")
    crc = binascii.crc32(body) & 0xFFFFFFFF
    header = struct.pack("<4sIQII", b"RLIF", 1, 0, len(body), crc)
    decoded = decode_frame(header + body)
    assert decoded is not None
    assert decoded.resource_id == "r0"
    assert decoded.agent_name == ""
    assert decoded.extra == {}
    assert decoded.status == "busy"
    assert decoded.metadata_available is True
