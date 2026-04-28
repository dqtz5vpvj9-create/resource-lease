"""Invalid-input tests for the public resource_lease API."""

from __future__ import annotations

import binascii
import json
import math
import struct

import pytest

from resource_lease import LeaseInfo
from resource_lease.backends.noop import NoopLeaseBackend
from resource_lease.info import (
    HEADER_LEN,
    MAX_RESOURCE_ID_CHARS,
    MAX_STATUS_CHARS,
    decode_frame,
    encode_frame,
)


@pytest.mark.parametrize("resource_id", [None, "", "   ", "dev\x00x"])
def test_lease_info_rejects_invalid_resource_id(resource_id):
    with pytest.raises((TypeError, ValueError)):
        LeaseInfo(resource_id=resource_id)


def test_lease_info_rejects_overlong_resource_id():
    with pytest.raises(ValueError):
        LeaseInfo(resource_id="x" * (MAX_RESOURCE_ID_CHARS + 1))


@pytest.mark.parametrize("status", [None, "", "   ", "bad\x00status", "bad\nstatus"])
def test_lease_info_rejects_invalid_status(status):
    with pytest.raises((TypeError, ValueError)):
        LeaseInfo(resource_id="r0", status=status)


def test_lease_info_rejects_overlong_status():
    with pytest.raises(ValueError):
        LeaseInfo(resource_id="r0", status="x" * (MAX_STATUS_CHARS + 1))


@pytest.mark.parametrize(
    "namespace",
    [
        None,
        "",
        "   ",
        "ns..x",
        ".ns",
        "ns.",
        "ns x",
        "ns/x",
        r"ns\x",
        "ns\nx",
        "雪",
    ],
)
def test_backends_reject_invalid_namespace(namespace):
    with pytest.raises((TypeError, ValueError)):
        NoopLeaseBackend(namespace)


@pytest.mark.parametrize("resource_id", [None, "", "   ", "dev\x00x"])
def test_backend_methods_reject_invalid_resource_id(resource_id):
    backend = NoopLeaseBackend("validation.ns")
    with pytest.raises((TypeError, ValueError)):
        backend.query(resource_id)
    with pytest.raises((TypeError, ValueError)):
        backend.acquire(resource_id, LeaseInfo(resource_id="valid"))


def test_acquire_rejects_mismatched_lease_info_resource_id():
    backend = NoopLeaseBackend("validation.ns")
    with pytest.raises(ValueError, match="does not match"):
        backend.acquire("r0", LeaseInfo(resource_id="r1"))


def test_update_rejects_mismatched_lease_info_resource_id():
    backend = NoopLeaseBackend("validation.ns")
    handle = backend.acquire("r0", LeaseInfo(resource_id="r0"))
    try:
        with pytest.raises(ValueError, match="does not match"):
            backend.update("r0", LeaseInfo(resource_id="r1"))
    finally:
        handle.release()


def test_lease_info_accepts_none_extra_as_empty_dict():
    info = LeaseInfo(resource_id="r0", extra=None)
    assert info.extra == {}


@pytest.mark.parametrize("extra", [["bad"], "bad"])
def test_lease_info_rejects_non_dict_extra(extra):
    with pytest.raises(TypeError):
        LeaseInfo(resource_id="r0", extra=extra)


@pytest.mark.parametrize("field", ["agent_name", "purpose", "run_id", "cmdline"])
def test_lease_info_rejects_non_string_text_fields(field):
    with pytest.raises(TypeError):
        LeaseInfo(resource_id="r0", **{field: object()})


@pytest.mark.parametrize("field", ["resource_hash", "owner_token"])
def test_lease_info_rejects_control_chars_in_backend_fields(field):
    with pytest.raises(ValueError):
        LeaseInfo(resource_id="r0", **{field: "bad\nvalue"})


@pytest.mark.parametrize("field", ["pid", "uid"])
def test_lease_info_rejects_non_integer_ids(field):
    with pytest.raises(TypeError):
        LeaseInfo(resource_id="r0", **{field: "not-int"})


@pytest.mark.parametrize("started_at", ["not-float", math.inf, -1])
def test_lease_info_rejects_invalid_started_at(started_at):
    with pytest.raises((TypeError, ValueError)):
        LeaseInfo(resource_id="r0", started_at=started_at)


def test_encode_frame_rejects_non_json_extra():
    with pytest.raises(ValueError, match="JSON-serializable"):
        encode_frame(LeaseInfo(resource_id="r0", extra={"bad": object()}))


def test_encode_frame_rejects_portability_size_overflow():
    with pytest.raises(ValueError, match="frame too large"):
        encode_frame(LeaseInfo(resource_id="r0", extra={"blob": "x" * 70000}))


def _frame_for_body(body) -> bytes:
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    crc = binascii.crc32(payload) & 0xFFFFFFFF
    return struct.pack("<4sIQII", b"RLIF", 1, 0, len(payload), crc) + payload


@pytest.mark.parametrize(
    "body",
    [
        [],
        {"kind": "resource_lease.info", "resource_id": "r0", "pid": "not-int"},
        {"kind": "resource_lease.info", "resource_id": "r0", "extra": ["bad"]},
        {"kind": "resource_lease.info", "resource_id": ""},
        {"kind": "resource_lease.info", "resource_id": "r0", "namespace": "bad ns"},
    ],
)
def test_decode_frame_rejects_valid_crc_but_bad_typed_payload(body):
    assert decode_frame(_frame_for_body(body)) is None


def test_decode_frame_rejects_empty_json_payload_with_valid_header():
    header = struct.pack("<4sIQII", b"RLIF", 1, 0, 0, 0)
    assert len(header) == HEADER_LEN
    assert decode_frame(header) is None
