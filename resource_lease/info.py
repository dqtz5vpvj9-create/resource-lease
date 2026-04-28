"""LeaseInfo dataclass and the cross-backend frame codec.

Frame format (all little-endian):
    magic     4 bytes   "RLIF"
    version   u32       1
    seq       u64       even = stable, odd = writer mid-update
    json_len  u32       payload length in bytes
    crc32     u32       CRC32 over the json bytes only
    json      bytes     UTF-8 JSON object (see below)
    pad       zeros     ignored

The ``seq`` field exists for the Windows shared-memory writer (which cannot
update atomically); set it odd before writing payload, then even after, so a
concurrent reader can detect torn writes. Linux's abstract-socket GET protocol
delivers the frame in a single ``send`` call, so seq=0 is fine there.
"""

from __future__ import annotations

import binascii
import json
import math
import secrets
import struct
import time
from dataclasses import dataclass, field, replace
from typing import Any, Dict, Optional

_MAGIC = b"RLIF"
_VERSION = 1
_HEADER_FMT = "<4sIQII"  # magic, version, seq, json_len, crc32
_HEADER_LEN = struct.calcsize(_HEADER_FMT)
MAX_RESOURCE_ID_CHARS = 4096
MAX_STATUS_CHARS = 128
MAX_INFO_FRAME_BYTES = 65536


def _require_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be str, got {type(value).__name__}")
    return value


def _reject_nul(value: str, field_name: str) -> None:
    if "\x00" in value:
        raise ValueError(f"{field_name} must not contain NUL bytes")


def _reject_control(value: str, field_name: str) -> None:
    _reject_nul(value, field_name)
    for ch in value:
        if ord(ch) < 32 or ord(ch) == 127:
            raise ValueError(f"{field_name} must not contain control characters")


def validate_resource_id(resource_id: str) -> str:
    """Validate the opaque resource name accepted by every backend.

    The value remains opaque: the library does not parse device names, hosts,
    ports, GPU ids, etc.  We only reject values that cannot be represented
    safely in metadata or are overwhelmingly likely to be caller bugs.
    """
    resource_id = _require_str(resource_id, "resource_id")
    if not resource_id or not resource_id.strip():
        raise ValueError("resource_id must be non-empty")
    _reject_nul(resource_id, "resource_id")
    if len(resource_id) > MAX_RESOURCE_ID_CHARS:
        raise ValueError(
            f"resource_id too long ({len(resource_id)} > {MAX_RESOURCE_ID_CHARS})"
        )
    return resource_id


def validate_namespace(namespace: str, *, allow_empty: bool = False) -> str:
    namespace = _require_str(namespace, "namespace")
    if not namespace:
        if allow_empty:
            return namespace
        raise ValueError("namespace must be non-empty")
    if not namespace.strip():
        raise ValueError("namespace must be non-empty")
    _reject_control(namespace, "namespace")
    if any(ch.isspace() for ch in namespace):
        raise ValueError("namespace must not contain whitespace")
    if "/" in namespace or "\\" in namespace:
        raise ValueError("namespace must not contain slashes or backslashes")
    try:
        namespace.encode("ascii")
    except UnicodeEncodeError as e:
        raise ValueError("namespace must be ASCII") from e
    if "." in namespace and any(part == "" for part in namespace.split(".")):
        raise ValueError(f"namespace must not contain empty dot segments: {namespace!r}")
    return namespace


def validate_status(status: str) -> str:
    status = _require_str(status, "status")
    if not status or not status.strip():
        raise ValueError("status must be non-empty")
    _reject_control(status, "status")
    if len(status) > MAX_STATUS_CHARS:
        raise ValueError(f"status too long ({len(status)} > {MAX_STATUS_CHARS})")
    return status


@dataclass
class LeaseInfo:
    """Owner metadata for a held lease.

    Consumers populate the agent_name/purpose/run_id/extra fields. The backend
    fills namespace/resource_hash/owner_token at acquire time via
    :meth:`with_backend_metadata`.
    """

    resource_id: str
    agent_name: str = ""
    purpose: str = ""
    run_id: str = ""
    pid: int = 0
    uid: int = 0
    started_at: float = 0.0
    cmdline: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    status: str = "busy"
    namespace: str = ""
    resource_hash: str = ""
    owner_token: str = ""
    metadata_available: bool = True

    def __post_init__(self) -> None:
        self.resource_id = validate_resource_id(self.resource_id)
        self.agent_name = _require_str(self.agent_name, "agent_name")
        self.purpose = _require_str(self.purpose, "purpose")
        self.run_id = _require_str(self.run_id, "run_id")
        self.cmdline = _require_str(self.cmdline, "cmdline")
        self.status = validate_status(self.status)
        self.namespace = validate_namespace(self.namespace, allow_empty=True)
        self.resource_hash = _require_str(self.resource_hash, "resource_hash")
        self.owner_token = _require_str(self.owner_token, "owner_token")
        _reject_control(self.resource_hash, "resource_hash")
        _reject_control(self.owner_token, "owner_token")
        if self.extra is None:
            self.extra = {}
        if not isinstance(self.extra, dict):
            raise TypeError(f"extra must be dict, got {type(self.extra).__name__}")
        try:
            self.pid = int(self.pid or 0)
        except (TypeError, ValueError) as e:
            raise TypeError("pid must be an integer") from e
        try:
            self.uid = int(self.uid or 0)
        except (TypeError, ValueError) as e:
            raise TypeError("uid must be an integer") from e
        try:
            self.started_at = float(self.started_at or 0.0)
        except (TypeError, ValueError) as e:
            raise TypeError("started_at must be a finite non-negative number") from e
        if not math.isfinite(self.started_at) or self.started_at < 0:
            raise ValueError("started_at must be a finite non-negative number")

    def with_backend_metadata(
        self,
        *,
        namespace: str,
        resource_hash: str,
        owner_token: Optional[str] = None,
    ) -> LeaseInfo:
        return replace(
            self,
            namespace=namespace,
            resource_hash=resource_hash,
            owner_token=owner_token or new_owner_token(self.pid),
            started_at=self.started_at or time.time(),
            metadata_available=True,
        )


def new_owner_token(pid: int) -> str:
    """`<pid>-<time_ns>-<random>` — distinguishes acquire generations and
    survives PID reuse."""
    return f"{pid}-{time.time_ns()}-{secrets.token_hex(8)}"


def _info_to_json_bytes(info: LeaseInfo) -> bytes:
    body = {
        "kind": "resource_lease.info",
        "version": _VERSION,
        "namespace": info.namespace,
        "resource_id": info.resource_id,
        "resource_hash": info.resource_hash,
        "owner_token": info.owner_token,
        "pid": info.pid,
        "uid": info.uid,
        "agent_name": info.agent_name,
        "purpose": info.purpose,
        "run_id": info.run_id,
        "started_at": info.started_at,
        "cmdline": info.cmdline,
        "extra": info.extra,
        "status": info.status,
        "metadata_available": info.metadata_available,
    }
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _json_bytes_to_info(buf: bytes) -> Optional[LeaseInfo]:
    try:
        body = json.loads(buf.decode("utf-8"))
        if not isinstance(body, dict):
            return None
        if body.get("kind") != "resource_lease.info":
            return None
        extra = body.get("extra") or {}
        if not isinstance(extra, dict):
            return None
        return LeaseInfo(
            resource_id=body.get("resource_id", ""),
            agent_name=body.get("agent_name", "") or "",
            purpose=body.get("purpose", "") or "",
            run_id=body.get("run_id", "") or "",
            pid=int(body.get("pid") or 0),
            uid=int(body.get("uid") or 0),
            started_at=float(body.get("started_at") or 0.0),
            cmdline=body.get("cmdline", "") or "",
            extra=extra,
            status=body.get("status", "") or "busy",
            namespace=body.get("namespace", "") or "",
            resource_hash=body.get("resource_hash", "") or "",
            owner_token=body.get("owner_token", "") or "",
            metadata_available=bool(body.get("metadata_available", True)),
        )
    except Exception:
        return None


def encode_frame(info: LeaseInfo, *, seq: int = 0) -> bytes:
    try:
        json_bytes = _info_to_json_bytes(info)
    except (TypeError, ValueError) as e:
        raise ValueError("LeaseInfo must be JSON-serializable") from e
    crc = binascii.crc32(json_bytes) & 0xFFFFFFFF
    header = struct.pack(_HEADER_FMT, _MAGIC, _VERSION, seq, len(json_bytes), crc)
    frame = header + json_bytes
    if len(frame) > MAX_INFO_FRAME_BYTES:
        raise ValueError(
            f"LeaseInfo frame too large ({len(frame)} > {MAX_INFO_FRAME_BYTES} bytes)"
        )
    return frame


def decode_frame(buf: bytes, *, accept_odd_seq: bool = False) -> Optional[LeaseInfo]:
    if len(buf) < _HEADER_LEN:
        return None
    magic, version, seq, json_len, crc = struct.unpack(_HEADER_FMT, buf[:_HEADER_LEN])
    if magic != _MAGIC:
        return None
    if version != _VERSION:
        return None
    if not accept_odd_seq and (seq & 1):
        return None
    if json_len > len(buf) - _HEADER_LEN:
        return None
    json_bytes = buf[_HEADER_LEN : _HEADER_LEN + json_len]
    if (binascii.crc32(json_bytes) & 0xFFFFFFFF) != crc:
        return None
    return _json_bytes_to_info(json_bytes)


HEADER_LEN = _HEADER_LEN
"""Public alias so backends can compute frame sizes without touching internals."""
