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
import secrets
import struct
import time
from dataclasses import dataclass, field, replace
from typing import Any, Dict, Optional

_MAGIC = b"RLIF"
_VERSION = 1
_HEADER_FMT = "<4sIQII"  # magic, version, seq, json_len, crc32
_HEADER_LEN = struct.calcsize(_HEADER_FMT)


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
    except Exception:
        return None
    if body.get("kind") != "resource_lease.info":
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
        extra=body.get("extra") or {},
        status=body.get("status", "") or "busy",
        namespace=body.get("namespace", "") or "",
        resource_hash=body.get("resource_hash", "") or "",
        owner_token=body.get("owner_token", "") or "",
        metadata_available=bool(body.get("metadata_available", True)),
    )


def encode_frame(info: LeaseInfo, *, seq: int = 0) -> bytes:
    json_bytes = _info_to_json_bytes(info)
    crc = binascii.crc32(json_bytes) & 0xFFFFFFFF
    header = struct.pack(_HEADER_FMT, _MAGIC, _VERSION, seq, len(json_bytes), crc)
    return header + json_bytes


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
