"""Linux backend: abstract Unix domain sockets.

Each held lease is an abstract-namespace ``AF_UNIX`` socket whose name encodes
the (namespace, uid, resource_id) tuple. The owner ``bind()``s the name and
serves a tiny ``GET``-protocol on it; ``query()`` connects and reads the frame.
The kernel removes the abstract name automatically when the owner process dies
or the socket is closed — no cleanup required.

Discovery is done by scanning ``/proc/net/unix``: the kernel exposes every
abstract name there, prefixed by ``@``. We don't keep any user-space index.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import logging
import os
import socket
import struct
import threading
from dataclasses import dataclass, replace
from typing import Dict, List, Optional

from ..base import LeaseBackend
from ..errors import LeaseConflict
from ..handle import LeaseHandle
from ..info import LeaseInfo, decode_frame, encode_frame, new_owner_token

logger = logging.getLogger("resource_lease.abstract_socket")

_SENTINEL = "resource_lease.v1."
_SUN_PATH_MAX = 108  # struct sockaddr_un.sun_path on Linux
_UCRED_FMT = "3i"
_UCRED_LEN = struct.calcsize(_UCRED_FMT)


def _resource_hash(resource_id: str) -> str:
    return hashlib.sha256(resource_id.encode("utf-8")).hexdigest()[:16]


def _abstract_name(namespace: str, uid: int, resource_id: str) -> bytes:
    """Compute the abstract socket name (leading NUL + ASCII suffix)."""
    suffix = f"{_SENTINEL}{namespace}.{uid}.{_resource_hash(resource_id)}"
    name = b"\x00" + suffix.encode("ascii")
    if len(name) > _SUN_PATH_MAX:
        raise ValueError(
            f"abstract socket name too long ({len(name)} > {_SUN_PATH_MAX}); "
            f"shorten the namespace ({namespace!r})"
        )
    return name


def _set_cloexec(sock: socket.socket) -> None:
    """Belt-and-suspenders: set FD_CLOEXEC + non-inheritable so subprocess
    children (e.g. the agent's ``demo_ysh_dag.py``) don't keep the lease alive
    after the orchestrator releases."""
    sock.set_inheritable(False)
    fd = sock.fileno()
    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)


def _peer_uid(conn: socket.socket) -> Optional[int]:
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED_LEN)
    except OSError:
        return None
    if len(raw) < _UCRED_LEN:
        return None
    _pid, uid, _gid = struct.unpack(_UCRED_FMT, raw[:_UCRED_LEN])
    return int(uid)


@dataclass
class _Lease:
    sock: socket.socket
    thread: threading.Thread
    closed: threading.Event
    info: LeaseInfo
    frame: bytes
    lock: threading.Lock


class AbstractSocketLeaseBackend(LeaseBackend):
    def __init__(self, namespace: str) -> None:
        if "." in namespace and any(p == "" for p in namespace.split(".")):
            raise ValueError(f"namespace must not contain empty dot segments: {namespace!r}")
        if not namespace:
            raise ValueError("namespace must be non-empty")
        self.namespace = namespace
        self._uid = os.getuid()
        # Backend owns the underlying sockets so a forgotten/GC'd LeaseHandle
        # does NOT silently release the lease. Released only by explicit
        # handle.release() or backend.close().
        self._held: Dict[str, _Lease] = {}
        self._held_lock = threading.Lock()

    # ── acquire / release ────────────────────────────────────────────────

    def acquire(self, resource_id: str, info: LeaseInfo) -> LeaseHandle:
        name = _abstract_name(self.namespace, self._uid, resource_id)
        rhash = _resource_hash(resource_id)

        with self._held_lock:
            if resource_id in self._held:
                raise LeaseConflict(resource_id, self.query(resource_id))

        if info.pid == 0:
            info = replace(info, pid=os.getpid())
        if info.uid == 0:
            info = replace(info, uid=self._uid)

        stamped = info.with_backend_metadata(
            namespace=self.namespace,
            resource_hash=rhash,
            owner_token=new_owner_token(info.pid),
        )
        frame = encode_frame(stamped)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        _set_cloexec(sock)
        try:
            sock.bind(name)
        except OSError as e:
            sock.close()
            if e.errno == errno.EADDRINUSE:
                owner = self.query(resource_id, timeout=0.5)
                raise LeaseConflict(resource_id, owner) from None
            raise

        sock.listen(8)

        closed = threading.Event()
        lease = _Lease(
            sock=sock,
            thread=None,  # type: ignore[arg-type]
            closed=closed,
            info=stamped,
            frame=frame,
            lock=threading.Lock(),
        )
        thread = threading.Thread(
            target=self._serve,
            name=f"resource_lease.serve[{self.namespace}/{rhash}]",
            args=(lease,),
            daemon=True,
        )
        lease.thread = thread
        thread.start()

        with self._held_lock:
            self._held[resource_id] = lease

        return LeaseHandle(
            resource_id,
            stamped,
            lambda rid=resource_id: self._release(rid),
            lambda info, rid=resource_id: self.update(rid, info),
        )

    def update(self, resource_id: str, info: LeaseInfo) -> LeaseInfo:
        with self._held_lock:
            lease = self._held.get(resource_id)
        if lease is None:
            raise RuntimeError(f"resource is not held by this backend: {resource_id!r}")
        with lease.lock:
            current = lease.info
            if info.pid == 0:
                info = replace(info, pid=current.pid or os.getpid())
            if info.uid == 0:
                info = replace(info, uid=current.uid or self._uid)
            stamped = replace(
                info,
                namespace=self.namespace,
                resource_hash=current.resource_hash,
                owner_token=current.owner_token,
                started_at=current.started_at,
                metadata_available=True,
            )
            lease.info = stamped
            lease.frame = encode_frame(stamped)
            return stamped

    def _release(self, resource_id: str) -> None:
        with self._held_lock:
            lease = self._held.pop(resource_id, None)
        if lease is None:
            return
        lease.closed.set()
        try:
            lease.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            lease.sock.close()
        except OSError:
            pass

    def close(self) -> None:
        with self._held_lock:
            ids = list(self._held.keys())
        for rid in ids:
            self._release(rid)

    # ── serve thread ─────────────────────────────────────────────────────

    def _serve(self, lease: _Lease) -> None:
        sock = lease.sock
        closed = lease.closed
        while not closed.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            try:
                conn.settimeout(2.0)
                peer = _peer_uid(conn)
                if peer is not None and peer != self._uid:
                    try:
                        conn.sendall(b'{"error":"permission_denied"}\n')
                    except OSError:
                        pass
                    continue
                try:
                    req = conn.recv(64)
                except OSError:
                    continue
                if req.strip() == b"GET":
                    try:
                        with lease.lock:
                            frame = lease.frame
                        conn.sendall(frame)
                    except OSError:
                        pass
                else:
                    try:
                        conn.sendall(b'{"error":"unknown_request"}\n')
                    except OSError:
                        pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    # ── query ────────────────────────────────────────────────────────────

    def query(
        self, resource_id: str, *, timeout: float = 0.5
    ) -> Optional[LeaseInfo]:
        name = _abstract_name(self.namespace, self._uid, resource_id)
        return _connect_and_get(name, timeout)

    # ── list / list_namespaces ───────────────────────────────────────────

    def list(self) -> List[LeaseInfo]:
        prefix = f"@{_SENTINEL}{self.namespace}.{self._uid}."
        names = _scan_proc_net_unix_with_prefix(prefix)
        out: List[LeaseInfo] = []
        for at_name in names:
            addr = b"\x00" + at_name[1:].encode("ascii", errors="replace")
            info = _connect_and_get(addr, timeout=0.5)
            if info is not None:
                out.append(info)
        return out

    def list_namespaces(self) -> List[str]:
        prefix = f"@{_SENTINEL}"
        names = _scan_proc_net_unix_with_prefix(prefix)
        seen: set = set()
        my_uid = str(self._uid)
        for at_name in names:
            tail = at_name[len(prefix):]
            try:
                ns_part, uid_part, _rid = tail.rsplit(".", 2)
            except ValueError:
                continue
            if uid_part != my_uid:
                continue
            if ns_part:
                seen.add(ns_part)
        return sorted(seen)


# ── helpers ──────────────────────────────────────────────────────────────


def _connect_and_get(
    addr: bytes, timeout: float
) -> Optional[LeaseInfo]:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect(addr)
        except OSError:
            return None
        try:
            sock.sendall(b"GET\n")
        except OSError:
            return None
        chunks = []
        while True:
            try:
                buf = sock.recv(4096)
            except socket.timeout:
                return None
            except OSError:
                break
            if not buf:
                break
            chunks.append(buf)
        data = b"".join(chunks)
        if not data:
            return None
        return decode_frame(data)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _scan_proc_net_unix_with_prefix(prefix: str) -> List[str]:
    """Return abstract names from /proc/net/unix that start with *prefix*.

    Names are returned in their ``@``-prefixed display form (kernel convention
    for abstract names).
    """
    out: List[str] = []
    try:
        with open("/proc/net/unix", encoding="utf-8", errors="replace") as f:
            f.readline()  # skip header
            for line in f:
                parts = line.rstrip("\n").split()
                if len(parts) < 8:
                    continue
                name = parts[7]
                if not name.startswith("@"):
                    continue
                if name.startswith(prefix):
                    out.append(name)
    except FileNotFoundError:
        pass
    return out
