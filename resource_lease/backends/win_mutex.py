"""Windows backend: named mutex (ownership) + named file mapping (metadata + index).

Three classes of named kernel object per namespace:

1. **per-resource mutex + info mapping** — ownership truth and current owner's
   metadata. ``WaitForSingleObject`` on the mutex is the source of truth for
   whether a resource is held; ``WAIT_ABANDONED`` is the crash-recovery signal.
2. **namespace index** — 256 mapping shards keyed by the first byte of
   ``sha256(resource_id)``, recording active leases for ``list(namespace)``.
3. **catalog** — 16 mapping shards keyed by ``sha256(namespace)[0]``, recording
   active namespaces for ``list_namespaces()``.

A single keeper thread per held lease holds the mutex from acquire to release —
required because Win32 mutex ownership is thread-bound.

This module is imported lazily from :mod:`resource_lease.autoselect`; ``import
resource_lease`` on Linux must not fail just because pywin32 is absent.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..base import LeaseBackend
from ..errors import LeaseConflict
from ..handle import LeaseHandle
from ..info import (
    HEADER_LEN,
    LeaseInfo,
    decode_frame,
    encode_frame,
    new_owner_token,
)

logger = logging.getLogger("resource_lease.win_mutex")

# Imported lazily so that "import resource_lease" works on platforms without
# pywin32 (Linux, CI). The autoselect module only constructs this class on
# sys.platform == 'win32'.
try:
    import pywintypes  # type: ignore
    import win32api  # type: ignore
    import win32con  # type: ignore
    import win32event  # type: ignore
    import win32security  # type: ignore
    import winerror  # type: ignore

    _HAS_PYWIN32 = True
except ImportError:  # pragma: no cover - exercised on non-Windows
    _HAS_PYWIN32 = False


# ── Win32 constants we use directly ──────────────────────────────────────

WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102

INFO_MAPPING_SIZE = 65536        # 64 KiB per resource
INDEX_MAPPING_SIZE = 1 << 20     # 1 MiB per namespace-index shard
CATALOG_MAPPING_SIZE = 1 << 18   # 256 KiB per catalog shard
NAMESPACE_INDEX_SHARDS = 256
CATALOG_SHARDS = 16

PAGE_READWRITE = 0x00000004
FILE_MAP_WRITE = 0x0002
FILE_MAP_READ = 0x0004
FILE_MAP_ALL_ACCESS = 0x001F
MUTEX_ALL_ACCESS = 0x001F0001

if _HAS_PYWIN32:  # pragma: no branch - platform gated at construction time
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _CreateFileMappingW = _kernel32.CreateFileMappingW
    _CreateFileMappingW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPCWSTR,
    ]
    _CreateFileMappingW.restype = wintypes.HANDLE

    _OpenFileMappingW = _kernel32.OpenFileMappingW
    _OpenFileMappingW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    _OpenFileMappingW.restype = wintypes.HANDLE

    _MapViewOfFile = _kernel32.MapViewOfFile
    _MapViewOfFile.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_size_t,
    ]
    _MapViewOfFile.restype = ctypes.c_void_p

    _UnmapViewOfFile = _kernel32.UnmapViewOfFile
    _UnmapViewOfFile.argtypes = [wintypes.LPCVOID]
    _UnmapViewOfFile.restype = wintypes.BOOL

    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL
else:  # pragma: no cover - only used for importability on non-Windows
    ctypes = None  # type: ignore
    wintypes = None  # type: ignore
    _CreateFileMappingW = None
    _OpenFileMappingW = None
    _MapViewOfFile = None
    _UnmapViewOfFile = None
    _CloseHandle = None


def _hash16(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def _user_sid_hash() -> str:
    """Hash of the current user's SID, so different users on the same machine
    can never collide on object names (and DACL-restricted creates wouldn't
    let them anyway)."""
    if not _HAS_PYWIN32:
        return _hash16(os.environ.get("USERNAME", "anon"))
    try:
        h_token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        sid, _attr = win32security.GetTokenInformation(
            h_token, win32security.TokenUser
        )
        sid_str = win32security.ConvertSidToStringSid(sid)
        return _hash16(sid_str)
    except Exception:
        return _hash16(os.environ.get("USERNAME", "anon"))


def _user_dacl_security_attrs():
    """Return a SECURITY_ATTRIBUTES granting access only to the current user.

    Prevents another user on the same machine from pre-creating a same-named
    mutex to block our acquire.
    """
    if not _HAS_PYWIN32:
        return None
    try:
        h_token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        sid, _ = win32security.GetTokenInformation(h_token, win32security.TokenUser)
        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            win32con.GENERIC_ALL,
            sid,
        )
        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(True, dacl, False)
        sa = pywintypes.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = sd
        sa.bInheritHandle = False
        return sa
    except Exception as e:
        logger.warning("could not build user-only SECURITY_ATTRIBUTES: %s", e)
        return None


def _scope_prefix(scope: str) -> str:
    if scope not in ("Local", "Global"):
        raise ValueError(f"scope must be 'Local' or 'Global', got {scope!r}")
    return f"{scope}\\"


def _resource_mutex_name(scope: str, sid_h: str, ns_h: str, rid_h: str) -> str:
    return f"{_scope_prefix(scope)}ResourceLease.Res.{sid_h}.{ns_h}.{rid_h}.Mutex"


def _resource_info_name(scope: str, sid_h: str, ns_h: str, rid_h: str) -> str:
    return f"{_scope_prefix(scope)}ResourceLease.Res.{sid_h}.{ns_h}.{rid_h}.Info"


def _index_shard_mutex_name(scope: str, sid_h: str, ns_h: str, shard: int) -> str:
    return f"{_scope_prefix(scope)}ResourceLease.Ns.{sid_h}.{ns_h}.{shard:03d}.IndexMutex"


def _index_shard_map_name(scope: str, sid_h: str, ns_h: str, shard: int) -> str:
    return f"{_scope_prefix(scope)}ResourceLease.Ns.{sid_h}.{ns_h}.{shard:03d}.IndexMap"


def _catalog_shard_mutex_name(scope: str, sid_h: str, shard: int) -> str:
    return f"{_scope_prefix(scope)}ResourceLease.Catalog.{sid_h}.{shard:02d}.Mutex"


def _catalog_shard_map_name(scope: str, sid_h: str, shard: int) -> str:
    return f"{_scope_prefix(scope)}ResourceLease.Catalog.{sid_h}.{shard:02d}.Map"


def _shard_for_rid(rid_hash16: str) -> int:
    return int(rid_hash16[:2], 16)


def _shard_for_ns(ns_hash16: str) -> int:
    return int(ns_hash16[:1], 16) % CATALOG_SHARDS


def _winerr(exc: BaseException) -> Optional[int]:
    return getattr(exc, "winerror", None) or getattr(exc, "errno", None)


def _raise_last_error(action: str) -> None:
    err = ctypes.get_last_error() if ctypes is not None else 0
    raise OSError(err, f"{action} failed with WinError {err}")


def _create_file_mapping(name: str, size: int) -> int:
    """Create or open a paging-file-backed named mapping."""
    handle = _CreateFileMappingW(
        -1,  # INVALID_HANDLE_VALUE: paging-file backed mapping
        None,
        PAGE_READWRITE,
        0,
        size,
        name,
    )
    if not handle:
        _raise_last_error(f"CreateFileMappingW({name})")
    return int(handle)


def _open_file_mapping(name: str, *, write: bool) -> int:
    access = FILE_MAP_ALL_ACCESS if write else FILE_MAP_READ
    handle = _OpenFileMappingW(access, False, name)
    if not handle:
        _raise_last_error(f"OpenFileMappingW({name})")
    return int(handle)


def _close_mapping_handle(handle: int) -> None:
    if not handle:
        return
    try:
        _CloseHandle(handle)
    except Exception:
        pass


# ── shard-level frame writer (RLIF + JSON dict) ──────────────────────────


def _write_shard_frame(view, body: dict, *, mapping_size: int) -> None:
    """Write a shard frame with seq=odd-during-write/even-when-stable.

    Caller must hold the shard's mutex. Caller is responsible for
    ``view.flush()``.
    """
    import json as _json

    payload = _json.dumps(body, separators=(",", ":")).encode("utf-8")
    if len(payload) + HEADER_LEN > mapping_size:
        raise RuntimeError(
            f"shard frame too large ({len(payload)} bytes payload, "
            f"limit {mapping_size - HEADER_LEN})"
        )

    # We synthesize an info-shaped frame just to reuse the codec — the JSON
    # body has its own 'kind'. To do that we hand-pack the header.
    import binascii
    import struct

    # Step 1: mark seq odd
    view.seek(0)
    header = view.read(HEADER_LEN) if view.size() >= HEADER_LEN else b""
    if len(header) >= HEADER_LEN:
        _, _, seq, _, _ = struct.unpack("<4sIQII", header)
    else:
        seq = 0

    if seq % 2 == 0:
        seq += 1
    crc = binascii.crc32(payload) & 0xFFFFFFFF
    odd_header = struct.pack("<4sIQII", b"RLIF", 1, seq, len(payload), crc)
    view.seek(0)
    view.write(odd_header)
    view.write(payload)
    # Step 2: bump to even (stable)
    seq += 1
    even_header = struct.pack("<4sIQII", b"RLIF", 1, seq, len(payload), crc)
    view.seek(0)
    view.write(even_header)


def _read_shard_frame(view) -> Optional[dict]:
    """Best-effort read of a shard frame; returns the JSON dict or None."""
    import json as _json
    import struct

    if view.size() < HEADER_LEN:
        return None
    view.seek(0)
    header = view.read(HEADER_LEN)
    try:
        magic, version, seq, json_len, crc = struct.unpack("<4sIQII", header)
    except struct.error:
        return None
    if magic != b"RLIF" or version != 1:
        return None
    if seq % 2 == 1:
        return None  # writer mid-update
    if json_len <= 0 or json_len + HEADER_LEN > view.size():
        return None
    payload = view.read(json_len)
    import binascii
    if (binascii.crc32(payload) & 0xFFFFFFFF) != crc:
        return None
    try:
        return _json.loads(payload.decode("utf-8"))
    except Exception:
        return None


# ── per-resource state ───────────────────────────────────────────────────


@dataclass
class _Held:
    keeper: threading.Thread
    release_event: threading.Event


# ── backend ──────────────────────────────────────────────────────────────


class WindowsMutexMappingLeaseBackend(LeaseBackend):
    """Windows backend; pywin32 required.

    Args:
        namespace: short string scoping all leases under this consumer.
        scope: ``"Local"`` (per-session, default) or ``"Global"`` (cross-
            session — needs SeCreateGlobalPrivilege in non-session-0).
    """

    def __init__(self, namespace: str, *, scope: str = "Local") -> None:
        if not _HAS_PYWIN32:
            raise RuntimeError(
                "pywin32 not installed — install resource-lease[win32] to "
                "use the Windows backend"
            )
        if not namespace:
            raise ValueError("namespace must be non-empty")
        if "\\" in namespace:
            raise ValueError("namespace must not contain backslashes")
        self.namespace = namespace
        self.scope = scope
        self._sid_hash = _user_sid_hash()
        self._ns_hash = _hash16(namespace)
        self._sa = _user_dacl_security_attrs()

        # Process-local source of truth — keeper threads + release events
        self._held: Dict[str, _Held] = {}
        self._held_lock = threading.Lock()

        # Keep open handles to index/catalog mappings as long as the backend
        # is alive, so the kernel doesn't free them between leases.
        self._open_index_maps: Dict[int, int] = {}
        self._open_catalog_maps: Dict[int, int] = {}
        self._maps_lock = threading.Lock()

    # ── public API ───────────────────────────────────────────────────────

    def acquire(self, resource_id: str, info: LeaseInfo) -> LeaseHandle:
        rid_hash = _hash16(resource_id)
        owner_token = new_owner_token(info.pid or os.getpid())

        from dataclasses import replace
        if info.pid == 0:
            info = replace(info, pid=os.getpid())
        stamped = info.with_backend_metadata(
            namespace=self.namespace,
            resource_hash=rid_hash,
            owner_token=owner_token,
        )

        with self._held_lock:
            if resource_id in self._held:
                # Same-process re-acquire → fail-fast like the cross-process case
                raise LeaseConflict(resource_id, self.query(resource_id))

        acquired_evt = threading.Event()
        failed_evt = threading.Event()
        release_evt = threading.Event()
        result: Dict[str, object] = {"owner": None}

        keeper = threading.Thread(
            target=self._keeper_main,
            name=f"resource_lease.win_keeper[{self.namespace}/{rid_hash}]",
            args=(resource_id, rid_hash, stamped,
                  acquired_evt, failed_evt, release_evt, result),
            daemon=True,
        )
        keeper.start()

        # Wait for keeper to either acquire or fail.
        while not acquired_evt.is_set() and not failed_evt.is_set():
            acquired_evt.wait(timeout=0.5)

        if failed_evt.is_set():
            raise LeaseConflict(resource_id, result.get("owner"))  # type: ignore[arg-type]

        with self._held_lock:
            self._held[resource_id] = _Held(keeper=keeper, release_event=release_evt)

        return LeaseHandle(
            resource_id, stamped, lambda rid=resource_id: self._release(rid)
        )

    def _release(self, resource_id: str) -> None:
        with self._held_lock:
            held = self._held.pop(resource_id, None)
        if held is None:
            return
        held.release_event.set()
        held.keeper.join(timeout=10)

    def close(self) -> None:
        with self._held_lock:
            ids = list(self._held.keys())
        for rid in ids:
            self._release(rid)
        with self._maps_lock:
            for h in list(self._open_index_maps.values()) + list(
                self._open_catalog_maps.values()
            ):
                _close_mapping_handle(h)
            self._open_index_maps.clear()
            self._open_catalog_maps.clear()

    # ── query ────────────────────────────────────────────────────────────

    def query(
        self, resource_id: str, *, timeout: float = 0.1
    ) -> Optional[LeaseInfo]:
        rid_hash = _hash16(resource_id)
        mutex_name = _resource_mutex_name(
            self.scope, self._sid_hash, self._ns_hash, rid_hash
        )

        # Step 1: open the mutex; absent → idle
        try:
            h_mutex = win32event.OpenMutex(
                win32con.SYNCHRONIZE, False, mutex_name
            )
        except pywintypes.error as e:
            if e.winerror in (winerror.ERROR_FILE_NOT_FOUND,
                              winerror.ERROR_PATH_NOT_FOUND):
                return None
            raise

        try:
            rc = win32event.WaitForSingleObject(h_mutex, 0)
            if rc in (WAIT_OBJECT_0, WAIT_ABANDONED):
                # No one held it; we did. Release immediately.
                try:
                    win32event.ReleaseMutex(h_mutex)
                except Exception:
                    pass
                return None
            if rc == WAIT_TIMEOUT:
                # Held by someone else: read info mapping
                return self._read_info_mapping(rid_hash) or self._busy_stub(
                    resource_id, rid_hash
                )
        finally:
            win32api.CloseHandle(h_mutex)

        return None

    # ── list / list_namespaces ───────────────────────────────────────────

    def list(self) -> List[LeaseInfo]:
        out: List[LeaseInfo] = []
        for shard in range(NAMESPACE_INDEX_SHARDS):
            entries = self._read_index_shard(shard, prune_stale=True)
            if not entries:
                continue
            for entry in entries:
                rid = entry.get("resource_id")
                if not rid:
                    continue
                # Re-query authoritative info from the per-resource mapping.
                live = self.query(rid)
                if live is not None:
                    out.append(live)
        return out

    def list_namespaces(self) -> List[str]:
        seen: Dict[str, bool] = {}
        # Snapshot all catalog shards first.
        snapshots: List[List[dict]] = []
        for shard in range(CATALOG_SHARDS):
            entries = self._read_catalog_shard(shard, prune_stale=False)
            snapshots.append(entries)

        for entries in snapshots:
            for entry in entries:
                ns = entry.get("namespace")
                if not ns:
                    continue
                # A namespace counts as "active" iff at least one of its
                # resources is still busy. Use a quick scan via list().
                back = WindowsMutexMappingLeaseBackend(ns, scope=self.scope)
                try:
                    if back.list():
                        seen[ns] = True
                finally:
                    back.close()

        # Prune catalog entries that have no active leases anymore.
        for shard in range(CATALOG_SHARDS):
            self._prune_catalog_shard(shard, alive=set(seen.keys()))

        return sorted(seen.keys())

    # ── keeper thread ────────────────────────────────────────────────────

    def _keeper_main(
        self,
        resource_id: str,
        rid_hash: str,
        info: LeaseInfo,
        acquired_evt: threading.Event,
        failed_evt: threading.Event,
        release_evt: threading.Event,
        result: dict,
    ) -> None:
        mutex_name = _resource_mutex_name(
            self.scope, self._sid_hash, self._ns_hash, rid_hash
        )
        info_name = _resource_info_name(
            self.scope, self._sid_hash, self._ns_hash, rid_hash
        )

        h_mutex = None
        h_info_map = None
        info_view = None
        owns_mutex = False
        try:
            h_mutex = win32event.CreateMutex(self._sa, False, mutex_name)
            rc = win32event.WaitForSingleObject(h_mutex, 0)
            if rc == WAIT_TIMEOUT:
                result["owner"] = self._read_info_mapping(
                    rid_hash
                ) or self._busy_stub(resource_id, rid_hash)
                failed_evt.set()
                return
            if rc not in (WAIT_OBJECT_0, WAIT_ABANDONED):
                logger.error("unexpected wait rc=%#x for %s", rc, mutex_name)
                failed_evt.set()
                return
            if rc == WAIT_ABANDONED:
                logger.info(
                    "[lease] inherited abandoned mutex for %s "
                    "(previous owner crashed without release)", resource_id,
                )
            owns_mutex = True

            # Create info mapping + write frame
            h_info_map = _create_file_mapping(info_name, INFO_MAPPING_SIZE)
            info_view = _MapView(h_info_map, INFO_MAPPING_SIZE, write=True)
            self._write_info_frame(info_view, info)
            info_view.flush()

            self._register_index_entry(rid_hash, info)
            self._register_catalog_entry()

            acquired_evt.set()
            release_evt.wait()  # held until consumer .release()

            self._unregister_index_entry(rid_hash)
            self._maybe_unregister_catalog_entry()

        except Exception as e:
            logger.exception("keeper thread for %s failed: %s", resource_id, e)
            if not acquired_evt.is_set():
                failed_evt.set()
        finally:
            try:
                if info_view is not None:
                    info_view.close()
                if h_info_map is not None:
                    _close_mapping_handle(h_info_map)
            except Exception:
                pass
            try:
                if h_mutex is not None:
                    if owns_mutex:
                        try:
                            win32event.ReleaseMutex(h_mutex)
                        except Exception:
                            pass
                    win32api.CloseHandle(h_mutex)
            except Exception:
                pass

    # ── info mapping I/O ─────────────────────────────────────────────────

    def _write_info_frame(self, view, info: LeaseInfo) -> None:
        """Write the per-resource info mapping with seq parity."""
        import struct

        frame = encode_frame(info)  # seq=0 by default
        # Re-seq with even after a brief odd state for cross-process readers.
        magic = b"RLIF"
        version = 1
        json_len_bytes = frame[HEADER_LEN - 8 : HEADER_LEN - 4]
        crc_bytes = frame[HEADER_LEN - 4 : HEADER_LEN]
        json_len = int.from_bytes(json_len_bytes, "little")
        payload = frame[HEADER_LEN : HEADER_LEN + json_len]
        # Step 1: seq=1 (odd, writer in progress)
        view.seek(0)
        view.write(struct.pack("<4sIQII", magic, version, 1, json_len,
                               int.from_bytes(crc_bytes, "little")))
        view.write(payload)
        # Step 2: seq=2 (even, stable)
        view.seek(0)
        view.write(struct.pack("<4sIQII", magic, version, 2, json_len,
                               int.from_bytes(crc_bytes, "little")))

    def _read_info_mapping(self, rid_hash: str) -> Optional[LeaseInfo]:
        info_name = _resource_info_name(
            self.scope, self._sid_hash, self._ns_hash, rid_hash
        )
        try:
            h_map = _open_file_mapping(info_name, write=False)
        except (pywintypes.error, OSError) as e:
            if _winerr(e) in (winerror.ERROR_FILE_NOT_FOUND,
                              winerror.ERROR_PATH_NOT_FOUND):
                return None
            return None

        view = None
        try:
            view = _MapView(h_map, INFO_MAPPING_SIZE, write=False)
            view.seek(0)
            buf = view.read(INFO_MAPPING_SIZE)
            return decode_frame(buf)
        finally:
            if view is not None:
                view.close()
            try:
                _close_mapping_handle(h_map)
            except Exception:
                pass

    def _busy_stub(self, resource_id: str, rid_hash: str) -> LeaseInfo:
        """Return a busy marker when the mutex is held but metadata is absent.

        This preserves the source-of-truth semantics: a busy mutex means the
        resource is occupied even if the owner died mid-publish or a reader
        observed a torn mapping frame.
        """
        return LeaseInfo(
            resource_id=resource_id,
            namespace=self.namespace,
            resource_hash=rid_hash,
            metadata_available=False,
        )

    # ── namespace index (per-resource → shard) ───────────────────────────

    def _index_shard_handles(self, shard: int):
        mutex_name = _index_shard_mutex_name(
            self.scope, self._sid_hash, self._ns_hash, shard
        )
        map_name = _index_shard_map_name(
            self.scope, self._sid_hash, self._ns_hash, shard
        )
        return mutex_name, map_name

    def _open_or_create_index_map(self, shard: int):
        with self._maps_lock:
            if shard in self._open_index_maps:
                return self._open_index_maps[shard]
        _, map_name = self._index_shard_handles(shard)
        h = _create_file_mapping(map_name, INDEX_MAPPING_SIZE)
        with self._maps_lock:
            existing = self._open_index_maps.setdefault(shard, h)
        if existing is not h:
            _close_mapping_handle(h)
        return existing

    def _register_index_entry(self, rid_hash: str, info: LeaseInfo) -> None:
        shard = _shard_for_rid(rid_hash)
        mutex_name, _ = self._index_shard_handles(shard)
        h_mutex = win32event.CreateMutex(self._sa, False, mutex_name)
        try:
            rc = win32event.WaitForSingleObject(h_mutex, 5000)
            if rc not in (WAIT_OBJECT_0, WAIT_ABANDONED):
                raise TimeoutError(f"timeout waiting for index shard mutex {mutex_name}")
            try:
                h_map = self._open_or_create_index_map(shard)
                view = _MapView(h_map, INDEX_MAPPING_SIZE, write=True)
                try:
                    body = _read_shard_frame(view) or {
                        "kind": "resource_lease.index",
                        "version": 1,
                        "namespace": self.namespace,
                        "namespace_hash": self._ns_hash,
                        "shard": shard,
                        "entries": [],
                    }
                    entries = [
                        e for e in body.get("entries", [])
                        if e.get("resource_hash") != rid_hash
                    ]
                    entries.append({
                        "resource_id": info.resource_id,
                        "resource_hash": rid_hash,
                        "owner_token": info.owner_token,
                        "pid": info.pid,
                        "agent_name": info.agent_name,
                        "purpose": info.purpose,
                        "run_id": info.run_id,
                        "started_at": info.started_at,
                    })
                    body["entries"] = entries
                    body["updated_at"] = time.time()
                    _write_shard_frame(view, body, mapping_size=INDEX_MAPPING_SIZE)
                finally:
                    view.close()
            finally:
                try:
                    win32event.ReleaseMutex(h_mutex)
                except Exception:
                    pass
        finally:
            win32api.CloseHandle(h_mutex)

    def _unregister_index_entry(self, rid_hash: str) -> None:
        shard = _shard_for_rid(rid_hash)
        mutex_name, _ = self._index_shard_handles(shard)
        try:
            h_mutex = win32event.OpenMutex(
                MUTEX_ALL_ACCESS, False, mutex_name
            )
        except pywintypes.error:
            return
        try:
            if win32event.WaitForSingleObject(h_mutex, 5000) not in (
                WAIT_OBJECT_0, WAIT_ABANDONED
            ):
                return
            try:
                with self._maps_lock:
                    h_map = self._open_index_maps.get(shard)
                if h_map is None:
                    return
                view = _MapView(h_map, INDEX_MAPPING_SIZE, write=True)
                try:
                    body = _read_shard_frame(view) or {}
                    entries = [
                        e for e in body.get("entries", [])
                        if e.get("resource_hash") != rid_hash
                    ]
                    body["entries"] = entries
                    body["updated_at"] = time.time()
                    _write_shard_frame(view, body, mapping_size=INDEX_MAPPING_SIZE)
                finally:
                    view.close()
            finally:
                try:
                    win32event.ReleaseMutex(h_mutex)
                except Exception:
                    pass
        finally:
            win32api.CloseHandle(h_mutex)

    def _read_index_shard(self, shard: int, *, prune_stale: bool) -> List[dict]:
        mutex_name, map_name = self._index_shard_handles(shard)
        try:
            h_map = _open_file_mapping(map_name, write=prune_stale)
        except (pywintypes.error, OSError):
            return []
        try:
            try:
                h_mutex = win32event.OpenMutex(
                    MUTEX_ALL_ACCESS, False, mutex_name
                )
            except pywintypes.error:
                h_mutex = None
            try:
                if h_mutex is not None:
                    rc = win32event.WaitForSingleObject(h_mutex, 1000)
                    if rc not in (WAIT_OBJECT_0, WAIT_ABANDONED):
                        return []
                view = _MapView(
                    h_map, INDEX_MAPPING_SIZE,
                    write=prune_stale,
                )
                try:
                    body = _read_shard_frame(view) or {}
                    entries = body.get("entries", []) or []
                    if prune_stale and h_mutex is not None:
                        kept = [
                            e for e in entries
                            if self._validate_entry(e) == "active"
                        ]
                        if kept != entries:
                            body["entries"] = kept
                            body["updated_at"] = time.time()
                            _write_shard_frame(
                                view, body, mapping_size=INDEX_MAPPING_SIZE
                            )
                        return kept
                    return entries
                finally:
                    view.close()
            finally:
                if h_mutex is not None:
                    try:
                        win32event.ReleaseMutex(h_mutex)
                    except Exception:
                        pass
                    win32api.CloseHandle(h_mutex)
        finally:
            _close_mapping_handle(h_map)

    def _validate_entry(self, entry: dict) -> str:
        rid = entry.get("resource_id")
        if not rid:
            return "stale"
        rid_hash = _hash16(rid)
        mutex_name = _resource_mutex_name(
            self.scope, self._sid_hash, self._ns_hash, rid_hash
        )
        try:
            h_mutex = win32event.OpenMutex(
                win32con.SYNCHRONIZE, False, mutex_name
            )
        except pywintypes.error:
            return "stale"
        try:
            rc = win32event.WaitForSingleObject(h_mutex, 0)
            if rc == WAIT_TIMEOUT:
                return "active"
            # We grabbed it → no one holds → stale
            try:
                win32event.ReleaseMutex(h_mutex)
            except Exception:
                pass
            return "stale"
        finally:
            win32api.CloseHandle(h_mutex)

    # ── catalog (namespace-level) ────────────────────────────────────────

    def _catalog_shard_handles(self, shard: int):
        mutex_name = _catalog_shard_mutex_name(self.scope, self._sid_hash, shard)
        map_name = _catalog_shard_map_name(self.scope, self._sid_hash, shard)
        return mutex_name, map_name

    def _open_or_create_catalog_map(self, shard: int):
        with self._maps_lock:
            if shard in self._open_catalog_maps:
                return self._open_catalog_maps[shard]
        _, map_name = self._catalog_shard_handles(shard)
        h = _create_file_mapping(map_name, CATALOG_MAPPING_SIZE)
        with self._maps_lock:
            existing = self._open_catalog_maps.setdefault(shard, h)
        if existing is not h:
            _close_mapping_handle(h)
        return existing

    def _register_catalog_entry(self) -> None:
        shard = _shard_for_ns(self._ns_hash)
        mutex_name, _ = self._catalog_shard_handles(shard)
        h_mutex = win32event.CreateMutex(self._sa, False, mutex_name)
        try:
            rc = win32event.WaitForSingleObject(h_mutex, 5000)
            if rc not in (WAIT_OBJECT_0, WAIT_ABANDONED):
                raise TimeoutError(f"timeout waiting for catalog shard mutex {mutex_name}")
            try:
                h_map = self._open_or_create_catalog_map(shard)
                view = _MapView(h_map, CATALOG_MAPPING_SIZE, write=True)
                try:
                    body = _read_shard_frame(view) or {
                        "kind": "resource_lease.catalog",
                        "version": 1,
                        "shard": shard,
                        "entries": [],
                    }
                    entries = [
                        e for e in body.get("entries", [])
                        if e.get("namespace_hash") != self._ns_hash
                    ]
                    entries.append({
                        "namespace": self.namespace,
                        "namespace_hash": self._ns_hash,
                        "last_seen": time.time(),
                    })
                    body["entries"] = entries
                    body["updated_at"] = time.time()
                    _write_shard_frame(view, body, mapping_size=CATALOG_MAPPING_SIZE)
                finally:
                    view.close()
            finally:
                try:
                    win32event.ReleaseMutex(h_mutex)
                except Exception:
                    pass
        finally:
            win32api.CloseHandle(h_mutex)

    def _maybe_unregister_catalog_entry(self) -> None:
        # Catalog entries are sticky: they record "namespace seen recently".
        # list_namespaces() prunes them. So nothing to do on per-lease release.
        pass

    def _read_catalog_shard(self, shard: int, *, prune_stale: bool) -> List[dict]:
        mutex_name, map_name = self._catalog_shard_handles(shard)
        try:
            h_map = _open_file_mapping(map_name, write=False)
        except (pywintypes.error, OSError):
            return []
        h_mutex = None
        try:
            try:
                h_mutex = win32event.OpenMutex(
                    MUTEX_ALL_ACCESS, False, mutex_name
                )
            except pywintypes.error:
                h_mutex = None
            if h_mutex is not None:
                rc = win32event.WaitForSingleObject(h_mutex, 1000)
                if rc not in (WAIT_OBJECT_0, WAIT_ABANDONED):
                    return []
            view = _MapView(h_map, CATALOG_MAPPING_SIZE, write=False)
            try:
                body = _read_shard_frame(view) or {}
                return body.get("entries", []) or []
            finally:
                view.close()
        finally:
            if h_mutex is not None:
                try:
                    win32event.ReleaseMutex(h_mutex)
                except Exception:
                    pass
                try:
                    win32api.CloseHandle(h_mutex)
                except Exception:
                    pass
            _close_mapping_handle(h_map)

    def _prune_catalog_shard(self, shard: int, *, alive: set) -> None:
        mutex_name, map_name = self._catalog_shard_handles(shard)
        local_h_map = None
        try:
            h_mutex = win32event.OpenMutex(
                MUTEX_ALL_ACCESS, False, mutex_name
            )
        except pywintypes.error:
            return
        try:
            if win32event.WaitForSingleObject(h_mutex, 1000) not in (
                WAIT_OBJECT_0, WAIT_ABANDONED
            ):
                return
            try:
                with self._maps_lock:
                    h_map = self._open_catalog_maps.get(shard)
                if h_map is None:
                    try:
                        h_map = _open_file_mapping(map_name, write=True)
                        local_h_map = h_map
                    except (pywintypes.error, OSError):
                        return
                view = _MapView(h_map, CATALOG_MAPPING_SIZE, write=True)
                try:
                    body = _read_shard_frame(view) or {}
                    entries = [
                        e for e in body.get("entries", []) or []
                        if e.get("namespace") in alive
                    ]
                    body["entries"] = entries
                    body["updated_at"] = time.time()
                    _write_shard_frame(view, body, mapping_size=CATALOG_MAPPING_SIZE)
                finally:
                    view.close()
            finally:
                try:
                    win32event.ReleaseMutex(h_mutex)
                except Exception:
                    pass
        finally:
            if local_h_map is not None:
                _close_mapping_handle(local_h_map)
            win32api.CloseHandle(h_mutex)


# ── thin wrapper around ctypes MapViewOfFile ────────────────────────────


class _MapView:
    """Minimal file-like wrapper over a Win32 mapping view."""

    def __init__(self, handle, size: int, *, write: bool) -> None:
        access = FILE_MAP_ALL_ACCESS if write else FILE_MAP_READ
        ptr = _MapViewOfFile(handle, access, 0, 0, size)
        if not ptr:
            _raise_last_error("MapViewOfFile")
        self._ptr = int(ptr)
        self._size = size
        self._pos = 0
        self._write = write

    def size(self) -> int:
        return self._size

    def seek(self, pos: int) -> None:
        if pos < 0 or pos > self._size:
            raise ValueError(f"seek out of range: {pos}")
        self._pos = pos

    def read(self, n: int) -> bytes:
        end = min(self._pos + n, self._size)
        chunk = ctypes.string_at(self._ptr + self._pos, end - self._pos)
        self._pos = end
        return chunk

    def write(self, data: bytes) -> None:
        if not self._write:
            raise OSError("read-only view")
        end = self._pos + len(data)
        if end > self._size:
            raise ValueError("write past end of mapping view")
        ctypes.memmove(self._ptr + self._pos, data, len(data))
        self._pos = end

    def flush(self) -> None:
        # Paging-file backed mappings are visible to peer views without
        # FlushViewOfFile; this method exists for interface symmetry.
        pass

    def close(self) -> None:
        ptr = getattr(self, "_ptr", 0)
        if ptr:
            try:
                _UnmapViewOfFile(ptr)
            except Exception:
                pass
        self._ptr = 0
