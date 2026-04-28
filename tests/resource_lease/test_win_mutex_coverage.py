"""Coverage-focused Windows unit tests for win_mutex internals.

The public behavior is covered in test_win_mutex.py. These tests exercise
failure and cleanup paths by mocking Win32 calls so coverage can stay at 100%
without relying on rare OS failures.
"""

from __future__ import annotations

import binascii
import errno
import os
import struct
import sys
import threading

import pytest

if sys.platform != "win32":
    pytest.skip("Windows-only backend", allow_module_level=True)

from resource_lease import LeaseConflict, LeaseInfo
from resource_lease.backends import win_mutex as mod
from resource_lease.backends.win_mutex import WindowsMutexMappingLeaseBackend


def _ns() -> str:
    import uuid

    return f"rl.win.cov.{uuid.uuid4().hex[:10]}"


def _info(rid: str = "r0", **kw) -> LeaseInfo:
    base = dict(resource_id=rid, agent_name="cov", pid=os.getpid())
    base.update(kw)
    return LeaseInfo(**base)


class MemView:
    def __init__(self, size=4096, initial=b""):
        self.buf = bytearray(size)
        self.buf[: len(initial)] = initial
        self.pos = 0
        self.closed = False

    def size(self):
        return len(self.buf)

    def seek(self, pos):
        self.pos = pos

    def read(self, n):
        end = min(self.pos + n, len(self.buf))
        out = bytes(self.buf[self.pos:end])
        self.pos = end
        return out

    def write(self, data):
        end = self.pos + len(data)
        self.buf[self.pos:end] = data
        self.pos = end

    def close(self):
        self.closed = True

    def flush(self):
        pass


class ShortHeaderView(MemView):
    def size(self):
        return mod.HEADER_LEN

    def read(self, n):
        return b"short"


class ShortReadMemView(MemView):
    def read(self, n):
        return b"short"


def _pywin_error(code=2):
    return mod.pywintypes.error(code, "api", "message")


def test_helper_fallbacks_and_win32_wrapper_errors(monkeypatch):
    old_has = mod._HAS_PYWIN32
    monkeypatch.setattr(mod, "_HAS_PYWIN32", False)
    assert mod._user_sid_hash()
    assert mod._user_dacl_security_attrs() is None
    monkeypatch.setattr(mod, "_HAS_PYWIN32", old_has)

    monkeypatch.setattr(mod.win32security, "OpenProcessToken", lambda *a: (_ for _ in ()).throw(RuntimeError("sid")))
    assert mod._user_sid_hash()
    assert mod._user_dacl_security_attrs() is None

    with pytest.raises(ValueError):
        mod._scope_prefix("Session")

    class WithWinerror:
        winerror = 123

    class WithErrno:
        errno = 456

    assert mod._winerr(WithWinerror()) == 123
    assert mod._winerr(WithErrno()) == 456

    monkeypatch.setattr(mod.ctypes, "get_last_error", lambda: 5)
    with pytest.raises(OSError):
        mod._raise_last_error("thing")

    monkeypatch.setattr(mod, "_CreateFileMappingW", lambda *a: 0)
    with pytest.raises(OSError):
        mod._create_file_mapping("x", 128)

    monkeypatch.setattr(mod, "_OpenFileMappingW", lambda *a: 0)
    with pytest.raises(OSError):
        mod._open_file_mapping("x", write=False)

    mod._close_mapping_handle(0)
    monkeypatch.setattr(mod, "_CloseHandle", lambda h: (_ for _ in ()).throw(RuntimeError("close")))
    mod._close_mapping_handle(1)


def test_shard_frame_codec_edges():
    with pytest.raises(RuntimeError):
        mod._write_shard_frame(MemView(64), {"blob": "x" * 200}, mapping_size=64)

    small = MemView(512)
    mod._write_shard_frame(small, {"kind": "k"}, mapping_size=512)
    assert mod._read_shard_frame(small) == {"kind": "k"}

    short_existing = ShortReadMemView(512)
    mod._write_shard_frame(short_existing, {"short": True}, mapping_size=512)

    existing = MemView(512)
    mod._write_shard_frame(existing, {"n": 1}, mapping_size=512)
    mod._write_shard_frame(existing, {"n": 2}, mapping_size=512)
    assert mod._read_shard_frame(existing) == {"n": 2}

    assert mod._read_shard_frame(MemView(mod.HEADER_LEN - 1)) is None
    assert mod._read_shard_frame(ShortHeaderView()) is None

    def frame(magic=b"RLIF", version=1, seq=0, body=b"{}",
              crc=None, json_len=None):
        crc = binascii.crc32(body) & 0xFFFFFFFF if crc is None else crc
        json_len = len(body) if json_len is None else json_len
        return struct.pack("<4sIQII", magic, version, seq, json_len, crc) + body

    for data in (
        frame(magic=b"BAD!"),
        frame(version=99),
        frame(seq=1),
        frame(json_len=0),
        frame(json_len=9999),
        frame(body=b"{}", crc=123),
        frame(body=b"{not-json"),
    ):
        assert mod._read_shard_frame(MemView(512, data)) is None


def test_backend_init_acquire_release_close_edges(monkeypatch):
    old_has = mod._HAS_PYWIN32
    monkeypatch.setattr(mod, "_HAS_PYWIN32", False)
    with pytest.raises(RuntimeError):
        WindowsMutexMappingLeaseBackend("x")
    monkeypatch.setattr(mod, "_HAS_PYWIN32", old_has)

    with pytest.raises(ValueError):
        WindowsMutexMappingLeaseBackend("")
    with pytest.raises(ValueError):
        WindowsMutexMappingLeaseBackend("bad\\ns")

    b = WindowsMutexMappingLeaseBackend(_ns())
    h = b.acquire("r0", LeaseInfo(resource_id="r0", pid=0))
    try:
        assert h.info.pid == os.getpid()
        with pytest.raises(LeaseConflict):
            b.acquire("r0", _info("r0"))
    finally:
        h.release()
        b.close()

    b._release("missing")

    b = WindowsMutexMappingLeaseBackend(_ns())
    b.acquire("a", _info("a"))
    b.acquire("b", _info("b"))
    b.close()
    assert b.query("a") is None


def test_update_missing_resource_and_zero_pid_branch():
    b = WindowsMutexMappingLeaseBackend(_ns())
    with pytest.raises(RuntimeError):
        b.update("missing", _info("missing"))

    h = b.acquire("r0", _info("r0", pid=os.getpid()))
    try:
        updated = b.update(
            "r0",
            LeaseInfo(resource_id="r0", agent_name="zero-pid", pid=0),
        )
        assert updated.pid == os.getpid()
        assert b.query("r0").agent_name == "zero-pid"
    finally:
        h.release()
        b.close()


def test_query_error_and_busy_stub_branches(monkeypatch):
    b = WindowsMutexMappingLeaseBackend(_ns())

    monkeypatch.setattr(mod.win32event, "OpenMutex", lambda *a: (_ for _ in ()).throw(_pywin_error(5)))
    with pytest.raises(mod.pywintypes.error):
        b.query("r0")

    monkeypatch.setattr(mod.win32event, "OpenMutex", lambda *a: "mutex")
    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: mod.WAIT_OBJECT_0)
    monkeypatch.setattr(mod.win32event, "ReleaseMutex", lambda h: (_ for _ in ()).throw(RuntimeError("release")))
    monkeypatch.setattr(mod.win32api, "CloseHandle", lambda h: None)
    assert b.query("r0") is None

    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: 999)
    assert b.query("r0") is None

    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: mod.WAIT_TIMEOUT)
    monkeypatch.setattr(b, "_read_info_mapping", lambda rid_hash: None)
    q = b.query("r0")
    assert q is not None
    assert q.metadata_available is False


def test_list_skips_empty_resource_and_namespace_entries(monkeypatch):
    b = WindowsMutexMappingLeaseBackend(_ns())
    monkeypatch.setattr(b, "_read_index_shard", lambda shard, prune_stale: (
        [{"resource_id": ""}] if shard == 0 else []
    ))
    assert b.list() == []

    monkeypatch.setattr(b, "_read_catalog_shard", lambda shard, prune_stale: (
        [{"namespace": ""}] if shard == 0 else []
    ))
    pruned = []
    monkeypatch.setattr(b, "_prune_catalog_shard", lambda shard, alive: pruned.append((shard, alive)))
    assert b.list_namespaces() == []
    assert pruned


def test_keeper_wait_timeout_unexpected_abandoned_and_cleanup_errors(monkeypatch):
    b = WindowsMutexMappingLeaseBackend(_ns())

    def run_keeper(wait_rc, *, map_error=False):
        acquired = threading.Event()
        failed = threading.Event()
        release = threading.Event()
        result = {}
        monkeypatch.setattr(mod.win32event, "CreateMutex", lambda *a: "mutex")
        monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: wait_rc)
        monkeypatch.setattr(mod.win32api, "CloseHandle", lambda h: None)
        if map_error:
            monkeypatch.setattr(mod, "_create_file_mapping", lambda *a: (_ for _ in ()).throw(RuntimeError("map")))
        b._keeper_main("r0", mod._hash16("r0"), _info("r0"), acquired, failed, release, result)
        return acquired, failed, result

    acquired, failed, result = run_keeper(mod.WAIT_TIMEOUT)
    assert not acquired.is_set()
    assert failed.is_set()
    assert result["owner"].metadata_available is False

    acquired, failed, _ = run_keeper(999)
    assert not acquired.is_set()
    assert failed.is_set()

    acquired, failed, _ = run_keeper(mod.WAIT_ABANDONED, map_error=True)
    assert not acquired.is_set()
    assert failed.is_set()

    class BadView:
        def close(self):
            raise RuntimeError("view close")

    acquired = threading.Event()
    failed = threading.Event()
    release = threading.Event()
    monkeypatch.setattr(mod.win32event, "CreateMutex", lambda *a: "mutex")
    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: mod.WAIT_OBJECT_0)
    monkeypatch.setattr(mod, "_create_file_mapping", lambda *a: 42)
    monkeypatch.setattr(mod, "_MapView", lambda *a, **k: BadView())
    monkeypatch.setattr(b, "_write_info_frame", lambda *a: (_ for _ in ()).throw(RuntimeError("write")))
    monkeypatch.setattr(mod, "_close_mapping_handle", lambda h: (_ for _ in ()).throw(RuntimeError("close map")))
    monkeypatch.setattr(mod.win32event, "ReleaseMutex", lambda h: (_ for _ in ()).throw(RuntimeError("release")))
    monkeypatch.setattr(mod.win32api, "CloseHandle", lambda h: (_ for _ in ()).throw(RuntimeError("close mutex")))
    b._keeper_main("r0", mod._hash16("r0"), _info("r0"), acquired, failed, release, {})
    assert failed.is_set()


def test_info_mapping_errors_and_busy_stub(monkeypatch):
    b = WindowsMutexMappingLeaseBackend(_ns())
    monkeypatch.setattr(mod, "_open_file_mapping", lambda *a, **k: (_ for _ in ()).throw(OSError(mod.winerror.ERROR_FILE_NOT_FOUND, "missing")))
    assert b._read_info_mapping("abc") is None
    monkeypatch.setattr(mod, "_open_file_mapping", lambda *a, **k: (_ for _ in ()).throw(OSError(errno.EACCES, "denied")))
    assert b._read_info_mapping("abc") is None

    monkeypatch.setattr(mod, "_open_file_mapping", lambda *a, **k: 42)
    monkeypatch.setattr(mod, "_MapView", lambda *a, **k: MemView(mod.INFO_MAPPING_SIZE, b"bad"))
    monkeypatch.setattr(mod, "_close_mapping_handle", lambda h: (_ for _ in ()).throw(RuntimeError("close")))
    assert b._read_info_mapping("abc") is None

    stub = b._busy_stub("rid", "hash")
    assert stub.resource_id == "rid"
    assert stub.resource_hash == "hash"
    assert stub.metadata_available is False


def test_index_helpers_error_and_cleanup_paths(monkeypatch):
    b = WindowsMutexMappingLeaseBackend(_ns())
    rid_hash = mod._hash16("r0")
    shard = mod._shard_for_rid(rid_hash)

    b._open_index_maps[shard] = 123
    assert b._open_or_create_index_map(shard) == 123

    class OddDict(dict):
        def __contains__(self, key):
            return False

        def setdefault(self, key, value):
            return 999

    b._open_index_maps = OddDict()
    monkeypatch.setattr(mod, "_create_file_mapping", lambda *a: 555)
    closed = []
    monkeypatch.setattr(mod, "_close_mapping_handle", lambda h: closed.append(h))
    assert b._open_or_create_index_map(shard) == 999
    assert closed == [555]

    monkeypatch.setattr(mod.win32event, "CreateMutex", lambda *a: "mutex")
    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: 999)
    monkeypatch.setattr(mod.win32api, "CloseHandle", lambda h: None)
    with pytest.raises(TimeoutError):
        b._register_index_entry(rid_hash, _info("r0"))

    view = MemView(mod.INDEX_MAPPING_SIZE)
    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: mod.WAIT_OBJECT_0)
    monkeypatch.setattr(b, "_open_or_create_index_map", lambda shard: 1)
    monkeypatch.setattr(mod, "_MapView", lambda *a, **k: view)
    monkeypatch.setattr(mod.win32event, "ReleaseMutex", lambda h: (_ for _ in ()).throw(RuntimeError("release")))
    b._register_index_entry(rid_hash, _info("r0"))

    monkeypatch.setattr(mod.win32event, "OpenMutex", lambda *a: (_ for _ in ()).throw(_pywin_error()))
    b._unregister_index_entry(rid_hash)

    monkeypatch.setattr(mod.win32event, "OpenMutex", lambda *a: "mutex")
    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: 999)
    b._unregister_index_entry(rid_hash)

    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: mod.WAIT_OBJECT_0)
    b._open_index_maps = {}
    b._unregister_index_entry(rid_hash)

    b._open_index_maps = {shard: 1}
    view = MemView(mod.INDEX_MAPPING_SIZE)
    mod._write_shard_frame(view, {"entries": [{"resource_hash": "other"}]}, mapping_size=mod.INDEX_MAPPING_SIZE)
    monkeypatch.setattr(mod, "_MapView", lambda *a, **k: view)
    b._unregister_index_entry(rid_hash)


def test_read_index_and_validate_paths(monkeypatch):
    b = WindowsMutexMappingLeaseBackend(_ns())
    monkeypatch.setattr(mod, "_open_file_mapping", lambda *a, **k: (_ for _ in ()).throw(OSError("missing")))
    assert b._read_index_shard(1, prune_stale=False) == []

    body = {"entries": [{"resource_id": "active"}, {"resource_id": "stale"}]}
    view = MemView(mod.INDEX_MAPPING_SIZE)
    mod._write_shard_frame(view, body, mapping_size=mod.INDEX_MAPPING_SIZE)
    monkeypatch.setattr(mod, "_open_file_mapping", lambda *a, **k: 1)
    monkeypatch.setattr(mod.win32event, "OpenMutex", lambda *a: (_ for _ in ()).throw(_pywin_error()))
    monkeypatch.setattr(mod, "_MapView", lambda *a, **k: view)
    assert b._read_index_shard(1, prune_stale=False) == body["entries"]

    monkeypatch.setattr(mod.win32event, "OpenMutex", lambda *a: "mutex")
    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: 999)
    monkeypatch.setattr(mod.win32api, "CloseHandle", lambda h: None)
    assert b._read_index_shard(1, prune_stale=True) == []

    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: mod.WAIT_OBJECT_0)
    monkeypatch.setattr(b, "_validate_entry", lambda e: "active" if e["resource_id"] == "active" else "stale")
    monkeypatch.setattr(mod.win32event, "ReleaseMutex", lambda h: (_ for _ in ()).throw(RuntimeError("release")))
    kept = b._read_index_shard(1, prune_stale=True)
    assert kept == [{"resource_id": "active"}]

    b = WindowsMutexMappingLeaseBackend(_ns())
    assert b._validate_entry({}) == "stale"
    monkeypatch.setattr(mod.win32event, "OpenMutex", lambda *a: (_ for _ in ()).throw(_pywin_error()))
    assert b._validate_entry({"resource_id": "r0"}) == "stale"
    monkeypatch.setattr(mod.win32event, "OpenMutex", lambda *a: "mutex")
    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: mod.WAIT_TIMEOUT)
    assert b._validate_entry({"resource_id": "r0"}) == "active"
    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: mod.WAIT_OBJECT_0)
    monkeypatch.setattr(mod.win32event, "ReleaseMutex", lambda h: (_ for _ in ()).throw(RuntimeError("release")))
    assert b._validate_entry({"resource_id": "r0"}) == "stale"


def test_catalog_helpers_error_and_cleanup_paths(monkeypatch):
    b = WindowsMutexMappingLeaseBackend(_ns())
    shard = mod._shard_for_ns(b._ns_hash)

    b._open_catalog_maps[shard] = 123
    assert b._open_or_create_catalog_map(shard) == 123

    class OddDict(dict):
        def __contains__(self, key):
            return False

        def setdefault(self, key, value):
            return 999

    b._open_catalog_maps = OddDict()
    monkeypatch.setattr(mod, "_create_file_mapping", lambda *a: 555)
    closed = []
    monkeypatch.setattr(mod, "_close_mapping_handle", lambda h: closed.append(h))
    assert b._open_or_create_catalog_map(shard) == 999
    assert closed == [555]

    monkeypatch.setattr(mod.win32event, "CreateMutex", lambda *a: "mutex")
    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: 999)
    monkeypatch.setattr(mod.win32api, "CloseHandle", lambda h: None)
    with pytest.raises(TimeoutError):
        b._register_catalog_entry()

    view = MemView(mod.CATALOG_MAPPING_SIZE)
    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: mod.WAIT_OBJECT_0)
    monkeypatch.setattr(b, "_open_or_create_catalog_map", lambda shard: 1)
    monkeypatch.setattr(mod, "_MapView", lambda *a, **k: view)
    monkeypatch.setattr(mod.win32event, "ReleaseMutex", lambda h: (_ for _ in ()).throw(RuntimeError("release")))
    b._register_catalog_entry()
    b._maybe_unregister_catalog_entry()

    monkeypatch.setattr(mod, "_open_file_mapping", lambda *a, **k: (_ for _ in ()).throw(OSError("missing")))
    assert b._read_catalog_shard(shard, prune_stale=False) == []

    view = MemView(mod.CATALOG_MAPPING_SIZE)
    mod._write_shard_frame(view, {"entries": [{"namespace": b.namespace}]}, mapping_size=mod.CATALOG_MAPPING_SIZE)
    monkeypatch.setattr(mod, "_open_file_mapping", lambda *a, **k: 1)
    monkeypatch.setattr(mod.win32event, "OpenMutex", lambda *a: (_ for _ in ()).throw(_pywin_error()))
    monkeypatch.setattr(mod, "_MapView", lambda *a, **k: view)
    assert b._read_catalog_shard(shard, prune_stale=False) == [{"namespace": b.namespace}]

    monkeypatch.setattr(mod.win32event, "OpenMutex", lambda *a: "mutex")
    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: 999)
    assert b._read_catalog_shard(shard, prune_stale=False) == []

    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: mod.WAIT_OBJECT_0)
    monkeypatch.setattr(mod.win32event, "ReleaseMutex", lambda h: (_ for _ in ()).throw(RuntimeError("release")))
    monkeypatch.setattr(mod.win32api, "CloseHandle", lambda h: (_ for _ in ()).throw(RuntimeError("close")))
    assert b._read_catalog_shard(shard, prune_stale=False) == [{"namespace": b.namespace}]

    monkeypatch.setattr(mod.win32event, "OpenMutex", lambda *a: (_ for _ in ()).throw(_pywin_error()))
    b._prune_catalog_shard(shard, alive=set())

    monkeypatch.setattr(mod.win32event, "OpenMutex", lambda *a: "mutex")
    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: 999)
    monkeypatch.setattr(mod.win32api, "CloseHandle", lambda h: None)
    b._prune_catalog_shard(shard, alive=set())

    monkeypatch.setattr(mod.win32event, "WaitForSingleObject", lambda *a: mod.WAIT_OBJECT_0)
    monkeypatch.setattr(mod, "_open_file_mapping", lambda *a, **k: (_ for _ in ()).throw(OSError("missing")))
    b._open_catalog_maps = {}
    b._prune_catalog_shard(shard, alive=set())

    view = MemView(mod.CATALOG_MAPPING_SIZE)
    mod._write_shard_frame(view, {"entries": [{"namespace": "keep"}, {"namespace": "drop"}]}, mapping_size=mod.CATALOG_MAPPING_SIZE)
    monkeypatch.setattr(mod, "_open_file_mapping", lambda *a, **k: 1)
    monkeypatch.setattr(mod, "_MapView", lambda *a, **k: view)
    b._prune_catalog_shard(shard, alive={"keep"})


def test_mapview_edges(monkeypatch):
    monkeypatch.setattr(mod, "_MapViewOfFile", lambda *a: 0)
    with pytest.raises(OSError):
        mod._MapView(1, 8, write=False)

    monkeypatch.setattr(mod, "_MapViewOfFile", lambda *a: 1000)
    monkeypatch.setattr(mod.ctypes, "string_at", lambda ptr, n: b"x" * n)
    moved = []
    monkeypatch.setattr(mod.ctypes, "memmove", lambda ptr, data, n: moved.append((ptr, data, n)))

    view = mod._MapView(1, 8, write=True)
    assert view.size() == 8
    with pytest.raises(ValueError):
        view.seek(9)
    assert view.read(2) == b"xx"
    view.write(b"ab")
    assert moved
    with pytest.raises(ValueError):
        view.write(b"x" * 100)
    view.flush()
    monkeypatch.setattr(mod, "_UnmapViewOfFile", lambda ptr: (_ for _ in ()).throw(RuntimeError("unmap")))
    view.close()
    view.close()

    ro = mod._MapView(1, 8, write=False)
    with pytest.raises(IOError):
        ro.write(b"x")
