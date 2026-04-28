"""Windows tests for named mutex + file mapping backend.

These are skipped on non-Windows hosts. They intentionally exercise only public
API behavior; private mapping/index helpers are validated indirectly through
query(), list(), and list_namespaces().
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid

import pytest

if sys.platform != "win32":
    pytest.skip("Windows-only backend", allow_module_level=True)

pytest.importorskip("win32event")

from resource_lease import LeaseConflict, LeaseInfo
from resource_lease.backends.win_mutex import WindowsMutexMappingLeaseBackend


def _ns() -> str:
    return f"rl.win.{uuid.uuid4().hex[:10]}"


def _info(rid: str = "r0", **kw) -> LeaseInfo:
    base = dict(
        resource_id=rid,
        agent_name="win-tester",
        purpose="unit",
        run_id="run-1",
        pid=os.getpid(),
        uid=0,
        started_at=time.time(),
        cmdline="pytest",
    )
    base.update(kw)
    return LeaseInfo(**base)


def test_acquire_query_release_cycle():
    b = WindowsMutexMappingLeaseBackend(_ns())
    h = b.acquire("r0", _info(agent_name="owner"))
    try:
        q = b.query("r0")
        assert q is not None
        assert q.metadata_available is True
        assert q.agent_name == "owner"
        assert q.owner_token == h.info.owner_token
    finally:
        h.release()
        b.close()
    assert WindowsMutexMappingLeaseBackend(b.namespace).query("r0") is None


def test_conflict_carries_owner_metadata():
    ns = _ns()
    a = WindowsMutexMappingLeaseBackend(ns)
    b = WindowsMutexMappingLeaseBackend(ns)
    h = a.acquire("r0", _info(agent_name="first", purpose="hold"))
    try:
        with pytest.raises(LeaseConflict) as exc:
            b.acquire("r0", _info(agent_name="second"))
        assert exc.value.owner is not None
        assert exc.value.owner.agent_name == "first"
        assert exc.value.owner.purpose == "hold"
    finally:
        h.release()
        a.close()
        b.close()


def test_namespace_isolation_same_resource_id():
    a = WindowsMutexMappingLeaseBackend(_ns())
    b = WindowsMutexMappingLeaseBackend(_ns())
    ha = a.acquire("same", _info("same", agent_name="A"))
    try:
        hb = b.acquire("same", _info("same", agent_name="B"))
        hb.release()
    finally:
        ha.release()
        a.close()
        b.close()


def test_list_and_list_namespaces():
    ns = _ns()
    b = WindowsMutexMappingLeaseBackend(ns)
    handles = [
        b.acquire(f"r{i}", _info(f"r{i}", agent_name=f"agent-{i}"))
        for i in range(3)
    ]
    try:
        active = b.list()
        assert sorted(i.resource_id for i in active) == ["r0", "r1", "r2"]
        assert ns in b.list_namespaces()
    finally:
        for h in handles:
            h.release()
        b.close()

    observer = WindowsMutexMappingLeaseBackend(ns)
    try:
        assert observer.list() == []
        assert ns not in observer.list_namespaces()
    finally:
        observer.close()


def test_process_death_releases_mutex():
    ns = _ns()
    rid = f"r-{uuid.uuid4().hex[:8]}"
    code = f"""
import os, sys, time
sys.path.insert(0, {os.getcwd()!r})
from resource_lease import LeaseInfo
from resource_lease.backends.win_mutex import WindowsMutexMappingLeaseBackend
b = WindowsMutexMappingLeaseBackend({ns!r})
b.acquire({rid!r}, LeaseInfo(resource_id={rid!r}, agent_name='child', pid=os.getpid(), started_at=time.time()))
print('READY', flush=True)
time.sleep(30)
"""
    proc = subprocess.Popen(
        [sys.executable, "-c", code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline().strip() == "READY"
        observer = WindowsMutexMappingLeaseBackend(ns)
        try:
            q = observer.query(rid)
            assert q is not None
            assert q.agent_name == "child"
        finally:
            observer.close()
    finally:
        proc.kill()
        proc.wait(timeout=10)

    deadline = time.time() + 5
    while time.time() < deadline:
        observer = WindowsMutexMappingLeaseBackend(ns)
        try:
            if observer.query(rid) is None:
                break
        finally:
            observer.close()
        time.sleep(0.05)

    reclaimer = WindowsMutexMappingLeaseBackend(ns)
    try:
        assert reclaimer.query(rid) is None
        h = reclaimer.acquire(rid, _info(rid, agent_name="reclaimer"))
        h.release()
    finally:
        reclaimer.close()
