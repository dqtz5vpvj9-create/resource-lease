"""Cross-backend namespace isolation invariants."""

from __future__ import annotations

import os
import sys
import uuid

import pytest

from resource_lease import LeaseConflict, LeaseInfo, auto_select_backend


def _info() -> LeaseInfo:
    return LeaseInfo(
        resource_id="r0",
        agent_name="tester",
        pid=os.getpid(),
        uid=os.getuid(),
    )


def _force() -> str:
    return "abstract" if sys.platform.startswith("linux") else "none"


def test_same_resource_id_different_namespaces_do_not_conflict():
    ns_a = f"rl.iso.a.{uuid.uuid4().hex[:8]}"
    ns_b = f"rl.iso.b.{uuid.uuid4().hex[:8]}"
    ba = auto_select_backend(ns_a, force=_force())
    bb = auto_select_backend(ns_b, force=_force())
    ha = ba.acquire("r0", _info())
    try:
        hb = bb.acquire("r0", _info())  # must not raise
        hb.release()
    finally:
        ha.release()


def test_same_namespace_same_resource_id_conflicts():
    ns = f"rl.iso.same.{uuid.uuid4().hex[:8]}"
    ba = auto_select_backend(ns, force=_force())
    bb = auto_select_backend(ns, force=_force())
    ha = ba.acquire("r0", _info())
    try:
        if _force() == "none":
            # NoopLeaseBackend is per-instance; two instances are independent
            # so we skip the cross-instance assertion here.
            pytest.skip("Noop backend is per-instance")
        with pytest.raises(LeaseConflict):
            bb.acquire("r0", _info())
    finally:
        ha.release()
