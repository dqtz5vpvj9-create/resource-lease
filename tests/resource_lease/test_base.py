"""Tests for backend ABC defaults."""

from __future__ import annotations

from typing import List, Optional

from resource_lease.base import LeaseBackend
from resource_lease.handle import LeaseHandle
from resource_lease.info import LeaseInfo


class _BackendWithDefaultClose(LeaseBackend):
    namespace = "test.base"

    def acquire(self, resource_id: str, info: LeaseInfo) -> LeaseHandle:
        raise NotImplementedError

    def query(
        self, resource_id: str, *, timeout: float = 0.5
    ) -> Optional[LeaseInfo]:
        return None

    def list(self) -> List[LeaseInfo]:
        return []

    def list_namespaces(self) -> List[str]:
        return []


def test_default_close_is_noop():
    backend = _BackendWithDefaultClose()
    assert backend.close() is None
    try:
        backend.update("r0", LeaseInfo(resource_id="r0"))
    except NotImplementedError as exc:
        assert "metadata updates" in str(exc)
