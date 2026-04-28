"""In-process fallback backend.

Used when no native cross-process backend is available (macOS / BSD) or when
explicitly selected via ``--lease-backend none``. Tracks leases in a
process-local dict — provides the API surface but is NOT cross-process.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Dict, List, Optional

from ..base import LeaseBackend
from ..errors import LeaseConflict
from ..handle import LeaseHandle
from ..info import LeaseInfo, new_owner_token

logger = logging.getLogger("resource_lease.noop")


class NoopLeaseBackend(LeaseBackend):
    def __init__(self, namespace: str) -> None:
        self.namespace = namespace
        self._lock = threading.Lock()
        self._held: Dict[str, LeaseInfo] = {}

    def acquire(self, resource_id: str, info: LeaseInfo) -> LeaseHandle:
        with self._lock:
            existing = self._held.get(resource_id)
            if existing is not None:
                raise LeaseConflict(resource_id, existing)
            stamped = info.with_backend_metadata(
                namespace=self.namespace,
                resource_hash="",
                owner_token=new_owner_token(info.pid or os.getpid()),
            )
            self._held[resource_id] = stamped
        return LeaseHandle(
            resource_id,
            stamped,
            lambda: self._release(resource_id),
            lambda info, rid=resource_id: self.update(rid, info),
        )

    def update(self, resource_id: str, info: LeaseInfo) -> LeaseInfo:
        with self._lock:
            current = self._held.get(resource_id)
            if current is None:
                raise RuntimeError(f"resource is not held by this backend: {resource_id!r}")
            stamped = info.with_backend_metadata(
                namespace=self.namespace,
                resource_hash=current.resource_hash,
                owner_token=current.owner_token,
            )
            stamped.started_at = current.started_at
            self._held[resource_id] = stamped
            return stamped

    def _release(self, resource_id: str) -> None:
        with self._lock:
            self._held.pop(resource_id, None)

    def query(
        self, resource_id: str, *, timeout: float = 0.5
    ) -> Optional[LeaseInfo]:
        with self._lock:
            return self._held.get(resource_id)

    def list(self) -> List[LeaseInfo]:
        with self._lock:
            return list(self._held.values())

    def list_namespaces(self) -> List[str]:
        with self._lock:
            return [self.namespace] if self._held else []
