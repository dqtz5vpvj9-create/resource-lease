"""LeaseHandle — opaque resource handle returned by acquire()."""

from __future__ import annotations

import threading
from dataclasses import replace
from typing import Callable, Optional

from .info import LeaseInfo


class LeaseHandle:
    """Returned by :meth:`LeaseBackend.acquire`. Idempotent ``release()``.

    A handle is a *token* — the underlying lease is owned by the backend, not
    by the handle. Dropping the handle without calling :meth:`release` does
    NOT release the lease (that would silently break consumers who acquire,
    fire-and-forget, and rely on the lease being held until process death).
    The lease is freed only by:

    1. an explicit :meth:`release` call (or context-manager exit),
    2. an explicit :meth:`LeaseBackend.close`,
    3. the owning process exiting (kernel cleanup).
    """

    def __init__(
        self,
        resource_id: str,
        info: LeaseInfo,
        release_fn: Callable[[], None],
        update_fn: Optional[Callable[[LeaseInfo], LeaseInfo]] = None,
    ) -> None:
        self.resource_id = resource_id
        self.info = info
        self._release_fn = release_fn
        self._update_fn = update_fn
        self._released = threading.Event()

    @property
    def released(self) -> bool:
        return self._released.is_set()

    def release(self) -> None:
        if self._released.is_set():
            return
        self._released.set()
        try:
            self._release_fn()
        except Exception:
            pass

    def update(self, info: LeaseInfo) -> LeaseInfo:
        """Replace owner metadata for this held lease.

        Backends preserve immutable backend fields (namespace, resource hash,
        owner token, started_at) while publishing the new consumer metadata.
        """
        if self._released.is_set():
            raise RuntimeError(f"cannot update released lease {self.resource_id!r}")
        if self._update_fn is None:
            raise NotImplementedError("lease backend does not support metadata updates")
        self.info = self._update_fn(info)
        return self.info

    def update_status(self, status: str, **extra) -> LeaseInfo:
        merged_extra = dict(self.info.extra or {})
        merged_extra.update(extra)
        return self.update(replace(self.info, status=status, extra=merged_extra))

    def __enter__(self) -> LeaseHandle:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()
