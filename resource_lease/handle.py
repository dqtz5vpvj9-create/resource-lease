"""LeaseHandle — opaque resource handle returned by acquire()."""

from __future__ import annotations

import threading
from typing import Callable

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
    ) -> None:
        self.resource_id = resource_id
        self.info = info
        self._release_fn = release_fn
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

    def __enter__(self) -> LeaseHandle:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()
