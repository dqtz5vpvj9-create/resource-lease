"""LeaseBackend ABC. All backends bind to a single namespace at construction."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from .handle import LeaseHandle
from .info import LeaseInfo


class LeaseBackend(ABC):
    """Abstract backend for cross-process named resource leases.

    A backend instance is bound to a single ``namespace`` string. Different
    namespaces never collide on the same ``resource_id`` (the namespace is
    incorporated into the kernel object name), so multiple tools can coexist
    on the same client without coordination.
    """

    namespace: str

    @abstractmethod
    def acquire(self, resource_id: str, info: LeaseInfo) -> LeaseHandle:
        """Take an exclusive lease on *resource_id*.

        Raises :class:`LeaseConflict` if another process holds it.
        """

    @abstractmethod
    def query(
        self, resource_id: str, *, timeout: float = 0.5
    ) -> Optional[LeaseInfo]:
        """Read the current owner's metadata, or None if idle."""

    @abstractmethod
    def list(self) -> List[LeaseInfo]:
        """All currently active leases in this namespace (same user, same client)."""

    @abstractmethod
    def list_namespaces(self) -> List[str]:
        """All namespaces with at least one active lease (same user, same client).

        May be more expensive than :meth:`list` since it scans across namespaces.
        """

    def close(self) -> None:
        """Release backend-level caches (file mapping handles etc.).

        Default no-op. Calling :meth:`acquire` after :meth:`close` is undefined.
        """
        return None
