"""Pick a backend based on platform."""

from __future__ import annotations

import logging
import sys
from typing import Optional

from .base import LeaseBackend

logger = logging.getLogger("resource_lease.autoselect")


def auto_select_backend(
    namespace: str,
    *,
    force: Optional[str] = None,
) -> LeaseBackend:
    """Construct a backend for *namespace*.

    *force* options:
        ``"abstract"`` — Linux abstract Unix socket
        ``"winmutex"`` — Windows named mutex + file mapping
        ``"none"``     — :class:`NoopLeaseBackend` (no cross-process semantics)
        ``None``       — auto-select by ``sys.platform``
    """
    if force == "none":
        from .backends.noop import NoopLeaseBackend

        return NoopLeaseBackend(namespace)

    if force == "abstract" or (force is None and sys.platform.startswith("linux")):
        from .backends.abstract_socket import AbstractSocketLeaseBackend

        return AbstractSocketLeaseBackend(namespace)

    if force == "winmutex" or (force is None and sys.platform == "win32"):
        from .backends.win_mutex import WindowsMutexMappingLeaseBackend

        return WindowsMutexMappingLeaseBackend(namespace)

    if force is not None:
        raise ValueError(f"unknown lease backend: {force!r}")

    logger.warning(
        "no native resource_lease backend on platform %r; using NoopLeaseBackend "
        "(no cross-process coordination)",
        sys.platform,
    )
    from .backends.noop import NoopLeaseBackend

    return NoopLeaseBackend(namespace)
