"""Library exceptions."""

from __future__ import annotations

from typing import Optional

from .info import LeaseInfo


class LeaseConflict(RuntimeError):
    """Raised by :meth:`LeaseBackend.acquire` when another process holds the lease.

    The ``owner`` attribute carries the holder's :class:`LeaseInfo` if it could
    be read (it may be ``None`` on rare races where the holder has the mutex
    but hasn't published metadata yet).
    """

    def __init__(self, resource_id: str, owner: Optional[LeaseInfo]) -> None:
        self.resource_id = resource_id
        self.owner = owner
        if owner is not None:
            agent = owner.agent_name or "?"
            purpose = owner.purpose or "<no purpose>"
            super().__init__(
                f"resource {resource_id!r} held by {agent} "
                f"(pid={owner.pid}): {purpose}"
            )
        else:
            super().__init__(
                f"resource {resource_id!r} held (owner metadata unavailable)"
            )
