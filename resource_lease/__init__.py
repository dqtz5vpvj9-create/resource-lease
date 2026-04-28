"""resource_lease: daemonless, local, named resource leases with owner metadata.

Public API:

    from resource_lease import (
        auto_select_backend,
        LeaseBackend, LeaseInfo, LeaseHandle, LeaseConflict,
    )

    backend = auto_select_backend(namespace="my.tool.devices")
    info = LeaseInfo(resource_id="dev0", agent_name="alice",
                     purpose="smoke", pid=os.getpid(), uid=os.getuid())
    try:
        handle = backend.acquire("dev0", info)
    except LeaseConflict as e:
        print(f"held by {e.owner.agent_name}: {e.owner.purpose}")
        raise
    # ... use ...
    handle.release()
"""

from .autoselect import auto_select_backend
from .base import LeaseBackend
from .errors import LeaseConflict
from .handle import LeaseHandle
from .info import LeaseInfo, new_owner_token

__all__ = [
    "LeaseBackend",
    "LeaseConflict",
    "LeaseHandle",
    "LeaseInfo",
    "auto_select_backend",
    "new_owner_token",
]

__version__ = "0.1.0"
