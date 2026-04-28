# resource-lease

**Daemonless local resource leases for Python.**

Claim any local resource by name, attach owner metadata, detect conflicts, and inspect who is using what.

No daemon.  
No lock files.  
No stale cleanup jobs.

```python
from resource_lease import LeaseInfo, auto_select_backend

backend = auto_select_backend("bench.devices")

info = LeaseInfo(
    resource_id="gpu:0",
    agent_name="agent-a",
    purpose="run benchmark shard 3",
    run_id="2026-04-28-103104",
)

with backend.acquire("gpu:0", info):
    run_benchmark()
```

## What It Does

`resource-lease` coordinates opaque resource names on one client machine:

```text
gpu:0
license:foo
0.0.0.0:6520
pro0:0.0.0.0:6520
```

It does not parse device names, hosts, ports, or resource classes. Consumers choose a namespace and pass `resource_id` strings through unchanged.

## Install

```bash
pip install resource-lease
```

Windows users who need the native named-mutex backend should install:

```bash
pip install "resource-lease[win32]"
```

## Backends

- Linux: abstract Unix domain sockets. The kernel releases the lease when the owner process exits.
- Windows: named mutex plus named file mapping. The mutex is the source of truth; mappings store owner metadata and volatile list indexes.
- Other platforms: `NoopLeaseBackend`, useful for tests but not cross-process.

## Inspect Leases

```bash
resource-lease status --namespace bench.devices --resources gpu:0 gpu:1
resource-lease list --namespace bench.devices
resource-lease list-namespaces
```

JSON output is available with `--json`.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/resource_lease
```

Linux/common coverage gate:

```bash
python -m coverage run --source=resource_lease \
  --omit='resource_lease/backends/win_mutex.py' \
  -m pytest tests/resource_lease
python -m coverage report --fail-under=100 \
  --omit='resource_lease/backends/win_mutex.py'
```

Windows backend coverage gate:

```powershell
python -m pip install -e ".[dev,win32]"
python -m coverage run --source=resource_lease.backends.win_mutex `
  -m pytest tests/resource_lease/test_win_mutex.py `
            tests/resource_lease/test_win_mutex_coverage.py
python -m coverage report --fail-under=100
```

## Scope

This is a local lease library, not a distributed lock service. If multiple client machines need to coordinate access to the same physical resources, use a distributed backend or broker.
