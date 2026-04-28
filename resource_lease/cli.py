"""Command-line interface and reusable formatters for resource_lease.

Subcommands:
    status            print a table of (resource → busy/idle + owner) for
                      the given resource ids
    list              list all currently active leases in a namespace
    list-namespaces   list all namespaces with at least one active lease
    info              dump full owner metadata for a single resource
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Iterable, Sequence
from typing import List, Optional

from .autoselect import auto_select_backend
from .base import LeaseBackend
from .info import LeaseInfo


def _fmt_age(started_at: float, now: Optional[float] = None) -> str:
    if not started_at:
        return "-"
    delta = max(0.0, (now or time.time()) - started_at)
    if delta < 60:
        return f"{int(delta)}s"
    if delta < 3600:
        return f"{int(delta // 60)}m"
    if delta < 86400:
        return f"{int(delta // 3600)}h{int((delta % 3600) // 60)}m"
    return f"{int(delta // 86400)}d{int((delta % 86400) // 3600)}h"


def _truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    if n <= 1:
        return s[:n]
    return s[: n - 1] + "…"


def status_rows(
    backend: LeaseBackend, resource_ids: Sequence[str]
) -> List[dict]:
    """One row per resource — used by both `status` CLI and benchmark_runner."""
    now = time.time()
    rows = []
    for rid in resource_ids:
        owner = backend.query(rid)
        if owner is None:
            rows.append({
                "resource_id": rid,
                "status": "idle",
                "owner": None,
                "age": "-",
            })
            continue
        rows.append({
            "resource_id": rid,
            "status": "busy",
            "owner": owner,
            "age": _fmt_age(owner.started_at, now),
        })
    return rows


def status_table(
    backend: LeaseBackend,
    resource_ids: Sequence[str],
    *,
    json_output: bool = False,
    out=None,
) -> int:
    """Print a status table. Returns the count of busy rows."""
    out = out if out is not None else sys.stdout
    rows = status_rows(backend, resource_ids)
    busy = sum(1 for r in rows if r["status"] == "busy")

    if json_output:
        payload = []
        for r in rows:
            owner = r["owner"]
            payload.append({
                "resource_id": r["resource_id"],
                "status": r["status"],
                "age": r["age"],
                "owner": _info_to_dict(owner) if owner else None,
            })
        out.write(json.dumps({"namespace": backend.namespace, "rows": payload}, indent=2))
        out.write("\n")
        return busy

    headers = ("RESOURCE", "STATUS", "OWNER", "PID", "PURPOSE", "RUN_ID", "AGE")
    body = []
    for r in rows:
        owner = r["owner"]
        if owner is None:
            body.append((r["resource_id"], "idle", "-", "-", "-", "-", "-"))
        else:
            body.append((
                r["resource_id"],
                "busy",
                _truncate(owner.agent_name or "?", 24),
                str(owner.pid),
                _truncate(owner.purpose or "-", 28),
                _truncate(owner.run_id or "-", 22),
                r["age"],
            ))
    _write_table(out, headers, body)
    return busy


def list_table(
    backend: LeaseBackend,
    *,
    json_output: bool = False,
    out=None,
) -> int:
    """Print all active leases. Returns number of active leases."""
    out = out if out is not None else sys.stdout
    infos = backend.list()
    if json_output:
        out.write(json.dumps(
            {"namespace": backend.namespace,
             "active": [_info_to_dict(i) for i in infos]},
            indent=2,
        ))
        out.write("\n")
        return len(infos)

    if not infos:
        out.write(f"(no active leases in namespace {backend.namespace!r})\n")
        return 0

    headers = ("RESOURCE", "OWNER", "PID", "PURPOSE", "RUN_ID", "AGE")
    now = time.time()
    body = [
        (
            _truncate(i.resource_id, 32),
            _truncate(i.agent_name or "?", 24),
            str(i.pid),
            _truncate(i.purpose or "-", 28),
            _truncate(i.run_id or "-", 22),
            _fmt_age(i.started_at, now),
        )
        for i in infos
    ]
    _write_table(out, headers, body)
    return len(infos)


def _info_to_dict(info: LeaseInfo) -> dict:
    return {
        "resource_id": info.resource_id,
        "namespace": info.namespace,
        "owner_token": info.owner_token,
        "agent_name": info.agent_name,
        "purpose": info.purpose,
        "run_id": info.run_id,
        "pid": info.pid,
        "uid": info.uid,
        "started_at": info.started_at,
        "cmdline": info.cmdline,
        "extra": info.extra,
        "metadata_available": info.metadata_available,
    }


def _write_table(out, headers: Iterable[str], body: Iterable[Iterable[str]]) -> None:
    headers = list(headers)
    body = [list(row) for row in body]
    widths = [len(h) for h in headers]
    for row in body:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    out.write(fmt.format(*headers).rstrip() + "\n")
    for row in body:
        out.write(fmt.format(*row).rstrip() + "\n")


# ── argparse ─────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="resource-lease",
        description="Inspect resource_lease leases on this machine.",
    )
    p.add_argument(
        "--backend",
        choices=("auto", "abstract", "winmutex", "none"),
        default="auto",
        help="Force a backend (default: auto-select by platform).",
    )
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_status = sub.add_parser("status", help="Status table for given resources.")
    s_status.add_argument("--namespace", required=True)
    s_status.add_argument("--resources", nargs="+", required=True)

    s_list = sub.add_parser("list", help="List all active leases in a namespace.")
    s_list.add_argument("--namespace", required=True)

    sub.add_parser("list-namespaces", help="List namespaces with active leases.")

    s_info = sub.add_parser("info", help="Dump owner metadata for one resource.")
    s_info.add_argument("--namespace", required=True)
    s_info.add_argument("--resource", required=True)

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    force = None if args.backend == "auto" else args.backend

    if args.cmd == "list-namespaces":
        # We need *some* backend to enumerate; namespace value is irrelevant.
        backend = auto_select_backend("__list__", force=force)
        names = backend.list_namespaces()
        if args.json:
            sys.stdout.write(json.dumps({"namespaces": names}, indent=2) + "\n")
        else:
            for n in names:
                sys.stdout.write(n + "\n")
            if not names:
                sys.stdout.write("(no active namespaces)\n")
        return 0

    backend = auto_select_backend(args.namespace, force=force)

    if args.cmd == "status":
        busy = status_table(backend, args.resources, json_output=args.json)
        return 1 if busy else 0

    if args.cmd == "list":
        list_table(backend, json_output=args.json)
        return 0

    if args.cmd == "info":
        info = backend.query(args.resource)
        if info is None:
            if args.json:
                sys.stdout.write(json.dumps({"resource_id": args.resource, "status": "idle"}, indent=2) + "\n")
            else:
                sys.stdout.write(f"{args.resource}: idle\n")
            return 0
        if args.json:
            sys.stdout.write(json.dumps({
                "resource_id": args.resource,
                "status": "busy",
                "owner": _info_to_dict(info),
            }, indent=2) + "\n")
        else:
            for k, v in _info_to_dict(info).items():
                sys.stdout.write(f"{k:>14}: {v}\n")
        return 1

    return 2  # pragma: no cover - argparse subcommands make this unreachable.
