"""Smoke tests for the resource_lease CLI."""

from __future__ import annotations

import io
import json
import os
import sys
import time
import uuid

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("CLI smoke uses the Linux backend", allow_module_level=True)

from resource_lease import LeaseInfo, auto_select_backend
from resource_lease.cli import (
    _fmt_age,
    _truncate,
    list_table,
    main,
    status_rows,
    status_table,
)


def _ns() -> str:
    return f"rl.cli.{uuid.uuid4().hex[:8]}"


def _info(rid: str, **kw) -> LeaseInfo:
    base = dict(
        resource_id=rid,
        agent_name="alice",
        purpose="cli-test",
        run_id="run-x",
        pid=os.getpid(),
        uid=os.getuid(),
    )
    base.update(kw)
    return LeaseInfo(**base)


def test_status_rows_idle_and_busy():
    ns = _ns()
    b = auto_select_backend(ns, force="abstract")
    h = b.acquire("dev0", _info("dev0"))
    try:
        rows = status_rows(b, ["dev0", "dev1"])
        statuses = {r["resource_id"]: r["status"] for r in rows}
        assert statuses == {"dev0": "busy", "dev1": "idle"}
    finally:
        h.release()


def test_status_table_text():
    ns = _ns()
    b = auto_select_backend(ns, force="abstract")
    h = b.acquire("dev0", _info("dev0", agent_name="alice", purpose="smoke"))
    try:
        out = io.StringIO()
        busy = status_table(b, ["dev0", "dev1"], out=out)
        text = out.getvalue()
        assert busy == 1
        assert "dev0" in text
        assert "dev1" in text
        assert "alice" in text
        assert "smoke" in text
        assert "busy" in text
        assert "idle" in text
    finally:
        h.release()


def test_status_table_json():
    ns = _ns()
    b = auto_select_backend(ns, force="abstract")
    h = b.acquire("dev0", _info("dev0", agent_name="alice"))
    try:
        out = io.StringIO()
        status_table(b, ["dev0", "dev1"], json_output=True, out=out)
        payload = json.loads(out.getvalue())
        assert payload["namespace"] == ns
        rows = {r["resource_id"]: r for r in payload["rows"]}
        assert rows["dev0"]["status"] == "busy"
        assert rows["dev0"]["owner"]["agent_name"] == "alice"
        assert rows["dev1"]["status"] == "idle"
        assert rows["dev1"]["owner"] is None
    finally:
        h.release()


def test_list_table_empty():
    ns = _ns()
    b = auto_select_backend(ns, force="abstract")
    out = io.StringIO()
    n = list_table(b, out=out)
    assert n == 0
    assert ns in out.getvalue()


def test_list_table_json():
    ns = _ns()
    b = auto_select_backend(ns, force="abstract")
    h = b.acquire("dev0", _info("dev0", agent_name="alice"))
    try:
        out = io.StringIO()
        n = list_table(b, json_output=True, out=out)
        payload = json.loads(out.getvalue())
        assert n == 1
        assert payload["namespace"] == ns
        assert payload["active"][0]["resource_id"] == "dev0"
        assert payload["active"][0]["metadata_available"] is True
    finally:
        h.release()


def test_list_table_with_active():
    ns = _ns()
    b = auto_select_backend(ns, force="abstract")
    handles = [
        b.acquire(rid, _info(rid, agent_name=f"a-{rid}"))
        for rid in ("x", "y")
    ]
    try:
        out = io.StringIO()
        n = list_table(b, out=out)
        assert n == 2
        text = out.getvalue()
        assert "x" in text and "y" in text
        assert "a-x" in text and "a-y" in text
    finally:
        for h in handles:
            h.release()


def test_main_status_exit_code(capsys):
    ns = _ns()
    b = auto_select_backend(ns, force="abstract")
    h = b.acquire("dev0", _info("dev0"))
    try:
        # status returns 1 when at least one resource is busy
        rc = main(["--backend", "abstract", "status", "--namespace", ns,
                   "--resources", "dev0", "dev1"])
        assert rc == 1
        captured = capsys.readouterr()
        assert "busy" in captured.out
        assert "idle" in captured.out
    finally:
        h.release()
    rc = main(["--backend", "abstract", "status", "--namespace", ns,
               "--resources", "dev0"])
    assert rc == 0


def test_main_list_namespaces_includes_busy_namespace(capsys):
    ns = _ns()
    b = auto_select_backend(ns, force="abstract")
    h = b.acquire("dev0", _info("dev0"))
    try:
        rc = main(["--backend", "abstract", "list-namespaces"])
        assert rc == 0
        out = capsys.readouterr().out
        assert ns in out
    finally:
        h.release()


def test_main_list_namespaces_json_and_empty_text(capsys):
    rc = main(["--backend", "none", "--json", "list-namespaces"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {"namespaces": []}

    rc = main(["--backend", "none", "list-namespaces"])
    assert rc == 0
    assert "(no active namespaces)" in capsys.readouterr().out


def test_main_info_idle(capsys):
    ns = _ns()
    rc = main(["--backend", "abstract", "info", "--namespace", ns,
               "--resource", "missing"])
    assert rc == 0
    assert "idle" in capsys.readouterr().out


def test_main_info_idle_json(capsys):
    ns = _ns()
    rc = main(["--backend", "abstract", "--json", "info", "--namespace", ns,
               "--resource", "missing"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"resource_id": "missing", "status": "idle"}


def test_main_info_busy_text_and_json(capsys):
    ns = _ns()
    b = auto_select_backend(ns, force="abstract")
    h = b.acquire("dev0", _info("dev0", agent_name="alice"))
    try:
        rc = main(["--backend", "abstract", "info", "--namespace", ns,
                   "--resource", "dev0"])
        assert rc == 1
        assert "agent_name" in capsys.readouterr().out

        rc = main(["--backend", "abstract", "--json", "info", "--namespace", ns,
                   "--resource", "dev0"])
        assert rc == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "busy"
        assert payload["owner"]["agent_name"] == "alice"
    finally:
        h.release()


def test_main_list_active_and_json(capsys):
    ns = _ns()
    b = auto_select_backend(ns, force="abstract")
    h = b.acquire("dev0", _info("dev0", agent_name="alice"))
    try:
        rc = main(["--backend", "abstract", "list", "--namespace", ns])
        assert rc == 0
        assert "dev0" in capsys.readouterr().out

        rc = main(["--backend", "abstract", "--json", "list", "--namespace", ns])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["active"][0]["resource_id"] == "dev0"
    finally:
        h.release()


def test_format_helpers_edges():
    now = time.time()
    assert _fmt_age(0, now) == "-"
    assert _fmt_age(now - 59, now) == "59s"
    assert _fmt_age(now - 61, now) == "1m"
    assert _fmt_age(now - 3661, now) == "1h1m"
    assert _fmt_age(now - 90000, now) == "1d1h"
    assert _truncate("abcdef", 10) == "abcdef"
    assert _truncate("abcdef", 1) == "a"
    assert _truncate("abcdef", 4) == "abc…"
