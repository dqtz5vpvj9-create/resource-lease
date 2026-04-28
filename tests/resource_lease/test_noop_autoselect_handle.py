"""Coverage tests for small resource_lease modules."""

from __future__ import annotations

import importlib
import logging
import runpy
import sys

import pytest

from resource_lease import LeaseConflict, LeaseHandle, LeaseInfo, auto_select_backend
from resource_lease.backends.noop import NoopLeaseBackend


def test_noop_backend_full_cycle_and_conflict():
    backend = NoopLeaseBackend("noop.ns")
    assert backend.query("r0") is None
    assert backend.list() == []
    assert backend.list_namespaces() == []

    h = backend.acquire("r0", LeaseInfo(resource_id="r0", agent_name="owner"))
    assert backend.query("r0").agent_name == "owner"
    assert backend.list() == [h.info]
    assert backend.list_namespaces() == ["noop.ns"]

    with pytest.raises(LeaseConflict) as exc:
        backend.acquire("r0", LeaseInfo(resource_id="r0", agent_name="second"))
    assert "held by owner" in str(exc.value)

    h.release()
    assert backend.query("r0") is None


def test_lease_conflict_without_owner_message():
    exc = LeaseConflict("r0", None)
    assert "metadata unavailable" in str(exc)


def test_handle_context_manager_and_swallowed_release_error():
    calls = []

    def release():
        calls.append("release")
        raise RuntimeError("ignored")

    h = LeaseHandle("r0", LeaseInfo(resource_id="r0"), release)
    assert not h.released
    with h as same:
        assert same is h
    assert h.released
    h.release()
    assert calls == ["release"]


def test_auto_select_forced_none():
    backend = auto_select_backend("ns", force="none")
    assert isinstance(backend, NoopLeaseBackend)


def test_auto_select_unknown_force():
    with pytest.raises(ValueError):
        auto_select_backend("ns", force="bogus")


def test_auto_select_non_native_platform_falls_back(monkeypatch, caplog):
    mod = importlib.import_module("resource_lease.autoselect")
    monkeypatch.setattr(mod.sys, "platform", "darwin")
    caplog.set_level(logging.WARNING, logger="resource_lease.autoselect")
    backend = mod.auto_select_backend("ns")
    assert isinstance(backend, NoopLeaseBackend)
    assert "no native resource_lease backend" in caplog.text


def test_auto_select_winmutex_without_pywin32_raises_on_linux():
    if sys.platform == "win32":
        pytest.skip("covered by Windows backend tests")
    with pytest.raises(RuntimeError):
        auto_select_backend("ns", force="winmutex")


def test_module_main_delegates_to_cli_main(monkeypatch):
    import resource_lease.cli as cli

    monkeypatch.setattr(cli, "main", lambda: 7)
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("resource_lease.__main__", run_name="__main__")
    assert exc.value.code == 7
