"""Tests for the Linux abstract Unix socket backend."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("Linux-only backend", allow_module_level=True)

from resource_lease import LeaseConflict, LeaseInfo
from resource_lease.backends.abstract_socket import (
    AbstractSocketLeaseBackend,
    _abstract_name,
    _connect_and_get,
    _Lease,
    _peer_uid,
    _scan_proc_net_unix_with_prefix,
)


def _ns() -> str:
    return f"rl.test.{uuid.uuid4().hex[:10]}"


def _info(rid: str = "r0", **kw) -> LeaseInfo:
    base = dict(
        resource_id=rid,
        agent_name="tester",
        purpose="unit",
        run_id="run-1",
        pid=os.getpid(),
        uid=os.getuid(),
    )
    base.update(kw)
    return LeaseInfo(**base)


def test_acquire_release_cycle():
    b = AbstractSocketLeaseBackend(_ns())
    h = b.acquire("r0", _info())
    assert h.info.namespace == b.namespace
    assert h.info.owner_token
    h.release()
    h2 = b.acquire("r0", _info())
    h2.release()


def test_conflict_raises_with_owner_metadata():
    b = AbstractSocketLeaseBackend(_ns())
    h = b.acquire("r0", _info(agent_name="first", purpose="hold"))
    try:
        with pytest.raises(LeaseConflict) as exc:
            b.acquire("r0", _info(agent_name="second"))
        assert exc.value.resource_id == "r0"
        assert exc.value.owner is not None
        assert exc.value.owner.agent_name == "first"
        assert exc.value.owner.purpose == "hold"
    finally:
        h.release()


def test_query_returns_none_when_idle():
    b = AbstractSocketLeaseBackend(_ns())
    t0 = time.time()
    assert b.query("missing") is None
    # query of a never-bound name should not block ~timeout seconds
    assert (time.time() - t0) < 0.2


def test_query_returns_metadata_when_busy():
    b = AbstractSocketLeaseBackend(_ns())
    h = b.acquire("r0", _info(agent_name="A", purpose="P", run_id="RID"))
    try:
        q = b.query("r0")
        assert q is not None
        assert q.agent_name == "A"
        assert q.purpose == "P"
        assert q.run_id == "RID"
        assert q.pid == os.getpid()
        assert q.uid == os.getuid()
        assert q.owner_token == h.info.owner_token
    finally:
        h.release()


def test_update_status_publishes_new_metadata():
    b = AbstractSocketLeaseBackend(_ns())
    h = b.acquire("r0", _info(agent_name="A", purpose="P", status="allocated"))
    try:
        assert b.query("r0").status == "allocated"
        updated = h.update_status("in_use", job_name="job-a")
        assert updated.status == "in_use"
        q = b.query("r0")
        assert q is not None
        assert q.status == "in_use"
        assert q.owner_token == h.info.owner_token
        assert q.started_at == h.info.started_at
        assert q.extra["job_name"] == "job-a"
    finally:
        h.release()


def test_update_fills_pid_uid_and_rejects_not_held():
    b = AbstractSocketLeaseBackend(_ns())
    with pytest.raises(RuntimeError):
        b.update("missing", _info("missing"))
    h = b.acquire("r0", _info(agent_name="A"))
    try:
        updated = h.update(LeaseInfo(resource_id="r0", agent_name="B", status="allocated"))
        assert updated.pid == os.getpid()
        assert updated.uid == os.getuid()
        assert b.query("r0").agent_name == "B"
    finally:
        h.release()


def test_acquire_rejects_mismatched_info_resource_id():
    b = AbstractSocketLeaseBackend(_ns())
    with pytest.raises(ValueError, match="does not match"):
        b.acquire("r0", _info("r1"))


def test_update_rejects_mismatched_info_resource_id():
    b = AbstractSocketLeaseBackend(_ns())
    h = b.acquire("r0", _info("r0"))
    try:
        with pytest.raises(ValueError, match="does not match"):
            b.update("r0", _info("r1"))
    finally:
        h.release()


def test_release_is_idempotent():
    b = AbstractSocketLeaseBackend(_ns())
    h = b.acquire("r0", _info())
    h.release()
    h.release()  # must not raise


def test_context_manager_releases():
    b = AbstractSocketLeaseBackend(_ns())
    with b.acquire("r0", _info()):
        assert b.query("r0") is not None
    assert b.query("r0") is None


def test_cross_process_conflict_via_fork():
    ns = _ns()
    rid = "r0"

    pid = os.fork()
    if pid == 0:
        # child: hold the lease, signal parent via stdout, then sleep
        try:
            cb = AbstractSocketLeaseBackend(ns)
            cb.acquire(rid, _info(agent_name="child", purpose="hold"))
            sys.stdout.write("ACQUIRED\n")
            sys.stdout.flush()
            time.sleep(30)
        finally:
            os._exit(0)

    # parent
    deadline = time.time() + 5
    while time.time() < deadline:
        time.sleep(0.05)
        if AbstractSocketLeaseBackend(ns).query(rid) is not None:
            break
    try:
        b = AbstractSocketLeaseBackend(ns)
        with pytest.raises(LeaseConflict) as exc:
            b.acquire(rid, _info(agent_name="parent"))
        assert exc.value.owner is not None
        assert exc.value.owner.agent_name == "child"
    finally:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


def test_sigkill_releases_via_kernel_cleanup():
    ns = _ns()
    rid = "r0"

    pid = os.fork()
    if pid == 0:
        cb = AbstractSocketLeaseBackend(ns)
        cb.acquire(rid, _info(agent_name="ghost"))
        time.sleep(30)
        os._exit(0)

    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            if AbstractSocketLeaseBackend(ns).query(rid) is not None:
                break
            time.sleep(0.05)
        assert AbstractSocketLeaseBackend(ns).query(rid) is not None, "child never acquired"
    finally:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)

    # Kernel should free the abstract name immediately on process death.
    deadline = time.time() + 2
    while time.time() < deadline:
        if AbstractSocketLeaseBackend(ns).query(rid) is None:
            break
        time.sleep(0.05)
    assert AbstractSocketLeaseBackend(ns).query(rid) is None

    # And we should be able to re-acquire.
    b = AbstractSocketLeaseBackend(ns)
    h = b.acquire(rid, _info(agent_name="reclaimer"))
    h.release()


def test_list_returns_active_leases():
    ns = _ns()
    b = AbstractSocketLeaseBackend(ns)
    handles = []
    try:
        for rid in ("a", "b", "c"):
            handles.append(b.acquire(rid, _info(rid=rid, agent_name=f"agent-{rid}")))
        active = b.list()
        ids = sorted(i.resource_id for i in active)
        assert ids == ["a", "b", "c"]
        agents = {i.resource_id: i.agent_name for i in active}
        assert agents == {"a": "agent-a", "b": "agent-b", "c": "agent-c"}
    finally:
        for h in handles:
            h.release()
    assert b.list() == []


def test_list_namespaces_includes_active_only():
    ns_a = _ns()
    ns_b = _ns()
    ba = AbstractSocketLeaseBackend(ns_a)
    bb = AbstractSocketLeaseBackend(ns_b)
    h_a = ba.acquire("r0", _info())
    h_b = bb.acquire("r0", _info())
    try:
        names = ba.list_namespaces()
        assert ns_a in names
        assert ns_b in names
    finally:
        h_a.release()
        h_b.release()
    after = ba.list_namespaces()
    assert ns_a not in after
    assert ns_b not in after


def test_fd_does_not_leak_to_subprocess():
    """If the lease socket fd leaked to a child via fork+exec, the child would
    keep the abstract name alive after parent's release(). FD_CLOEXEC must
    prevent this."""
    ns = _ns()
    b = AbstractSocketLeaseBackend(ns)
    h = b.acquire("r0", _info(agent_name="parent"))

    # Spawn a long-running child that does NOT hold the lease socket itself.
    # close_fds defaults to True on POSIX since Python 3.7, but we want to
    # confirm CLOEXEC works even with close_fds=False.
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=False,
    )
    try:
        h.release()
        # After parent release, the abstract name must be gone — even though
        # the child is still alive — because exec() honored FD_CLOEXEC.
        deadline = time.time() + 2
        while time.time() < deadline:
            if b.query("r0") is None:
                break
            time.sleep(0.05)
        assert b.query("r0") is None, (
            "fd leaked into subprocess; lease still appears held"
        )
    finally:
        child.kill()
        child.wait(timeout=5)


def test_peer_uid_check_rejects_other_uid(monkeypatch):
    """Mock SO_PEERCRED to simulate a different uid; query should refuse."""
    ns = _ns()
    b = AbstractSocketLeaseBackend(ns)
    h = b.acquire("r0", _info())

    # Force the served accepted-conn to report a foreign uid.
    from resource_lease.backends import abstract_socket as mod

    real_peer_uid = mod._peer_uid

    def fake_peer_uid(conn):
        return os.getuid() + 1  # always foreign

    monkeypatch.setattr(mod, "_peer_uid", fake_peer_uid)

    try:
        # query() uses our own client connect; it should get the
        # permission_denied response instead of a frame.
        result = b.query("r0", timeout=0.5)
        assert result is None  # decode_frame on the JSON error returns None
    finally:
        monkeypatch.setattr(mod, "_peer_uid", real_peer_uid)
        h.release()


def test_namespace_isolation_same_resource_id():
    ns_a = _ns()
    ns_b = _ns()
    ba = AbstractSocketLeaseBackend(ns_a)
    bb = AbstractSocketLeaseBackend(ns_b)
    ha = ba.acquire("dev0", _info("dev0", agent_name="A"))
    try:
        # Same resource_id but different namespace must not conflict.
        hb = bb.acquire("dev0", _info("dev0", agent_name="B"))
        hb.release()
    finally:
        ha.release()


def test_long_namespace_rejected():
    too_long = "x" * 200
    b = AbstractSocketLeaseBackend(too_long)
    with pytest.raises(ValueError):
        b.acquire("r0", _info())


def test_invalid_namespaces_rejected():
    with pytest.raises(ValueError):
        AbstractSocketLeaseBackend("")
    with pytest.raises(ValueError):
        AbstractSocketLeaseBackend("bad..ns")


def test_abstract_name_format():
    """Sanity check the on-the-wire name layout the kernel sees."""
    name = _abstract_name("foo.bar", 1234, "dev0")
    assert name.startswith(b"\x00resource_lease.v1.foo.bar.1234.")
    # 16 hex chars at the end
    suffix = name.rsplit(b".", 1)[-1]
    assert len(suffix) == 16
    assert all(c in b"0123456789abcdef" for c in suffix)


def test_peer_uid_error_and_short_cred():
    class Raises:
        def getsockopt(self, *args):
            raise OSError("no creds")

    class Short:
        def getsockopt(self, *args):
            return b"x"

    assert _peer_uid(Raises()) is None
    assert _peer_uid(Short()) is None


def test_acquire_stamps_missing_pid_and_uid():
    b = AbstractSocketLeaseBackend(_ns())
    h = b.acquire("r0", LeaseInfo(resource_id="r0", agent_name="zero"))
    try:
        assert h.info.pid == os.getpid()
        assert h.info.uid == os.getuid()
    finally:
        h.release()


def test_bind_non_addrinuse_error_propagates(monkeypatch):
    from resource_lease.backends import abstract_socket as mod

    class FakeSocket:
        def set_inheritable(self, value):
            pass

        def fileno(self):
            return 0

        def bind(self, name):
            raise OSError(12345, "boom")

        def close(self):
            pass

    monkeypatch.setattr(mod.fcntl, "fcntl", lambda *args: 0)
    monkeypatch.setattr(mod.socket, "socket", lambda *args, **kwargs: FakeSocket())

    b = AbstractSocketLeaseBackend(_ns())
    with pytest.raises(OSError) as exc:
        b.acquire("r0", _info())
    assert exc.value.errno == 12345


def test_release_missing_and_socket_close_errors_are_ignored():
    class BadSock:
        def shutdown(self, *args):
            raise OSError("shutdown")

        def close(self):
            raise OSError("close")

    b = AbstractSocketLeaseBackend(_ns())
    b._release("missing")
    b._held["r0"] = _Lease(
        sock=BadSock(),
        thread=None,
        closed=threading.Event(),
        info=_info(),
        frame=b"frame",
        lock=threading.Lock(),
    )
    b._release("r0")
    assert "r0" not in b._held


def test_backend_close_releases_all():
    b = AbstractSocketLeaseBackend(_ns())
    b.acquire("a", _info("a"))
    b.acquire("b", _info("b"))
    assert b.list()
    b.close()
    assert b.list() == []


class _FakeServerSocket:
    def __init__(self, conn):
        self.conn = conn
        self.calls = 0

    def accept(self):
        self.calls += 1
        if self.calls == 1:
            return self.conn, None
        raise OSError("stop")


class _FakeConn:
    def __init__(self, recv_value=b"GET\n", *, recv_error=False,
                 send_error=False, close_error=False):
        self.recv_value = recv_value
        self.recv_error = recv_error
        self.send_error = send_error
        self.close_error = close_error
        self.sent = []

    def settimeout(self, value):
        self.timeout = value

    def recv(self, n):
        if self.recv_error:
            raise OSError("recv")
        return self.recv_value

    def sendall(self, data):
        if self.send_error:
            raise OSError("send")
        self.sent.append(data)

    def close(self):
        if self.close_error:
            raise OSError("close")


def _fake_lease(conn, frame=b"frame"):
    return _Lease(
        sock=_FakeServerSocket(conn),
        thread=None,
        closed=threading.Event(),
        info=_info(),
        frame=frame,
        lock=threading.Lock(),
    )


def test_serve_permission_denied_send_error(monkeypatch):
    from resource_lease.backends import abstract_socket as mod

    b = AbstractSocketLeaseBackend(_ns())
    conn = _FakeConn(send_error=True)
    monkeypatch.setattr(mod, "_peer_uid", lambda c: os.getuid() + 1)
    b._serve(_fake_lease(conn))


def test_serve_recv_error_and_close_error(monkeypatch):
    from resource_lease.backends import abstract_socket as mod

    b = AbstractSocketLeaseBackend(_ns())
    conn = _FakeConn(recv_error=True, close_error=True)
    monkeypatch.setattr(mod, "_peer_uid", lambda c: os.getuid())
    b._serve(_fake_lease(conn))


def test_serve_get_send_error(monkeypatch):
    from resource_lease.backends import abstract_socket as mod

    b = AbstractSocketLeaseBackend(_ns())
    conn = _FakeConn(send_error=True)
    monkeypatch.setattr(mod, "_peer_uid", lambda c: os.getuid())
    b._serve(_fake_lease(conn))


def test_serve_unknown_request_success_and_send_error(monkeypatch):
    from resource_lease.backends import abstract_socket as mod

    b = AbstractSocketLeaseBackend(_ns())
    monkeypatch.setattr(mod, "_peer_uid", lambda c: os.getuid())

    ok = _FakeConn(recv_value=b"BAD\n")
    b._serve(_fake_lease(ok))
    assert ok.sent == [b'{"error":"unknown_request"}\n']

    bad = _FakeConn(recv_value=b"BAD\n", send_error=True)
    b._serve(_fake_lease(bad))


def test_connect_and_get_send_recv_empty_timeout_and_close_errors(monkeypatch):
    from resource_lease.backends import abstract_socket as mod

    class FakeClient:
        def __init__(self, *, send_error=False, recv_values=None,
                     recv_timeout=False, close_error=False):
            self.send_error = send_error
            self.recv_values = list(recv_values or [])
            self.recv_timeout = recv_timeout
            self.close_error = close_error

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, addr):
            pass

        def sendall(self, data):
            if self.send_error:
                raise OSError("send")

        def recv(self, n):
            if self.recv_timeout:
                raise socket.timeout("timeout")
            if self.recv_values:
                value = self.recv_values.pop(0)
                if isinstance(value, BaseException):
                    raise value
                return value
            return b""

        def close(self):
            if self.close_error:
                raise OSError("close")

    def run(fake):
        monkeypatch.setattr(mod.socket, "socket", lambda *args, **kwargs: fake)
        return _connect_and_get(b"\0addr", 0.01)

    assert run(FakeClient(send_error=True)) is None
    assert run(FakeClient(recv_timeout=True)) is None
    assert run(FakeClient(recv_values=[OSError("recv")])) is None
    assert run(FakeClient(recv_values=[], close_error=True)) is None


def test_scan_proc_net_unix_parser_edges(monkeypatch):
    import builtins
    from io import StringIO

    data = "\n".join([
        "Num RefCount Protocol Flags Type St Inode Path",
        "too short",
        "0: 0 0 0 0 0 1 /tmp/socket",
        "0: 0 0 0 0 0 1 @resource_lease.v1.ns.1.abc",
        "0: 0 0 0 0 0 1 @other",
    ])
    monkeypatch.setattr(builtins, "open", lambda *args, **kwargs: StringIO(data))
    assert _scan_proc_net_unix_with_prefix("@resource_lease.v1.ns.") == [
        "@resource_lease.v1.ns.1.abc"
    ]

    def missing(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(builtins, "open", missing)
    assert _scan_proc_net_unix_with_prefix("@anything") == []


def test_list_namespaces_ignores_malformed_and_other_uid(monkeypatch):
    from resource_lease.backends import abstract_socket as mod

    b = AbstractSocketLeaseBackend(_ns())
    monkeypatch.setattr(mod, "_scan_proc_net_unix_with_prefix", lambda prefix: [
        "@resource_lease.v1.malformed",
        f"@resource_lease.v1.other.{os.getuid() + 1}.abc",
        f"@resource_lease.v1.good.ns.{os.getuid()}.abc",
    ])
    assert b.list_namespaces() == ["good.ns"]
