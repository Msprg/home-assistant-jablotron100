"""The long-running PersistentSnapshotSession reconnects after a USB stream
failure, re-detects a renumbered /dev/hidrawN port, and backs off after a failed
(re)open without hot-looping or holding its I/O lock to sleep.

Part of the upstream cd2432d + b7fa29e auto-recovery port. These tests drive
_ensure_client_locked directly (with the post-open drain stubbed out) so a frozen
clock cannot spin a timeout loop; they exercise the reopen/backoff/redetect logic,
not packet draining.
"""

from __future__ import annotations

import errno

import pytest

from jablotron_api.protocol import legacy
from jablotron_api.protocol.legacy import PersistentSnapshotSession
from jablotron_usb_debug import JablotronUSBStreamError


def _patch_session_protocol_fakes(monkeypatch, client_factory) -> None:
    monkeypatch.setattr(legacy, "JablotronUSBClient", client_factory)
    monkeypatch.setattr(legacy, "perform_login", lambda c, code, *, reset: None)
    monkeypatch.setattr(legacy, "perform_enable_device_states", lambda c: None)
    monkeypatch.setattr(legacy, "perform_sections_query", lambda c: None)
    monkeypatch.setattr(legacy.time, "sleep", lambda _: None)


class _OkClient:
    def __init__(self, serial_port: str) -> None:
        self.serial_port = serial_port

    def send_packet(self, packet: bytes) -> None:
        return None

    def send_packets(self, packets) -> None:
        return None

    def read_packets(self, *, timeout=None):
        return iter(())

    def close(self) -> None:
        return None


def test_reopen_backoff_gate_then_recovers(monkeypatch) -> None:
    creations = {"n": 0}

    class FlakyClient(_OkClient):
        def __init__(self, serial_port: str) -> None:
            creations["n"] += 1
            if creations["n"] == 1:
                # First open fails: device path absent.
                raise OSError(errno.ENOENT, "No such device", serial_port)
            super().__init__(serial_port)

    clock = {"t": 1000.0}
    monkeypatch.setattr(legacy.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    # Stub the post-open drain so a frozen clock cannot spin its timeout loop;
    # this test exercises the (re)open + backoff logic, not packet draining.
    monkeypatch.setattr(legacy.PersistentSnapshotSession, "_drain_packets_locked", lambda self, *a, **k: None)
    _patch_session_protocol_fakes(monkeypatch, FlakyClient)

    session = PersistentSnapshotSession(port="auto", code="1812", reset=True)
    try:
        with session._io_lock:
            # Attempt 1: ctor OSError -> backoff armed, surfaced as a catchable error.
            with pytest.raises(JablotronUSBStreamError):
                session._ensure_client_locked()
            assert creations["n"] == 1
            assert session._reopen_failures == 1

            # Attempt 2 within the backoff window: the gate refuses WITHOUT trying
            # to construct a client (no hot-loop / no extra login attempt).
            with pytest.raises(JablotronUSBStreamError):
                session._ensure_client_locked()
            assert creations["n"] == 1

            # After the deadline passes, the next attempt reopens and resets backoff.
            clock["t"] += legacy.STREAM_REOPEN_MAX_DELAY_SECONDS + 1.0
            session._ensure_client_locked()
            assert creations["n"] == 2
            assert session._reopen_failures == 0
            assert session._next_reopen_allowed_at == 0.0
    finally:
        session.close()


def test_close_client_does_not_reset_backoff(monkeypatch) -> None:
    class AlwaysFailClient(_OkClient):
        def __init__(self, serial_port: str) -> None:
            raise OSError(errno.ENOENT, "gone", serial_port)

    clock = {"t": 5000.0}
    monkeypatch.setattr(legacy.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    _patch_session_protocol_fakes(monkeypatch, AlwaysFailClient)

    session = PersistentSnapshotSession(port="auto", code="1812", reset=True)
    try:
        with session._io_lock:
            with pytest.raises(JablotronUSBStreamError):
                session._ensure_client_locked()
            assert session._reopen_failures == 1
            armed_deadline = session._next_reopen_allowed_at
            # The reconnect failure path calls _close_client_locked(); it must
            # NOT clear the backoff streak, or the gate would be defeated.
            session._close_client_locked()
            assert session._reopen_failures == 1
            assert session._next_reopen_allowed_at == armed_deadline
    finally:
        session.close()


def test_redetect_follows_renumbered_port_on_reconnect(monkeypatch) -> None:
    creations: list[str] = []

    class FlakyClient(_OkClient):
        def __init__(self, serial_port: str) -> None:
            creations.append(serial_port)
            if len(creations) == 1:
                raise OSError(errno.ENOENT, "gone", serial_port)
            super().__init__(serial_port)

    resolve_state = {"n": 0}

    def fake_ensure(port):
        resolve_state["n"] += 1
        return "/dev/hidraw0" if resolve_state["n"] == 1 else "/dev/hidraw5"

    clock = {"t": 500.0}
    monkeypatch.setattr(legacy.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(legacy, "ensure_serial_port", fake_ensure)
    monkeypatch.setattr(legacy.PersistentSnapshotSession, "_drain_packets_locked", lambda self, *a, **k: None)
    _patch_session_protocol_fakes(monkeypatch, FlakyClient)

    session = PersistentSnapshotSession(port="auto", code="1812", reset=True)
    assert session._serial_port == "/dev/hidraw0"
    try:
        with session._io_lock:
            with pytest.raises(JablotronUSBStreamError):
                session._ensure_client_locked()
            clock["t"] += 100.0  # past the backoff deadline
            session._ensure_client_locked()
            assert session._serial_port == "/dev/hidraw5"
            assert creations == ["/dev/hidraw0", "/dev/hidraw5"]
    finally:
        session.close()


@pytest.mark.parametrize("redetect_error", [SystemExit("no device"), OSError(errno.ENOENT, "no hidraw")])
def test_redetect_never_raises_when_no_device(monkeypatch, redetect_error) -> None:
    state = {"n": 0}

    def fake_ensure(port):
        state["n"] += 1
        if state["n"] == 1:
            return "/dev/hidraw0"  # initial construction must succeed
        raise redetect_error

    monkeypatch.setattr(legacy, "ensure_serial_port", fake_ensure)
    _patch_session_protocol_fakes(monkeypatch, _OkClient)

    session = PersistentSnapshotSession(port="auto", code="1812", reset=True)
    try:
        with session._io_lock:
            # Must not raise even though ensure_serial_port blows up.
            session._redetect_serial_port_locked()
        assert session._serial_port == "/dev/hidraw0"  # unchanged
    finally:
        session.close()


def test_stream_loop_iteration_survives_send_failure_and_redetect_no_device(monkeypatch) -> None:
    # The keepalive/stream daemon thread must not die if a write fails AND port
    # redetection finds no device (ensure_serial_port raises SystemExit).
    state = {"n": 0}

    def fake_ensure(port):
        state["n"] += 1
        if state["n"] == 1:
            return "/dev/hidraw0"
        raise SystemExit("Unable to auto-detect Jablotron USB interface.")

    class FailingSendClient(_OkClient):
        def send_packet(self, packet: bytes) -> None:
            raise JablotronUSBStreamError("USB write failed on /dev/hidraw0")

    monkeypatch.setattr(legacy, "ensure_serial_port", fake_ensure)
    _patch_session_protocol_fakes(monkeypatch, FailingSendClient)

    session = PersistentSnapshotSession(port="auto", code="1812", reset=True)
    try:
        session._client = FailingSendClient("/dev/hidraw0")
        # Run exactly one keepalive loop body, then stop.
        waits = {"n": 0}

        def fake_wait(timeout):
            waits["n"] += 1
            return waits["n"] > 1  # False once (run body), then True (exit)

        monkeypatch.setattr(session._stop_event, "wait", fake_wait)
        # Should return normally; no exception escapes the loop body.
        session._stream_loop()
        assert session._client is None  # failed client was dropped
    finally:
        session.close()
