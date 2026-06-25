"""The low-level USB client raises a catchable JablotronUSBStreamError (not the
uncatchable SystemExit) on read/write I/O failure, and one-shot CLI tools convert
it back to a clean SystemExit at their entrypoints.

Part of the upstream cd2432d + b7fa29e auto-recovery port.
"""

from __future__ import annotations

import errno
import importlib
import types

import pytest

import jablotron_usb_debug as ud
from jablotron_usb_debug import JablotronUSBClient, JablotronUSBStreamError


def test_stream_error_is_catchable_exception_not_systemexit() -> None:
    assert issubclass(JablotronUSBStreamError, Exception)
    assert issubclass(JablotronUSBStreamError, OSError)
    assert not issubclass(JablotronUSBStreamError, SystemExit)


def test_read_packets_raises_stream_error_on_io_failure(monkeypatch) -> None:
    monkeypatch.setattr(ud.os, "open", lambda *a, **k: 4242)
    monkeypatch.setattr(ud.os, "close", lambda fd: None)
    monkeypatch.setattr(ud.select, "select", lambda r, w, x, t: (list(r), [], []))

    def boom(fd, size):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(ud.os, "read", boom)

    client = JablotronUSBClient("/dev/hidraw9")
    with pytest.raises(JablotronUSBStreamError) as excinfo:
        list(client.read_packets(timeout=0.05))
    # The error names the offending port and is a normal Exception, so the
    # server's `except Exception` recovery can catch it.
    assert "/dev/hidraw9" in str(excinfo.value)
    assert isinstance(excinfo.value, Exception)


def test_write_raises_stream_error_on_io_failure(monkeypatch) -> None:
    monkeypatch.setattr(ud.os, "open", lambda *a, **k: 4242)
    monkeypatch.setattr(ud.os, "close", lambda fd: None)
    monkeypatch.setattr(ud.time, "sleep", lambda _: None)

    def boom(fd, payload):
        raise OSError(errno.ENODEV, "No such device")

    monkeypatch.setattr(ud.os, "write", boom)

    client = JablotronUSBClient("/dev/hidraw9")
    with pytest.raises(JablotronUSBStreamError):
        client.send_packet(b"\x52\x01\x02")


@pytest.mark.parametrize("module_name", ["jablotron_noauth_probe", "dev_test", "jablotron_event_tool"])
def test_cli_main_converts_stream_error_to_systemexit(monkeypatch, module_name) -> None:
    module = importlib.import_module(module_name)

    def boom(_args):
        raise module.JablotronUSBStreamError("USB read failed on /dev/hidraw0: [Errno 5]")

    args = types.SimpleNamespace(func=boom)
    monkeypatch.setattr(
        module, "build_parser", lambda: types.SimpleNamespace(parse_args=lambda: args)
    )
    with pytest.raises(SystemExit) as excinfo:
        module.main()
    assert "/dev/hidraw0" in str(excinfo.value)
