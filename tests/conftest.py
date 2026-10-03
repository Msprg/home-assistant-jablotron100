from __future__ import annotations

import builtins
import io
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
HASS_SUBMODULE = ROOT / "jablotron100-api-HASS"

for path in (HASS_SUBMODULE, ROOT, SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


# Keep the test suite off the real panel.
#
# On 2026-10-03 one test reached the live JA-107K through an unpatched cleanup
# path and logged in with a placeholder code on every suite run; about ninety
# runs in three hours tripped the panel's wrong-code tamper alarm. No test may
# open the panel's HID device or its block devices, through os.open or the
# builtin open. Any attempt fails the test with a clear message instead of
# touching hardware. JABLOTRON_ALLOW_HARDWARE_TESTS=1 lifts the guard only for
# a test that is meant to talk to the panel, on purpose, with the owner watching.

_REAL_OS_OPEN = os.open
_REAL_IO_OPEN = io.open
_BLOCKED_PREFIXES = ("/dev/hidraw", "/dev/sd", "/dev/bus/usb", "/dev/serial", "/dev/ttyUSB", "/dev/ttyACM")


def _is_panel_device(path: object) -> bool:
    if isinstance(path, int):
        return False
    try:
        text = os.fspath(path)
    except TypeError:
        return False
    if isinstance(text, bytes):
        text = text.decode(errors="replace")
    return text.startswith(_BLOCKED_PREFIXES)


def _refuse(path: object) -> None:
    if _is_panel_device(path) and os.environ.get("JABLOTRON_ALLOW_HARDWARE_TESTS") != "1":
        raise PermissionError(
            f"test tried to open the panel device {os.fspath(path)!r}; tests must patch the USB client "
            "and the block reader (JABLOTRON_ALLOW_HARDWARE_TESTS=1 only for a deliberate live test)"
        )


def _guarded_os_open(path, flags, *args, **kwargs):
    _refuse(path)
    return _REAL_OS_OPEN(path, flags, *args, **kwargs)


def _guarded_io_open(file, *args, **kwargs):
    _refuse(file)
    return _REAL_IO_OPEN(file, *args, **kwargs)


@pytest.fixture(autouse=True)
def _no_panel_hardware(monkeypatch):
    monkeypatch.setattr(os, "open", _guarded_os_open)
    monkeypatch.setattr(io, "open", _guarded_io_open)
    monkeypatch.setattr(builtins, "open", _guarded_io_open)
    yield
