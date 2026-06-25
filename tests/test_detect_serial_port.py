"""detect_serial_port returns None (clean ensure_serial_port SystemExit) instead
of tracebacking when /sys/class/hidraw is absent.

Port of upstream 342521c part 2 (the shared low-level robustness half; the
integration-only SerialPortNotDetected/config_flow/translations were skipped).
"""

from __future__ import annotations

import errno

import pytest

import jablotron_usb_debug as ud
from jablotron_usb_debug import ensure_serial_port


def test_detect_serial_port_returns_none_when_hidraw_missing(monkeypatch) -> None:
    import custom_components.jablotron100.jablotron as jmod

    def boom(path):
        raise FileNotFoundError(errno.ENOENT, "No such file or directory", path)

    monkeypatch.setattr(jmod.os, "listdir", boom)
    assert jmod.Jablotron.detect_serial_port() is None


def test_ensure_serial_port_clean_exit_when_no_device(monkeypatch) -> None:
    # With detection returning None, ensure_serial_port must surface the clear
    # SystemExit rather than letting a raw OSError traceback escape.
    monkeypatch.setattr(ud.Jablotron, "detect_serial_port", staticmethod(lambda: None))
    with pytest.raises(SystemExit) as excinfo:
        ensure_serial_port("auto")
    assert "auto-detect" in str(excinfo.value)
