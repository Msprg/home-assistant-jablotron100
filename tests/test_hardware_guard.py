"""The suite-wide guard in conftest.py keeps every test off the panel hardware.

Added after the 2026-10-03 false alarm: a test that reached /dev/hidraw0 made
one wrong-code login per suite run. These checks fail loudly if the guard is
ever removed or bypassed.
"""

from __future__ import annotations

import io
import os
from pathlib import Path

import pytest

DEVICES = ["/dev/hidraw0", "/dev/hidraw9", "/dev/sdb1", "/dev/sdc", "/dev/bus/usb/009/009", "/dev/serial/by-id/x"]


@pytest.mark.parametrize("device", DEVICES)
def test_os_open_of_a_panel_device_is_refused(device: str) -> None:
    with pytest.raises(PermissionError, match="panel device"):
        os.open(device, os.O_RDONLY)


@pytest.mark.parametrize("device", DEVICES)
def test_builtin_open_of_a_panel_device_is_refused(device: str) -> None:
    with pytest.raises(PermissionError, match="panel device"):
        open(device, "rb")
    with pytest.raises(PermissionError, match="panel device"):
        io.open(device, "rb")
    with pytest.raises(PermissionError, match="panel device"):
        Path(device).open("rb")


def test_the_usb_client_cannot_be_constructed_on_the_real_device() -> None:
    from jablotron_usb_debug import JablotronUSBClient

    with pytest.raises(PermissionError, match="panel device"):
        JablotronUSBClient("/dev/hidraw0")


def test_ordinary_files_still_open(tmp_path: Path) -> None:
    target = tmp_path / "ok.txt"
    target.write_text("fine")
    assert target.read_text() == "fine"
    fd = os.open(str(target), os.O_RDONLY)
    os.close(fd)
