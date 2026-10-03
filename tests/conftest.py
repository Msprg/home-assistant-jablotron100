from __future__ import annotations

import builtins
import io
import os
import shlex
import subprocess
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
# reach the panel's HID device or its block devices:
#
# - opening one through os.open or the builtin open is refused;
# - starting a subprocess whose command line names one (dd's if=/of= forms,
#   mount, umount, mount.vfat, sudo in front of any of them) is refused. The
#   block reads and IMPORT.CFG staging in jablotron_re_tools go through
#   subprocess, not open, so the open guard alone would miss them.
#
# Paths are compared after os.path.realpath, so a udev symlink such as
# /dev/jablotron or /dev/disk/by-label/FLEXI_CFG is caught by its target.
#
# Session code catches OSError and turns a refusal into a reopen backoff, so
# a refusal alone could pass unnoticed. Every refused path is therefore also
# recorded, and the fixture fails the test after it ran if anything was
# recorded, whether or not the test saw the PermissionError. A test that
# provokes a refusal on purpose takes the panel_refusals fixture, checks what
# was refused and clears the list.
#
# JABLOTRON_ALLOW_HARDWARE_TESTS=1 lifts the guard only for a test that is
# meant to talk to the panel, on purpose, with the owner watching.

pytest_plugins = ["pytester"]

_REAL_OS_OPEN = os.open
_REAL_IO_OPEN = io.open
_REAL_POPEN = subprocess.Popen
_BLOCKED_PREFIXES = ("/dev/hidraw", "/dev/sd", "/dev/bus/usb", "/dev/serial", "/dev/ttyUSB", "/dev/ttyACM")
_REFUSED: list[str] = []


def _as_text(path: object) -> str | None:
    if isinstance(path, int):
        return None
    try:
        text = os.fspath(path)
    except TypeError:
        return None
    if isinstance(text, bytes):
        text = text.decode(errors="replace")
    return text


def _is_panel_device(path: object) -> bool:
    text = _as_text(path)
    if not text:
        return False
    if text.startswith(_BLOCKED_PREFIXES):
        return True
    try:
        # A path that does not exist resolves to itself, which is fine.
        resolved = os.path.realpath(text)
    except (OSError, ValueError):
        return False
    return resolved.startswith(_BLOCKED_PREFIXES)


def _guard_enabled() -> bool:
    return os.environ.get("JABLOTRON_ALLOW_HARDWARE_TESTS") != "1"


def _refuse(path: object) -> None:
    if _is_panel_device(path) and _guard_enabled():
        _REFUSED.append(_as_text(path) or repr(path))
        raise PermissionError(
            f"test tried to open the panel device {_as_text(path)!r}; tests must patch the USB client "
            "and the block reader (JABLOTRON_ALLOW_HARDWARE_TESTS=1 only for a deliberate live test)"
        )


def _argv_elements(args: object) -> list[str]:
    if isinstance(args, (str, bytes)):
        text = args.decode(errors="replace") if isinstance(args, bytes) else args
        try:
            return shlex.split(text)
        except ValueError:
            return text.split()
    if isinstance(args, os.PathLike):
        return [_as_text(args) or ""]
    try:
        return [_as_text(item) or "" for item in args]  # type: ignore[union-attr]
    except TypeError:
        return []


def _blocked_argv_path(args: object) -> str | None:
    """The first panel device a command line names, or None.

    Every element is checked as a path, and so is the value of every
    key=value element (dd's if= and of=, mount's -o source=...)."""

    for element in _argv_elements(args):
        candidates = [element]
        if "=" in element:
            candidates.append(element.split("=", 1)[1])
        for candidate in candidates:
            if _is_panel_device(candidate):
                return candidate
    return None


class _GuardedPopen(_REAL_POPEN):
    """subprocess.Popen that refuses a command naming a panel device.
    subprocess.run, check_call and check_output all go through it."""

    def __init__(self, args, *pargs, **kwargs):
        blocked = _blocked_argv_path(args)
        if blocked is not None and _guard_enabled():
            _REFUSED.append(blocked)
            raise PermissionError(
                f"test tried to run a command on the panel device {blocked!r}: {_argv_elements(args)!r}; "
                "tests must patch the block reader and the mount helpers "
                "(JABLOTRON_ALLOW_HARDWARE_TESTS=1 only for a deliberate live test)"
            )
        super().__init__(args, *pargs, **kwargs)


def _guarded_os_open(path, flags, *args, **kwargs):
    _refuse(path)
    return _REAL_OS_OPEN(path, flags, *args, **kwargs)


def _guarded_io_open(file, *args, **kwargs):
    _refuse(file)
    return _REAL_IO_OPEN(file, *args, **kwargs)


@pytest.fixture(autouse=True)
def _no_panel_hardware(monkeypatch):
    _REFUSED.clear()
    monkeypatch.setattr(os, "open", _guarded_os_open)
    monkeypatch.setattr(io, "open", _guarded_io_open)
    monkeypatch.setattr(builtins, "open", _guarded_io_open)
    monkeypatch.setattr(subprocess, "Popen", _GuardedPopen)
    yield _REFUSED
    refused = list(_REFUSED)
    _REFUSED.clear()
    assert not refused, (
        f"the hardware guard refused panel device access during this test: {refused!r}. "
        "A refusal fails the test even when the code under test caught the PermissionError; "
        "patch the USB client, the block reader and the mount helpers instead "
        "(a test that provokes a refusal on purpose takes panel_refusals and clears it)."
    )


@pytest.fixture
def panel_refusals(_no_panel_hardware) -> list[str]:
    """The paths the hardware guard refused so far in this test. A test that
    provokes a refusal on purpose asserts on this list and clears it, so the
    guard's after-test check passes."""

    return _no_panel_hardware
