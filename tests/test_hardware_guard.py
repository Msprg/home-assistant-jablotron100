"""The suite-wide guard in conftest.py keeps every test off the panel hardware.

Added after the 2026-10-03 false alarm: a test that reached /dev/hidraw0 made
one wrong-code login per suite run. The guard refuses opening the panel's HID
or block devices (os.open, the builtin open, io.open, Path.open) and starting
a subprocess whose command line names one (dd if=/of=, mount, umount, with or
without sudo in front), which is how jablotron_re_tools reads EXPORT.CFG and
stages IMPORT.CFG. Paths are resolved first, so a udev symlink is caught by
its target. A refusal is also recorded and fails the test afterwards even if
the code under test swallowed the PermissionError, as the session's reopen
backoff does. These checks fail loudly if the guard is ever removed,
bypassed or made swallowable.

Tests here provoke refusals on purpose, so each one takes panel_refusals,
checks what was refused and clears it for the after-test check.
"""

from __future__ import annotations

import io
import os
import subprocess
import textwrap
from pathlib import Path

import pytest

import jablotron_re_tools as tools

DEVICES = ["/dev/hidraw0", "/dev/hidraw9", "/dev/sdb1", "/dev/sdc", "/dev/bus/usb/009/009", "/dev/serial/by-id/x"]
CONFTEST = Path(__file__).with_name("conftest.py")


@pytest.mark.parametrize("device", DEVICES)
def test_os_open_of_a_panel_device_is_refused(device: str, panel_refusals: list[str]) -> None:
    with pytest.raises(PermissionError, match="panel device"):
        os.open(device, os.O_RDONLY)
    assert panel_refusals == [device]
    panel_refusals.clear()


@pytest.mark.parametrize("device", DEVICES)
def test_builtin_open_of_a_panel_device_is_refused(device: str, panel_refusals: list[str]) -> None:
    with pytest.raises(PermissionError, match="panel device"):
        open(device, "rb")
    with pytest.raises(PermissionError, match="panel device"):
        io.open(device, "rb")
    with pytest.raises(PermissionError, match="panel device"):
        Path(device).open("rb")
    assert panel_refusals == [device, device, device]
    panel_refusals.clear()


def test_a_symlink_to_a_panel_device_is_refused(tmp_path: Path, panel_refusals: list[str]) -> None:
    """A udev rule can give the panel a name like /dev/jablotron; the guard
    compares the resolved path."""

    link = tmp_path / "jablotron"
    link.symlink_to("/dev/hidraw9")
    with pytest.raises(PermissionError, match="panel device"):
        open(link, "rb")
    with pytest.raises(PermissionError, match="panel device"):
        subprocess.run(["dd", f"if={link}", "of=/dev/null"], check=False)
    assert len(panel_refusals) == 2
    panel_refusals.clear()


def test_the_usb_client_cannot_be_constructed_on_the_real_device(panel_refusals: list[str]) -> None:
    from jablotron_usb_debug import JablotronUSBClient

    with pytest.raises(PermissionError, match="panel device"):
        JablotronUSBClient("/dev/hidraw0")
    assert panel_refusals == ["/dev/hidraw0"]
    panel_refusals.clear()


def test_the_direct_block_read_is_refused(panel_refusals: list[str]) -> None:
    """read_device_direct_bytes reads with dd (behind sudo -n when not root),
    not with open, so the subprocess guard has to stop it."""

    with pytest.raises(PermissionError, match="panel device"):
        tools.read_device_direct_bytes(device="/dev/sdb1", start_lba=0, sectors=1)
    assert len(panel_refusals) == 1
    assert os.path.realpath(panel_refusals[0]).startswith("/dev/sd")
    panel_refusals.clear()


def test_dd_on_a_panel_device_is_refused(panel_refusals: list[str]) -> None:
    with pytest.raises(PermissionError, match="panel device"):
        subprocess.run(["dd", "if=/dev/sdb1", "of=/tmp/never-written.bin", "bs=512", "count=1"], check=False)
    with pytest.raises(PermissionError, match="panel device"):
        subprocess.run(["sudo", "-n", "dd", "if=/tmp/never-read.bin", "of=/dev/sdb1"], check=False)
    assert panel_refusals == ["/dev/sdb1", "/dev/sdb1"]
    panel_refusals.clear()


def test_mounting_a_panel_device_is_refused(panel_refusals: list[str]) -> None:
    with pytest.raises(PermissionError, match="panel device"):
        subprocess.run(["sudo", "-n", "mount", "/dev/sdb1", "/mnt/x"], check=False)
    with pytest.raises(PermissionError, match="panel device"):
        subprocess.run(["umount", "/dev/sdb1"], check=False)
    with pytest.raises(PermissionError, match="panel device"):
        subprocess.run("sudo -n mount.vfat /dev/sdc1 /mnt/x", shell=True, check=False)
    assert panel_refusals == ["/dev/sdb1", "/dev/sdb1", "/dev/sdc1"]
    panel_refusals.clear()


def test_ordinary_subprocesses_still_run() -> None:
    assert subprocess.run(["true"], check=False).returncode == 0
    result = subprocess.run(["echo", "of=/tmp/fine"], check=True, capture_output=True, text=True)
    assert result.stdout.strip() == "of=/tmp/fine"


def test_ordinary_files_still_open(tmp_path: Path) -> None:
    target = tmp_path / "ok.txt"
    target.write_text("fine")
    assert target.read_text() == "fine"
    fd = os.open(str(target), os.O_RDONLY)
    os.close(fd)


def test_a_swallowed_refusal_still_fails_the_test(pytester: pytest.Pytester, monkeypatch) -> None:
    """Session code catches OSError and turns the refusal into a reopen
    backoff. The guard must fail the test anyway: in an inner run with this
    conftest, a test that swallows the PermissionError errors in the guard's
    after-test check, and a clean test next to it still passes. The inner
    paths do not exist on any host, and the guard refuses them before any
    open or dd would run."""

    monkeypatch.delenv("JABLOTRON_ALLOW_HARDWARE_TESTS", raising=False)
    pytester.makeconftest(CONFTEST.read_text())
    pytester.makepyfile(
        test_inner=textwrap.dedent(
            """
            import subprocess

            def test_swallows_a_refused_open():
                try:
                    open("/dev/hidraw99", "rb")
                except OSError:
                    pass

            def test_swallows_a_refused_block_read():
                try:
                    subprocess.run(["dd", "if=/dev/sdz9", "of=/dev/null"], check=False)
                except OSError:
                    pass

            def test_clean():
                assert True
            """
        )
    )

    result = pytester.runpytest_subprocess("-p", "no:cacheprovider")

    # A teardown error is reported on top of the test's own pass.
    result.assert_outcomes(passed=3, errors=2)
    result.stdout.fnmatch_lines(["*hardware guard refused panel device access during this test*/dev/hidraw99*"])
    result.stdout.fnmatch_lines(["*hardware guard refused panel device access during this test*/dev/sdz9*"])
