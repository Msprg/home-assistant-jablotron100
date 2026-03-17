import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jablotron_re_tools as tools


def _fake_mount_command(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 0, "", "")


def test_mount_device_allows_log_volume_without_expected_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mountpoint = tmp_path / "flexi_log"

    monkeypatch.setattr(tools, "run_command", _fake_mount_command)
    monkeypatch.setattr(tools, "is_device_mounted", lambda _device: False)
    monkeypatch.setattr(tools, "get_device_mountpoint", lambda _device: mountpoint)
    monkeypatch.setattr(tools.time, "sleep", lambda _seconds: None)

    tools.mount_device("/dev/fake-log", mountpoint, mount_tool="sudo")


def test_mount_device_accepts_expected_path_when_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mountpoint = tmp_path / "flexi_cfg"
    expected_path = mountpoint / "IMPORT.CFG"
    mountpoint.mkdir(parents=True, exist_ok=True)
    expected_path.write_bytes(b"")

    monkeypatch.setattr(tools, "run_command", _fake_mount_command)
    monkeypatch.setattr(tools, "is_device_mounted", lambda _device: False)
    monkeypatch.setattr(tools, "get_device_mountpoint", lambda _device: mountpoint)
    monkeypatch.setattr(tools.time, "sleep", lambda _seconds: None)

    tools.mount_device("/dev/fake-cfg", mountpoint, mount_tool="sudo", expected_path=expected_path)


def test_mount_device_rejects_missing_expected_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mountpoint = tmp_path / "flexi_cfg"
    expected_path = mountpoint / "IMPORT.CFG"

    monkeypatch.setattr(tools, "run_command", _fake_mount_command)
    monkeypatch.setattr(tools, "is_device_mounted", lambda _device: False)
    monkeypatch.setattr(tools, "get_device_mountpoint", lambda _device: mountpoint)
    monkeypatch.setattr(tools.time, "sleep", lambda _seconds: None)

    with pytest.raises(SystemExit, match="expected_path_exists=False"):
        tools.mount_device("/dev/fake-cfg", mountpoint, mount_tool="sudo", expected_path=expected_path)
