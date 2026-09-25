"""apply_import_sector in stage_mode="direct" must never mount.

The deployed container has no CAP_SYS_ADMIN, so mount(2) fails there; the
default "filesystem" stage mode mounts FLEXI_CFG to drop IMPORT.CFG into
place, while "direct" writes the encoded sector at its LBA and reads it
back. Everything here is offline: the HID session and the block device are
replaced, and the assertions are about which helpers were called in which
order.
"""

from __future__ import annotations

import errno
import subprocess
from pathlib import Path

import pytest

import jablotron_re_tools as tools


def _stub_session(monkeypatch: pytest.MonkeyPatch, calls: list, *, mounted: bool = False) -> None:
    class FakeClient:
        def __init__(self, port: str) -> None:
            calls.append(("client", port))

        def close(self) -> None:
            calls.append(("close",))

    monkeypatch.setattr(tools, "resolve_flexi_cfg_device", lambda device: device)
    monkeypatch.setattr(tools, "is_device_mounted", lambda device: mounted)
    monkeypatch.setattr(tools, "mount_device", lambda *a, **k: calls.append(("mount_device",)))
    monkeypatch.setattr(tools, "unmount_device", lambda *a, **k: calls.append(("unmount_device",)))
    monkeypatch.setattr(tools, "ensure_serial_port", lambda port: port)
    monkeypatch.setattr(tools, "JablotronUSBClient", FakeClient)
    monkeypatch.setattr(tools, "perform_login", lambda client, code, reset: calls.append(("login",)))
    monkeypatch.setattr(tools.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(tools, "drain_packets", lambda client, **k: [])
    monkeypatch.setattr(
        tools, "enter_setup_mode", lambda client, **k: calls.append(("enter_setup_mode",))
    )
    monkeypatch.setattr(
        tools,
        "stage_import_direct",
        lambda **k: calls.append(("stage_import_direct", k["device"], k["sector_path"])),
    )
    monkeypatch.setattr(tools, "stage_import", lambda *a: calls.append(("stage_import",)))
    monkeypatch.setattr(
        tools,
        "verify_import_sector_direct",
        lambda **k: calls.append(("verify_direct", k["device"], k["expected_sector"])),
    )
    monkeypatch.setattr(
        tools,
        "ensure_import_path_available",
        lambda **k: calls.append(("ensure_import_path_available",)),
    )
    monkeypatch.setattr(
        tools, "perform_import_accept_sequence", lambda client, **k: calls.append(("accept",))
    )
    monkeypatch.setattr(tools, "graceful_exit_session", lambda client, **k: [])
    monkeypatch.setattr(
        tools,
        "cleanup_read_session",
        lambda **k: calls.append(("cleanup",)) or tools.EXITED_SECTIONS_MODE,
    )


def _apply(tmp_path: Path, *, stage_mode: str):
    sector = tmp_path / "sector.bin"
    sector.write_bytes(b"\x00" * tools.SECTOR_SIZE)
    return sector, tools.apply_import_sector(
        sector_path=sector,
        import_path=tmp_path / "flexi_cfg" / "IMPORT.CFG",
        device="/dev/sdb1",
        port="auto",
        code="1812",
        reset=True,
        mount_tool="sudo",
        stage_mode=stage_mode,
        write_cleanup_mode="auto",
        verbose=False,
        verify_output=None,
    )


def test_direct_stage_mode_never_mounts(monkeypatch, tmp_path: Path) -> None:
    calls: list = []
    _stub_session(monkeypatch, calls)

    sector, result = _apply(tmp_path, stage_mode="direct")

    assert result is None
    names = [call[0] for call in calls]
    assert "mount_device" not in names
    assert "unmount_device" not in names
    assert "stage_import" not in names
    assert "ensure_import_path_available" not in names
    assert ("stage_import_direct", "/dev/sdb1", sector) in calls
    # The sector is staged inside the configuration session, before the
    # panel is asked to accept the import.
    assert names.index("enter_setup_mode") < names.index("stage_import_direct") < names.index("accept")
    assert names[-1] == "cleanup", "no exit mode was observed, so the session is cleaned up"


def test_filesystem_stage_mode_mounts_which_the_container_cannot(monkeypatch, tmp_path: Path) -> None:
    """The contrast: the default stage mode needs mount(2)."""

    calls: list = []
    _stub_session(monkeypatch, calls)

    _apply(tmp_path, stage_mode="filesystem")

    names = [call[0] for call in calls]
    assert "mount_device" in names
    assert "stage_import" in names
    assert "stage_import_direct" not in names


def test_filesystem_stage_mode_verifies_the_sector_directly_before_accepting(
    monkeypatch, tmp_path: Path
) -> None:
    """After unmount the staged sector is read back with O_DIRECT, so a write
    the panel refused (which the page cache would have hidden) is caught
    before the accept sequence runs."""

    calls: list = []
    _stub_session(monkeypatch, calls)

    sector, _ = _apply(tmp_path, stage_mode="filesystem")

    names = [call[0] for call in calls]
    assert ("verify_direct", "/dev/sdb1", sector.read_bytes()) in calls
    assert (
        names.index("stage_import")
        < names.index("unmount_device")
        < names.index("verify_direct")
        < names.index("accept")
    )


def test_filesystem_stage_mode_does_not_accept_when_the_sector_did_not_land(
    monkeypatch, tmp_path: Path
) -> None:
    calls: list = []
    _stub_session(monkeypatch, calls)

    def refused(**kwargs):
        calls.append(("verify_direct",))
        raise SystemExit("Direct IMPORT.CFG verification failed")

    monkeypatch.setattr(tools, "verify_import_sector_direct", refused)

    with pytest.raises(SystemExit, match="verification failed"):
        _apply(tmp_path, stage_mode="filesystem")

    names = [call[0] for call in calls]
    assert "accept" not in names
    assert names[-1] == "mount_device", "the host mount is restored on the way out"


# --------------------------------------------------------------------- stage_import


def test_stage_import_writes_the_sector_prefix_in_place(tmp_path: Path) -> None:
    sector = tmp_path / "sector.bin"
    payload = bytes(range(256)) * 2
    sector.write_bytes(payload)
    import_file = tmp_path / "IMPORT.CFG"
    import_file.write_bytes(b"\xff" * (tools.SECTOR_SIZE * 3))

    tools.stage_import(import_file, sector)

    assert import_file.read_bytes() == payload + b"\xff" * (tools.SECTOR_SIZE * 2)


def test_stage_import_treats_a_refused_write_as_fatal_even_if_the_readback_matches(
    monkeypatch, tmp_path: Path
) -> None:
    """The 2026-09-25 live attempt: the panel answered the SCSI write with a
    sense error, the kernel raised EIO on fsync, and the file still read back
    correctly from the page cache. That must not count as staged."""

    sector = tmp_path / "sector.bin"
    sector.write_bytes(b"\x01" * tools.SECTOR_SIZE)
    import_file = tmp_path / "IMPORT.CFG"
    import_file.write_bytes(b"\x00" * tools.SECTOR_SIZE)

    def refuse(fd):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(tools.os, "fsync", refuse)

    with pytest.raises(SystemExit, match=r"staging failed.*Input/output error"):
        tools.stage_import(import_file, sector)

    # The bytes did reach the page cache; that is exactly the misleading
    # signal the fatal exit exists for.
    assert import_file.read_bytes() == b"\x01" * tools.SECTOR_SIZE


def test_direct_stage_mode_unmounts_a_host_mount_first_and_restores_it(
    monkeypatch, tmp_path: Path
) -> None:
    """On a host that has FLEXI_CFG mounted, the raw write must not race the
    kernel's page cache: unmount, write, remount."""

    calls: list = []
    _stub_session(monkeypatch, calls, mounted=True)

    _apply(tmp_path, stage_mode="direct")

    names = [call[0] for call in calls]
    assert names.index("unmount_device") < names.index("stage_import_direct")
    assert names.index("mount_device") > names.index("accept")


def test_unknown_stage_mode_is_refused_before_touching_anything(monkeypatch, tmp_path: Path) -> None:
    calls: list = []
    _stub_session(monkeypatch, calls)
    with pytest.raises(SystemExit, match="Unsupported stage mode"):
        _apply(tmp_path, stage_mode="magic")
    assert calls == []


# ------------------------------------------------------------- stage_import_direct


def test_stage_import_direct_writes_the_sector_at_its_lba_and_verifies_it(
    monkeypatch, tmp_path: Path
) -> None:
    sector = tmp_path / "sector.bin"
    payload = bytes(range(256)) * 2
    sector.write_bytes(payload + b"trailing bytes are ignored")
    written: list = []

    monkeypatch.setattr(
        tools,
        "write_device_direct_bytes",
        lambda *, device, start_lba, data: written.append((device, start_lba, data)),
    )
    monkeypatch.setattr(tools, "read_import_sector_direct", lambda *, device: payload)
    monkeypatch.setattr(tools, "resolve_import_sector_lba", lambda device: 2082)

    assert tools.stage_import_direct(device="/dev/sdb1", sector_path=sector) == payload
    assert written == [("/dev/sdb1", 2082, payload)]


def test_stage_import_direct_fails_when_the_readback_differs(monkeypatch, tmp_path: Path) -> None:
    sector = tmp_path / "sector.bin"
    sector.write_bytes(b"\x01" * tools.SECTOR_SIZE)
    monkeypatch.setattr(tools, "write_device_direct_bytes", lambda **k: None)
    monkeypatch.setattr(tools, "resolve_import_sector_lba", lambda device: 2082)
    monkeypatch.setattr(tools, "read_import_sector_direct", lambda *, device: b"\x02" * tools.SECTOR_SIZE)
    with pytest.raises(SystemExit, match="verification"):
        tools.stage_import_direct(device="/dev/sdb1", sector_path=sector)


def test_stage_import_direct_rejects_a_short_sector(tmp_path: Path) -> None:
    sector = tmp_path / "sector.bin"
    sector.write_bytes(b"\x01" * 100)
    with pytest.raises(SystemExit, match="512-byte"):
        tools.stage_import_direct(device="/dev/sdb1", sector_path=sector)


def test_direct_write_runs_dd_without_sudo_when_already_root(monkeypatch) -> None:
    """The container runs as root and ships no sudo binary."""

    commands: list = []

    def fake_run(command, check=True, **kwargs):
        commands.append(list(command))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(tools, "resolve_flexi_cfg_device", lambda device: device)
    monkeypatch.setattr(tools.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tools.subprocess, "run", fake_run)

    tools.write_device_direct_bytes(device="/dev/sdb1", start_lba=tools.IMPORT_START_LBA, data=b"\x00" * 512)

    assert len(commands) == 1
    command = commands[0]
    assert command[0] == "dd"
    assert "sudo" not in command
    assert "of=/dev/sdb1" in command
    assert f"seek={tools.IMPORT_START_LBA}" in command
    assert "count=1" in command
    assert "oflag=direct" in command
    assert "conv=fsync,notrunc" in command


def test_direct_write_falls_back_to_a_buffered_write_if_o_direct_is_refused(monkeypatch) -> None:
    commands: list = []

    def fake_run(command, check=True, **kwargs):
        commands.append(list(command))
        if "oflag=direct" in command:
            raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(tools, "resolve_flexi_cfg_device", lambda device: device)
    monkeypatch.setattr(tools.os, "geteuid", lambda: 0)
    monkeypatch.setattr(tools.subprocess, "run", fake_run)

    tools.write_device_direct_bytes(device="/dev/sdb1", start_lba=1, data=b"\x00" * 512)

    assert [("oflag=direct" in command) for command in commands] == [True, False]


def test_direct_write_uses_sudo_when_not_root(monkeypatch) -> None:
    commands: list = []

    def fake_run(command, check=True, **kwargs):
        commands.append(list(command))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(tools, "resolve_flexi_cfg_device", lambda device: device)
    monkeypatch.setattr(tools.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(tools.subprocess, "run", fake_run)

    tools.write_device_direct_bytes(device="/dev/sdb1", start_lba=1, data=b"\x00" * 512)

    assert commands[0][:2] == ["sudo", "-n"]


# ------------------------------------------------------------ configuration


def test_stage_mode_reaches_the_user_manager_from_the_environment(monkeypatch) -> None:
    """JABLOTRON_PANEL_STAGE_MODE=direct is what the container needs; make
    sure the value survives ServerSettings → PanelRuntime → UserManagerConfig."""

    from jablotron_api.panel.runtime import PanelRuntime
    from jablotron_api.server.config import ServerSettings

    monkeypatch.setenv("JABLOTRON_PANEL_AUTH_CODE", "1812")
    monkeypatch.setenv("JABLOTRON_PANEL_STAGE_MODE", "direct")
    settings = ServerSettings()
    assert settings.panel.stage_mode == "direct"
    runtime = PanelRuntime(settings.panel)
    assert runtime._user_manager_config().stage_mode == "direct"

    monkeypatch.delenv("JABLOTRON_PANEL_STAGE_MODE")
    assert ServerSettings().panel.stage_mode == "filesystem"


# ------------------------------------------------------- resolve_import_sector_lba


def test_import_sector_lba_comes_from_the_fat_directory(monkeypatch) -> None:
    """The capture constant 2083 is an absolute disk LBA; the partition we
    open starts at sector 1, so the directory walk must win."""

    class Reader:
        def __init__(self, device: str) -> None:
            assert device == "/dev/sdb1"

        def first_sector(self, name: bytes) -> int:
            assert name == tools.IMPORT_FILENAME_83
            return 2082

    monkeypatch.setattr(tools, "resolve_flexi_cfg_device", lambda device: "/dev/sdb1")
    monkeypatch.setattr(tools, "FatVolumeReader", Reader)
    assert tools.resolve_import_sector_lba("auto") == 2082


def test_import_sector_lba_falls_back_to_the_constant_minus_the_partition_offset(monkeypatch) -> None:
    class Reader:
        def __init__(self, device: str) -> None:
            pass

        def first_sector(self, name: bytes) -> int | None:
            raise OSError("no device")

    monkeypatch.setattr(tools, "resolve_flexi_cfg_device", lambda device: "/dev/sdb1")
    monkeypatch.setattr(tools, "FatVolumeReader", Reader)
    monkeypatch.setattr(tools, "partition_start_sector", lambda device: 1)
    assert tools.resolve_import_sector_lba("auto") == tools.IMPORT_START_LBA - 1


def test_partition_start_sector_reads_sysfs(monkeypatch, tmp_path: Path) -> None:
    sysfs = tmp_path / "sdz1"
    sysfs.mkdir()
    (sysfs / "start").write_text("1\n")
    real_path = tools.Path

    class FakePath(type(real_path())):
        def __new__(cls, *parts):
            if parts and parts[0] == "/sys/class/block":
                return real_path(tmp_path, *parts[1:])
            return real_path(*parts)

    monkeypatch.setattr(tools, "Path", FakePath)
    assert tools.partition_start_sector("/dev/sdz1") == 1
    assert tools.partition_start_sector("/dev/sdq1") == 0
