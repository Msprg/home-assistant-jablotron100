"""Mount-free FAT16 reads of the panel's mass-storage volumes.

The panel exposes FLEXI_CFG and FLEXI_LOG as USB mass storage. Reading them
through a kernel mount needs CAP_SYS_ADMIN and a `sudo` binary, neither of
which the API server container has — which is why `/v1/events` returned 500
there. These tests drive the reader against a synthetic FAT16 image built in
memory, so no block device and no privilege is involved.
"""

from __future__ import annotations

from struct import pack

import pytest

import jablotron_event_tool as event_tool
import jablotron_re_tools as re_tools
from jablotron_event_tool import (
    FLEXILOG_OLD_83,
    FLEXILOG_TXT_83,
    LOGINDEX_83,
    parse_log_index_points,
    read_volume_log_range,
)
from jablotron_re_tools import FatVolumeReader

SECTOR = 512
SECTORS_PER_CLUSTER = 4
CLUSTER = SECTOR * SECTORS_PER_CLUSTER  # 2048
RESERVED = 1
FAT_COUNT = 2
ROOT_ENTRIES = 16
SECTORS_PER_FAT = 2
ROOT_DIR_SECTORS = ROOT_ENTRIES * 32 // SECTOR  # 1
DATA_START = RESERVED + FAT_COUNT * SECTORS_PER_FAT + ROOT_DIR_SECTORS  # 6
TOTAL_SECTORS = 512


class FatImage:
    """A minimal, valid-enough FAT16 volume held in memory."""

    def __init__(self) -> None:
        self.data = bytearray(SECTOR * TOTAL_SECTORS)
        boot = bytearray(SECTOR)
        boot[11:13] = pack("<H", SECTOR)
        boot[13] = SECTORS_PER_CLUSTER
        boot[14:16] = pack("<H", RESERVED)
        boot[16] = FAT_COUNT
        boot[17:19] = pack("<H", ROOT_ENTRIES)
        boot[22:24] = pack("<H", SECTORS_PER_FAT)
        self.data[0:SECTOR] = boot
        self._dir_slot = 0
        self.reads: list[tuple[int, int]] = []

    # -- authoring -------------------------------------------------------

    def _write_cluster(self, cluster: int, payload: bytes) -> None:
        offset = (DATA_START + (cluster - 2) * SECTORS_PER_CLUSTER) * SECTOR
        self.data[offset : offset + len(payload)] = payload

    def _set_fat(self, cluster: int, value: int) -> None:
        for copy in range(FAT_COUNT):
            base = (RESERVED + copy * SECTORS_PER_FAT) * SECTOR
            self.data[base + cluster * 2 : base + cluster * 2 + 2] = pack("<H", value)

    def add_file(self, name_83: bytes, payload: bytes, clusters: list[int], *,
                 attributes: int = 0x20, date_raw: int = 0x594F, time_raw: int = 0x5C1E) -> None:
        assert len(name_83) == 11
        for index, cluster in enumerate(clusters):
            chunk = payload[index * CLUSTER : (index + 1) * CLUSTER]
            self._write_cluster(cluster, chunk)
            nxt = clusters[index + 1] if index + 1 < len(clusters) else 0xFFFF
            self._set_fat(cluster, nxt)
        entry = bytearray(32)
        entry[0:11] = name_83
        entry[11] = attributes
        entry[22:24] = pack("<H", time_raw)
        entry[24:26] = pack("<H", date_raw)
        entry[26:28] = pack("<H", clusters[0])
        entry[28:32] = pack("<I", len(payload))
        self._put_dir_entry(entry)

    def add_raw_dir_entry(self, entry: bytes) -> None:
        self._put_dir_entry(bytearray(entry))

    def _put_dir_entry(self, entry: bytearray) -> None:
        base = (RESERVED + FAT_COUNT * SECTORS_PER_FAT) * SECTOR + self._dir_slot * 32
        self.data[base : base + 32] = entry
        self._dir_slot += 1

    # -- reading ---------------------------------------------------------

    def read_sectors(self, start_lba: int, sectors: int) -> bytes:
        self.reads.append((start_lba, sectors))
        start = start_lba * SECTOR
        return bytes(self.data[start : start + sectors * SECTOR])

    def reader(self) -> FatVolumeReader:
        return FatVolumeReader("/dev/null", read_sectors=self.read_sectors)


def _payload(marker: bytes, size: int) -> bytes:
    return (marker * ((size // len(marker)) + 1))[:size]


@pytest.fixture
def image() -> FatImage:
    img = FatImage()
    img.add_file(b"CONTIG  BIN", _payload(b"contiguous-", 5000), [2, 3, 4])
    img.add_file(b"FRAGMENTBIN", _payload(b"fragmented-", 5000), [5, 9, 6])
    img.add_file(b"TINY    BIN", b"tiny", [7])
    return img


# ------------------------------------------------------------------ geometry


def test_geometry_is_parsed_from_the_boot_sector(image):
    geometry = image.reader().geometry
    assert geometry["bytes_per_sector"] == SECTOR
    assert geometry["cluster_size_bytes"] == CLUSTER
    assert geometry["root_dir_start_sector"] == RESERVED + FAT_COUNT * SECTORS_PER_FAT
    assert geometry["data_start_sector"] == DATA_START


def test_directory_lists_entries_with_size_cluster_and_mtime(image):
    entries = image.reader().entries()
    assert set(entries) == {b"CONTIG  BIN", b"FRAGMENTBIN", b"TINY    BIN"}
    contig = entries[b"CONTIG  BIN"]
    assert contig.size == 5000
    assert contig.start_cluster == 2
    assert contig.attributes == 0x20
    assert entries[b"TINY    BIN"].size == 4


def test_mtime_is_decoded_from_the_dos_fields():
    img = FatImage()
    # 2026-08-19 11:31:32 -> the EXPORT.CFG timestamp seen on the live panel.
    date_raw = ((2026 - 1980) << 9) | (8 << 5) | 19
    time_raw = (11 << 11) | (31 << 5) | (32 // 2)
    img.add_file(b"STAMP   BIN", b"x", [2], date_raw=date_raw, time_raw=time_raw)
    assert img.reader().entries()[b"STAMP   BIN"].modified == "2026-08-19 11:31:32"


def test_deleted_and_long_name_entries_are_skipped():
    img = FatImage()
    deleted = bytearray(32)
    deleted[0] = 0xE5
    deleted[0:11] = b"\xe5ELETEDBIN"
    img.add_raw_dir_entry(bytes(deleted))
    lfn = bytearray(32)
    lfn[0] = 0x41
    lfn[11] = 0x0F
    img.add_raw_dir_entry(bytes(lfn))
    img.add_file(b"REAL    BIN", b"payload", [2])
    assert set(img.reader().entries()) == {b"REAL    BIN"}


# --------------------------------------------------------------------- reads


def test_whole_file_read_matches_and_is_truncated_to_size(image):
    data = image.reader().read_file(b"CONTIG  BIN")
    assert data == _payload(b"contiguous-", 5000)
    assert len(data) == 5000  # not rounded up to the 6144-byte cluster run


def test_fragmented_chain_is_reassembled_in_chain_order(image):
    assert image.reader().read_file(b"FRAGMENTBIN") == _payload(b"fragmented-", 5000)


def test_range_read_inside_one_cluster(image):
    expected = _payload(b"contiguous-", 5000)[100:200]
    assert image.reader().read_file(b"CONTIG  BIN", start=100, length=100) == expected


def test_range_read_spanning_a_cluster_boundary(image):
    expected = _payload(b"contiguous-", 5000)[CLUSTER - 50 : CLUSTER + 50]
    assert image.reader().read_file(b"CONTIG  BIN", start=CLUSTER - 50, length=100) == expected


def test_range_read_spanning_a_fragmented_boundary(image):
    expected = _payload(b"fragmented-", 5000)[CLUSTER - 10 : 2 * CLUSTER + 10]
    got = image.reader().read_file(b"FRAGMENTBIN", start=CLUSTER - 10, length=len(expected))
    assert got == expected


def test_read_past_the_end_is_truncated_not_padded(image):
    got = image.reader().read_file(b"CONTIG  BIN", start=4900, length=1000)
    assert got == _payload(b"contiguous-", 5000)[4900:]
    assert len(got) == 100


def test_read_starting_past_the_end_is_empty(image):
    assert image.reader().read_file(b"CONTIG  BIN", start=5000, length=10) == b""


def test_missing_file_reads_empty(image):
    assert image.reader().read_file(b"NOPE    BIN") == b""
    assert image.reader().size(b"NOPE    BIN") == 0


def test_negative_start_is_rejected(image):
    with pytest.raises(ValueError):
        image.reader().read_file(b"CONTIG  BIN", start=-1, length=1)


def test_contiguous_clusters_are_read_as_one_run(image):
    reader = image.reader()
    reader.refresh()
    image.reads.clear()
    reader.read_file(b"CONTIG  BIN")
    # One dd per contiguous run, not one per cluster: the live volumes are
    # slow enough that this matters (a 10 MB log is 160 clusters).
    assert len(image.reads) == 1
    assert image.reads[0] == (DATA_START, 3 * SECTORS_PER_CLUSTER)


def test_fragmented_clusters_are_read_as_one_call_per_run(image):
    reader = image.reader()
    reader.refresh()
    image.reads.clear()
    reader.read_file(b"FRAGMENTBIN")
    assert len(image.reads) == 3  # clusters 5, 9, 6 are three separate runs


def test_refresh_picks_up_a_volume_the_panel_rewrote(image):
    reader = image.reader()
    assert reader.size(b"TINY    BIN") == 4
    # The panel materialises these volumes inside a session and zeroes them
    # afterwards, so the directory changes underneath a long-lived reader.
    image.add_file(b"LATER   BIN", b"appeared", [8])
    assert b"LATER   BIN" not in reader.entries()
    reader.refresh()
    assert b"LATER   BIN" in reader.entries()


# ------------------------------------------------------ event-log addressing


def _log_image(old: bytes, current: bytes) -> FatImage:
    img = FatImage()
    img.add_file(FLEXILOG_OLD_83, old, [2, 3, 4])
    img.add_file(FLEXILOG_TXT_83, current, [5, 6])
    return img


def test_combined_range_reads_from_the_old_half():
    img = _log_image(_payload(b"OLD-", 4000), _payload(b"NEW-", 3000))
    got = read_volume_log_range(volume=img.reader(), old_size=4000, start=10, length=50)
    assert got == _payload(b"OLD-", 4000)[10:60]


def test_combined_range_reads_from_the_current_half():
    img = _log_image(_payload(b"OLD-", 4000), _payload(b"NEW-", 3000))
    got = read_volume_log_range(volume=img.reader(), old_size=4000, start=4100, length=50)
    assert got == _payload(b"NEW-", 3000)[100:150]


def test_combined_range_spans_the_boundary_between_the_halves():
    old, current = _payload(b"OLD-", 4000), _payload(b"NEW-", 3000)
    got = read_volume_log_range(volume=_log_image(old, current).reader(),
                                old_size=4000, start=3980, length=40)
    assert got == old[3980:] + current[:20]


def test_index_points_parse_from_bytes():
    blob = pack("<IIII", 1_700_000_000, 4096, 1_700_003_600, 8192)
    points = parse_log_index_points(blob)
    assert [(p.timestamp, p.offset) for p in points] == [
        (1_700_000_000, 4096),
        (1_700_003_600, 8192),
    ]


def test_index_points_skip_empty_and_implausible_records():
    blob = pack("<IIII", 0, 0, 5, 4096) + pack("<IIII", 1_700_000_000, 0, 1_700_000_000, 8192)
    assert [p.offset for p in parse_log_index_points(blob)] == [8192]


def test_index_points_read_through_the_volume():
    img = FatImage()
    img.add_file(LOGINDEX_83, pack("<IIII", 1_700_000_000, 4096, 0, 0), [2])
    points = parse_log_index_points(img.reader().read_file(LOGINDEX_83))
    assert [p.offset for p in points] == [4096]


# -------------------------------------------------------------- privilege use


def test_sudo_is_not_used_when_already_root(monkeypatch):
    monkeypatch.setattr(re_tools.os, "geteuid", lambda: 0)
    assert re_tools._privileged_command(["mount", "-o", "ro", "/dev/x", "/mnt"]) == [
        "mount", "-o", "ro", "/dev/x", "/mnt",
    ]


def test_sudo_is_used_when_not_root(monkeypatch):
    monkeypatch.setattr(re_tools.os, "geteuid", lambda: 1000)
    assert re_tools._privileged_command(["umount", "/dev/x"]) == [
        "sudo", "-n", "umount", "/dev/x",
    ]


def test_the_server_event_path_never_mounts(monkeypatch, tmp_path):
    """Drive the server's own entry point offline and assert no mount."""

    from jablotron_api.services.event_reader import EventReaderConfig, read_recent_events

    records = b"".join(
        f"260821 19:{minute:02d}:00\tEVENT\tsomething happened\r\n".encode()
        for minute in range(10, 40)
    )
    img = FatImage()
    img.add_file(FLEXILOG_OLD_83, b"\x00" * 64, [2])
    img.add_file(FLEXILOG_TXT_83, records, list(range(3, 3 + (len(records) // CLUSTER) + 1)))
    img.add_file(LOGINDEX_83, pack("<IIII", 1_800_000_000, 64 + len(records), 0, 0), [12])

    calls: list[str] = []

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        def close(self):
            calls.append("close")

    def _boom(*a, **k):
        calls.append("mount_device")
        raise AssertionError("the server event path must not mount the volume")

    monkeypatch.setattr(event_tool, "mount_device", _boom)
    monkeypatch.setattr(event_tool, "unmount_device", _boom)
    monkeypatch.setattr(event_tool, "ensure_serial_port", lambda port: "/dev/null")
    monkeypatch.setattr(event_tool, "JablotronUSBClient", _FakeClient)
    monkeypatch.setattr(event_tool, "perform_login", lambda *a, **k: calls.append("login"))
    monkeypatch.setattr(event_tool, "drain_packets", lambda *a, **k: [])
    monkeypatch.setattr(
        event_tool, "enter_setup_mode", lambda *a, **k: calls.append("enter_setup_mode")
    )
    monkeypatch.setattr(event_tool, "graceful_exit_session", lambda *a, **k: [])
    monkeypatch.setattr(event_tool, "extract_sections_state_mode", lambda packet: None)
    monkeypatch.setattr(event_tool.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(
        event_tool, "FatVolumeReader", lambda device, **kw: img.reader()
    )
    monkeypatch.chdir(tmp_path)

    events = read_recent_events(
        EventReaderConfig(
            flexi_log_device="/dev/null",
            port="auto",
            auth_code="0000",
            reset=True,
            mount_tool="sudo",
        ),
        limit=5,
    )

    assert "mount_device" not in calls
    assert "enter_setup_mode" in calls, "the session is still required to materialise the log"
    assert len(events) == 5
    assert all(event.text for event in events)


# ------------------------------------------------------------------ end mode


def test_the_server_asks_for_the_live_window_not_the_stale_index():
    """`end_mode` decides how old the returned events are."""

    from jablotron_api.services.event_reader import EventReaderConfig, _build_archive_args

    args = _build_archive_args(
        EventReaderConfig(
            flexi_log_device="/dev/null", port="auto", auth_code="0", reset=True, mount_tool="sudo"
        )
    )
    assert args.end_mode == "physical"


def test_an_unknown_end_mode_is_rejected_rather_than_silently_ignored():
    from types import SimpleNamespace

    args = SimpleNamespace(end_mode="logical", log_device="/dev/null", mountpoint="/mnt",
                           output=None, metadata_output=None, records_output=None,
                           output_prefix="x", records_format="jsonl", save_records=False)
    with pytest.raises(ValueError, match="end mode"):
        event_tool.pull_live_archive(args)


def test_window_end_follows_the_live_sizes_when_the_index_lags():
    """The regression that made /v1/events return ~20-hour-old events."""

    # Position-encoded payload: a repeating marker would make two different
    # windows compare equal by accident.
    old_payload = b"".join(f"O{index:09d}".encode() for index in range(400))
    current_payload = b"".join(f"N{index:09d}".encode() for index in range(300))
    img = _log_image(old_payload, current_payload)
    volume = img.reader()
    physical_total = volume.size(FLEXILOG_OLD_83) + volume.size(FLEXILOG_TXT_83)
    # An index checkpoint far behind the live write position.
    stale_index_end = physical_total - 2500

    from_index = read_volume_log_range(
        volume=volume, old_size=4000, start=stale_index_end - 100, length=100
    )
    from_physical = read_volume_log_range(
        volume=volume, old_size=4000, start=physical_total - 100, length=100
    )
    assert from_index != from_physical
    assert from_physical == current_payload[-100:]


# --------------------------------------------------------------- first_sector


def test_first_sector_is_the_data_start_of_the_first_cluster(image):
    reader = image.reader()
    assert reader.first_sector(b"CONTIG  BIN") == DATA_START
    assert reader.first_sector(b"FRAGMENTBIN") == DATA_START + 3 * SECTORS_PER_CLUSTER


def test_first_sector_of_a_missing_file_is_none(image):
    assert image.reader().first_sector(b"MISSING BIN") is None
