#!/usr/bin/env python3
"""Shared reverse-engineering helpers for live Jablotron config workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from struct import unpack_from
from typing import Callable, Iterable, Optional

import msgpack

from flexi_pcap_tool import IMPORT_START_LBA
from jablotron_usb_debug import (
    Jablotron,
    JablotronUSBClient,
    JablotronUSBStreamError,
    build_flink_info_log_reports,
    describe_packet,
    ensure_serial_port,
    perform_login,
    perform_send_raw_report,
)

SECTOR_SIZE = 512
EXPORT_START_LBA = 35
EXPORT_SECTORS = 2048
EXPORT_FILENAME_83 = b"EXPORT  CFG"
IMPORT_FILENAME_83 = b"IMPORT  CFG"
DEFAULT_FLEXI_CFG_LABEL = "FLEXI_CFG"
DEFAULT_FLEXI_CFG_LINK = Path("/dev/disk/by-label") / DEFAULT_FLEXI_CFG_LABEL
DEFAULT_FLEXI_LOG_LABEL = "FLEXI_LOG"
DEFAULT_FLEXI_LOG_LINK = Path("/dev/disk/by-label") / DEFAULT_FLEXI_LOG_LABEL
DEFAULT_IMPORT_MOUNTPOINT = Path("/mnt/flexi_cfg")
DEFAULT_IMPORT_PATH = DEFAULT_IMPORT_MOUNTPOINT / "IMPORT.CFG"
REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_ADD_TEMPLATE_PCAP = REPO_ROOT / "research/captures/usb/f_link/f-link-add-user-USER91TEST.pcapng"
DEFAULT_ADD_TEMPLATE_FRAME = 2085
IMPORT_METADATA_START_LBA = 27
IMPORT_METADATA_SECTORS = 8

REPORT_520102 = "520102" + "00" * 61
REPORT_520124 = "520124" + "00" * 61
REPORT_52010C = "52010c" + "00" * 61
REPORT_800114 = "800114" + "00" * 61
REPORT_80010F = "80010f" + "00" * 61
REPORT_800102 = "800102" + "00" * 61
REPORT_520125 = "520125" + "00" * 61
REPORT_520213059A00 = "520213059a00" + "00" * 58
EXIT_DIAGNOSTICS_OFF_PACKET = bytes.fromhex("94020100")
EXITED_SECTIONS_MODE = 0x90
CONFIGURATION_SECTIONS_MODE = 0x94
SETUP_MODE_NUDGE_DELAY = 0.35
SETUP_MODE_FIRST_KEEPALIVE_DELAY = 0.7
SETUP_MODE_KEEPALIVE_INTERVAL = 1.0

ARC_PROTOCOL_NAMES = {
    0: "ARC_PROTO_NONE",
    1: "ARC_PROTO_SIA_IP",
    4: "ARC_PROTO_SIA_CID",
    5: "ARC_PROTO_SIA_FSK",
    6: "ARC_PROTO_JABLO_IP",
    7: "ARC_PROTO_JABLO_SMS",
    9: "ARC_PROTO_IMG",
    10: "ARC_PROTO_DEVICE",
}

ARC_SPECIFIC_NAMES = {
    0: "sia_ip",
    1: "sia_cid",
    2: "sia_fsk",
    3: "jablo_ip",
    4: "jablo_sms",
    5: "jablo_img",
    6: "device",
}

ARC_SERVICE_ACCESS_NAMES = {
    0: "ARC_ACCESS_FULL",
    1: "ARC_ACCESS_OFF",
    2: "ARC_ACCESS_READ",
}

ARC_ATS_CLASS_NAMES = {
    0: "ARC_ATS_NONE",
    1: "ARC_ATS_SP2",
    2: "ARC_ATS_SP3",
    3: "ARC_ATS_SP4",
    4: "ARC_ATS_SP5",
    5: "ARC_ATS_DP2",
    6: "ARC_ATS_DP3",
}

USER_FLAG_NAMES = {
    0: "blocked",
    1: "suppress_control_events",
    2: "pg_ring_controlled",
}

WEEKDAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


@dataclass(frozen=True)
class UserRecord:
    offset: int
    user_id: Optional[int]
    raw_id_bytes: str
    flags_raw: Optional[int]
    flags: list[str]
    access_raw: Optional[int]
    rights: str
    enabled: Optional[bool]
    section_access_mask_raw: Optional[int]
    section_ids: list[int]
    pg_access_masks_raw: list[int]
    pg_ids: list[int]
    name: str
    phone: str
    code: str
    cards: list[str]
    comment: str
    pg_num_if_ring_raw: Optional[int]
    time_limited_group_raw: Optional[int]
    parent_user_no_raw: Optional[int]

    @property
    def card(self) -> str:
        return self.cards[0] if self.cards else ""

    @property
    def card2(self) -> str:
        return self.cards[1] if len(self.cards) > 1 else ""

    @property
    def permissions_raw(self) -> Optional[int]:
        return self.access_raw

    @property
    def status_raw(self) -> Optional[int]:
        return self.flags_raw


@dataclass(frozen=True)
class ExportUserTimeLimitWindow:
    on: str
    off: str


@dataclass(frozen=True)
class ExportUserTimeLimitSectionRule:
    section_id: int
    windows: list[ExportUserTimeLimitWindow]


@dataclass(frozen=True)
class ExportUserTimeLimitDay:
    day_index: int
    day_name: str
    section_rules: list[ExportUserTimeLimitSectionRule]


@dataclass(frozen=True)
class ExportUserTimeLimitGroup:
    group_id: int
    group_display_id: int
    comment: str
    days: list[ExportUserTimeLimitDay]


@dataclass(frozen=True)
class ExportSnapshot:
    path: Path
    sha256: str
    raw_records: list[UserRecord]
    records: list[UserRecord]
    sections_by_id: dict[int, "ExportSectionRecord"]
    pgs_by_id: dict[int, "ExportPGRecord"]
    time_limit_groups_by_id: dict[int, ExportUserTimeLimitGroup]


@dataclass(frozen=True)
class ExportSectionRecord:
    section_id: int
    display_id: int
    name: str
    flags_raw: int | None
    options_raw: int | None
    state_raw: int | None
    comment: str


@dataclass(frozen=True)
class ExportObjectRecord:
    object_id: int
    name: str
    kind_raw: int | None
    section_id: int | None
    type_raw: int | None
    subtype_raw: int | None
    pg_masks: list[int]
    comment: str


@dataclass(frozen=True)
class ExportHardwareRecord:
    object_id: int
    model: str
    hardware_code: str
    firmware: str
    field3_raw: int | None
    field4_raw: int | None
    field5_raw: int | None


@dataclass(frozen=True)
class ExportPGRecord:
    pg_id: int
    display_id: int
    name: str
    type_raw: int | None
    section_id: int | None
    field6_raw: int | None
    comment: str


@dataclass(frozen=True)
class ExportArcSpecificRecord:
    name: str
    endpoints: list[str]
    crypt_key: str
    token_type_raw: int | None
    key_type_raw: int | None
    prefix_raw: int | None
    backward_compatibility: bool | None
    text_sync_enable: bool | None
    proto_version_raw: int | None
    delivery_timeout_raw: int | None
    disable_sms: bool | None
    limiter_soft_raw: int | None
    limiter_hard_raw: int | None


@dataclass(frozen=True)
class ExportARCRecord:
    arc_id: int
    protocol_type_raw: int | None
    protocol_name: str
    enabled: bool | None
    contest_in_fixed_time: bool | None
    backup: bool | None
    backup_test_reports: bool | None
    section_object_ids: list[int]
    err_wait_time_raw: int | None
    report_time_raw: int | None
    report_time_backup_raw: int | None
    retry_count_raw: int | None
    time_out_raw: int | None
    channel_id: int | None
    channel_name: str
    comment: str
    ats_class_raw: int | None
    ats_class_name: str
    service_access_raw: int | None
    service_access_name: str
    specific_by_name: dict[str, ExportArcSpecificRecord]


@dataclass(frozen=True)
class ExportMainConfig:
    users_raw: int | None
    peripheries_raw: int | None
    sections_raw: int | None
    pgs_raw: int | None
    language_id: str
    language_raw: int | None
    code_len_raw: int | None
    code_prefix: bool | None
    wpp_dedicated: bool | None
    rfid_restrict: bool | None
    simple_log: bool | None
    default_config: bool | None
    language_unlock_code: str
    name: str


@dataclass(frozen=True)
class ExportCommunicationFlags:
    pcos_on: bool | None
    ytun_persistent: bool | None
    voice_menu_without_code: bool | None
    ytun_log_disable: bool | None
    wpp_lock: bool | None
    ytun_device_info_disable: bool | None
    ytun_enable: bool | None
    comm_configured: bool | None
    gsm_autoconfig_disabled: bool | None
    send_sms_on_failed_arm: bool | None


@dataclass(frozen=True)
class ExportCommunicationSDCConfig:
    flags_raw: int | None
    allow_reports_alarm_voice: bool | None
    sdc_position: int | None
    sdc_position_name: str


@dataclass(frozen=True)
class ExportCommunicationsConfig:
    flags: ExportCommunicationFlags
    ytun_url: str
    sms_resend_to_user: int | None
    aes_key_ascii: str
    aes_key_hex: str
    ytun_key: str
    rf_key_ascii: str
    rf_key_hex: str
    y0_hb_time_raw: int | None
    data_channels_raw: list[int]
    data_channels: list[str]
    sms_channels_raw: list[int]
    sms_channels: list[str]
    voice_channels_raw: list[int]
    voice_channels: list[str]
    local_listen_port_raw: int | None
    sdc: ExportCommunicationSDCConfig | None
    service_access_raw: int | None
    service_access_name: str


@dataclass(frozen=True)
class ExportCatalogSnapshot:
    path: Path
    users: list[UserRecord]
    sections_by_id: dict[int, ExportSectionRecord]
    objects_by_id: dict[int, ExportObjectRecord]
    hardware_by_id: dict[int, ExportHardwareRecord]
    pgs_by_id: dict[int, ExportPGRecord]
    arcs_by_id: dict[int, ExportARCRecord]
    time_limit_groups_by_id: dict[int, ExportUserTimeLimitGroup]
    main_config: ExportMainConfig | None
    communications: ExportCommunicationsConfig | None

    @property
    def communicators_by_id(self) -> dict[int, ExportObjectRecord]:
        return {
            object_id: record
            for object_id, record in self.objects_by_id.items()
            if object_id >= 233 or record.name.lower().endswith("communicator")
        }


def compress_numeric_ids(values: Iterable[int]) -> str:
    numbers = sorted(set(values))
    if not numbers:
        return ""
    ranges: list[str] = []
    start = numbers[0]
    end = numbers[0]
    for value in numbers[1:]:
        if value == end + 1:
            end = value
            continue
        ranges.append(f"{start}-{end}" if start != end else str(start))
        start = end = value
    ranges.append(f"{start}-{end}" if start != end else str(start))
    return ",".join(ranges)


def format_section_access(
    record: UserRecord,
    snapshot: ExportSnapshot | ExportCatalogSnapshot,
    *,
    show_names: bool = True,
) -> str:
    if not record.section_ids:
        return "-"
    if not show_names:
        return compress_numeric_ids(record.section_ids)
    parts = []
    for section_id in record.section_ids:
        section = snapshot.sections_by_id.get(section_id)
        parts.append(f"{section_id}:{section.name}" if section is not None else str(section_id))
    return ",".join(parts)


def format_pg_access(
    record: UserRecord,
    snapshot: ExportSnapshot | ExportCatalogSnapshot,
    *,
    show_names: bool = True,
) -> str:
    if not record.pg_ids:
        return "-"
    if not show_names or len(record.pg_ids) > 12:
        return compress_numeric_ids(record.pg_ids)
    parts = []
    for pg_id in record.pg_ids:
        pg = snapshot.pgs_by_id.get(pg_id - 1)
        parts.append(f"{pg_id}:{pg.name}" if pg is not None else str(pg_id))
    return ",".join(parts)


def summarize_time_limit_group(group: ExportUserTimeLimitGroup) -> str:
    active_days = [day.day_name for day in group.days if day.section_rules]
    active_sections = sorted({rule.section_id for day in group.days for rule in day.section_rules})
    parts = [f"G{group.group_display_id}"]
    if active_days:
        parts.append(",".join(active_days))
    if active_sections:
        parts.append(f"S{compress_numeric_ids(active_sections)}")
    if group.comment:
        parts.append(group.comment)
    return " ".join(parts)


def resolve_time_limit_group(
    record: UserRecord,
    snapshot: ExportSnapshot | ExportCatalogSnapshot,
) -> ExportUserTimeLimitGroup | None:
    raw_value = record.time_limited_group_raw
    if raw_value is None or raw_value <= 0:
        return None
    group = snapshot.time_limit_groups_by_id.get(raw_value - 1)
    if group is not None:
        return group
    return snapshot.time_limit_groups_by_id.get(raw_value)


def format_time_limit_binding(
    record: UserRecord,
    snapshot: ExportSnapshot | ExportCatalogSnapshot,
) -> str:
    group = resolve_time_limit_group(record, snapshot)
    if group is not None:
        return summarize_time_limit_group(group)
    raw_value = record.time_limited_group_raw
    if raw_value in (None, 0):
        return "-"
    return f"raw:{raw_value}"


def format_cards(record: UserRecord) -> str:
    cards = [card for card in record.cards if card]
    return ",".join(cards) if cards else "-"


def allow_code_change(record: UserRecord) -> bool | None:
    if record.rights in {"coMaster", "coService"}:
        return True
    if record.rights == "coUserNoSelfedit":
        return False
    if record.rights in {"coNoAccess", "coPanic", "coPGOnly", "coArmOnly", "coUserGuard", "coPCOGuard", "WPPPhone"}:
        return None
    if record.access_raw is None:
        return None
    return bool(record.access_raw & (1 << 4))


def format_allow_code_change(record: UserRecord) -> str:
    value = allow_code_change(record)
    if value is None:
        return "-"
    return "yes" if value else "no"


def log_user_actions(record: UserRecord) -> bool:
    return "suppress_control_events" not in record.flags


def format_log_user_actions(record: UserRecord) -> str:
    return "yes" if log_user_actions(record) else "no"


def user_record_to_output_dict(
    record: UserRecord,
    snapshot: ExportSnapshot | ExportCatalogSnapshot,
    *,
    show_names: bool = True,
) -> dict[str, object]:
    data = asdict(record)
    data["cards"] = [card for card in record.cards if card]
    data["allow_code_change"] = allow_code_change(record)
    data["allow_code_change_display"] = format_allow_code_change(record)
    data["log_user_actions"] = log_user_actions(record)
    data["log_user_actions_display"] = format_log_user_actions(record)
    data["sections_display"] = format_section_access(record, snapshot, show_names=show_names)
    data["pgs_display"] = format_pg_access(record, snapshot, show_names=show_names)
    data["flags_display"] = ",".join(record.flags) if record.flags else "-"
    data["time_limit_display"] = format_time_limit_binding(record, snapshot)
    linked_group = resolve_time_limit_group(record, snapshot)
    if linked_group is not None:
        data["time_limit_group"] = asdict(linked_group)
    return data


def emit_user_records(
    records: list[UserRecord],
    fmt: str,
    snapshot: ExportSnapshot | ExportCatalogSnapshot,
    *,
    show_names: bool = True,
    include_raw_metadata: bool = False,
) -> None:
    if fmt == "json":
        print(
            json.dumps(
                [user_record_to_output_dict(record, snapshot, show_names=show_names) for record in records],
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    headers = ["ID", "Name", "Phone", "Code", "Cards", "Access", "SelfCode", "Log", "TimeLimit", "Sections", "PGs", "Flags", "Comment"]
    if include_raw_metadata:
        headers = ["ID", "RawID", *headers[1:], "Offset"]

    rows = [tuple(headers)]
    for record in records:
        row = [
            "" if record.user_id is None else str(record.user_id),
            record.name,
            record.phone,
            record.code,
            format_cards(record),
            record.rights,
            format_allow_code_change(record),
            format_log_user_actions(record),
            format_time_limit_binding(record, snapshot),
            format_section_access(record, snapshot, show_names=show_names),
            format_pg_access(record, snapshot, show_names=show_names),
            ",".join(record.flags) if record.flags else "-",
            record.comment,
        ]
        if include_raw_metadata:
            row = [row[0], record.raw_id_bytes, *row[1:], str(record.offset)]
        rows.append(tuple(row))

    if fmt == "tsv":
        for row in rows:
            print("\t".join(row))
        return

    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())


def invert_blob(data: bytes) -> bytes:
    return bytes(byte ^ 0xFF for byte in data)


def _parse_lsblk_pairs(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        pairs = dict(re.findall(r'(\w+)="([^"]*)"', line))
        if pairs:
            rows.append(pairs)
    return rows


def resolve_labeled_block_device(
    device: str | None,
    *,
    label: str,
    by_label_link: Path,
    option_name: str,
) -> str:
    if device and device != "auto":
        path = Path(device)
        return str(path.resolve()) if path.exists() else device

    if by_label_link.exists():
        return str(by_label_link.resolve())

    result = subprocess.run(
        ["lsblk", "-P", "-o", "PATH,LABEL,TYPE"],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode == 0:
        for row in _parse_lsblk_pairs(result.stdout):
            if row.get("LABEL") == label and row.get("TYPE") == "part":
                return row["PATH"]

    raise SystemExit(
        f"Unable to resolve the {label} block device. "
        f"Connect the panel or pass --{option_name} /dev/sdX1 explicitly."
    )


def resolve_flexi_cfg_device(device: str | None = None) -> str:
    return resolve_labeled_block_device(
        device,
        label=DEFAULT_FLEXI_CFG_LABEL,
        by_label_link=DEFAULT_FLEXI_CFG_LINK,
        option_name="device",
    )


def resolve_flexi_log_device(device: str | None = None) -> str:
    return resolve_labeled_block_device(
        device,
        label=DEFAULT_FLEXI_LOG_LABEL,
        by_label_link=DEFAULT_FLEXI_LOG_LINK,
        option_name="log-device",
    )


def block_device_argument_help(*, label: str) -> str:
    return (
        f"{label} block device or 'auto' to prefer /dev/disk/by-label/{label} "
        "and fall back to lsblk."
    )


def add_flexi_cfg_device_argument(parser: argparse.ArgumentParser, *, option: str = "--device") -> None:
    parser.add_argument(option, default="auto", help=block_device_argument_help(label=DEFAULT_FLEXI_CFG_LABEL))


def add_flexi_log_device_argument(parser: argparse.ArgumentParser, *, option: str = "--log-device") -> None:
    parser.add_argument(option, default="auto", help=block_device_argument_help(label=DEFAULT_FLEXI_LOG_LABEL))


def print_export_snapshot_summary(
    snapshot: "ExportSnapshot",
    *,
    device: str | None = None,
    resolver: Callable[[str | None], str] | None = None,
) -> None:
    print(f"wrote {snapshot.path}")
    print(f"sha256 {snapshot.sha256}")
    if device is not None:
        resolve = resolver or resolve_flexi_cfg_device
        print(f"device {resolve(device)}")
    print(f"users_raw {len(snapshot.raw_records)}")
    print(f"users_deduped {len(snapshot.records)}")


def is_device_mounted(device: str) -> bool:
    return get_device_mountpoint(device) is not None


def get_device_mountpoint(device: str) -> Path | None:
    resolved_device = resolve_flexi_cfg_device(device)
    result = subprocess.run(
        ["lsblk", "-P", "-o", "PATH,MOUNTPOINT", resolved_device],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    rows = _parse_lsblk_pairs(result.stdout)
    for row in rows:
        if row.get("PATH") == resolved_device and row.get("MOUNTPOINT"):
            return Path(row["MOUNTPOINT"])
    return None


def default_export_output(prefix: str) -> Path:
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    return Path("/tmp") / f"{timestamp}_{prefix}_EXPORT.CFG.bin"


def default_sector_output(prefix: str) -> Path:
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    return Path("/tmp") / f"{timestamp}_{prefix}_IMPORT-sector.bin"


def decode_user_id(id_bytes: bytes) -> Optional[int]:
    if len(id_bytes) == 1:
        return id_bytes[0]
    if len(id_bytes) == 3 and id_bytes[:2] == b"\xcd\x02":
        return 0x200 + id_bytes[2]
    return None


def encode_msgpack_int_hex(value: int) -> str:
    if 0 <= value <= 0x7F:
        return f"{value:02x}"
    if 0 <= value <= 0xFF:
        return "cc" + f"{value:02x}"
    if 0 <= value <= 0xFFFF:
        return "cd" + value.to_bytes(2, "big").hex()
    if 0 <= value <= 0xFFFFFFFF:
        return "ce" + value.to_bytes(4, "big").hex()
    return f"{value:x}"


def decode_msgpack_string(data: bytes, start: int) -> str:
    if start >= len(data):
        return ""
    marker = data[start]
    if 0xA0 <= marker <= 0xBF:
        length = marker - 0xA0
        offset = start + 1
    elif marker == 0xD9 and start + 1 < len(data):
        length = data[start + 1]
        offset = start + 2
    elif marker == 0xDA and start + 2 < len(data):
        length = int.from_bytes(data[start + 1 : start + 3], "big")
        offset = start + 3
    elif marker == 0xDB and start + 4 < len(data):
        length = int.from_bytes(data[start + 1 : start + 5], "big")
        offset = start + 5
    else:
        return ""
    return data[offset : offset + length].decode("utf-8", "replace")


def decode_msgpack_bin(data: bytes, start: int) -> tuple[bytes | None, int]:
    if start >= len(data):
        return None, start
    marker = data[start]
    if marker == 0xC4 and start + 1 < len(data):
        length = data[start + 1]
        offset = start + 2
    elif marker == 0xC5 and start + 2 < len(data):
        length = int.from_bytes(data[start + 1 : start + 3], "big")
        offset = start + 3
    elif marker == 0xC6 and start + 4 < len(data):
        length = int.from_bytes(data[start + 1 : start + 5], "big")
        offset = start + 5
    else:
        return None, start
    return data[offset : offset + length], offset + length


def decode_msgpack_int(data: bytes, start: int) -> tuple[Optional[int], int]:
    if start >= len(data):
        return None, start
    marker = data[start]
    if marker <= 0x7F:
        return marker, start + 1
    if marker >= 0xE0:
        return marker - 0x100, start + 1
    if marker == 0xCC and start + 1 < len(data):
        return data[start + 1], start + 2
    if marker == 0xCD and start + 2 < len(data):
        return int.from_bytes(data[start + 1 : start + 3], "big"), start + 3
    if marker == 0xCE and start + 4 < len(data):
        return int.from_bytes(data[start + 1 : start + 5], "big"), start + 5
    if marker == 0xCF and start + 8 < len(data):
        return int.from_bytes(data[start + 1 : start + 9], "big"), start + 9
    if marker == 0xD0 and start + 1 < len(data):
        return int.from_bytes(data[start + 1 : start + 2], "big", signed=True), start + 2
    if marker == 0xD1 and start + 2 < len(data):
        return int.from_bytes(data[start + 1 : start + 3], "big", signed=True), start + 3
    if marker == 0xD2 and start + 4 < len(data):
        return int.from_bytes(data[start + 1 : start + 5], "big", signed=True), start + 5
    if marker == 0xD3 and start + 8 < len(data):
        return int.from_bytes(data[start + 1 : start + 9], "big", signed=True), start + 9
    return None, start


def decode_msgpack_value(data: bytes, start: int) -> tuple[object | None, int]:
    if start >= len(data):
        return None, start

    marker = data[start]

    if marker == 0xC0:
        return None, start + 1
    if marker == 0xC2:
        return False, start + 1
    if marker == 0xC3:
        return True, start + 1
    if marker <= 0x7F or marker >= 0xE0 or marker in {0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3}:
        value, end = decode_msgpack_int(data, start)
        if end <= start:
            raise ValueError(f"Invalid MessagePack integer at offset 0x{start:04x}")
        return value, end
    if marker in {0xC4, 0xC5, 0xC6}:
        value, end = decode_msgpack_bin(data, start)
        if end <= start:
            raise ValueError(f"Invalid MessagePack binary blob at offset 0x{start:04x}")
        return value, end
    if 0xA0 <= marker <= 0xBF or marker in {0xD9, 0xDA, 0xDB}:
        end = _skip_msgpack_string(data, start)
        if end <= start:
            raise ValueError(f"Invalid MessagePack string at offset 0x{start:04x}")
        return decode_msgpack_string(data, start), end
    if 0x90 <= marker <= 0x9F:
        length = marker - 0x90
        cursor = start + 1
        items: list[object | None] = []
        for _ in range(length):
            item, next_cursor = decode_msgpack_value(data, cursor)
            if next_cursor <= cursor:
                raise ValueError(f"Invalid MessagePack array item at offset 0x{cursor:04x}")
            cursor = next_cursor
            items.append(item)
        return items, cursor
    if 0x80 <= marker <= 0x8F:
        length = marker - 0x80
        cursor = start + 1
        mapping: dict[object, object | None] = {}
        for _ in range(length):
            key, next_cursor = decode_msgpack_value(data, cursor)
            if next_cursor <= cursor:
                raise ValueError(f"Invalid MessagePack map key at offset 0x{cursor:04x}")
            cursor = next_cursor
            value, next_cursor = decode_msgpack_value(data, cursor)
            if next_cursor <= cursor:
                raise ValueError(f"Invalid MessagePack map value at offset 0x{cursor:04x}")
            cursor = next_cursor
            mapping[normalize_msgpack_key(key)] = value
        return mapping, cursor
    if marker == 0xDC and start + 2 < len(data):
        length = int.from_bytes(data[start + 1 : start + 3], "big")
        cursor = start + 3
        items: list[object | None] = []
        for _ in range(length):
            item, next_cursor = decode_msgpack_value(data, cursor)
            if next_cursor <= cursor:
                raise ValueError(f"Invalid MessagePack array16 item at offset 0x{cursor:04x}")
            cursor = next_cursor
            items.append(item)
        return items, cursor
    if marker == 0xDE and start + 2 < len(data):
        length = int.from_bytes(data[start + 1 : start + 3], "big")
        cursor = start + 3
        mapping: dict[object, object | None] = {}
        for _ in range(length):
            key, next_cursor = decode_msgpack_value(data, cursor)
            if next_cursor <= cursor:
                raise ValueError(f"Invalid MessagePack map16 key at offset 0x{cursor:04x}")
            cursor = next_cursor
            value, next_cursor = decode_msgpack_value(data, cursor)
            if next_cursor <= cursor:
                raise ValueError(f"Invalid MessagePack map16 value at offset 0x{cursor:04x}")
            cursor = next_cursor
            mapping[normalize_msgpack_key(key)] = value
        return mapping, cursor
    if marker == 0xDF and start + 4 < len(data):
        length = int.from_bytes(data[start + 1 : start + 5], "big")
        cursor = start + 5
        mapping: dict[object, object | None] = {}
        for _ in range(length):
            key, next_cursor = decode_msgpack_value(data, cursor)
            if next_cursor <= cursor:
                raise ValueError(f"Invalid MessagePack map32 key at offset 0x{cursor:04x}")
            cursor = next_cursor
            value, next_cursor = decode_msgpack_value(data, cursor)
            if next_cursor <= cursor:
                raise ValueError(f"Invalid MessagePack map32 value at offset 0x{cursor:04x}")
            cursor = next_cursor
            mapping[normalize_msgpack_key(key)] = value
        return mapping, cursor
    raise ValueError(f"Unsupported MessagePack marker 0x{marker:02x} at offset 0x{start:04x}")


def _skip_msgpack_string(data: bytes, start: int) -> int:
    marker = data[start]
    if 0xA0 <= marker <= 0xBF:
        return start + 1 + (marker - 0xA0)
    if marker == 0xD9 and start + 1 < len(data):
        return start + 2 + data[start + 1]
    if marker == 0xDA and start + 2 < len(data):
        return start + 3 + int.from_bytes(data[start + 1 : start + 3], "big")
    if marker == 0xDB and start + 4 < len(data):
        return start + 5 + int.from_bytes(data[start + 1 : start + 5], "big")
    return start


def _extract_export_root_fields(blob: bytes) -> dict[int, object | None]:
    unpacker = msgpack.Unpacker(raw=False, strict_map_key=False)
    unpacker.feed(blob)
    try:
        root = next(unpacker)
    except Exception:
        return {}
    if not isinstance(root, dict):
        return {}
    return {key: value for key, value in root.items() if isinstance(key, int)}


def normalize_msgpack_key(key: object | None) -> object:
    if isinstance(key, list):
        return tuple(normalize_msgpack_key(item) for item in key)
    if isinstance(key, dict):
        return tuple((normalize_msgpack_key(item_key), normalize_msgpack_key(item_value)) for item_key, item_value in key.items())
    return key


def value_as_string(value: object | None) -> str:
    return value if isinstance(value, str) else ""


def value_as_bool(value: object | None) -> Optional[bool]:
    return value if isinstance(value, bool) else None


def value_as_int(value: object | None) -> Optional[int]:
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


def value_as_flag_bool(value: object | None) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    return None


def collect_nested_strings(value: object | None) -> list[str]:
    strings: list[str] = []

    def visit(node: object | None) -> None:
        if isinstance(node, str):
            if node:
                strings.append(node)
            return
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if isinstance(node, dict):
            for item in node.values():
                visit(item)

    visit(value)
    return strings


def value_as_bytes(value: object | None) -> bytes | None:
    return bytes(value) if isinstance(value, (bytes, bytearray)) else None


def _decode_ascii_blob(value: object | None) -> str:
    if isinstance(value, str):
        return value
    data = value_as_bytes(value)
    if data is None:
        return ""
    return data.rstrip(b"\x00").decode("ascii", "replace")


def _format_comm_channel_label(channel_id: int | None, objects_by_id: dict[int, ExportObjectRecord]) -> str:
    if channel_id is None:
        return ""
    if channel_id == 0:
        return "none"
    object_record = objects_by_id.get(channel_id)
    if object_record is not None:
        return f"{channel_id}:{object_record.name}"
    return str(channel_id)


def _extract_export_main_config(root_fields: dict[int, object | None]) -> ExportMainConfig | None:
    fields = root_fields.get(2)
    if not isinstance(fields, dict):
        return None
    return ExportMainConfig(
        users_raw=value_as_int(fields.get(0)),
        peripheries_raw=value_as_int(fields.get(1)),
        sections_raw=value_as_int(fields.get(2)),
        pgs_raw=value_as_int(fields.get(3)),
        language_id=value_as_string(fields.get(4)),
        language_raw=value_as_int(fields.get(5)),
        code_len_raw=value_as_int(fields.get(6)),
        code_prefix=value_as_bool(fields.get(7)),
        wpp_dedicated=value_as_bool(fields.get(8)),
        rfid_restrict=value_as_bool(fields.get(9)),
        simple_log=value_as_bool(fields.get(10)),
        default_config=value_as_bool(fields.get(11)),
        language_unlock_code=value_as_string(fields.get(12)),
        name=value_as_string(fields.get(13)),
    )


def _extract_export_comm_flags(value: object | None) -> ExportCommunicationFlags:
    fields = value if isinstance(value, dict) else {}
    return ExportCommunicationFlags(
        pcos_on=value_as_flag_bool(fields.get(0)),
        ytun_persistent=value_as_flag_bool(fields.get(1)),
        voice_menu_without_code=value_as_flag_bool(fields.get(2)),
        ytun_log_disable=value_as_flag_bool(fields.get(3)),
        wpp_lock=value_as_flag_bool(fields.get(4)),
        ytun_device_info_disable=value_as_flag_bool(fields.get(5)),
        ytun_enable=value_as_flag_bool(fields.get(6)),
        comm_configured=value_as_flag_bool(fields.get(7)),
        gsm_autoconfig_disabled=value_as_flag_bool(fields.get(8)),
        send_sms_on_failed_arm=value_as_flag_bool(fields.get(9)),
    )


def _extract_export_comm_sdc(
    value: object | None,
    *,
    objects_by_id: dict[int, ExportObjectRecord],
) -> ExportCommunicationSDCConfig | None:
    fields = value if isinstance(value, dict) else None
    if fields is None:
        return None
    flags_raw = value_as_int(fields.get(0))
    sdc_position = value_as_int(fields.get(1))
    return ExportCommunicationSDCConfig(
        flags_raw=flags_raw,
        allow_reports_alarm_voice=None if flags_raw is None else bool(flags_raw & 0x1),
        sdc_position=sdc_position,
        sdc_position_name=_format_comm_channel_label(sdc_position, objects_by_id),
    )


def _extract_export_communications(
    root_fields: dict[int, object | None],
    *,
    objects_by_id: dict[int, ExportObjectRecord],
) -> ExportCommunicationsConfig | None:
    fields = root_fields.get(5)
    if not isinstance(fields, dict):
        return None

    def decode_channel_list(value: object | None) -> tuple[list[int], list[str]]:
        raw_values: list[int] = []
        labels: list[str] = []
        if isinstance(value, list):
            for item in value:
                channel_id = value_as_int(item)
                if channel_id is None:
                    continue
                raw_values.append(channel_id)
                labels.append(_format_comm_channel_label(channel_id, objects_by_id))
        return raw_values, labels

    data_channels_raw, data_channels = decode_channel_list(fields.get(7))
    sms_channels_raw, sms_channels = decode_channel_list(fields.get(8))
    voice_channels_raw, voice_channels = decode_channel_list(fields.get(9))
    aes_key = value_as_bytes(fields.get(3)) or b""
    rf_key = value_as_bytes(fields.get(5)) or b""
    service_access_raw = value_as_int(fields.get(12))

    return ExportCommunicationsConfig(
        flags=_extract_export_comm_flags(fields.get(0)),
        ytun_url=value_as_string(fields.get(1)),
        sms_resend_to_user=value_as_int(fields.get(2)),
        aes_key_ascii=_decode_ascii_blob(aes_key),
        aes_key_hex=aes_key.hex(),
        ytun_key=value_as_string(fields.get(4)),
        rf_key_ascii=_decode_ascii_blob(rf_key),
        rf_key_hex=rf_key.hex(),
        y0_hb_time_raw=value_as_int(fields.get(6)),
        data_channels_raw=data_channels_raw,
        data_channels=data_channels,
        sms_channels_raw=sms_channels_raw,
        sms_channels=sms_channels,
        voice_channels_raw=voice_channels_raw,
        voice_channels=voice_channels,
        local_listen_port_raw=value_as_int(fields.get(10)),
        sdc=_extract_export_comm_sdc(fields.get(11), objects_by_id=objects_by_id),
        service_access_raw=service_access_raw,
        service_access_name=ARC_SERVICE_ACCESS_NAMES.get(service_access_raw, ""),
    )


def parse_card_value(value: object | None) -> str:
    cards = parse_card_values(value)
    return cards[0] if cards else ""


def parse_card_values(value: object | None) -> list[str]:
    if not isinstance(value, list):
        return []
    cards: list[str] = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        card = entry.get(0)
        if isinstance(card, str):
            cards.append(card)
        else:
            cards.append("")
    while cards and not cards[-1]:
        cards.pop()
    return cards


def decode_bitmask_ids(mask: int | None, *, bits: int, first_id: int = 1) -> list[int]:
    if mask is None:
        return []
    return [first_id + bit for bit in range(bits) if mask & (1 << bit)]


def decode_pg_ids(pg_masks: object | None) -> tuple[list[int], list[int]]:
    if not isinstance(pg_masks, list):
        return [], []
    raw_masks = [value_as_int(item) or 0 for item in pg_masks]
    ids: list[int] = []
    for group_index, mask in enumerate(raw_masks):
        for bit in range(32):
            if mask & (1 << bit):
                ids.append(group_index * 32 + bit + 1)
    return raw_masks, ids


def decode_user_flags(flags_raw: int | None) -> list[str]:
    if flags_raw is None:
        return []
    names: list[str] = []
    bit = 0
    remaining = flags_raw
    while remaining:
        if remaining & 1:
            names.append(USER_FLAG_NAMES.get(bit, f"bit{bit}"))
        remaining >>= 1
        bit += 1
    return names


def decode_user_enabled(flags_raw: int | None) -> Optional[bool]:
    if flags_raw is None:
        return None
    return not bool(flags_raw & 0x1)


def decode_pg_num(value: object | None) -> Optional[int]:
    raw_value = value_as_int(value)
    if raw_value is None or raw_value <= 0 or raw_value > 128:
        return None
    return raw_value


def decode_parent_user_no(value: object | None) -> Optional[int]:
    raw_value = value_as_int(value)
    if raw_value is None or raw_value < 0:
        return None
    return raw_value


def decode_rights_name(
    permissions_raw: Optional[int],
    *,
    user_id: Optional[int],
    name: str,
    phone: str,
    code: str,
    card: str,
    time_limited_group_raw: Optional[int],
) -> str:
    mapping = {
        0: "coNoAccess",
        1: "coPanic",
        2: "coPGOnly",
        256: "coArmOnly",
        799: "coUserGuard",
        827: "coUser",
        2875: "coService",
        4639: "coPCOGuard",
        6971: "coPCO",
        1851: "coMaster",
        811: "coUserNoSelfedit",
    }
    if permissions_raw == 827 and user_id is not None and 603 <= user_id <= 610 and name.startswith("User ") and not code and not card:
        return "WPPPhone"
    if permissions_raw == 811 and (time_limited_group_raw or 0) > 0:
        return "coUserTimeLimitedNoSelfedit"
    if permissions_raw == 827 and (time_limited_group_raw or 0) > 0:
        return "coUserTimeLimited"
    if permissions_raw in mapping:
        return mapping[permissions_raw]
    if permissions_raw is None:
        return ""
    return f"raw:{permissions_raw}"


def dedupe_user_records(records: Iterable[UserRecord]) -> list[UserRecord]:
    anonymous_records: list[UserRecord] = []
    latest_by_id: dict[int, UserRecord] = {}
    for record in sorted(records, key=lambda item: item.offset):
        if record.user_id is None:
            anonymous_records.append(record)
            continue
        latest_by_id[record.user_id] = record
    return [*anonymous_records, *(latest_by_id[user_id] for user_id in sorted(latest_by_id))]


def _iter_export_collection_hits(
    blob: bytes,
    *,
    collection_id: int,
    expected_keys: set[int] | None = None,
) -> list[tuple[int, int, dict[object, object | None]]]:
    pattern = bytes([collection_id, 0x81])
    hits: list[tuple[int, int, dict[object, object | None]]] = []
    seen: set[tuple[int, int]] = set()

    def maybe_store(offset: int, item_id: object | None, fields: object | None) -> None:
        if not isinstance(item_id, int) or not isinstance(fields, dict):
            return
        if expected_keys is not None and set(fields.keys()) != expected_keys:
            return
        key = (offset, item_id)
        if key in seen:
            return
        seen.add(key)
        hits.append((offset, item_id, fields))

    try:
        leading_value, cursor = decode_msgpack_value(blob, 0)
        leading_record, _next = decode_msgpack_value(blob, cursor)
    except Exception:
        leading_value = None
        leading_record = None
    if collection_id == 0x06 and isinstance(leading_value, int):
        maybe_store(0, leading_value, leading_record)
    elif isinstance(leading_value, int) and leading_value == collection_id:
        if isinstance(leading_record, dict) and len(leading_record) == 1:
            item_id, fields = next(iter(leading_record.items()))
            maybe_store(0, item_id, fields)

    offset = 0
    while True:
        offset = blob.find(pattern, offset)
        if offset == -1:
            break
        try:
            parsed_collection_id, cursor = decode_msgpack_value(blob, offset)
            record, _next = decode_msgpack_value(blob, cursor)
        except Exception:
            offset += 1
            continue
        if parsed_collection_id != collection_id or not isinstance(record, dict) or len(record) != 1:
            offset += 1
            continue
        item_id, fields = next(iter(record.items()))
        maybe_store(offset, item_id, fields)
        offset += 1

    return hits


def extract_users(path: Path, *, dedupe: str = "raw") -> list[UserRecord]:
    blob = invert_blob(path.read_bytes())
    hits = _iter_export_collection_hits(blob, collection_id=0x07, expected_keys=set(range(12)))
    users: list[UserRecord] = []
    for offset, item_id, field_map_value in hits:
        name = value_as_string(field_map_value.get(4))
        if not name:
            continue

        user_id = item_id
        phone = value_as_string(field_map_value.get(5))
        code = value_as_string(field_map_value.get(6))
        cards = parse_card_values(field_map_value.get(7))
        comment = value_as_string(field_map_value.get(10))
        flags_raw = value_as_int(field_map_value.get(0))
        access_raw = value_as_int(field_map_value.get(1))
        section_access_mask_raw = value_as_int(field_map_value.get(2))
        section_ids = decode_bitmask_ids(section_access_mask_raw, bits=15, first_id=1)
        pg_access_masks_raw, pg_ids = decode_pg_ids(field_map_value.get(3))
        pg_num_if_ring_raw = value_as_int(field_map_value.get(8))
        time_limited_group_raw = value_as_int(field_map_value.get(9))
        parent_user_no_raw = decode_parent_user_no(field_map_value.get(11))

        users.append(
            UserRecord(
                offset=offset,
                user_id=user_id,
                raw_id_bytes=encode_msgpack_int_hex(item_id),
                flags_raw=flags_raw,
                flags=decode_user_flags(flags_raw),
                access_raw=access_raw,
                rights=decode_rights_name(
                    access_raw,
                    user_id=user_id,
                    name=name,
                    phone=phone,
                    code=code,
                    card=cards[0] if cards else "",
                    time_limited_group_raw=time_limited_group_raw,
                ),
                enabled=decode_user_enabled(flags_raw),
                section_access_mask_raw=section_access_mask_raw,
                section_ids=section_ids,
                pg_access_masks_raw=pg_access_masks_raw,
                pg_ids=pg_ids,
                name=name,
                phone=phone,
                code=code,
                cards=cards,
                comment=comment,
                pg_num_if_ring_raw=pg_num_if_ring_raw,
                time_limited_group_raw=time_limited_group_raw,
                parent_user_no_raw=parent_user_no_raw,
            )
        )

    if dedupe == "raw":
        return users
    if dedupe == "dedupe":
        return dedupe_user_records(users)
    raise ValueError(f"Unsupported dedupe mode: {dedupe}")


def read_decoded_export_blob(path: Path) -> bytes:
    return invert_blob(path.read_bytes())


def _extract_export_collection_records(
    blob: bytes,
    *,
    collection_id: int,
    expected_keys: set[int],
) -> dict[int, dict[object, object | None]]:
    records: dict[int, dict[object, object | None]] = {}
    for _offset, item_id, fields in _iter_export_collection_hits(
        blob,
        collection_id=collection_id,
        expected_keys=expected_keys,
    ):
        if item_id in records:
            continue
        records[item_id] = fields
    return records


def decode_time_value(value: object | None) -> str | None:
    if not isinstance(value, dict):
        return None
    minute = value_as_int(value.get(0))
    hour = value_as_int(value.get(1))
    if minute is None or hour is None:
        return None
    if hour == 99 and minute == 99:
        return None
    return f"{hour:02d}:{minute:02d}"


def _decode_time_limit_day(day_index: int, value: object | None) -> ExportUserTimeLimitDay:
    section_rules: list[ExportUserTimeLimitSectionRule] = []
    if isinstance(value, dict):
        on1_values = value.get(0)
        off1_values = value.get(1)
        on2_values = value.get(2)
        off2_values = value.get(3)
        for section_bit in range(15):
            windows: list[ExportUserTimeLimitWindow] = []
            on1 = decode_time_value(on1_values[section_bit] if isinstance(on1_values, list) and section_bit < len(on1_values) else None)
            off1 = decode_time_value(off1_values[section_bit] if isinstance(off1_values, list) and section_bit < len(off1_values) else None)
            on2 = decode_time_value(on2_values[section_bit] if isinstance(on2_values, list) and section_bit < len(on2_values) else None)
            off2 = decode_time_value(off2_values[section_bit] if isinstance(off2_values, list) and section_bit < len(off2_values) else None)
            if on1 or off1:
                windows.append(ExportUserTimeLimitWindow(on=on1 or "?", off=off1 or "?"))
            if on2 or off2:
                windows.append(ExportUserTimeLimitWindow(on=on2 or "?", off=off2 or "?"))
            if windows:
                section_rules.append(ExportUserTimeLimitSectionRule(section_id=section_bit + 1, windows=windows))
    return ExportUserTimeLimitDay(
        day_index=day_index,
        day_name=WEEKDAY_NAMES[day_index],
        section_rules=section_rules,
    )


def extract_users_time_limits(path: Path) -> dict[int, ExportUserTimeLimitGroup]:
    blob = read_decoded_export_blob(path)
    fields_by_group = _extract_export_collection_records(blob, collection_id=0x08, expected_keys={0, 1})
    groups_by_id: dict[int, ExportUserTimeLimitGroup] = {}
    for group_id, fields in fields_by_group.items():
        day_values = fields.get(0)
        days = [
            _decode_time_limit_day(day_index, day_values[day_index] if isinstance(day_values, list) and day_index < len(day_values) else None)
            for day_index in range(7)
        ]
        groups_by_id[group_id] = ExportUserTimeLimitGroup(
            group_id=group_id,
            group_display_id=group_id + 1,
            comment=value_as_string(fields.get(1)),
            days=days,
        )
    return groups_by_id


def _has_meaningful_arc_specific_data(fields: dict[object, object | None]) -> bool:
    for value in fields.values():
        if isinstance(value, str) and value:
            return True
        if isinstance(value, bool) and value:
            return True
        if isinstance(value, int) and value != 0:
            return True
        if collect_nested_strings(value):
            return True
    return False


def _parse_arc_specific_record(index: int, fields: dict[object, object | None]) -> ExportArcSpecificRecord | None:
    name = ARC_SPECIFIC_NAMES.get(index, f"specific_{index}")
    endpoints: list[str] = []
    crypt_key = ""
    token_type_raw = None
    key_type_raw = None
    prefix_raw = None
    backward_compatibility = None
    text_sync_enable = None
    proto_version_raw = None
    delivery_timeout_raw = None
    disable_sms = None
    limiter_soft_raw = None
    limiter_hard_raw = None

    if index == 0:
        endpoints = collect_nested_strings(fields.get(0))
        token_type_raw = value_as_int(fields.get(1))
        key_type_raw = value_as_int(fields.get(7))
        prefix_raw = value_as_int(fields.get(8))
        crypt_key = value_as_string(fields.get(9)).strip()
    elif index in {1, 2}:
        endpoints = collect_nested_strings(fields.get(0)) + collect_nested_strings(fields.get(1))
    elif index == 3:
        endpoints = collect_nested_strings(fields.get(0))
        backward_compatibility = value_as_bool(fields.get(1))
        text_sync_enable = value_as_bool(fields.get(2))
        proto_version_raw = value_as_int(fields.get(4))
        crypt_key = value_as_string(fields.get(5)).strip()
    elif index == 4:
        endpoints = collect_nested_strings(fields.get(0))
        delivery_timeout_raw = value_as_int(fields.get(1))
    elif index == 5:
        endpoints = collect_nested_strings(fields.get(0))
        disable_sms = value_as_bool(fields.get(1))
        proto_version_raw = value_as_int(fields.get(2))
        crypt_key = value_as_string(fields.get(3)).strip()
        limiter_soft_raw = value_as_int(fields.get(4))
        limiter_hard_raw = value_as_int(fields.get(5))
    elif index == 6:
        delivery_timeout_raw = value_as_int(fields.get(0))

    record = ExportArcSpecificRecord(
        name=name,
        endpoints=endpoints,
        crypt_key=crypt_key,
        token_type_raw=token_type_raw,
        key_type_raw=key_type_raw,
        prefix_raw=prefix_raw,
        backward_compatibility=backward_compatibility,
        text_sync_enable=text_sync_enable,
        proto_version_raw=proto_version_raw,
        delivery_timeout_raw=delivery_timeout_raw,
        disable_sms=disable_sms,
        limiter_soft_raw=limiter_soft_raw,
        limiter_hard_raw=limiter_hard_raw,
    )

    if _has_meaningful_arc_specific_data(fields):
        return record
    return None


def extract_export_catalog(path: Path) -> ExportCatalogSnapshot:
    blob = read_decoded_export_blob(path)
    root_fields = _extract_export_root_fields(blob)
    users = extract_users(path, dedupe="dedupe")
    time_limit_groups_by_id = extract_users_time_limits(path)

    section_fields = _extract_export_collection_records(blob, collection_id=0x06, expected_keys={0, 1, 2, 3, 4})
    object_fields = _extract_export_collection_records(blob, collection_id=0x09, expected_keys={0, 1, 2, 3, 4, 5, 6, 7})
    hardware_fields = _extract_export_collection_records(blob, collection_id=0x0B, expected_keys={0, 1, 2, 3, 4, 5, 6})
    pg_fields = _extract_export_collection_records(
        blob,
        collection_id=0x0C,
        expected_keys=set(range(18)),
    )
    arc_fields = _extract_export_collection_records(
        blob,
        collection_id=0x11,
        expected_keys=set(range(16)),
    )

    sections_by_id: dict[int, ExportSectionRecord] = {}
    for section_id, fields in section_fields.items():
        name = value_as_string(fields.get(0)).strip()
        if not name:
            continue
        sections_by_id[section_id] = ExportSectionRecord(
            section_id=section_id,
            display_id=section_id,
            name=name,
            flags_raw=value_as_int(fields.get(1)),
            options_raw=value_as_int(fields.get(2)),
            state_raw=value_as_int(fields.get(3)),
            comment=value_as_string(fields.get(4)),
        )

    objects_by_id: dict[int, ExportObjectRecord] = {}
    for object_id, fields in object_fields.items():
        name = value_as_string(fields.get(6)).strip()
        if not name:
            continue
        pg_masks_value = fields.get(5)
        pg_masks = [value_as_int(item) or 0 for item in pg_masks_value] if isinstance(pg_masks_value, list) else []
        sections_count = len(sections_by_id)
        section_id = value_as_int(fields.get(2))
        if section_id is not None and section_id < 0:
            section_id = None
        if section_id is not None and sections_count and section_id >= sections_count:
            section_id = None
        objects_by_id[object_id] = ExportObjectRecord(
            object_id=object_id,
            name=name,
            kind_raw=value_as_int(fields.get(1)),
            section_id=section_id,
            type_raw=value_as_int(fields.get(3)),
            subtype_raw=value_as_int(fields.get(4)),
            pg_masks=pg_masks,
            comment=value_as_string(fields.get(7)),
        )

    hardware_by_id: dict[int, ExportHardwareRecord] = {}
    for object_id, fields in hardware_fields.items():
        model = value_as_string(fields.get(0)).strip()
        if not model:
            continue
        hardware_by_id[object_id] = ExportHardwareRecord(
            object_id=object_id,
            model=model,
            hardware_code=value_as_string(fields.get(1)).strip(),
            firmware=value_as_string(fields.get(2)).strip(),
            field3_raw=value_as_int(fields.get(3)),
            field4_raw=value_as_int(fields.get(4)),
            field5_raw=value_as_int(fields.get(5)),
        )

    pgs_by_id: dict[int, ExportPGRecord] = {}
    for pg_id, fields in pg_fields.items():
        name = value_as_string(fields.get(16)).strip()
        if not name:
            continue
        section_id = value_as_int(fields.get(5))
        sections_count = len(sections_by_id)
        if section_id is not None and section_id < 0:
            section_id = None
        if section_id is not None and sections_count and section_id >= sections_count:
            section_id = None
        pgs_by_id[pg_id] = ExportPGRecord(
            pg_id=pg_id,
            display_id=pg_id + 1,
            name=name,
            type_raw=value_as_int(fields.get(0)),
            section_id=section_id,
            field6_raw=value_as_int(fields.get(6)),
            comment=value_as_string(fields.get(17)),
        )

    arcs_by_id: dict[int, ExportARCRecord] = {}
    for arc_id, fields in arc_fields.items():
        protocol_type_raw = value_as_int(fields.get(0))
        channel_id = value_as_int(fields.get(11))
        channel_name = ""
        if channel_id == 0:
            channel_name = "automatic"
        elif channel_id is not None and channel_id in objects_by_id:
            channel_name = objects_by_id[channel_id].name
        ats_class_raw = value_as_int(fields.get(14))
        service_access_raw = value_as_int(fields.get(15))

        specific_by_name: dict[str, ExportArcSpecificRecord] = {}
        specific_value = fields.get(13)
        if isinstance(specific_value, dict):
            for index, specific_fields in specific_value.items():
                if not isinstance(index, int) or not isinstance(specific_fields, dict):
                    continue
                specific_record = _parse_arc_specific_record(index, specific_fields)
                if specific_record is None:
                    continue
                specific_by_name[specific_record.name] = specific_record

        section_object_ids = []
        object_ids_value = fields.get(5)
        if isinstance(object_ids_value, list):
            for item in object_ids_value:
                object_id = value_as_int(item)
                if object_id is None:
                    continue
                section_object_ids.append(object_id)

        arcs_by_id[arc_id] = ExportARCRecord(
            arc_id=arc_id,
            protocol_type_raw=protocol_type_raw,
            protocol_name=ARC_PROTOCOL_NAMES.get(
                protocol_type_raw,
                "" if protocol_type_raw is None else f"ARC_PROTO_{protocol_type_raw}",
            ),
            enabled=value_as_bool(fields.get(1)),
            contest_in_fixed_time=value_as_bool(fields.get(2)),
            backup=value_as_bool(fields.get(3)),
            backup_test_reports=value_as_bool(fields.get(4)),
            section_object_ids=section_object_ids,
            err_wait_time_raw=value_as_int(fields.get(6)),
            report_time_raw=value_as_int(fields.get(7)),
            report_time_backup_raw=value_as_int(fields.get(8)),
            retry_count_raw=value_as_int(fields.get(9)),
            time_out_raw=value_as_int(fields.get(10)),
            channel_id=channel_id,
            channel_name=channel_name,
            comment=value_as_string(fields.get(12)),
            ats_class_raw=ats_class_raw,
            ats_class_name=ARC_ATS_CLASS_NAMES.get(ats_class_raw, ""),
            service_access_raw=service_access_raw,
            service_access_name=ARC_SERVICE_ACCESS_NAMES.get(service_access_raw, ""),
            specific_by_name=specific_by_name,
        )

    main_config = _extract_export_main_config(root_fields)
    communications = _extract_export_communications(root_fields, objects_by_id=objects_by_id)

    return ExportCatalogSnapshot(
        path=path,
        users=users,
        sections_by_id=sections_by_id,
        objects_by_id=objects_by_id,
        hardware_by_id=hardware_by_id,
        pgs_by_id=pgs_by_id,
        arcs_by_id=arcs_by_id,
        time_limit_groups_by_id=time_limit_groups_by_id,
        main_config=main_config,
        communications=communications,
    )


def iter_printable_strings(blob: bytes, *, min_length: int) -> Iterable[str]:
    pattern = re.compile(rb"[\x20-\x7e\xc0-\xff]{" + str(min_length).encode("ascii") + rb",}")
    for match in pattern.finditer(blob):
        yield match.group().decode("utf-8", "replace")


def read_export_direct(
    *,
    device: str,
    output: Path,
    start_lba: int = EXPORT_START_LBA,
    sectors: int = EXPORT_SECTORS,
) -> None:
    resolved_device = resolve_flexi_cfg_device(device)
    output.parent.mkdir(parents=True, exist_ok=True)
    if start_lba == EXPORT_START_LBA and sectors == EXPORT_SECTORS:
        file_bytes = _read_export_file_via_fat(device=resolved_device)
        if file_bytes is not None:
            output.write_bytes(file_bytes)
            return
    command = [
        "dd",
        f"if={resolved_device}",
        f"of={output}",
        f"bs={SECTOR_SIZE}",
        f"skip={start_lba}",
        f"count={sectors}",
        "iflag=direct",
        "status=none",
    ]
    if os.geteuid() != 0:
        command = ["sudo", "-n"] + command
    subprocess.run(command, check=True)


def _read_export_file_via_fat(*, device: str) -> bytes | None:
    """Read EXPORT.CFG by walking the FAT, or None if that is not possible.

    Falls back to the caller's raw-LBA read when it returns None.
    """

    try:
        data = FatVolumeReader(device).read_file(EXPORT_FILENAME_83)
    except Exception:
        return None
    return data or None


def _parse_fat_geometry(boot_sector: bytes) -> dict[str, int]:
    if len(boot_sector) < SECTOR_SIZE:
        raise ValueError("Short FAT boot sector.")
    bytes_per_sector = unpack_from("<H", boot_sector, 11)[0]
    sectors_per_cluster = boot_sector[13]
    reserved_sectors = unpack_from("<H", boot_sector, 14)[0]
    fat_count = boot_sector[16]
    root_entries = unpack_from("<H", boot_sector, 17)[0]
    sectors_per_fat = unpack_from("<H", boot_sector, 22)[0]
    if bytes_per_sector != SECTOR_SIZE or sectors_per_cluster <= 0 or fat_count <= 0 or sectors_per_fat <= 0:
        raise ValueError("Unsupported FAT geometry for EXPORT.CFG direct read.")
    root_dir_sectors = (root_entries * 32 + bytes_per_sector - 1) // bytes_per_sector
    data_start_sector = reserved_sectors + fat_count * sectors_per_fat + root_dir_sectors
    return {
        "bytes_per_sector": bytes_per_sector,
        "sectors_per_cluster": sectors_per_cluster,
        "cluster_size_bytes": bytes_per_sector * sectors_per_cluster,
        "reserved_sectors": reserved_sectors,
        "sectors_per_fat": sectors_per_fat,
        "root_dir_start_sector": reserved_sectors + fat_count * sectors_per_fat,
        "root_dir_sectors": root_dir_sectors,
        "data_start_sector": data_start_sector,
    }


def _find_fat_root_entry(root_dir: bytes, filename_83: bytes) -> tuple[int, int] | None:
    for offset in range(0, len(root_dir), 32):
        entry = root_dir[offset : offset + 32]
        if len(entry) < 32:
            break
        first = entry[0]
        if first == 0x00:
            break
        if first == 0xE5:
            continue
        attrs = entry[11]
        if attrs == 0x0F:
            continue
        if entry[:11] != filename_83:
            continue
        start_cluster = unpack_from("<H", entry, 26)[0]
        file_size = unpack_from("<I", entry, 28)[0]
        return start_cluster, file_size
    return None


def _follow_fat16_chain(*, fat: bytes, start_cluster: int, max_clusters: int) -> list[int]:
    clusters: list[int] = []
    seen: set[int] = set()
    cluster = start_cluster
    while cluster >= 2 and cluster not in seen and len(clusters) < max_clusters:
        seen.add(cluster)
        clusters.append(cluster)
        entry_offset = cluster * 2
        if entry_offset + 2 > len(fat):
            break
        next_cluster = unpack_from("<H", fat, entry_offset)[0]
        if next_cluster >= 0xFFF8 or next_cluster == 0x0000:
            break
        cluster = next_cluster
    return clusters


def _cluster_runs(clusters: list[int]) -> list[tuple[int, int]]:
    if not clusters:
        return []
    runs: list[tuple[int, int]] = []
    run_start = clusters[0]
    run_length = 1
    for cluster in clusters[1:]:
        if cluster == run_start + run_length:
            run_length += 1
            continue
        runs.append((run_start, run_length))
        run_start = cluster
        run_length = 1
    runs.append((run_start, run_length))
    return runs


@dataclass(frozen=True)
class FatDirEntry:
    """One 8.3 entry from a FAT16 root directory."""

    name_83: bytes
    attributes: int
    size: int
    start_cluster: int
    modified: str


class FatVolumeReader:
    """Read files off a FAT16 volume with raw block reads, without mounting.

    The panel exposes FLEXI_CFG and FLEXI_LOG as USB mass storage. Going
    through a kernel mount needs ``CAP_SYS_ADMIN`` — and, the way
    :func:`mount_device` is written, a ``sudo`` binary — neither of which an
    unprivileged container has. Everything here reads the block device
    directly instead: boot sector, root directory, FAT, then the file's
    cluster runs. No mount, no privilege beyond read access to the device.

    The volume's directory is re-read by :meth:`refresh`, which callers must
    do *after* the panel has materialised the files they want: the panel
    fills these volumes only inside a configuration session and zeroes them
    afterwards, so sizes and contents change under you.

    ``read_sectors`` exists so the reader can be tested against a synthetic
    image without a block device.
    """

    def __init__(
        self,
        device: str,
        *,
        read_sectors: Callable[[int, int], bytes] | None = None,
    ) -> None:
        self._device = device
        self._read_sectors = read_sectors or self._read_sectors_from_device
        self._geometry: dict[str, int] | None = None
        self._entries: dict[bytes, FatDirEntry] | None = None
        self._fat: bytes | None = None

    def _read_sectors_from_device(self, start_lba: int, sectors: int) -> bytes:
        return read_device_direct_bytes(device=self._device, start_lba=start_lba, sectors=sectors)

    def refresh(self) -> None:
        """(Re-)read geometry, root directory and allocation table."""

        geometry = _parse_fat_geometry(self._read_sectors(0, 1))
        root_dir = self._read_sectors(
            geometry["root_dir_start_sector"], geometry["root_dir_sectors"]
        )
        self._geometry = geometry
        self._entries = _parse_fat_root_entries(root_dir)
        self._fat = self._read_sectors(geometry["reserved_sectors"], geometry["sectors_per_fat"])

    def _ensure_loaded(self) -> None:
        if self._geometry is None or self._entries is None or self._fat is None:
            self.refresh()

    @property
    def geometry(self) -> dict[str, int]:
        self._ensure_loaded()
        assert self._geometry is not None
        return self._geometry

    def entries(self) -> dict[bytes, FatDirEntry]:
        self._ensure_loaded()
        assert self._entries is not None
        return dict(self._entries)

    def entry(self, filename_83: bytes) -> FatDirEntry | None:
        self._ensure_loaded()
        assert self._entries is not None
        return self._entries.get(filename_83)

    def size(self, filename_83: bytes) -> int:
        entry = self.entry(filename_83)
        return 0 if entry is None else entry.size

    def first_sector(self, filename_83: bytes) -> int | None:
        """Device-relative LBA of the file's first data sector, or None if absent."""

        entry = self.entry(filename_83)
        if entry is None or entry.start_cluster < 2:
            return None
        geometry = self.geometry
        return geometry["data_start_sector"] + (entry.start_cluster - 2) * geometry["sectors_per_cluster"]

    def read_file(self, filename_83: bytes, *, start: int = 0, length: int | None = None) -> bytes:
        """Read ``length`` bytes of a root-directory file from ``start``.

        Returns fewer bytes than asked for when the range runs past the end
        of the file, and ``b""`` when the file is absent or empty.
        """

        self._ensure_loaded()
        assert self._geometry is not None and self._fat is not None
        entry = self.entry(filename_83)
        if entry is None or entry.size <= 0 or entry.start_cluster < 2:
            return b""
        if start < 0:
            raise ValueError("start must not be negative")
        available = max(0, entry.size - start)
        wanted = available if length is None else min(length, available)
        if wanted <= 0:
            return b""

        geometry = self._geometry
        cluster_size = geometry["cluster_size_bytes"]
        clusters = _follow_fat16_chain(
            fat=self._fat,
            start_cluster=entry.start_cluster,
            max_clusters=(entry.size + cluster_size - 1) // cluster_size,
        )
        first_index = start // cluster_size
        last_index = (start + wanted - 1) // cluster_size
        selected = clusters[first_index : last_index + 1]
        if not selected:
            return b""
        parts: list[bytes] = []
        for run_start, run_length in _cluster_runs(selected):
            start_sector = (
                geometry["data_start_sector"]
                + (run_start - 2) * geometry["sectors_per_cluster"]
            )
            parts.append(
                self._read_sectors(start_sector, run_length * geometry["sectors_per_cluster"])
            )
        blob = b"".join(parts)
        offset = start - first_index * cluster_size
        return blob[offset : offset + wanted]


def _parse_fat_root_entries(root_dir: bytes) -> dict[bytes, FatDirEntry]:
    entries: dict[bytes, FatDirEntry] = {}
    for offset in range(0, len(root_dir), 32):
        raw = root_dir[offset : offset + 32]
        if len(raw) < 32 or raw[0] == 0x00:
            break
        if raw[0] == 0xE5:
            continue
        attributes = raw[11]
        if attributes & 0x0F == 0x0F:  # long-file-name fragment
            continue
        entries[raw[:11]] = FatDirEntry(
            name_83=raw[:11],
            attributes=attributes,
            size=unpack_from("<I", raw, 28)[0],
            start_cluster=unpack_from("<H", raw, 26)[0],
            modified=_format_fat_timestamp(
                unpack_from("<H", raw, 24)[0], unpack_from("<H", raw, 22)[0]
            ),
        )
    return entries


def _format_fat_timestamp(date_raw: int, time_raw: int) -> str:
    if not date_raw:
        return ""
    year = 1980 + ((date_raw >> 9) & 0x7F)
    month = (date_raw >> 5) & 0x0F
    day = date_raw & 0x1F
    hour = (time_raw >> 11) & 0x1F
    minute = (time_raw >> 5) & 0x3F
    second = (time_raw & 0x1F) * 2
    return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"


def read_device_direct_bytes(*, device: str, start_lba: int, sectors: int) -> bytes:
    resolved_device = resolve_flexi_cfg_device(device)
    aligned_sectors = max(sectors, 8)
    fd, temp_name = tempfile.mkstemp(prefix="jablotron-direct-read-", suffix=".bin")
    os.close(fd)
    os.unlink(temp_name)
    temp_path = Path(temp_name)
    try:
        command = [
            "dd",
            f"if={resolved_device}",
            f"of={temp_path}",
            f"bs={SECTOR_SIZE}",
            f"skip={start_lba}",
            f"count={aligned_sectors}",
            "iflag=direct",
            "status=none",
        ]
        if os.geteuid() != 0:
            command = ["sudo", "-n"] + command
        subprocess.run(command, check=True)
        return temp_path.read_bytes()[: sectors * SECTOR_SIZE]
    finally:
        try:
            temp_path.unlink()
        except PermissionError:
            subprocess.run(["sudo", "-n", "rm", "-f", str(temp_path)], check=False)
        except FileNotFoundError:
            pass


def write_device_direct_bytes(*, device: str, start_lba: int, data: bytes) -> None:
    resolved_device = resolve_flexi_cfg_device(device)
    fd, temp_name = tempfile.mkstemp(prefix="jablotron-direct-write-", suffix=".bin")
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        temp_path.write_bytes(data)
        base_command = [
            "dd",
            f"if={temp_path}",
            f"of={resolved_device}",
            f"bs={SECTOR_SIZE}",
            f"seek={start_lba}",
            f"count={(len(data) + SECTOR_SIZE - 1) // SECTOR_SIZE}",
            "conv=fsync,notrunc",
            "status=none",
        ]
        commands = [base_command + ["oflag=direct"], base_command]
        if os.geteuid() != 0:
            commands = [["sudo", "-n", *command] for command in commands]
        last_error: subprocess.CalledProcessError | None = None
        for command in commands:
            try:
                subprocess.run(command, check=True)
                return
            except subprocess.CalledProcessError as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
    finally:
        try:
            temp_path.unlink()
        except PermissionError:
            subprocess.run(["sudo", "-n", "rm", "-f", str(temp_path)], check=False)
        except FileNotFoundError:
            pass


def partition_start_sector(device: str) -> int:
    """Where a partition device starts on its disk, in sectors (0 if unknown)."""

    try:
        return int(Path("/sys/class/block", Path(device).name, "start").read_text().strip())
    except (OSError, ValueError):
        return 0


def resolve_import_sector_lba(device: str) -> int:
    """LBA of IMPORT.CFG's first sector, relative to the device we open.

    ``IMPORT_START_LBA`` (2083) is the absolute disk LBA seen in USB
    captures. The device we open is the FLEXI_CFG partition, which starts at
    absolute sector 1 on this panel, so the constant applied to the
    partition lands on IMPORT.CFG+512 (a sector nobody writes). Walk the FAT
    root directory instead, which is what mounting does; fall back to the
    constant corrected by the partition offset when the directory cannot be
    read.
    """

    resolved_device = resolve_flexi_cfg_device(device)
    try:
        lba = FatVolumeReader(resolved_device).first_sector(IMPORT_FILENAME_83)
    except Exception:
        lba = None
    if lba is not None:
        return lba
    return IMPORT_START_LBA - partition_start_sector(resolved_device)


def read_import_sector_direct(*, device: str) -> bytes:
    data = read_device_direct_bytes(device=device, start_lba=resolve_import_sector_lba(device), sectors=1)
    if len(data) < SECTOR_SIZE:
        raise SystemExit(f"Short direct read for IMPORT.CFG sector 0: got {len(data)} bytes.")
    return data[:SECTOR_SIZE]


def verify_import_sector_direct(
    *,
    device: str,
    expected_sector: bytes,
    retries: int = 6,
    retry_delay: float = 0.1,
) -> bytes:
    last_sector = b""
    for attempt in range(retries):
        last_sector = read_import_sector_direct(device=device)
        if last_sector == expected_sector:
            return last_sector
        if attempt + 1 < retries:
            time.sleep(retry_delay)
    raise SystemExit(
        f"Direct IMPORT.CFG verification failed at LBA {resolve_import_sector_lba(device)} after unmount: "
        "the staged sector was not readable back from the block device."
    )


def probe_import_sector_direct(
    *,
    device: str,
    expected_sector: bytes,
    retries: int = 3,
    retry_delay: float = 0.1,
) -> bool:
    for attempt in range(retries):
        if read_import_sector_direct(device=device) == expected_sector:
            return True
        if attempt + 1 < retries:
            time.sleep(retry_delay)
    return False


def stage_import_direct(*, device: str, sector_path: Path) -> bytes:
    expected_sector = sector_path.read_bytes()[:SECTOR_SIZE]
    if len(expected_sector) != SECTOR_SIZE:
        raise SystemExit(f"Expected a 512-byte encoded IMPORT sector in {sector_path}.")
    lba = resolve_import_sector_lba(device)
    write_device_direct_bytes(device=device, start_lba=lba, data=expected_sector)
    current = read_import_sector_direct(device=device)
    if current != expected_sector:
        raise SystemExit(f"Direct IMPORT.CFG staging failed verification at LBA {lba}.")
    return expected_sector


def extract_sections_state_mode(packet: bytes) -> int | None:
    if Jablotron._is_sections_states_packet(packet) and packet:
        return packet[-1]
    return None


def extract_system_state_mode(packet: bytes) -> int | None:
    if packet.startswith(b"\x73\x09") and len(packet) >= 3:
        return packet[-3]
    return None


def is_configuration_sections_mode(mode: int | None) -> bool:
    return mode == CONFIGURATION_SECTIONS_MODE


def packet_has_configuration_channels_in_use(packet: bytes) -> bool:
    return extract_system_state_mode(packet) == CONFIGURATION_SECTIONS_MODE


def describe_sections_mode(mode: int | None) -> str:
    if mode is None:
        return "unknown"
    if mode == EXITED_SECTIONS_MODE:
        return f"exited (0x{mode:02x})"
    if mode == CONFIGURATION_SECTIONS_MODE:
        return f"configuration-active (0x{mode:02x})"
    return f"0x{mode:02x}"


def configuration_in_use_message() -> str:
    return "System is already in configuration mode; another F-Link/configuration session appears to be active."


def packet_startswith(packet: bytes, hex_prefix: str) -> bool:
    return packet.startswith(bytes.fromhex(hex_prefix))


def wait_for_packets(
    client: JablotronUSBClient,
    *,
    deadline: float,
    timeout: float,
    prefix: str,
    verbose: bool,
) -> list[bytes]:
    remaining = max(0.0, min(timeout, deadline - time.time()))
    if remaining <= 0:
        return []
    return drain_packets(client, timeout=remaining, prefix=prefix, verbose=verbose)


def send_flink_export_refresh_sequence(client: JablotronUSBClient, *, verbose: bool) -> None:
    send_report(client, REPORT_520102, verbose=verbose)
    send_report(client, REPORT_520102, verbose=verbose)
    send_report(client, REPORT_80010F, verbose=verbose)
    send_report(client, REPORT_520102, verbose=verbose)
    send_config_reload_sequence(client, verbose=verbose)


def send_config_reload_sequence(client: JablotronUSBClient, *, verbose: bool) -> None:
    """Ask the panel to rebuild its configuration export and wait for it.

    This is what F-Link does right after "Setting mode entered" and before
    any write to IMPORT.CFG. The 2026-09-25 capture of an F-Link session
    shows the panel refusing a mass-storage write before this step and
    accepting the same write after it, which is why ``apply_import_sector``
    can run it before staging.
    """

    send_report(client, REPORT_520213059A00, verbose=verbose)
    for report in build_flink_info_log_reports():
        send_report(client, report, verbose=verbose)
    send_report(client, REPORT_520125, verbose=verbose)

    deadline = time.time() + 8.0
    last_keepalive = 0.0
    saw_reload_complete = False

    while time.time() < deadline:
        packets = wait_for_packets(client, deadline=deadline, timeout=0.5, prefix="export", verbose=verbose)
        now = time.time()
        for packet in packets:
            if packet_startswith(packet, "5204830b25"):
                last_keepalive = now
            elif packet_startswith(packet, "5207830125"):
                saw_reload_complete = True

        if not saw_reload_complete and now - last_keepalive >= 1.0:
            send_report(client, REPORT_520102, verbose=verbose)
            last_keepalive = now

        if saw_reload_complete:
            break

    if not saw_reload_complete:
        raise SystemExit("Export refresh did not reach the reload-complete state.")

    send_report(client, REPORT_520102, verbose=verbose)
    send_report(client, REPORT_800102, verbose=verbose)
    time.sleep(0.05)
    drain_packets(client, timeout=0.4, prefix="export-post", verbose=verbose)
    send_report(client, REPORT_520102, verbose=verbose)
    drain_packets(client, timeout=0.4, prefix="export-post", verbose=verbose)


def trigger_live_export(*, port: str, code: str, reset: bool) -> None:
    serial_port = ensure_serial_port(port)
    client = JablotronUSBClient(serial_port)
    try:
        perform_login(client, code, reset=reset)
        time.sleep(0.5)
        send_flink_export_refresh_sequence(client, verbose=False)
    finally:
        client.close()


def pull_live_export_snapshot(
    *,
    output: Path,
    device: str,
    port: str,
    code: str,
    reset: bool,
    trigger: bool = True,
    start_lba: int = EXPORT_START_LBA,
    sectors: int = EXPORT_SECTORS,
    cleanup_mode: str = "auto",
    verbose: bool = False,
) -> ExportSnapshot:
    resolved_device = resolve_flexi_cfg_device(device)
    if get_device_mountpoint(resolved_device) is not None:
        unmount_device(resolved_device, mount_tool="sudo")

    cleanup_sections_mode: int | None = None
    if trigger:
        trigger_live_export(port=port, code=code, reset=reset)
    read_export_direct(device=resolved_device, output=output, start_lba=start_lba, sectors=sectors)
    if trigger and cleanup_mode != "none":
        cleanup_sections_mode = cleanup_read_session(port=port, code=code, cleanup_mode=cleanup_mode, verbose=verbose)
        if cleanup_sections_mode == CONFIGURATION_SECTIONS_MODE:
            print(
                "warning: read-session cleanup ended in the configuration-active state "
                f"({describe_sections_mode(cleanup_sections_mode)}); "
                "another F-Link/configuration session appears to be active. "
                "Continuing because EXPORT.CFG was already read successfully."
            )
        elif cleanup_sections_mode != EXITED_SECTIONS_MODE:
            print(
                "warning: read-session cleanup did not reach the exited state "
                f"(expected 0x{EXITED_SECTIONS_MODE:02x}, got {describe_sections_mode(cleanup_sections_mode)}); "
                "continuing because EXPORT.CFG was already read successfully."
            )
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    raw_records = extract_users(output, dedupe="raw")
    catalog = extract_export_catalog(output)
    records = catalog.users
    return ExportSnapshot(
        path=output,
        sha256=digest,
        raw_records=raw_records,
        records=records,
        sections_by_id=catalog.sections_by_id,
        pgs_by_id=catalog.pgs_by_id,
        time_limit_groups_by_id=catalog.time_limit_groups_by_id,
    )


def run_command(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def write_file_prefix_with_sudo(*, source: Path, target: Path, size: int) -> None:
    subprocess.run(
        [
            "sudo",
            "-n",
            "dd",
            f"if={source}",
            f"of={target}",
            f"bs={size}",
            "count=1",
            "conv=notrunc",
            "status=none",
        ],
        check=True,
        text=True,
        capture_output=True,
    )


def stage_import(import_path: Path, sector_path: Path) -> None:
    """Write the encoded sector over the start of the mounted IMPORT.CFG.

    Any OSError from the write or the fsync is fatal. When the panel refuses
    the SCSI write the kernel reports EIO here, and re-reading the file
    afterwards only returns the page cache, which proves nothing about the
    panel's storage (the 2026-09-25 live attempt ran the accept sequence
    against unchanged storage that way). The read-back below is a sanity
    check of the file content only; the authoritative check is the O_DIRECT
    read of the sector after unmount in ``apply_import_sector``.
    """

    sector = sector_path.read_bytes()[:SECTOR_SIZE]

    try:
        with import_path.open("r+b", buffering=0) as handle:
            try:
                handle.seek(0)
                handle.write(sector)
                handle.flush()
                os.fsync(handle.fileno())
            except OSError as exc:
                raise SystemExit(
                    f"IMPORT.CFG staging failed: the write to {import_path} raised {exc}"
                ) from exc
    except PermissionError:
        write_file_prefix_with_sudo(source=sector_path, target=import_path, size=SECTOR_SIZE)

    current = import_path.read_bytes()[:SECTOR_SIZE]
    if current != sector:
        raise SystemExit("IMPORT.CFG staging failed verification.")


def ensure_import_path_available(*, import_path: Path, device: str, mount_tool: str) -> None:
    if import_path.exists():
        return
    mount_device(device, import_path.parent, mount_tool=mount_tool, expected_path=import_path)
    if not import_path.exists():
        raise SystemExit(f"IMPORT.CFG is still missing after remount: {import_path}")


def _privileged_command(command: list[str]) -> list[str]:
    """Prefix a command with ``sudo -n`` only when we are not already root.

    The API server container runs as root and ships no ``sudo`` binary, so
    an unconditional prefix fails with ``FileNotFoundError: 'sudo'`` before
    the command is even attempted — which is what made /v1/events return
    500 there. Mirrors what the direct-read helpers already do.
    """

    if os.geteuid() == 0:
        return list(command)
    return ["sudo", "-n"] + list(command)


def _user_mount_options() -> str:
    return f"uid={os.getuid()},gid={os.getgid()},umask=022"


def mount_device(
    device: str,
    mountpoint: Path,
    *,
    mount_tool: str,
    expected_path: Path | None = None,
) -> None:
    resolved_device = resolve_flexi_cfg_device(device)
    suppress_message = False
    if mount_tool == "sudo":
        mountpoint.mkdir(parents=True, exist_ok=True)
        options = _user_mount_options()
        if is_device_mounted(resolved_device):
            result = run_command(
                _privileged_command(["mount", "-o", f"remount,{options}", resolved_device, str(mountpoint)]),
                check=False,
            )
        else:
            result = run_command(
                _privileged_command(["mount", "-o", options, resolved_device, str(mountpoint)]),
                check=False,
            )
        stderr = result.stderr.lower()
        suppress_message = result.returncode != 0 and "already mounted" in stderr
        if result.returncode != 0 and not suppress_message:
            raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"mount failed for {resolved_device}")
    elif mount_tool == "udisksctl":
        result = run_command(["udisksctl", "mount", "-b", resolved_device], check=False)
        suppress_message = result.returncode != 0 and "already mounted" in result.stderr.lower()
        if result.returncode != 0 and not suppress_message:
            raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"mount failed for {resolved_device}")
    else:
        raise SystemExit(f"Unsupported mount tool: {mount_tool}")

    message = result.stdout.strip() or result.stderr.strip()
    if message and not suppress_message:
        print(message)

    for _attempt in range(10):
        actual_mountpoint = get_device_mountpoint(resolved_device)
        if actual_mountpoint != mountpoint:
            time.sleep(0.1)
            continue
        if expected_path is None or expected_path.exists():
            return
        time.sleep(0.1)

    actual_mountpoint = get_device_mountpoint(resolved_device)
    expected_exists = expected_path.exists() if expected_path is not None else None
    raise SystemExit(
        "mount completed but the requested filesystem was not available at the expected mountpoint: "
        f"device={resolved_device} expected_mountpoint={mountpoint} "
        f"actual_mountpoint={actual_mountpoint} expected_path={expected_path} "
        f"expected_path_exists={expected_exists}"
    )


def unmount_device(device: str, *, mount_tool: str) -> None:
    resolved_device = resolve_flexi_cfg_device(device)
    suppress_message = False
    if mount_tool == "sudo":
        result = run_command(_privileged_command(["umount", resolved_device]), check=False)
        stderr = result.stderr.lower()
        suppress_message = result.returncode != 0 and "not mounted" in stderr
        if result.returncode != 0 and not suppress_message:
            raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"unmount failed for {resolved_device}")
    elif mount_tool == "udisksctl":
        result = run_command(["udisksctl", "unmount", "-b", resolved_device], check=False)
        suppress_message = result.returncode != 0 and "not mounted" in result.stderr.lower()
        if result.returncode != 0 and not suppress_message:
            raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"unmount failed for {resolved_device}")
    else:
        raise SystemExit(f"Unsupported mount tool: {mount_tool}")

    message = result.stdout.strip() or result.stderr.strip()
    if message and not suppress_message:
        print(message)


def drain_packets(client: JablotronUSBClient, *, timeout: float, prefix: str, verbose: bool) -> list[bytes]:
    packets = list(client.read_packets(timeout=timeout))
    if verbose:
        for packet in packets:
            print(prefix, describe_packet(packet, decode=True))
    return packets


def send_report(client: JablotronUSBClient, report_hex: str, *, verbose: bool) -> None:
    perform_send_raw_report(client, report_hex)
    if verbose:
        print("tx", report_hex[:6])


def send_packet(client: JablotronUSBClient, packet: bytes, *, verbose: bool) -> None:
    client.send_packet(packet)
    if verbose:
        print("tx", Jablotron.format_packet_to_string(packet))


def send_packets(client: JablotronUSBClient, packets: Iterable[bytes], *, verbose: bool) -> None:
    packet_list = list(packets)
    client.send_packets(packet_list)
    if verbose:
        for packet in packet_list:
            print("tx", Jablotron.format_packet_to_string(packet))


def enter_setup_mode(client: JablotronUSBClient, *, verbose: bool, initial_packets: list[bytes] | None = None) -> None:
    service_rights = False
    service_rights_at: float | None = None
    nudged_0f = False
    saw_1a0a = False
    saw_1a0a_at: float | None = None
    saw_1b00 = False
    saw_sections_94 = False
    saw_preexisting_configuration_state = False
    saw_config_channels_in_use = False
    entered_setup = False
    deadline = time.time() + 15.0
    last_keepalive_at: float | None = None
    next_keepalive_at: float | None = None

    while time.time() < deadline and not entered_setup:
        if initial_packets is not None:
            packets = initial_packets
            initial_packets = None
        else:
            packets = drain_packets(client, timeout=0.5, prefix="setup", verbose=verbose)
        now = time.time()

        for packet in packets:
            if packet_startswith(packet, "801a0c") and not service_rights:
                service_rights = True
                service_rights_at = now
            elif packet_startswith(packet, "80021a0a") and not saw_1a0a:
                saw_1a0a = True
                saw_1a0a_at = now
                send_report(client, REPORT_80010F, verbose=verbose)
                next_keepalive_at = now + SETUP_MODE_FIRST_KEEPALIVE_DELAY
            elif packet_startswith(packet, "80021b00"):
                saw_1b00 = True
            elif packet_startswith(packet, "800112"):
                entered_setup = True
            else:
                sections_mode = extract_sections_state_mode(packet)
                system_state_mode = extract_system_state_mode(packet)
                if not saw_1a0a and is_configuration_sections_mode(sections_mode):
                    saw_preexisting_configuration_state = True
                if saw_1a0a and sections_mode == 0x94:
                    saw_sections_94 = True
                if is_configuration_sections_mode(system_state_mode):
                    saw_config_channels_in_use = True

        if saw_config_channels_in_use and not entered_setup:
            break

        if (
            service_rights
            and not saw_1a0a
            and not nudged_0f
            and service_rights_at is not None
            and now - service_rights_at >= SETUP_MODE_NUDGE_DELAY
        ):
            send_report(client, REPORT_80010F, verbose=verbose)
            nudged_0f = True
        elif (
            saw_1a0a
            and not entered_setup
            and next_keepalive_at is not None
            and now >= next_keepalive_at
            and (saw_sections_94 or saw_1b00 or (saw_1a0a_at is not None and now - saw_1a0a_at >= SETUP_MODE_FIRST_KEEPALIVE_DELAY))
        ):
            send_report(client, REPORT_520102, verbose=verbose)
            last_keepalive_at = now
            next_keepalive_at = now + SETUP_MODE_KEEPALIVE_INTERVAL

    if verbose:
        print(
            "setup_state",
            {
                "service_rights": service_rights,
                "nudged_0f": nudged_0f,
                "saw_1a0a": saw_1a0a,
                "saw_sections_94": saw_sections_94,
                "saw_preexisting_configuration_state": saw_preexisting_configuration_state,
                "saw_config_channels_in_use": saw_config_channels_in_use,
                "saw_1b00": saw_1b00,
                "last_keepalive_at": last_keepalive_at,
                "next_keepalive_at": next_keepalive_at,
                "entered_setup": entered_setup,
            },
        )

    if not entered_setup:
        if saw_config_channels_in_use or (saw_preexisting_configuration_state and not saw_1a0a):
            raise SystemExit(configuration_in_use_message())
        raise SystemExit("Did not enter setup mode.")


def perform_import_accept_sequence(client: JablotronUSBClient, *, verbose: bool) -> None:
    send_report(client, REPORT_520102, verbose=verbose)
    time.sleep(0.2)
    drain_packets(client, timeout=1.0, prefix="p1", verbose=verbose)

    send_report(client, REPORT_520124, verbose=verbose)
    time.sleep(0.2)
    drain_packets(client, timeout=1.2, prefix="p2", verbose=verbose)

    send_report(client, REPORT_520102, verbose=verbose)
    time.sleep(0.05)
    send_report(client, REPORT_52010C, verbose=verbose)

    sent_800114 = False
    sent_80010f = False
    sent_post_520102 = False
    deadline = time.time() + 12.0
    while time.time() < deadline:
        packets = drain_packets(client, timeout=0.5, prefix="p3", verbose=verbose)
        if not packets:
            time.sleep(0.05)
            continue

        for packet in packets:
            if packet.startswith(bytes.fromhex("800117")) and not sent_800114:
                send_report(client, REPORT_800114, verbose=verbose)
                sent_800114 = True
            elif packet.startswith(bytes.fromhex("80021a0a")) and not sent_80010f:
                send_report(client, REPORT_80010F, verbose=verbose)
                sent_80010f = True
                time.sleep(0.8)
                send_report(client, REPORT_520102, verbose=verbose)
                sent_post_520102 = True

    if verbose:
        print(
            "accept_flags",
            {
                "sent_800114": sent_800114,
                "sent_80010f": sent_80010f,
                "sent_post_520102": sent_post_520102,
            },
        )


def graceful_exit_session(client: JablotronUSBClient, *, verbose: bool) -> list[bytes]:
    """Mirror the F-Link exit sequence instead of dropping the HID session abruptly."""

    send_packet(client, EXIT_DIAGNOSTICS_OFF_PACKET, verbose=verbose)
    time.sleep(0.03)
    send_packets(
        client,
        [
            Jablotron.create_packet_ui_control(b"\x01"),
            Jablotron.create_packet_command(b"\x0e"),
        ],
        verbose=verbose,
    )
    time.sleep(0.06)
    send_packet(client, Jablotron.create_packet_command(b"\x02"), verbose=verbose)
    return drain_packets(client, timeout=0.8, prefix="exit", verbose=verbose)


def cleanup_read_session(
    *,
    port: str,
    code: str,
    cleanup_mode: str,
    verbose: bool,
) -> int | None:
    """Close a read/export session after the block read without racing EXPORT.CFG refresh."""

    if cleanup_mode not in {"none", "auto", "exit-only", "login-exit"}:
        raise SystemExit(f"Unsupported read cleanup mode: {cleanup_mode}")
    if cleanup_mode == "none":
        return None

    serial_port = ensure_serial_port(port)
    attempts = ["exit-only", "login-exit"] if cleanup_mode == "auto" else [cleanup_mode]
    final_mode: int | None = None

    for attempt in attempts:
        client = JablotronUSBClient(serial_port)
        try:
            pre_packets = drain_packets(client, timeout=0.4, prefix=f"{attempt}-pre", verbose=verbose)
            if attempt == "login-exit":
                perform_login(client, code, reset=False)
                time.sleep(0.5)
                pre_packets.extend(drain_packets(client, timeout=0.8, prefix="login", verbose=verbose))
            exit_packets = graceful_exit_session(client, verbose=verbose)
            post_packets = drain_packets(client, timeout=0.5, prefix=f"{attempt}-post", verbose=verbose)
            observed_modes = [
                mode
                for mode in (
                    extract_sections_state_mode(packet) or extract_system_state_mode(packet)
                    for packet in [*pre_packets, *exit_packets, *post_packets]
                )
                if mode is not None
            ]
            saw_config_channels_in_use = any(
                packet_has_configuration_channels_in_use(packet)
                for packet in [*pre_packets, *exit_packets, *post_packets]
            )
            final_mode = observed_modes[-1] if observed_modes else None
            if verbose:
                print(
                    "read_cleanup",
                    {
                        "attempt": attempt,
                        "sections_mode": describe_sections_mode(final_mode),
                        "config_channels_in_use": saw_config_channels_in_use,
                    },
                )
            if final_mode == EXITED_SECTIONS_MODE:
                return final_mode
            if saw_config_channels_in_use or final_mode == CONFIGURATION_SECTIONS_MODE:
                return final_mode
        finally:
            client.close()

    return final_mode


def apply_import_sector(
    *,
    sector_path: Path,
    import_path: Path,
    device: str,
    port: str,
    code: str,
    reset: bool,
    mount_tool: str,
    stage_mode: str,
    write_cleanup_mode: str,
    verbose: bool,
    verify_output: Path | None = None,
    reload_before_stage: bool = False,
) -> ExportSnapshot | None:
    resolved_device = resolve_flexi_cfg_device(device)
    mountpoint = import_path.parent
    remount_after = False
    if stage_mode not in {"direct", "filesystem"}:
        raise SystemExit(f"Unsupported stage mode: {stage_mode}")
    if stage_mode == "filesystem":
        if is_device_mounted(resolved_device):
            unmount_device(resolved_device, mount_tool=mount_tool)
            remount_after = True
        mount_device(resolved_device, mountpoint, mount_tool=mount_tool, expected_path=import_path)
        remount_after = True
    else:
        if is_device_mounted(resolved_device):
            unmount_device(resolved_device, mount_tool=mount_tool)
            remount_after = True
    try:
        write_exit_mode: int | None = None
        serial_port = ensure_serial_port(port)
        client = JablotronUSBClient(serial_port)
        try:
            perform_login(client, code, reset=reset)
            time.sleep(0.7)
            pre_packets = drain_packets(client, timeout=1.0, prefix="pre", verbose=verbose)
            enter_setup_mode(client, verbose=verbose, initial_packets=pre_packets)
            if reload_before_stage:
                send_config_reload_sequence(client, verbose=verbose)
                if verbose:
                    print("reload_before_stage", "complete")
            if stage_mode == "filesystem":
                ensure_import_path_available(import_path=import_path, device=resolved_device, mount_tool=mount_tool)
                stage_import(import_path, sector_path)
                unmount_device(resolved_device, mount_tool=mount_tool)
                # The page cache is gone with the unmount, so this O_DIRECT
                # read shows what the panel actually stored. A refused write
                # (directory sector or data sector) stops here, before the
                # panel is asked to accept an import that never landed.
                expected_sector = sector_path.read_bytes()[:SECTOR_SIZE]
                verify_import_sector_direct(device=resolved_device, expected_sector=expected_sector)
                if verbose:
                    print("import_sector_verified", {"lba": resolve_import_sector_lba(resolved_device)})
            else:
                stage_import_direct(device=resolved_device, sector_path=sector_path)
                if verbose:
                    print("import_sector_lba", resolve_import_sector_lba(resolved_device))
            perform_import_accept_sequence(client, verbose=verbose)
            exit_packets = graceful_exit_session(client, verbose=verbose)
            post_exit_packets = drain_packets(client, timeout=0.5, prefix="exit-post", verbose=verbose)
            observed_modes = [
                mode
                for mode in (
                    extract_sections_state_mode(packet)
                    for packet in [*exit_packets, *post_exit_packets]
                )
                if mode is not None
            ]
            write_exit_mode = observed_modes[-1] if observed_modes else None
            if verbose:
                print("write_exit_mode", write_exit_mode)
        finally:
            client.close()

        if write_cleanup_mode != "none" and write_exit_mode != EXITED_SECTIONS_MODE:
            cleanup_mode = cleanup_read_session(port=port, code=code, cleanup_mode=write_cleanup_mode, verbose=verbose)
            if verbose:
                print("write_cleanup_mode", cleanup_mode)

        if verify_output is None:
            return None
        last_error: SystemExit | None = None
        for attempt in range(1, 4):
            try:
                return pull_live_export_snapshot(
                    output=verify_output,
                    device=resolved_device,
                    port=port,
                    code=code,
                    reset=reset,
                )
            except SystemExit as exc:
                if "reload-complete state" not in str(exc):
                    raise
                last_error = exc
                if attempt == 3:
                    raise
                print(
                    "warning: embedded verification export did not reach the reload-complete state; "
                    f"retrying ({attempt}/3)"
                )
                time.sleep(2.0)
        if last_error is not None:
            raise last_error
        return None
    finally:
        if remount_after:
            mount_device(resolved_device, mountpoint, mount_tool=mount_tool, expected_path=import_path)
