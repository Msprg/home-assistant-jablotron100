#!/usr/bin/env python3
"""Shared reverse-engineering helpers for live Jablotron config workflows."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from flexi_pcap_tool import IMPORT_START_LBA
from jablotron_usb_debug import (
    Jablotron,
    JablotronUSBClient,
    build_flink_info_log_reports,
    describe_packet,
    ensure_serial_port,
    perform_login,
    perform_send_raw_report,
)

SECTOR_SIZE = 512
EXPORT_START_LBA = 35
EXPORT_SECTORS = 2048
DEFAULT_FLEXI_CFG_LABEL = "FLEXI_CFG"
DEFAULT_FLEXI_CFG_LINK = Path("/dev/disk/by-label") / DEFAULT_FLEXI_CFG_LABEL
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
SETUP_MODE_NUDGE_DELAY = 0.35
SETUP_MODE_FIRST_KEEPALIVE_DELAY = 0.7
SETUP_MODE_KEEPALIVE_INTERVAL = 1.0


@dataclass(frozen=True)
class UserRecord:
    offset: int
    user_id: Optional[int]
    raw_id_bytes: str
    status_raw: Optional[int]
    permissions_raw: Optional[int]
    rights: str
    enabled: Optional[bool]
    name: str
    phone: str
    code: str
    card: str
    comment: str


@dataclass(frozen=True)
class ExportSnapshot:
    path: Path
    sha256: str
    raw_records: list[UserRecord]
    records: list[UserRecord]


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
class ExportCatalogSnapshot:
    path: Path
    users: list[UserRecord]
    sections_by_id: dict[int, ExportSectionRecord]
    objects_by_id: dict[int, ExportObjectRecord]
    hardware_by_id: dict[int, ExportHardwareRecord]
    pgs_by_id: dict[int, ExportPGRecord]

    @property
    def communicators_by_id(self) -> dict[int, ExportObjectRecord]:
        return {
            object_id: record
            for object_id, record in self.objects_by_id.items()
            if object_id >= 233 or record.name.lower().endswith("communicator")
        }


def invert_blob(data: bytes) -> bytes:
    return bytes(byte ^ 0xFF for byte in data)


def _parse_lsblk_pairs(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        pairs = dict(re.findall(r'(\w+)="([^"]*)"', line))
        if pairs:
            rows.append(pairs)
    return rows


def resolve_flexi_cfg_device(device: str | None = None) -> str:
    if device and device != "auto":
        path = Path(device)
        return str(path.resolve()) if path.exists() else device

    if DEFAULT_FLEXI_CFG_LINK.exists():
        return str(DEFAULT_FLEXI_CFG_LINK.resolve())

    result = subprocess.run(
        ["lsblk", "-P", "-o", "PATH,LABEL,TYPE"],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode == 0:
        for row in _parse_lsblk_pairs(result.stdout):
            if row.get("LABEL") == DEFAULT_FLEXI_CFG_LABEL and row.get("TYPE") == "part":
                return row["PATH"]

    raise SystemExit(
        "Unable to resolve the FLEXI_CFG block device. "
        "Connect the panel or pass --device /dev/sdX1 explicitly."
    )


def is_device_mounted(device: str) -> bool:
    resolved_device = resolve_flexi_cfg_device(device)
    result = subprocess.run(
        ["lsblk", "-P", "-o", "PATH,MOUNTPOINT", resolved_device],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return False
    rows = _parse_lsblk_pairs(result.stdout)
    return any(row.get("PATH") == resolved_device and row.get("MOUNTPOINT") for row in rows)


def default_export_output(prefix: str) -> Path:
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    return Path("/tmp") / f"{timestamp}_{prefix}_EXPORT.CFG.bin"


def default_sector_output(prefix: str) -> Path:
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    return Path("/tmp") / f"{timestamp}_{prefix}_IMPORT-sector.bin"


def find_record_starts(blob: bytes) -> list[int]:
    starts: list[int] = []
    for offset in range(len(blob) - 4):
        if blob[offset : offset + 2] != b"\x07\x81":
            continue
        if b"\x04" not in blob[offset : offset + 96]:
            continue
        if starts and offset - starts[-1] <= 32:
            continue
        starts.append(offset)
    return starts


def decode_user_id(id_bytes: bytes) -> Optional[int]:
    if len(id_bytes) == 1:
        return id_bytes[0]
    if len(id_bytes) == 3 and id_bytes[:2] == b"\xcd\x02":
        return 0x200 + id_bytes[2]
    return None


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
    if marker == 0xD0 and start + 1 < len(data):
        return int.from_bytes(data[start + 1 : start + 2], "big", signed=True), start + 2
    if marker == 0xD1 and start + 2 < len(data):
        return int.from_bytes(data[start + 1 : start + 3], "big", signed=True), start + 3
    if marker == 0xD2 and start + 4 < len(data):
        return int.from_bytes(data[start + 1 : start + 5], "big", signed=True), start + 5
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
    if marker <= 0x7F or marker >= 0xE0 or marker in {0xCC, 0xCD, 0xCE, 0xD0, 0xD1, 0xD2}:
        return decode_msgpack_int(data, start)
    if 0xA0 <= marker <= 0xBF or marker in {0xD9, 0xDA, 0xDB}:
        return decode_msgpack_string(data, start), _skip_msgpack_string(data, start)
    if 0x90 <= marker <= 0x9F:
        length = marker - 0x90
        cursor = start + 1
        items: list[object | None] = []
        for _ in range(length):
            item, cursor = decode_msgpack_value(data, cursor)
            items.append(item)
        return items, cursor
    if 0x80 <= marker <= 0x8F:
        length = marker - 0x80
        cursor = start + 1
        mapping: dict[object, object | None] = {}
        for _ in range(length):
            key, cursor = decode_msgpack_value(data, cursor)
            value, cursor = decode_msgpack_value(data, cursor)
            mapping[normalize_msgpack_key(key)] = value
        return mapping, cursor
    if marker == 0xDC and start + 2 < len(data):
        length = int.from_bytes(data[start + 1 : start + 3], "big")
        cursor = start + 3
        items: list[object | None] = []
        for _ in range(length):
            item, cursor = decode_msgpack_value(data, cursor)
            items.append(item)
        return items, cursor
    if marker == 0xDE and start + 2 < len(data):
        length = int.from_bytes(data[start + 1 : start + 3], "big")
        cursor = start + 3
        mapping: dict[object, object | None] = {}
        for _ in range(length):
            key, cursor = decode_msgpack_value(data, cursor)
            value, cursor = decode_msgpack_value(data, cursor)
            mapping[normalize_msgpack_key(key)] = value
        return mapping, cursor
    return None, start


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


def normalize_msgpack_key(key: object | None) -> object:
    if isinstance(key, list):
        return tuple(normalize_msgpack_key(item) for item in key)
    if isinstance(key, dict):
        return tuple((normalize_msgpack_key(item_key), normalize_msgpack_key(item_value)) for item_key, item_value in key.items())
    return key


def value_as_string(value: object | None) -> str:
    return value if isinstance(value, str) else ""


def value_as_int(value: object | None) -> Optional[int]:
    return value if isinstance(value, int) else None


def parse_card_value(value: object | None) -> str:
    if not isinstance(value, list):
        return ""
    for entry in value:
        if not isinstance(entry, dict):
            continue
        card = entry.get(0)
        if isinstance(card, str) and card:
            return card
    return ""


def decode_rights_name(
    permissions_raw: Optional[int],
    *,
    user_id: Optional[int],
    name: str,
    phone: str,
    code: str,
    card: str,
) -> str:
    mapping = {
        0: "coNoAccess",
        1: "coPanic",
        2: "coPGOnly",
        256: "coArmOnly",
        799: "coUserGuard",
        2875: "coService",
        4639: "coPCOGuard",
        1851: "coMaster",
        811: "coUserNoSelfedit",
    }
    if permissions_raw == 827 and user_id is not None and 603 <= user_id <= 610 and name.startswith("User ") and not code and not card:
        return "WPPPhone"
    if permissions_raw in mapping:
        return mapping[permissions_raw]
    if permissions_raw is None:
        return ""
    return f"raw:{permissions_raw}"


def dedupe_user_records(records: Iterable[UserRecord]) -> list[UserRecord]:
    deduped: list[UserRecord] = []
    seen_ids: set[int] = set()
    for record in sorted(records, key=lambda item: item.offset):
        if record.user_id is None:
            deduped.append(record)
            continue
        if record.user_id in seen_ids:
            continue
        seen_ids.add(record.user_id)
        deduped.append(record)
    return deduped


def extract_users(path: Path, *, dedupe: str = "raw") -> list[UserRecord]:
    blob = invert_blob(path.read_bytes())
    starts = find_record_starts(blob)
    users: list[UserRecord] = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else min(len(blob), start + 256)
        record = blob[start:end]

        cursor = 2
        id_bytes = bytearray()
        while cursor < len(record) and record[cursor] != 0x8C and len(id_bytes) < 4:
            id_bytes.append(record[cursor])
            cursor += 1
        if cursor >= len(record) or record[cursor] != 0x8C:
            continue

        field_map_value, _next = decode_msgpack_value(record, cursor)
        if not isinstance(field_map_value, dict):
            continue

        status_raw = value_as_int(field_map_value.get(0))
        permissions_raw = value_as_int(field_map_value.get(1))
        name = value_as_string(field_map_value.get(4))
        if not name:
            continue

        user_id = decode_user_id(bytes(id_bytes))
        phone = value_as_string(field_map_value.get(5))
        code = value_as_string(field_map_value.get(6))
        card = parse_card_value(field_map_value.get(7))
        comment = value_as_string(field_map_value.get(10))

        users.append(
            UserRecord(
                offset=start,
                user_id=user_id,
                raw_id_bytes=bytes(id_bytes).hex(),
                status_raw=status_raw,
                permissions_raw=permissions_raw,
                rights=decode_rights_name(
                    permissions_raw,
                    user_id=user_id,
                    name=name,
                    phone=phone,
                    code=code,
                    card=card,
                ),
                enabled=None if status_raw is None else status_raw != 1,
                name=name,
                phone=phone,
                code=code,
                card=card,
                comment=comment,
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
    pattern = bytes([collection_id, 0x81])
    records: dict[int, dict[object, object | None]] = {}

    try:
        leading_item_id, cursor = decode_msgpack_value(blob, 0)
        leading_fields, _next = decode_msgpack_value(blob, cursor)
    except Exception:
        leading_item_id = None
        leading_fields = None
    if isinstance(leading_item_id, int) and isinstance(leading_fields, dict) and set(leading_fields.keys()) == expected_keys:
        records[leading_item_id] = leading_fields

    offset = 0
    while True:
        offset = blob.find(pattern, offset)
        if offset == -1:
            break
        offset += 1
        try:
            record_value, _next = decode_msgpack_value(blob, offset)
        except Exception:
            continue
        if not isinstance(record_value, dict) or len(record_value) != 1:
            continue
        item_id, fields = next(iter(record_value.items()))
        if not isinstance(item_id, int) or not isinstance(fields, dict):
            continue
        if set(fields.keys()) != expected_keys or item_id in records:
            continue
        records[item_id] = fields
    return records


def extract_export_catalog(path: Path) -> ExportCatalogSnapshot:
    blob = read_decoded_export_blob(path)
    users = extract_users(path, dedupe="dedupe")

    section_fields = _extract_export_collection_records(blob, collection_id=0x06, expected_keys={0, 1, 2, 3, 4})
    object_fields = _extract_export_collection_records(blob, collection_id=0x09, expected_keys={0, 1, 2, 3, 4, 5, 6, 7})
    hardware_fields = _extract_export_collection_records(blob, collection_id=0x0B, expected_keys={0, 1, 2, 3, 4, 5, 6})
    pg_fields = _extract_export_collection_records(
        blob,
        collection_id=0x0C,
        expected_keys=set(range(18)),
    )

    sections_by_id: dict[int, ExportSectionRecord] = {}
    for section_id, fields in section_fields.items():
        name = value_as_string(fields.get(0)).strip()
        if not name:
            continue
        sections_by_id[section_id] = ExportSectionRecord(
            section_id=section_id,
            display_id=section_id + 1,
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

    return ExportCatalogSnapshot(
        path=path,
        users=users,
        sections_by_id=sections_by_id,
        objects_by_id=objects_by_id,
        hardware_by_id=hardware_by_id,
        pgs_by_id=pgs_by_id,
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


def read_import_sector_direct(*, device: str) -> bytes:
    data = read_device_direct_bytes(device=device, start_lba=IMPORT_START_LBA, sectors=1)
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
        "Direct IMPORT.CFG verification failed at LBA 2083 after unmount: "
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
    write_device_direct_bytes(device=device, start_lba=IMPORT_START_LBA, data=expected_sector)
    current = read_import_sector_direct(device=device)
    if current != expected_sector:
        raise SystemExit("Direct IMPORT.CFG staging failed verification at LBA 2083.")
    return expected_sector


def extract_sections_state_mode(packet: bytes) -> int | None:
    if Jablotron._is_sections_states_packet(packet) and packet:
        return packet[-1]
    return None


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
    cleanup_sections_mode: int | None = None
    if trigger:
        trigger_live_export(port=port, code=code, reset=reset)
    read_export_direct(device=device, output=output, start_lba=start_lba, sectors=sectors)
    if trigger and cleanup_mode != "none":
        cleanup_sections_mode = cleanup_read_session(port=port, code=code, cleanup_mode=cleanup_mode, verbose=verbose)
        if cleanup_sections_mode != EXITED_SECTIONS_MODE:
            raise SystemExit(
                "Read-session cleanup did not reach the exited state "
                f"(expected 0x{EXITED_SECTIONS_MODE:02x}, got {cleanup_sections_mode!r})."
            )
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    raw_records = extract_users(output, dedupe="raw")
    records = dedupe_user_records(raw_records)
    return ExportSnapshot(path=output, sha256=digest, raw_records=raw_records, records=records)


def run_command(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def stage_import(import_path: Path, sector_path: Path) -> None:
    sector = sector_path.read_bytes()[:SECTOR_SIZE]
    write_error: OSError | None = None

    with import_path.open("r+b", buffering=0) as handle:
        try:
            handle.seek(0)
            handle.write(sector)
            handle.flush()
            os.fsync(handle.fileno())
        except OSError as exc:
            write_error = exc

    current = import_path.read_bytes()[:SECTOR_SIZE]
    if current != sector:
        if write_error is not None:
            raise SystemExit(f"IMPORT.CFG staging failed and did not verify: {write_error}") from write_error
        raise SystemExit("IMPORT.CFG staging failed verification.")

    if write_error is not None:
        print(f"warning: write raised {write_error}; continuing because staged bytes verified exactly")


def mount_device(device: str, mountpoint: Path, *, mount_tool: str) -> None:
    resolved_device = resolve_flexi_cfg_device(device)
    suppress_message = False
    if mount_tool == "sudo":
        mountpoint.mkdir(parents=True, exist_ok=True)
        result = run_command(["sudo", "-n", "mount", resolved_device, str(mountpoint)], check=False)
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


def unmount_device(device: str, *, mount_tool: str) -> None:
    resolved_device = resolve_flexi_cfg_device(device)
    suppress_message = False
    if mount_tool == "sudo":
        result = run_command(["sudo", "-n", "umount", resolved_device], check=False)
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
                if saw_1a0a and sections_mode == 0x94:
                    saw_sections_94 = True

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
                "saw_1b00": saw_1b00,
                "last_keepalive_at": last_keepalive_at,
                "next_keepalive_at": next_keepalive_at,
                "entered_setup": entered_setup,
            },
        )

    if not entered_setup:
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
                    extract_sections_state_mode(packet)
                    for packet in [*pre_packets, *exit_packets, *post_packets]
                )
                if mode is not None
            ]
            final_mode = observed_modes[-1] if observed_modes else None
            if verbose:
                print("read_cleanup", {"attempt": attempt, "sections_mode": final_mode})
            if final_mode == 0x90:
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
) -> ExportSnapshot | None:
    resolved_device = resolve_flexi_cfg_device(device)
    mountpoint = import_path.parent
    remount_after = False
    if stage_mode not in {"direct", "filesystem"}:
        raise SystemExit(f"Unsupported stage mode: {stage_mode}")
    if stage_mode == "filesystem":
        mount_device(resolved_device, mountpoint, mount_tool=mount_tool)
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
            if stage_mode == "filesystem":
                stage_import(import_path, sector_path)
                unmount_device(resolved_device, mount_tool=mount_tool)
                if verbose:
                    expected_sector = sector_path.read_bytes()[:SECTOR_SIZE]
                    print("import_sector_probe", {"lba": IMPORT_START_LBA, "matched": probe_import_sector_direct(device=resolved_device, expected_sector=expected_sector)})
            else:
                stage_import_direct(device=resolved_device, sector_path=sector_path)
                if verbose:
                    print("import_sector_lba", IMPORT_START_LBA)
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
        return pull_live_export_snapshot(
            output=verify_output,
            device=resolved_device,
            port=port,
            code=code,
            reset=reset,
        )
    finally:
        if remount_after:
            mount_device(resolved_device, mountpoint, mount_tool=mount_tool)
