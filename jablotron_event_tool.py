#!/usr/bin/env python3
"""Pull Jablotron event-memory archive windows from FLEXI_LOG."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import TextIO

from jablotron_re_tools import (
    CONFIGURATION_SECTIONS_MODE,
    EXITED_SECTIONS_MODE,
    JablotronUSBClient,
    add_flexi_log_device_argument,
    cleanup_read_session,
    configuration_in_use_message,
    describe_sections_mode,
    drain_packets,
    enter_setup_mode,
    extract_export_catalog,
    extract_sections_state_mode,
    graceful_exit_session,
    mount_device,
    pull_live_export_snapshot,
    resolve_flexi_log_device,
    unmount_device,
)
from jablotron_usb_debug import ensure_serial_port, perform_login

DEFAULT_FLEXI_LOG_MOUNTPOINT = Path("/mnt/flexi_log")
DEFAULT_WINDOW_BYTES = 102400
DEFAULT_FILES = ("FLEXILOG.OLD", "FLEXILOG.TXT", "LOGINDEX.BIN")
MIN_VALID_UNIX_TS = 946684800
COMPACT_NUMERIC_TRANSLATION = str.maketrans(
    {
        "P": "0",
        "Q": "1",
        "R": "2",
        "S": "3",
        "T": "4",
        "U": "5",
        "V": "6",
        "W": "7",
        "X": "8",
        "Y": "9",
        "Z": ":",
    }
)
MIXED_EVENT_PREFIX_RE = re.compile(r"^(?:[0-9P-Y]{6} )?[0-9P-Y]{2}[:Z][0-9P-Y]{2}[:Z][0-9P-Y]{2} ")
DECODED_EVENT_RE = re.compile(
    r"^(?:(?P<date>\d{6}) )?(?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<kind>EVENT|INFO)\((?P<id>\d+)\):(?P<code>\d+),(?P<text>[^;]*);"
    r"(?: Src:(?P<src_id>\d+),(?P<src_name>[^;]*);)?"
    r"(?: Chnl:(?P<channel>[^;]*);)?"
    r"(?: Sect:(?P<section>[^;]*);)?"
)
TIMESTAMP_PREFIX_RE = re.compile(r"(?:[0-9P-Y]{6} )?[0-9P-Y]{2}[:Z][0-9P-Y]{2}[:Z][0-9P-Y]{2} ")
NUMERIC_REGION_RE = re.compile(r"(?<![A-Za-zÀ-ž])([0-9P-YZ][0-9P-YZ:.-]{1,})(?![A-Za-zÀ-ž])")
INFO_DELIVERED_RE = re.compile(
    r"^(?:(?P<date>\d{6}) )?(?P<time>\d{2}:\d{2}:\d{2}) "
    r"INFO\((?P<route>[^,]+),(?P<event_id>\d+)\):(?P<message>EVENT DELIVERED|EVENT NOT DELIVERED)$",
    re.IGNORECASE,
)
INFO_GENERIC_RE = re.compile(
    r"^(?:(?P<date>\d{6}) )?(?P<time>\d{2}:\d{2}:\d{2}) "
    r"INFO\((?P<subject>[^)]*)\):(?P<message>.+)$",
    re.IGNORECASE,
)
UUID_RE = re.compile(r"(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
HOST_USER_RE = re.compile(r"([A-Za-z0-9_.-]+\\[A-Za-z0-9_.-]+)")
EVENT_TEXT_BY_CODE = {
    "18": "Oneskorený poplach",
    "19": "Zrušenie poplachu",
    "21": "Aktivacia-oneskoreny detektor",
    "22": "Ukludnenie-oneskor. Detektor",
    "44": "Vstup do režimu servis",
    "48": "Zmena konfigurácie",
    "119": "Neplatná autorizace",
    "123": "Kontrolný prenos na PCO 1",
    "132": "Porucha začiatok",
    "150": "Autorizácia OK",
    "156": "Spojenie nadviazané",
    "157": "Spojenie ukončené",
    "194": "Zablokované pri zap. ochrany",
    "195": "Blokovanie ukončené",
    "40": "Zapnutá ochrana",
    "41": "Vypnutá ochrana",
}
CHANNEL_ALIAS_MAP = {
    "0": "0: Ústredňa",
    "arc1": "ARC 1",
    "arc 1": "ARC 1",
    "gsm": "GSM",
    "inet_a": "Server",
    "inet_b": "Server",
    "ineta": "Server",
    "inetb": "Server",
    "lan": "LAN",
    "pstn": "PSTN",
    "server": "Server",
    "sms": "SMS",
    "usb": "USB",
}
PERIPHERAL_SOURCE_BASE = 26
USER_SOURCE_BASE = 267
PG_ON_MIN_CODE = 51
PG_ON_MAX_CODE = 82
PG_OFF_MIN_CODE = 83
PG_OFF_MAX_CODE = 114

@dataclass(frozen=True)
class LogPoint:
    timestamp: int
    offset: int


@dataclass(frozen=True)
class EventArchiveSnapshot:
    output: Path
    metadata_output: Path
    transport: str
    sha256: str
    log_device: str
    old_size: int
    current_size: int
    physical_total: int
    logical_end: int
    window_start: int
    window_bytes: int
    record_count: int
    record_length_histogram: dict[int, int]
    record_preview: list[EventRecord]
    index_points: list[LogPoint]
    crlf_part_lengths: list[int]
    printable_preview: list[str]
    last_nonzero_offset: int | None = None
    populated_bytes: int | None = None
    trailing_zero_bytes: int | None = None


@dataclass(frozen=True)
class EventRecord:
    index: int
    offset: int
    length: int
    sha256: str
    hex_prefix: str
    printable_preview: str


@dataclass(frozen=True)
class DecodedEventRecord:
    text: str
    kind: str | None
    timestamp_prefix: str | None
    event_id: str | None
    event_code: str | None
    event_text: str | None
    info_subject: str | None
    info_message: str | None
    source_id: str | None
    source_name: str | None
    channel: str | None
    section: str | None


@dataclass(frozen=True)
class DecoderCatalog:
    user_labels_by_name_key: dict[str, str]
    event_text_by_code: dict[str, str]
    object_name_by_id: dict[int, str]
    source_labels_by_object_id: dict[int, str]
    channel_labels_by_id: dict[int, str]
    pg_names_by_id: dict[int, str]
    section_names_by_display_id: dict[int, str]
    user_labels_by_slot: dict[int, str]


@dataclass(frozen=True)
class FLinkExportRow:
    event_id: str | None
    timestamp: str
    source: str
    section: str
    event: str
    channel: str


@dataclass(frozen=True)
class AlignedEventRow:
    event_id: str
    decoded_timestamp: str | None
    decoded_code: str | None
    decoded_event: str | None
    decoded_source: str | None
    decoded_channel: str | None
    decoded_section: str | None
    export_timestamp: str | None
    export_event: str | None
    export_source: str | None
    export_channel: str | None
    export_section: str | None
    status: str

def read_log_index_points(path: Path) -> list[LogPoint]:
    blob = path.read_bytes()
    points: list[LogPoint] = []
    for offset in range(0, len(blob), 16):
        chunk = blob[offset : offset + 16]
        if len(chunk) < 16:
            break
        values = [int.from_bytes(chunk[index : index + 4], "little") for index in range(0, 16, 4)]
        for timestamp, file_offset in ((values[0], values[1]), (values[2], values[3])):
            if timestamp < MIN_VALID_UNIX_TS or file_offset <= 0:
                continue
            points.append(LogPoint(timestamp=timestamp, offset=file_offset))
    return points


def find_last_nonzero_offset(data: bytes) -> int | None:
    """Return the index of the last non-zero byte in ``data`` or ``None``.

    FLEXILOG files are fixed-size preallocated archives where unused tail bytes
    are zero. Knowing the last non-zero offset tells callers how much of the
    archive actually contains events and how much is pre-erased flash padding.
    """
    if not data:
        return None
    stripped = data.rstrip(b"\x00")
    if not stripped:
        return None
    return len(stripped) - 1


def read_combined_log_range(*, old_path: Path, current_path: Path, start: int, length: int) -> bytes:
    old_size = old_path.stat().st_size
    output = bytearray()
    remaining = length
    position = start

    if position < old_size:
        chunk = min(remaining, old_size - position)
        with old_path.open("rb") as handle:
            handle.seek(position)
            output.extend(handle.read(chunk))
        remaining -= chunk
        position = old_size

    if remaining > 0:
        current_offset = max(0, position - old_size)
        with current_path.open("rb") as handle:
            handle.seek(current_offset)
            output.extend(handle.read(remaining))

    return bytes(output)


def isoformat_utc(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat().replace("+00:00", "Z")


def build_printable_preview(data: bytes, *, limit: int) -> list[str]:
    preview: list[str] = []
    current = bytearray()
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(byte)
            continue
        if len(current) >= 6:
            preview.append(current.decode("ascii", "replace"))
            if len(preview) >= limit:
                break
        current.clear()
    if len(current) >= 6 and len(preview) < limit:
        preview.append(current.decode("ascii", "replace"))
    return preview


def build_single_printable_preview(data: bytes, *, limit: int = 1) -> str:
    preview = build_printable_preview(data, limit=limit)
    return preview[0] if preview else ""


def split_crlf_records(data: bytes, *, base_offset: int) -> list[EventRecord]:
    records: list[EventRecord] = []
    cursor = 0
    parts = data.split(b"\r\n")
    for index, part in enumerate(parts):
        if not part:
            cursor += 2
            continue
        records.append(
            EventRecord(
                index=index,
                offset=base_offset + cursor,
                length=len(part),
                sha256=hashlib.sha256(part).hexdigest(),
                hex_prefix=part[:24].hex(),
                printable_preview=build_single_printable_preview(part),
            )
        )
        cursor += len(part)
        if index != len(parts) - 1:
            cursor += 2
    return records


def delta_decode_record(data: bytes) -> bytes:
    decoded = bytearray()
    previous = 0
    for byte in data:
        decoded.append((byte - previous) & 0xFF)
        previous = byte
    return bytes(decoded)


def is_compact_upper_ascii(value: int) -> bool:
    return 0x21 <= value <= 0x3A


def is_ambiguous_alpha(value: int) -> bool:
    return 0x41 <= value <= 0x5A


def compact_base_ascii(value: int) -> int:
    if value <= 0x3F:
        return value + 0x20
    return value


def compact_is_token_separator(value: int) -> bool:
    return compact_base_ascii(value) in {0x20, 0x28, 0x29, 0x2C, 0x3A, 0x3B, 0x3D, 0x5B, 0x5C, 0x5D, 0x7B, 0x7D}


def compact_token_has_explicit_lowercase(delta: bytes, index: int) -> bool:
    for probe in range(index, len(delta)):
        candidate = delta[probe]
        if compact_is_token_separator(candidate):
            break
        if 0x61 <= candidate <= 0x7A:
            return True
    return False


def compact_case_mode_hint(delta: bytes, index: int) -> str | None:
    for probe in range(index + 1, min(len(delta), index + 4)):
        candidate = delta[probe]
        if candidate in {0x00, 0x0C, 0x1B, 0x3B, 0x3F}:
            return None
        if is_compact_upper_ascii(candidate):
            return "upper"
        if is_ambiguous_alpha(candidate) or 0x61 <= candidate <= 0x7A:
            return "lower"
    return None


def compact_decode_text(data: bytes) -> str:
    delta = delta_decode_record(data)
    if delta and (delta[0] < 0x20 or delta[0] > 0x7E):
        delta = delta[1:]

    decoded = bytearray()
    remaining_utf8 = 0
    case_mode: str | None = None
    title_prefixes = {0x28, 0x3A, 0x2C, 0x2D, 0x5C, 0x7B}
    for index, byte in enumerate(delta):
        value = byte
        previous_value = decoded[-1] if decoded else None
        if remaining_utf8 and 0x40 <= value <= 0x7F:
            value += 0x20
        elif value <= 0x3F:
            value += 0x20
            if 0x41 <= value <= 0x5A:
                case_mode = "upper"
            elif value in {0x20, 0x2C, 0x3B, 0x3D, 0x5D, 0x5F}:
                case_mode = None
        elif is_ambiguous_alpha(value):
            has_lowercase_ahead = compact_token_has_explicit_lowercase(delta, index)
            token_initial = previous_value is None or not chr(previous_value).isalnum()
            if has_lowercase_ahead:
                if not (token_initial and previous_value in title_prefixes):
                    value += 0x20
            else:
                if case_mode is None:
                    case_mode = compact_case_mode_hint(delta, index)
                if case_mode != "upper":
                    value += 0x20
        decoded.append(value)

        if 0xC2 <= value <= 0xDF:
            remaining_utf8 = 1
        elif 0xE0 <= value <= 0xEF:
            remaining_utf8 = 2
        elif 0xF0 <= value <= 0xF4:
            remaining_utf8 = 3
        elif remaining_utf8:
            remaining_utf8 -= 1
        elif 0x41 <= value <= 0x5A:
            case_mode = "upper"
        elif 0x61 <= value <= 0x7A:
            case_mode = "lower"
        elif value in {0x20, 0x2C, 0x3B, 0x3D, 0x5D, 0x5F}:
            case_mode = None

    return decoded.decode("utf-8", "replace").replace("\x00", " ").strip()


def normalize_numeric_token(token: str) -> str:
    return token.translate(COMPACT_NUMERIC_TRANSLATION)


def simplify_match_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "", ascii_only.lower())


def titlecase_words(value: str) -> str:
    words: list[str] = []
    for token in value.split():
        if not token:
            continue
        if any(character.isdigit() for character in token):
            words.append(token)
            continue
        if token.isupper() and len(token) <= 4:
            words.append(token)
            continue
        words.append(token[:1].upper() + token[1:].lower())
    return " ".join(words)


def text_quality_key(value: str) -> tuple[int, int, int, int]:
    simplified = simplify_match_text(value)
    return (
        len(simplified),
        sum(1 for character in value if character.isalpha()),
        sum(1 for character in value if ord(character) > 127),
        -value.count("\ufffd"),
    )


def choose_better_text(current: str | None, candidate: str | None) -> str | None:
    if not candidate:
        return current
    if not current:
        return candidate
    return candidate if text_quality_key(candidate) > text_quality_key(current) else current


def normalize_timestamp(date: str | None, time_value: str) -> str:
    if date:
        return f"{normalize_numeric_token(date)} {normalize_numeric_token(time_value)}"
    return normalize_numeric_token(time_value)


def normalize_decoded_text(text: str) -> str:
    match = TIMESTAMP_PREFIX_RE.search(text)
    if match:
        text = text[match.start() :]

    text = NUMERIC_REGION_RE.sub(lambda item: normalize_numeric_token(item.group(0)), text)
    text = (
        text.replace("EVENTH", "EVENT(")
        .replace("INFOH", "INFO(")
        .replace("eVENTH", "EVENT(")
        .replace("iNFOH", "INFO(")
        .replace("[", ";")
    )
    text = re.sub(r"(?i)\bevent(?=\()", "EVENT", text)
    text = re.sub(r"(?i)\binfo(?=\()", "INFO", text)
    text = re.sub(r"(?i)INFO\((ARC1?)\)", lambda item: f"INFO({item.group(1).upper()})", text)
    text = re.sub(r"(?i)INFO\(DEVICE([LI])", "INFO(DEVICE,", text)
    text = re.sub(r"(?i)INFO\(ARC[1Q]L(\d+)\)", r"INFO(ARC1,\1)", text)
    text = re.sub(r"(?i)\bsrcz(?=\d|[,;:])", "Src:", text)
    text = re.sub(r"(?i)\bchnlz(?=[A-Za-z0-9_]|[,;:])", "Chnl:", text)
    text = re.sub(r"(?i)\bsectz(?=\d|[,;:])", "Sect:", text)
    text = re.sub(r"(?i)\bsrc(?=:)", "Src", text)
    text = re.sub(r"(?i)\bchnl(?=:)", "Chnl", text)
    text = re.sub(r"(?i)\bsect(?=:)", "Sect", text)
    text = re.sub(r"(?i)Chnl:(?:53B|5SB|5Sb|53b);", "Chnl:USB;", text)
    text = text.replace("53B", "USB").replace("5Sb", "USB").replace("5SB", "USB")
    text = text.replace(")Z", "):").replace(")z", "):")
    return re.sub(r"\s+", " ", text).strip()


def repair_event_line_structure(text: str) -> str:
    repaired = text
    repaired = re.sub(r"(?i)EVENT\((\d+)[A-Z]:(\d+)", r"EVENT(\1):\2", repaired)
    repaired = re.sub(r"(?i)(EVENT\(\d+\):\d+)[A-Z](?=[A-Za-zÀ-ž])", r"\1,", repaired)
    repaired = re.sub(r"(?i)(Src:\d+)[A-Z](?=[A-Za-zÀ-ž�])", r"\1,", repaired)
    repaired = re.sub(r"(?i)Chnl:INeT_A", "Chnl:INET_A", repaired)
    repaired = re.sub(r"(?i)Chnl:uSB", "Chnl:USB", repaired)
    return repaired


def normalize_route_suffix(value: str) -> str:
    return value.upper().translate(COMPACT_NUMERIC_TRANSLATION)


def normalize_channel_route_name(value: str) -> str | None:
    simplified = simplify_match_text(value)
    if not simplified:
        return None
    return CHANNEL_ALIAS_MAP.get(simplified) or CHANNEL_ALIAS_MAP.get(value.lower())


def normalize_source_route_name(value: str) -> str | None:
    simplified = simplify_match_text(value)
    if not simplified:
        return None
    if simplified == "ustredna":
        return "Ústredňa"
    if simplified in {"kalendar", "kalendr"}:
        return "Kalendár"
    if simplified == "homeassistant":
        return "HomeAssistant"
    if simplified == "arc":
        return "ARC"
    if simplified.startswith("arc") and len(simplified) > 3:
        suffix = normalize_route_suffix(simplified[3:])
        if suffix.isdigit():
            return f"ARC{suffix}"
    if simplified.startswith("pco") and len(simplified) > 3:
        suffix = normalize_route_suffix(simplified[3:])
        if suffix.isdigit():
            return f"PCO {suffix}"
    return None


def prettify_value(value: str, *, mode: str) -> str:
    cleaned = re.sub(r"\s+", " ", value).strip().replace("\ufffd", "")
    if not cleaned:
        return cleaned
    if mode == "channel":
        if re.fullmatch(r"[0-9P-YZ]+", cleaned):
            cleaned = normalize_numeric_token(cleaned)
        normalized_route = normalize_channel_route_name(cleaned)
        if normalized_route:
            return normalized_route
        lowered = cleaned.lower()
        return cleaned.upper() if lowered in {"lan", "pstn"} else cleaned
    if mode == "source":
        normalized_route = normalize_source_route_name(cleaned)
        return normalized_route if normalized_route else titlecase_words(cleaned)
    lowered = cleaned.lower()
    return lowered[:1].upper() + lowered[1:]


def normalize_event_text(event_code: str | None, value: str) -> str:
    if event_code and event_code in EVENT_TEXT_BY_CODE:
        return EVENT_TEXT_BY_CODE[event_code]
    return prettify_value(value, mode="event")


def normalize_host_user(value: str) -> str:
    cleaned = value.strip().strip("]}_;, ")
    if "\\" not in cleaned:
        return cleaned
    host, user = cleaned.split("\\", 1)
    host = re.sub(r"[^A-Za-z0-9_.-]+", "", host)
    user = re.sub(r"[^A-Za-z0-9_.-]+", "", user)
    if host:
        host = host.upper()
    if user:
        user = user[:1].upper() + user[1:].lower()
    return f"{host}\\{user}" if host and user else cleaned


def extract_comm_log_name(value: str) -> str | None:
    match = re.search(r"([A-Za-z]:\\[^;]*?comm\.log[^; ]*|/[^; ]*comm\.log[^; ]*)", value, re.IGNORECASE)
    if not match:
        return None
    path = match.group(1)
    return re.split(r"[\\/]", path)[-1]


@lru_cache(maxsize=8)
def load_decoder_catalog(fdb_path: str) -> DecoderCatalog:
    from fdb_tool import choose_snapshot, find_user_snapshots, iter_user_rows, read_fdb

    container = read_fdb(Path(fdb_path))
    snapshot = choose_snapshot(find_user_snapshots(container.xml_text), "latest")
    root = ET.fromstring(container.xml_bytes)
    labels: dict[str, str] = {}
    ambiguous: set[str] = set()
    user_labels_by_slot: dict[int, str] = {}

    for record in iter_user_rows(snapshot, include_null=False):
        if record.slot_index != record.user_id:
            continue
        name = record.properties.get("Name", "").strip()
        if not name or name.startswith("Užívateľ "):
            continue
        key = simplify_match_text(name)
        if not key:
            continue
        label = f"Užívateľ {record.slot_index}: {name}"
        user_labels_by_slot[record.slot_index] = label
        existing = labels.get(key)
        if existing and existing != label:
            ambiguous.add(key)
            continue
        labels[key] = label

    for key in ambiguous:
        labels.pop(key, None)

    def find_named_class(name: str) -> ET.Element | None:
        for node in root.iter("class"):
            if node.attrib.get("name") == name:
                return node
        return None

    def build_map(class_name: str, value_name: str) -> dict[int, str]:
        node = find_named_class(class_name)
        if node is None:
            return {}
        mapping: dict[int, str] = {}
        for item in node.findall("./item"):
            props = {
                prop.attrib.get("name"): (prop.text or "").strip()
                for prop in item.findall("./property")
            }
            if "ID" not in props or value_name not in props:
                continue
            try:
                item_id = int(props["ID"])
            except ValueError:
                continue
            mapping[item_id] = props[value_name]
        return mapping

    event_text_by_code = {str(key): value for key, value in build_map("TJA100AllTexts", "Text").items()}
    peripheral_names = build_map("TJA100AllPeripherals", "Name")
    object_name_by_id = {0: "Ústredňa", **peripheral_names}
    source_labels_by_object_id = {0: "Ústredňa"}
    channel_labels_by_id = {0: "0: Ústredňa"}
    for object_id, name in peripheral_names.items():
        source_labels_by_object_id[object_id] = f"Periféria {object_id}: {name}"
        channel_labels_by_id[object_id] = f"{object_id}: {name}"
    pg_names_by_id = build_map("TJA100AllPGs", "Name")
    section_names_raw = build_map("TJA100AllSections", "Name")
    section_names_by_display_id = {section_id + 1: name for section_id, name in section_names_raw.items()}

    return DecoderCatalog(
        user_labels_by_name_key=labels,
        event_text_by_code=event_text_by_code,
        object_name_by_id=object_name_by_id,
        source_labels_by_object_id=source_labels_by_object_id,
        channel_labels_by_id=channel_labels_by_id,
        pg_names_by_id=pg_names_by_id,
        section_names_by_display_id=section_names_by_display_id,
        user_labels_by_slot=user_labels_by_slot,
    )


@lru_cache(maxsize=16)
def load_export_decoder_catalog(export_cfg_path: str) -> DecoderCatalog:
    snapshot = extract_export_catalog(Path(export_cfg_path))
    labels: dict[str, str] = {}
    ambiguous: set[str] = set()
    user_labels_by_slot: dict[int, str] = {}

    for record in snapshot.users:
        if record.user_id is None or record.user_id <= 0:
            continue
        name = record.name.strip()
        if not name:
            continue
        label = f"Užívateľ {record.user_id}: {name}"
        user_labels_by_slot[record.user_id] = label
        key = simplify_match_text(name)
        if not key:
            continue
        existing = labels.get(key)
        if existing and existing != label:
            ambiguous.add(key)
            continue
        labels[key] = label

    for key in ambiguous:
        labels.pop(key, None)

    object_name_by_id = {record.object_id: record.name for record in snapshot.objects_by_id.values()}
    source_labels_by_object_id: dict[int, str] = {0: "Ústredňa"}
    channel_labels_by_id: dict[int, str] = {0: "0: Ústredňa"}

    for object_id, record in snapshot.objects_by_id.items():
        object_name_by_id[object_id] = record.name
        if object_id == 0:
            continue
        if object_id >= 233 or record.name.lower().endswith("communicator"):
            source_labels_by_object_id[object_id] = record.name
        else:
            source_labels_by_object_id[object_id] = f"Periféria {object_id}: {record.name}"
        channel_labels_by_id[object_id] = f"{object_id}: {record.name}"

    pg_names_by_id = {record.pg_id: record.name for record in snapshot.pgs_by_id.values()}
    section_names_by_display_id = {
        record.display_id: record.name for record in snapshot.sections_by_id.values()
    }

    return DecoderCatalog(
        user_labels_by_name_key=labels,
        event_text_by_code={},
        object_name_by_id=object_name_by_id,
        source_labels_by_object_id=source_labels_by_object_id,
        channel_labels_by_id=channel_labels_by_id,
        pg_names_by_id=pg_names_by_id,
        section_names_by_display_id=section_names_by_display_id,
        user_labels_by_slot=user_labels_by_slot,
    )


def merge_decoder_catalogs(primary: DecoderCatalog | None, secondary: DecoderCatalog | None) -> DecoderCatalog | None:
    if primary is None:
        return secondary
    if secondary is None:
        return primary
    return DecoderCatalog(
        user_labels_by_name_key={**primary.user_labels_by_name_key, **secondary.user_labels_by_name_key},
        event_text_by_code={**primary.event_text_by_code, **secondary.event_text_by_code},
        object_name_by_id={**primary.object_name_by_id, **secondary.object_name_by_id},
        source_labels_by_object_id={**primary.source_labels_by_object_id, **secondary.source_labels_by_object_id},
        channel_labels_by_id={**primary.channel_labels_by_id, **secondary.channel_labels_by_id},
        pg_names_by_id={**primary.pg_names_by_id, **secondary.pg_names_by_id},
        section_names_by_display_id={**primary.section_names_by_display_id, **secondary.section_names_by_display_id},
        user_labels_by_slot={**primary.user_labels_by_slot, **secondary.user_labels_by_slot},
    )


def resolve_decoder_catalog(
    *,
    fdb_path: str | None = None,
    export_cfg_path: str | None = None,
) -> DecoderCatalog | None:
    catalog: DecoderCatalog | None = None
    if fdb_path:
        catalog = load_decoder_catalog(str(Path(fdb_path)))
    if export_cfg_path:
        catalog = merge_decoder_catalogs(catalog, load_export_decoder_catalog(str(Path(export_cfg_path))))
    return catalog


def pull_runtime_export_catalog(args: argparse.Namespace, *, prefix: str) -> tuple[DecoderCatalog | None, Path]:
    output = Path("/tmp") / f"{datetime.now().strftime('%Y-%m-%d_%H%M%S')}_{prefix}_EXPORT.CFG.bin"
    snapshot = pull_live_export_snapshot(
        output=output,
        device="auto",
        port=args.port,
        code=args.auth_code,
        reset=not args.no_reset,
        trigger=True,
        cleanup_mode="auto",
        verbose=args.verbose,
    )
    return load_export_decoder_catalog(str(snapshot.path)), snapshot.path


def decode_pg_event_text(event_code: str, catalog: DecoderCatalog | None) -> str | None:
    if not event_code.isdigit():
        return None
    code = int(event_code)
    if PG_ON_MIN_CODE <= code <= PG_ON_MAX_CODE:
        pg_number = code - 50
        if catalog:
            pg_name = catalog.pg_names_by_id.get(pg_number - 1)
            if pg_name:
                return f"PG {pg_number}: {pg_name} Zap."
        return f"PG {pg_number}: Zap."
    if PG_OFF_MIN_CODE <= code <= PG_OFF_MAX_CODE:
        pg_number = code - 82
        if catalog:
            pg_name = catalog.pg_names_by_id.get(pg_number - 1)
            if pg_name:
                return f"PG {pg_number}: {pg_name} Vyp."
        return f"PG {pg_number}: Vyp."
    return None


def normalize_event_label(*, event_code: str | None, event_text: str, catalog: DecoderCatalog | None) -> str:
    if not event_code:
        return event_text
    pg_text = decode_pg_event_text(event_code, catalog)
    if pg_text:
        return pg_text
    if event_code in EVENT_TEXT_BY_CODE:
        return EVENT_TEXT_BY_CODE[event_code]
    if catalog and event_code in catalog.event_text_by_code:
        return catalog.event_text_by_code[event_code]
    return event_text


def normalize_channel_label(channel: str | None, catalog: DecoderCatalog | None) -> str | None:
    if not channel:
        return channel
    lowered = channel.lower()
    if lowered in CHANNEL_ALIAS_MAP:
        return CHANNEL_ALIAS_MAP[lowered]
    if not catalog:
        return channel
    if channel.isdigit():
        channel_id = int(channel)
        label = catalog.channel_labels_by_id.get(channel_id)
        if label:
            return label
    return channel


def normalize_source_label(
    *,
    source_id: str | None,
    source_name: str | None,
    event_code: str | None,
    catalog: DecoderCatalog | None,
) -> str | None:
    if catalog and source_id:
        slot = source_id_to_user_slot(source_id)
        if slot is not None:
            label = catalog.user_labels_by_slot.get(slot)
            if label:
                return label
        object_id = source_id_to_object_id(source_id)
        if object_id is not None:
            label = catalog.source_labels_by_object_id.get(object_id)
            if label:
                return label
    if not source_name:
        return source_name
    if event_code in {"150", "40", "41"} and catalog:
        label = catalog.user_labels_by_name_key.get(simplify_match_text(source_name))
        if label:
            return label
    return source_name


def normalize_section_label(section: str | None, catalog: DecoderCatalog | None) -> str | None:
    if not section:
        return section
    if not catalog:
        return section
    try:
        display_id = int(section)
    except ValueError:
        return section
    name = catalog.section_names_by_display_id.get(display_id)
    if not name:
        return section
    return f"{display_id}: {name}"


def source_id_to_user_slot(source_id: str | None) -> int | None:
    if not source_id or not source_id.isdigit():
        return None
    raw_source_id = int(source_id)
    if raw_source_id < USER_SOURCE_BASE:
        return None
    return raw_source_id - USER_SOURCE_BASE


def source_id_to_object_id(source_id: str | None) -> int | None:
    if not source_id or not source_id.isdigit():
        return None
    raw_source_id = int(source_id)
    if raw_source_id >= USER_SOURCE_BASE or raw_source_id < PERIPHERAL_SOURCE_BASE:
        return None
    return raw_source_id - PERIPHERAL_SOURCE_BASE


def rebuild_decoded_event_text(record: DecodedEventRecord) -> str:
    if record.kind == "EVENT":
        parts = [record.timestamp_prefix or "", f"EVENT({record.event_id}):{record.event_code},{record.event_text};"]
        if record.source_id or record.source_name:
            parts.append(f"Src:{record.source_id},{record.source_name};")
        if record.channel:
            parts.append(f"Chnl:{record.channel};")
        if record.section:
            parts.append(f"Sect:{record.section};")
        return " ".join(part for part in parts if part)
    if record.kind == "INFO":
        label = f"INFO({record.info_subject}{',' + record.event_id if record.event_id else ''})"
        return f"{record.timestamp_prefix} {label}:{record.info_message}"
    return record.text


def canonicalize_decoded_records(
    records: list[DecodedEventRecord],
    *,
    catalog: DecoderCatalog | None = None,
) -> list[DecodedEventRecord]:
    if not records:
        return records

    best_source_name_by_id: dict[str, str] = {}
    best_event_text_by_code: dict[str, str] = {}
    object_name_by_id: dict[int, str] = {}

    for record in records:
        if record.kind != "EVENT":
            continue
        if not catalog and record.source_id and record.source_name:
            best_source_name_by_id[record.source_id] = choose_better_text(
                best_source_name_by_id.get(record.source_id),
                record.source_name,
            ) or record.source_name
            object_id = source_id_to_object_id(record.source_id)
            if object_id is not None:
                object_name_by_id[object_id] = choose_better_text(
                    object_name_by_id.get(object_id),
                    record.source_name,
                ) or record.source_name
        if record.event_code and record.event_text and record.event_text != "No text":
            if record.event_code not in EVENT_TEXT_BY_CODE:
                best_event_text_by_code[record.event_code] = choose_better_text(
                    best_event_text_by_code.get(record.event_code),
                    record.event_text,
                ) or record.event_text

    output: list[DecodedEventRecord] = []
    for record in records:
        if record.kind != "EVENT":
            output.append(record)
            continue

        source_name = record.source_name if catalog else best_source_name_by_id.get(record.source_id or "", record.source_name)
        channel = record.channel
        section = record.section
        event_text = record.event_text

        if record.event_code and (
            record.event_code in EVENT_TEXT_BY_CODE
            or (catalog is not None and record.event_code in catalog.event_text_by_code)
        ):
            event_text = normalize_event_label(
                event_code=record.event_code,
                event_text=event_text or "No text",
                catalog=catalog,
            )
        elif event_text == "No text" and record.event_code:
            event_text = normalize_event_label(
                event_code=record.event_code,
                event_text=event_text,
                catalog=catalog,
            )
        elif record.event_code and record.event_code in best_event_text_by_code:
            event_text = best_event_text_by_code[record.event_code]

        if catalog:
            source_name = normalize_source_label(
                source_id=record.source_id,
                source_name=source_name,
                event_code=record.event_code,
                catalog=catalog,
            )
            channel = normalize_channel_label(channel, catalog)
            section = normalize_section_label(section, catalog)
        else:
            user_slot = source_id_to_user_slot(record.source_id)
            object_id = source_id_to_object_id(record.source_id)
            if user_slot is not None and source_name and not source_name.startswith("Užívateľ "):
                source_name = f"Užívateľ {user_slot}: {source_name}"
            elif object_id is not None and source_name and not source_name.startswith("Periféria "):
                source_name = f"Periféria {object_id}: {source_name}"

            if channel and channel.isdigit():
                channel_id = int(channel)
                if channel_id == 0:
                    channel = "0: Ústredňa"
                elif channel_id in object_name_by_id:
                    channel = f"{channel_id}: {object_name_by_id[channel_id]}"

        updated = replace(
            record,
            event_text=event_text,
            source_name=source_name,
            channel=channel,
            section=section,
        )
        output.append(replace(updated, text=rebuild_decoded_event_text(updated)))
    return output


def build_info_record(*, date: str | None, time_value: str, subject: str, message: str, event_id: str | None) -> DecodedEventRecord:
    timestamp_prefix = normalize_timestamp(date, time_value)
    normalized_subject = normalize_decoded_text(subject).upper()
    normalized_subject = normalized_subject.replace("ARCQ", "ARC1").replace("ARCZ", "ARC:")
    normalized_subject = re.sub(r"^DEVICE[LI](\d+)$", r"DEVICE,\1", normalized_subject)
    normalized_message = normalize_decoded_text(message)
    if normalized_subject in {"ARC", "ARC1"} and "JABLO_IP" in normalized_message.upper():
        normalized_message = re.sub(r"(?i)\bARC[1Q]L(?=BK)", "ARC1,", normalized_message)
        normalized_message = re.sub(r"(?i)\bBKLA\b", "BK,A", normalized_message)
        normalized_message = re.sub(r"(?i)\bALLAN\b", "A,LAN", normalized_message)
        normalized_message = re.sub(r"(?i)\bLANL(?=JABLO_IP)", "LAN,", normalized_message)
        normalized_message = re.sub(r"(?i)\bJABLO_IP([LX]?V)(?=,|$)", r"JABLO_IP,\1", normalized_message)
        parts = [item.strip() for item in normalized_message.split(",") if item.strip()]
        normalized_parts: list[str] = []
        for part in parts:
            lowered = part.lower()
            if lowered in {"arc1", "arcq"}:
                normalized_parts.append("ARC1")
            elif lowered in {"bk", "bkla"}:
                normalized_parts.append("BK")
            elif lowered in {"a"}:
                normalized_parts.append("A")
            elif lowered in {"lan", "allan"}:
                normalized_parts.append("LAN")
            elif lowered == "gsm":
                normalized_parts.append("GSM")
            elif lowered == "jablo_ip":
                normalized_parts.append("JABLO_IP")
            elif lowered in {"vldone", "xvdone", "lvdone"}:
                normalized_parts.extend(["v", "DONE"])
            elif lowered in {"lv", "xv", "86"}:
                normalized_parts.append("v")
            elif lowered in {"done", "donee"}:
                normalized_parts.append("DONE")
            elif lowered in {"v", "xv", "86"}:
                normalized_parts.append("v")
            else:
                normalized_parts.append(part)
        normalized_message = ",".join(normalized_parts)
    elif normalized_subject.startswith("DEVICE"):
        if "connected_" in normalized_message.lower() or "connected" in normalized_message.lower():
            normalized_message = "Device connected on YTUN"
        elif "disconnected" in normalized_message.lower():
            normalized_message = "Device disconnected from YTUN"
        elif "started at" in normalized_message.lower():
            cleaned_for_parse = (
                normalized_message.replace("55ID", "UUID")
                .replace("55iD", "UUID")
                .replace("UuID", "UUID")
                .replace("uUID", "UUID")
                .replace("UUID=;", "UUID=")
                .replace("UUID];", "UUID=")
                .replace("UUID=:", "UUID=")
                .replace("F-link", "F-Link")
                .replace("R.9.2.1509", "2.9.2.1509")
                .replace("2N9.2.1509", "2.9.2.1509")
                .replace("2.9.R.1509", "2.9.2.1509")
                .replace("2.9.9.1509", "2.9.2.1509")
            )
            version_match = re.search(r"(?i)f-?link[^0-9]*([0-9][0-9A-Z.]*\.[0-9]+)", cleaned_for_parse)
            timestamp_match = re.search(
                r"(\d{1,2})[.\s]+(\d{1,2})[.\s]+(20\d{2})\s+(\d{2}:\d{2}:\d{2})",
                cleaned_for_parse,
            )
            uuid_match = UUID_RE.search(cleaned_for_parse)
            host_match = HOST_USER_RE.search(cleaned_for_parse)
            parts = ["F-Link"]
            if version_match:
                version = version_match.group(1).replace("N", "9").replace("R", "9")
                parts[0] = f"F-Link {version}"
            if timestamp_match:
                day, month, year, time_part = timestamp_match.groups()
                parts.append(f"started at {int(day)}. {int(month)}. {year} {time_part}")
            if uuid_match:
                parts.append(f"UUID={uuid_match.group(1).lower()}")
            if host_match:
                parts.append(normalize_host_user(host_match.group(1)))
            normalized_message = "; ".join(parts)
        elif "comm.log" in normalized_message.lower():
            cleaned_for_parse = (
                normalized_message.replace("UuID", "UUID")
                .replace("uUID", "UUID")
                .replace("55ID", "UUID")
                .replace("55iD", "UUID")
            )
            uuid_match = UUID_RE.search(cleaned_for_parse)
            file_name = extract_comm_log_name(cleaned_for_parse)
            host_match = HOST_USER_RE.search(cleaned_for_parse)
            parts = ["comm.log saved"]
            if file_name:
                parts.append(file_name)
            if uuid_match:
                parts.append(f"UUID={uuid_match.group(1).lower()}")
            if host_match:
                parts.append(normalize_host_user(host_match.group(1)))
            normalized_message = "; ".join(parts)
    label = f"INFO({normalized_subject}{',' + event_id if event_id else ''})"
    return DecodedEventRecord(
        text=f"{timestamp_prefix} {label}:{normalized_message}",
        kind="INFO",
        timestamp_prefix=timestamp_prefix,
        event_id=event_id,
        event_code=None,
        event_text=None,
        info_subject=normalized_subject,
        info_message=normalized_message,
        source_id=None,
        source_name=None,
        channel=None,
        section=None,
    )


def reconstruct_streamed_packets(packets: list[bytes]) -> list[bytes]:
    reassembled: list[bytes] = []
    current = bytearray()

    for packet in packets:
        if not packet:
            continue
        head = packet[0]
        if head == 0x48:
            if current:
                reassembled.append(bytes(current))
            current = bytearray(packet[3:])
        elif head in {0x49, 0x4A}:
            if current:
                current.extend(packet[2:])
            else:
                current = bytearray(packet[2:])
        else:
            if current:
                reassembled.append(bytes(current))
                current = bytearray()
            reassembled.append(packet)

    if current:
        reassembled.append(bytes(current))
    return reassembled


def build_direct_open_packet(end_offset: int, *, window_bytes: int, logical_name: bytes = b"log\x00") -> bytes:
    if len(logical_name) != 4:
        raise ValueError("logical_name must be exactly 4 bytes including NUL terminator")
    return (
        bytes.fromhex("5b0e0100")
        + end_offset.to_bytes(4, "little")
        + b"\x00"
        + int(window_bytes).to_bytes(2, "little")
        + b"\x00"
        + logical_name
    )


def build_direct_close_packet(logical_name: bytes = b"log\x00") -> bytes:
    if len(logical_name) != 4:
        raise ValueError("logical_name must be exactly 4 bytes including NUL terminator")
    return bytes.fromhex("5b0e0000") + (b"\x00" * 8) + logical_name


def build_direct_continue_packet(handle: bytes, *, request_blocks: int) -> bytes:
    if len(handle) != 2:
        raise ValueError("handle must be exactly 2 bytes")
    return bytes.fromhex("5d0602") + handle + b"\x01\x00" + bytes([request_blocks])


def parse_direct_handle(packets: list[bytes]) -> bytes | None:
    for packet in packets:
        if packet[:3] == bytes.fromhex("5d0801") and len(packet) >= 5:
            return packet[3:5]
    return None


def parse_direct_status_codes(packets: list[bytes]) -> list[int]:
    statuses: list[int] = []
    for packet in packets:
        if packet[:2] == bytes.fromhex("5c0c") and len(packet) >= 4:
            statuses.append(int.from_bytes(packet[2:4], "little"))
    return statuses


def extract_direct_stream_data(packets: list[bytes]) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    complete = False

    for packet in reconstruct_streamed_packets(packets):
        if packet[:3] == bytes.fromhex("5d0304"):
            complete = True
            continue
        if packet[:1] == b"\x5d" and packet[2:3] == b"\x03" and len(packet) > 11:
            chunks.append(packet[11:])

    return b"".join(chunks), complete


def direct_packets_present(packets: list[bytes]) -> bool:
    for packet in packets:
        if not packet:
            continue
        if packet[0] in {0x48, 0x49, 0x4A, 0x5C, 0x5D}:
            return True
    return False


def close_direct_log(*, client: JablotronUSBClient, verbose: bool, prefix: str) -> list[bytes]:
    client.send_packet(build_direct_close_packet())
    time.sleep(0.05)
    client.send_packet(bytes.fromhex("520102"))
    return drain_packets(client, timeout=0.8, prefix=prefix, verbose=verbose)


def read_direct_recent_log(*, client: JablotronUSBClient, end_offset: int, window_bytes: int, verbose: bool) -> bytes:
    stale_packets = drain_packets(client, timeout=0.15, prefix="direct-stale", verbose=verbose)
    if direct_packets_present(stale_packets):
        close_direct_log(client=client, verbose=verbose, prefix="direct-reset")

    last_statuses: list[int] = []
    for attempt in range(4):
        client.send_packet(build_direct_open_packet(end_offset, window_bytes=window_bytes))
        time.sleep(0.35)
        client.send_packet(bytes.fromhex("520102"))
        open_packets = drain_packets(client, timeout=1.6, prefix="direct-open", verbose=verbose)
        handle = parse_direct_handle(open_packets)
        last_statuses = parse_direct_status_codes(open_packets)
        if handle is None:
            if last_statuses and attempt < 3:
                close_direct_log(client=client, verbose=verbose, prefix="direct-recover")
                cooldown = 0.4 + (attempt * 0.6)
                time.sleep(cooldown)
                client.send_packet(bytes.fromhex("520102"))
                drain_packets(client, timeout=0.6, prefix="direct-wait", verbose=verbose)
                continue
            status_text = f" status_codes={last_statuses}" if last_statuses else ""
            raise SystemExit(
                "Direct log read failed: panel did not return a JA100_READ_FILE handle." + status_text
            )

        auto_data, complete = extract_direct_stream_data(open_packets)
        if complete and auto_data:
            close_direct_log(client=client, verbose=verbose, prefix="direct-close")
            return auto_data

        client.send_packet(build_direct_continue_packet(handle, request_blocks=7))
        time.sleep(0.2)
        client.send_packet(bytes.fromhex("520102"))
        read_packets = drain_packets(client, timeout=2.5, prefix="direct-read", verbose=verbose)
        continuation_data, complete = extract_direct_stream_data(read_packets)
        payload = auto_data + continuation_data
        close_direct_log(client=client, verbose=verbose, prefix="direct-close")
        if complete and payload:
            return payload
        if payload:
            return payload

    raise SystemExit("Direct log read returned no payload data.")


def decode_event_record(data: bytes, *, catalog: DecoderCatalog | None = None) -> DecodedEventRecord:
    if data.startswith(b"BRev"):
        data = data[4:]

    text = normalize_decoded_text(compact_decode_text(data))
    if MIXED_EVENT_PREFIX_RE.match(text):
        text = normalize_decoded_text(text)
    text = repair_event_line_structure(text)

    delivered = INFO_DELIVERED_RE.match(text)
    if delivered:
        return build_info_record(
            date=delivered.group("date"),
            time_value=delivered.group("time"),
            subject=delivered.group("route"),
            message=delivered.group("message").upper(),
            event_id=delivered.group("event_id"),
        )

    info = INFO_GENERIC_RE.match(text)
    if info:
        return build_info_record(
            date=info.group("date"),
            time_value=info.group("time"),
            subject=info.group("subject"),
            message=info.group("message"),
            event_id=None,
        )

    match = DECODED_EVENT_RE.match(text)
    if not match:
        return DecodedEventRecord(
            text=text,
            kind=None,
            timestamp_prefix=None,
            event_id=None,
            event_code=None,
            event_text=None,
            info_subject=None,
            info_message=None,
            source_id=None,
            source_name=None,
            channel=None,
            section=None,
        )

    timestamp_prefix = normalize_timestamp(match.group("date"), match.group("time"))
    kind = match.group("kind").upper()
    event_id = normalize_numeric_token(match.group("id"))
    event_code = normalize_numeric_token(match.group("code"))
    event_text = normalize_event_text(event_code, match.group("text"))
    event_text = normalize_event_label(event_code=event_code, event_text=event_text, catalog=catalog)
    source_id = normalize_numeric_token(match.group("src_id")) if match.group("src_id") else None
    source_name = prettify_value(match.group("src_name"), mode="source") if match.group("src_name") else None
    channel = prettify_value(match.group("channel"), mode="channel") if match.group("channel") else None
    section = normalize_numeric_token(match.group("section")) if match.group("section") else None
    source_name = normalize_source_label(
        source_id=source_id,
        source_name=source_name,
        event_code=event_code,
        catalog=catalog,
    )
    channel = normalize_channel_label(channel, catalog)
    section = normalize_section_label(section, catalog)

    parts = [timestamp_prefix, f"{kind}({event_id}):{event_code},{event_text};"]
    if source_id or source_name:
        parts.append(f"Src:{source_id},{source_name};")
    if channel:
        parts.append(f"Chnl:{channel};")
    if section:
        parts.append(f"Sect:{section};")

    return DecodedEventRecord(
        text=" ".join(parts),
        kind=kind,
        timestamp_prefix=timestamp_prefix,
        event_id=event_id,
        event_code=event_code,
        event_text=event_text,
        info_subject=None,
        info_message=None,
        source_id=source_id,
        source_name=source_name,
        channel=channel,
        section=section,
    )


def build_record_length_histogram(records: list[EventRecord]) -> dict[int, int]:
    histogram: dict[int, int] = {}
    for record in records:
        histogram[record.length] = histogram.get(record.length, 0) + 1
    return dict(sorted(histogram.items()))


def build_record_metadata(records: list[EventRecord], *, preview_limit: int) -> list[dict[str, object]]:
    return [
        {
            "index": record.index,
            "offset": record.offset,
            "length": record.length,
            "sha256": record.sha256,
            "hex_prefix": record.hex_prefix,
            "printable_preview": record.printable_preview,
        }
        for record in records[:preview_limit]
    ] 


def build_decoded_records(
    records: list[EventRecord],
    archive: bytes,
    *,
    catalog: DecoderCatalog | None = None,
) -> list[DecodedEventRecord]:
    decoded_records: list[DecodedEventRecord] = []
    if not records:
        return decoded_records
    base_offset = records[0].offset
    for record in records:
        start = record.offset - base_offset
        raw = archive[start : start + record.length]
        decoded = decode_event_record(raw, catalog=catalog)
        decoded_records.append(decoded)
    return canonicalize_decoded_records(decoded_records, catalog=catalog)


def load_decoded_records_from_jsonl(path: Path) -> list[DecodedEventRecord]:
    records: list[DecodedEventRecord] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            payload = json.loads(line)
            parsed = payload.get("parsed")
            if not parsed:
                continue
            records.append(DecodedEventRecord(**parsed))
    # Keep JSONL-loaded rows consistent with live decode paths (event-label
    # normalization, source/channel prettification, rebuilt text payload).
    return canonicalize_decoded_records(records)


def parse_flink_export_xml(path: Path) -> list[FLinkExportRow]:
    root = ET.fromstring(path.read_text(encoding="utf-8", errors="replace"))
    rows: list[FLinkExportRow] = []
    for row in root.findall(".//row"):
        values: dict[str, str] = {}
        for child in row:
            key = child.tag.strip()
            values[key] = (child.text or "").strip()
        rows.append(
            FLinkExportRow(
                event_id=values.get("id") or None,
                timestamp=values.get("Čas", ""),
                source=values.get("zdroj", ""),
                section=values.get("sekcia", ""),
                event=values.get("udalosť", ""),
                channel=values.get("kanál", ""),
            )
        )
    return rows


def parse_flink_export_csv(path: Path) -> list[FLinkExportRow]:
    import csv

    rows: list[FLinkExportRow] = []
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=";")
        for row in reader:
            rows.append(
                FLinkExportRow(
                    event_id=(row.get("ID") or "").strip() or None,
                    timestamp=(row.get("Time") or row.get("Čas") or "").strip(),
                    source=(row.get("Source") or row.get("zdroj") or "").strip(),
                    section=(row.get("Section") or row.get("sekcia") or "").strip(),
                    event=(row.get("Event") or row.get("udalosť") or "").strip(),
                    channel=(row.get("Channel") or row.get("kanál") or "").strip(),
                )
            )
    return rows


def parse_flink_export(path: Path) -> list[FLinkExportRow]:
    suffix = path.suffix.lower()
    if suffix == ".xml":
        return parse_flink_export_xml(path)
    if suffix == ".csv":
        return parse_flink_export_csv(path)
    raise SystemExit(f"Unsupported F-Link export format: {path.suffix}. Use XML or CSV.")


def align_decoded_with_export(
    *,
    decoded_records: list[DecodedEventRecord],
    export_rows: list[FLinkExportRow],
) -> list[AlignedEventRow]:
    decoded_by_id = {
        record.event_id: record
        for record in decoded_records
        if record.kind == "EVENT" and record.event_id
    }
    export_by_id = {row.event_id: row for row in export_rows if row.event_id}
    aligned: list[AlignedEventRow] = []

    for event_id in sorted(set(decoded_by_id) | set(export_by_id), key=int):
        decoded = decoded_by_id.get(event_id)
        export = export_by_id.get(event_id)
        if decoded and export:
            mismatches: list[str] = []
            if (decoded.event_text or "") != export.event:
                mismatches.append("event")
            if (decoded.source_name or "") != export.source:
                mismatches.append("source")
            if (decoded.channel or "") != export.channel:
                mismatches.append("channel")
            if (decoded.section or "") != export.section:
                mismatches.append("section")
            status = "match" if not mismatches else "diff:" + ",".join(mismatches)
        elif decoded:
            status = "decoded-only"
        else:
            status = "export-only"
        aligned.append(
            AlignedEventRow(
                event_id=event_id,
                decoded_timestamp=decoded.timestamp_prefix if decoded else None,
                decoded_code=decoded.event_code if decoded else None,
                decoded_event=decoded.event_text if decoded else None,
                decoded_source=decoded.source_name if decoded else None,
                decoded_channel=decoded.channel if decoded else None,
                decoded_section=decoded.section if decoded else None,
                export_timestamp=export.timestamp if export else None,
                export_event=export.event if export else None,
                export_source=export.source if export else None,
                export_channel=export.channel if export else None,
                export_section=export.section if export else None,
                status=status,
            )
        )
    return aligned


def emit_aligned_rows(rows: list[AlignedEventRow], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps([asdict(row) for row in rows], indent=2, ensure_ascii=False))
        return
    header = (
        "EventID",
        "Status",
        "Code",
        "DecodedEvent",
        "ExportEvent",
        "DecodedSource",
        "ExportSource",
        "DecodedChannel",
        "ExportChannel",
        "DecodedSection",
        "ExportSection",
    )
    rendered = [header]
    for row in rows:
        rendered.append(
            (
                row.event_id,
                row.status,
                row.decoded_code or "",
                row.decoded_event or "",
                row.export_event or "",
                row.decoded_source or "",
                row.export_source or "",
                row.decoded_channel or "",
                row.export_channel or "",
                row.decoded_section or "",
                row.export_section or "",
            )
        )
    if fmt == "tsv":
        for row in rendered:
            print("\t".join(row))
        return
    widths = [max(len(row[index]) for row in rendered) for index in range(len(header))]
    for row in rendered:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())


def print_decoded_table(records: list[DecodedEventRecord]) -> None:
    rows = [("Timestamp", "Kind", "ID", "Code", "Event/Info", "Source", "Channel", "Sect")]
    for record in records:
        message = record.event_text or record.info_message or record.text
        source = record.source_name or record.info_subject or ""
        rows.append(
            (
                record.timestamp_prefix or "",
                record.kind or "",
                record.event_id or "",
                record.event_code or "",
                message or "",
                source,
                record.channel or "",
                record.section or "",
            )
        )
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())


def print_decoded_tsv(records: list[DecodedEventRecord]) -> None:
    print("\t".join(["Timestamp", "Kind", "ID", "Code", "EventOrInfo", "Source", "Channel", "Sect"]))
    for record in records:
        print(
            "\t".join(
                [
                    record.timestamp_prefix or "",
                    record.kind or "",
                    record.event_id or "",
                    record.event_code or "",
                    record.event_text or record.info_message or record.text,
                    record.source_name or record.info_subject or "",
                    record.channel or "",
                    record.section or "",
                ]
            )
        )


def emit_decoded_records(records: list[DecodedEventRecord], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps([asdict(record) for record in records], indent=2, ensure_ascii=False))
        return
    if fmt == "tsv":
        print_decoded_tsv(records)
        return
    print_decoded_table(records)


# --- Pretty / colorized rendering for the `show` subcommand ----------------

_ANSI = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "white": "\x1b[37m",
    "bright_red": "\x1b[91m",
    "bright_green": "\x1b[92m",
    "bright_yellow": "\x1b[93m",
    "bright_blue": "\x1b[94m",
    "bright_magenta": "\x1b[95m",
    "bright_cyan": "\x1b[96m",
    "bg_red": "\x1b[41m",
}
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Keyword-driven highlight rules for EVENT/INFO messages. Order matters; the
# first matching rule wins. Patterns match on the upper-cased message text.
# Keywords cover EN plus the CZ/SK localizations this panel uses.
_EVENT_STYLE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    # Alarm clear / restore wins over the alarm rules below ("Zrušenie poplachu"
    # contains both "ZRUŠEN" and "POPLACH" — the clear rule must match first).
    (re.compile(r"ZRUŠEN|ZRUSEN|RESTORE|CLEAR|OBNOV"), "bright_green"),
    # Alarms / panic / sabotage (both EN and SK/CZ).
    (re.compile(r"ALARM|PANIC|BURGLAR|SABOT|TAMPER|POPLACH"), "bright_red"),
    (re.compile(r"FIRE|SMOKE|GAS|FLOOD|POŽIAR|POZIAR|ZAPLAV"), "bright_red"),
    # Faults / low battery / failures.
    (re.compile(r"FAULT|FAILURE|LOW BATTERY|BATTERY FAIL|PORUCHA|AKUMUL|BATÉRI|BATERI"), "bright_yellow"),
    # Unset / disarm.
    (re.compile(r"UNSET|DISARM|ODSTREZ|ODSTREŽ|ODJIST"), "green"),
    # Set / arm / partial set.
    (re.compile(r"\bSET\b|\bARM(?:ED|ING)?\b|PARTIAL|ZASTREZ|ZASTREŽ|ZAJIST"), "yellow"),
    # Entry / exit.
    (re.compile(r"ENTRY|EXIT|VSTUP|ODCHOD|PRÍCHOD|PRICHOD"), "cyan"),
    # Power / mains / AC.
    (re.compile(r"MAINS|POWER|AC LOSS|AC RESTORE|STRATA SIET|SIET OBNOV|SIEŤ|VÝPADOK|VYPADOK"), "magenta"),
    # Communication / connection / GSM / LAN.
    (re.compile(r"COMMUNICATION|\bLINE\b|GSM|\bLAN\b|\bARC\b|SPOJEN|KOMUNIK|PRENOS"), "blue"),
    (re.compile(r"EVENT (?:NOT )?DELIVERED|ODOSLAN|DORUCEN|DORUČEN"), "dim"),
    # Authorization / user activity.
    (re.compile(r"AUTORIZ|AUTHORIZ|LOGIN|LOGOUT"), "bright_cyan"),
    # PG outputs (Jablotron programmable outputs).
    (re.compile(r"^PG \d+:"), "dim"),
)

# Jablotron event code -> style fallback when keyword rules do not match.
def _code_style_fallback(event_code: str | None) -> str | None:
    if not event_code:
        return None
    try:
        code = int(event_code)
    except ValueError:
        return None
    if code in (13, 15, 25, 26, 27, 28, 29, 30):  # alarms / panic / fire
        return "bright_red"
    if code == 14:  # alarm clear
        return "bright_green"
    if 40 <= code <= 49:  # tampers / sabotage
        return "bright_red"
    if 50 <= code <= 74:  # arm/set operations
        return "yellow"
    if 75 <= code <= 99:  # PG / auxiliary output operations
        return None
    if 100 <= code <= 149:  # faults / low battery / service
        return "bright_yellow"
    if 150 <= code <= 199:  # authorization / communication
        return "blue"
    return None


def _ansi_supported(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    isatty = getattr(stream, "isatty", None)
    try:
        return bool(isatty and isatty())
    except Exception:
        return False


def _visual_width(text: str) -> int:
    return len(_ANSI_RE.sub("", text))


def _pad(text: str, width: int) -> str:
    padding = width - _visual_width(text)
    return text + (" " * padding if padding > 0 else "")


class _Palette:
    __slots__ = ("enabled",)

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, *styles: str) -> str:
        if not self.enabled or not text:
            return text
        prefix = "".join(_ANSI[s] for s in styles if s in _ANSI)
        if not prefix:
            return text
        return f"{prefix}{text}{_ANSI['reset']}"


def _prettify_timestamp(prefix: str | None) -> str:
    if not prefix:
        return ""
    prefix = prefix.strip()
    m = re.match(r"^(\d{2})(\d{2})(\d{2}) (\d{2}:\d{2}:\d{2})$", prefix)
    if m:
        yy, mm, dd, hms = m.groups()
        return f"20{yy}-{mm}-{dd} {hms}"
    return prefix


def _record_kind_style(kind: str | None) -> tuple[str, ...]:
    if kind == "EVENT":
        return ("bright_cyan",)
    if kind == "INFO":
        return ("dim",)
    return ("dim", "magenta")


def _message_style(
    message: str,
    kind: str | None,
    *,
    event_code: str | None = None,
) -> tuple[str, ...]:
    if not message:
        return ()
    upper = message.upper()
    for pattern, style in _EVENT_STYLE_RULES:
        if pattern.search(upper):
            return (style, "bold") if style.startswith("bright_red") else (style,)
    fallback = _code_style_fallback(event_code)
    if fallback:
        return (fallback, "bold") if fallback.startswith("bright_red") else (fallback,)
    if kind == "EVENT":
        return ("white",)
    return ("dim",)


def _filter_by_date(
    records: list[DecodedEventRecord],
    *,
    since: str | None,
    until: str | None,
) -> list[DecodedEventRecord]:
    if not since and not until:
        return records

    def _to_key(value: str) -> str:
        # accept YYYY-MM-DD, YYYYMMDD, or YYMMDD -> normalize to YYYYMMDD
        s = value.replace("-", "").replace("/", "")
        if len(s) == 6:
            s = "20" + s
        return s

    since_key = _to_key(since) if since else None
    until_key = _to_key(until) if until else None
    filtered: list[DecodedEventRecord] = []
    for record in records:
        prefix = (record.timestamp_prefix or "").strip()
        m = re.match(r"^(\d{2})(\d{2})(\d{2}) ", prefix)
        if not m:
            continue
        yy, mm, dd = m.groups()
        key = f"20{yy}{mm}{dd}"
        if since_key and key < since_key:
            continue
        if until_key and key > until_key:
            continue
        filtered.append(record)
    return filtered


def _filter_by_grep(
    records: list[DecodedEventRecord],
    pattern: str | None,
    *,
    ignore_case: bool = True,
) -> list[DecodedEventRecord]:
    if not pattern:
        return records
    flags = re.IGNORECASE if ignore_case else 0
    regex = re.compile(pattern, flags)
    filtered: list[DecodedEventRecord] = []
    for record in records:
        blob = " ".join(
            filter(
                None,
                (
                    record.text or "",
                    record.event_text or "",
                    record.info_subject or "",
                    record.info_message or "",
                    record.source_name or "",
                    record.channel or "",
                    record.section or "",
                ),
            )
        )
        if regex.search(blob):
            filtered.append(record)
    return filtered


def print_colorized_history(
    records: list[DecodedEventRecord],
    *,
    stream: TextIO | None = None,
    color: str = "auto",
    pretty_timestamp: bool = True,
    show_header: bool = True,
    group_by_day: bool = False,
) -> None:
    stream = stream or sys.stdout
    if color == "always":
        enabled = True
    elif color == "never":
        enabled = False
    else:
        enabled = _ansi_supported(stream)
    palette = _Palette(enabled)

    header = ("Timestamp", "Kind", "ID", "Code", "Event / Info", "Source", "Channel", "Sect")
    rows: list[tuple[str, ...]] = []
    for record in records:
        message = record.event_text or record.info_message or record.text or ""
        source = record.source_name or record.info_subject or ""
        ts = _prettify_timestamp(record.timestamp_prefix) if pretty_timestamp else (record.timestamp_prefix or "")
        rows.append(
            (
                ts,
                record.kind or "RAW",
                record.event_id or "",
                record.event_code or "",
                message,
                source,
                record.channel or "",
                record.section or "",
            )
        )

    widths = [len(h) for h in header]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], _visual_width(cell))

    def _emit(cells: list[str]) -> None:
        stream.write("  ".join(_pad(cells[i], widths[i]) for i in range(len(cells))).rstrip() + "\n")

    if show_header:
        painted_header = [palette.paint(h, "bold", "white") for h in header]
        _emit(painted_header)
        _emit([palette.paint("-" * widths[i], "dim") for i in range(len(header))])

    current_day = ""
    for record, row in zip(records, rows):
        if group_by_day:
            day = row[0][:10] if pretty_timestamp else row[0][:6]
            if day and day != current_day:
                current_day = day
                banner_label = day if pretty_timestamp else f"20{day[:2]}-{day[2:4]}-{day[4:6]}"
                line = palette.paint(f"── {banner_label} ", "bold", "bright_blue")
                stream.write(line + "\n")

        ts = palette.paint(row[0], "dim")
        kind_styles = _record_kind_style(record.kind)
        kind = palette.paint(row[1], *kind_styles)
        event_id = palette.paint(row[2], "dim")
        code = palette.paint(row[3], "dim") if record.kind == "INFO" else palette.paint(row[3], "yellow")
        message_styles = _message_style(row[4], record.kind, event_code=record.event_code)
        message = palette.paint(row[4], *message_styles) if message_styles else row[4]
        source = palette.paint(row[5], "magenta") if row[5] else ""
        channel = palette.paint(row[6], "cyan") if row[6] else ""
        section = palette.paint(row[7], "bright_yellow") if row[7] else ""

        _emit([ts, kind, event_id, code, message, source, channel, section])

    stream.flush()


def _iter_decoded_from_archive(
    *,
    archive_path: Path,
    metadata_path: Path | None,
    base_offset: int,
    catalog: DecoderCatalog | None,
) -> list[DecodedEventRecord]:
    data = archive_path.read_bytes()
    window_start = base_offset
    if metadata_path is not None:
        try:
            meta = json.loads(metadata_path.read_text(encoding="utf-8"))
            window_start = int(meta.get("window_start", window_start))
        except Exception:
            pass
    records = split_crlf_records(data, base_offset=window_start)
    return build_decoded_records(records, data, catalog=catalog)


def load_history_records(
    *,
    records_jsonl: Path | None = None,
    archive: Path | None = None,
    metadata: Path | None = None,
    base_offset: int = 0,
    catalog: DecoderCatalog | None = None,
    files_dir: Path | None = None,
) -> list[DecodedEventRecord]:
    """Resolve decoded records from (in priority order):

    1. A pre-decoded JSONL produced by ``--records-output --decode-records``.
    2. A raw archive window file plus optional metadata.
    3. A ``--copy-files-dir`` directory that contains ``FLEXILOG.OLD`` and
       ``FLEXILOG.TXT`` (concatenated in that order).
    """
    if records_jsonl is not None:
        return load_decoded_records_from_jsonl(records_jsonl)
    if archive is not None:
        return _iter_decoded_from_archive(
            archive_path=archive,
            metadata_path=metadata,
            base_offset=base_offset,
            catalog=catalog,
        )
    if files_dir is not None:
        old_path = files_dir / "FLEXILOG.OLD"
        new_path = files_dir / "FLEXILOG.TXT"
        pieces: list[bytes] = []
        if old_path.exists():
            pieces.append(old_path.read_bytes())
        if new_path.exists():
            pieces.append(new_path.read_bytes())
        if not pieces:
            raise SystemExit(
                f"No FLEXILOG.OLD/FLEXILOG.TXT found in {files_dir}. Pass --records or --archive instead."
            )
        data = b"".join(pieces)
        last_nz = find_last_nonzero_offset(data)
        if last_nz is not None:
            data = data[: last_nz + 1]
        records = split_crlf_records(data, base_offset=0)
        return build_decoded_records(records, data, catalog=catalog)
    raise SystemExit(
        "show requires one of --records, --archive, or --files-dir to locate event data."
    )


def build_metadata(snapshot: EventArchiveSnapshot) -> dict[str, object]:
    metadata = asdict(snapshot)
    metadata["output"] = str(snapshot.output)
    metadata["metadata_output"] = str(snapshot.metadata_output)
    metadata["index_points"] = [
        {
            "timestamp": point.timestamp,
            "timestamp_utc": isoformat_utc(point.timestamp),
            "offset": point.offset,
        }
        for point in snapshot.index_points
    ]
    metadata["record_length_histogram"] = {
        str(length): count for length, count in snapshot.record_length_histogram.items()
    }
    metadata["record_preview"] = build_record_metadata(snapshot.record_preview, preview_limit=len(snapshot.record_preview))
    return metadata


def write_metadata(path: Path, snapshot: EventArchiveSnapshot) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_metadata(snapshot), indent=2), encoding="utf-8")


def emit_snapshot(snapshot: EventArchiveSnapshot) -> None:
    print(f"output {snapshot.output}")
    print(f"metadata {snapshot.metadata_output}")
    print(f"transport {snapshot.transport}")
    print(f"sha256 {snapshot.sha256}")
    print(f"log_device {snapshot.log_device}")
    print(f"old_size {snapshot.old_size}")
    print(f"current_size {snapshot.current_size}")
    print(f"physical_total {snapshot.physical_total}")
    print(f"logical_end {snapshot.logical_end}")
    print(f"window_start {snapshot.window_start}")
    print(f"window_bytes {snapshot.window_bytes}")
    if snapshot.populated_bytes is not None:
        print(f"populated_bytes {snapshot.populated_bytes}")
    if snapshot.last_nonzero_offset is not None:
        print(f"last_nonzero_offset {snapshot.last_nonzero_offset}")
    if snapshot.trailing_zero_bytes:
        print(f"trailing_zero_bytes {snapshot.trailing_zero_bytes}")
    print(f"record_count {snapshot.record_count}")
    if snapshot.record_length_histogram:
        print(
            "record_lengths "
            + ",".join(f"{length}:{count}" for length, count in snapshot.record_length_histogram.items())
        )
    if snapshot.index_points:
        latest = snapshot.index_points[-1]
        print(f"latest_index_offset {latest.offset}")
        print(f"latest_index_timestamp {isoformat_utc(latest.timestamp)}")
    if snapshot.crlf_part_lengths:
        print("crlf_part_lengths " + ",".join(str(length) for length in snapshot.crlf_part_lengths[:16]))
    for item in snapshot.printable_preview:
        print(f"preview {item}")


def print_snapshot_summary(snapshot: EventArchiveSnapshot) -> None:
    print(f"wrote {snapshot.output}")
    print(f"metadata {snapshot.metadata_output}")
    print(f"transport {snapshot.transport}")
    print(f"sha256 {snapshot.sha256}")
    print(f"record_count {snapshot.record_count}")
    if snapshot.index_points:
        latest = snapshot.index_points[-1]
        print(f"latest_index_offset {latest.offset}")
        print(f"latest_index_timestamp {isoformat_utc(latest.timestamp)}")


def default_output_path(prefix: str) -> Path:
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    return Path("/tmp") / f"{stamp}_{prefix}.bin"


def resolve_output_paths(
    *,
    output: str | None,
    metadata_output: str | None,
    records_output: str | None,
    prefix: str,
    records_format: str,
    save_records: bool,
) -> tuple[Path, Path, Path | None]:
    output_path = Path(output) if output else default_output_path(prefix)
    resolved_metadata = (
        Path(metadata_output)
        if metadata_output
        else output_path.with_suffix(output_path.suffix + ".json")
    )
    if records_output:
        resolved_records = Path(records_output)
    elif save_records:
        records_suffix = ".jsonl" if records_format == "jsonl" else ".tsv"
        resolved_records = output_path.with_name(f"{output_path.stem}_records{records_suffix}")
    else:
        resolved_records = None
    return output_path, resolved_metadata, resolved_records


def select_display_records(
    records: list[DecodedEventRecord],
    *,
    limit: int,
    include_raw: bool,
    include_kinds: set[str] | None = None,
    exclude_kinds: set[str] | None = None,
) -> list[DecodedEventRecord]:
    if include_raw:
        selected = [record for record in records if record.text]
    else:
        selected = [record for record in records if record.kind]
        if not selected:
            selected = [record for record in records if record.text]
    if include_kinds:
        selected = [record for record in selected if (record.kind or "RAW") in include_kinds]
    if exclude_kinds:
        selected = [record for record in selected if (record.kind or "RAW") not in exclude_kinds]
    if limit <= 0:
        return selected
    return selected[-limit:]


def parse_kind_filter(value: str | None) -> set[str]:
    if not value:
        return set()
    allowed = {"EVENT", "INFO", "RAW"}
    parsed = {item.strip().upper() for item in value.split(",") if item.strip()}
    invalid = sorted(parsed - allowed)
    if invalid:
        raise SystemExit(f"Unsupported kind filter(s): {', '.join(invalid)}. Use EVENT, INFO, RAW.")
    return parsed


def copy_archive_files(*, mountpoint: Path, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in DEFAULT_FILES:
        shutil.copy2(mountpoint / name, output_dir / name)


def write_record_dump(
    path: Path,
    *,
    records: list[EventRecord],
    archive: bytes,
    fmt: str,
    decode: bool,
    catalog: DecoderCatalog | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    decoded_records = build_decoded_records(records, archive, catalog=catalog) if decode else []
    decoded_by_index = {record.index: decoded for record, decoded in zip(records, decoded_records)}

    if fmt == "jsonl":
        with path.open("w", encoding="utf-8") as handle:
            for record in records:
                start = record.offset - records[0].offset if records else 0
                raw = archive[start : start + record.length]
                payload = {
                    "index": record.index,
                    "offset": record.offset,
                    "length": record.length,
                    "sha256": record.sha256,
                    "hex": raw.hex(),
                    "printable_preview": record.printable_preview,
                }
                if decode:
                    decoded = decoded_by_index[record.index]
                    payload["decoded_text"] = decoded.text
                    payload["parsed"] = asdict(decoded)
                handle.write(json.dumps(payload) + "\n")
        return

    if fmt == "tsv":
        with path.open("w", encoding="utf-8") as handle:
            columns = ["index", "offset", "length", "sha256", "hex_prefix", "printable_preview"]
            if decode:
                columns.extend(
                    [
                        "decoded_text",
                        "kind",
                        "timestamp_prefix",
                        "event_id",
                        "event_code",
                        "event_text",
                        "info_subject",
                        "info_message",
                        "source_id",
                        "source_name",
                        "channel",
                        "section",
                    ]
                )
            handle.write("\t".join(columns) + "\n")
            for record in records:
                row = [
                    str(record.index),
                    str(record.offset),
                    str(record.length),
                    record.sha256,
                    record.hex_prefix,
                    record.printable_preview,
                ]
                if decode:
                    decoded = decoded_by_index[record.index]
                    row.extend(
                        [
                            decoded.text,
                            decoded.kind or "",
                            decoded.timestamp_prefix or "",
                            decoded.event_id or "",
                            decoded.event_code or "",
                            decoded.event_text or "",
                            decoded.info_subject or "",
                            decoded.info_message or "",
                            decoded.source_id or "",
                            decoded.source_name or "",
                            decoded.channel or "",
                            decoded.section or "",
                        ]
                    )
                handle.write("\t".join(row) + "\n")
        return

    raise SystemExit(f"Unsupported record dump format: {fmt}")


def print_record_dump(
    handle: TextIO,
    *,
    records: list[EventRecord],
    archive: bytes,
    limit: int,
    decode: bool,
    catalog: DecoderCatalog | None = None,
) -> None:
    print(f"records {len(records)}", file=handle)
    decoded_records = build_decoded_records(records, archive, catalog=catalog) if decode else []
    decoded_by_index = {record.index: decoded for record, decoded in zip(records, decoded_records)}
    for record in records[:limit]:
        preview = f" preview={record.printable_preview}" if record.printable_preview else ""
        line = (
            f"{record.index}\toffset={record.offset}\tlen={record.length}\tsha256={record.sha256[:16]}"
            f"\thex_prefix={record.hex_prefix}{preview}"
        )
        if decode:
            decoded = decoded_by_index[record.index]
            if decoded.text:
                line += f"\tdecoded={decoded.text}"
        print(line, file=handle)


def pull_live_archive(args: argparse.Namespace) -> EventArchiveSnapshot:
    output, metadata_output, records_output = resolve_output_paths(
        output=getattr(args, "output", None),
        metadata_output=getattr(args, "metadata_output", None),
        records_output=getattr(args, "records_output", None),
        prefix=getattr(args, "output_prefix", "live_events"),
        records_format=getattr(args, "records_format", "jsonl"),
        save_records=bool(getattr(args, "records_output", None)),
    )
    log_device = resolve_flexi_log_device(args.log_device)
    mountpoint = Path(args.mountpoint)
    catalog = resolve_decoder_catalog(
        fdb_path=getattr(args, "source_fdb", None),
        export_cfg_path=getattr(args, "source_export_cfg", None),
    )

    client = JablotronUSBClient(ensure_serial_port(args.port))
    mounted = False
    exit_mode: int | None = None

    try:
        perform_login(client, args.auth_code, reset=not args.no_reset)
        time.sleep(0.7)
        pre_packets = drain_packets(client, timeout=1.0, prefix="pre", verbose=args.verbose)
        enter_setup_mode(client, verbose=args.verbose, initial_packets=pre_packets)

        mount_device(log_device, mountpoint, mount_tool=args.mount_tool)
        mounted = True

        old_path = mountpoint / "FLEXILOG.OLD"
        current_path = mountpoint / "FLEXILOG.TXT"
        index_path = mountpoint / "LOGINDEX.BIN"

        old_size = old_path.stat().st_size
        current_size = current_path.stat().st_size
        physical_total = old_size + current_size
        index_points = read_log_index_points(index_path)
        logical_end = max((point.offset for point in index_points), default=physical_total)
        if args.end_mode == "physical":
            logical_end = physical_total
        full_mode = bool(getattr(args, "full", False))
        copy_files_dir = getattr(args, "copy_files_dir", None)
        if copy_files_dir:
            copy_archive_files(mountpoint=mountpoint, output_dir=Path(copy_files_dir))

        if args.transport == "direct":
            if full_mode:
                raise SystemExit(
                    "--full is not supported with --transport direct; the panel rejects JA100_READ_FILE "
                    "reads that span the whole FLEXILOG.OLD+TXT archive. Use --transport archive."
                )
            unmount_device(log_device, mount_tool=args.mount_tool)
            mounted = False
            logical_end = physical_total
            data = read_direct_recent_log(
                client=client,
                end_offset=physical_total,
                window_bytes=min(args.window_bytes, 2000),
                verbose=args.verbose,
            )
            window_start = max(0, logical_end - len(data))
        else:
            if full_mode:
                logical_end = physical_total
                window_start = 0
                read_length = physical_total
            else:
                window_start = max(0, logical_end - args.window_bytes)
                read_length = args.window_bytes
            data = read_combined_log_range(
                old_path=old_path,
                current_path=current_path,
                start=window_start,
                length=read_length,
            )
        if getattr(args, "strip_trailing_zeros", False):
            last_nz = find_last_nonzero_offset(data)
            if last_nz is None:
                data = b""
            else:
                data = data[: last_nz + 1]
        records = split_crlf_records(data, base_offset=window_start)

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
        if records_output:
            write_record_dump(
                records_output,
                records=records,
                archive=data,
                fmt=args.records_format,
                decode=args.decode_records,
                catalog=catalog,
            )

        sha256 = hashlib.sha256(data).hexdigest()
        last_nonzero_offset = find_last_nonzero_offset(data)
        if last_nonzero_offset is None:
            populated_bytes = 0
            trailing_zero_bytes = len(data)
        else:
            populated_bytes = last_nonzero_offset + 1
            trailing_zero_bytes = len(data) - populated_bytes
        snapshot = EventArchiveSnapshot(
            output=output,
            metadata_output=metadata_output,
            transport=args.transport,
            sha256=sha256,
            log_device=log_device,
            old_size=old_size,
            current_size=current_size,
            physical_total=physical_total,
            logical_end=logical_end,
            window_start=window_start,
            window_bytes=len(data),
            record_count=len(records),
            record_length_histogram=build_record_length_histogram(records),
            record_preview=records[: args.record_preview_count],
            index_points=index_points[-args.index_preview_count :],
            crlf_part_lengths=[len(part) for part in data.split(b"\r\n")[: args.crlf_preview_count]],
            printable_preview=build_printable_preview(data, limit=args.preview_limit),
            last_nonzero_offset=(
                window_start + last_nonzero_offset if last_nonzero_offset is not None else None
            ),
            populated_bytes=populated_bytes,
            trailing_zero_bytes=trailing_zero_bytes,
        )
        write_metadata(metadata_output, snapshot)
        return snapshot
    finally:
        if mounted:
            unmount_device(log_device, mount_tool=args.mount_tool)
        try:
            exit_packets = graceful_exit_session(client, verbose=args.verbose)
            post_exit_packets = drain_packets(client, timeout=0.5, prefix="exit-post", verbose=args.verbose)
            modes = [
                mode
                for mode in (
                    extract_sections_state_mode(packet)
                    for packet in [*exit_packets, *post_exit_packets]
                )
                if mode is not None
            ]
            exit_mode = modes[-1] if modes else None
        finally:
            client.close()

        if args.cleanup_mode != "none" and exit_mode != EXITED_SECTIONS_MODE:
            final_mode = cleanup_read_session(
                port=args.port,
                code=args.auth_code,
                cleanup_mode=args.cleanup_mode if args.cleanup_mode != "auto" else "login-exit",
                verbose=args.verbose,
            )
            if final_mode != EXITED_SECTIONS_MODE:
                if final_mode == CONFIGURATION_SECTIONS_MODE:
                    raise SystemExit(configuration_in_use_message())
                raise SystemExit(
                    "Event-session cleanup did not reach the exited state "
                    f"(expected 0x{EXITED_SECTIONS_MODE:02x}, got {describe_sections_mode(final_mode)})."
                )


def cmd_pull_live(args: argparse.Namespace) -> None:
    snapshot = pull_live_archive(args)
    emit_snapshot(snapshot)


def cmd_pull_full(args: argparse.Namespace) -> None:
    effective_args = argparse.Namespace(**vars(args))
    if not getattr(effective_args, "strip_trailing_zeros", False):
        effective_args.strip_trailing_zeros = not bool(
            getattr(effective_args, "keep_trailing_zeros", False)
        )
    snapshot = pull_live_archive(effective_args)
    emit_snapshot(snapshot)
    if snapshot.populated_bytes is not None:
        print(
            f"populated_span {snapshot.window_start}..{snapshot.window_start + snapshot.populated_bytes} "
            f"({snapshot.populated_bytes} bytes)"
        )


def cmd_recent(args: argparse.Namespace) -> None:
    effective_args = argparse.Namespace(**vars(args))
    output, metadata_output, records_output = resolve_output_paths(
        output=args.output,
        metadata_output=args.metadata_output,
        records_output=args.records_output,
        prefix=getattr(args, "output_prefix", "recent_events"),
        records_format=args.records_format,
        save_records=args.save_records or bool(args.records_output),
    )
    effective_args.output = str(output)
    effective_args.metadata_output = str(metadata_output)
    effective_args.records_output = str(records_output) if records_output else None
    effective_args.decode_records = bool(records_output)

    snapshot = pull_live_archive(effective_args)
    archive = snapshot.output.read_bytes()
    records = split_crlf_records(archive, base_offset=snapshot.window_start)
    catalog = resolve_decoder_catalog(
        fdb_path=getattr(args, "source_fdb", None),
        export_cfg_path=getattr(args, "source_export_cfg", None),
    )
    export_catalog_path: Path | None = None
    if not getattr(args, "source_export_cfg", None):
        try:
            export_catalog, export_catalog_path = pull_runtime_export_catalog(args, prefix="event_catalog")
        except SystemExit:
            export_catalog = None
        catalog = merge_decoder_catalogs(catalog, export_catalog)
    decoded_records = build_decoded_records(records, archive, catalog=catalog)
    if records_output:
        write_record_dump(
            records_output,
            records=records,
            archive=archive,
            fmt=args.records_format,
            decode=True,
            catalog=catalog,
        )
    include_kinds = parse_kind_filter(args.kinds)
    exclude_kinds = parse_kind_filter(args.exclude_kinds)
    if args.events_only:
        include_kinds = {"EVENT"}
    display_records = select_display_records(
        decoded_records,
        limit=args.limit,
        include_raw=args.include_raw,
        include_kinds=include_kinds or None,
        exclude_kinds=exclude_kinds or None,
    )

    print_snapshot_summary(snapshot)
    if export_catalog_path is not None:
        print(f"catalog_export {export_catalog_path}")
    if records_output:
        print(f"records {records_output}")
    print(f"displayed {len(display_records)}")
    emit_decoded_records(display_records, args.format)


def cmd_show(args: argparse.Namespace) -> None:
    catalog = resolve_decoder_catalog(
        fdb_path=getattr(args, "source_fdb", None),
        export_cfg_path=getattr(args, "source_export_cfg", None),
    )
    records = load_history_records(
        records_jsonl=Path(args.records) if args.records else None,
        archive=Path(args.archive) if args.archive else None,
        metadata=Path(args.metadata) if args.metadata else None,
        base_offset=args.base_offset,
        catalog=catalog,
        files_dir=Path(args.files_dir) if args.files_dir else None,
    )

    include_kinds = parse_kind_filter(args.kinds)
    exclude_kinds = parse_kind_filter(args.exclude_kinds)
    if args.events_only:
        include_kinds = {"EVENT"}

    records = select_display_records(
        records,
        limit=0,
        include_raw=args.include_raw,
        include_kinds=include_kinds or None,
        exclude_kinds=exclude_kinds or None,
    )
    records = _filter_by_date(records, since=args.since, until=args.until)
    records = _filter_by_grep(records, args.grep, ignore_case=not args.case_sensitive)

    if args.reverse:
        records = list(reversed(records))
    if args.limit and args.limit > 0:
        records = records[: args.limit] if args.reverse else records[-args.limit :]

    if args.format == "tsv":
        print_decoded_tsv(records)
        return
    if args.format == "json":
        print(json.dumps([asdict(r) for r in records], indent=2, ensure_ascii=False))
        return
    if args.format == "plain":
        color_mode = "never"
    else:
        color_mode = args.color
    print_colorized_history(
        records,
        stream=sys.stdout,
        color=color_mode,
        pretty_timestamp=not args.raw_timestamp,
        show_header=not args.no_header,
        group_by_day=args.group_by_day,
    )
    if not args.no_summary:
        total = len(records)
        kinds = sorted({r.kind or "RAW" for r in records})
        first_ts = _prettify_timestamp(records[0].timestamp_prefix) if records else ""
        last_ts = _prettify_timestamp(records[-1].timestamp_prefix) if records else ""
        enabled = color_mode == "always" or (color_mode == "auto" and _ansi_supported(sys.stdout))
        palette = _Palette(enabled)
        summary = (
            f"\n{palette.paint(f'{total} records', 'bold')} "
            f"{palette.paint('[' + ','.join(kinds) + ']', 'dim')} "
            f"{palette.paint(first_ts + '  ->  ' + last_ts, 'dim')}"
        )
        print(summary)


def cmd_dump_index(args: argparse.Namespace) -> None:
    points = read_log_index_points(Path(args.index_bin))
    print(f"points {len(points)}")
    for point in points[-args.limit :]:
        print(f"{point.offset}\t{isoformat_utc(point.timestamp)}")


def cmd_extract_records(args: argparse.Namespace) -> None:
    archive_path = Path(args.archive)
    data = archive_path.read_bytes()
    base_offset = args.base_offset
    if args.metadata:
        metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
        base_offset = int(metadata.get("window_start", base_offset))
    records = split_crlf_records(data, base_offset=base_offset)
    catalog = resolve_decoder_catalog(
        fdb_path=getattr(args, "source_fdb", None),
        export_cfg_path=getattr(args, "source_export_cfg", None),
    )

    if args.output:
        write_record_dump(
            Path(args.output),
            records=records,
            archive=data,
            fmt=args.format,
            decode=args.decode,
            catalog=catalog,
        )
        print(f"output {args.output}")
    else:
        if args.decode:
            decoded_records = build_decoded_records(records, data, catalog=catalog)
            include_kinds = parse_kind_filter(args.kinds)
            exclude_kinds = parse_kind_filter(args.exclude_kinds)
            if args.events_only:
                include_kinds = {"EVENT"}
            emit_decoded_records(
                select_display_records(
                    decoded_records,
                    limit=args.limit,
                    include_raw=args.include_raw,
                    include_kinds=include_kinds or None,
                    exclude_kinds=exclude_kinds or None,
                ),
                args.display_format,
            )
            return
        print_record_dump(
            handle=sys.stdout,
            records=records,
            archive=data,
            limit=args.limit,
            decode=args.decode,
            catalog=catalog,
        )


def cmd_align_export(args: argparse.Namespace) -> None:
    catalog = resolve_decoder_catalog(
        fdb_path=getattr(args, "source_fdb", None),
        export_cfg_path=getattr(args, "source_export_cfg", None),
    )
    if args.decoded_jsonl:
        decoded_records = load_decoded_records_from_jsonl(Path(args.decoded_jsonl))
    else:
        archive_path = Path(args.archive)
        data = archive_path.read_bytes()
        base_offset = args.base_offset
        if args.metadata:
            metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
            base_offset = int(metadata.get("window_start", base_offset))
        records = split_crlf_records(data, base_offset=base_offset)
        decoded_records = build_decoded_records(records, data, catalog=catalog)

    export_rows = parse_flink_export(Path(args.export))
    aligned_rows = align_decoded_with_export(decoded_records=decoded_records, export_rows=export_rows)
    if args.only_diffs:
        aligned_rows = [row for row in aligned_rows if row.status != "match"]
    if args.limit > 0:
        aligned_rows = aligned_rows[-args.limit :]
    if args.output:
        Path(args.output).write_text(
            json.dumps([asdict(row) for row in aligned_rows], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"output {args.output}")
        return
    emit_aligned_rows(aligned_rows, args.format)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    pull_live = subparsers.add_parser(
        "pull-live",
        help="Keep a live setup session open and pull the latest indexed event-memory archive window from FLEXI_LOG.",
    )
    pull_live.add_argument(
        "output",
        nargs="?",
        help="Where to write the raw archive window. Defaults to a timestamped file in /tmp.",
    )
    pull_live.add_argument("--metadata-output", help="Optional JSON metadata output path.")
    pull_live.add_argument("--copy-files-dir", help="Optional directory to copy FLEXILOG.OLD/TXT and LOGINDEX.BIN into.")
    pull_live.add_argument("--records-output", help="Optional JSONL/TSV dump of the CRLF-delimited archive records.")
    pull_live.add_argument(
        "--source-fdb",
        help="Optional F-Link .fdb snapshot used to enrich decoded source labels for user events.",
    )
    pull_live.add_argument(
        "--source-export-cfg",
        help="Optional EXPORT.CFG blob used to enrich decoded user labels without relying on .fdb name tables.",
    )
    pull_live.add_argument(
        "--decode-records",
        action="store_true",
        help="Include decoded event text in --records-output when possible.",
    )
    pull_live.add_argument(
        "--records-format",
        choices=("jsonl", "tsv"),
        default="jsonl",
        help="Format for --records-output.",
    )
    add_flexi_log_device_argument(pull_live)
    pull_live.add_argument("--mountpoint", default=str(DEFAULT_FLEXI_LOG_MOUNTPOINT), help="Temporary mountpoint.")
    pull_live.add_argument("--port", default="auto", help="HID port (default: auto).")
    pull_live.add_argument("--auth-code", default="1812", help="Authorisation code for the live session.")
    pull_live.add_argument("--no-reset", action="store_true", help="Skip the initial auth-end reset packet.")
    pull_live.add_argument("--mount-tool", choices=("sudo", "udisksctl"), default="sudo")
    pull_live.add_argument(
        "--transport",
        choices=("archive", "direct"),
        default="archive",
        help="Read the combined FLEXILOG files directly or use the live JA100_READ_FILE log transport.",
    )
    pull_live.add_argument("--window-bytes", type=int, default=DEFAULT_WINDOW_BYTES, help="Combined archive window size.")
    pull_live.add_argument(
        "--full",
        action="store_true",
        help="Pull the entire FLEXILOG.OLD+FLEXILOG.TXT archive (overrides --window-bytes and --end-mode).",
    )
    pull_live.add_argument(
        "--strip-trailing-zeros",
        action="store_true",
        help="Trim the preallocated zero tail from the read archive before parsing/writing.",
    )
    pull_live.add_argument(
        "--end-mode",
        choices=("index", "physical"),
        default="index",
        help="Use the latest LOGINDEX offset or the physical FLEXILOG.OLD+TXT size as the window end.",
    )
    pull_live.add_argument(
        "--cleanup-mode",
        choices=("auto", "none", "exit-only", "login-exit"),
        default="auto",
        help="How to close the post-read session (default: auto).",
    )
    pull_live.add_argument("--index-preview-count", type=int, default=8, help="How many latest index points to store in metadata.")
    pull_live.add_argument("--record-preview-count", type=int, default=12, help="How many parsed record summaries to store in metadata.")
    pull_live.add_argument("--crlf-preview-count", type=int, default=16, help="How many CRLF split lengths to include.")
    pull_live.add_argument("--preview-limit", type=int, default=10, help="How many printable snippets to show.")
    pull_live.add_argument("--verbose", action="store_true", help="Print observed HID packets.")
    pull_live.add_argument(
        "--output-prefix",
        default="live_events",
        help="Prefix for the auto-generated /tmp output file when OUTPUT is omitted.",
    )
    pull_live.set_defaults(func=cmd_pull_live)

    pull_full = subparsers.add_parser(
        "pull-full",
        help=(
            "Pull the entire FLEXILOG.OLD+FLEXILOG.TXT event archive at once. "
            "This is the oldest history still retained by the panel (typically well beyond "
            "what the F-Link UI shows). Use --copy-files-dir to also save the raw FLEXILOG "
            "files and LOGINDEX.BIN for offline re-decoding."
        ),
    )
    pull_full.add_argument(
        "output",
        nargs="?",
        help="Where to write the raw combined archive. Defaults to a timestamped file in /tmp.",
    )
    pull_full.add_argument("--metadata-output", help="Optional JSON metadata output path.")
    pull_full.add_argument(
        "--copy-files-dir",
        help="Directory to copy FLEXILOG.OLD/TXT and LOGINDEX.BIN into (recommended for full pulls).",
    )
    pull_full.add_argument("--records-output", help="Optional JSONL/TSV dump of the CRLF-delimited archive records.")
    pull_full.add_argument(
        "--source-fdb",
        help="Optional F-Link .fdb snapshot used to enrich decoded source labels for user events.",
    )
    pull_full.add_argument(
        "--source-export-cfg",
        help="Optional EXPORT.CFG blob used to enrich decoded user labels without relying on .fdb name tables.",
    )
    pull_full.add_argument(
        "--decode-records",
        action="store_true",
        help="Include decoded event text in --records-output when possible.",
    )
    pull_full.add_argument(
        "--records-format",
        choices=("jsonl", "tsv"),
        default="jsonl",
        help="Format for --records-output.",
    )
    add_flexi_log_device_argument(pull_full)
    pull_full.add_argument("--mountpoint", default=str(DEFAULT_FLEXI_LOG_MOUNTPOINT), help="Temporary mountpoint.")
    pull_full.add_argument("--port", default="auto", help="HID port (default: auto).")
    pull_full.add_argument("--auth-code", default="1812", help="Authorisation code for the live session.")
    pull_full.add_argument("--no-reset", action="store_true", help="Skip the initial auth-end reset packet.")
    pull_full.add_argument("--mount-tool", choices=("sudo", "udisksctl"), default="sudo")
    pull_full.add_argument(
        "--cleanup-mode",
        choices=("auto", "none", "exit-only", "login-exit"),
        default="auto",
        help="How to close the post-read session (default: auto).",
    )
    pull_full.add_argument("--index-preview-count", type=int, default=8, help="How many latest index points to store in metadata.")
    pull_full.add_argument("--record-preview-count", type=int, default=12, help="How many parsed record summaries to store in metadata.")
    pull_full.add_argument("--crlf-preview-count", type=int, default=16, help="How many CRLF split lengths to include.")
    pull_full.add_argument("--preview-limit", type=int, default=10, help="How many printable snippets to show.")
    pull_full.add_argument("--verbose", action="store_true", help="Print observed HID packets.")
    pull_full.add_argument(
        "--output-prefix",
        default="full_events",
        help="Prefix for the auto-generated /tmp output file when OUTPUT is omitted.",
    )
    pull_full.add_argument(
        "--keep-trailing-zeros",
        action="store_true",
        help=(
            "Keep the preallocated zero tail in the output. By default pull-full strips the "
            "trailing zero region so the archive and record dump only contain populated bytes."
        ),
    )
    pull_full.set_defaults(
        func=cmd_pull_full,
        full=True,
        transport="archive",
        window_bytes=0,
        end_mode="physical",
    )

    recent = subparsers.add_parser(
        "recent",
        help="Pull recent live events and print a readable table, TSV, or JSON summary.",
    )
    recent.add_argument("--output", help="Optional raw archive output path. Defaults to a timestamped file in /tmp.")
    recent.add_argument("--metadata-output", help="Optional JSON metadata output path.")
    recent.add_argument("--records-output", help="Optional decoded JSONL/TSV output file.")
    recent.add_argument(
        "--source-fdb",
        help="Optional F-Link .fdb snapshot used to enrich decoded source labels for user events.",
    )
    recent.add_argument(
        "--source-export-cfg",
        help="Optional EXPORT.CFG blob used to enrich decoded user labels. If omitted, recent auto-pulls one after the event snapshot.",
    )
    recent.add_argument(
        "--records-format",
        choices=("jsonl", "tsv"),
        default="jsonl",
        help="Format for --records-output when saving decoded records.",
    )
    recent.add_argument(
        "--format",
        choices=("table", "tsv", "json"),
        default="table",
        help="Console output format for decoded events.",
    )
    recent.add_argument(
        "--kinds",
        help="Comma-separated decoded row kinds to include in console output: EVENT, INFO, RAW.",
    )
    recent.add_argument(
        "--exclude-kinds",
        help="Comma-separated decoded row kinds to suppress from console output: EVENT, INFO, RAW.",
    )
    recent.add_argument(
        "--events-only",
        action="store_true",
        help="Shortcut for showing only EVENT rows in console output.",
    )
    recent.add_argument("--limit", type=int, default=150, help="How many most-recent decoded rows to display.")
    recent.add_argument("--include-raw", action="store_true", help="Include undecoded rows in console output.")
    recent.add_argument("--save-records", action="store_true", help="Also save decoded records next to the raw pull.")
    add_flexi_log_device_argument(recent)
    recent.add_argument("--mountpoint", default=str(DEFAULT_FLEXI_LOG_MOUNTPOINT), help="Temporary mountpoint.")
    recent.add_argument("--port", default="auto", help="HID port (default: auto).")
    recent.add_argument("--auth-code", default="1812", help="Authorisation code for the live session.")
    recent.add_argument("--no-reset", action="store_true", help="Skip the initial auth-end reset packet.")
    recent.add_argument("--mount-tool", choices=("sudo", "udisksctl"), default="sudo")
    recent.add_argument(
        "--transport",
        choices=("archive", "direct"),
        default="archive",
        help="Use the stable archive window read by default, or select the direct JA100_READ_FILE log workflow explicitly.",
    )
    recent.add_argument("--window-bytes", type=int, default=DEFAULT_WINDOW_BYTES, help="Combined archive window size.")
    recent.add_argument(
        "--full",
        action="store_true",
        help="Pull the entire FLEXILOG.OLD+FLEXILOG.TXT archive (overrides --window-bytes and --end-mode).",
    )
    recent.add_argument(
        "--strip-trailing-zeros",
        action="store_true",
        help="Trim the preallocated zero tail from the read archive before parsing/writing.",
    )
    recent.add_argument(
        "--end-mode",
        choices=("index", "physical"),
        default="physical",
        help="Use the physical FLEXILOG.OLD+TXT size by default, or the latest LOGINDEX offset if requested.",
    )
    recent.add_argument(
        "--cleanup-mode",
        choices=("auto", "none", "exit-only", "login-exit"),
        default="auto",
        help="How to close the post-read session (default: auto).",
    )
    recent.add_argument("--index-preview-count", type=int, default=8, help="How many latest index points to store in metadata.")
    recent.add_argument("--record-preview-count", type=int, default=12, help="How many parsed record summaries to store in metadata.")
    recent.add_argument("--crlf-preview-count", type=int, default=16, help="How many CRLF split lengths to include.")
    recent.add_argument("--preview-limit", type=int, default=10, help="How many printable snippets to show.")
    recent.add_argument("--verbose", action="store_true", help="Print observed HID packets.")
    recent.add_argument(
        "--output-prefix",
        default="recent_events",
        help="Prefix for the auto-generated /tmp output file when --output is omitted.",
    )
    recent.set_defaults(func=cmd_recent)

    show = subparsers.add_parser(
        "show",
        help=(
            "Render decoded event history as a colorized, user-friendly table. "
            "Reads from a records.jsonl produced by pull-full/pull-live/recent "
            "(--records), a raw archive window (--archive [--metadata]), or a "
            "copied FLEXILOG files directory (--files-dir)."
        ),
    )
    show_source = show.add_mutually_exclusive_group(required=True)
    show_source.add_argument(
        "--records",
        help="Decoded JSONL produced by pull-full/pull-live/recent with --records-output --decode-records.",
    )
    show_source.add_argument(
        "--archive",
        help="Raw archive window (e.g. from pull-full). Pair with --metadata when possible.",
    )
    show_source.add_argument(
        "--files-dir",
        help="Directory containing FLEXILOG.OLD and FLEXILOG.TXT (e.g. from pull-full --copy-files-dir).",
    )
    show.add_argument("--metadata", help="Optional metadata JSON for --archive (provides window_start).")
    show.add_argument("--base-offset", type=int, default=0, help="Logical archive offset of archive byte 0.")
    show.add_argument(
        "--source-fdb",
        help="Optional F-Link .fdb snapshot used to enrich decoded source labels for user events.",
    )
    show.add_argument(
        "--source-export-cfg",
        help="Optional EXPORT.CFG blob used to enrich decoded user labels.",
    )
    show.add_argument(
        "--format",
        choices=("pretty", "plain", "tsv", "json"),
        default="pretty",
        help="Output format (default: colorized pretty table).",
    )
    show.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="Colorization policy for pretty output (default: auto; also honors NO_COLOR/FORCE_COLOR env).",
    )
    show.add_argument("--events-only", action="store_true", help="Shortcut for showing only EVENT rows.")
    show.add_argument("--include-raw", action="store_true", help="Include undecoded rows.")
    show.add_argument(
        "--kinds",
        help="Comma-separated kinds to include: EVENT, INFO, RAW.",
    )
    show.add_argument(
        "--exclude-kinds",
        help="Comma-separated kinds to exclude: EVENT, INFO, RAW.",
    )
    show.add_argument("--since", help="Only show events on/after this date (YYYY-MM-DD, YYYYMMDD, or YYMMDD).")
    show.add_argument("--until", help="Only show events on/before this date (YYYY-MM-DD, YYYYMMDD, or YYMMDD).")
    show.add_argument("--grep", help="Regex to filter events by text/source/channel/section.")
    show.add_argument(
        "--case-sensitive",
        action="store_true",
        help="Make --grep case-sensitive (default: case-insensitive).",
    )
    show.add_argument("--limit", type=int, default=0, help="Limit output (0 = all matching records).")
    show.add_argument("--reverse", action="store_true", help="Print newest records first.")
    show.add_argument(
        "--group-by-day",
        action="store_true",
        help="Insert a day separator each time the date changes.",
    )
    show.add_argument(
        "--raw-timestamp",
        action="store_true",
        help="Keep the compact YYMMDD HH:MM:SS timestamp instead of pretty-printing it as YYYY-MM-DD.",
    )
    show.add_argument("--no-header", action="store_true", help="Suppress the pretty table header.")
    show.add_argument("--no-summary", action="store_true", help="Suppress the trailing summary line.")
    show.set_defaults(func=cmd_show)

    dump_index = subparsers.add_parser("dump-index", help="Print parsed LOGINDEX.BIN points.")
    dump_index.add_argument("index_bin", help="Path to LOGINDEX.BIN.")
    dump_index.add_argument("--limit", type=int, default=150, help="How many latest points to print.")
    dump_index.set_defaults(func=cmd_dump_index)

    extract_records = subparsers.add_parser(
        "extract-records",
        help="Split a saved archive window on CRLF and emit per-record summaries or dumps.",
    )
    extract_records.add_argument("archive", help="Path to a saved archive window from pull-live.")
    extract_records.add_argument("--metadata", help="Optional metadata JSON from pull-live; uses window_start automatically.")
    extract_records.add_argument(
        "--source-fdb",
        help="Optional F-Link .fdb snapshot used to enrich decoded source labels for user events.",
    )
    extract_records.add_argument(
        "--source-export-cfg",
        help="Optional EXPORT.CFG blob used to enrich decoded user labels without relying on .fdb name tables.",
    )
    extract_records.add_argument("--base-offset", type=int, default=0, help="Logical archive offset of archive byte 0.")
    extract_records.add_argument("--output", help="Optional JSONL/TSV output file.")
    extract_records.add_argument("--format", choices=("jsonl", "tsv"), default="jsonl", help="Output format.")
    extract_records.add_argument(
        "--display-format",
        choices=("table", "tsv", "json"),
        default="table",
        help="Console format when decoding without --output.",
    )
    extract_records.add_argument(
        "--decode",
        action="store_true",
        help="Decode compact event-memory records into readable lines when possible.",
    )
    extract_records.add_argument(
        "--kinds",
        help="Comma-separated decoded row kinds to include in console output: EVENT, INFO, RAW.",
    )
    extract_records.add_argument(
        "--exclude-kinds",
        help="Comma-separated decoded row kinds to suppress from console output: EVENT, INFO, RAW.",
    )
    extract_records.add_argument(
        "--events-only",
        action="store_true",
        help="Shortcut for showing only EVENT rows in console output.",
    )
    extract_records.add_argument("--include-raw", action="store_true", help="Include undecoded rows in console output.")
    extract_records.add_argument("--limit", type=int, default=40, help="Console preview limit when --output is not used.")
    extract_records.set_defaults(func=cmd_extract_records)

    align_export = subparsers.add_parser(
        "align-export",
        help="Align a F-Link XML/CSV event export with decoded raw records by event ID.",
    )
    align_export.add_argument("--export", required=True, help="Path to a F-Link XML or CSV event export.")
    align_export.add_argument("--archive", help="Raw archive window from pull-live/recent.")
    align_export.add_argument("--metadata", help="Optional metadata JSON for --archive.")
    align_export.add_argument("--base-offset", type=int, default=0, help="Logical archive offset of archive byte 0.")
    align_export.add_argument("--decoded-jsonl", help="Optional predecoded JSONL produced by --records-output.")
    align_export.add_argument(
        "--source-fdb",
        help="Optional F-Link .fdb snapshot used to enrich decoded source labels before alignment.",
    )
    align_export.add_argument(
        "--source-export-cfg",
        help="Optional EXPORT.CFG blob used to enrich decoded user labels before alignment.",
    )
    align_export.add_argument("--only-diffs", action="store_true", help="Show only rows whose fields do not match.")
    align_export.add_argument("--limit", type=int, default=100, help="Limit aligned rows shown or written.")
    align_export.add_argument("--output", help="Optional JSON output file.")
    align_export.add_argument("--format", choices=("table", "tsv", "json"), default="table")
    align_export.set_defaults(func=cmd_align_export)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
