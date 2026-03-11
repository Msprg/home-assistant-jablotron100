#!/usr/bin/env python3
"""Pull Jablotron event-memory archive windows from FLEXI_LOG."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import shutil
import sys
import time
import unicodedata
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import TextIO

from jablotron_re_tools import (
    EXITED_SECTIONS_MODE,
    JablotronUSBClient,
    cleanup_read_session,
    drain_packets,
    enter_setup_mode,
    extract_sections_state_mode,
    graceful_exit_session,
    mount_device,
    unmount_device,
)
from jablotron_usb_debug import ensure_serial_port, perform_login

DEFAULT_FLEXI_LOG_LABEL = "FLEXI_LOG"
DEFAULT_FLEXI_LOG_LINK = Path("/dev/disk/by-label") / DEFAULT_FLEXI_LOG_LABEL
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
NUMERIC_REGION_RE = re.compile(r"[0-9P-YZ:]{2,}")
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
EVENT_TEXT_BY_CODE = {
    "40": "Zapnutá ochrana",
    "41": "Vypnutá ochrana",
    "48": "Zmena konfigurácie",
    "119": "Neplatná autorizace",
    "123": "Kontrolný prenos na PCO 1",
    "150": "Autorizácia OK",
    "156": "Spojenie nadviazané",
    "157": "Spojenie ukončené",
}
EVENT_TEXT_CANDIDATES = [
    "Autorizácia OK",
    "Created backup configuration",
    "Kontrolný prenos na PCO 1",
    "Neplatná autorizace",
    "Spojenie nadviazané",
    "Spojenie ukončené",
    "Vypnutá ochrana",
    "Zapnutá ochrana",
    "Zmena konfigurácie",
]
CHANNEL_CANDIDATES = [
    "USB",
    "Server",
    "LAN",
    "PSTN",
    "SMS",
    "INET_A",
    "0: Ústredňa",
    "18: termostat 1NP office",
]
SOURCE_NAME_CANDIDATES = [
    "Ústredňa",
    "Matúš Prančík",
    "HomeAssistant",
    "PCO 1",
    "ARC 1",
    "ARC1",
    "LAN communicator",
    "termostat 1NP office",
    "Termostat 2NP radio",
    "DO MB",
    "Veronika Bachrat",
]
CHANNEL_ALIAS_MAP = {
    "arc 1": "ARC 1",
    "gsm": "GSM",
    "inet_a": "Server",
    "server": "Server",
    "sms": "SMS",
    "usb": "USB",
}
SPECIAL_SOURCE_LABELS = {
    ("26", "156"): "Detector 0: Ústredňa",
    ("26", "157"): "Detector 0: Ústredňa",
}


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


def _parse_lsblk_pairs(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        pairs: dict[str, str] = {}
        for field in line.split():
            if "=" not in field:
                continue
            key, value = field.split("=", 1)
            pairs[key] = value.strip('"')
        if pairs:
            rows.append(pairs)
    return rows


def resolve_flexi_log_device(device: str | None = None) -> str:
    if device and device != "auto":
        path = Path(device)
        return str(path.resolve()) if path.exists() else device

    if DEFAULT_FLEXI_LOG_LINK.exists():
        return str(DEFAULT_FLEXI_LOG_LINK.resolve())

    import subprocess

    result = subprocess.run(
        ["lsblk", "-P", "-o", "PATH,LABEL,TYPE"],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode == 0:
        for row in _parse_lsblk_pairs(result.stdout):
            if row.get("LABEL") == DEFAULT_FLEXI_LOG_LABEL and row.get("TYPE") == "part":
                return row["PATH"]

    raise SystemExit(
        "Unable to resolve the FLEXI_LOG block device. "
        "Connect the panel or pass --log-device /dev/sdX1 explicitly."
    )


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


def compact_decode_text(data: bytes) -> str:
    delta = delta_decode_record(data)
    if delta and (delta[0] < 0x20 or delta[0] > 0x7E):
        delta = delta[1:]

    decoded = bytearray()
    remaining_utf8 = 0
    for byte in delta:
        value = byte
        if remaining_utf8 and 0x40 <= value <= 0x7F:
            value += 0x20
        elif value <= 0x3F:
            value += 0x20
        elif 0x41 <= value <= 0x5A:
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

    return decoded.decode("utf-8", "replace").replace("\x00", " ").strip()


def normalize_numeric_token(token: str) -> str:
    return token.translate(COMPACT_NUMERIC_TRANSLATION)


def simplify_match_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "", ascii_only.lower())


def choose_canonical_candidate(value: str, candidates: list[str], *, threshold: float) -> str:
    simplified = simplify_match_text(value)
    if not simplified:
        return value

    best_candidate = value
    best_score = 0.0
    for candidate in candidates:
        score = difflib.SequenceMatcher(a=simplified, b=simplify_match_text(candidate)).ratio()
        if score > best_score:
            best_score = score
            best_candidate = candidate
    return best_candidate if best_score >= threshold else value


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
        .replace("SrcZ", "Src:")
        .replace("ChnlZ", "Chnl:")
        .replace("SectZ", "Sect:")
        .replace("INFO(ARc)", "INFO(ARC)")
        .replace("INFO(ARc1)", "INFO(ARC1)")
        .replace("INFO(aRC)", "INFO(ARC)")
        .replace("INFO(aRC1)", "INFO(ARC1)")
        .replace("INFO(s934eM)", "INFO(SYSTEM)")
        .replace("INFO(sYSTeM)", "INFO(SYSTEM)")
        .replace("INFO(3934EM)", "INFO(SYSTEM)")
        .replace("INFO(DeVICE", "INFO(DEVICE")
        .replace("[", ";")
        .replace("Homeassistant", "HomeAssistant")
    )
    text = re.sub(r"(?i)\bevent(?=\()", "EVENT", text)
    text = re.sub(r"(?i)\binfo(?=\()", "INFO", text)
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


def prettify_value(value: str, *, mode: str) -> str:
    cleaned = re.sub(r"\s+", " ", value).strip().replace("\ufffd", "")
    if not cleaned:
        return cleaned
    if mode == "channel":
        lowered = cleaned.lower()
        if lowered in CHANNEL_ALIAS_MAP:
            return CHANNEL_ALIAS_MAP[lowered]
        if lowered in {"lan", "pstn"}:
            return cleaned.upper()
        return choose_canonical_candidate(cleaned.title(), CHANNEL_CANDIDATES, threshold=0.72)
    if mode == "source":
        return choose_canonical_candidate(cleaned.title(), SOURCE_NAME_CANDIDATES, threshold=0.6)
    lowered = cleaned.lower()
    return lowered[:1].upper() + lowered[1:]


def normalize_event_text(event_code: str | None, value: str) -> str:
    if event_code and event_code in EVENT_TEXT_BY_CODE:
        return EVENT_TEXT_BY_CODE[event_code]
    return choose_canonical_candidate(prettify_value(value, mode="event"), EVENT_TEXT_CANDIDATES, threshold=0.6)


@lru_cache(maxsize=8)
def load_decoder_catalog(fdb_path: str) -> DecoderCatalog:
    from fdb_tool import choose_snapshot, find_user_snapshots, iter_user_rows, read_fdb

    container = read_fdb(Path(fdb_path))
    snapshot = choose_snapshot(find_user_snapshots(container.xml_text), "latest")
    labels: dict[str, str] = {}
    ambiguous: set[str] = set()

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
        existing = labels.get(key)
        if existing and existing != label:
            ambiguous.add(key)
            continue
        labels[key] = label

    for key in ambiguous:
        labels.pop(key, None)
    return DecoderCatalog(user_labels_by_name_key=labels)


def resolve_decoder_catalog(fdb_path: str | None) -> DecoderCatalog | None:
    if not fdb_path:
        return None
    return load_decoder_catalog(str(Path(fdb_path)))


def normalize_source_label(
    *,
    source_id: str | None,
    source_name: str | None,
    event_code: str | None,
    catalog: DecoderCatalog | None,
) -> str | None:
    if not source_name:
        return source_name
    special = SPECIAL_SOURCE_LABELS.get((source_id or "", event_code or ""))
    if special:
        return special
    if event_code == "150" and catalog:
        label = catalog.user_labels_by_name_key.get(simplify_match_text(source_name))
        if label:
            return label
    return source_name


def build_info_record(*, date: str | None, time_value: str, subject: str, message: str, event_id: str | None) -> DecodedEventRecord:
    timestamp_prefix = normalize_timestamp(date, time_value)
    normalized_subject = normalize_decoded_text(subject).upper()
    normalized_subject = normalized_subject.replace("ARCQ", "ARC1").replace("ARCZ", "ARC:")
    normalized_message = normalize_decoded_text(message)
    if normalized_subject in {"ARC", "ARC1"} and "JABLO_IP" in normalized_message.upper():
        normalized_message = re.sub(r"(?i)\bARC[1Q]L(?=BK)", "ARC1,", normalized_message)
        normalized_message = re.sub(r"(?i)\bBKLA\b", "BK,A", normalized_message)
        normalized_message = re.sub(r"(?i)\bALLAN\b", "A,LAN", normalized_message)
        normalized_message = re.sub(r"(?i)\bLANL(?=JABLO_IP)", "LAN,", normalized_message)
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
            elif lowered in {"done", "donee"}:
                normalized_parts.append("DONE")
            elif lowered in {"v", "xv"}:
                normalized_parts.append("v")
            else:
                normalized_parts.append(part)
        normalized_message = ",".join(normalized_parts)
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
    return decoded_records


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
) -> list[DecodedEventRecord]:
    if include_raw:
        selected = [record for record in records if record.text]
    else:
        selected = [record for record in records if record.kind]
        if not selected:
            selected = [record for record in records if record.text]
    if limit <= 0:
        return selected
    return selected[-limit:]


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
                    decoded = decode_event_record(raw, catalog=catalog)
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
                    raw = archive[record.offset - records[0].offset : record.offset - records[0].offset + record.length]
                    decoded = decode_event_record(raw, catalog=catalog)
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
    for record in records[:limit]:
        preview = f" preview={record.printable_preview}" if record.printable_preview else ""
        line = (
            f"{record.index}\toffset={record.offset}\tlen={record.length}\tsha256={record.sha256[:16]}"
            f"\thex_prefix={record.hex_prefix}{preview}"
        )
        if decode:
            raw = archive[record.offset - records[0].offset : record.offset - records[0].offset + record.length]
            decoded = decode_event_record(raw, catalog=catalog)
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
    catalog = resolve_decoder_catalog(getattr(args, "source_fdb", None))

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
        copy_files_dir = getattr(args, "copy_files_dir", None)
        if copy_files_dir:
            copy_archive_files(mountpoint=mountpoint, output_dir=Path(copy_files_dir))

        if args.transport == "direct":
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
            window_start = max(0, logical_end - args.window_bytes)
            data = read_combined_log_range(
                old_path=old_path,
                current_path=current_path,
                start=window_start,
                length=args.window_bytes,
            )
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
                raise SystemExit(
                    "Event-session cleanup did not reach the exited state "
                    f"(expected 0x{EXITED_SECTIONS_MODE:02x}, got {final_mode!r})."
                )


def cmd_pull_live(args: argparse.Namespace) -> None:
    snapshot = pull_live_archive(args)
    emit_snapshot(snapshot)


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
    decoded_records = build_decoded_records(records, archive, catalog=resolve_decoder_catalog(args.source_fdb))
    display_records = select_display_records(
        decoded_records,
        limit=args.limit,
        include_raw=args.include_raw,
    )

    print_snapshot_summary(snapshot)
    if records_output:
        print(f"records {records_output}")
    print(f"displayed {len(display_records)}")
    emit_decoded_records(display_records, args.format)


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
    catalog = resolve_decoder_catalog(args.source_fdb)

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
            emit_decoded_records(
                select_display_records(
                    decoded_records,
                    limit=args.limit,
                    include_raw=args.include_raw,
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
    pull_live.add_argument("--log-device", default="auto", help="FLEXI_LOG block device or 'auto'.")
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
    recent.add_argument("--limit", type=int, default=150, help="How many most-recent decoded rows to display.")
    recent.add_argument("--include-raw", action="store_true", help="Include undecoded rows in console output.")
    recent.add_argument("--save-records", action="store_true", help="Also save decoded records next to the raw pull.")
    recent.add_argument("--log-device", default="auto", help="FLEXI_LOG block device or 'auto'.")
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
    extract_records.add_argument("--include-raw", action="store_true", help="Include undecoded rows in console output.")
    extract_records.add_argument("--limit", type=int, default=40, help="Console preview limit when --output is not used.")
    extract_records.set_defaults(func=cmd_extract_records)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
