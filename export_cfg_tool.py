#!/usr/bin/env python3
"""Decode user records from Jablotron EXPORT.CFG blobs.

The live panel's EXPORT.CFG is bytewise XORed with 0xff. After inverting it,
the user table is stored in a compact binary record format with inline UTF-8
strings for names, phone numbers, codes, comments, and access cards.
"""

from __future__ import annotations

import argparse
import json
import hashlib
import os
import sys
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from jablotron_usb_debug import JablotronUSBClient, ensure_serial_port, perform_flink_export_session, perform_login

SECTOR_SIZE = 512
EXPORT_START_LBA = 35
EXPORT_SECTORS = 2048


@dataclass(frozen=True)
class UserRecord:
    offset: int
    user_id: Optional[int]
    raw_id_bytes: str
    name: str
    phone: str
    code: str
    card: str
    comment: str


def invert_blob(data: bytes) -> bytes:
    return bytes(byte ^ 0xFF for byte in data)


def find_record_starts(blob: bytes) -> List[int]:
    starts: List[int] = []
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


def parse_len_string(record: bytes, tag: int) -> str:
    index = record.find(bytes([tag]))
    if index == -1 or index + 1 >= len(record):
        return ""
    return decode_msgpack_string(record, index + 1)


def parse_card(record: bytes) -> str:
    start = record.find(b"\x07")
    if start == -1:
        return ""
    end = record.find(b"\x08", start)
    if end == -1:
        end = len(record)
    field = record[start:end]
    marker_index = field.find(b"\x81\x00")
    if marker_index == -1 or marker_index + 2 >= len(field):
        return ""
    return decode_msgpack_string(field, marker_index + 2)


def extract_users(path: Path) -> List[UserRecord]:
    blob = invert_blob(path.read_bytes())
    starts = find_record_starts(blob)
    users: List[UserRecord] = []
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

        name = parse_len_string(record, 0x04)
        if not name:
            continue

        users.append(
            UserRecord(
                offset=start,
                user_id=decode_user_id(bytes(id_bytes)),
                raw_id_bytes=bytes(id_bytes).hex(),
                name=name,
                phone=parse_len_string(record, 0x05),
                code=parse_len_string(record, 0x06),
                card=parse_card(record),
                comment=parse_len_string(record, 0x0A),
            )
        )
    return users


def read_export_direct(
    *,
    device: str,
    output: Path,
    start_lba: int = EXPORT_START_LBA,
    sectors: int = EXPORT_SECTORS,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "dd",
        f"if={device}",
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


def trigger_live_export(*, port: str, code: str, reset: bool) -> None:
    serial_port = ensure_serial_port(port)
    client = JablotronUSBClient(serial_port)
    try:
        perform_login(client, code, reset=reset)
        time.sleep(0.5)
        perform_flink_export_session(client)
        end = time.time() + 4.0
        while time.time() < end:
            for _packet in client.read_packets(timeout=0.2):
                pass
    finally:
        client.close()


def print_table(records: Iterable[UserRecord]) -> None:
    rows = [("ID", "RawID", "Name", "Code", "Phone", "Card", "Comment")]
    for record in records:
        rows.append(
            (
                "" if record.user_id is None else str(record.user_id),
                record.raw_id_bytes,
                record.name,
                record.code,
                record.phone,
                record.card,
                record.comment,
            )
        )
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())


def print_tsv(records: Iterable[UserRecord]) -> None:
    print("\t".join(["ID", "RawID", "Name", "Code", "Phone", "Card", "Comment"]))
    for record in records:
        print(
            "\t".join(
                [
                    "" if record.user_id is None else str(record.user_id),
                    record.raw_id_bytes,
                    record.name,
                    record.code,
                    record.phone,
                    record.card,
                    record.comment,
                ]
            )
        )


def iter_printable_strings(blob: bytes, *, min_length: int) -> Iterable[str]:
    pattern = re.compile(rb"[\x20-\x7e\xc0-\xff]{" + str(min_length).encode("ascii") + rb",}")
    for match in pattern.finditer(blob):
        yield match.group().decode("utf-8", "replace")


def cmd_extract_users(args: argparse.Namespace) -> None:
    records = extract_users(Path(args.export_cfg))
    if args.format == "json":
        print(json.dumps([record.__dict__ for record in records], indent=2, ensure_ascii=False))
        return
    if args.format == "tsv":
        print_tsv(records)
        return
    print_table(records)


def cmd_pull_live(args: argparse.Namespace) -> None:
    output = Path(args.output)
    if not args.no_trigger:
        trigger_live_export(port=args.port, code=args.code, reset=not args.no_reset)
    read_export_direct(device=args.device, output=output, start_lba=args.start_lba, sectors=args.sectors)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"wrote {output}")
    print(f"sha256 {digest}")
    if args.extract_users:
        print_tsv(extract_users(output))


def cmd_dump_text(args: argparse.Namespace) -> None:
    blob = invert_blob(Path(args.export_cfg).read_bytes())
    for text in iter_printable_strings(blob, min_length=args.min_length):
        print(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    pull_parser = subparsers.add_parser(
        "pull-live",
        help="Trigger a live export session and read EXPORT.CFG directly from the block device with O_DIRECT dd.",
    )
    pull_parser.add_argument("output", help="Output file to write the pulled export blob to.")
    pull_parser.add_argument("--device", default="/dev/sdb1", help="Block device for FLEXI_CFG (default: /dev/sdb1).")
    pull_parser.add_argument("--port", default="auto", help="HID port to use for the trigger session (default: auto).")
    pull_parser.add_argument(
        "--code",
        default="1812",
        help="Authorisation code for the trigger session (default: captured service code 1812).",
    )
    pull_parser.add_argument("--no-reset", action="store_true", help="Skip the initial auth-end reset packet.")
    pull_parser.add_argument("--no-trigger", action="store_true", help="Only perform the direct block read.")
    pull_parser.add_argument("--start-lba", type=int, default=EXPORT_START_LBA, help="Starting LBA to read.")
    pull_parser.add_argument("--sectors", type=int, default=EXPORT_SECTORS, help="Number of sectors to read.")
    pull_parser.add_argument("--extract-users", action="store_true", help="Also print parsed users as TSV after pulling.")
    pull_parser.set_defaults(func=cmd_pull_live)

    extract_parser = subparsers.add_parser("extract-users", help="Extract user records from an EXPORT.CFG blob.")
    extract_parser.add_argument("export_cfg", help="Path to EXPORT.CFG or an equivalent 1 MiB export blob.")
    extract_parser.add_argument("--format", choices=["table", "tsv", "json"], default="table")
    extract_parser.set_defaults(func=cmd_extract_users)

    dump_text_parser = subparsers.add_parser(
        "dump-text",
        help="Print printable UTF-8-ish strings from a decoded EXPORT.CFG blob.",
    )
    dump_text_parser.add_argument("export_cfg", help="Path to EXPORT.CFG or an equivalent 1 MiB export blob.")
    dump_text_parser.add_argument(
        "--min-length",
        type=int,
        default=4,
        help="Minimum printable string length to emit (default: 4).",
    )
    dump_text_parser.set_defaults(func=cmd_dump_text)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except BrokenPipeError:
        sys.exit(0)


if __name__ == "__main__":
    main()
