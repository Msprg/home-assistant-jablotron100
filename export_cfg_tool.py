#!/usr/bin/env python3
"""Decode user records from Jablotron EXPORT.CFG blobs.

The live panel's EXPORT.CFG is bytewise XORed with 0xff. After inverting it,
the user table is stored in a compact binary record format with inline UTF-8
strings for names, phone numbers, codes, comments, and access cards.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional


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


def parse_len_string(record: bytes, tag: int) -> str:
    index = record.find(bytes([tag]))
    if index == -1 or index + 1 >= len(record):
        return ""
    marker = record[index + 1]
    if marker < 0xA0:
        return ""
    length = marker - 0xA0
    return record[index + 2 : index + 2 + length].decode("utf-8", "replace")


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
    marker = field[marker_index + 2]
    if marker < 0xA0:
        return ""
    length = marker - 0xA0
    return field[marker_index + 3 : marker_index + 3 + length].decode("ascii", "ignore")


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


def cmd_extract_users(args: argparse.Namespace) -> None:
    records = extract_users(Path(args.export_cfg))
    if args.format == "json":
        print(json.dumps([record.__dict__ for record in records], indent=2, ensure_ascii=False))
        return
    if args.format == "tsv":
        print_tsv(records)
        return
    print_table(records)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract_parser = subparsers.add_parser("extract-users", help="Extract user records from an EXPORT.CFG blob.")
    extract_parser.add_argument("export_cfg", help="Path to EXPORT.CFG or an equivalent 1 MiB export blob.")
    extract_parser.add_argument("--format", choices=["table", "tsv", "json"], default="table")
    extract_parser.set_defaults(func=cmd_extract_users)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
