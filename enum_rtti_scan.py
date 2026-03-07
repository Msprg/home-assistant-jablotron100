#!/usr/bin/env python3
"""Extract Delphi RTTI enum metadata from F-Link process dumps.

This parser targets the length-prefixed RTTI blocks observed in the supplied
F-Link memory dumps. It is intentionally conservative: it scans for known
module namespaces, validates candidate enum blocks, and emits only records that
look like Delphi enum metadata.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

MODULE_NAMES = (b"Central100Types", b"Central100Intf")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.<>]*$")


@dataclass(frozen=True)
class EnumRecord:
    module: str
    type_name: str
    min_value: int
    max_value: int
    members: Tuple[str, ...]
    dump_path: str
    offset: int

    @property
    def count(self) -> int:
        return len(self.members)


def is_identifier(text: str) -> bool:
    return bool(IDENT_RE.fullmatch(text))


def decode_pascal_identifier(data: bytes, offset: int) -> Tuple[str, int] | None:
    if offset + 1 >= len(data):
        return None
    length = data[offset]
    if length <= 0 or length > 96:
        return None
    end = offset + 1 + length
    if end > len(data):
        return None
    chunk = data[offset + 1 : end]
    if any(byte < 0x20 or byte > 0x7E for byte in chunk):
        return None
    text = chunk.decode("ascii", "strict")
    if not is_identifier(text):
        return None
    return text, end


def parse_enum_at(data: bytes, module: bytes, module_offset: int) -> EnumRecord | None:
    start = module_offset + len(module)
    search_end = min(len(data), start + 48)
    name_offset = None
    type_name = None
    for offset in range(start, search_end - 2):
        if data[offset] != 0x03:
            continue
        decoded = decode_pascal_identifier(data, offset + 1)
        if decoded is None:
            continue
        candidate_name, after_name = decoded
        if after_name + 13 > len(data):
            continue
        if data[after_name] != 0x01:
            continue
        min_value = int.from_bytes(data[after_name + 1 : after_name + 5], "little", signed=True)
        max_value = int.from_bytes(data[after_name + 5 : after_name + 9], "little", signed=True)
        if min_value < 0 or max_value < min_value or max_value - min_value > 512:
            continue
        name_offset = after_name
        type_name = candidate_name
        break

    if name_offset is None or type_name is None:
        return None

    count = max_value - min_value + 1
    cursor = name_offset + 13
    members: List[str] = []
    for _ in range(count):
        decoded = decode_pascal_identifier(data, cursor)
        if decoded is None:
            return None
        member_name, cursor = decoded
        members.append(member_name)

    return EnumRecord(
        module=module.decode("ascii"),
        type_name=type_name,
        min_value=min_value,
        max_value=max_value,
        members=tuple(members),
        dump_path="",
        offset=module_offset,
    )


def scan_dump(path: Path) -> List[EnumRecord]:
    data = path.read_bytes()
    records: List[EnumRecord] = []
    seen_offsets: set[int] = set()

    for module in MODULE_NAMES:
        cursor = 0
        while True:
            offset = data.find(module, cursor)
            if offset == -1:
                break
            cursor = offset + 1
            if offset in seen_offsets:
                continue
            record = parse_enum_at(data, module, offset)
            if record is None:
                continue
            seen_offsets.add(offset)
            records.append(
                EnumRecord(
                    module=record.module,
                    type_name=record.type_name,
                    min_value=record.min_value,
                    max_value=record.max_value,
                    members=record.members,
                    dump_path=str(path),
                    offset=record.offset,
                )
            )

    records.sort(key=lambda record: (record.module, record.type_name, record.offset))
    return records


def dedupe_records(records: Iterable[EnumRecord]) -> List[EnumRecord]:
    deduped: Dict[Tuple[str, str, Tuple[str, ...]], EnumRecord] = {}
    for record in records:
        key = (record.module, record.type_name, record.members)
        current = deduped.get(key)
        if current is None or (record.dump_path, record.offset) < (current.dump_path, current.offset):
            deduped[key] = record
    return sorted(deduped.values(), key=lambda record: (record.module, record.type_name))


def filter_records(records: Iterable[EnumRecord], keywords: Sequence[str]) -> List[EnumRecord]:
    if not keywords:
        return list(records)
    lowered = [keyword.lower() for keyword in keywords]
    filtered: List[EnumRecord] = []
    for record in records:
        haystack = " ".join([record.module, record.type_name, *record.members]).lower()
        if any(keyword in haystack for keyword in lowered):
            filtered.append(record)
    return filtered


def print_text(records: Iterable[EnumRecord]) -> None:
    for record in records:
        print(f"{record.module}.{record.type_name} [{record.min_value}..{record.max_value}]")
        print(f"  source: {record.dump_path} @ 0x{record.offset:x}")
        print(f"  members: {', '.join(record.members)}")
        print()


def cmd_scan(args: argparse.Namespace) -> None:
    records = []
    for dump_path in args.dumps:
        records.extend(scan_dump(Path(dump_path)))

    if args.dedupe:
        records = dedupe_records(records)
    records = filter_records(records, args.keyword)

    if args.format == "json":
        print(json.dumps([asdict(record) for record in records], indent=2))
        return

    print_text(records)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan one or more dumps for RTTI enum blocks")
    scan_parser.add_argument("dumps", nargs="+", help="process dump paths")
    scan_parser.add_argument(
        "--keyword",
        action="append",
        default=[],
        help="case-insensitive substring filter applied to module, type, and member names",
    )
    scan_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format",
    )
    scan_parser.add_argument(
        "--dedupe",
        action="store_true",
        help="collapse identical enum definitions found in multiple dumps",
    )
    scan_parser.set_defaults(func=cmd_scan)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
