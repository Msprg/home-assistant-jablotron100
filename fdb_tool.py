#!/usr/bin/env python3
"""Inspect, unpack, repack, and query F-Link .fdb files.

Observed .fdb container format:

- 29-byte fixed header: b"\\x00\\x00\\x00ODBO-Link database file\\xff\\xff\\xff"
- zlib-compressed payload beginning at offset 29
- decompressed payload starts with a 16-byte preamble
- XML document begins immediately after that preamble

The exact semantics of the 16-byte preamble are not fully decoded yet.
In the supplied samples it equals the MD5 of the empty string.
"""

from __future__ import annotations

import argparse
import json
import re
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

FDB_HEADER = b"\x00\x00\x00ODBO-Link database file\xff\xff\xff"
DEFAULT_PREAMBLE = bytes.fromhex("d41d8cd98f00b204e9800998ecf8427e")
XML_MARKER = b"<?xml"
ROOT_RE = re.compile(
    r'<class name="JA100UsersSetup"[^>]*class="TJA100AllUsers">\s*<class name="TJA100AllUsers">',
    re.DOTALL,
)
ITEM_RE = re.compile(r'<item index="([0-9A-Fa-f]+)">(.*?)</item>', re.DOTALL)
PROPERTY_RE = re.compile(
    r'<property name="([^"]+)" type="([^"]+)">\s*<!\[CDATA\[(.*?)\]\]>\s*</property>',
    re.DOTALL,
)
EXPECTED_USER_COUNT = 601


@dataclass(frozen=True)
class FdbContainer:
    header: bytes
    compressed_payload: bytes
    decompressed_payload: bytes
    xml_offset: int

    @property
    def preamble(self) -> bytes:
        return self.decompressed_payload[: self.xml_offset]

    @property
    def xml_bytes(self) -> bytes:
        return self.decompressed_payload[self.xml_offset :]

    @property
    def xml_text(self) -> str:
        return self.xml_bytes.decode("utf-8", "replace")


@dataclass(frozen=True)
class UserRecord:
    slot_index: int
    user_id: int
    properties: Dict[str, str]


@dataclass(frozen=True)
class UserSnapshot:
    start_offset: int
    users: Dict[int, UserRecord]

    @property
    def unique_ids(self) -> int:
        return len(self.users)

    @property
    def is_complete(self) -> bool:
        return self.unique_ids == EXPECTED_USER_COUNT and 600 in self.users


def read_fdb(path: Path) -> FdbContainer:
    data = path.read_bytes()
    if not data.startswith(FDB_HEADER):
        raise SystemExit(f"{path} does not start with the expected ODBO-Link header.")
    compressed_payload = data[len(FDB_HEADER) :]
    decompressed_payload = zlib.decompress(compressed_payload)
    xml_offset = decompressed_payload.find(XML_MARKER)
    if xml_offset == -1:
        raise SystemExit(f"{path} does not contain an XML document after decompression.")
    return FdbContainer(
        header=FDB_HEADER,
        compressed_payload=compressed_payload,
        decompressed_payload=decompressed_payload,
        xml_offset=xml_offset,
    )


def write_fdb(
    *,
    output: Path,
    payload: bytes,
    header: bytes = FDB_HEADER,
    compression_level: int = 1,
) -> None:
    compressed = zlib.compress(payload, compression_level)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(header + compressed)


def build_payload_from_xml(xml_bytes: bytes, *, preamble: bytes) -> bytes:
    return preamble + xml_bytes


def parse_snapshot(text: str, *, start_offset: int) -> UserSnapshot:
    users: Dict[int, UserRecord] = {}
    for item_match in ITEM_RE.finditer(text):
        properties = {
            property_match.group(1): property_match.group(3).strip()
            for property_match in PROPERTY_RE.finditer(item_match.group(2))
        }
        if "ID" not in properties:
            continue
        try:
            user_id = int(properties["ID"])
        except ValueError:
            continue
        if user_id in users:
            if user_id == 0 and len(users) >= EXPECTED_USER_COUNT:
                break
            continue
        users[user_id] = UserRecord(
            slot_index=int(item_match.group(1), 16),
            user_id=user_id,
            properties=properties,
        )
        if user_id == 600 and len(users) >= EXPECTED_USER_COUNT:
            break
    return UserSnapshot(start_offset=start_offset, users=users)


def find_user_snapshots(text: str) -> List[UserSnapshot]:
    snapshots: List[UserSnapshot] = []
    for root_match in ROOT_RE.finditer(text):
        start = root_match.start()
        window = text[start : start + 3_500_000]
        snapshot = parse_snapshot(window, start_offset=start)
        if snapshot.unique_ids:
            snapshots.append(snapshot)
    return snapshots


def choose_snapshot(snapshots: List[UserSnapshot], selector: str) -> UserSnapshot:
    if not snapshots:
        raise SystemExit("No JA100UsersSetup / TJA100AllUsers snapshots found in the .fdb payload.")
    if selector == "latest":
        return max(snapshots, key=lambda snapshot: (snapshot.unique_ids, snapshot.start_offset))
    try:
        index = int(selector)
    except ValueError as exc:
        raise SystemExit(f"Invalid snapshot selector: {selector}") from exc
    try:
        return snapshots[index]
    except IndexError as exc:
        raise SystemExit(f"Snapshot index {index} is out of range.") from exc


def iter_user_rows(snapshot: UserSnapshot, *, include_null: bool) -> Iterable[UserRecord]:
    for user_id in sorted(snapshot.users):
        record = snapshot.users[user_id]
        if not include_null and record.properties.get("IsNull") == "True":
            continue
        yield record


def print_user_table(records: Iterable[UserRecord]) -> None:
    rows = [("ID", "Slot", "Name", "Code", "Permissions", "Card1", "Null", "Comment")]
    for record in records:
        props = record.properties
        rows.append(
            (
                str(record.user_id),
                str(record.slot_index),
                props.get("Name", ""),
                props.get("Code", ""),
                props.get("Permissions", ""),
                props.get("AccessCard1", ""),
                props.get("IsNull", ""),
                props.get("Comment", ""),
            )
        )
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())


def print_user_tsv(records: Iterable[UserRecord]) -> None:
    print("\t".join(["ID", "Slot", "Name", "Code", "Permissions", "Card1", "Null", "Comment"]))
    for record in records:
        props = record.properties
        print(
            "\t".join(
                [
                    str(record.user_id),
                    str(record.slot_index),
                    props.get("Name", ""),
                    props.get("Code", ""),
                    props.get("Permissions", ""),
                    props.get("AccessCard1", ""),
                    props.get("IsNull", ""),
                    props.get("Comment", ""),
                ]
            )
        )


def cmd_info(args: argparse.Namespace) -> None:
    container = read_fdb(Path(args.fdb))
    print(f"path: {args.fdb}")
    print(f"header_len: {len(container.header)}")
    print(f"compressed_len: {len(container.compressed_payload)}")
    print(f"decompressed_len: {len(container.decompressed_payload)}")
    print(f"xml_offset: {container.xml_offset}")
    print(f"preamble_hex: {container.preamble.hex()}")
    print(f"xml_head: {container.xml_bytes[:120].decode('utf-8', 'replace')}")


def cmd_unpack(args: argparse.Namespace) -> None:
    container = read_fdb(Path(args.fdb))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.xml_only:
        output.write_bytes(container.xml_bytes)
    elif args.payload_only:
        output.write_bytes(container.decompressed_payload)
    else:
        output.write_bytes(container.xml_bytes)
    print(f"wrote {output}")


def cmd_pack(args: argparse.Namespace) -> None:
    input_path = Path(args.input)
    output_path = Path(args.output)

    header = FDB_HEADER
    preamble = DEFAULT_PREAMBLE
    if args.template:
        template = read_fdb(Path(args.template))
        header = template.header
        preamble = template.preamble

    if args.xml:
        payload = build_payload_from_xml(input_path.read_bytes(), preamble=preamble)
    else:
        payload = input_path.read_bytes()

    write_fdb(output=output_path, payload=payload, header=header, compression_level=args.compression_level)
    print(f"wrote {output_path}")


def cmd_extract_users(args: argparse.Namespace) -> None:
    container = read_fdb(Path(args.fdb))
    snapshots = find_user_snapshots(container.xml_text)
    snapshot = choose_snapshot(snapshots, args.snapshot)
    records = list(iter_user_rows(snapshot, include_null=args.include_null))
    if args.format == "json":
        payload = [
            {
                "slot_index": record.slot_index,
                "user_id": record.user_id,
                "properties": record.properties,
            }
            for record in records
        ]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    if args.format == "tsv":
        print_user_tsv(records)
        return
    print_user_table(records)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    info_parser = subparsers.add_parser("info", help="Show container-level information about an .fdb file.")
    info_parser.add_argument("fdb", help="Path to the .fdb file.")
    info_parser.set_defaults(func=cmd_info)

    unpack_parser = subparsers.add_parser("unpack", help="Decompress an .fdb file.")
    unpack_parser.add_argument("fdb", help="Path to the .fdb file.")
    unpack_parser.add_argument("output", help="Output file to write.")
    unpack_parser.add_argument("--xml-only", action="store_true", help="Write only the XML portion.")
    unpack_parser.add_argument("--payload-only", action="store_true", help="Write the full decompressed payload.")
    unpack_parser.set_defaults(func=cmd_unpack)

    pack_parser = subparsers.add_parser("pack", help="Create an .fdb file from XML or a decompressed payload.")
    pack_parser.add_argument("input", help="Input XML or decompressed payload file.")
    pack_parser.add_argument("output", help="Output .fdb path.")
    pack_parser.add_argument("--xml", action="store_true", help="Treat the input as XML and prepend the known preamble.")
    pack_parser.add_argument(
        "--template",
        help="Optional existing .fdb whose header and preamble should be preserved when packing.",
    )
    pack_parser.add_argument(
        "--compression-level",
        type=int,
        default=1,
        choices=range(0, 10),
        help="zlib compression level (default: 1, matching observed files best).",
    )
    pack_parser.set_defaults(func=cmd_pack)

    users_parser = subparsers.add_parser("extract-users", help="Extract users from the decompressed XML content.")
    users_parser.add_argument("fdb", help="Path to the .fdb file.")
    users_parser.add_argument("--snapshot", default="latest", help="Snapshot index or 'latest'.")
    users_parser.add_argument("--include-null", action="store_true", help="Include empty/default user slots.")
    users_parser.add_argument("--format", choices=["table", "tsv", "json"], default="table")
    users_parser.set_defaults(func=cmd_extract_users)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
