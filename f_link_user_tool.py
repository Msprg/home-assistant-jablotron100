#!/usr/bin/env python3
"""Extract JA-100 user tables from F-Link process memory dumps.

F-Link keeps serialized `JA100UsersSetup` / `TJA100AllUsers` objects in memory.
This helper finds coherent snapshots of that structure and can:

- list available user-table snapshots in a dump
- print the latest complete user list
- diff two dumps snapshot-to-snapshot
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List

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
DEFAULT_WINDOW_BYTES = 3_500_000


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


def load_text(path: Path) -> str:
    return path.read_bytes().decode("latin1", "ignore")


def fix_text(value: str) -> str:
    if not value:
        return value
    try:
        repaired = value.encode("latin1").decode("utf-8")
    except UnicodeError:
        return value
    if "\ufffd" in repaired:
        return value
    return repaired


def parse_snapshot(window: str, *, start_offset: int) -> UserSnapshot:
    users: Dict[int, UserRecord] = {}
    for item_match in ITEM_RE.finditer(window):
        properties = {
            property_match.group(1): fix_text(property_match.group(3).strip())
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


def find_user_snapshots(path: Path, *, window_bytes: int = DEFAULT_WINDOW_BYTES) -> List[UserSnapshot]:
    text = load_text(path)
    snapshots: List[UserSnapshot] = []
    for root_match in ROOT_RE.finditer(text):
        start = root_match.start()
        window = text[start : start + window_bytes]
        snapshot = parse_snapshot(window, start_offset=start)
        if snapshot.unique_ids:
            snapshots.append(snapshot)
    return snapshots


def choose_snapshot(snapshots: List[UserSnapshot], selector: str) -> UserSnapshot:
    if not snapshots:
        raise SystemExit("No JA100UsersSetup / TJA100AllUsers snapshots found.")
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
        is_null = record.properties.get("IsNull") == "True"
        if not include_null and is_null:
            continue
        yield record


def record_to_json(record: UserRecord) -> Dict[str, object]:
    return {
        "slot_index": record.slot_index,
        "user_id": record.user_id,
        "properties": record.properties,
    }


def print_table(snapshot: UserSnapshot, *, include_null: bool) -> None:
    header = ("ID", "Slot", "Name", "Code", "Permissions", "Card1", "Null", "Comment")
    rows = [header]
    for record in iter_user_rows(snapshot, include_null=include_null):
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
    widths = [max(len(row[column]) for row in rows) for column in range(len(header))]
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())


def print_tsv(snapshot: UserSnapshot, *, include_null: bool) -> None:
    print("\t".join(["ID", "Slot", "Name", "Code", "Permissions", "Card1", "Null", "Comment"]))
    for record in iter_user_rows(snapshot, include_null=include_null):
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


def cmd_list_snapshots(args: argparse.Namespace) -> None:
    snapshots = find_user_snapshots(Path(args.dump))
    if not snapshots:
        raise SystemExit("No JA100 user snapshots found.")
    for index, snapshot in enumerate(snapshots):
        label = "complete" if snapshot.is_complete else "partial"
        user_91 = snapshot.users.get(91)
        user_91_summary = "-"
        if user_91:
            user_91_summary = (
                f"u91={user_91.properties.get('Name', '')}/"
                f"{user_91.properties.get('Code', '')}/"
                f"null={user_91.properties.get('IsNull', '')}"
            )
        print(
            f"{index:2d}  offset=0x{snapshot.start_offset:08x}  "
            f"users={snapshot.unique_ids:3d}  {label:<8}  {user_91_summary}"
        )


def cmd_extract_users(args: argparse.Namespace) -> None:
    snapshots = find_user_snapshots(Path(args.dump))
    snapshot = choose_snapshot(snapshots, args.snapshot)
    if args.format == "json":
        payload = {
            "start_offset": snapshot.start_offset,
            "unique_ids": snapshot.unique_ids,
            "is_complete": snapshot.is_complete,
            "users": [record_to_json(record) for record in iter_user_rows(snapshot, include_null=args.include_null)],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    if args.format == "tsv":
        print_tsv(snapshot, include_null=args.include_null)
        return
    print_table(snapshot, include_null=args.include_null)


def cmd_diff_users(args: argparse.Namespace) -> None:
    left = choose_snapshot(find_user_snapshots(Path(args.left_dump)), args.left_snapshot)
    right = choose_snapshot(find_user_snapshots(Path(args.right_dump)), args.right_snapshot)

    differing_ids = []
    for user_id in sorted(set(left.users) | set(right.users)):
        left_record = left.users.get(user_id)
        right_record = right.users.get(user_id)
        if left_record is None or right_record is None:
            differing_ids.append(user_id)
            continue
        left_props = left_record.properties
        right_props = right_record.properties
        differing_keys = sorted(key for key in set(left_props) | set(right_props) if left_props.get(key, "") != right_props.get(key, ""))
        if differing_keys:
            differing_ids.append((user_id, differing_keys))

    if not differing_ids:
        print("No user differences found.")
        return

    for item in differing_ids:
        if isinstance(item, int):
            print(f"user {item}: present in only one snapshot")
            continue
        user_id, keys = item
        print(f"user {user_id}:")
        left_props = left.users[user_id].properties if user_id in left.users else {}
        right_props = right.users[user_id].properties if user_id in right.users else {}
        for key in keys:
            print(f"  {key}: {left_props.get(key, '')!r} -> {right_props.get(key, '')!r}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshots_parser = subparsers.add_parser("list-snapshots", help="List user-table snapshots found in a dump.")
    snapshots_parser.add_argument("dump", help="Path to the F-Link process memory dump.")
    snapshots_parser.set_defaults(func=cmd_list_snapshots)

    extract_parser = subparsers.add_parser("extract-users", help="Print one user-table snapshot from a dump.")
    extract_parser.add_argument("dump", help="Path to the F-Link process memory dump.")
    extract_parser.add_argument(
        "--snapshot",
        default="latest",
        help="Snapshot index to use, or 'latest' to choose the best complete/latest snapshot.",
    )
    extract_parser.add_argument("--include-null", action="store_true", help="Include empty/default user slots.")
    extract_parser.add_argument("--format", choices=["table", "tsv", "json"], default="table")
    extract_parser.set_defaults(func=cmd_extract_users)

    diff_parser = subparsers.add_parser("diff-users", help="Compare extracted user snapshots from two dumps.")
    diff_parser.add_argument("left_dump", help="Path to the left dump.")
    diff_parser.add_argument("right_dump", help="Path to the right dump.")
    diff_parser.add_argument("--left-snapshot", default="latest", help="Left snapshot index or 'latest'.")
    diff_parser.add_argument("--right-snapshot", default="latest", help="Right snapshot index or 'latest'.")
    diff_parser.set_defaults(func=cmd_diff_users)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
