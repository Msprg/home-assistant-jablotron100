#!/usr/bin/env python3
"""Decode user records from Jablotron EXPORT.CFG blobs."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from jablotron_re_tools import (
    EXPORT_SECTORS,
    EXPORT_START_LBA,
    UserRecord,
    default_export_output,
    extract_users,
    invert_blob,
    iter_printable_strings,
    pull_live_export_snapshot,
    read_export_direct,
    resolve_flexi_cfg_device,
    trigger_live_export,
)


def print_table(records: Iterable[UserRecord]) -> None:
    rows = [("ID", "RawID", "Rights", "Enabled", "Name", "Code", "Phone", "Card", "Comment", "Offset")]
    for record in records:
        rows.append(
            (
                "" if record.user_id is None else str(record.user_id),
                record.raw_id_bytes,
                record.rights,
                "" if record.enabled is None else ("yes" if record.enabled else "no"),
                record.name,
                record.code,
                record.phone,
                record.card,
                record.comment,
                str(record.offset),
            )
        )
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip())


def print_tsv(records: Iterable[UserRecord]) -> None:
    print("\t".join(["ID", "RawID", "Rights", "Enabled", "Name", "Code", "Phone", "Card", "Comment", "Offset"]))
    for record in records:
        print(
            "\t".join(
                [
                    "" if record.user_id is None else str(record.user_id),
                    record.raw_id_bytes,
                    record.rights,
                    "" if record.enabled is None else ("yes" if record.enabled else "no"),
                    record.name,
                    record.code,
                    record.phone,
                    record.card,
                    record.comment,
                    str(record.offset),
                ]
            )
        )


def emit_records(records: list[UserRecord], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps([asdict(record) for record in records], indent=2, ensure_ascii=False))
        return
    if fmt == "tsv":
        print_tsv(records)
        return
    print_table(records)


def cmd_extract_users(args: argparse.Namespace) -> None:
    records = extract_users(Path(args.export_cfg), dedupe=args.user_mode)
    emit_records(records, args.format)


def cmd_pull_live(args: argparse.Namespace) -> None:
    output = Path(args.output) if args.output else default_export_output("pull-live")
    snapshot = pull_live_export_snapshot(
        output=output,
        device=args.device,
        port=args.port,
        code=args.code,
        reset=not args.no_reset,
        trigger=not args.no_trigger,
        start_lba=args.start_lba,
        sectors=args.sectors,
        cleanup_mode=args.read_cleanup_mode,
        verbose=args.verbose,
    )
    print(f"wrote {snapshot.path}")
    print(f"sha256 {snapshot.sha256}")
    print(f"device {resolve_flexi_cfg_device(args.device)}")
    print(f"users_raw {len(snapshot.raw_records)}")
    print(f"users_deduped {len(snapshot.records)}")
    if args.extract_users:
        emit_records(snapshot.records if args.user_mode == "dedupe" else snapshot.raw_records, args.format)


def cmd_dump_text(args: argparse.Namespace) -> None:
    blob = invert_blob(Path(args.export_cfg).read_bytes())
    for text in iter_printable_strings(blob, min_length=args.min_length):
        print(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    pull_parser = subparsers.add_parser(
        "pull-live",
        help="Trigger a live export session and read EXPORT.CFG directly from the FLEXI_CFG block device.",
    )
    pull_parser.add_argument(
        "output",
        nargs="?",
        help="Output file to write. Defaults to a timestamped file in /tmp.",
    )
    pull_parser.add_argument(
        "--device",
        default="auto",
        help="FLEXI_CFG block device or 'auto' to resolve /dev/disk/by-label/FLEXI_CFG.",
    )
    pull_parser.add_argument("--port", default="auto", help="HID port to use for the trigger session (default: auto).")
    pull_parser.add_argument(
        "--code",
        default="1812",
        help="Authorisation code for the trigger session (default: captured service code 1812).",
    )
    pull_parser.add_argument("--no-reset", action="store_true", help="Skip the initial auth-end reset packet.")
    pull_parser.add_argument("--no-trigger", action="store_true", help="Only perform the direct block read.")
    pull_parser.add_argument(
        "--read-cleanup-mode",
        choices=["auto", "none", "exit-only", "login-exit"],
        default="auto",
        help="How to close the post-read HID session after a live trigger (default: auto).",
    )
    pull_parser.add_argument("--start-lba", type=int, default=EXPORT_START_LBA, help="Starting LBA to read.")
    pull_parser.add_argument("--sectors", type=int, default=EXPORT_SECTORS, help="Number of sectors to read.")
    pull_parser.add_argument("--extract-users", action="store_true", help="Also print parsed users after pulling.")
    pull_parser.add_argument("--format", choices=["table", "tsv", "json"], default="tsv")
    pull_parser.add_argument("--verbose", action="store_true", help="Print the observed HID packets for debugging.")
    pull_parser.add_argument(
        "--user-mode",
        choices=["dedupe", "raw"],
        default="dedupe",
        help="User view to print when extracting: operator-safe dedupe or raw RE mode.",
    )
    pull_parser.set_defaults(func=cmd_pull_live)

    extract_parser = subparsers.add_parser("extract-users", help="Extract user records from an EXPORT.CFG blob.")
    extract_parser.add_argument("export_cfg", help="Path to EXPORT.CFG or an equivalent 1 MiB export blob.")
    extract_parser.add_argument("--format", choices=["table", "tsv", "json"], default="table")
    extract_parser.add_argument(
        "--user-mode",
        choices=["dedupe", "raw"],
        default="dedupe",
        help="User view to print: operator-safe dedupe or raw RE mode.",
    )
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
