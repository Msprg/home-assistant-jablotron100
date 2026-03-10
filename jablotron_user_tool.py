#!/usr/bin/env python3
"""Operator-facing user-management CLI built on the live RE helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Iterable

from import_cfg_tool import (
    build_user_delete_payload,
    build_user_upsert_payload,
    describe_payload,
    encode_sector,
    write_output,
)
from jablotron_re_tools import (
    DEFAULT_ADD_TEMPLATE_FRAME,
    DEFAULT_ADD_TEMPLATE_PCAP,
    DEFAULT_IMPORT_PATH,
    ExportSnapshot,
    UserRecord,
    apply_import_sector,
    default_export_output,
    default_sector_output,
    dedupe_user_records,
    extract_users,
    pull_live_export_snapshot,
    resolve_flexi_cfg_device,
)


def print_table(records: Iterable[UserRecord]) -> None:
    rows = [("ID", "Rights", "Enabled", "Name", "Code", "Phone", "Card", "Comment", "Offset")]
    for record in records:
        rows.append(
            (
                "" if record.user_id is None else str(record.user_id),
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
    print("\t".join(["ID", "Rights", "Enabled", "Name", "Code", "Phone", "Card", "Comment", "Offset"]))
    for record in records:
        print(
            "\t".join(
                [
                    "" if record.user_id is None else str(record.user_id),
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


def load_snapshot_from_file(path: Path) -> ExportSnapshot:
    raw_records = extract_users(path, dedupe="raw")
    records = dedupe_user_records(raw_records)
    return ExportSnapshot(
        path=path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        raw_records=raw_records,
        records=records,
    )


def load_snapshot(args: argparse.Namespace, *, prefix: str) -> ExportSnapshot:
    export_cfg = getattr(args, "export_cfg", None)
    if export_cfg:
        return load_snapshot_from_file(Path(export_cfg))

    output = Path(args.output) if getattr(args, "output", None) else default_export_output(prefix)
    return pull_live_export_snapshot(
        output=output,
        device=args.device,
        port=args.port,
        code=args.auth_code,
        reset=not args.no_reset,
        trigger=not getattr(args, "no_trigger", False),
    )


def print_snapshot_summary(snapshot: ExportSnapshot, *, device: str | None = None) -> None:
    print(f"wrote {snapshot.path}")
    print(f"sha256 {snapshot.sha256}")
    if device is not None:
        print(f"device {resolve_flexi_cfg_device(device)}")
    print(f"users_raw {len(snapshot.raw_records)}")
    print(f"users_deduped {len(snapshot.records)}")


def find_user(snapshot: ExportSnapshot, user_id: int) -> UserRecord:
    for record in snapshot.records:
        if record.user_id == user_id:
            return record
    raise SystemExit(f"User {user_id} not found in {snapshot.path}.")


def resolve_template_args(args: argparse.Namespace, *, allow_default_minimal: bool) -> tuple[str | None, str | None, int | None]:
    template_file = getattr(args, "template_file", None)
    template_pcap = getattr(args, "template_pcap", None)
    template_frame = getattr(args, "template_frame", None)

    if template_pcap and template_frame is None:
        raise SystemExit("--template-frame is required when using --template-pcap.")

    if template_file or template_pcap:
        return template_file, template_pcap, template_frame

    if allow_default_minimal:
        return None, str(DEFAULT_ADD_TEMPLATE_PCAP), DEFAULT_ADD_TEMPLATE_FRAME

    raise SystemExit(
        "Editing requires a template source for unknown fields. "
        "Pass --template-file, --template-pcap/--template-frame, or --use-minimal-template for minimal users."
    )


def build_upsert_sector(args: argparse.Namespace, *, current: UserRecord | None) -> tuple[Path, dict[str, object], bool]:
    allow_default_minimal = args.command == "add" or getattr(args, "use_minimal_template", False)
    template_file, template_pcap, template_frame = resolve_template_args(args, allow_default_minimal=allow_default_minimal)

    name = args.name if args.name is not None else (current.name if current else None)
    phone = args.phone if args.phone is not None else (current.phone if current else None)
    pin = args.pin if args.pin is not None else (current.code if current else None)
    card1 = args.card1 if args.card1 is not None else (current.card if current and current.card else None)
    comment = args.comment if args.comment is not None else (current.comment if current else None)

    if name is None:
        raise SystemExit("A user name is required for add/edit upserts.")

    payload_args = SimpleNamespace(
        template_file=template_file,
        template_pcap=template_pcap,
        template_frame=template_frame,
        user_id=args.user_id,
        name=name,
        phone=phone,
        code=pin,
        card1=card1,
        card2=args.card2,
        comment=comment,
        field0_raw=args.field0_raw,
        permissions_raw=args.permissions_raw,
        sections_mask=args.sections_mask,
        sections=args.sections,
        pg_masks=args.pg_masks,
        pgs=args.pgs,
        field8_raw=args.field8_raw,
        field9_raw=args.field9_raw,
        field11_raw=args.field11_raw,
    )
    payload = build_user_upsert_payload(payload_args)
    sector = encode_sector(payload)

    sector_path = Path(args.sector_output) if args.sector_output else default_sector_output(f"{args.command}-user{args.user_id}")
    write_output(sector_path, sector)
    ephemeral = args.sector_output is None and not args.keep_sector
    return sector_path, describe_payload(payload), ephemeral


def build_delete_sector(args: argparse.Namespace) -> tuple[Path, dict[str, object], bool]:
    payload = build_user_delete_payload(args.user_id)
    sector = encode_sector(payload)
    sector_path = Path(args.sector_output) if args.sector_output else default_sector_output(f"delete-user{args.user_id}")
    write_output(sector_path, sector)
    ephemeral = args.sector_output is None and not args.keep_sector
    return sector_path, describe_payload(payload), ephemeral


def emit_verify_result(snapshot: ExportSnapshot, *, user_id: int | None, fmt: str) -> None:
    records = snapshot.records
    if user_id is not None:
        records = [record for record in records if record.user_id == user_id]
    emit_records(records, fmt)


def maybe_cleanup(path: Path, *, cleanup: bool) -> None:
    if cleanup:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def add_live_read_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--export-cfg", help="Read users from an existing EXPORT.CFG blob instead of pulling live.")
    parser.add_argument(
        "--output",
        help="When pulling live, write the export blob here. Defaults to a timestamped file in /tmp.",
    )
    add_live_session_arguments(parser)
    parser.add_argument("--no-trigger", action="store_true", help="Skip the HID export trigger before the block read.")


def add_live_session_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--device",
        default="auto",
        help="FLEXI_CFG block device or 'auto' to resolve /dev/disk/by-label/FLEXI_CFG.",
    )
    parser.add_argument("--port", default="auto", help="HID port for live pulls (default: auto).")
    parser.add_argument("--auth-code", default="1812", help="Authorisation code for live sessions.")
    parser.add_argument("--no-reset", action="store_true", help="Skip the initial auth-end reset packet.")


def add_live_apply_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--sector-output", help="Write the generated IMPORT sector here.")
    parser.add_argument("--keep-sector", action="store_true", help="Keep the generated sector file when auto-created.")
    parser.add_argument(
        "--import-path",
        default=str(DEFAULT_IMPORT_PATH),
        help=f"Mounted IMPORT.CFG path (default: {DEFAULT_IMPORT_PATH}).",
    )
    parser.add_argument(
        "--mount-tool",
        choices=("sudo", "udisksctl"),
        default="sudo",
        help="Mount helper to use for remount/unmount (default: sudo).",
    )
    parser.add_argument("--verify-output", help="If set, verify against this export path. Defaults to /tmp.")
    parser.add_argument("--no-apply", action="store_true", help="Only build the sector and do not touch the panel.")
    parser.add_argument("--verbose", action="store_true", help="Print the observed HID packets.")


def add_upsert_field_arguments(parser: argparse.ArgumentParser, *, require_name: bool) -> None:
    parser.add_argument("--name", required=require_name, help="User name.")
    parser.add_argument("--phone", help="Phone number field.")
    parser.add_argument("--pin", help="PIN/code field without the user prefix.")
    parser.add_argument("--card1", help="Primary access-card decimal string.")
    parser.add_argument("--card2", help="Secondary access-card decimal string.")
    parser.add_argument("--comment", help="Comment field.")
    parser.add_argument("--field0-raw", type=int, help="Raw field 0 value.")
    parser.add_argument("--permissions-raw", type=int, help="Raw field 1 value.")
    parser.add_argument("--sections-mask", type=int, help="Raw field 2 bitmask.")
    parser.add_argument("--sections", help="Comma-separated 1-based section numbers to encode into field 2.")
    parser.add_argument("--pg-masks", help="Comma-separated raw PG masks for field 3 (exactly four integers).")
    parser.add_argument("--pgs", help="Comma-separated 1-based PG numbers to encode into the four 16-bit masks.")
    parser.add_argument("--field8-raw", type=int, help="Raw field 8 value.")
    parser.add_argument("--field9-raw", type=int, help="Raw field 9 value.")
    parser.add_argument("--field11-raw", type=int, help="Raw field 11 value.")
    parser.add_argument("--template-file", help="Use an existing encoded sector as the template for unknown fields.")
    parser.add_argument("--template-pcap", help="Use a pcap frame as the template source.")
    parser.add_argument("--template-frame", type=int, help="Frame number used with --template-pcap.")


def cmd_pull_export(args: argparse.Namespace) -> None:
    output = Path(args.output) if args.output else default_export_output("user-tool-pull")
    snapshot = pull_live_export_snapshot(
        output=output,
        device=args.device,
        port=args.port,
        code=args.auth_code,
        reset=not args.no_reset,
        trigger=not args.no_trigger,
    )
    print_snapshot_summary(snapshot, device=args.device)


def cmd_list(args: argparse.Namespace) -> None:
    snapshot = load_snapshot(args, prefix="user-tool-list")
    print_snapshot_summary(snapshot, device=None if args.export_cfg else args.device)
    emit_records(snapshot.records if args.user_mode == "dedupe" else snapshot.raw_records, args.format)


def cmd_get(args: argparse.Namespace) -> None:
    snapshot = load_snapshot(args, prefix=f"user-tool-get{args.user_id}")
    print_snapshot_summary(snapshot, device=None if args.export_cfg else args.device)
    records = snapshot.records if args.user_mode == "dedupe" else snapshot.raw_records
    records = [record for record in records if record.user_id == args.user_id]
    if not records:
        raise SystemExit(f"User {args.user_id} not found.")
    emit_records(records, args.format)


def cmd_add(args: argparse.Namespace) -> None:
    sector_path, summary, cleanup_sector = build_upsert_sector(args, current=None)
    try:
        print(f"sector {sector_path}")
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        if args.no_apply:
            return

        verify_output = Path(args.verify_output) if args.verify_output else default_export_output(f"post-add-user{args.user_id}")
        snapshot = apply_import_sector(
            sector_path=sector_path,
            import_path=Path(args.import_path),
            device=args.device,
            port=args.port,
            code=args.auth_code,
            reset=not args.no_reset,
            mount_tool=args.mount_tool,
            verbose=args.verbose,
            verify_output=verify_output,
        )
        if snapshot is None:
            return
        print_snapshot_summary(snapshot, device=args.device)
        emit_verify_result(snapshot, user_id=args.user_id, fmt=args.format)
    finally:
        maybe_cleanup(sector_path, cleanup=cleanup_sector)


def cmd_edit(args: argparse.Namespace) -> None:
    snapshot_before = load_snapshot(args, prefix=f"pre-edit-user{args.user_id}")
    current = find_user(snapshot_before, args.user_id)
    sector_path, summary, cleanup_sector = build_upsert_sector(args, current=current)
    try:
        print(f"sector {sector_path}")
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        if args.no_apply:
            return

        verify_output = Path(args.verify_output) if args.verify_output else default_export_output(f"post-edit-user{args.user_id}")
        snapshot = apply_import_sector(
            sector_path=sector_path,
            import_path=Path(args.import_path),
            device=args.device,
            port=args.port,
            code=args.auth_code,
            reset=not args.no_reset,
            mount_tool=args.mount_tool,
            verbose=args.verbose,
            verify_output=verify_output,
        )
        if snapshot is None:
            return
        print_snapshot_summary(snapshot, device=args.device)
        emit_verify_result(snapshot, user_id=args.user_id, fmt=args.format)
    finally:
        maybe_cleanup(sector_path, cleanup=cleanup_sector)


def cmd_delete(args: argparse.Namespace) -> None:
    sector_path, summary, cleanup_sector = build_delete_sector(args)
    try:
        print(f"sector {sector_path}")
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        if args.no_apply:
            return

        verify_output = Path(args.verify_output) if args.verify_output else default_export_output(f"post-delete-user{args.user_id}")
        snapshot = apply_import_sector(
            sector_path=sector_path,
            import_path=Path(args.import_path),
            device=args.device,
            port=args.port,
            code=args.auth_code,
            reset=not args.no_reset,
            mount_tool=args.mount_tool,
            verbose=args.verbose,
            verify_output=verify_output,
        )
        if snapshot is None:
            return
        print_snapshot_summary(snapshot, device=args.device)
        records = [record for record in snapshot.records if record.user_id == args.user_id]
        if records:
            emit_records(records, args.format)
        else:
            print(f"user {args.user_id} absent after delete")
    finally:
        maybe_cleanup(sector_path, cleanup=cleanup_sector)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    pull_export = subparsers.add_parser("pull-export", help="Trigger a live export and save the blob.")
    pull_export.add_argument("output", nargs="?", help="Output path. Defaults to a timestamped file in /tmp.")
    pull_export.add_argument(
        "--device",
        default="auto",
        help="FLEXI_CFG block device or 'auto' to resolve /dev/disk/by-label/FLEXI_CFG.",
    )
    pull_export.add_argument("--port", default="auto", help="HID port (default: auto).")
    pull_export.add_argument("--auth-code", default="1812", help="Authorisation code for the export session.")
    pull_export.add_argument("--no-reset", action="store_true", help="Skip the initial auth-end reset packet.")
    pull_export.add_argument("--no-trigger", action="store_true", help="Skip the HID export trigger before reading.")
    pull_export.set_defaults(func=cmd_pull_export)

    list_parser = subparsers.add_parser("list", help="List users from a live panel or saved export.")
    add_live_read_arguments(list_parser)
    list_parser.add_argument("--format", choices=["table", "tsv", "json"], default="table")
    list_parser.add_argument("--user-mode", choices=["dedupe", "raw"], default="dedupe")
    list_parser.set_defaults(func=cmd_list)

    get_parser = subparsers.add_parser("get", help="Show one user from a live panel or saved export.")
    get_parser.add_argument("user_id", type=int, help="User ID to print.")
    add_live_read_arguments(get_parser)
    get_parser.add_argument("--format", choices=["table", "tsv", "json"], default="table")
    get_parser.add_argument("--user-mode", choices=["dedupe", "raw"], default="dedupe")
    get_parser.set_defaults(func=cmd_get)

    add_parser = subparsers.add_parser("add", help="Add a user to an empty slot and apply it live by default.")
    add_parser.add_argument("user_id", type=int, help="Target user ID.")
    add_upsert_field_arguments(add_parser, require_name=True)
    add_live_session_arguments(add_parser)
    add_live_apply_arguments(add_parser)
    add_parser.add_argument("--format", choices=["table", "tsv", "json"], default="table")
    add_parser.set_defaults(func=cmd_add)

    edit_parser = subparsers.add_parser("edit", help="Edit a user and apply it live by default.")
    edit_parser.add_argument("user_id", type=int, help="Target user ID.")
    add_upsert_field_arguments(edit_parser, require_name=False)
    add_live_read_arguments(edit_parser)
    add_live_apply_arguments(edit_parser)
    edit_parser.add_argument(
        "--use-minimal-template",
        action="store_true",
        help="Use the known minimal add template when no explicit template source is provided.",
    )
    edit_parser.add_argument("--format", choices=["table", "tsv", "json"], default="table")
    edit_parser.set_defaults(func=cmd_edit)

    delete_parser = subparsers.add_parser("delete", help="Delete a user and apply it live by default.")
    delete_parser.add_argument("user_id", type=int, help="Target user ID.")
    add_live_session_arguments(delete_parser)
    add_live_apply_arguments(delete_parser)
    delete_parser.add_argument("--format", choices=["table", "tsv", "json"], default="table")
    delete_parser.set_defaults(func=cmd_delete)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
