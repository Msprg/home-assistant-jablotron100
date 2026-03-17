#!/usr/bin/env python3
"""Decode user records from Jablotron EXPORT.CFG blobs."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from jablotron_re_tools import (
    EXPORT_SECTORS,
    EXPORT_START_LBA,
    ExportCatalogSnapshot,
    UserRecord,
    decode_msgpack_value,
    default_export_output,
    extract_export_catalog,
    extract_users,
    invert_blob,
    iter_printable_strings,
    pull_live_export_snapshot,
    read_export_direct,
    resolve_flexi_cfg_device,
    trigger_live_export,
)


KNOWN_COLLECTIONS = {
    0x06: "sections",
    0x07: "users",
    0x08: "unknown",
    0x09: "objects",
    0x0A: "unknown",
    0x0B: "hardware",
    0x0C: "pgs",
    0x0D: "unknown",
    0x11: "unknown",
    0x13: "unknown",
    0x14: "unknown",
    0x17: "unknown",
    0x18: "unknown",
}


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


def emit_catalog(snapshot: ExportCatalogSnapshot, fmt: str) -> None:
    payload = {
        "path": str(snapshot.path),
        "users": [asdict(record) for record in snapshot.users],
        "sections": {section_id: asdict(record) for section_id, record in snapshot.sections_by_id.items()},
        "objects": {object_id: asdict(record) for object_id, record in snapshot.objects_by_id.items()},
        "hardware": {object_id: asdict(record) for object_id, record in snapshot.hardware_by_id.items()},
        "pgs": {pg_id: asdict(record) for pg_id, record in snapshot.pgs_by_id.items()},
        "communicators": {object_id: asdict(record) for object_id, record in snapshot.communicators_by_id.items()},
    }
    if fmt == "summary":
        print(f"path {snapshot.path}")
        print(f"users {len(snapshot.users)}")
        print(f"sections {len(snapshot.sections_by_id)}")
        print(f"objects {len(snapshot.objects_by_id)}")
        print(f"communicators {len(snapshot.communicators_by_id)}")
        print(f"pgs {len(snapshot.pgs_by_id)}")
        return
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def _json_ready(value: object | None) -> object | None:
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value


def _field_shape(fields: dict[object, object | None]) -> tuple[str, ...]:
    return tuple(sorted(str(key) for key in fields.keys()))


def _scan_export_collections(blob: bytes) -> dict[int, dict[int, dict[object, object | None]]]:
    collections: dict[int, dict[int, dict[object, object | None]]] = {}

    def store(collection_id: int, item_id: int, fields: dict[object, object | None]) -> None:
        if not all(isinstance(key, int) for key in fields):
            return
        collections.setdefault(collection_id, {}).setdefault(item_id, fields)

    try:
        leading_collection_id, cursor = decode_msgpack_value(blob, 0)
        leading_record, _next = decode_msgpack_value(blob, cursor)
    except Exception:
        leading_collection_id = None
        leading_record = None
    if isinstance(leading_collection_id, int) and isinstance(leading_record, dict) and len(leading_record) == 1:
        item_id, fields = next(iter(leading_record.items()))
        if isinstance(item_id, int) and isinstance(fields, dict):
            store(leading_collection_id, item_id, fields)

    for offset in range(len(blob) - 1):
        collection_id = blob[offset]
        if collection_id > 0x3F or blob[offset + 1] != 0x81:
            continue
        try:
            parsed_collection_id, cursor = decode_msgpack_value(blob, offset)
            record, _next = decode_msgpack_value(blob, cursor)
        except Exception:
            continue
        if parsed_collection_id != collection_id or not isinstance(record, dict) or len(record) != 1:
            continue
        item_id, fields = next(iter(record.items()))
        if not isinstance(item_id, int) or not isinstance(fields, dict):
            continue
        store(collection_id, item_id, fields)

    return collections


def _append_heading(lines: list[str], title: str) -> None:
    if lines:
        lines.append("")
    lines.append(f"## {title}")
    lines.append("")


def _summarize_catalog(snapshot: ExportCatalogSnapshot) -> list[str]:
    lines: list[str] = []

    _append_heading(lines, "Catalog Summary")
    lines.append(f"path: {snapshot.path}")
    lines.append(f"users: {len(snapshot.users)}")
    lines.append(f"sections: {len(snapshot.sections_by_id)}")
    lines.append(f"objects: {len(snapshot.objects_by_id)}")
    lines.append(f"communicators: {len(snapshot.communicators_by_id)}")
    lines.append(f"hardware records: {len(snapshot.hardware_by_id)}")
    lines.append(f"pgs: {len(snapshot.pgs_by_id)}")

    _append_heading(lines, "Sections")
    for section in sorted(snapshot.sections_by_id.values(), key=lambda item: item.display_id):
        extras = []
        if section.flags_raw is not None:
            extras.append(f"flags={section.flags_raw}")
        if section.options_raw is not None:
            extras.append(f"options={section.options_raw}")
        if section.state_raw is not None:
            extras.append(f"state={section.state_raw}")
        suffix = f" [{' '.join(extras)}]" if extras else ""
        if section.comment:
            suffix += f" comment={section.comment!r}"
        lines.append(f"{section.display_id:>3}: {section.name}{suffix}")

    _append_heading(lines, "Objects")
    for object_record in sorted(snapshot.objects_by_id.values(), key=lambda item: item.object_id):
        section_name = None
        if object_record.section_id is not None:
            section = snapshot.sections_by_id.get(object_record.section_id)
            if section is not None:
                section_name = f"{section.display_id}: {section.name}"
        hardware = snapshot.hardware_by_id.get(object_record.object_id)
        extras = []
        if section_name:
            extras.append(f"section={section_name}")
        if object_record.kind_raw is not None:
            extras.append(f"kind={object_record.kind_raw}")
        if object_record.type_raw is not None:
            extras.append(f"type={object_record.type_raw}")
        if object_record.subtype_raw is not None:
            extras.append(f"subtype={object_record.subtype_raw}")
        if hardware is not None:
            extras.append(
                f"hw={hardware.model or '?'} / {hardware.hardware_code or '?'} / {hardware.firmware or '?'}"
            )
        if object_record.pg_masks:
            extras.append(f"pg_masks={object_record.pg_masks}")
        if object_record.comment:
            extras.append(f"comment={object_record.comment!r}")
        suffix = f" [{' ; '.join(extras)}]" if extras else ""
        lines.append(f"{object_record.object_id:>3}: {object_record.name}{suffix}")

    _append_heading(lines, "PGs")
    for pg in sorted(snapshot.pgs_by_id.values(), key=lambda item: item.display_id):
        extras = []
        if pg.type_raw is not None:
            extras.append(f"type={pg.type_raw}")
        if pg.section_id is not None:
            section = snapshot.sections_by_id.get(pg.section_id)
            if section is not None:
                extras.append(f"section={section.display_id}: {section.name}")
            else:
                extras.append(f"section_id={pg.section_id}")
        if pg.field6_raw is not None:
            extras.append(f"field6={pg.field6_raw}")
        if pg.comment:
            extras.append(f"comment={pg.comment!r}")
        suffix = f" [{' ; '.join(extras)}]" if extras else ""
        lines.append(f"{pg.display_id:>3}: {pg.name}{suffix}")

    _append_heading(lines, "Users")
    for user in snapshot.users:
        fields = [f"slot={user.user_id if user.user_id is not None else '?'}"]
        if user.rights:
            fields.append(f"rights={user.rights}")
        if user.enabled is not None:
            fields.append(f"enabled={'yes' if user.enabled else 'no'}")
        if user.code:
            fields.append(f"code={user.code}")
        if user.card:
            fields.append(f"card={user.card}")
        if user.phone:
            fields.append(f"phone={user.phone}")
        if user.comment:
            fields.append(f"comment={user.comment!r}")
        lines.append(f"{user.name or '<unnamed>'}: {' ; '.join(fields)}")

    return lines


def render_readable_export_report(
    export_cfg: Path,
    *,
    include_raw_records: bool,
    include_strings: bool,
    min_string_length: int,
) -> str:
    raw_blob = export_cfg.read_bytes()
    blob = invert_blob(raw_blob)
    snapshot = extract_export_catalog(export_cfg)
    collections = {
        collection_id: items
        for collection_id, items in _scan_export_collections(blob).items()
        if collection_id in KNOWN_COLLECTIONS or len(items) >= 2
    }

    lines: list[str] = [
        f"# EXPORT.CFG readable dump: {export_cfg}",
        "",
        f"blob_size: {len(raw_blob)} bytes",
        f"sha256: {hashlib.sha256(raw_blob).hexdigest()}",
    ]
    lines.extend(_summarize_catalog(snapshot))

    _append_heading(lines, "Collection Inventory")
    for collection_id in sorted(collections):
        items = collections[collection_id]
        field_shapes = sorted({_field_shape(fields) for fields in items.values()})
        shape_text = ", ".join(str(list(shape)) for shape in field_shapes[:4])
        if len(field_shapes) > 4:
            shape_text += ", ..."
        name = KNOWN_COLLECTIONS.get(collection_id, "unknown")
        lines.append(
            f"0x{collection_id:02x} ({name}): {len(items)} item(s)"
            + (f"; field keys: {shape_text}" if shape_text else "")
        )

    if include_raw_records:
        _append_heading(lines, "Raw Collection Records")
        for collection_id in sorted(collections):
            items = collections[collection_id]
            name = KNOWN_COLLECTIONS.get(collection_id, "unknown")
            lines.append(f"### 0x{collection_id:02x} ({name})")
            lines.append("")
            for item_id in sorted(items):
                payload = json.dumps(_json_ready(items[item_id]), ensure_ascii=False, sort_keys=True)
                lines.append(f"{item_id}: {payload}")
            lines.append("")

    if include_strings:
        _append_heading(lines, "Unique Printable Strings")
        seen: set[str] = set()
        for text in iter_printable_strings(blob, min_length=min_string_length):
            if text in seen:
                continue
            seen.add(text)
            lines.append(text)

    return "\n".join(lines).rstrip() + "\n"


def cmd_extract_users(args: argparse.Namespace) -> None:
    records = extract_users(Path(args.export_cfg), dedupe=args.user_mode)
    emit_records(records, args.format)


def cmd_extract_catalog(args: argparse.Namespace) -> None:
    snapshot = extract_export_catalog(Path(args.export_cfg))
    emit_catalog(snapshot, args.format)


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


def cmd_dump_readable(args: argparse.Namespace) -> None:
    export_cfg = Path(args.export_cfg)
    report = render_readable_export_report(
        export_cfg,
        include_raw_records=not args.no_raw_records,
        include_strings=not args.no_strings,
        min_string_length=args.min_length,
    )
    if args.output:
        output = Path(args.output)
        output.write_text(report, encoding="utf-8")
        print(f"wrote {output}")
        return
    sys.stdout.write(report)


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

    catalog_parser = subparsers.add_parser(
        "extract-catalog",
        help="Extract the broader panel-derived catalog from an EXPORT.CFG blob.",
    )
    catalog_parser.add_argument("export_cfg", help="Path to EXPORT.CFG or an equivalent 1 MiB export blob.")
    catalog_parser.add_argument("--format", choices=["json", "summary"], default="summary")
    catalog_parser.set_defaults(func=cmd_extract_catalog)

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

    readable_parser = subparsers.add_parser(
        "dump-readable",
        help="Render a skimmable text dump of an EXPORT.CFG blob: catalog, raw collections, and strings.",
    )
    readable_parser.add_argument("export_cfg", help="Path to EXPORT.CFG or an equivalent 1 MiB export blob.")
    readable_parser.add_argument("--output", help="Optional text file to write instead of stdout.")
    readable_parser.add_argument(
        "--min-length",
        type=int,
        default=4,
        help="Minimum printable string length to include in the strings section (default: 4).",
    )
    readable_parser.add_argument(
        "--no-raw-records",
        action="store_true",
        help="Skip the raw collection record section.",
    )
    readable_parser.add_argument(
        "--no-strings",
        action="store_true",
        help="Skip the printable strings section.",
    )
    readable_parser.set_defaults(func=cmd_dump_readable)

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
