#!/usr/bin/env python3
"""Decode user records from Jablotron EXPORT.CFG blobs."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path

from jablotron_re_tools import (
    EXPORT_SECTORS,
    EXPORT_START_LBA,
    ExportCatalogSnapshot,
    UserRecord,
    add_flexi_cfg_device_argument,
    compress_numeric_ids,
    decode_msgpack_value,
    default_export_output,
    emit_user_records,
    extract_export_catalog,
    extract_users,
    format_allow_code_change,
    format_cards,
    format_log_user_actions,
    format_pg_access,
    format_section_access,
    format_time_limit_binding,
    invert_blob,
    iter_printable_strings,
    print_export_snapshot_summary,
    pull_live_export_snapshot,
    read_export_direct,
    resolve_flexi_cfg_device,
    trigger_live_export,
)


KNOWN_COLLECTIONS = {
    0x06: "sections",
    0x07: "users",
    0x08: "users_time_limit",
    0x09: "objects",
    0x0A: "unknown",
    0x0B: "hardware",
    0x0C: "pgs",
    0x0D: "unknown",
    0x11: "arc_setup",
    0x13: "unknown",
    0x14: "unknown",
    0x17: "unknown",
    0x18: "unknown",
}

def emit_records(records: list[UserRecord], fmt: str, snapshot: ExportCatalogSnapshot) -> None:
    emit_user_records(records, fmt, snapshot, show_names=True, include_raw_metadata=True)


def emit_catalog(snapshot: ExportCatalogSnapshot, fmt: str) -> None:
    payload = {
        "path": str(snapshot.path),
        "users": [asdict(record) for record in snapshot.users],
        "sections": {section_id: asdict(record) for section_id, record in snapshot.sections_by_id.items()},
        "objects": {object_id: asdict(record) for object_id, record in snapshot.objects_by_id.items()},
        "hardware": {object_id: asdict(record) for object_id, record in snapshot.hardware_by_id.items()},
        "pgs": {pg_id: asdict(record) for pg_id, record in snapshot.pgs_by_id.items()},
        "arcs": {arc_id: asdict(record) for arc_id, record in snapshot.arcs_by_id.items()},
        "time_limit_groups": {group_id: asdict(record) for group_id, record in snapshot.time_limit_groups_by_id.items()},
        "communicators": {object_id: asdict(record) for object_id, record in snapshot.communicators_by_id.items()},
        "main_config": asdict(snapshot.main_config) if snapshot.main_config is not None else None,
        "communications": asdict(snapshot.communications) if snapshot.communications is not None else None,
    }
    if fmt == "summary":
        print(f"path {snapshot.path}")
        print(f"users {len(snapshot.users)}")
        print(f"sections {len(snapshot.sections_by_id)}")
        print(f"objects {len(snapshot.objects_by_id)}")
        print(f"communicators {len(snapshot.communicators_by_id)}")
        print(f"pgs {len(snapshot.pgs_by_id)}")
        print(f"arcs {len(snapshot.arcs_by_id)}")
        print(f"time_limit_groups {len(snapshot.time_limit_groups_by_id)}")
        print(f"main_config {'yes' if snapshot.main_config is not None else 'no'}")
        print(f"communications {'yes' if snapshot.communications is not None else 'no'}")
        return
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def emit_time_limits(snapshot: ExportCatalogSnapshot, fmt: str) -> None:
    groups = [record for _, record in sorted(snapshot.time_limit_groups_by_id.items())]
    if fmt == "json":
        print(json.dumps([asdict(record) for record in groups], indent=2, ensure_ascii=False))
        return
    for group in groups:
        active_days = [day.day_name for day in group.days if day.section_rules]
        active_sections = sorted({rule.section_id for day in group.days for rule in day.section_rules})
        parts = [f"G{group.group_display_id}"]
        if active_days:
            parts.append(f"days={','.join(active_days)}")
        if active_sections:
            parts.append(f"sections={compress_numeric_ids(active_sections)}")
        if group.comment:
            parts.append(f"comment={group.comment!r}")
        print(" | ".join(parts))


def emit_arcs(snapshot: ExportCatalogSnapshot, fmt: str) -> None:
    sorted_arcs = [record for _, record in sorted(snapshot.arcs_by_id.items())]
    records = [asdict(record) for record in sorted_arcs]
    if fmt == "json":
        print(json.dumps(records, indent=2, ensure_ascii=False))
        return
    for arc in sorted_arcs:
        parts = [f"ARC {arc.arc_id}", arc.protocol_name or f"type={arc.protocol_type_raw}"]
        if arc.channel_name:
            parts.append(f"channel={arc.channel_name}")
        elif arc.channel_id is not None:
            parts.append(f"channel_id={arc.channel_id}")
        if arc.enabled is not None:
            parts.append(f"enabled={'yes' if arc.enabled else 'no'}")
        if arc.service_access_name:
            parts.append(f"service_access={arc.service_access_name}")
        for specific in arc.specific_by_name.values():
            if specific.endpoints:
                parts.append(f"{specific.name}.endpoints={specific.endpoints}")
            if specific.crypt_key:
                parts.append(f"{specific.name}.crypt_key={specific.crypt_key!r}")
        print(" | ".join(parts))


def emit_communications(snapshot: ExportCatalogSnapshot, fmt: str) -> None:
    payload = {
        "main_config": asdict(snapshot.main_config) if snapshot.main_config is not None else None,
        "communications": asdict(snapshot.communications) if snapshot.communications is not None else None,
    }
    if fmt == "json":
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    if snapshot.main_config is not None:
        main = snapshot.main_config
        print(
            "main"
            f" | name={main.name!r}"
            f" | language_id={main.language_id!r}"
            f" | code_len={main.code_len_raw}"
            f" | code_prefix={main.code_prefix}"
            f" | wpp_dedicated={main.wpp_dedicated}"
            f" | default_config={main.default_config}"
        )
    if snapshot.communications is not None:
        comm = snapshot.communications
        flags = comm.flags
        parts = [
            "communications",
            f"service_access={comm.service_access_name or comm.service_access_raw}",
            f"ytun_url={comm.ytun_url!r}",
            f"local_listen_port={comm.local_listen_port_raw}",
            f"data_channels={comm.data_channels}",
            f"sms_channels={comm.sms_channels}",
            f"voice_channels={comm.voice_channels}",
            f"wpp_lock={flags.wpp_lock}",
            f"ytun_enable={flags.ytun_enable}",
            f"ytun_persistent={flags.ytun_persistent}",
            f"comm_configured={flags.comm_configured}",
        ]
        if comm.sdc is not None:
            parts.append(f"sdc_position={comm.sdc.sdc_position_name or comm.sdc.sdc_position}")
            parts.append(f"sdc_flags={comm.sdc.flags_raw}")
        print(" | ".join(parts))


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
    lines.append(f"arcs: {len(snapshot.arcs_by_id)}")
    lines.append(f"time_limit_groups: {len(snapshot.time_limit_groups_by_id)}")

    if snapshot.main_config is not None:
        main = snapshot.main_config
        _append_heading(lines, "Main Config")
        lines.append(f"name: {main.name!r}")
        lines.append(f"language_id: {main.language_id!r}")
        lines.append(f"language_raw: {main.language_raw}")
        lines.append(f"code_len_raw: {main.code_len_raw}")
        lines.append(f"code_prefix: {main.code_prefix}")
        lines.append(f"wpp_dedicated: {main.wpp_dedicated}")
        lines.append(f"default_config: {main.default_config}")
        lines.append(f"language_unlock_code: {main.language_unlock_code!r}")

    if snapshot.communications is not None:
        comm = snapshot.communications
        flags = comm.flags
        _append_heading(lines, "Communications")
        lines.append(f"service_access: {comm.service_access_name or comm.service_access_raw}")
        lines.append(f"ytun_url: {comm.ytun_url!r}")
        lines.append(f"sms_resend_to_user: {comm.sms_resend_to_user}")
        lines.append(f"y0_hb_time_raw: {comm.y0_hb_time_raw}")
        lines.append(f"data_channels: {comm.data_channels}")
        lines.append(f"sms_channels: {comm.sms_channels}")
        lines.append(f"voice_channels: {comm.voice_channels}")
        lines.append(f"local_listen_port_raw: {comm.local_listen_port_raw}")
        lines.append(f"aes_key_ascii: {comm.aes_key_ascii!r}")
        lines.append(f"ytun_key: {comm.ytun_key!r}")
        lines.append(f"rf_key_ascii: {comm.rf_key_ascii!r}")
        lines.append(
            "flags: "
            f"wpp_lock={flags.wpp_lock}, ytun_enable={flags.ytun_enable}, "
            f"ytun_persistent={flags.ytun_persistent}, comm_configured={flags.comm_configured}, "
            f"gsm_autoconfig_disabled={flags.gsm_autoconfig_disabled}"
        )
        if comm.sdc is not None:
            lines.append(
                "sdc: "
                f"flags_raw={comm.sdc.flags_raw}, "
                f"allow_reports_alarm_voice={comm.sdc.allow_reports_alarm_voice}, "
                f"sdc_position={comm.sdc.sdc_position_name or comm.sdc.sdc_position}"
            )

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

    _append_heading(lines, "ARCs")
    for arc in sorted(snapshot.arcs_by_id.values(), key=lambda item: item.arc_id):
        extras = []
        if arc.protocol_name:
            extras.append(f"protocol={arc.protocol_name}")
        if arc.enabled is not None:
            extras.append(f"enabled={'yes' if arc.enabled else 'no'}")
        if arc.backup:
            extras.append("backup=yes")
        if arc.channel_id is not None:
            channel_label = arc.channel_name or str(arc.channel_id)
            extras.append(f"channel={channel_label}")
        if arc.report_time_raw is not None:
            extras.append(f"report_time={arc.report_time_raw}")
        if arc.retry_count_raw is not None:
            extras.append(f"retries={arc.retry_count_raw}")
        if arc.service_access_name:
            extras.append(f"service_access={arc.service_access_name}")
        if arc.ats_class_name:
            extras.append(f"ats={arc.ats_class_name}")
        if arc.section_object_ids:
            extras.append(f"section_ids={arc.section_object_ids}")
        if arc.comment:
            extras.append(f"comment={arc.comment!r}")
        for specific in arc.specific_by_name.values():
            details = []
            if specific.endpoints:
                details.append(f"endpoints={specific.endpoints}")
            if specific.crypt_key:
                details.append(f"crypt_key={specific.crypt_key!r}")
            if specific.delivery_timeout_raw is not None:
                details.append(f"delivery_timeout={specific.delivery_timeout_raw}")
            if specific.key_type_raw is not None:
                details.append(f"key_type={specific.key_type_raw}")
            if specific.proto_version_raw is not None:
                details.append(f"proto_version={specific.proto_version_raw}")
            if details:
                extras.append(f"{specific.name}({', '.join(details)})")
        suffix = f" [{' ; '.join(extras)}]" if extras else ""
        lines.append(f"{arc.arc_id:>3}: ARC{suffix}")

    _append_heading(lines, "Time-Limit Groups")
    for group in sorted(snapshot.time_limit_groups_by_id.values(), key=lambda item: item.group_display_id):
        active_days = [day.day_name for day in group.days if day.section_rules]
        active_sections = sorted({rule.section_id for day in group.days for rule in day.section_rules})
        extras = []
        if active_days:
            extras.append(f"days={','.join(active_days)}")
        if active_sections:
            extras.append(f"sections={compress_numeric_ids(active_sections)}")
        if group.comment:
            extras.append(f"comment={group.comment!r}")
        suffix = f" [{' ; '.join(extras)}]" if extras else ""
        lines.append(f"G{group.group_display_id}: time-limit{suffix}")

    _append_heading(lines, "Users")
    for user in snapshot.users:
        fields = [f"slot={user.user_id if user.user_id is not None else '?'}"]
        if user.rights:
            fields.append(f"rights={user.rights}")
        if user.enabled is not None:
            fields.append(f"enabled={'yes' if user.enabled else 'no'}")
        fields.append(f"self_code={format_allow_code_change(user)}")
        fields.append(f"log={format_log_user_actions(user)}")
        if user.flags:
            fields.append(f"flags={','.join(user.flags)}")
        if user.section_ids:
            fields.append(f"sections={format_section_access(user, snapshot)}")
        if user.pg_ids:
            fields.append(f"pgs={format_pg_access(user, snapshot)}")
        if user.time_limited_group_raw:
            fields.append(f"time_limit={format_time_limit_binding(user, snapshot)}")
        if user.code:
            fields.append(f"code={user.code}")
        cards = format_cards(user)
        if cards != "-":
            fields.append(f"cards={cards}")
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
    snapshot = extract_export_catalog(Path(args.export_cfg))
    records = snapshot.users if args.user_mode == "dedupe" else extract_users(Path(args.export_cfg), dedupe="raw")
    emit_records(records, args.format, snapshot)


def cmd_extract_catalog(args: argparse.Namespace) -> None:
    snapshot = extract_export_catalog(Path(args.export_cfg))
    emit_catalog(snapshot, args.format)


def cmd_extract_arcs(args: argparse.Namespace) -> None:
    snapshot = extract_export_catalog(Path(args.export_cfg))
    emit_arcs(snapshot, args.format)


def cmd_extract_communications(args: argparse.Namespace) -> None:
    snapshot = extract_export_catalog(Path(args.export_cfg))
    emit_communications(snapshot, args.format)


def cmd_extract_time_limits(args: argparse.Namespace) -> None:
    snapshot = extract_export_catalog(Path(args.export_cfg))
    emit_time_limits(snapshot, args.format)


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
    print_export_snapshot_summary(snapshot, device=args.device, resolver=resolve_flexi_cfg_device)
    if args.extract_users:
        catalog = extract_export_catalog(snapshot.path)
        records = snapshot.records if args.user_mode == "dedupe" else snapshot.raw_records
        emit_records(records, args.format, catalog)


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
    add_flexi_cfg_device_argument(pull_parser)
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

    arcs_parser = subparsers.add_parser(
        "extract-arcs",
        help="Extract ARC/reporting records from an EXPORT.CFG blob.",
    )
    arcs_parser.add_argument("export_cfg", help="Path to EXPORT.CFG or an equivalent 1 MiB export blob.")
    arcs_parser.add_argument("--format", choices=["summary", "json"], default="summary")
    arcs_parser.set_defaults(func=cmd_extract_arcs)

    comm_parser = subparsers.add_parser(
        "extract-communications",
        help="Extract the top-level main/communications config blocks from an EXPORT.CFG blob.",
    )
    comm_parser.add_argument("export_cfg", help="Path to EXPORT.CFG or an equivalent 1 MiB export blob.")
    comm_parser.add_argument("--format", choices=["summary", "json"], default="summary")
    comm_parser.set_defaults(func=cmd_extract_communications)

    time_limits_parser = subparsers.add_parser(
        "extract-time-limits",
        help="Extract user time-limit groups from an EXPORT.CFG blob.",
    )
    time_limits_parser.add_argument("export_cfg", help="Path to EXPORT.CFG or an equivalent 1 MiB export blob.")
    time_limits_parser.add_argument("--format", choices=["summary", "json"], default="summary")
    time_limits_parser.set_defaults(func=cmd_extract_time_limits)

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
