#!/usr/bin/env python3
"""Operator-facing user-management CLI built on the live RE helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable

from import_cfg_tool import (
    build_user_record,
    build_user_delete_payload,
    build_user_upsert_payload,
    describe_payload,
    encode_sector,
    write_output,
)
from jablotron_api.domain.codes import CodeFormat, resolve_code_format
from jablotron_api.domain.user_validation import (
    UserTableEntry,
    UserWriteRejected,
    entry_from_record,
    validate_user_write,
)
from jablotron_re_tools import (
    DEFAULT_IMPORT_PATH,
    ExportSnapshot,
    UserRecord,
    add_flexi_cfg_device_argument,
    apply_import_sector,
    default_export_output,
    default_sector_output,
    emit_user_records,
    extract_export_catalog,
    extract_users,
    print_export_snapshot_summary,
    pull_live_export_snapshot,
    resolve_flexi_cfg_device,
)

COMPARE_FIELDS = (
    "name",
    "phone",
    "code",
    "cards",
    "comment",
    "flags_raw",
    "access_raw",
    "section_access_mask_raw",
    "pg_access_masks_raw",
    "pg_num_if_ring_raw",
    "time_limited_group_raw",
    "parent_user_no_raw",
)

FIELD_LABELS = {
    "name": "name",
    "phone": "phone",
    "code": "code",
    "cards": "cards",
    "comment": "comment",
    "flags_raw": "flags",
    "access_raw": "access",
    "section_access_mask_raw": "sections",
    "pg_access_masks_raw": "pgs",
    "pg_num_if_ring_raw": "pg_num_if_ring",
    "time_limited_group_raw": "time_limit",
    "parent_user_no_raw": "parent_user_no",
}

def emit_records(records: list[UserRecord], fmt: str, snapshot: ExportSnapshot, *, show_names: bool) -> None:
    emit_user_records(records, fmt, snapshot, show_names=show_names)


def load_snapshot_from_file(path: Path) -> ExportSnapshot:
    raw_records = extract_users(path, dedupe="raw")
    catalog = extract_export_catalog(path)
    return ExportSnapshot(
        path=path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        raw_records=raw_records,
        records=catalog.users,
        sections_by_id=catalog.sections_by_id,
        pgs_by_id=catalog.pgs_by_id,
        time_limit_groups_by_id=catalog.time_limit_groups_by_id,
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
        cleanup_mode=getattr(args, "read_cleanup_mode", "auto"),
        verbose=getattr(args, "verbose", False),
    )


def _lookup_user(snapshot: ExportSnapshot, user_id: int) -> UserRecord | None:
    for record in snapshot.records:
        if record.user_id == user_id:
            return record
    return None


def _compare_state(record: UserRecord | None) -> dict[str, Any]:
    if record is None:
        return {field: None for field in COMPARE_FIELDS}
    return {
        "name": record.name,
        "phone": record.phone,
        "code": record.code,
        "cards": [card for card in record.cards if card],
        "comment": record.comment,
        "flags_raw": record.flags_raw,
        "access_raw": record.access_raw,
        "section_access_mask_raw": record.section_access_mask_raw,
        "pg_access_masks_raw": list(record.pg_access_masks_raw),
        "pg_num_if_ring_raw": record.pg_num_if_ring_raw,
        "time_limited_group_raw": record.time_limited_group_raw,
        "parent_user_no_raw": record.parent_user_no_raw,
    }


def _diff_states(before: dict[str, Any], after: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
    return {field: (before[field], after[field]) for field in COMPARE_FIELDS if before[field] != after[field]}


def _format_field_names(fields: Iterable[str]) -> str:
    labels = [FIELD_LABELS.get(field, field) for field in fields]
    return ", ".join(labels) if labels else "-"


def _derive_refetch_output(path: Path) -> Path:
    if path.name.endswith(".bin"):
        return path.with_name(path.name[:-4] + "_refetch.bin")
    return path.with_name(path.name + "_refetch")


def _collect_raw_record_diagnostics(snapshot: ExportSnapshot, *, user_id: int | None = None) -> dict[str, Any]:
    counts: dict[int, int] = {}
    offsets: dict[int, list[int]] = {}
    for record in snapshot.raw_records:
        if record.user_id is None:
            continue
        counts[record.user_id] = counts.get(record.user_id, 0) + 1
        offsets.setdefault(record.user_id, []).append(record.offset)

    duplicates = {uid: counts[uid] for uid in sorted(counts) if counts[uid] > 1}
    if user_id is not None:
        return {
            "user_id": user_id,
            "raw_match_count": counts.get(user_id, 0),
            "raw_match_offsets": offsets.get(user_id, []),
            "duplicate_user_ids": duplicates,
        }
    return {
        "duplicate_user_ids": duplicates,
        "duplicate_raw_record_total": sum(count - 1 for count in duplicates.values()),
    }


def print_raw_record_diagnostics(snapshot: ExportSnapshot, *, user_id: int | None = None) -> None:
    diagnostics = _collect_raw_record_diagnostics(snapshot, user_id=user_id)
    if user_id is not None:
        print(f"raw_matches_user{user_id} {diagnostics['raw_match_count']}")
        offsets = diagnostics["raw_match_offsets"]
        print(
            "raw_match_offsets "
            + (",".join(str(offset) for offset in offsets) if offsets else "-")
        )
        return

    duplicates = diagnostics["duplicate_user_ids"]
    print(f"raw_duplicate_user_ids {len(duplicates)}")
    print(f"raw_duplicate_record_overhang {diagnostics['duplicate_raw_record_total']}")
    if duplicates:
        rendered = ", ".join(f"{user_id}x{count}" for user_id, count in list(duplicates.items())[:12])
        if len(duplicates) > 12:
            rendered += ", ..."
        print(f"raw_duplicate_examples {rendered}")


def print_snapshot_summary(snapshot: ExportSnapshot, *, device: str | None = None) -> None:
    print_export_snapshot_summary(snapshot, device=device, resolver=resolve_flexi_cfg_device)


def find_user(snapshot: ExportSnapshot, user_id: int) -> UserRecord:
    record = _lookup_user(snapshot, user_id)
    if record is None:
        raise SystemExit(f"User {user_id} not found in {snapshot.path}.")
    return record


def build_upsert_sector(args: argparse.Namespace, *, current: UserRecord | None) -> tuple[Path, dict[str, object], bool]:
    name = args.name if args.name is not None else (current.name if current else None)
    phone = args.phone if args.phone is not None else (current.phone if current else None)
    pin = args.pin if args.pin is not None else (current.code if current else None)
    card1 = args.card1 if args.card1 is not None else (current.card if current and current.card else None)
    card2 = args.card2 if args.card2 is not None else (current.card2 if current and current.card2 else None)
    comment = args.comment if args.comment is not None else (current.comment if current else None)

    if name is None:
        raise SystemExit("A user name is required for add/edit upserts.")

    base_user_record = None
    if current is not None:
        base_user_record = build_user_record(
            flags_raw=current.flags_raw or 0,
            access_raw=current.access_raw or 0,
            section_access_mask=current.section_access_mask_raw or 0,
            pg_access_masks=current.pg_access_masks_raw or [0, 0, 0, 0],
            name=current.name,
            phone=current.phone,
            code=current.code,
            cards=current.cards,
            pg_num_if_ring_raw=current.pg_num_if_ring_raw or 0,
            time_limited_group_raw=current.time_limited_group_raw or 0,
            comment=current.comment,
            parent_user_no_raw=current.parent_user_no_raw if current.parent_user_no_raw is not None else -1,
        )

    payload_args = SimpleNamespace(
        base_user_record=base_user_record,
        template_file=getattr(args, "template_file", None),
        template_pcap=getattr(args, "template_pcap", None),
        template_frame=getattr(args, "template_frame", None),
        user_id=args.user_id,
        name=name,
        phone=phone,
        code=pin,
        card1=card1,
        card2=card2,
        comment=comment,
        flags_raw=args.flags_raw,
        field0_raw=args.field0_raw,
        access_raw=args.access_raw,
        permissions_raw=args.permissions_raw,
        sections_mask=args.sections_mask,
        sections=args.sections,
        pg_masks=args.pg_masks,
        pgs=args.pgs,
        pg_num_if_ring_raw=args.pg_num_if_ring_raw,
        field8_raw=args.field8_raw,
        time_limited_group_raw=args.time_limited_group_raw,
        field9_raw=args.field9_raw,
        parent_user_no_raw=args.parent_user_no_raw,
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


def _preflight_target(summary: dict[str, object]) -> dict[str, Any]:
    # Card slots keep their position: an empty card1 must not renumber card2
    # in a validation message.
    cards = [str(card) for card in summary.get("cards", [])]
    return {
        "name": str(summary.get("name", "")),
        "phone": str(summary.get("phone", "")),
        "code": str(summary.get("code", "")),
        "cards": cards,
        "comment": str(summary.get("comment", "")),
        "flags_raw": summary.get("flags_raw"),
        "access_raw": summary.get("access_raw"),
        "section_access_mask_raw": summary.get("section_access_mask"),
        "pg_access_masks_raw": list(summary.get("pg_access_masks", [])),
        "pg_num_if_ring_raw": summary.get("pg_num_if_ring_raw"),
        "time_limited_group_raw": summary.get("time_limited_group_raw"),
        "parent_user_no_raw": summary.get("parent_user_no_raw"),
    }


def _requested_fields_from_args(args: argparse.Namespace) -> set[str]:
    requested: set[str] = set()
    if getattr(args, "name", None) is not None:
        requested.add("name")
    if getattr(args, "phone", None) is not None:
        requested.add("phone")
    if getattr(args, "pin", None) is not None:
        requested.add("code")
    if getattr(args, "card1", None) is not None or getattr(args, "card2", None) is not None:
        requested.add("cards")
    if getattr(args, "comment", None) is not None:
        requested.add("comment")
    if getattr(args, "flags_raw", None) is not None or getattr(args, "field0_raw", None) is not None:
        requested.add("flags_raw")
    if getattr(args, "access_raw", None) is not None or getattr(args, "permissions_raw", None) is not None:
        requested.add("access_raw")
    if getattr(args, "sections_mask", None) is not None or getattr(args, "sections", None) is not None:
        requested.add("section_access_mask_raw")
    if getattr(args, "pg_masks", None) is not None or getattr(args, "pgs", None) is not None:
        requested.add("pg_access_masks_raw")
    if getattr(args, "pg_num_if_ring_raw", None) is not None or getattr(args, "field8_raw", None) is not None:
        requested.add("pg_num_if_ring_raw")
    if getattr(args, "time_limited_group_raw", None) is not None or getattr(args, "field9_raw", None) is not None:
        requested.add("time_limited_group_raw")
    if getattr(args, "parent_user_no_raw", None) is not None or getattr(args, "field11_raw", None) is not None:
        requested.add("parent_user_no_raw")
    return requested


def resolve_snapshot_code_format(snapshot: ExportSnapshot, *, server_auth_code: str | None) -> CodeFormat:
    """Resolve the panel's code format from the export blob behind ``snapshot``.

    ``ExportSnapshot`` carries the user records but not ``main_config``, so
    the blob is re-parsed here. Falls back to inferring the format from the
    session's own authorisation code, which the panel accepted and whose
    length therefore matches ``code_length``.
    """

    main_config = None
    try:
        main_config = extract_export_catalog(snapshot.path).main_config
    except (OSError, ValueError):
        main_config = None
    return resolve_code_format(
        catalog_code_length=main_config.code_len_raw if main_config is not None else None,
        catalog_code_prefix=main_config.code_prefix if main_config is not None else None,
        server_auth_code=server_auth_code,
    )


def validate_preflight(
    *,
    snapshot: ExportSnapshot,
    user_id: int,
    current: UserRecord | None,
    target: dict[str, Any],
    code_format: CodeFormat,
) -> None:
    """Run the shared user-table rules over a freshly read snapshot.

    The rules themselves live in ``jablotron_api.domain.user_validation`` so
    that this CLI and the HTTP write path enforce one implementation.
    Failures raise ``UserWriteRejected``; ``main()`` turns that into the
    CLI's non-zero exit.
    """

    warnings = validate_user_write(
        existing=[entry_from_record(record) for record in snapshot.records],
        user_id=user_id,
        current=entry_from_record(current) if current is not None else None,
        target=UserTableEntry(
            user_id=user_id,
            code=str(target.get("code") or ""),
            cards=tuple(str(card) for card in target.get("cards") or ()),
            time_limited_group_raw=target.get("time_limited_group_raw"),
            name=str(target.get("name") or ""),
            comment=str(target.get("comment") or ""),
        ),
        code_format=code_format,
    )
    if code_format.source != "panel" and code_format.code_length is not None:
        print(
            f"warning: preflight code length {code_format.code_length} was {code_format.source}, "
            "not read from the panel's main_config"
        )
    for message in warnings:
        print(f"warning: preflight {message}")


def verify_authoritatively(
    args: argparse.Namespace,
    *,
    verify_output: Path,
) -> ExportSnapshot:
    refetch_output = _derive_refetch_output(verify_output)
    print("authoritative_refetch", refetch_output)
    return pull_live_export_snapshot(
        output=refetch_output,
        device=args.device,
        port=args.port,
        code=args.auth_code,
        reset=not args.no_reset,
        cleanup_mode=getattr(args, "read_cleanup_mode", "auto"),
        verbose=args.verbose,
    )


def print_requested_field_summary(
    *,
    before: UserRecord,
    inline_after: UserRecord | None,
    fresh_after: UserRecord | None,
    requested_fields: set[str],
) -> None:
    before_state = _compare_state(before)
    inline_state = _compare_state(inline_after)
    fresh_state = _compare_state(fresh_after)
    inline_changes = set(_diff_states(before_state, inline_state))
    fresh_changes = set(_diff_states(before_state, fresh_state))
    requested_changed = sorted(field for field in requested_fields if field in fresh_changes)
    requested_unchanged = sorted(field for field in requested_fields if field not in fresh_changes)
    unexpected_changes = sorted(field for field in fresh_changes if field not in requested_fields)
    preserved_unrequested = sorted(field for field in COMPARE_FIELDS if field not in requested_fields and field not in fresh_changes)

    print(f"requested_fields {_format_field_names(sorted(requested_fields))}")
    print(f"requested_changed {_format_field_names(requested_changed)}")
    print(f"requested_unchanged {_format_field_names(requested_unchanged)}")
    print(f"preserved_unrequested {_format_field_names(preserved_unrequested)}")
    print(f"unexpected_changes {_format_field_names(unexpected_changes)}")
    if inline_state != fresh_state:
        inline_vs_fresh = sorted(_diff_states(inline_state, fresh_state))
        print(f"warning: inline verify differed from authoritative refetch in {_format_field_names(inline_vs_fresh)}")


def emit_verify_result(snapshot: ExportSnapshot, *, user_id: int | None, fmt: str) -> None:
    records = snapshot.records
    if user_id is not None:
        records = [record for record in records if record.user_id == user_id]
    emit_records(records, fmt, snapshot, show_names=False)


def maybe_cleanup(path: Path, *, cleanup: bool) -> None:
    if cleanup:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def add_verbose_argument(parser: argparse.ArgumentParser) -> None:
    if "--verbose" not in parser._option_string_actions:
        parser.add_argument("--verbose", action="store_true", help="Print observed HID packets for debugging.")


def add_live_read_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--export-cfg", help="Read users from an existing EXPORT.CFG blob instead of pulling live.")
    parser.add_argument(
        "--output",
        help="When pulling live, write the export blob here. Defaults to a timestamped file in /tmp.",
    )
    add_live_session_arguments(parser)
    add_verbose_argument(parser)
    parser.add_argument("--no-trigger", action="store_true", help="Skip the HID export trigger before the block read.")
    parser.add_argument(
        "--show-access-names",
        action="store_true",
        help="Expand section and PG columns from compact IDs/ranges to ID:name labels.",
    )


def add_live_session_arguments(parser: argparse.ArgumentParser) -> None:
    add_flexi_cfg_device_argument(parser)
    parser.add_argument("--port", default="auto", help="HID port for live pulls (default: auto).")
    parser.add_argument("--auth-code", default="1812", help="Authorisation code for live sessions.")
    parser.add_argument("--no-reset", action="store_true", help="Skip the initial auth-end reset packet.")
    parser.add_argument(
        "--read-cleanup-mode",
        choices=("auto", "none", "exit-only", "login-exit"),
        default="auto",
        help="How to close the post-read HID session after a live trigger (default: auto).",
    )


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
    parser.add_argument(
        "--stage-mode",
        choices=("direct", "filesystem"),
        default="filesystem",
        help="How to stage IMPORT.CFG before accept (default: filesystem write plus direct LBA readback).",
    )
    parser.add_argument(
        "--write-cleanup-mode",
        choices=("auto", "none", "exit-only", "login-exit"),
        default="auto",
        help="How to close the write session after apply when the inline exit does not fully reach 0x90 (default: auto).",
    )
    parser.add_argument(
        "--reload-before-stage",
        action="store_true",
        help="After entering setup mode, run the configuration reload F-Link runs before its first write, then stage.",
    )
    parser.add_argument("--verify-output", help="If set, verify against this export path. Defaults to /tmp.")
    parser.add_argument("--no-apply", action="store_true", help="Only build the sector and do not touch the panel.")
    add_verbose_argument(parser)


def add_upsert_field_arguments(parser: argparse.ArgumentParser, *, require_name: bool) -> None:
    parser.add_argument("--name", required=require_name, help="User name.")
    parser.add_argument("--phone", help="Phone number field.")
    parser.add_argument("--pin", help="PIN/code field without the user prefix.")
    parser.add_argument("--card1", help="Primary access-card decimal string.")
    parser.add_argument("--card2", help="Secondary access-card decimal string.")
    parser.add_argument("--comment", help="Comment field.")
    parser.add_argument("--flags-raw", type=int, help="Raw cfg_user_t.flags value.")
    parser.add_argument("--field0-raw", type=int, help="Raw field 0 value.")
    parser.add_argument("--access-raw", type=int, help="Raw cfg_user_t.access value.")
    parser.add_argument("--permissions-raw", type=int, help="Raw field 1 value.")
    parser.add_argument("--sections-mask", type=int, help="Raw cfg_user_t.section_access bitmask.")
    parser.add_argument("--sections", help="Comma-separated 1-based section numbers to encode into field 2.")
    parser.add_argument("--pg-masks", help="Comma-separated raw PG masks for field 3 (exactly four integers).")
    parser.add_argument("--pgs", help="Comma-separated 1-based PG numbers to encode into the four 32-bit masks.")
    parser.add_argument("--pg-num-if-ring-raw", type=int, help="Raw cfg_user_t.pg_num_if_ring value.")
    parser.add_argument("--field8-raw", type=int, help="Raw field 8 value.")
    parser.add_argument("--time-limited-group-raw", type=int, help="Raw cfg_user_t.time_limited_group value.")
    parser.add_argument("--field9-raw", type=int, help="Raw field 9 value.")
    parser.add_argument("--parent-user-no-raw", type=int, help="Raw cfg_user_t.parent_user_no value.")
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
    print_raw_record_diagnostics(snapshot)
    emit_records(
        snapshot.records if args.user_mode == "dedupe" else snapshot.raw_records,
        args.format,
        snapshot,
        show_names=args.show_access_names,
    )


def cmd_get(args: argparse.Namespace) -> None:
    snapshot = load_snapshot(args, prefix=f"user-tool-get{args.user_id}")
    print_snapshot_summary(snapshot, device=None if args.export_cfg else args.device)
    print_raw_record_diagnostics(snapshot, user_id=args.user_id)
    records = snapshot.records if args.user_mode == "dedupe" else snapshot.raw_records
    records = [record for record in records if record.user_id == args.user_id]
    if not records:
        raise SystemExit(f"User {args.user_id} not found.")
    emit_records(records, args.format, snapshot, show_names=args.show_access_names)


def cmd_add(args: argparse.Namespace) -> None:
    sector_path, summary, cleanup_sector = build_upsert_sector(args, current=None)
    try:
        print(f"sector {sector_path}")
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        if not getattr(args, "no_preflight_validation", False):
            snapshot_before = load_snapshot(args, prefix=f"pre-add-user{args.user_id}")
            if _lookup_user(snapshot_before, args.user_id) is not None:
                raise SystemExit(f"User {args.user_id} already exists in {snapshot_before.path}.")
            validate_preflight(
                snapshot=snapshot_before,
                user_id=args.user_id,
                current=None,
                target=_preflight_target(summary),
                code_format=resolve_snapshot_code_format(
                    snapshot_before, server_auth_code=args.auth_code
                ),
            )
        if args.no_apply:
            return

        verify_output = Path(args.verify_output) if args.verify_output else default_export_output(f"post-add-user{args.user_id}")
        inline_snapshot = apply_import_sector(
            sector_path=sector_path,
            import_path=Path(args.import_path),
            device=args.device,
            port=args.port,
            code=args.auth_code,
            reset=not args.no_reset,
            mount_tool=args.mount_tool,
            stage_mode=args.stage_mode,
            write_cleanup_mode=args.write_cleanup_mode,
            verbose=args.verbose,
            verify_output=verify_output,
            reload_before_stage=args.reload_before_stage,
        )
        if inline_snapshot is None:
            return
        print("inline_verify")
        print_snapshot_summary(inline_snapshot, device=args.device)
        fresh_snapshot = verify_authoritatively(args, verify_output=verify_output)
        print("authoritative_verify")
        print_snapshot_summary(fresh_snapshot, device=args.device)
        emit_verify_result(fresh_snapshot, user_id=args.user_id, fmt=args.format)
    finally:
        maybe_cleanup(sector_path, cleanup=cleanup_sector)


def cmd_edit(args: argparse.Namespace) -> None:
    snapshot_before = load_snapshot(args, prefix=f"pre-edit-user{args.user_id}")
    current = find_user(snapshot_before, args.user_id)
    requested_fields = _requested_fields_from_args(args)
    sector_path, summary, cleanup_sector = build_upsert_sector(args, current=current)
    try:
        print(f"sector {sector_path}")
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        if not getattr(args, "no_preflight_validation", False):
            validate_preflight(
                snapshot=snapshot_before,
                user_id=args.user_id,
                current=current,
                target=_preflight_target(summary),
                code_format=resolve_snapshot_code_format(
                    snapshot_before, server_auth_code=args.auth_code
                ),
            )
        if args.no_apply:
            return

        verify_output = Path(args.verify_output) if args.verify_output else default_export_output(f"post-edit-user{args.user_id}")
        inline_snapshot = apply_import_sector(
            sector_path=sector_path,
            import_path=Path(args.import_path),
            device=args.device,
            port=args.port,
            code=args.auth_code,
            reset=not args.no_reset,
            mount_tool=args.mount_tool,
            stage_mode=args.stage_mode,
            write_cleanup_mode=args.write_cleanup_mode,
            verbose=args.verbose,
            verify_output=verify_output,
            reload_before_stage=args.reload_before_stage,
        )
        if inline_snapshot is None:
            return
        print("inline_verify")
        print_snapshot_summary(inline_snapshot, device=args.device)
        fresh_snapshot = verify_authoritatively(args, verify_output=verify_output)
        print("authoritative_verify")
        print_snapshot_summary(fresh_snapshot, device=args.device)
        print_requested_field_summary(
            before=current,
            inline_after=_lookup_user(inline_snapshot, args.user_id),
            fresh_after=_lookup_user(fresh_snapshot, args.user_id),
            requested_fields=requested_fields,
        )
        emit_verify_result(fresh_snapshot, user_id=args.user_id, fmt=args.format)
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
        inline_snapshot = apply_import_sector(
            sector_path=sector_path,
            import_path=Path(args.import_path),
            device=args.device,
            port=args.port,
            code=args.auth_code,
            reset=not args.no_reset,
            mount_tool=args.mount_tool,
            stage_mode=args.stage_mode,
            write_cleanup_mode=args.write_cleanup_mode,
            verbose=args.verbose,
            verify_output=verify_output,
            reload_before_stage=args.reload_before_stage,
        )
        if inline_snapshot is None:
            return
        print("inline_verify")
        print_snapshot_summary(inline_snapshot, device=args.device)
        fresh_snapshot = verify_authoritatively(args, verify_output=verify_output)
        print("authoritative_verify")
        print_snapshot_summary(fresh_snapshot, device=args.device)
        records = [record for record in fresh_snapshot.records if record.user_id == args.user_id]
        if records:
            emit_records(records, args.format, fresh_snapshot, show_names=False)
        else:
            print(f"user {args.user_id} absent after delete")
    finally:
        maybe_cleanup(sector_path, cleanup=cleanup_sector)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    pull_export = subparsers.add_parser("pull-export", help="Trigger a live export and save the blob.")
    pull_export.add_argument("output", nargs="?", help="Output path. Defaults to a timestamped file in /tmp.")
    add_flexi_cfg_device_argument(pull_export)
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
    add_parser.add_argument(
        "--no-preflight-validation",
        action="store_true",
        help="Skip duplicate/consistency checks before building and applying the upsert.",
    )
    add_parser.add_argument("--format", choices=["table", "tsv", "json"], default="table")
    add_parser.set_defaults(func=cmd_add)

    edit_parser = subparsers.add_parser("edit", help="Edit a user and apply it live by default.")
    edit_parser.add_argument("user_id", type=int, help="Target user ID.")
    add_upsert_field_arguments(edit_parser, require_name=False)
    add_live_read_arguments(edit_parser)
    add_live_apply_arguments(edit_parser)
    edit_parser.add_argument(
        "--no-preflight-validation",
        action="store_true",
        help="Skip duplicate/consistency checks before building and applying the upsert.",
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
    try:
        args.func(args)
    except UserWriteRejected as rejection:
        # The CLI boundary: the rules raise a typed refusal so the HTTP
        # server can map it to a 4xx; here it becomes the usual exit code.
        raise SystemExit(rejection.cli_message()) from rejection


if __name__ == "__main__":
    main()
