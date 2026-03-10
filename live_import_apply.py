#!/usr/bin/env python3
"""Apply a staged IMPORT.CFG command to a live Jablotron panel.

This keeps the low-level reverse-engineering workflow available while routing
the transport logic through the shared live-panel helper module.

Operational note:
- on desktop Linux systems `udisksctl` can trigger an interactive polkit
  prompt and appear to hang in terminal automation
- this helper therefore supports `sudo mount` / `sudo umount` workflows
"""

from __future__ import annotations

import argparse
from pathlib import Path

from jablotron_re_tools import (
    DEFAULT_IMPORT_PATH,
    apply_import_sector,
    resolve_flexi_cfg_device,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sector", help="Encoded 512-byte IMPORT.CFG sector to stage and apply.")
    parser.add_argument(
        "--import-path",
        default=str(DEFAULT_IMPORT_PATH),
        help=f"Mounted IMPORT.CFG path (default: {DEFAULT_IMPORT_PATH}).",
    )
    parser.add_argument(
        "--device",
        default="auto",
        help="FLEXI_CFG block device or 'auto' to resolve /dev/disk/by-label/FLEXI_CFG.",
    )
    parser.add_argument("--port", default="auto", help="HID port (default: auto).")
    parser.add_argument("--code", default="1812", help="Authorisation code for the service session.")
    parser.add_argument("--no-reset", action="store_true", help="Skip the initial auth-end packet during login.")
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
    parser.add_argument("--verify-output", help="If set, pull a fresh EXPORT.CFG into this path after apply.")
    parser.add_argument(
        "--verify-user-id",
        type=int,
        action="append",
        default=[],
        help="User ID to print from the verification export. Repeatable.",
    )
    parser.add_argument(
        "--verify-mode",
        choices=("dedupe", "raw"),
        default="dedupe",
        help="How to print verification users (default: dedupe).",
    )
    parser.add_argument("--verbose", action="store_true", help="Print the observed HID packets.")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    snapshot = apply_import_sector(
        sector_path=Path(args.sector),
        import_path=Path(args.import_path),
        device=args.device,
        port=args.port,
        code=args.code,
        reset=not args.no_reset,
        mount_tool=args.mount_tool,
        stage_mode=args.stage_mode,
        write_cleanup_mode=args.write_cleanup_mode,
        verbose=args.verbose,
        verify_output=Path(args.verify_output) if args.verify_output else None,
    )

    print(f"device {resolve_flexi_cfg_device(args.device)}")
    print(f"staged {Path(args.sector)} via {args.stage_mode}")

    if snapshot is None:
        return

    print(f"wrote {snapshot.path}")
    print(f"sha256 {snapshot.sha256}")
    print(f"users_raw {len(snapshot.raw_records)}")
    print(f"users_deduped {len(snapshot.records)}")

    records = snapshot.records if args.verify_mode == "dedupe" else snapshot.raw_records
    if args.verify_user_id:
        wanted = set(args.verify_user_id)
        records = [record for record in records if record.user_id in wanted]

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


if __name__ == "__main__":
    main()
