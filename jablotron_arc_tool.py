#!/usr/bin/env python3
"""Build and apply ARC/service-access communicator patches.

The currently verified safe write shape for unlocking ARC-managed communication
pages for a service session is a sparse top-level IMPORT.CFG payload:

    {5: {12: 0}}

Where:
- top-level key `5` matches `cfg_communications_t`
- nested field `12` matches `cfg_communications_t.service_access`
- value `0` means `ARC_ACCESS_FULL`

This utility keeps that workflow explicit instead of replaying a full stale
communications object.
"""

from __future__ import annotations

import argparse
import time
from collections import OrderedDict
from pathlib import Path

from import_cfg_tool import encode_sector
from jablotron_re_tools import (
    DEFAULT_IMPORT_PATH,
    add_flexi_cfg_device_argument,
    apply_import_sector,
    print_export_snapshot_summary,
    resolve_flexi_cfg_device,
)

COMMUNICATIONS_KEY = 5
SERVICE_ACCESS_FIELD = 12
SERVICE_ACCESS_MODES = {
    "full": 0,
    "off": 1,
    "read": 2,
}


def default_sector_output(prefix: str) -> Path:
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    return Path("/tmp") / f"{timestamp}_{prefix}_IMPORT-sector.bin"


def default_export_output(prefix: str) -> Path:
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    return Path("/tmp") / f"{timestamp}_{prefix}_EXPORT.CFG.bin"


def parse_mode(spec: str) -> int:
    lowered = spec.strip().lower()
    if lowered in SERVICE_ACCESS_MODES:
        return SERVICE_ACCESS_MODES[lowered]
    return int(spec, 0)


def build_service_access_payload(mode_raw: int) -> OrderedDict[int, OrderedDict[int, int]]:
    return OrderedDict({COMMUNICATIONS_KEY: OrderedDict({SERVICE_ACCESS_FIELD: int(mode_raw)})})


def write_sector(path: Path, *, mode_raw: int) -> None:
    payload = build_service_access_payload(mode_raw)
    encoded_sector = encode_sector(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded_sector)


def print_mode_summary(*, mode_raw: int, output: Path) -> None:
    mode_name = next((name for name, value in SERVICE_ACCESS_MODES.items() if value == mode_raw), str(mode_raw))
    print(f"mode {mode_name} ({mode_raw})")
    print(f"sector {output}")
    print("payload {5: {12: %d}}" % mode_raw)


def cmd_build_sector(args: argparse.Namespace) -> None:
    mode_raw = parse_mode(args.mode)
    output = Path(args.output)
    write_sector(output, mode_raw=mode_raw)
    print_mode_summary(mode_raw=mode_raw, output=output)


def cmd_set_live(args: argparse.Namespace) -> None:
    mode_raw = parse_mode(args.mode)
    sector = Path(args.sector) if args.sector else default_sector_output("arc-service-access")
    verify_output = Path(args.verify_output) if args.verify_output else default_export_output("arc-service-access-verify")

    write_sector(sector, mode_raw=mode_raw)
    snapshot = apply_import_sector(
        sector_path=sector,
        import_path=Path(args.import_path),
        device=args.device,
        port=args.port,
        code=args.code,
        reset=not args.no_reset,
        mount_tool=args.mount_tool,
        stage_mode=args.stage_mode,
        write_cleanup_mode=args.write_cleanup_mode,
        verbose=args.verbose,
        verify_output=verify_output,
    )

    print(f"device {resolve_flexi_cfg_device(args.device)}")
    print_mode_summary(mode_raw=mode_raw, output=sector)
    print(f"verify_output {verify_output}")

    if snapshot is not None:
        print_export_snapshot_summary(snapshot)

    print(
        "note current live EXPORT.CFG pulls do not always expose the top-level "
        "`cfg_communications_t` object directly, so final confirmation of the "
        "unlock still comes from F-Link UI behavior."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser(
        "build-sector",
        help="Build a sparse IMPORT.CFG sector that only changes cfg_communications_t.service_access.",
    )
    build.add_argument("output", help="Output file for the encoded 512-byte sector.")
    build.add_argument(
        "--mode",
        default="full",
        help="Target service_access mode: full/off/read or a raw integer (default: full).",
    )
    build.set_defaults(func=cmd_build_sector)

    live = subparsers.add_parser(
        "set-live",
        help="Build and apply the sparse service_access patch to a live panel, then pull a verification export.",
    )
    live.add_argument(
        "--mode",
        default="full",
        help="Target service_access mode: full/off/read or a raw integer (default: full).",
    )
    live.add_argument(
        "--sector",
        help="Optional path for the generated IMPORT.CFG sector. Defaults to a timestamped file in /tmp.",
    )
    live.add_argument(
        "--verify-output",
        help="Optional path for the fresh EXPORT.CFG pulled after apply. Defaults to a timestamped file in /tmp.",
    )
    live.add_argument(
        "--import-path",
        default=str(DEFAULT_IMPORT_PATH),
        help=f"Mounted IMPORT.CFG path (default: {DEFAULT_IMPORT_PATH}).",
    )
    add_flexi_cfg_device_argument(live)
    live.add_argument("--port", default="auto", help="HID port (default: auto).")
    live.add_argument("--code", default="1812", help="Authorisation code for the service session.")
    live.add_argument("--no-reset", action="store_true", help="Skip the initial auth-end packet during login.")
    live.add_argument(
        "--mount-tool",
        choices=("sudo", "udisksctl"),
        default="sudo",
        help="Mount helper to use for remount/unmount (default: sudo).",
    )
    live.add_argument(
        "--stage-mode",
        choices=("direct", "filesystem"),
        default="filesystem",
        help="How to stage IMPORT.CFG before accept (default: filesystem write plus direct LBA readback).",
    )
    live.add_argument(
        "--write-cleanup-mode",
        choices=("auto", "none", "exit-only", "login-exit"),
        default="auto",
        help="How to close the write session after apply when the inline exit does not fully reach 0x90 (default: auto).",
    )
    live.add_argument("--verbose", action="store_true", help="Print the observed HID packets.")
    live.set_defaults(func=cmd_set_live)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
