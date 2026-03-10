#!/usr/bin/env python3
"""Apply a staged IMPORT.CFG command to a live Jablotron panel.

This script follows the write path that was validated against the live panel:

1. enter setup mode from an authenticated HID session
2. stage sector 0 of IMPORT.CFG through the mounted FAT filesystem
3. unmount FLEXI_CFG to flush the filesystem metadata to the device
4. perform the minimal HID accept/import sequence
5. optionally verify persistence with a fresh EXPORT.CFG pull
6. remount FLEXI_CFG

It is designed to be used with sectors built by import_cfg_tool.py.

Operational note:
- on desktop Linux systems `udisksctl` can trigger an interactive polkit
  prompt and appear to hang in terminal automation
- this helper therefore supports `sudo mount` / `sudo umount` workflows
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import time
from pathlib import Path
from typing import Iterable

from export_cfg_tool import extract_users, read_export_direct, trigger_live_export
from jablotron_usb_debug import (
    JablotronUSBClient,
    describe_packet,
    ensure_serial_port,
    perform_login,
    perform_send_raw_report,
)

SECTOR_SIZE = 512

REPORT_520102 = "520102" + "00" * 61
REPORT_520124 = "520124" + "00" * 61
REPORT_52010C = "52010c" + "00" * 61
REPORT_800114 = "800114" + "00" * 61
REPORT_80010F = "80010f" + "00" * 61


def run_command(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def stage_import(import_path: Path, sector_path: Path) -> None:
    sector = sector_path.read_bytes()[:SECTOR_SIZE]
    write_error: OSError | None = None

    with import_path.open("r+b", buffering=0) as handle:
        try:
            handle.seek(0)
            handle.write(sector)
            handle.flush()
            os.fsync(handle.fileno())
        except OSError as exc:
            write_error = exc

    current = import_path.read_bytes()[:SECTOR_SIZE]
    if current != sector:
        if write_error is not None:
            raise SystemExit(f"IMPORT.CFG staging failed and did not verify: {write_error}") from write_error
        raise SystemExit("IMPORT.CFG staging failed verification.")

    if write_error is not None:
        print(f"warning: write raised {write_error}; continuing because staged bytes verified exactly")


def mount_device(device: str, mountpoint: Path, *, mount_tool: str) -> None:
    if mount_tool == "sudo":
        mountpoint.mkdir(parents=True, exist_ok=True)
        result = run_command(["sudo", "-n", "mount", device, str(mountpoint)], check=False)
        stderr = result.stderr.lower()
        if result.returncode != 0 and "already mounted" not in stderr:
            raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"mount failed for {device}")
    elif mount_tool == "udisksctl":
        result = run_command(["udisksctl", "mount", "-b", device], check=False)
        if result.returncode != 0 and "already mounted" not in result.stderr.lower():
            raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"mount failed for {device}")
    else:
        raise SystemExit(f"Unsupported mount tool: {mount_tool}")

    message = result.stdout.strip() or result.stderr.strip()
    if message:
        print(message)


def unmount_device(device: str, *, mount_tool: str) -> None:
    if mount_tool == "sudo":
        result = run_command(["sudo", "-n", "umount", device], check=False)
        stderr = result.stderr.lower()
        if result.returncode != 0 and "not mounted" not in stderr:
            raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"unmount failed for {device}")
    elif mount_tool == "udisksctl":
        result = run_command(["udisksctl", "unmount", "-b", device], check=False)
        if result.returncode != 0 and "not mounted" not in result.stderr.lower():
            raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"unmount failed for {device}")
    else:
        raise SystemExit(f"Unsupported mount tool: {mount_tool}")

    message = result.stdout.strip() or result.stderr.strip()
    if message:
        print(message)


def drain_packets(client: JablotronUSBClient, *, timeout: float, prefix: str, verbose: bool) -> list[bytes]:
    packets = list(client.read_packets(timeout=timeout))
    if verbose:
        for packet in packets:
            print(prefix, describe_packet(packet, decode=True))
    return packets


def send_report(client: JablotronUSBClient, report_hex: str, *, verbose: bool) -> None:
    perform_send_raw_report(client, report_hex)
    if verbose:
        print("tx", report_hex[:6])


def enter_setup_mode(client: JablotronUSBClient, *, verbose: bool, initial_packets: list[bytes] | None = None) -> None:
    service_rights = False
    service_rights_at: float | None = None
    nudged_0f = False
    saw_1a0a = False
    sent_post_1a0a_520102 = False
    entered_setup = False
    deadline = time.time() + 15.0
    last_keepalive = 0.0

    while time.time() < deadline and not entered_setup:
        if initial_packets is not None:
            packets = initial_packets
            initial_packets = None
        else:
            packets = drain_packets(client, timeout=0.5, prefix="setup", verbose=verbose)
        now = time.time()

        for packet in packets:
            if packet.startswith(bytes.fromhex("801a0c")) and not service_rights:
                service_rights = True
                service_rights_at = time.time()
            elif packet.startswith(bytes.fromhex("80021a0a")):
                saw_1a0a = True
                send_report(client, REPORT_80010F, verbose=verbose)
                last_keepalive = time.time()
            elif packet.startswith(bytes.fromhex("800112")):
                entered_setup = True

        if service_rights and not saw_1a0a and not nudged_0f and service_rights_at and now - service_rights_at >= 0.35:
            send_report(client, REPORT_80010F, verbose=verbose)
            nudged_0f = True
        elif saw_1a0a and not sent_post_1a0a_520102 and now - last_keepalive >= 0.7:
            send_report(client, REPORT_520102, verbose=verbose)
            sent_post_1a0a_520102 = True
            last_keepalive = now
        elif sent_post_1a0a_520102 and now - last_keepalive >= 0.9:
            send_report(client, REPORT_520102, verbose=verbose)
            last_keepalive = now

    if verbose:
        print(
            "setup_state",
            {
                "service_rights": service_rights,
                "nudged_0f": nudged_0f,
                "saw_1a0a": saw_1a0a,
                "sent_post_1a0a_520102": sent_post_1a0a_520102,
                "entered_setup": entered_setup,
            },
        )

    if not entered_setup:
        raise SystemExit("Did not enter setup mode.")


def perform_import_accept_sequence(client: JablotronUSBClient, *, verbose: bool) -> None:
    send_report(client, REPORT_520102, verbose=verbose)
    time.sleep(0.2)
    drain_packets(client, timeout=1.0, prefix="p1", verbose=verbose)

    send_report(client, REPORT_520124, verbose=verbose)
    time.sleep(0.2)
    drain_packets(client, timeout=1.2, prefix="p2", verbose=verbose)

    send_report(client, REPORT_520102, verbose=verbose)
    time.sleep(0.05)
    send_report(client, REPORT_52010C, verbose=verbose)

    sent_800114 = False
    sent_80010f = False
    sent_post_520102 = False
    deadline = time.time() + 12.0
    while time.time() < deadline:
        packets = drain_packets(client, timeout=0.5, prefix="p3", verbose=verbose)
        if not packets:
            time.sleep(0.05)
            continue

        for packet in packets:
            if packet.startswith(bytes.fromhex("800117")) and not sent_800114:
                send_report(client, REPORT_800114, verbose=verbose)
                sent_800114 = True
            elif packet.startswith(bytes.fromhex("80021a0a")) and not sent_80010f:
                send_report(client, REPORT_80010F, verbose=verbose)
                sent_80010f = True
                time.sleep(0.8)
                send_report(client, REPORT_520102, verbose=verbose)
                sent_post_520102 = True

    if verbose:
        print(
            "accept_flags",
            {
                "sent_800114": sent_800114,
                "sent_80010f": sent_80010f,
                "sent_post_520102": sent_post_520102,
            },
        )


def verify_export(
    *,
    output: Path,
    device: str,
    port: str,
    code: str,
    reset: bool,
    extract_user_ids: Iterable[int],
) -> None:
    trigger_live_export(port=port, code=code, reset=reset)
    read_export_direct(device=device, output=output)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"wrote {output}")
    print(f"sha256 {digest}")

    records = extract_users(output)
    if extract_user_ids:
        wanted = set(extract_user_ids)
        records = [record for record in records if record.user_id in wanted]

    for record in records:
        print(
            "\t".join(
                [
                    "" if record.user_id is None else str(record.user_id),
                    record.raw_id_bytes,
                    record.name,
                    record.code,
                    record.phone,
                    record.card,
                    record.comment,
                    str(record.offset),
                ]
            )
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sector", help="Encoded 512-byte IMPORT.CFG sector to stage and apply.")
    parser.add_argument(
        "--import-path",
        default="/mnt/flexi_cfg/IMPORT.CFG",
        help="Mounted IMPORT.CFG path (default: /mnt/flexi_cfg/IMPORT.CFG).",
    )
    parser.add_argument("--device", default="/dev/sdb1", help="FLEXI_CFG block device (default: /dev/sdb1).")
    parser.add_argument("--port", default="auto", help="HID port (default: auto).")
    parser.add_argument("--code", default="1812", help="Authorisation code for the service session.")
    parser.add_argument("--no-reset", action="store_true", help="Skip the initial auth-end packet during login.")
    parser.add_argument(
        "--mount-tool",
        choices=("sudo", "udisksctl"),
        default="sudo",
        help="Mount helper to use for remount/unmount (default: sudo).",
    )
    parser.add_argument("--verify-output", help="If set, pull a fresh EXPORT.CFG into this path after apply.")
    parser.add_argument(
        "--verify-user-id",
        type=int,
        action="append",
        default=[],
        help="User ID to print from the verification export. Repeatable.",
    )
    parser.add_argument("--verbose", action="store_true", help="Print the observed HID packets.")
    return parser


def main() -> None:
    args = build_parser().parse_args()

    import_path = Path(args.import_path)
    sector_path = Path(args.sector)
    mountpoint = import_path.parent
    mount_device(args.device, mountpoint, mount_tool=args.mount_tool)
    unmounted = False
    try:
        port = ensure_serial_port(args.port)
        client = JablotronUSBClient(port)
        try:
            perform_login(client, args.code, reset=not args.no_reset)
            time.sleep(0.7)
            pre_packets = drain_packets(client, timeout=1.0, prefix="pre", verbose=args.verbose)
            enter_setup_mode(client, verbose=args.verbose, initial_packets=pre_packets)
            stage_import(import_path, sector_path)
            print(f"staged {sector_path} into {import_path}")
            unmount_device(args.device, mount_tool=args.mount_tool)
            unmounted = True
            perform_import_accept_sequence(client, verbose=args.verbose)
        finally:
            client.close()

        if args.verify_output:
            verify_export(
                output=Path(args.verify_output),
                device=args.device,
                port=args.port,
                code=args.code,
                reset=not args.no_reset,
                extract_user_ids=args.verify_user_id,
            )
    finally:
        if unmounted:
            mount_device(args.device, mountpoint, mount_tool=args.mount_tool)


if __name__ == "__main__":
    main()
