#!/usr/bin/env python3
"""Probe Jablotron USB metadata that is readable without authentication."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import Dict, List

from export_cfg_tool import extract_users, read_export_direct
from jablotron_re_tools import add_flexi_cfg_device_argument, resolve_flexi_cfg_device
from jablotron_usb_debug import (
    JablotronUSBClient,
    JablotronUSBStreamError,
    Jablotron,
    SystemInfo,
    describe_packet,
    ensure_serial_port,
    perform_trigger_export,
)


def probe_noauth(*, port: str, response_timeout: float, minimal: bool) -> dict:
    serial_port = ensure_serial_port(port)
    client = JablotronUSBClient(serial_port)
    try:
        perform_trigger_export(
            client,
            include_info_query=not minimal,
            include_fl_var_query=not minimal,
        )

        system_info: Dict[str, str] = {}
        sections_packets: List[str] = []
        pg_packets: List[str] = []
        other_packets: List[str] = []

        for packet in client.read_packets(timeout=response_timeout):
            if packet[:1] == b"\x40" and len(packet) >= 3:
                try:
                    info_type = SystemInfo(Jablotron.bytes_to_int(packet[2:3])).name.lower()
                except ValueError:
                    info_type = f"unknown_0x{packet[2]:02x}"
                try:
                    decoded = Jablotron.decode_system_info_packet(packet)
                except UnicodeDecodeError:
                    decoded = None
                system_info[info_type] = decoded if decoded is not None else packet.hex()
                continue

            if Jablotron._is_sections_states_packet(packet):
                sections_packets.append(Jablotron.format_packet_to_string(packet))
                continue

            if Jablotron._is_pg_outputs_states_packet(packet):
                pg_packets.append(Jablotron.format_packet_to_string(packet))
                continue

            other_packets.append(describe_packet(packet, decode=True))

        return {
            "port": serial_port,
            "minimal": minimal,
            "system_info": system_info,
            "sections_packets": sections_packets,
            "pg_packets": pg_packets,
            "other_packets": other_packets,
        }
    finally:
        client.close()


def inspect_export(*, device: str, output: Path, start_lba: int, sectors: int) -> dict:
    resolved_device = resolve_flexi_cfg_device(device)
    read_export_direct(device=resolved_device, output=output, start_lba=start_lba, sectors=sectors)
    blob = output.read_bytes()
    sha256 = hashlib.sha256(blob).hexdigest()
    all_zero = not any(blob)
    payload = {
        "path": str(output),
        "device": resolved_device,
        "sha256": sha256,
        "all_zero": all_zero,
        "size": len(blob),
    }
    if not all_zero:
        payload["users"] = [record.__dict__ for record in extract_users(output)]
    else:
        payload["users"] = []
    return payload


def print_text(result: dict) -> None:
    print(f"port: {result['port']}")
    print(f"trigger: {'minimal' if result['minimal'] else 'full'}")
    print("system_info:")
    for key, value in sorted(result["system_info"].items()):
        print(f"  {key}: {value}")
    print("sections_packets:")
    if result["sections_packets"]:
        for packet in result["sections_packets"]:
            print(f"  {packet}")
    else:
        print("  <none>")
    print("pg_packets:")
    if result["pg_packets"]:
        for packet in result["pg_packets"]:
            print(f"  {packet}")
    else:
        print("  <none>")
    print("other_packets:")
    if result["other_packets"]:
        for packet in result["other_packets"]:
            print(f"  {packet}")
    else:
        print("  <none>")
    if "export_check" in result:
        export_check = result["export_check"]
        print("export_check:")
        print(f"  path: {export_check['path']}")
        print(f"  sha256: {export_check['sha256']}")
        print(f"  all_zero: {export_check['all_zero']}")
        print(f"  users: {len(export_check['users'])}")


def cmd_probe(args: argparse.Namespace) -> None:
    result = probe_noauth(port=args.port, response_timeout=args.response_timeout, minimal=args.minimal)
    if args.read_export:
        if args.delay > 0:
            time.sleep(args.delay)
        result["export_check"] = inspect_export(
            device=args.device,
            output=Path(args.export_output),
            start_lba=args.start_lba,
            sectors=args.sectors,
        )

    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
    print_text(result)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    probe_parser = subparsers.add_parser("probe", help="Run the unauthenticated trigger probe.")
    probe_parser.add_argument("--port", default="auto", help="HID port to use (default: auto).")
    probe_parser.add_argument(
        "--response-timeout",
        type=float,
        default=3.0,
        help="Seconds to read HID responses after the unauthenticated trigger.",
    )
    probe_parser.add_argument(
        "--minimal",
        action="store_true",
        help="Use only the two final export-trigger reports instead of the full pre-auth sequence.",
    )
    probe_parser.add_argument(
        "--read-export",
        action="store_true",
        help="After the HID probe, read EXPORT.CFG directly from the block device and report whether it is populated.",
    )
    add_flexi_cfg_device_argument(probe_parser)
    probe_parser.add_argument(
        "--export-output",
        default="research/exports/noauth_probe_EXPORT.CFG.bin",
        help="Path where the direct EXPORT.CFG read should be saved if --read-export is used.",
    )
    probe_parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Optional delay in seconds between the HID probe and the direct block read.",
    )
    probe_parser.add_argument("--start-lba", type=int, default=35, help="Starting LBA for EXPORT.CFG.")
    probe_parser.add_argument("--sectors", type=int, default=2048, help="Number of sectors to read for EXPORT.CFG.")
    probe_parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format.")
    probe_parser.set_defaults(func=cmd_probe)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except JablotronUSBStreamError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
