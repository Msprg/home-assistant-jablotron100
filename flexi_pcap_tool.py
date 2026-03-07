#!/usr/bin/env python3
"""Inspect JA-100 Flexi USB mass-storage traffic in USBPcap captures.

The Jablotron panel exposes two USB interfaces:
- HID for live state/control traffic
- Mass storage ("Flexi") for config/log volumes

This helper focuses on the storage side. It uses `tshark` to:
- list SCSI Read(10)/Write(10) commands with LBAs
- dump raw bytes for a specific USB frame
- diff two frame payloads to spot config changes

Typical examples:

    python3 flexi_pcap_tool.py list-scsi capture.pcapng
    python3 flexi_pcap_tool.py dump-frame capture.pcapng 1013
    python3 flexi_pcap_tool.py diff-frames capture.pcapng 1013 1094
"""

from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

USBPCAP_HEADER_LEN = 27
SECTOR_SIZE = 512
EXPORT_START_LBA = 35
IMPORT_START_LBA = 2083
FILE_SECTORS = 2048  # 1 MiB


@dataclass(frozen=True)
class ScsiCommand:
    frame: int
    time_relative: float
    opcode: int
    lba: int
    sectors: int

    @property
    def direction(self) -> str:
        return "READ" if self.opcode == 0x28 else "WRITE"

    @property
    def byte_length(self) -> int:
        return self.sectors * SECTOR_SIZE


def run_tshark(args: Sequence[str]) -> str:
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or f"tshark failed with exit code {proc.returncode}")
    return proc.stdout


def parse_scsi_commands(pcap: Path) -> List[ScsiCommand]:
    output = run_tshark(
        [
            "tshark",
            "-r",
            str(pcap),
            "-Y",
            "usb.endpoint_address==0x02 && (scsi_sbc.opcode==0x28 || scsi_sbc.opcode==0x2a)",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "frame.time_relative",
            "-e",
            "scsi_sbc.opcode",
            "-e",
            "scsi_sbc.rdwr10.lba",
            "-e",
            "scsi_sbc.rdwr10.xferlen",
        ]
    )

    commands: List[ScsiCommand] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 5 or not parts[3] or not parts[4]:
            continue
        commands.append(
            ScsiCommand(
                frame=int(parts[0]),
                time_relative=float(parts[1]),
                opcode=int(parts[2], 16),
                lba=int(parts[3]),
                sectors=int(parts[4]),
            )
        )
    return commands


def describe_lba(lba: int) -> str:
    if EXPORT_START_LBA <= lba < EXPORT_START_LBA + FILE_SECTORS:
        return f"EXPORT.CFG+0x{(lba - EXPORT_START_LBA) * SECTOR_SIZE:05x}"
    if IMPORT_START_LBA <= lba < IMPORT_START_LBA + FILE_SECTORS:
        return f"IMPORT.CFG+0x{(lba - IMPORT_START_LBA) * SECTOR_SIZE:05x}"
    return "-"


def parse_hex_dump(output: str) -> bytes:
    payload = bytearray()
    for line in output.splitlines():
        match = re.match(r"^[0-9a-f]{4}\s+((?:[0-9a-f]{2}\s+)+)", line)
        if not match:
            continue
        for byte_hex in match.group(1).split():
            payload.append(int(byte_hex, 16))
    return bytes(payload)


def get_frame_bytes(pcap: Path, frame: int) -> bytes:
    output = run_tshark(["tshark", "-r", str(pcap), "-Y", f"frame.number=={frame}", "-x"])
    frame_bytes = parse_hex_dump(output)
    if not frame_bytes:
        raise SystemExit(f"Unable to extract bytes for frame {frame}.")
    return frame_bytes


def hexdump(data: bytes, *, start_offset: int = 0) -> Iterable[str]:
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        yield f"{start_offset + offset:04x}  {hex_part:<47}  {ascii_part}"


def cmd_list_scsi(args: argparse.Namespace) -> None:
    commands = parse_scsi_commands(Path(args.pcap))
    for command in commands:
        if args.only and command.direction != args.only:
            continue
        if args.lba is not None and command.lba != args.lba:
            continue
        label = describe_lba(command.lba)
        print(
            f"{command.frame:5d}  {command.time_relative:9.6f}  "
            f"{command.direction:<5}  lba={command.lba:<6d}  sectors={command.sectors:<4d}  "
            f"bytes={command.byte_length:<6d}  {label}"
        )


def cmd_dump_frame(args: argparse.Namespace) -> None:
    raw = get_frame_bytes(Path(args.pcap), args.frame)
    view = raw[args.skip :]
    if args.length is not None:
        view = view[: args.length]
    for line in hexdump(view):
        print(line)


def cmd_diff_frames(args: argparse.Namespace) -> None:
    left = get_frame_bytes(Path(args.pcap), args.left)[args.skip :]
    right = get_frame_bytes(Path(args.pcap), args.right)[args.skip :]
    limit = min(len(left), len(right))
    differences = [offset for offset in range(limit) if left[offset] != right[offset]]

    if len(left) != len(right):
        print(f"length differs: left={len(left)} right={len(right)}")

    if not differences:
        print("payloads are identical")
        return

    print(f"first {min(args.max_diffs, len(differences))} differing offsets:")
    for offset in differences[: args.max_diffs]:
        print(f"  0x{offset:04x}: {left[offset]:02x} -> {right[offset]:02x}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list-scsi", help="List SCSI Read(10)/Write(10) commands.")
    list_parser.add_argument("pcap", help="Path to the USBPcap capture.")
    list_parser.add_argument("--only", choices=["READ", "WRITE"], help="Filter by direction.")
    list_parser.add_argument("--lba", type=int, help="Filter by exact LBA.")
    list_parser.set_defaults(func=cmd_list_scsi)

    dump_parser = subparsers.add_parser("dump-frame", help="Hexdump one frame's raw bytes.")
    dump_parser.add_argument("pcap", help="Path to the USBPcap capture.")
    dump_parser.add_argument("frame", type=int, help="Frame number to dump.")
    dump_parser.add_argument(
        "--skip",
        type=int,
        default=USBPCAP_HEADER_LEN,
        help="Skip this many leading bytes before dumping (default: USBPcap header length).",
    )
    dump_parser.add_argument("--length", type=int, help="Limit output to this many bytes after --skip.")
    dump_parser.set_defaults(func=cmd_dump_frame)

    diff_parser = subparsers.add_parser("diff-frames", help="Compare two frame payloads byte-for-byte.")
    diff_parser.add_argument("pcap", help="Path to the USBPcap capture.")
    diff_parser.add_argument("left", type=int, help="Left frame number.")
    diff_parser.add_argument("right", type=int, help="Right frame number.")
    diff_parser.add_argument(
        "--skip",
        type=int,
        default=USBPCAP_HEADER_LEN,
        help="Skip this many leading bytes in both frames (default: USBPcap header length).",
    )
    diff_parser.add_argument("--max-diffs", type=int, default=64, help="Show at most this many differing offsets.")
    diff_parser.set_defaults(func=cmd_diff_frames)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
