#!/usr/bin/env python3
"""Merged host<->panel HID timeline from a USBPcap/usbmon capture of a JA-100 panel.

The panel's HID channel carries 64-byte reports that are a concatenation of
TLV packets ``[type][length][data...]`` padded with zeros.  Host->panel reports
travel as HID SET_REPORT control transfers (bmRequestType 0x21); panel->host
reports are interrupt-IN transfers.  This tool decodes both directions into one
chronological text file, one line per report::

    <frame>\t<hh:mm:ss.fff>\t<H>P|P>H>\t<type>:<data hex> | <type>:<data hex> ...

Statistics-only helpers (``--histogram``) summarise which packet types each
direction used.  Requires ``tshark`` on PATH.
"""

from __future__ import annotations

import argparse
import collections
import subprocess
import sys
from pathlib import Path
from typing import Iterable

PANEL_TO_HOST_FILTER = "usb.transfer_type==0x01 && usb.endpoint_address==0x81 && usb.data_len>0"
HOST_TO_PANEL_FILTER = "usb.transfer_type==0x02 && usb.bmRequestType==0x21 && usb.data_len>0"


def split_tlv(payload: bytes) -> list[tuple[int, bytes]]:
    """Split one report into (type, data) packets; stops at the zero padding."""
    packets: list[tuple[int, bytes]] = []
    offset = 0
    while offset + 1 < len(payload) and payload[offset] != 0:
        packet_type = payload[offset]
        length = payload[offset + 1]
        packets.append((packet_type, payload[offset + 2 : offset + 2 + length]))
        offset += 2 + length
    return packets


def format_tlv(payload: bytes) -> str:
    return " | ".join(f"{packet_type:02x}:{data.hex()}" for packet_type, data in split_tlv(payload))


def run_tshark(pcap: Path, display_filter: str, data_field: str) -> list[tuple[int, str, bytes]]:
    command = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "frame.time",
        "-e",
        data_field,
    ]
    output = subprocess.run(command, capture_output=True, text=True, check=True).stdout
    rows: list[tuple[int, str, bytes]] = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 3 or not fields[2]:
            continue
        rows.append((int(fields[0]), fields[1], bytes.fromhex(fields[2].replace(":", ""))))
    return rows


def load_flow(pcap: Path) -> list[tuple[int, str, str, bytes]]:
    rows: list[tuple[int, str, str, bytes]] = []
    for frame, when, payload in run_tshark(pcap, PANEL_TO_HOST_FILTER, "usbhid.data"):
        rows.append((frame, when, "P>H", payload))
    for frame, when, payload in run_tshark(pcap, HOST_TO_PANEL_FILTER, "usb.data_fragment"):
        rows.append((frame, when, "H>P", payload))
    rows.sort()
    return rows


def clock_only(frame_time: str) -> str:
    """'Sep 25, 2026 20:28:41.207795000 CEST' -> '20:28:41.207'."""
    parts = frame_time.split()
    for part in parts:
        if part.count(":") == 2:
            return part[:12]
    return frame_time


def write_flow(rows: Iterable[tuple[int, str, str, bytes]], output) -> None:
    for frame, when, direction, payload in rows:
        output.write(f"{frame}\t{clock_only(when)}\t{direction}\t{format_tlv(payload)}\n")


def print_histogram(rows: Iterable[tuple[int, str, str, bytes]]) -> None:
    counters = {"H>P": collections.Counter(), "P>H": collections.Counter()}
    for _frame, _when, direction, payload in rows:
        for packet_type, data in split_tlv(payload):
            counters[direction][(packet_type, len(data))] += 1
    for direction, counter in counters.items():
        print(f"{direction} (type, data length) -> count")
        for (packet_type, length), count in sorted(counter.items(), key=lambda item: -item[1]):
            print(f"  {packet_type:02x} len={length:<3d} {count}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pcap", type=Path, help="USBPcap or usbmon capture (.pcapng)")
    parser.add_argument("-o", "--output", type=Path, help="Write the merged timeline here instead of stdout")
    parser.add_argument("--histogram", action="store_true", help="Print a per-direction packet type histogram")
    args = parser.parse_args()

    rows = load_flow(args.pcap)
    if args.output:
        with args.output.open("w", encoding="utf-8") as handle:
            write_flow(rows, handle)
        print(f"{len(rows)} reports -> {args.output}", file=sys.stderr)
    elif not args.histogram:
        write_flow(rows, sys.stdout)
    if args.histogram:
        print_histogram(rows)


if __name__ == "__main__":
    main()
