"""Parsers for the panel's periphery state tables and topology lists.

Decoded in ``research/2026-10-03_periphery-state-and-topology.md`` from an
F-Link session on one JA-107K; the field names there carry the confidence
levels. Three packets:

- ``52 .. A8 <pos> ...``: single device status (reply to ``52 02 28 <pos>``).
- ``52 FA A9 ...``: the collective table (reply to ``52 03 2B 01 E6``), one
  record per position; arrives chunked and is reassembled by the USB client.
- ``90 .. <pos> 6B <len> 0D <count> ...``: the topology list a bus master or
  radio module returns to ``96 04 <pos> 6A 01 0D``.

Nothing here talks to the panel; the server does not send these queries yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

SINGLE_STATUS_PREFIX = bytes.fromhex("52")
SINGLE_STATUS_COMMAND = 0xA8
COLLECTIVE_STATUS_COMMAND = 0xA9
COLLECTIVE_STATUS_QUERY = bytes.fromhex("52032b01e6")
TOPOLOGY_SUBPACKET = 0x6B
TOPOLOGY_PARAM = 0x0D
SINCE_NEVER = 0xFFFF

CODE_PRESENT = 0xFF
CODE_ABSENT = 0x00
TYPE_EMPTY = 0x06
TYPE_INPUT_ACTIVE_BITS = 0x88


@dataclass(frozen=True)
class DeviceStatusRecord:
    position: int
    code: int
    type_byte: int
    flags: int
    since_seconds: int | None
    class_byte: int | None
    radio_counter: int | None

    @property
    def present(self) -> bool:
        return self.code == CODE_PRESENT

    @property
    def empty(self) -> bool:
        return self.type_byte == TYPE_EMPTY and self.since_seconds in (0, None)

    @property
    def never_heard(self) -> bool:
        return self.since_seconds == SINCE_NEVER

    @property
    def input_active(self) -> bool:
        return self.type_byte & TYPE_INPUT_ACTIVE_BITS == TYPE_INPUT_ACTIVE_BITS

    @property
    def radio(self) -> bool:
        return self.radio_counter is not None


@dataclass(frozen=True)
class TopologyEntry:
    device_id: int
    parent_position: int
    link: int

    @property
    def radio(self) -> bool:
        return bool(self.link & 0x80)

    @property
    def bus_line(self) -> int | None:
        """1 or 2 for a bus device (`0x31` / `0x32`), None for a radio device."""

        if self.radio:
            return None
        return self.link & 0x0F if self.link & 0x0F in (1, 2) else None


def parse_single_device_status(packet: bytes) -> DeviceStatusRecord | None:
    """`52 <len> A8 <pos> <code> <type> <flags> <u16 since> <class> [<u16 rfc>] 00`."""

    if len(packet) < 10 or packet[0] != 0x52 or packet[2] != SINGLE_STATUS_COMMAND:
        return None
    body = packet[3 : 3 + packet[1] - 1]
    if len(body) not in (8, 10):
        return None
    radio_counter = int.from_bytes(body[7:9], "little") if len(body) == 10 else None
    return DeviceStatusRecord(
        position=body[0],
        code=body[1],
        type_byte=body[2],
        flags=body[3],
        since_seconds=int.from_bytes(body[4:6], "little"),
        class_byte=body[6],
        radio_counter=radio_counter,
    )


def parse_collective_status(packet: bytes, *, radio_positions: Iterable[int] | None = None) -> list[DeviceStatusRecord]:
    """Walk the `52 FA A9` table into one record per position.

    Records are ``<pos> FF|00 <type> <flags> <u16 since> <class>`` with a
    trailing ``<u16 rfc>`` on radio devices, or ``<pos> 06 00`` for an empty
    position. The 9-byte form carries no marker, so radio positions come
    from ``radio_positions`` (the catalog) when given; otherwise the parser
    relies on positions being consecutive: after a 7-byte record the next
    byte is either the next position or the low byte of the counter.
    """

    if len(packet) < 3 or packet[0] != 0x52 or packet[2] != COLLECTIVE_STATUS_COMMAND:
        raise ValueError("Not a collective periphery state packet (52 .. A9).")
    body = packet[3:].rstrip(b"\x00")
    radio = set(radio_positions) if radio_positions is not None else None
    records: list[DeviceStatusRecord] = []
    i = 0
    while i < len(body):
        position = body[i]
        if i + 1 >= len(body):
            raise ValueError(f"Truncated record for position {position}.")
        code = body[i + 1]
        if code == TYPE_EMPTY:
            records.append(DeviceStatusRecord(position, CODE_ABSENT, TYPE_EMPTY, body[i + 2] if i + 2 < len(body) else 0, 0, None, None))
            i += 3
            continue
        if code not in (CODE_PRESENT, CODE_ABSENT):
            raise ValueError(f"Unknown record code 0x{code:02x} at position {position}.")
        if i + 7 > len(body):
            raise ValueError(f"Truncated record for position {position}.")
        type_byte, flags = body[i + 2], body[i + 3]
        since = int.from_bytes(body[i + 4 : i + 6], "little")
        class_byte = body[i + 6]
        if radio is not None:
            has_counter = position in radio
        else:
            has_counter = i + 7 < len(body) and body[i + 7] != position + 1 and i + 9 <= len(body)
        counter = int.from_bytes(body[i + 7 : i + 9], "little") if has_counter else None
        records.append(DeviceStatusRecord(position, code, type_byte, flags, since, class_byte, counter))
        i += 9 if has_counter else 7
    return records


def parse_topology_subpacket(subpacket: bytes) -> list[TopologyEntry] | None:
    """`6B <len> 0D <count> <count x (u32 LE id, parent pos, link)>`; None for the `40`/`80` closers."""

    if len(subpacket) < 4 or subpacket[0] != TOPOLOGY_SUBPACKET or subpacket[2] != TOPOLOGY_PARAM:
        return None
    length = subpacket[1]
    if length <= 2:
        # `6B 02 0D 40` / `6B 02 0D 80`: the status bytes that close a read, not a list.
        return None
    count = subpacket[3]
    data = subpacket[4 : 2 + length]
    if len(data) != count * 6 or length != 2 + count * 6:
        raise ValueError(f"Topology list says {count} entries but carries {len(data)} bytes.")
    return [
        TopologyEntry(
            device_id=int.from_bytes(data[j : j + 4], "little"),
            parent_position=data[j + 4],
            link=data[j + 5],
        )
        for j in range(0, len(data), 6)
    ]


def topology_entries_from_device_info(packet: bytes) -> tuple[int, list[TopologyEntry]] | None:
    """Pull the topology list out of a whole `90 <len> <pos> 6B ...` device-info packet."""

    if len(packet) < 5 or packet[0] != 0x90:
        return None
    position = packet[2]
    entries = parse_topology_subpacket(packet[3:])
    if entries is None:
        return None
    return position, entries
