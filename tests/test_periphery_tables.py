"""Periphery state and topology parsers, against the layouts in
research/2026-10-03_periphery-state-and-topology.md.

Byte values are synthetic but shaped like the captured ones: a present bus
device, a magnetic contact with its input open (`8C`), a present radio device
with the frame counter, a silent radio device (`since = 0xFFFF`), empty
positions (`06 00`), and the radio module's two-entry topology list.
"""

from __future__ import annotations

import pytest

from jablotron_api.protocol import periphery_tables as pt


def _single(pos: int, code: int, type_byte: int, flags: int, since: int, class_byte: int, rfc: int | None = None) -> bytes:
    body = bytes([pos, code, type_byte, flags]) + since.to_bytes(2, "little") + bytes([class_byte])
    if rfc is not None:
        body += rfc.to_bytes(2, "little")
    body += b"\x00"
    return bytes([0x52, len(body) + 1, 0xA8]) + body


def test_single_status_of_a_bus_device() -> None:
    rec = pt.parse_single_device_status(_single(0x02, 0xFF, 0x04, 0x00, 549, 0x01))
    assert rec == pt.DeviceStatusRecord(2, 0xFF, 0x04, 0x00, 549, 0x01, None)
    assert rec.present and not rec.radio and not rec.input_active and not rec.empty


def test_single_status_of_an_open_magnetic_contact() -> None:
    rec = pt.parse_single_device_status(_single(0x05, 0xFF, 0x8C, 0x00, 526, 0x01))
    assert rec.input_active


def test_single_status_of_a_radio_device_carries_the_frame_counter() -> None:
    rec = pt.parse_single_device_status(_single(0x29, 0xFF, 0x04, 0x00, 81, 0x01, 1166))
    assert rec.radio and rec.radio_counter == 1166 and rec.since_seconds == 81


def test_single_status_of_a_silent_radio_device() -> None:
    rec = pt.parse_single_device_status(_single(0x2B, 0x00, 0x06, 0x00, 0xFFFF, 0xFC, 2725))
    assert rec.never_heard and not rec.present and not rec.empty


def test_single_status_of_an_empty_position() -> None:
    rec = pt.parse_single_device_status(_single(0x24, 0x00, 0x06, 0x00, 0, 0xFC))
    assert rec.empty and not rec.present


def test_single_status_ignores_other_packets() -> None:
    assert pt.parse_single_device_status(bytes.fromhex("52071b01004f200100")) is None
    assert pt.parse_single_device_status(bytes.fromhex("520102")) is None


def _collective(records: list[bytes]) -> bytes:
    body = b"".join(records)
    return bytes([0x52, min(len(body) + 1, 0xFA), 0xA9]) + body + b"\x00"


COLLECTIVE = _collective(
    [
        bytes([0x01, 0xFF, 0x04, 0x00, 0, 0, 0xF2]),
        bytes([0x02, 0xFF, 0x04, 0x00, 0xE7, 0x01, 0x01]),
        bytes([0x03, 0xFF, 0x8C, 0x00, 0xDF, 0x01, 0x01]),
        bytes([0x04, 0x06, 0x00]),
        bytes([0x05, 0x06, 0x00]),
        bytes([0x06, 0xFF, 0x04, 0x20, 0x09, 0x00, 0x01]),
        bytes([0x07, 0xFF, 0x04, 0x00, 0x06, 0x00, 0x01, 0x8E, 0x04]),
        bytes([0x08, 0x00, 0x06, 0x00, 0xFF, 0xFF, 0xFC, 0xA5, 0x0A]),
        bytes([0x09, 0xFF, 0x04, 0x00, 0x97, 0x00, 0x01]),
    ]
)


@pytest.mark.parametrize("radio_positions", [None, {7, 8}])
def test_the_collective_table_walks_every_record_shape(radio_positions) -> None:
    records = pt.parse_collective_status(COLLECTIVE, radio_positions=radio_positions)
    assert [r.position for r in records] == list(range(1, 10))
    by = {r.position: r for r in records}
    assert by[1].present and by[1].class_byte == 0xF2 and by[1].since_seconds == 0
    assert by[2].since_seconds == 487 and not by[2].radio
    assert by[3].input_active
    assert by[4].empty and by[5].empty
    assert by[6].flags == 0x20
    assert by[7].radio and by[7].radio_counter == 0x048E and by[7].since_seconds == 6
    assert by[8].never_heard and by[8].radio_counter == 0x0AA5 and not by[8].present
    assert by[9].since_seconds == 0x97 and not by[9].radio


def test_the_collective_table_rejects_other_packets_and_garbage() -> None:
    with pytest.raises(ValueError, match="Not a collective"):
        pt.parse_collective_status(bytes.fromhex("520102"))
    with pytest.raises(ValueError, match="Unknown record code 0x12"):
        pt.parse_collective_status(bytes.fromhex("5204a90112"))


def test_the_topology_list_of_a_radio_module() -> None:
    sub = bytes.fromhex("6b0e0d02") + bytes.fromhex("144b40510031") + bytes.fromhex("084b40510031")
    entries = pt.parse_topology_subpacket(sub)
    assert [e.device_id for e in entries] == [0x51404B14, 0x51404B08]
    assert all(e.parent_position == 0 and e.bus_line == 1 and not e.radio for e in entries)


def test_the_topology_list_marks_radio_children_and_bus_lines() -> None:
    entries = pt.parse_topology_subpacket(
        bytes.fromhex("6b140d03") + bytes.fromhex("57d219100032") + bytes.fromhex("60c643100031") + bytes.fromhex("144b40512780")
    )
    assert [(e.bus_line, e.radio, e.parent_position) for e in entries] == [(2, False, 0), (1, False, 0), (None, True, 0x27)]


def test_the_topology_closers_and_other_params_are_not_lists() -> None:
    assert pt.parse_topology_subpacket(bytes.fromhex("6b020d40")) is None
    assert pt.parse_topology_subpacket(bytes.fromhex("6b020d80")) is None
    assert pt.parse_topology_subpacket(bytes.fromhex("6b021203")) is None
    assert pt.parse_topology_subpacket(bytes.fromhex("6b011a")) is None


def test_the_topology_list_length_must_match_the_count() -> None:
    with pytest.raises(ValueError, match="says 3 entries"):
        pt.parse_topology_subpacket(bytes.fromhex("6b0e0d03") + bytes(12))


def test_a_whole_device_info_packet_yields_position_and_entries() -> None:
    packet = bytes.fromhex("901127") + bytes.fromhex("6b0e0d02144b40510031084b40510031")
    position, entries = pt.topology_entries_from_device_info(packet)
    assert position == 0x27 and len(entries) == 2
    assert pt.topology_entries_from_device_info(bytes.fromhex("9005276b020d40")) is None
