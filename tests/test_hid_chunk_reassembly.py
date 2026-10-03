"""The USB client hands long panel replies to its readers as one packet.

The panel sends a TLV longer than one 64-byte report as chunk reports
`48 3E <count> ...`, `49 3E ...`, `4A <len> ...` (2026-10-03 capture: the
`90 EF` device table, the `52 FA` reply to `52 2B`). `JablotronUSBClient.read_packets`
reassembles them so the diagnostics reader in `jablotron_api.protocol.legacy`
sees the whole `90 EF` packet instead of three or four unrelated chunks.
Reports here are synthetic; only the framing comes from the capture.
"""

from __future__ import annotations

import pytest

import jablotron_usb_debug as ud
from jablotron_api.domain.models import CentralStatusModel
from jablotron_api.protocol import legacy
from jablotron_usb_debug import JablotronUSBClient

KEEPALIVE = bytes.fromhex("520102")
DEVICE_STATE = bytes.fromhex("5505010203ff00")


def _report(packet: bytes) -> bytes:
    return packet.ljust(64, b"\x00")


def _long_device_table() -> bytes:
    # `90 EF` + 239 data bytes: device 0 header, then filler, as long as the captured table.
    return ud.build_long_tlv_packet(0x90, bytes([0x00, 0x9C]) + bytes(range(237)))


class _FakeBus:
    """Feeds scripted 64-byte reports to `os.read`; one list per `read_packets` call."""

    def __init__(self, monkeypatch, batches: list[list[bytes]]) -> None:
        self.batches = batches
        self.current: list[bytes] = []
        monkeypatch.setattr(ud.os, "open", lambda *a, **k: 4242)
        monkeypatch.setattr(ud.os, "close", lambda fd: None)
        monkeypatch.setattr(ud.select, "select", lambda r, w, x, t: (list(r) if self.current else [], [], []))
        monkeypatch.setattr(ud.os, "read", self._read)

    def _read(self, fd, size):
        return self.current.pop(0)

    def next_batch(self, client: JablotronUSBClient) -> list[bytes]:
        self.current = list(self.batches.pop(0))
        return list(client.read_packets(timeout=0.05))


def test_chunked_reply_comes_out_as_one_packet_between_ordinary_ones(monkeypatch) -> None:
    table = _long_device_table()
    chunks = ud.split_packet_into_hid_reports(table)
    assert len(chunks) == 4 and chunks[0][:3] == bytes([0x48, 0x3E, 4])
    bus = _FakeBus(monkeypatch, [[_report(KEEPALIVE), *chunks, _report(DEVICE_STATE)]])
    client = JablotronUSBClient("/dev/hidraw9")
    assert bus.next_batch(client) == [KEEPALIVE, table, DEVICE_STATE]


def test_chunks_are_kept_across_read_calls(monkeypatch) -> None:
    table = _long_device_table()
    chunks = ud.split_packet_into_hid_reports(table)
    bus = _FakeBus(monkeypatch, [chunks[:2], chunks[2:]])
    client = JablotronUSBClient("/dev/hidraw9")
    assert bus.next_batch(client) == []
    assert bus.next_batch(client) == [table]


def test_a_broken_sequence_is_dropped_and_the_next_packet_goes_through(monkeypatch) -> None:
    chunks = ud.split_packet_into_hid_reports(_long_device_table())
    bus = _FakeBus(monkeypatch, [[chunks[0], chunks[1], _report(KEEPALIVE), *chunks]])
    client = JablotronUSBClient("/dev/hidraw9")
    # The keepalive ends the first, unfinished sequence; the complete one after it reassembles.
    assert bus.next_batch(client) == [KEEPALIVE, _long_device_table()]


def test_a_wrong_count_byte_drops_the_group_only(monkeypatch) -> None:
    chunks = ud.split_packet_into_hid_reports(_long_device_table())
    bad_first = chunks[0][:2] + bytes([9]) + chunks[0][3:]
    bus = _FakeBus(monkeypatch, [[bad_first, *chunks[1:], _report(KEEPALIVE)]])
    client = JablotronUSBClient("/dev/hidraw9")
    assert bus.next_batch(client) == [KEEPALIVE]


def test_a_stray_middle_or_last_chunk_without_a_first_is_passed_through(monkeypatch) -> None:
    chunks = ud.split_packet_into_hid_reports(_long_device_table())
    bus = _FakeBus(monkeypatch, [[chunks[1], chunks[-1]]])
    client = JablotronUSBClient("/dev/hidraw9")
    assert [packet[0] for packet in bus.next_batch(client)] == [0x49, 0x4A]


def test_the_snapshot_parser_receives_the_whole_device_table(monkeypatch) -> None:
    table = _long_device_table()
    bus = _FakeBus(monkeypatch, [ud.split_packet_into_hid_reports(table)])
    client = JablotronUSBClient("/dev/hidraw9")
    parser = legacy._SnapshotParser(devices_by_id={}, special_devices={}, central=CentralStatusModel())
    seen: list[bytes] = []
    monkeypatch.setattr(parser, "_parse_device_info_packet", seen.append)
    for packet in bus.next_batch(client):
        parser.parse_packet(packet, pg_count=4)
    assert seen == [table]
    assert seen[0][:2] == bytes([0x90, 0xEF])


@pytest.mark.parametrize("data_len", [239, 304])
def test_the_captured_reply_sizes_round_trip(data_len: int) -> None:
    # `90 EF` (239 data bytes, 4 chunks) and `52 FA` (304 data bytes, 5 chunks) in the capture.
    packet = ud.build_long_tlv_packet(0x52 if data_len > 250 else 0x90, bytes(data_len))
    reports = ud.split_packet_into_hid_reports(packet)
    assert len(reports) == (5 if data_len > 250 else 4)
    assert ud.reassemble_hid_chunk_reports(reports) == packet
