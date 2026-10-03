"""Device-info subpackets of unknown type are ignored, as the upstream integration does.

A `90` packet is `90 <len> <device> <subpackets>`. Only the wireless (`01`),
periodic (`9C`) and requested (`0A`) subpackets carry the battery byte and the
info records the parser reads. The 2026-10-03 F-Link capture shows a 239-byte
`90 EF 01 6B EC ...` reply to the diagnostics command `96 01 6A ...`: device 1,
one subpacket of type `6B`. Now that the USB client reassembles such replies
whole, the parser must not read a battery level or info records out of them.
Bytes here are synthetic apart from that header.
"""

from __future__ import annotations

from jablotron_api.domain.models import CentralStatusModel, DeviceStatusModel
from jablotron_api.protocol.legacy import _SnapshotParser


def _parser() -> _SnapshotParser:
    return _SnapshotParser(
        devices_by_id={1: DeviceStatusModel(id=1, name="Device 1", inferred_device_type="thermometer", state="off")},
        special_devices={},
        central=CentralStatusModel(),
    )


def _device_info(device: int, subpackets: bytes) -> bytes:
    body = bytes([device]) + subpackets
    return bytes([0x90, min(len(body), 0xFA)]) + body


def test_a_diagnostics_command_response_subpacket_is_ignored() -> None:
    parser = _parser()
    before = parser.devices_by_id[1].model_copy(deep=True)
    # `6B EC` + 236 bytes whose first byte would read as a battery level.
    blob = bytes([0x6B, 0xEC, 0x0D, 0x27, 0x57]) + bytes(range(1, 234))
    packet = _device_info(1, blob)
    assert packet[:5] == bytes([0x90, 0xEF, 0x01, 0x6B, 0xEC])
    parser.parse_packet(packet, pg_count=4)
    assert parser.devices_by_id[1] == before


def test_the_listed_unknown_subpacket_05_is_ignored_too() -> None:
    parser = _parser()
    before = parser.devices_by_id[1].model_copy(deep=True)
    parser.parse_packet(_device_info(1, bytes([0x05, 0x03, 0x0A, 0x00, 0x00])), pg_count=4)
    assert parser.devices_by_id[1] == before


def test_the_wireless_subpacket_still_marks_the_device_wireless() -> None:
    parser = _parser()
    parser.parse_packet(_device_info(1, bytes([0x01, 0x01, 0x0A])), pg_count=4)
    device = parser.devices_by_id[1]
    assert device.wireless is True
    assert device.connection == "wireless"
