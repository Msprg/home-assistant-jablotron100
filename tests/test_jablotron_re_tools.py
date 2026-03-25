from __future__ import annotations

import pytest

import jablotron_re_tools as re_tools


SECTIONS_90_PACKET = bytes.fromhex(
    "5122010001000100010001000100070007000700070007000700070007000700070007000090"
)
SECTIONS_94_PACKET = bytes.fromhex(
    "5122010001000100010001000100070007000700070007000700070007000700070007000094"
)
SYSTEM_90_PACKET = bytes.fromhex("730900000000000090A000")
SYSTEM_94_PACKET = bytes.fromhex("730900000000000094A000")
SERVICE_RIGHTS_PACKET = bytes.fromhex("801A0CFFFFFFFF0F003F003F0029200700270000000000000000000000")
SETUP_READY_PACKET = bytes.fromhex("80021A0A")
SETTING_MODE_ENTERED_PACKET = bytes.fromhex("800112")


class FakeClient:
    def __init__(self, scripted_reads: list[list[bytes]] | None = None) -> None:
        self.scripted_reads = list(scripted_reads or [])
        self.sent_packets: list[bytes] = []

    def read_packets(self, *, timeout: float):
        if self.scripted_reads:
            return iter(self.scripted_reads.pop(0))
        return iter(())

    def send_packet(self, packet: bytes) -> None:
        self.sent_packets.append(packet)

    def send_packets(self, packets: list[bytes]) -> None:
        self.sent_packets.extend(packets)

    def close(self) -> None:
        return None


def test_configuration_helpers_detect_configuration_mode() -> None:
    assert re_tools.extract_sections_state_mode(SECTIONS_94_PACKET) == re_tools.CONFIGURATION_SECTIONS_MODE
    assert re_tools.extract_system_state_mode(SYSTEM_94_PACKET) == re_tools.CONFIGURATION_SECTIONS_MODE
    assert re_tools.packet_has_configuration_channels_in_use(SYSTEM_94_PACKET) is True
    assert re_tools.packet_has_configuration_channels_in_use(SYSTEM_90_PACKET) is False
    assert re_tools.describe_sections_mode(re_tools.CONFIGURATION_SECTIONS_MODE) == "configuration-active (0x94)"


def test_enter_setup_mode_reports_configuration_in_use() -> None:
    client = FakeClient()
    with pytest.raises(SystemExit, match="already in configuration mode"):
        re_tools.enter_setup_mode(
            client,
            verbose=False,
            initial_packets=[SECTIONS_94_PACKET, SYSTEM_94_PACKET],
        )


def test_enter_setup_mode_allows_expected_94_during_successful_transition(monkeypatch: pytest.MonkeyPatch) -> None:
    sent_reports: list[str] = []
    monkeypatch.setattr(re_tools, "perform_send_raw_report", lambda client, report_hex: sent_reports.append(report_hex))

    client = FakeClient()
    re_tools.enter_setup_mode(
        client,
        verbose=False,
        initial_packets=[
            SERVICE_RIGHTS_PACKET,
            SETUP_READY_PACKET,
            SECTIONS_94_PACKET,
            SETTING_MODE_ENTERED_PACKET,
        ],
    )

    assert re_tools.REPORT_80010F in sent_reports


def test_cleanup_read_session_returns_configuration_mode_without_login_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    created_clients: list[FakeClient] = []
    login_calls: list[tuple[str, bool]] = []

    def build_client(_port: str) -> FakeClient:
        client = FakeClient(scripted_reads=[[SYSTEM_94_PACKET], [], []])
        created_clients.append(client)
        return client

    monkeypatch.setattr(re_tools, "ensure_serial_port", lambda port: port)
    monkeypatch.setattr(re_tools, "JablotronUSBClient", build_client)
    monkeypatch.setattr(re_tools, "perform_login", lambda client, code, reset=False: login_calls.append((code, reset)))

    final_mode = re_tools.cleanup_read_session(
        port="auto",
        code="1812",
        cleanup_mode="auto",
        verbose=False,
    )

    assert final_mode == re_tools.CONFIGURATION_SECTIONS_MODE
    assert login_calls == []
    assert len(created_clients) == 1
