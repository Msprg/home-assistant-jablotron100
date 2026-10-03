"""The HID configuration write and the reply-driven commit, against captured bytes.

Every byte string here is lifted from the 2026-09-25 F-Link captures (see
docs/handoff-2026-09-25-write-gate.md, "Decoded") or the March 2026 ones.
The panel is replaced by a scripted client; the assertions are about which
bytes go out, in which order, and which replies are required.
"""

from __future__ import annotations

from collections import OrderedDict
from pathlib import Path

import pytest

import import_cfg_tool
import jablotron_re_tools as tools
import jablotron_api.services.user_manager as user_manager
from jablotron_api.panel.runtime import PanelRuntime, PanelRuntimeConfig
from jablotron_api.server.config import PanelSettings, ServerSettings
from jablotron_api.services.user_manager import UserManagerConfig

# Login replies `80 1A 0C ...` as the panel sent them.
LOGIN_ARC_POSITION_7 = bytes.fromhex("801a0cffff0f003f003f002a20070027000000000000000000000000")
LOGIN_MASTER_POSITION_100 = bytes.fromhex("801a0cffff0f003f003f002820640027000000000000000000000000")
LOGIN_SERVICE_POSITION_7_MARCH = bytes.fromhex("801a0cffff00003f003f002920070027000000000000000000000000")

# The F-Link save of user 96 ("Test96" / "handoff-test") and its delete, as sent over HID.
HID_SAVE_PACKET = bytes.fromhex(
    "1d3b0900810781608c00000100020003940000000004a654657374393605a006a007928100a08100a0080009000aac"
    "68616e646f66662d746573740bff"
)
HID_DELETE_PACKET = bytes.fromhex("1d07090081078160c0")
HID_ACK = bytes.fromhex("1d03440000")

ACCEPT_CONFIRMED = bytes.fromhex("5203830102")
CONFIG_ESCAPED = bytes.fromhex("800117")
IMPORT_PROGRESS_0 = bytes.fromhex("5204830b2400")
IMPORT_PROGRESS_100 = bytes.fromhex("5204830b2464")
IMPORT_COMPLETE = bytes.fromhex("520483012401")
REVISION_0X204F = bytes.fromhex("52071b01004f200100")
REVISION_0X2050 = bytes.fromhex("52071b010050200100")


class ScriptedClient:
    """Answers each read with the next scripted batch; records everything sent."""

    def __init__(self, reads: list[list[bytes]] | None = None) -> None:
        self.reads = list(reads or [])
        self.sent: list[bytes] = []

    def read_packets(self, *, timeout: float):
        if self.reads:
            return iter(self.reads.pop(0))
        return iter(())

    def send_packet(self, packet: bytes) -> None:
        self.sent.append(packet)

    def send_packets(self, packets) -> None:
        self.sent.extend(packets)

    def _write(self, report: bytes) -> None:
        self.sent.append(report.rstrip(b"\x00"))

    def close(self) -> None:
        return None


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(tools.time, "sleep", lambda seconds: None)


# ------------------------------------------------------------- login rights


def test_login_reply_names_rights_and_position_as_f_link_logs_them() -> None:
    arc = tools.parse_login_rights(LOGIN_ARC_POSITION_7)
    master = tools.parse_login_rights(LOGIN_MASTER_POSITION_100)
    service = tools.parse_login_rights(LOGIN_SERVICE_POSITION_7_MARCH)

    assert (arc.rights, arc.position, arc.is_master) == ("arc", 7, False)
    assert (master.rights, master.position, master.is_master) == ("master", 100, True)
    assert (service.rights, service.position, service.is_master) == ("service", 7, False)
    assert tools.parse_login_rights(bytes.fromhex("80021a0a")) is None


def test_enter_setup_mode_returns_the_login_rights(monkeypatch) -> None:
    monkeypatch.setattr(tools, "perform_send_raw_report", lambda client, report_hex: None)
    rights = tools.enter_setup_mode(
        ScriptedClient(),
        verbose=False,
        initial_packets=[LOGIN_MASTER_POSITION_100, bytes.fromhex("80021a0a"), bytes.fromhex("800112")],
    )
    assert rights == tools.LoginRights(rights_raw=0x28, position=100)


# ------------------------------------------------------- revision counter


def test_config_revision_reply_is_a_little_endian_counter() -> None:
    assert tools.parse_config_revision(REVISION_0X204F) == 0x204F
    assert tools.parse_config_revision(bytes.fromhex("52071b0a00e9000000")) is None, "other sub-ids are not the revision"


def test_revision_check_fails_when_the_counter_did_not_move() -> None:
    client = ScriptedClient([[REVISION_0X204F]])
    with pytest.raises(SystemExit, match="revision stayed at 0x204f"):
        tools.verify_config_revision_advanced(client, before=0x204F, verbose=False)
    assert client.sent == [tools.CONFIG_REVISION_QUERY_PACKET]


def test_revision_check_passes_when_the_counter_advanced() -> None:
    client = ScriptedClient([[REVISION_0X2050]])
    assert tools.verify_config_revision_advanced(client, before=0x204F, verbose=False) == 0x2050


def test_revision_check_is_skipped_without_a_baseline() -> None:
    client = ScriptedClient([[]])
    assert tools.verify_config_revision_advanced(client, before=None, verbose=False) is None


# ------------------------------------------------------------ HID write


def _sector_payload(payload) -> bytes:
    return import_cfg_tool.pack_msgpack(payload)


def test_the_hid_packet_for_the_captured_save_matches_f_link_byte_for_byte() -> None:
    record = OrderedDict(
        [
            (0, 0),
            (1, 0),
            (2, 0),
            (3, [0, 0, 0, 0]),
            (4, "Test96"),
            (5, ""),
            (6, ""),
            (7, [OrderedDict({0: ""}), OrderedDict({0: ""})]),
            (8, 0),
            (9, 0),
            (10, "handoff-test"),
            (11, -1),
        ]
    )
    payload = _sector_payload(OrderedDict({7: OrderedDict({96: record})}))
    assert tools.build_hid_config_write_packet(payload) == HID_SAVE_PACKET


def test_the_hid_packet_for_the_captured_delete_matches_f_link_byte_for_byte() -> None:
    payload = _sector_payload(import_cfg_tool.build_user_delete_payload(96))
    assert tools.build_hid_config_write_packet(payload) == HID_DELETE_PACKET


def test_the_sector_builders_feed_the_hid_transport_without_re_encoding(tmp_path: Path) -> None:
    """The IMPORT.CFG sector body and the HID payload are the same bytes."""

    sector = tmp_path / "delete.bin"
    sector.write_bytes(import_cfg_tool.encode_sector(import_cfg_tool.build_user_delete_payload(96)))
    assert tools.build_hid_config_write_packet(user_manager.sector_payload_bytes(sector)) == HID_DELETE_PACKET


def test_a_payload_over_the_sanity_cap_is_refused() -> None:
    with pytest.raises(SystemExit, match="exceeds the HID write limit"):
        tools.build_hid_config_write_packet(b"\x00" * (tools.HID_CONFIG_WRITE_MAX_PAYLOAD + 1))


# ------------------------------------------------------- chunk framing
#
# Sizes and framing from the 2026-10-03 F-Link capture
# (docs/handoff-2026-10-03-long-hid-writes.md): inner `1D <len> 09 00 <msgpack>`
# of 198, 324 and 397 data bytes went out as 4, 6 and 7 chunks. The record
# contents are the owner's; the tests rebuild only the framing from synthetic
# payloads of the same sizes.


@pytest.mark.parametrize(
    ("data_len", "len_byte", "chunks", "last_len"),
    [
        (198, 0xC6, 4, 15),  # SAVE 3, frames 12581-12587
        (324, 0xFA, 6, 17),  # SAVE 2, frames 9475-9485
        (397, 0xFA, 7, 28),  # SAVE 1, frames 6333-6345
    ],
)
def test_long_writes_are_framed_as_f_link_frames_them(data_len: int, len_byte: int, chunks: int, last_len: int) -> None:
    payload = bytes(range(256))[: data_len - 2] if data_len <= 258 else (bytes(range(256)) * 2)[: data_len - 2]
    packet = tools.build_hid_config_write_packet(payload)
    assert packet[:2] == bytes([0x1D, len_byte])
    assert packet[2:4] == b"\x09\x00"
    assert len(packet) == data_len + 2

    reports = tools.build_hid_config_write_reports(payload)
    assert len(reports) == chunks
    assert all(len(report) == 64 for report in reports)
    assert reports[0][:3] == bytes([0x48, 0x3E, chunks])
    assert all(report[:2] == bytes([0x49, 0x3E]) for report in reports[1:-1])
    assert reports[-1][:2] == bytes([0x4A, last_len])
    assert reports[-1][2 + last_len :] == b"\x00" * (62 - last_len)

    body = reports[0][3:] + b"".join(report[2:] for report in reports[1:-1]) + reports[-1][2 : 2 + last_len]
    assert body == packet
    assert tools.reassemble_hid_chunk_reports(reports) == packet


def test_the_length_byte_is_real_up_to_250_and_0xfa_beyond() -> None:
    assert tools.build_hid_config_write_packet(b"\x00" * 248)[1] == 0xFA
    assert tools.build_hid_config_write_packet(b"\x00" * 249)[1] == 0xFA
    assert tools.build_hid_config_write_packet(b"\x00" * 247)[1] == 0xF9


def test_a_packet_that_fits_one_report_is_sent_unchunked() -> None:
    # 60 payload bytes: `1D 3E 09 00` + 60 = 64, exactly one report.
    reports = tools.build_hid_config_write_reports(b"\x00" * 60)
    assert len(reports) == 1 and reports[0][:2] == bytes([0x1D, 0x3E])
    # 61 payload bytes: 65-byte packet, two chunks, the last carrying 4 bytes.
    reports = tools.build_hid_config_write_reports(b"\x00" * 61)
    assert [report[:2] for report in reports] == [bytes([0x48, 0x3E]), bytes([0x4A, 0x04])]
    assert reports[0][2] == 2


def test_reassembly_checks_the_count_byte_and_the_chunk_types() -> None:
    reports = tools.build_hid_config_write_reports(b"\x00" * 200)
    with pytest.raises(ValueError, match="count byte says 4 chunks, got 3"):
        tools.reassemble_hid_chunk_reports(reports[:-1])
    broken = [reports[0], bytes([0x4B]) + reports[1][1:], *reports[2:]]
    with pytest.raises(ValueError, match="Unexpected chunk type 0x4b"):
        tools.reassemble_hid_chunk_reports(broken)


def test_write_config_over_hid_sends_the_chunks_back_to_back(monkeypatch) -> None:
    client = ScriptedClient([[HID_ACK]])
    sent_reports: list[bytes] = []
    monkeypatch.setattr(tools, "perform_send_raw_report", lambda c, report_hex: sent_reports.append(bytes.fromhex(report_hex)))
    payload = b"\x81" * 196
    reply = tools.write_config_over_hid(client, payload, verbose=False)
    assert reply == HID_ACK
    assert client.sent == []
    assert sent_reports == tools.build_hid_config_write_reports(payload)
    assert [report[0] for report in sent_reports] == [0x48, 0x49, 0x49, 0x4A]


def test_the_logon_info_line_carries_the_a0_header_and_our_own_name() -> None:
    import jablotron_usb_debug as usb

    reports = [bytes.fromhex(report) for report in usb.build_logon_info_reports()]
    assert len(reports) == 3 and reports[0][:3] == bytes([0x48, 0x3E, 0x03])
    inner = usb.reassemble_hid_chunk_reports(reports)
    assert inner[0] == 0xA0
    assert inner[1] == len(inner) - 2 <= 0x7D
    assert inner[2] == 0x03
    text = inner[3:].decode()
    assert text.startswith("Info(0):--jablotron-api-server started at ")
    assert "F-Link" not in text
    assert "UUID={" in text


def test_the_verification_export_waits_for_the_panel_to_settle(monkeypatch, tmp_path: Path) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(tools.time, "sleep", sleeps.append)
    monkeypatch.setattr(tools, "pull_live_export_snapshot", lambda **k: "snapshot")
    assert (
        tools.pull_verification_export(
            verify_output=tmp_path / "v.bin", device="/dev/sdx", port="/dev/hidraw0", code="0000", reset=False, settle=1.5
        )
        == "snapshot"
    )
    assert sleeps == [1.5]


def test_write_config_over_hid_waits_for_the_ack() -> None:
    client = ScriptedClient([[bytes.fromhex("52a80dff0400b0010100")], [HID_ACK]])
    reply = tools.write_config_over_hid(client, HID_DELETE_PACKET[2:][2:], verbose=False)
    assert reply == HID_ACK
    assert client.sent == [HID_DELETE_PACKET]


def test_write_config_over_hid_fails_without_an_ack() -> None:
    client = ScriptedClient()
    with pytest.raises(SystemExit, match="did not answer the HID configuration write"):
        tools.write_config_over_hid(client, b"\xc0", verbose=False, timeout=0.01)


def test_write_config_over_hid_reports_an_unexpected_reply() -> None:
    client = ScriptedClient([[bytes.fromhex("1d03450000")]])
    with pytest.raises(SystemExit, match="rejected the HID configuration write: 1d03450000"):
        tools.write_config_over_hid(client, b"\xc0", verbose=False)


# ------------------------------------------------------- commit sequence


def _raw(monkeypatch, client: ScriptedClient) -> None:
    monkeypatch.setattr(
        tools, "perform_send_raw_report", lambda c, report_hex: client.sent.append(bytes.fromhex(report_hex).rstrip(b"\x00"))
    )


def test_accept_sends_80_01_14_after_the_panel_confirms_and_awaits_80_01_17(monkeypatch) -> None:
    client = ScriptedClient([[ACCEPT_CONFIRMED], [CONFIG_ESCAPED]])
    _raw(monkeypatch, client)

    tools.perform_accept_configuration(client, verbose=False)

    assert client.sent == [bytes.fromhex("52010c"), bytes.fromhex("800114")]


def test_accept_fails_when_the_panel_does_not_confirm(monkeypatch) -> None:
    client = ScriptedClient()
    _raw(monkeypatch, client)
    monkeypatch.setattr(tools.time, "time", _clock(step=1.0))

    with pytest.raises(SystemExit, match="did not confirm the configuration accept"):
        tools.perform_accept_configuration(client, verbose=False)

    assert bytes.fromhex("800114") not in client.sent


def test_import_accept_follows_the_captured_order(monkeypatch) -> None:
    client = ScriptedClient(
        [
            [],  # p1 drain after the first keepalive
            [IMPORT_PROGRESS_0, IMPORT_PROGRESS_100],
            [IMPORT_COMPLETE],
            [ACCEPT_CONFIRMED],
            [CONFIG_ESCAPED],
        ]
    )
    _raw(monkeypatch, client)

    tools.perform_import_accept_sequence(client, verbose=False)

    assert client.sent == [
        bytes.fromhex("520102"),
        bytes.fromhex("520124"),
        bytes.fromhex("520102"),
        bytes.fromhex("52010c"),
        bytes.fromhex("800114"),
    ]


def _clock(*, step: float):
    now = [1000.0]

    def fake_time() -> float:
        now[0] += step
        return now[0]

    return fake_time


# --------------------------------------------------- whole HID write session


def test_apply_config_payload_over_hid_runs_the_captured_session(monkeypatch, tmp_path: Path) -> None:
    calls: list = []
    client = ScriptedClient(
        [
            [REVISION_0X204F],
            [HID_ACK],
            [ACCEPT_CONFIRMED],
            [CONFIG_ESCAPED],
            [REVISION_0X2050],
        ]
    )
    _raw(monkeypatch, client)
    monkeypatch.setattr(tools, "ensure_serial_port", lambda port: port)
    monkeypatch.setattr(tools, "JablotronUSBClient", lambda port: client)
    monkeypatch.setattr(tools, "perform_login", lambda c, code, reset: calls.append(("login", code, reset)))
    monkeypatch.setattr(
        tools,
        "enter_setup_mode",
        lambda c, **k: calls.append(("setup",)) or tools.LoginRights(0x28, 100),
    )
    monkeypatch.setattr(tools, "graceful_exit_session", lambda c, **k: calls.append(("exit",)) or [])
    monkeypatch.setattr(tools, "cleanup_read_session", lambda **k: calls.append(("cleanup",)) or 0x90)
    monkeypatch.setattr(
        tools, "pull_live_export_snapshot", lambda **k: calls.append(("verify", k["device"], k["code"])) or "snapshot"
    )
    monkeypatch.setattr(tools, "POST_WRITE_EXPORT_SETTLE_SECONDS", 0.0)
    real_drain = tools.drain_packets
    monkeypatch.setattr(tools, "drain_packets", lambda c, **k: [] if k.get("prefix") in {"pre", "exit-post"} else real_drain(c, **k))

    result = tools.apply_config_payload_over_hid(
        payload=HID_DELETE_PACKET[4:],
        device="auto",
        port="auto",
        code="9146",
        reset=True,
        write_cleanup_mode="auto",
        verbose=False,
        verify_output=tmp_path / "verify.bin",
    )

    assert result == "snapshot"
    assert [call[0] for call in calls] == ["login", "setup", "exit", "cleanup", "verify"]
    assert client.sent == [
        tools.CONFIG_REVISION_QUERY_PACKET,
        HID_DELETE_PACKET,
        bytes.fromhex("52010c"),
        bytes.fromhex("800114"),
        tools.CONFIG_REVISION_QUERY_PACKET,
    ]


def test_storage_write_refuses_a_master_login_before_touching_the_volume(monkeypatch, tmp_path: Path) -> None:
    calls: list = []

    class FakeClient:
        def __init__(self, port: str) -> None:
            pass

        def close(self) -> None:
            calls.append(("close",))

    monkeypatch.setattr(tools, "resolve_flexi_cfg_device", lambda device: device)
    monkeypatch.setattr(tools, "is_device_mounted", lambda device: False)
    monkeypatch.setattr(tools, "mount_device", lambda *a, **k: calls.append(("mount",)))
    monkeypatch.setattr(tools, "unmount_device", lambda *a, **k: calls.append(("unmount",)))
    monkeypatch.setattr(tools, "ensure_serial_port", lambda port: port)
    monkeypatch.setattr(tools, "JablotronUSBClient", FakeClient)
    monkeypatch.setattr(tools, "perform_login", lambda c, code, reset: None)
    monkeypatch.setattr(tools, "drain_packets", lambda c, **k: [])
    monkeypatch.setattr(tools, "enter_setup_mode", lambda c, **k: tools.LoginRights(0x28, 100))
    monkeypatch.setattr(tools, "exit_write_session", lambda c, **k: calls.append(("exit",)) or 0x90)
    monkeypatch.setattr(tools, "stage_import", lambda *a: calls.append(("stage_import",)))
    monkeypatch.setattr(tools, "ensure_import_path_available", lambda **k: None)

    sector = tmp_path / "sector.bin"
    sector.write_bytes(b"\x00" * tools.SECTOR_SIZE)
    with pytest.raises(SystemExit, match="master rights .*JABLOTRON_PANEL_WRITE_TRANSPORT=hid"):
        tools.apply_import_sector(
            sector_path=sector,
            import_path=tmp_path / "flexi_cfg" / "IMPORT.CFG",
            device="/dev/sdb1",
            port="auto",
            code="9146",
            reset=True,
            mount_tool="sudo",
            stage_mode="filesystem",
            write_cleanup_mode="auto",
            verbose=False,
        )

    assert ("stage_import",) not in calls
    assert ("exit",) in calls, "the session leaves configuration mode before failing"


# ------------------------------------------------------ transport selection


def _config(tmp_path: Path, **overrides) -> UserManagerConfig:
    values = dict(
        import_path=tmp_path / "IMPORT.CFG",
        flexi_cfg_device="/dev/null",
        port="auto",
        auth_code="9146",
        write_auth_code="",
        reset=True,
        mount_tool="sudo",
        stage_mode="filesystem",
        write_cleanup_mode="auto",
        read_cleanup_mode="auto",
    )
    values.update(overrides)
    return UserManagerConfig(**values)


def test_auto_transport_follows_the_rights_the_panel_grants_the_write_code(monkeypatch, tmp_path: Path) -> None:
    probes: list = []

    def probe(**kwargs):
        probes.append(kwargs["code"])
        return tools.LoginRights(0x28, 100) if kwargs["code"] == "9146" else tools.LoginRights(0x2A, 7)

    monkeypatch.setattr(user_manager, "probe_login_rights", probe)

    assert user_manager.select_write_transport(_config(tmp_path)) == "hid"
    assert user_manager.select_write_transport(_config(tmp_path, write_auth_code="1812")) == "storage"
    assert probes == ["9146", "1812"], "the probe logs in with the code the write will use"


def test_auto_transport_falls_back_to_storage_when_rights_are_unknown(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(user_manager, "probe_login_rights", lambda **k: None)
    assert user_manager.select_write_transport(_config(tmp_path)) == "storage"


def test_explicit_transports_do_not_probe(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(user_manager, "probe_login_rights", lambda **k: pytest.fail("probed"))
    assert user_manager.select_write_transport(_config(tmp_path, write_transport="hid")) == "hid"
    assert user_manager.select_write_transport(_config(tmp_path, write_transport="storage")) == "storage"
    with pytest.raises(RuntimeError, match="Unsupported user write transport"):
        user_manager.select_write_transport(_config(tmp_path, write_transport="usb"))


def test_the_hid_transport_sends_the_sector_payload_with_the_write_code(monkeypatch, tmp_path: Path) -> None:
    sector = tmp_path / "sector.bin"
    sector.write_bytes(import_cfg_tool.encode_sector(import_cfg_tool.build_user_delete_payload(96)))
    sent: list = []
    monkeypatch.setattr(user_manager, "apply_config_payload_over_hid", lambda **kw: sent.append(kw))
    monkeypatch.setattr(user_manager, "apply_import_sector", lambda **kw: pytest.fail("storage path used"))

    user_manager.write_sector_to_panel(
        _config(tmp_path, write_transport="hid", write_auth_code="4455"), sector_path=sector, verify_prefix="t"
    )

    assert len(sent) == 1
    assert sent[0]["payload"] == HID_DELETE_PACKET[4:]
    assert sent[0]["code"] == "4455"
    assert sent[0]["device"] == "/dev/null"


def test_apply_sector_dispatches_the_cli_write_by_transport(monkeypatch, tmp_path: Path) -> None:
    sector = tmp_path / "sector.bin"
    sector.write_bytes(import_cfg_tool.encode_sector(import_cfg_tool.build_user_delete_payload(96)))
    hid_calls: list = []
    storage_calls: list = []
    monkeypatch.setattr(tools, "apply_config_payload_over_hid", lambda **kw: hid_calls.append(kw))
    monkeypatch.setattr(tools, "apply_import_sector", lambda **kw: storage_calls.append(kw))
    monkeypatch.setattr(tools, "probe_login_rights", lambda **kw: tools.LoginRights(0x28, 100))

    common = dict(
        sector_path=sector,
        import_path=tmp_path / "IMPORT.CFG",
        device="auto",
        port="auto",
        code="9146",
        reset=True,
        mount_tool="sudo",
        stage_mode="filesystem",
        write_cleanup_mode="auto",
        verbose=False,
    )
    tools.apply_sector(transport="auto", **common)
    tools.apply_sector(transport="storage", **common)

    assert len(hid_calls) == 1 and hid_calls[0]["payload"] == HID_DELETE_PACKET[4:]
    assert len(storage_calls) == 1 and storage_calls[0]["sector_path"] == sector
    with pytest.raises(SystemExit, match="Unsupported write transport"):
        tools.apply_sector(transport="usb", **common)


def test_the_transport_setting_reaches_the_user_manager() -> None:
    runtime = PanelRuntime(PanelRuntimeConfig(port="auto", auth_code="9146", write_transport="hid"))
    assert runtime._user_manager_config().write_transport == "hid"
    assert PanelSettings(auth_code="9146").write_transport == "auto"
    # PanelSettings is what production hands to PanelRuntime; the field must exist on both.
    assert PanelRuntime(PanelSettings(auth_code="9146", write_transport="storage"))._user_manager_config().write_transport == "storage"


def test_the_in_session_switch_is_read_from_the_environment(monkeypatch) -> None:
    """JABLOTRON_PANEL_IN_SESSION_CONFIG_OPS is the rollback for the in-session
    write: it must default on, parse like the other boolean settings, and
    reach the runtime through PanelSettings."""

    monkeypatch.delenv("JABLOTRON_PANEL_IN_SESSION_CONFIG_OPS", raising=False)
    assert ServerSettings().panel.in_session_config_ops is True
    for value in ("false", "0", "no", "False"):
        monkeypatch.setenv("JABLOTRON_PANEL_IN_SESSION_CONFIG_OPS", value)
        assert ServerSettings().panel.in_session_config_ops is False, value
    monkeypatch.setenv("JABLOTRON_PANEL_IN_SESSION_CONFIG_OPS", "true")
    assert ServerSettings().panel.in_session_config_ops is True

    assert PanelRuntime(PanelSettings(auth_code="9146"))._config.in_session_config_ops is True
    assert PanelRuntime(PanelSettings(auth_code="9146", in_session_config_ops=False))._config.in_session_config_ops is False


# ---------------------------------------------- in-session write plumbing


def test_enter_setup_mode_assume_logged_in_sends_the_nudge_without_a_login_reply(monkeypatch) -> None:
    """The status session logged in long ago; its 80 1A 0C is gone. The first
    80 01 0F goes out at once, the rest of the handshake is unchanged."""

    client = ScriptedClient([[bytes.fromhex("80021a0a")], [bytes.fromhex("800112")]])
    reports: list[bytes] = []
    monkeypatch.setattr(
        tools, "perform_send_raw_report", lambda c, report_hex: reports.append(bytes.fromhex(report_hex).rstrip(b"\x00"))
    )

    assert tools.enter_setup_mode(client, verbose=False, assume_logged_in=True) is None

    assert reports == [bytes.fromhex("80010f"), bytes.fromhex("80010f")]
    assert client.sent == []


def test_accept_reports_whether_the_panel_left_configuration_mode(monkeypatch) -> None:
    client = ScriptedClient([[ACCEPT_CONFIRMED], [CONFIG_ESCAPED]])
    _raw(monkeypatch, client)
    assert tools.perform_accept_configuration(client, verbose=False) is True

    client = ScriptedClient([[ACCEPT_CONFIRMED]])
    _raw(monkeypatch, client)
    monkeypatch.setattr(tools.time, "time", _clock(step=1.0))
    assert tools.perform_accept_configuration(client, verbose=False) is False, "a missing 80 01 17 warns, it does not raise"
    assert client.sent == [bytes.fromhex("52010c"), bytes.fromhex("800114")]


class FakeSession:
    """The status session as write_sector_to_panel sees it."""

    def __init__(self, rights=None) -> None:
        self.writes: list[tuple[bytes, str | None]] = []
        self.closes = 0
        self.rights = rights
        self.rights_requests: list[str] = []

    def login_rights_for_code(self, code: str):
        self.rights_requests.append(code)
        return self.rights

    def write_configuration(self, payload: bytes, *, code: str | None = None) -> int | None:
        self.writes.append((payload, code))
        return 0x2050

    def close(self) -> None:
        self.closes += 1


def _delete_sector(tmp_path: Path) -> Path:
    sector = tmp_path / "sector.bin"
    sector.write_bytes(import_cfg_tool.encode_sector(import_cfg_tool.build_user_delete_payload(96)))
    return sector


def test_write_sector_to_panel_uses_the_session_for_hid_when_the_codes_match(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(user_manager, "apply_config_payload_over_hid", lambda **kw: pytest.fail("separate client used"))
    monkeypatch.setattr(user_manager, "apply_import_sector", lambda **kw: pytest.fail("storage path used"))
    monkeypatch.setattr(user_manager, "probe_login_rights", lambda **kw: pytest.fail("probed"))
    session = FakeSession()

    user_manager.write_sector_to_panel(
        _config(tmp_path, write_transport="hid"), sector_path=_delete_sector(tmp_path), verify_prefix="t", session=session
    )

    assert session.writes == [(HID_DELETE_PACKET[4:], "9146")]
    assert session.closes == 0


def test_write_sector_to_panel_falls_back_to_a_separate_client_when_the_write_code_differs(
    monkeypatch, tmp_path: Path
) -> None:
    sent: list = []
    monkeypatch.setattr(user_manager, "apply_config_payload_over_hid", lambda **kw: sent.append(kw))
    monkeypatch.setattr(user_manager, "apply_import_sector", lambda **kw: pytest.fail("storage path used"))
    session = FakeSession()
    config = _config(tmp_path, write_transport="hid", write_auth_code="4455")
    assert user_manager.session_code_matches(config) is False
    assert user_manager.session_code_matches(_config(tmp_path)) is True
    assert user_manager.session_code_matches(_config(tmp_path, write_auth_code="9146")) is True

    user_manager.write_sector_to_panel(config, sector_path=_delete_sector(tmp_path), verify_prefix="t", session=session)

    assert session.writes == []
    assert session.closes == 1, "the separate client needs the bus to itself"
    assert len(sent) == 1
    assert sent[0]["code"] == "4455"
    assert sent[0]["payload"] == HID_DELETE_PACKET[4:]
    assert sent[0]["verify_output"] is None, "no verification export in the server path"


def test_storage_transport_closes_the_session_and_skips_the_verification_export(monkeypatch, tmp_path: Path) -> None:
    staged: list = []
    monkeypatch.setattr(user_manager, "apply_config_payload_over_hid", lambda **kw: pytest.fail("hid path used"))
    monkeypatch.setattr(user_manager, "apply_import_sector", lambda **kw: staged.append(kw))
    session = FakeSession()

    user_manager.write_sector_to_panel(
        _config(tmp_path, write_transport="storage"), sector_path=_delete_sector(tmp_path), verify_prefix="t", session=session
    )

    assert session.writes == []
    assert session.closes == 1
    assert len(staged) == 1 and staged[0]["verify_output"] is None


def test_write_sector_to_panel_probes_when_the_session_has_no_rights(monkeypatch, tmp_path: Path) -> None:
    """Without rights from the session the probe logs in with its own client,
    so the session is closed first; a master result still writes in-session
    (the session logs in again on first use)."""

    order: list[str] = []
    session = FakeSession()
    monkeypatch.setattr(user_manager, "probe_login_rights", lambda **kw: order.append(f"probe:{session.closes}") or tools.LoginRights(0x28, 100))
    monkeypatch.setattr(user_manager, "apply_config_payload_over_hid", lambda **kw: pytest.fail("separate client used"))
    monkeypatch.setattr(user_manager, "apply_import_sector", lambda **kw: pytest.fail("storage path used"))

    user_manager.write_sector_to_panel(_config(tmp_path), sector_path=_delete_sector(tmp_path), verify_prefix="t", session=session)

    assert order == ["probe:1"], "the session was closed before the probe logged in"
    assert session.rights_requests == ["9146"]
    assert session.writes == [(HID_DELETE_PACKET[4:], "9146")]


def test_write_sector_to_panel_without_a_session_keeps_the_separate_client_path(monkeypatch, tmp_path: Path) -> None:
    sent: list = []
    monkeypatch.setattr(user_manager, "apply_config_payload_over_hid", lambda **kw: sent.append(kw))

    user_manager.write_sector_to_panel(_config(tmp_path, write_transport="hid"), sector_path=_delete_sector(tmp_path), verify_prefix="t")

    assert len(sent) == 1 and sent[0]["verify_output"] is None


# ------------------------------------------- rights from the status session


def test_auto_transport_uses_the_session_rights_without_probing(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(user_manager, "probe_login_rights", lambda **kw: pytest.fail("probed"))

    assert user_manager.select_write_transport(_config(tmp_path), session_rights=tools.LoginRights(0x28, 100)) == "hid"
    assert user_manager.select_write_transport(_config(tmp_path), session_rights=tools.LoginRights(0x2A, 7)) == "storage"
    # The same write code configured explicitly still counts as the session code.
    assert (
        user_manager.select_write_transport(
            _config(tmp_path, write_auth_code="9146"), session_rights=tools.LoginRights(0x28, 100)
        )
        == "hid"
    )


def test_auto_transport_ignores_session_rights_when_the_write_code_differs(monkeypatch, tmp_path: Path) -> None:
    probes: list = []
    monkeypatch.setattr(user_manager, "probe_login_rights", lambda **kw: probes.append(kw["code"]) or tools.LoginRights(0x2A, 7))

    chosen = user_manager.select_write_transport(
        _config(tmp_path, write_auth_code="1812"), session_rights=tools.LoginRights(0x28, 100)
    )

    assert chosen == "storage", "the probe's answer for the write code decides, not the session's rights"
    assert probes == ["1812"]


def test_explicit_transports_ignore_session_rights(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(user_manager, "probe_login_rights", lambda **kw: pytest.fail("probed"))
    assert (
        user_manager.select_write_transport(
            _config(tmp_path, write_transport="storage"), session_rights=tools.LoginRights(0x28, 100)
        )
        == "storage"
    )


def test_write_sector_to_panel_auto_writes_in_session_for_master_rights(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(user_manager, "probe_login_rights", lambda **kw: pytest.fail("probed"))
    monkeypatch.setattr(user_manager, "apply_config_payload_over_hid", lambda **kw: pytest.fail("separate client used"))
    monkeypatch.setattr(user_manager, "apply_import_sector", lambda **kw: pytest.fail("storage path used"))
    session = FakeSession(rights=tools.LoginRights(0x28, 100))

    user_manager.write_sector_to_panel(_config(tmp_path), sector_path=_delete_sector(tmp_path), verify_prefix="t", session=session)

    assert session.rights_requests == ["9146"]
    assert session.writes == [(HID_DELETE_PACKET[4:], "9146")]
    assert session.closes == 0


def test_write_sector_to_panel_auto_closes_the_session_for_arc_rights(monkeypatch, tmp_path: Path) -> None:
    order: list[str] = []
    session = FakeSession(rights=tools.LoginRights(0x2A, 7))
    monkeypatch.setattr(user_manager, "probe_login_rights", lambda **kw: pytest.fail("probed"))
    monkeypatch.setattr(user_manager, "apply_config_payload_over_hid", lambda **kw: pytest.fail("hid path used"))
    monkeypatch.setattr(user_manager, "apply_import_sector", lambda **kw: order.append((f"stage:{session.closes}", kw)))

    user_manager.write_sector_to_panel(_config(tmp_path), sector_path=_delete_sector(tmp_path), verify_prefix="t", session=session)

    assert session.writes == []
    assert session.closes == 1
    assert [step for step, _ in order] == ["stage:1"], "the session was closed before the storage write logged in"
    assert order[0][1]["verify_output"] is None
    assert order[0][1]["code"] == "9146"


def test_write_sector_to_panel_does_not_ask_the_session_when_the_write_code_differs(monkeypatch, tmp_path: Path) -> None:
    order: list[str] = []
    session = FakeSession(rights=tools.LoginRights(0x28, 100))
    monkeypatch.setattr(
        user_manager, "probe_login_rights", lambda **kw: order.append(f"probe:{session.closes}:{kw['code']}") or tools.LoginRights(0x28, 100)
    )
    monkeypatch.setattr(user_manager, "apply_config_payload_over_hid", lambda **kw: order.append(f"hid:{kw['code']}"))
    monkeypatch.setattr(user_manager, "apply_import_sector", lambda **kw: pytest.fail("storage path used"))

    user_manager.write_sector_to_panel(
        _config(tmp_path, write_auth_code="1812"), sector_path=_delete_sector(tmp_path), verify_prefix="t", session=session
    )

    assert session.rights_requests == [], "the session is logged in with another code"
    assert order == ["probe:1:1812", "hid:1812"]
    assert session.writes == []
