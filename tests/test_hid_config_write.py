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
from jablotron_api.server.config import PanelSettings
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


def test_a_payload_that_does_not_fit_one_report_is_refused() -> None:
    with pytest.raises(SystemExit, match="does not fit one HID report"):
        tools.build_hid_config_write_packet(b"\x00" * (tools.HID_CONFIG_WRITE_MAX_PAYLOAD + 1))


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
