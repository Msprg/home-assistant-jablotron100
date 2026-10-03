"""The HID configuration write running inside the persistent status session.

The panel is a scripted client; the assertions are about which bytes go out
in which order, that every packet read on the way still reaches the live
device-state parser (motion keeps publishing while the write holds the bus),
and that the session's channel ends every write in a known state: kept and
re-armed after a fully confirmed write, reset (graceful exit + re-login) on
every failure path and whenever the panel did not acknowledge leaving
configuration mode. The export trigger and the login-rights lookup the
``auto`` transport relies on run through the same session. No test opens
hardware: the USB client, the port lookup and the login helpers are replaced.
"""

from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace

import pytest

import jablotron_re_tools as tools
from jablotron_api.domain.models import DeviceStatusModel
from jablotron_api.panel.runtime import _run_panel_write
from jablotron_api.protocol import legacy
from jablotron_api.protocol.legacy import (
    MOTION_ON_MIN_DWELL_SECONDS,
    ConfigWriteError,
    ExportRefreshIncomplete,
    PersistentSnapshotSession,
    WrongCodeError,
    _SessionTeeClient,
)
from jablotron_api.services import catalog_io, user_manager

# A private name, imported on purpose: the retry in pull_catalog_snapshot
# recognises a stalled export only by this text in the error message, so the
# test has to check the session's error against the exact marker it uses.
from jablotron_api.services.catalog_io import _RELOAD_STALL_MARKER
from jablotron_usb_debug import Jablotron, JablotronUSBStreamError, build_logon_info_reports, perform_sections_query
from test_hid_config_write import (
    ACCEPT_CONFIRMED,
    CONFIG_ESCAPED,
    HID_ACK,
    HID_DELETE_PACKET,
    LOGIN_MASTER_POSITION_100,
    REVISION_0X204F,
    REVISION_0X2050,
    _clock,
    _config,
    _delete_sector,
)

# Panel replies.
SETUP_1A0A = bytes.fromhex("80021a0a")
SETUP_ENTERED = bytes.fromhex("800112")
CONFIG_IN_USE = b"\x73\x09" + bytes(6) + b"\x94\x00\x00"  # system-state packet reporting 0x94
D8_ON = b"\xd8\x01"
D8_OFF = b"\xd8\x00"
D8_PACKET = D8_ON

# Raw reports and packets we send.
R_80010F = bytes.fromhex("80010f")
R_52010C = bytes.fromhex("52010c")
R_800114 = bytes.fromhex("800114")
REVISION_QUERY = tools.CONFIG_REVISION_QUERY_PACKET
ENABLE_DEVICE_STATES = Jablotron.create_packet_enable_device_states()
EXIT_SEQUENCE = [
    bytes.fromhex("94020100"),
    Jablotron.create_packet_ui_control(b"\x01"),
    Jablotron.create_packet_command(b"\x0e"),
    Jablotron.create_packet_command(b"\x02"),
]
PAYLOAD = HID_DELETE_PACKET[4:]

# Export trigger (F-Link's refresh sequence) and the finish step after the read.
RELOAD_COMPLETE = bytes.fromhex("5207830125")
R_520102 = bytes.fromhex("520102")
R_520213059A00 = bytes.fromhex("520213059a")  # ScriptedClient strips the report's zero padding, trailing 00 included
R_520125 = bytes.fromhex("520125")
R_800102 = bytes.fromhex("800102")
SECTIONS_QUERY = Jablotron.create_packet_command(b"\x0e")
SECTIONS_EXITED = b"\x51\x02" + bytes(2) + bytes([tools.EXITED_SECTIONS_MODE])
SECTIONS_CONFIG_ACTIVE = b"\x51\x02" + bytes(2) + bytes([tools.CONFIGURATION_SECTIONS_MODE])


class ScriptedClient:
    """Answers reads from a positional script and, optionally, queues a reply
    batch when a given packet or raw report goes out. Records everything sent;
    raw reports arrive through ``_write`` and are stored without padding.
    ``reads_at_send[i]`` is the read count when ``sent[i]`` went out, so a test
    can tell whether the channel was polled between two packets."""

    def __init__(self, reads=None, *, replies=None) -> None:
        self.reads = list(reads or [])
        self.replies = {key: list(batches) for key, batches in (replies or {}).items()}
        self.sent: list[bytes] = []
        self.read_calls = 0
        self.reads_at_send: list[int] = []
        self.closed = False

    def read_packets(self, *, timeout=None):
        self.read_calls += 1
        if not self.reads:
            return iter(())
        batch = self.reads.pop(0)
        if isinstance(batch, BaseException):
            raise batch
        return iter(batch)

    def _queue_reply(self, packet: bytes) -> None:
        batches = self.replies.get(packet)
        if batches:
            self.reads.insert(0, batches.pop(0))

    def send_packet(self, packet: bytes) -> None:
        self.sent.append(packet)
        self.reads_at_send.append(self.read_calls)
        self._queue_reply(packet)

    def send_packets(self, packets) -> None:
        for packet in packets:
            self.send_packet(packet)

    def _write(self, report: bytes) -> None:
        stripped = report.rstrip(b"\x00")
        self.sent.append(stripped)
        self.reads_at_send.append(self.read_calls)
        self._queue_reply(stripped)

    def close(self) -> None:
        self.closed = True


def _harness(monkeypatch, client, *, reopen_clients=(), reopen_error=None, rights_captured=True, fresh_login=True):
    """A session that has just logged in on ``client`` (no login runs for the
    write itself) with one motion device whose live parser flips on a d8
    packet. Reopens construct the next prepared client, or fail with
    reopen_error. ``rights_captured`` records the login-rights reply of that
    login, as the login drain would have; the tests about capturing it pass
    False. ``fresh_login=False`` is the warm status session: logged in long
    ago, so a configuration operation has to log in again first."""

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(tools.time, "sleep", lambda seconds: None)
    pending = list(reopen_clients)
    constructed: list = []
    logins: list = []

    def factory(port):
        if reopen_error is not None:
            raise reopen_error
        assert pending, "the test prepared no client for this reopen"
        reopened = pending.pop(0)
        constructed.append(reopened)
        return reopened

    monkeypatch.setattr(legacy, "JablotronUSBClient", factory)
    monkeypatch.setattr(legacy, "perform_login", lambda c, code, *, reset: logins.append((c, code, reset)))
    monkeypatch.setattr(legacy, "perform_sections_query", lambda c: None)

    session = PersistentSnapshotSession(port="auto", code="1812", reset=True)
    # The stream thread is exercised in test_device_state_stream; here every
    # read must come from the test thread so the scripts stay deterministic.
    monkeypatch.setattr(session, "_ensure_keepalive_thread_locked", lambda: None)
    session._client = client
    session._authorized_code = "1812"
    if fresh_login:
        session._fresh_login_at = legacy.time.monotonic()
    if rights_captured:
        session._login_rights = tools.LoginRights(0x28, 100)
        session._login_rights_code = "1812"
    session.configure_live_devices(
        [DeviceStatusModel(id=4, name="PIR", inferred_entity_type="motion", state="off")],
        pg_count=0,
        panel_model="JA-107K",
    )

    def parse(packet, *, pg_count):
        if packet[:1] == b"\xd8":
            session._live_parser.devices_by_id[4].state = "on" if packet[1:2] != b"\x00" else "off"

    monkeypatch.setattr(session._live_parser, "parse_packet", parse)
    # The stream reader would have latched the baseline long before a write;
    # pre-latch it so the first packet through the tee does not publish "off".
    session._latched_states[4] = "off"
    frames: list[dict[int, str]] = []
    session.set_on_device_state_change(frames.append)
    return SimpleNamespace(session=session, frames=frames, logins=logins, constructed=constructed)


def _success_replies(*, escape=True, revision_after=REVISION_0X2050):
    """Reply-driven script for a complete write; the escape reply is optional."""

    replies = {
        R_80010F: [[SETUP_1A0A], [SETUP_ENTERED]],
        REVISION_QUERY: [[REVISION_0X204F], [revision_after]],
        HID_DELETE_PACKET: [[HID_ACK]],
        R_52010C: [[ACCEPT_CONFIRMED]],
    }
    if escape:
        replies[R_800114] = [[CONFIG_ESCAPED]]
    return replies


def _exit_sequence_sent_after(sent: list[bytes], marker: bytes) -> bool:
    index = len(sent) - 1 - sent[::-1].index(marker)
    return sent[index + 1 : index + 5] == EXIT_SEQUENCE


# ------------------------------------------------------------ happy path


def test_write_configuration_runs_the_captured_sequence_and_keeps_streaming(monkeypatch) -> None:
    client = ScriptedClient(
        [
            [SETUP_1A0A],
            [SETUP_ENTERED],
            [REVISION_0X204F],
            [D8_PACKET, HID_ACK],  # motion pushed while the ack is awaited
            [ACCEPT_CONFIRMED],
            [CONFIG_ESCAPED],
            [REVISION_0X2050],
        ]
    )
    h = _harness(monkeypatch, client)
    seen_at: list[tuple[dict[int, str], int]] = []
    h.session.set_on_device_state_change(lambda frame: seen_at.append((dict(frame), len(client.sent))))

    assert h.session.write_configuration(PAYLOAD) == 0x2050

    assert client.sent == [
        R_80010F,
        R_80010F,
        REVISION_QUERY,
        HID_DELETE_PACKET,
        R_52010C,
        R_800114,
        REVISION_QUERY,
        ENABLE_DEVICE_STATES,  # the 0x13 re-arm after 80 01 14 / 80 01 17
    ]
    assert EXIT_SEQUENCE[0] not in client.sent, "a confirmed write keeps the channel"
    # The motion edge was published during the write step, before the ack was consumed.
    assert seen_at == [({4: "on"}, 4)]
    assert h.session._client is client
    assert h.constructed == [] and h.logins == []
    assert h.session._last_enable_device_states_at > 0


def test_the_bounce_flag_restores_the_exit_shape_after_a_confirmed_write(monkeypatch) -> None:
    monkeypatch.setattr(legacy, "BOUNCE_AFTER_SUCCESSFUL_WRITE", True)
    client = ScriptedClient(replies=_success_replies())
    client2 = ScriptedClient([[]])
    h = _harness(monkeypatch, client, reopen_clients=[client2])

    assert h.session.write_configuration(PAYLOAD) == 0x2050

    assert client.sent[:7] == [R_80010F, R_80010F, REVISION_QUERY, HID_DELETE_PACKET, R_52010C, R_800114, REVISION_QUERY]
    assert client.sent[7:] == EXIT_SEQUENCE
    assert h.logins == [(client2, "1812", True)]
    assert h.session._client is client2
    assert h.session._last_enable_device_states_at > 0


class _DepthTrackingLock:
    """Wraps the session's RLock and records every moment it is fully released
    (nesting depth back at 0) together with how far the write had got by then.
    A per-step lock would show a full release between steps; one whole-write
    hold shows exactly one, at the very end."""

    def __init__(self, inner, progress) -> None:
        self._inner = inner
        self._progress = progress
        self.depth = 0
        self.full_releases: list = []

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        acquired = self._inner.acquire(blocking, timeout)
        if acquired:
            self.depth += 1
        return acquired

    def release(self) -> None:
        self._inner.release()
        self.depth -= 1
        if self.depth == 0:
            self.full_releases.append(self._progress())

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()

    def _is_owned(self) -> bool:
        return self._inner._is_owned()


def _track_lock_depth(session, clients, progress):
    """Swap the session's lock for a _DepthTrackingLock and record its depth
    at every read and every send (packets and raw reports) on ``clients``."""

    lock = _DepthTrackingLock(session._io_lock, progress)
    session._io_lock = lock
    depth_at_read: list[int] = []
    depth_at_send: list[int] = []
    for scripted in clients:
        original_read = scripted.read_packets
        original_send = scripted.send_packet
        original_write = scripted._write

        def read_packets(*, timeout=None, _original=original_read):
            depth_at_read.append(lock.depth)
            return _original(timeout=timeout)

        def send_packet(packet: bytes, _original=original_send) -> None:
            depth_at_send.append(lock.depth)
            _original(packet)

        def _write(report: bytes, _original=original_write) -> None:
            depth_at_send.append(lock.depth)
            _original(report)

        scripted.read_packets = read_packets
        scripted.send_packet = send_packet
        scripted._write = _write
    return lock, depth_at_read, depth_at_send


@pytest.mark.parametrize("bounce", [False, True], ids=["keep-channel", "bounce"])
def test_write_configuration_holds_the_io_lock_for_the_whole_write(monkeypatch, bounce) -> None:
    """One lock hold from the first 80 01 0F to the end of the write: the
    0x13 re-arm on the kept channel, or the reopen's drain with the bounce
    flag. A lock taken and released around each step would pass a per-read
    ownership check but let the stream thread slip a keepalive or the 0x13
    re-enable into the setup/accept handshake."""

    monkeypatch.setattr(legacy, "BOUNCE_AFTER_SUCCESSFUL_WRITE", bounce)
    client = ScriptedClient(replies=_success_replies())
    client2 = ScriptedClient([[]]) if bounce else None
    h = _harness(monkeypatch, client, reopen_clients=[client2] if bounce else [])

    def progress():
        return (len(client.sent), client.read_calls, client2.read_calls if client2 is not None else None)

    clients = [client, client2] if bounce else [client]
    lock, depth_at_read, depth_at_send = _track_lock_depth(h.session, clients, progress)

    h.session.write_configuration(PAYLOAD)

    assert client.sent[0] == R_80010F and depth_at_send[0] >= 1, "the lock was taken before the first 80 01 0F"
    assert depth_at_read and min(depth_at_read) >= 1
    assert min(depth_at_send) >= 1
    if bounce:
        assert client2.read_calls >= 1, "the reopen drained the new client"
    else:
        assert h.constructed == []
        assert client.sent[-1] == ENABLE_DEVICE_STATES, "the 0x13 re-arm is the last thing sent"
        assert depth_at_send[-1] >= 1, "the re-arm went out under the same hold"
    # The lock dropped to depth 0 exactly once: when write_configuration
    # returned, after every send and every read had happened.
    assert lock.full_releases == [progress()]
    assert not lock._is_owned()


def test_a_chunked_write_goes_out_back_to_back_under_one_lock_hold(monkeypatch) -> None:
    """A payload too long for one report goes out as the 48/49/4A chunks,
    consecutively and under the same lock hold as the rest of the write; the
    single ack comes after the last chunk, and motion read while it is
    awaited is still published."""

    payload = bytes((index % 250) + 1 for index in range(196))
    reports = [report.rstrip(b"\x00") for report in tools.build_hid_config_write_reports(payload)]
    assert len(reports) > 1, "the payload must need chunking"
    replies = _success_replies()
    del replies[HID_DELETE_PACKET]
    replies[reports[-1]] = [[D8_ON, HID_ACK]]
    client = ScriptedClient(replies=replies)
    h = _harness(monkeypatch, client)
    seen_at: list[tuple[dict[int, str], int]] = []
    h.session.set_on_device_state_change(lambda frame: seen_at.append((dict(frame), len(client.sent))))

    def progress():
        return (len(client.sent), client.read_calls)

    lock, depth_at_read, depth_at_send = _track_lock_depth(h.session, [client], progress)

    assert h.session.write_configuration(payload) == 0x2050

    assert client.sent == [
        R_80010F,
        R_80010F,
        REVISION_QUERY,
        *reports,
        R_52010C,
        R_800114,
        REVISION_QUERY,
        ENABLE_DEVICE_STATES,
    ]
    assert seen_at == [({4: "on"}, 3 + len(reports))]
    chunk_slice = slice(3, 3 + len(reports))
    assert all(depth >= 1 for depth in depth_at_send[chunk_slice])
    # No read between the chunks: they go out back to back.
    assert len(set(client.reads_at_send[chunk_slice])) == 1
    assert lock.full_releases == [progress()], "the lock never dropped to 0 between chunk reports"


def _fresh_login_harness(monkeypatch, reads):
    """A closed session whose write has to log in first, on a client that
    answers the login drain from ``reads`` and the write from the success
    script. Records every sleep with how many packets had gone out by then."""

    client = ScriptedClient(reads, replies=_success_replies())
    h = _harness(monkeypatch, ScriptedClient(), reopen_clients=[client], rights_captured=False)
    h.session._client = None
    h.session._authorized_code = None
    sleeps: list[tuple[float, int]] = []
    monkeypatch.setattr(legacy.time, "sleep", lambda seconds: sleeps.append((seconds, len(client.sent))))
    return h, client, sleeps


def _nudge_sleeps(sleeps):
    return [entry for entry in sleeps if entry[0] == tools.SETUP_MODE_NUDGE_DELAY]


def test_a_write_that_logs_in_waits_the_nudge_delay_before_80_01_0f(monkeypatch) -> None:
    # The login drain captures the rights reply, so no extra read is made.
    h, client, sleeps = _fresh_login_harness(monkeypatch, [[LOGIN_MASTER_POSITION_100], []])

    assert h.session.write_configuration(PAYLOAD) == 0x2050

    assert h.constructed == [client]
    assert client.sent[:2] == [ENABLE_DEVICE_STATES, R_80010F]
    assert client.reads_at_send[1] == 2, "the 80 01 0F followed the login drain without an extra read"
    assert _nudge_sleeps(sleeps) == [(tools.SETUP_MODE_NUDGE_DELAY, 1)], (
        "one nudge delay, after the login and before the first 80 01 0F"
    )


def test_a_write_that_logs_in_waits_for_a_late_login_reply(monkeypatch) -> None:
    # The drain's first read is quiet; the rights reply comes on the next read.
    h, client, sleeps = _fresh_login_harness(monkeypatch, [[], [LOGIN_MASTER_POSITION_100]])

    assert h.session.write_configuration(PAYLOAD) == 0x2050

    assert h.session._login_rights_code == "1812"
    assert client.sent[:2] == [ENABLE_DEVICE_STATES, R_80010F]
    assert client.reads_at_send[1] >= 2, "the first 80 01 0F went out only after the read that carried 80 1A 0C"
    assert client.sent[2:] == [R_80010F, REVISION_QUERY, HID_DELETE_PACKET, R_52010C, R_800114, REVISION_QUERY, ENABLE_DEVICE_STATES]
    assert _nudge_sleeps(sleeps) == [(tools.SETUP_MODE_NUDGE_DELAY, 1)]


def test_a_write_on_an_open_channel_adds_no_wait(monkeypatch) -> None:
    client = ScriptedClient(replies=_success_replies())
    h = _harness(monkeypatch, client)
    sleeps: list[float] = []
    monkeypatch.setattr(legacy.time, "sleep", sleeps.append)

    assert h.session.write_configuration(PAYLOAD) == 0x2050

    assert client.reads_at_send[0] == 0, "nothing was read before the first 80 01 0F"
    assert tools.SETUP_MODE_NUDGE_DELAY not in sleeps


def test_a_missing_80_01_17_on_success_reports_success_after_the_reset(monkeypatch, caplog) -> None:
    client = ScriptedClient(replies=_success_replies(escape=False))
    client2 = ScriptedClient([[]])
    h = _harness(monkeypatch, client, reopen_clients=[client2])
    monkeypatch.setattr(tools.time, "time", _clock(step=0.5))

    with caplog.at_level(logging.WARNING, logger="jablotron_api.protocol.legacy"):
        assert h.session.write_configuration(PAYLOAD) == 0x2050

    assert "did not acknowledge leaving configuration mode after the write" in caplog.text
    assert _exit_sequence_sent_after(client.sent, REVISION_QUERY)
    assert h.session._client is client2


def test_a_failed_post_write_re_arm_resets_the_channel_and_still_reports_success(monkeypatch, caplog) -> None:
    """The write is already applied when the 0x13 re-arm fails: the failure
    must not turn an applied change into a 409, and the channel must not be
    left half-dead, so the session resets it (graceful exit + re-login)."""

    client = ScriptedClient(replies=_success_replies())
    client2 = ScriptedClient([[]])
    h = _harness(monkeypatch, client, reopen_clients=[client2])
    real_enable = legacy.perform_enable_device_states
    enable_calls: list = []

    def flaky_enable(c):
        enable_calls.append(c)
        if len(enable_calls) == 1:
            raise JablotronUSBStreamError("USB write failed on /dev/fakehid")
        real_enable(c)

    monkeypatch.setattr(legacy, "perform_enable_device_states", flaky_enable)

    with caplog.at_level(logging.WARNING, logger="jablotron_api.protocol.legacy"):
        assert h.session.write_configuration(PAYLOAD) == 0x2050

    assert "Could not re-arm the device-state subscription" in caplog.text
    assert enable_calls == [client, client2], "the failed re-arm, then the reopen's own 0x13"
    assert ENABLE_DEVICE_STATES not in client.sent
    assert _exit_sequence_sent_after(client.sent, REVISION_QUERY)
    assert ENABLE_DEVICE_STATES in client2.sent
    assert h.session._client is client2
    assert h.logins == [(client2, "1812", True)]
    assert h.session._last_enable_device_states_at > 0


def test_a_live_parser_error_during_the_write_does_not_abort_it(monkeypatch) -> None:
    client = ScriptedClient(replies=_success_replies())
    client.replies[HID_DELETE_PACKET] = [[D8_PACKET, HID_ACK]]
    h = _harness(monkeypatch, client)

    def broken(packet, *, pg_count):
        if packet[:1] == b"\xd8":
            raise ValueError("malformed bitmap")

    monkeypatch.setattr(h.session._live_parser, "parse_packet", broken)

    assert h.session.write_configuration(PAYLOAD) == 0x2050
    assert h.session._client is client


# ------------------------------------------------------------ failure paths


class _LeaveAwareClient(ScriptedClient):
    """Answers the error-path 80 01 14 with 80 01 17."""

    def _write(self, report: bytes) -> None:
        super()._write(report)
        if report.rstrip(b"\x00") == R_800114:
            self.reads.insert(0, [CONFIG_ESCAPED])


def test_a_missing_ack_leaves_setup_mode_then_resets_the_channel(monkeypatch) -> None:
    client = _LeaveAwareClient([[SETUP_1A0A], [SETUP_ENTERED], [REVISION_0X204F]])
    client2 = ScriptedClient([[]])
    h = _harness(monkeypatch, client, reopen_clients=[client2])
    monkeypatch.setattr(tools.time, "time", _clock(step=1.0))

    with pytest.raises(ConfigWriteError, match="did not answer the HID configuration write"):
        h.session.write_configuration(PAYLOAD)

    assert client.sent[:4] == [R_80010F, R_80010F, REVISION_QUERY, HID_DELETE_PACKET]
    assert client.sent.count(R_800114) == 1
    assert client.sent[4:] == [R_800114, *EXIT_SEQUENCE]
    assert h.session._client is client2
    assert h.logins == [(client2, "1812", True)]


def test_an_unconfirmed_accept_leaves_setup_mode_then_resets_the_channel(monkeypatch) -> None:
    """52 01 0C draws no 52 03 83 01 02. The accept step raises before it ever
    sends 80 01 14, so the panel is still inside configuration mode (80 01 12
    was seen, the write was acked); the error path must send the captured way
    out, 80 01 14, exactly once, and then reset the channel."""

    replies = _success_replies()
    del replies[R_52010C]
    client = ScriptedClient(replies=replies)  # the error-path 80 01 14 still draws 80 01 17
    client2 = ScriptedClient([[]])
    h = _harness(monkeypatch, client, reopen_clients=[client2])
    monkeypatch.setattr(tools.time, "time", _clock(step=0.5))

    with pytest.raises(ConfigWriteError, match="did not confirm the configuration accept"):
        h.session.write_configuration(PAYLOAD)

    assert client.sent == [
        R_80010F,
        R_80010F,
        REVISION_QUERY,
        HID_DELETE_PACKET,
        R_52010C,
        R_800114,
        *EXIT_SEQUENCE,
    ]
    assert h.session._client is client2
    assert h.logins == [(client2, "1812", True)]


def test_a_missing_80_01_17_on_the_error_path_still_resets_the_channel(monkeypatch, caplog) -> None:
    client = ScriptedClient([[SETUP_1A0A], [SETUP_ENTERED], [REVISION_0X204F]])
    client2 = ScriptedClient([[]])
    h = _harness(monkeypatch, client, reopen_clients=[client2])
    monkeypatch.setattr(tools.time, "time", _clock(step=1.0))

    with caplog.at_level(logging.WARNING, logger="jablotron_api.protocol.legacy"):
        with pytest.raises(ConfigWriteError, match="did not answer the HID configuration write"):
            h.session.write_configuration(PAYLOAD)

    assert "No 80 01 17 after the error-path 80 01 14." in caplog.text
    assert client.sent[4:] == [R_800114, *EXIT_SEQUENCE]
    assert h.session._client is client2


def test_a_failed_setup_entry_sends_no_80_01_14_and_resets_the_channel(monkeypatch) -> None:
    client = ScriptedClient([])
    client2 = ScriptedClient([[]])
    h = _harness(monkeypatch, client, reopen_clients=[client2])
    monkeypatch.setattr(tools.time, "time", _clock(step=5.0))

    with pytest.raises(ConfigWriteError, match="Did not enter setup mode"):
        h.session.write_configuration(PAYLOAD)

    assert R_800114 not in client.sent
    assert client.sent == [R_80010F, *EXIT_SEQUENCE]
    assert h.session._client is client2


def test_a_configuration_in_use_entry_failure_sends_no_80_01_14(monkeypatch) -> None:
    assert tools.extract_system_state_mode(CONFIG_IN_USE) == 0x94
    client = ScriptedClient([[CONFIG_IN_USE]])
    client2 = ScriptedClient([[]])
    h = _harness(monkeypatch, client, reopen_clients=[client2])

    with pytest.raises(ConfigWriteError, match="already in configuration mode"):
        h.session.write_configuration(PAYLOAD)

    assert R_800114 not in client.sent
    assert client.sent == [R_80010F, *EXIT_SEQUENCE]
    assert h.session._client is client2


def test_an_unadvanced_revision_is_a_write_error_with_a_single_80_01_14(monkeypatch) -> None:
    client = ScriptedClient(replies=_success_replies(revision_after=REVISION_0X204F))
    client2 = ScriptedClient([[]])
    h = _harness(monkeypatch, client, reopen_clients=[client2])

    with pytest.raises(ConfigWriteError, match="revision stayed"):
        h.session.write_configuration(PAYLOAD)

    assert client.sent.count(R_800114) == 1
    assert client.sent[:7] == [R_80010F, R_80010F, REVISION_QUERY, HID_DELETE_PACKET, R_52010C, R_800114, REVISION_QUERY]
    assert client.sent[7:] == EXIT_SEQUENCE
    assert h.session._client is client2


def test_a_missing_80_01_17_and_an_unadvanced_revision_still_reset_the_channel(monkeypatch) -> None:
    client = ScriptedClient(replies=_success_replies(escape=False, revision_after=REVISION_0X204F))
    client2 = ScriptedClient([[]])
    h = _harness(monkeypatch, client, reopen_clients=[client2])
    monkeypatch.setattr(tools.time, "time", _clock(step=0.5))

    with pytest.raises(ConfigWriteError, match="revision stayed"):
        h.session.write_configuration(PAYLOAD)

    assert client.sent.count(R_800114) == 1
    assert _exit_sequence_sent_after(client.sent, REVISION_QUERY)
    assert h.session._client is client2


def test_a_usb_error_mid_write_closes_the_session_as_a_config_error(monkeypatch) -> None:
    client = ScriptedClient([[SETUP_1A0A], [SETUP_ENTERED], JablotronUSBStreamError("USB read failed on /dev/fakehid")])
    h = _harness(monkeypatch, client)

    with pytest.raises(ConfigWriteError, match="USB link failed during the write"):
        h.session.write_configuration(PAYLOAD)

    assert h.session._client is None
    assert client.closed
    assert h.constructed == [], "a dead link is left to the next poll's reopen and backoff"
    assert EXIT_SEQUENCE[0] not in client.sent


def test_a_usb_failure_before_the_write_is_a_config_error(monkeypatch) -> None:
    """Auto mode closes the session before the rights probe, so the write has
    to reopen it; a reopen refused by the backoff must reach the API as a
    ConfigWriteError (409), not as the raw OSError (500)."""

    h = _harness(monkeypatch, ScriptedClient())
    h.session._client = None
    h.session._authorized_code = None
    h.session._reopen_failures = 1
    h.session._next_reopen_allowed_at = legacy.time.monotonic() + 60.0

    with pytest.raises(ConfigWriteError, match="USB link failed before the write"):
        h.session.write_configuration(PAYLOAD)

    assert h.session._client is None
    assert h.constructed == [], "the backoff refused the reopen before any client was built"


def test_a_refused_write_code_is_a_config_error_and_closes_the_session(monkeypatch) -> None:
    # The session is authorised with another code; re-authorising with the
    # write code draws the panel's login-error reply (80 02 1B 03).
    client = ScriptedClient([[bytes.fromhex("80021b03")]])
    h = _harness(monkeypatch, client)
    h.session._authorized_code = "4458"

    with pytest.raises(ConfigWriteError, match="refused the write code"):
        h.session.write_configuration(PAYLOAD, code="1812")

    assert h.session._client is None
    assert R_80010F not in client.sent


def test_a_failed_reopen_after_the_write_is_logged_not_raised(monkeypatch, caplog) -> None:
    client = ScriptedClient(replies=_success_replies(escape=False))
    h = _harness(monkeypatch, client, reopen_error=OSError("device gone"))
    monkeypatch.setattr(tools.time, "time", _clock(step=0.5))

    with caplog.at_level(logging.WARNING, logger="jablotron_api.protocol.legacy"):
        assert h.session.write_configuration(PAYLOAD) == 0x2050

    assert "Could not reopen the status session" in caplog.text
    assert h.session._client is None
    assert h.session._reopen_failures == 1


# ------------------------------------------- fresh login before an operation

AUTH_END = Jablotron.create_packet_ui_control(b"\x01")
LOGIN_PACKETS = [AUTH_END, Jablotron.create_packet_authorisation_code("1812")]
PANEL_ENDED_AUTHORISATION = bytes.fromhex("800101")


def _one_read_per_login_wait(monkeypatch):
    """The wait for the login result reads until its 0.8 s deadline; give it
    a clock that expires after one read so the scripts stay positional."""

    def await_login_success(client, *, timeout=0.8):
        for packet in client.read_packets(timeout=0.1):
            if Jablotron._is_login_error_packet(packet):
                raise WrongCodeError("Wrong code.")

    monkeypatch.setattr(legacy, "_await_login_success", await_login_success)


def test_a_write_on_a_warm_session_logs_in_again_on_the_open_channel(monkeypatch) -> None:
    """The panel ends a login's authorisation after about a minute and then
    answers 80 01 0F with 80 02 1B 03; the write logs in again first, with
    the login packets on the same channel and no exit sequence."""

    client = ScriptedClient([[LOGIN_MASTER_POSITION_100]], replies=_success_replies())
    h = _harness(monkeypatch, client, fresh_login=False, rights_captured=False)
    _one_read_per_login_wait(monkeypatch)
    sleeps: list[tuple[float, int]] = []
    monkeypatch.setattr(legacy.time, "sleep", lambda seconds: sleeps.append((seconds, len(client.sent))))

    assert h.session.write_configuration(PAYLOAD) == 0x2050

    assert client.sent == [
        *LOGIN_PACKETS,
        ENABLE_DEVICE_STATES,
        R_80010F,
        R_80010F,
        REVISION_QUERY,
        HID_DELETE_PACKET,
        R_52010C,
        R_800114,
        REVISION_QUERY,
        ENABLE_DEVICE_STATES,
    ]
    assert h.session._client is client and h.constructed == [] and h.logins == []
    assert EXIT_SEQUENCE[0] not in client.sent
    assert h.session._login_rights == tools.LoginRights(0x28, 100), "the login reply was captured again"
    assert _nudge_sleeps(sleeps) == [(tools.SETUP_MODE_NUDGE_DELAY, 3)], (
        "the nudge delay sits between the login and the first 80 01 0F"
    )


def test_trigger_export_on_a_warm_session_logs_in_again_first(monkeypatch) -> None:
    client = ScriptedClient([[LOGIN_MASTER_POSITION_100], [RELOAD_COMPLETE], [], []])
    h = _harness(monkeypatch, client, fresh_login=False)
    _one_read_per_login_wait(monkeypatch)

    h.session.trigger_export()

    assert client.sent[:6] == [*LOGIN_PACKETS, ENABLE_DEVICE_STATES, R_520102, R_520102, R_80010F]
    assert client.sent[-3:] == [R_520102, R_800102, R_520102]
    assert h.session._client is client and h.constructed == [] and h.logins == []
    assert EXIT_SEQUENCE[0] not in client.sent


def test_one_login_serves_one_configuration_operation(monkeypatch) -> None:
    """A fresh login is spent by the operation that used it: the export
    trigger after a write logs in again even inside the freshness window."""

    replies = _success_replies()
    client = ScriptedClient(replies=replies)
    h = _harness(monkeypatch, client)
    _one_read_per_login_wait(monkeypatch)

    assert h.session.write_configuration(PAYLOAD) == 0x2050
    assert LOGIN_PACKETS[1] not in client.sent, "the write used the fresh login"

    sent_by_write = len(client.sent)
    client.reads = [[LOGIN_MASTER_POSITION_100], [RELOAD_COMPLETE], [], []]
    h.session.trigger_export()

    assert client.sent[sent_by_write : sent_by_write + 3] == [*LOGIN_PACKETS, ENABLE_DEVICE_STATES]


def test_a_login_older_than_the_window_is_not_fresh(monkeypatch) -> None:
    client = ScriptedClient(replies=_success_replies())
    h = _harness(monkeypatch, client)
    _one_read_per_login_wait(monkeypatch)
    h.session._fresh_login_at -= legacy.CONFIG_OP_FRESH_LOGIN_SECONDS + 0.1

    assert h.session.write_configuration(PAYLOAD) == 0x2050

    assert client.sent[:3] == [*LOGIN_PACKETS, ENABLE_DEVICE_STATES]


def test_the_panel_ending_the_authorisation_spends_the_login(monkeypatch) -> None:
    """80 01 01 pushed by the panel, read by any path, means the next
    configuration operation must log in again."""

    client = ScriptedClient([[PANEL_ENDED_AUTHORISATION]], replies=_success_replies())
    h = _harness(monkeypatch, client)
    _one_read_per_login_wait(monkeypatch)

    with h.session._io_lock:
        list(h.session._tee_client(client).read_packets(timeout=0.1))
    assert h.session._fresh_login_at == 0.0

    assert h.session.write_configuration(PAYLOAD) == 0x2050
    assert client.sent[:3] == [*LOGIN_PACKETS, ENABLE_DEVICE_STATES]


def test_a_login_made_by_the_reopen_is_used_as_it_is(monkeypatch) -> None:
    """finish_export resets the channel; the write that follows within the
    window starts from that login and sends no second one."""

    client = ScriptedClient([[SECTIONS_CONFIG_ACTIVE]])
    client2 = ScriptedClient([[LOGIN_MASTER_POSITION_100], []], replies=_success_replies())
    h = _harness(monkeypatch, client, reopen_clients=[client2], fresh_login=False)

    h.session.finish_export()
    assert h.session._client is client2

    assert h.session.write_configuration(PAYLOAD) == 0x2050
    assert client2.sent[:2] == [ENABLE_DEVICE_STATES, R_80010F]
    assert LOGIN_PACKETS[1] not in client2.sent


def test_a_refused_login_before_the_trigger_is_an_export_error(monkeypatch) -> None:
    client = ScriptedClient([[bytes.fromhex("80021b03")]])
    h = _harness(monkeypatch, client, fresh_login=False)
    _one_read_per_login_wait(monkeypatch)

    with pytest.raises(ExportRefreshIncomplete, match="refused the session code"):
        h.session.trigger_export()

    assert h.session._client is None
    assert client.sent == LOGIN_PACKETS, "nothing follows a refused login"


# ------------------------------------------------------- tee client / emit


def test_tee_client_feeds_every_packet_and_ages_pending_offs(monkeypatch) -> None:
    client = ScriptedClient([[D8_ON], [D8_OFF], []])
    h = _harness(monkeypatch, client)
    tee = h.session._tee_client(client)
    assert isinstance(tee, _SessionTeeClient)

    with h.session._io_lock:
        assert list(tee.read_packets(timeout=0.5)) == [D8_ON]
        assert h.frames[-1] == {4: "on"}

        # The off inside the dwell is deferred: the pulse stays visible.
        assert list(tee.read_packets(timeout=0.5)) == [D8_OFF]
        assert h.session._latched_states[4] == "on"
        assert 4 in h.session._pending_off
        assert h.frames[-1] == {4: "on"}

        # An empty read after the dwell publishes the deferred off through the post-read hook.
        base = legacy.time.monotonic()
        monkeypatch.setattr(legacy.time, "monotonic", lambda: base + MOTION_ON_MIN_DWELL_SECONDS + 0.1)
        assert list(tee.read_packets(timeout=0.5)) == []
        assert h.frames[-1] == {4: "off"}
        assert 4 not in h.session._pending_off

    assert client.read_calls == 3


def test_tee_client_passes_writes_through_and_never_closes_the_channel(monkeypatch) -> None:
    client = ScriptedClient()
    h = _harness(monkeypatch, client)
    tee = h.session._tee_client(client)

    tee.send_packet(REVISION_QUERY)
    tee.send_packets([R_52010C, R_800114])
    tee._write(R_80010F + b"\x00" * 61)
    tee.close()

    assert client.sent == [REVISION_QUERY, R_52010C, R_800114, R_80010F]
    assert not client.closed


def test_emitters_fire_under_the_lock_in_order(monkeypatch) -> None:
    class StreamClient(ScriptedClient):
        pass

    client = StreamClient([[D8_ON]])
    h = _harness(monkeypatch, client)
    records: list[tuple[dict[int, str], bool]] = []
    h.session.set_on_device_state_change(lambda frame: records.append((dict(frame), h.session._io_lock._is_owned())))

    waits = {"n": 0}

    def fake_wait(timeout):
        waits["n"] += 1
        return waits["n"] > 1  # one loop body, then exit

    monkeypatch.setattr(h.session._stop_event, "wait", fake_wait)
    h.session._stream_loop()
    assert records == [({4: "on"}, True)]

    # A later tee read (a configuration op holding the bus) sees the off after the dwell.
    h.session._state_on_since[4] -= MOTION_ON_MIN_DWELL_SECONDS + 1.0
    client.reads.append([D8_OFF])
    with h.session._io_lock:
        list(h.session._tee_client(client).read_packets(timeout=0.5))

    assert records == [({4: "on"}, True), ({4: "off"}, True)]


def test_the_login_drain_feeds_pushed_device_state_into_the_latch(monkeypatch) -> None:
    # A d8 pushed during the post-login drain is device state, not noise.
    client = ScriptedClient([[D8_ON], []])
    h = _harness(monkeypatch, ScriptedClient(), reopen_clients=[client])
    h.session._client = None
    h.session._authorized_code = None

    with h.session._io_lock:
        assert h.session._ensure_client_locked() is client

    assert h.frames == [{4: "on"}]


# ------------------------------------------------------- export trigger


def test_trigger_export_runs_the_flink_sequence_in_session_and_streams(monkeypatch) -> None:
    client = ScriptedClient([[D8_PACKET, RELOAD_COMPLETE], [], []])
    h = _harness(monkeypatch, client)
    seen_at: list[tuple[dict[int, str], int]] = []
    h.session.set_on_device_state_change(lambda frame: seen_at.append((dict(frame), len(client.sent))))
    # The logon-info line carries a fresh session UUID and timestamp per
    # call; pin one rendering so the bytes on the wire can be compared.
    logon_info = build_logon_info_reports()
    monkeypatch.setattr(tools, "build_logon_info_reports", lambda *args, **kwargs: logon_info)
    logon_info_reports = [bytes.fromhex(report).rstrip(b"\x00") for report in logon_info]
    assert len(logon_info_reports) == 3

    h.session.trigger_export()

    assert client.sent == [
        R_520102,
        R_520102,
        R_80010F,
        R_520102,
        R_520213059A00,
        *logon_info_reports,
        R_520125,
        R_520102,
        R_800102,
        R_520102,
    ]
    # The motion edge was published while the reload-complete reply was awaited.
    assert seen_at == [({4: "on"}, 6 + len(logon_info_reports))]
    assert h.session._client is client, "a completed trigger keeps the channel for the block read"
    assert EXIT_SEQUENCE[0] not in client.sent
    assert h.constructed == [] and h.logins == []


def _stalled_trigger(monkeypatch):
    """Run trigger_export on a panel that never sends the reload-complete
    reply. Returns the harness, both clients and the raised exception."""

    client = ScriptedClient([])
    client2 = ScriptedClient([[]])
    h = _harness(monkeypatch, client, reopen_clients=[client2])
    monkeypatch.setattr(tools.time, "time", _clock(step=2.0))

    with pytest.raises(ExportRefreshIncomplete, match="reload-complete") as excinfo:
        h.session.trigger_export()
    return h, client, client2, excinfo.value


def test_trigger_export_without_reload_complete_resets_the_channel_and_raises(monkeypatch) -> None:
    h, client, client2, error = _stalled_trigger(monkeypatch)

    # The catalog pull retries a stall only when its message carries this
    # marker, so the session's error has to keep it.
    assert _RELOAD_STALL_MARKER in str(error)
    assert client.sent[:5] == [R_520102, R_520102, R_80010F, R_520102, R_520213059A00]
    assert client.sent[-4:] == EXIT_SEQUENCE
    assert R_800102 not in client.sent, "the post-reload reports are not sent when the reload never completed"
    assert h.session._client is client2, "the retry starts from a fresh login"
    assert h.logins == [(client2, "1812", True)]


def test_the_catalog_pull_retries_the_real_in_session_stall(monkeypatch, tmp_path) -> None:
    """The retry in pull_catalog_snapshot matches the stall by message; feed
    it the very exception trigger_export raises, not a hand-written copy."""

    _, _, _, error = _stalled_trigger(monkeypatch)
    failures: list[BaseException] = [error]
    calls: list[dict] = []
    sleeps: list[float] = []

    def fake_pull_live_export_snapshot(**kwargs):
        calls.append(kwargs)
        if failures:
            raise failures.pop(0)
        return SimpleNamespace(path=tmp_path / "EXPORT.CFG.bin")

    monkeypatch.setattr(catalog_io, "pull_live_export_snapshot", fake_pull_live_export_snapshot)
    monkeypatch.setattr(
        catalog_io,
        "extract_export_catalog",
        lambda path: SimpleNamespace(sections_by_id={1: object()}, pgs_by_id={}, objects_by_id={}, users=[]),
    )
    config = catalog_io.CatalogPullConfig(
        flexi_cfg_device="auto",
        port="auto",
        auth_code="1812",
        reset=True,
        read_cleanup_mode="auto",
        trigger_session=object(),
    )

    catalog = catalog_io.pull_catalog_snapshot(config, "test-prefix", sleep=sleeps.append, reload_retries=3)

    assert catalog.sections_by_id
    assert len(calls) == 2, "the stall was recognised and retried once"

    # With no retries left the same error ends as ExportReloadStalled.
    failures.append(error)
    with pytest.raises(catalog_io.ExportReloadStalled, match="reload-complete"):
        catalog_io.pull_catalog_snapshot(config, "test-prefix", sleep=sleeps.append, reload_retries=1)


def test_a_usb_error_during_the_trigger_closes_the_session_as_an_export_error(monkeypatch) -> None:
    client = ScriptedClient([JablotronUSBStreamError("USB read failed on /dev/fakehid")])
    h = _harness(monkeypatch, client)

    with pytest.raises(ExportRefreshIncomplete, match="USB link failed during the export trigger"):
        h.session.trigger_export()

    assert h.session._client is None
    assert client.closed
    assert h.constructed == []


# ---------------------------------------------------------- finish export


def test_finish_export_keeps_the_session_on_exited_mode(monkeypatch) -> None:
    client = ScriptedClient([[SECTIONS_EXITED]])
    h = _harness(monkeypatch, client)
    monkeypatch.setattr(legacy, "perform_sections_query", perform_sections_query)  # the harness stubs it

    h.session.finish_export()

    assert client.sent == [SECTIONS_QUERY, ENABLE_DEVICE_STATES]
    assert h.session._client is client
    assert h.session.sections_mode == tools.EXITED_SECTIONS_MODE
    assert h.session._last_enable_device_states_at > 0
    assert h.constructed == []


def test_finish_export_resets_the_channel_on_configuration_mode(monkeypatch) -> None:
    client = ScriptedClient([[SECTIONS_CONFIG_ACTIVE]])
    client2 = ScriptedClient([[]])
    h = _harness(monkeypatch, client, reopen_clients=[client2])
    monkeypatch.setattr(legacy, "perform_sections_query", perform_sections_query)

    h.session.finish_export()

    assert client.sent[0] == SECTIONS_QUERY
    assert client.sent[1:] == EXIT_SEQUENCE
    assert h.session._client is client2
    assert h.logins == [(client2, "1812", True)]


def test_finish_export_resets_the_channel_when_no_mode_is_reported(monkeypatch) -> None:
    client = ScriptedClient([])
    client2 = ScriptedClient([[]])
    h = _harness(monkeypatch, client, reopen_clients=[client2])
    monkeypatch.setattr(legacy, "perform_sections_query", perform_sections_query)
    monkeypatch.setattr(legacy.time, "monotonic", _clock(step=0.5))

    h.session.finish_export()

    assert client.read_calls >= 1, "the reply window was polled before giving up"
    assert client.sent[0] == SECTIONS_QUERY
    assert client.sent[1:] == EXIT_SEQUENCE
    assert h.session._client is client2


def test_finish_export_logs_in_again_when_the_stream_reader_dropped_the_client(monkeypatch) -> None:
    """The lock is free during the block read; a read error in the stream
    loop closes the client without the exit sequence. The trigger left the
    panel in configuration mode, so finish_export must log in again, query
    the mode and, on configuration-active, send the exit sequence on the new
    channel instead of returning early."""
    # The login-time sections query gets no reply; the finish step's query
    # reports configuration-active mode.
    client2 = ScriptedClient(replies={SECTIONS_QUERY: [[], [SECTIONS_CONFIG_ACTIVE]]})
    client3 = ScriptedClient([[]])
    h = _harness(monkeypatch, ScriptedClient(), reopen_clients=[client2, client3])
    monkeypatch.setattr(legacy, "perform_sections_query", perform_sections_query)
    h.session._client = None

    h.session.finish_export()

    assert h.constructed == [client2, client3]
    assert h.logins == [(client2, "1812", True), (client3, "1812", True)]
    assert client2.sent[:3] == [ENABLE_DEVICE_STATES, SECTIONS_QUERY, SECTIONS_QUERY]
    assert client2.sent[3:] == EXIT_SEQUENCE
    assert client2.closed
    assert h.session._client is client3
    assert h.session.sections_mode == tools.CONFIGURATION_SECTIONS_MODE


def test_finish_export_leaves_the_retry_to_the_next_poll_when_the_reopen_fails(monkeypatch, caplog) -> None:
    h = _harness(monkeypatch, ScriptedClient(), reopen_error=OSError("device gone"))
    h.session._client = None

    with caplog.at_level(logging.WARNING, logger=legacy.LOGGER.name):
        h.session.finish_export()

    assert h.session._client is None
    assert h.session._reopen_failures == 1, "the failed reopen feeds the normal backoff"
    assert any("could not be reopened" in record.message for record in caplog.records)


# ------------------------------------------------- login rights (Phase 4)


AUTH_END = Jablotron.create_packet_ui_control(b"\x01")


def test_login_rights_are_captured_from_the_login_drain(monkeypatch) -> None:
    client = ScriptedClient([[LOGIN_MASTER_POSITION_100], []])
    h = _harness(monkeypatch, ScriptedClient(), reopen_clients=[client], rights_captured=False)
    h.session._client = None
    h.session._authorized_code = None

    assert h.session.login_rights_for_code("1812") == tools.LoginRights(0x28, 100)

    assert h.constructed == [client]
    assert h.logins == [(client, "1812", True)]
    assert client.sent == [ENABLE_DEVICE_STATES], "no re-authorisation, no channel reset"

    # Asked again on the same channel, the captured reply answers without any I/O.
    reads_before = client.read_calls
    assert h.session.login_rights_for_code("1812") == tools.LoginRights(0x28, 100)
    assert client.read_calls == reads_before
    assert client.sent == [ENABLE_DEVICE_STATES]


def test_login_rights_capture_also_works_from_the_stream_loop_read(monkeypatch) -> None:
    client = ScriptedClient([[LOGIN_MASTER_POSITION_100]])
    h = _harness(monkeypatch, client, rights_captured=False)
    waits = {"n": 0}

    def fake_wait(timeout):
        waits["n"] += 1
        return waits["n"] > 1  # one loop body, then exit

    monkeypatch.setattr(h.session._stop_event, "wait", fake_wait)
    h.session._stream_loop()

    assert h.session._login_rights is not None
    assert h.session._login_rights.position == 100
    assert h.session._login_rights_code == "1812"


def test_login_rights_are_reset_when_another_code_is_authorised(monkeypatch) -> None:
    client = ScriptedClient()
    client2 = ScriptedClient([[LOGIN_MASTER_POSITION_100], []])
    h = _harness(monkeypatch, client, reopen_clients=[client2])
    monkeypatch.setattr(legacy, "_await_login_success", lambda tee: None)
    h.session._login_rights = tools.LoginRights(0x28, 100)
    h.session._login_rights_code = "1812"

    # A control operation authorises another code on the same channel.
    with h.session._io_lock:
        h.session._ensure_authorized_code_locked(client, "4458")
    assert h.session._login_rights is None
    assert h.session._login_rights_code is None
    sent_before = len(client.sent)

    # Nothing answers the re-authorisation within the wait, so the session
    # falls back to one fresh login, whose drain carries the rights.
    monkeypatch.setattr(legacy.time, "monotonic", _clock(step=0.5))
    assert h.session.login_rights_for_code("1812") == tools.LoginRights(0x28, 100)

    assert client.sent[sent_before:] == [
        AUTH_END,
        Jablotron.create_packet_authorisation_code("1812"),
        *EXIT_SEQUENCE,
    ]
    # The graceful exit drains the channel too, so the read count alone cannot
    # show the wait. Count only the reads made between the re-authorisation and
    # the first exit packet: the login-success wait is stubbed out, so these
    # come from the rights wait alone.
    auth_index = len(client.sent) - 1 - client.sent[::-1].index(Jablotron.create_packet_authorisation_code("1812"))
    exit_index = client.sent.index(EXIT_SEQUENCE[0])
    assert client.reads_at_send[exit_index] > client.reads_at_send[auth_index], (
        "the reply window was polled before the reset"
    )
    assert client.closed
    assert h.logins == [(client2, "1812", True)]
    assert h.session._client is client2


def test_login_rights_for_code_returns_none_when_the_panel_never_reports_them(monkeypatch) -> None:
    client = ScriptedClient()
    client2 = ScriptedClient()
    h = _harness(monkeypatch, ScriptedClient(), reopen_clients=[client, client2], rights_captured=False)
    h.session._client = None
    h.session._authorized_code = None
    monkeypatch.setattr(legacy.time, "monotonic", _clock(step=0.5))

    assert h.session.login_rights_for_code("1812") is None

    assert h.constructed == [client, client2]
    assert client.sent == [ENABLE_DEVICE_STATES, *EXIT_SEQUENCE], "exactly one channel reset"
    assert EXIT_SEQUENCE[0] not in client2.sent
    assert client2.read_calls >= 1, "the fresh login's channel was polled for the reply too"
    assert h.session._client is client2


def test_login_rights_for_code_wraps_a_wrong_code_as_a_config_error(monkeypatch) -> None:
    client = ScriptedClient()
    h = _harness(monkeypatch, client)
    h.session._authorized_code = "4458"

    def refuse(tee):
        raise WrongCodeError("Wrong code.")

    monkeypatch.setattr(legacy, "_await_login_success", refuse)

    with pytest.raises(ConfigWriteError, match="refused the write code"):
        h.session.login_rights_for_code("1812")

    assert h.session._client is None
    assert h.constructed == []


def test_login_rights_for_code_wraps_a_dead_link_as_a_config_error(monkeypatch) -> None:
    h = _harness(monkeypatch, ScriptedClient())
    h.session._client = None
    h.session._authorized_code = None
    h.session._reopen_failures = 1
    h.session._next_reopen_allowed_at = legacy.time.monotonic() + 60.0

    with pytest.raises(ConfigWriteError, match="USB link failed while reading login rights"):
        h.session.login_rights_for_code("1812")

    assert h.session._client is None
    assert h.constructed == []


def test_an_auto_write_in_session_logs_in_once_and_never_probes(monkeypatch, tmp_path) -> None:
    """Phase 4 acceptance: with the auto transport the rights come from the
    session's own login reply, so the write follows that one login directly
    (80 01 0F first, no re-authorisation, no separate probe client)."""

    monkeypatch.setattr(user_manager, "probe_login_rights", lambda **kw: pytest.fail("probed"))
    monkeypatch.setattr(user_manager, "apply_config_payload_over_hid", lambda **kw: pytest.fail("separate client used"))
    monkeypatch.setattr(user_manager, "apply_import_sector", lambda **kw: pytest.fail("storage path used"))
    client = ScriptedClient([[LOGIN_MASTER_POSITION_100], []], replies=_success_replies())
    h = _harness(monkeypatch, ScriptedClient(), reopen_clients=[client], rights_captured=False)
    h.session._client = None
    h.session._authorized_code = None

    user_manager.write_sector_to_panel(
        _config(tmp_path, auth_code="1812"),
        sector_path=_delete_sector(tmp_path),
        verify_prefix="t",
        session=h.session,
    )

    assert h.constructed == [client]
    assert h.logins == [(client, "1812", True)]
    # The login's own 0x13 re-arm, then straight into the write.
    assert client.sent == [
        ENABLE_DEVICE_STATES,
        R_80010F,
        R_80010F,
        REVISION_QUERY,
        HID_DELETE_PACKET,
        R_52010C,
        R_800114,
        REVISION_QUERY,
        ENABLE_DEVICE_STATES,
    ]
    assert AUTH_END not in client.sent
    assert Jablotron.create_packet_authorisation_code("1812") not in client.sent
    assert h.session._client is client


# ------------------------------------------------------------- runtime glue


def test_run_panel_write_turns_a_config_error_into_a_409_runtime_error() -> None:
    def failing_write():
        raise ConfigWriteError("x")

    with pytest.raises(RuntimeError, match="Panel write failed: x"):
        asyncio.run(_run_panel_write(failing_write))
