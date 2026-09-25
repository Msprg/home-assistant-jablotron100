"""The persistent session runs a continuous device-state stream reader so a
brief PIR on->off pulse is latched and surfaced in real time instead of being
aliased away by the periodic snapshot poll (the c1c8beb latency regression).

Covers, from the inside out:
  * the latch edge + rising-edge dwell semantics that preserve a brief pulse,
  * syncing the latch from the live stream parser,
  * the snapshot path overlaying the latch without regressing a streamed edge,
  * the runtime's stream-reader-thread -> event-loop emit/overlay path,
  * one real _stream_loop iteration emitting on a device edge.
"""

from __future__ import annotations

import asyncio

from jablotron_api.domain.models import DeviceStatusModel, PanelStatusModel
from jablotron_api.panel.runtime import PanelRuntime, PanelRuntimeConfig
from jablotron_api.protocol import legacy
from jablotron_api.protocol.legacy import (
    MOTION_ON_MIN_DWELL_SECONDS,
    PersistentSnapshotSession,
    _panel_special_devices,
    _SnapshotParser,
)


def _make_session(monkeypatch) -> PersistentSnapshotSession:
    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    return PersistentSnapshotSession(port="auto", code="1812", reset=True)


# --------------------------------------------------------------- latch / dwell


def test_rising_edge_latches_and_off_within_dwell_is_deferred(monkeypatch) -> None:
    session = _make_session(monkeypatch)

    # off -> on is published immediately.
    assert session._apply_latched_state_locked(5, "on", 100.0) is True
    assert session._latched_states[5] == "on"

    # on -> off arriving within the dwell is deferred: the pulse stays visible.
    assert session._apply_latched_state_locked(5, "off", 100.0 + MOTION_ON_MIN_DWELL_SECONDS / 2) is False
    assert session._latched_states[5] == "on"
    assert 5 in session._pending_off

    # The deferred off does not fire before the dwell elapses...
    assert session._expire_pending_offs_locked(100.0 + MOTION_ON_MIN_DWELL_SECONDS / 2) is False
    assert session._latched_states[5] == "on"

    # ...and is applied once it does.
    assert session._expire_pending_offs_locked(100.0 + MOTION_ON_MIN_DWELL_SECONDS + 0.01) is True
    assert session._latched_states[5] == "off"
    assert 5 not in session._pending_off


def test_off_after_dwell_clears_immediately(monkeypatch) -> None:
    session = _make_session(monkeypatch)
    session._apply_latched_state_locked(2, "on", 0.0)
    assert session._apply_latched_state_locked(2, "off", MOTION_ON_MIN_DWELL_SECONDS + 1.0) is True
    assert session._latched_states[2] == "off"


def test_repeated_on_is_not_a_change(monkeypatch) -> None:
    session = _make_session(monkeypatch)
    assert session._apply_latched_state_locked(1, "on", 0.0) is True
    assert session._apply_latched_state_locked(1, "on", 0.4) is False


def test_new_on_cancels_a_pending_off(monkeypatch) -> None:
    session = _make_session(monkeypatch)
    session._apply_latched_state_locked(1, "on", 0.0)
    session._apply_latched_state_locked(1, "off", 0.2)  # deferred
    assert 1 in session._pending_off
    # A fresh "on" before the dwell expires cancels the pending clear.
    session._apply_latched_state_locked(1, "on", 0.3)
    assert 1 not in session._pending_off
    assert session._latched_states[1] == "on"


# ------------------------------------------------- sync from the live parser


def test_same_burst_pulse_is_preserved_via_per_packet_sync(monkeypatch) -> None:
    # This is the anti-aliasing core: the rising edge must be latched before the
    # falling edge of the same burst is observed, so the brief motion survives.
    session = _make_session(monkeypatch)
    session.configure_live_devices(
        [DeviceStatusModel(id=4, name="PIR", inferred_entity_type="motion", state="off")],
        pg_count=0,
        panel_model="JA-107K",
    )

    # First packet of the burst flips the device on.
    session._live_parser.devices_by_id[4].state = "on"
    assert session._sync_latch_from_live_parser_locked(1000.0) is True
    assert session._latched_states[4] == "on"

    # Second packet of the *same* burst flips it back off, but the dwell holds
    # the published value at "on" rather than collapsing the pulse to "off".
    session._live_parser.devices_by_id[4].state = "off"
    assert session._sync_latch_from_live_parser_locked(1000.2) is False
    assert session._latched_states[4] == "on"


# ------------------------------------------------ snapshot reconcile / overlay


def test_snapshot_overlay_does_not_regress_a_streamed_edge(monkeypatch) -> None:
    session = _make_session(monkeypatch)
    # The stream reader latched motion on.
    session._apply_latched_state_locked(7, "on", 0.0)

    # A snapshot whose parser merely carried the stale "off" baseline (no fresh
    # packet) must not push the latch back to off; the overlay wins.
    devices_by_id = {7: DeviceStatusModel(id=7, name="PIR", state="off")}
    session._reconcile_snapshot_devices_locked(devices_by_id, {7: "off"})

    assert session._latched_states[7] == "on"  # latch untouched
    assert devices_by_id[7].state == "on"  # returned snapshot reflects the latch


def test_snapshot_feeds_a_genuine_edge_into_the_latch(monkeypatch) -> None:
    session = _make_session(monkeypatch)
    # Parser observed on while its seed was off -> a real edge during the read.
    devices_by_id = {9: DeviceStatusModel(id=9, name="PIR", state="on")}
    session._reconcile_snapshot_devices_locked(devices_by_id, {9: "off"})
    assert session._latched_states[9] == "on"
    assert devices_by_id[9].state == "on"


# --------------------------------------------------------- runtime emit path


def test_runtime_stream_emit_overlays_latched_state_and_broadcasts() -> None:
    emitted: list[tuple[str, dict]] = []

    async def listener(topic: str, payload: dict) -> None:
        emitted.append((topic, payload))

    async def run() -> PanelRuntime:
        runtime = PanelRuntime(PanelRuntimeConfig(auth_code="1812"))
        runtime.add_listener(listener)
        runtime._loop = asyncio.get_running_loop()
        runtime._status = PanelStatusModel(
            devices=[
                DeviceStatusModel(id=1, name="PIR", inferred_entity_type="motion", state="off"),
                DeviceStatusModel(id=2, name="Door", inferred_entity_type="opening", state="off"),
            ]
        )
        # Simulate the stream reader thread reporting device 1 -> on.
        runtime._on_device_states_changed({1: "on", 2: "off"})
        await asyncio.sleep(0.05)
        return runtime

    runtime = asyncio.run(run())

    assert emitted, "stream edge should have produced a status broadcast"
    topic, payload = emitted[-1]
    assert topic == "status"
    assert payload["source"] == "stream"
    by_id = {device["id"]: device for device in payload["devices"]}
    assert by_id[1]["state"] == "on"
    assert by_id[2]["state"] == "off"
    # The runtime's cached status is updated so a subsequent GET /v1/status agrees.
    assert {d.id: d.state for d in runtime._status.devices} == {1: "on", 2: "off"}


def test_runtime_stream_emit_preserves_ordered_edges() -> None:
    emitted: list[dict] = []

    async def listener(topic: str, payload: dict) -> None:
        emitted.append(payload)

    async def run() -> None:
        runtime = PanelRuntime(PanelRuntimeConfig(auth_code="1812"))
        runtime.add_listener(listener)
        runtime._loop = asyncio.get_running_loop()
        runtime._status = PanelStatusModel(
            devices=[DeviceStatusModel(id=1, name="PIR", inferred_entity_type="motion", state="off")]
        )
        # Two notifications scheduled on the same loop turn must still be
        # broadcast as ordered edges. HA motion automations depend on observing
        # the rising "on" transition, not only the eventual final "off".
        runtime._handle_stream_device_states({1: "on"})
        runtime._handle_stream_device_states({1: "off"})
        await asyncio.sleep(0.05)

    asyncio.run(run())

    assert [payload["devices"][0]["state"] for payload in emitted] == ["on", "off"]


def test_runtime_stream_emit_compacts_backlog_without_losing_rising_edges() -> None:
    emitted: list[dict] = []

    async def run() -> None:
        first_emit_seen = asyncio.Event()
        release_first_emit = asyncio.Event()

        async def listener(topic: str, payload: dict) -> None:
            emitted.append(payload)
            if len(emitted) == 1:
                first_emit_seen.set()
                await release_first_emit.wait()

        runtime = PanelRuntime(PanelRuntimeConfig(auth_code="1812"))
        runtime.add_listener(listener)
        runtime._loop = asyncio.get_running_loop()
        runtime._status = PanelStatusModel(
            devices=[
                DeviceStatusModel(id=1, name="PIR A", inferred_entity_type="motion", state="off"),
                DeviceStatusModel(id=2, name="PIR B", inferred_entity_type="motion", state="off"),
            ]
        )

        runtime._handle_stream_device_states({1: "on", 2: "off"})
        await first_emit_seen.wait()

        # These arrive while the first websocket/status emit is blocked. The
        # runtime must not replay every stale full snapshot after the listener
        # resumes, but PIR B's not-yet-published rising edge still has to show up.
        runtime._handle_stream_device_states({1: "off", 2: "off"})
        runtime._handle_stream_device_states({1: "off", 2: "on"})
        runtime._handle_stream_device_states({1: "on", 2: "on"})
        runtime._handle_stream_device_states({1: "off", 2: "off"})

        release_first_emit.set()
        await asyncio.sleep(0.05)

    asyncio.run(run())

    states = [
        {device["id"]: device["state"] for device in payload["devices"]}
        for payload in emitted
    ]
    assert len(states) == 3
    assert states[0] == {1: "on", 2: "off"}
    assert states[1][2] == "on"
    assert states[-1] == {1: "off", 2: "off"}


def test_runtime_stream_callback_is_a_noop_without_a_loop() -> None:
    runtime = PanelRuntime(PanelRuntimeConfig(auth_code="1812"))
    # Before start()/after close() the loop is None; the worker-thread callback
    # must never raise.
    runtime._on_device_states_changed({1: "on"})


# -------------------------------- real-time edges during a long (diagnostics) read


def test_snapshot_read_hook_emits_device_edge_in_realtime(monkeypatch) -> None:
    # The per-packet hook is what keeps motion real-time while a multi-second
    # diagnostics read holds the bus (the stream loop is blocked on the lock).
    session = _make_session(monkeypatch)
    captured: list[dict[int, str]] = []
    session.set_on_device_state_change(captured.append)

    parser = _SnapshotParser(
        devices_by_id={7: DeviceStatusModel(id=7, name="PIR Rack", inferred_entity_type="device_state_motion", state="off")},
        special_devices=_panel_special_devices("JA-107K"),
    )
    seed = {7: "off"}

    # A device-state packet parsed mid-read flips device 7 on.
    parser.devices_by_id[7].state = "on"
    assert session._emit_snapshot_device_edges_locked(parser, seed) is True
    assert captured and captured[-1].get(7) == "on"
    assert seed[7] == "on"  # advanced so the edge is fed exactly once

    # No further parsed change -> no spurious re-emit.
    captured.clear()
    assert session._emit_snapshot_device_edges_locked(parser, seed) is False
    assert captured == []


def test_read_into_parser_invokes_on_packet_per_packet(monkeypatch) -> None:
    session = _make_session(monkeypatch)
    parser = _SnapshotParser(devices_by_id={}, special_devices={})
    monkeypatch.setattr(parser, "parse_packet", lambda packet, *, pg_count: None)

    class FakeClient:
        def __init__(self) -> None:
            self.reads = 0

        def read_packets(self, *, timeout=None):
            self.reads += 1
            return iter([b"\x55\x00", b"\xd8\x00"]) if self.reads == 1 else iter(())

    calls = {"n": 0}
    session._read_into_parser_locked(
        FakeClient(), parser, pg_count=0, timeout=0.1, on_packet=lambda: calls.__setitem__("n", calls["n"] + 1)
    )
    assert calls["n"] == 2  # once per parsed packet


# ---------------------------------------------------- one real loop iteration


def test_stream_loop_iteration_emits_on_device_edge(monkeypatch) -> None:
    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy, "perform_enable_device_states", lambda client: None)

    session = PersistentSnapshotSession(port="auto", code="1812", reset=True)
    session.configure_live_devices(
        [DeviceStatusModel(id=4, name="PIR", inferred_entity_type="motion", state="off")],
        pg_count=0,
        panel_model="JA-107K",
    )

    captured: list[dict[int, str]] = []
    session.set_on_device_state_change(captured.append)

    class FakeClient:
        def __init__(self) -> None:
            self.reads = 0

        def send_packet(self, packet: bytes) -> None:
            return None

        def read_packets(self, *, timeout=None):
            self.reads += 1
            return iter([b"\x55\x00\x00"]) if self.reads == 1 else iter(())

        def close(self) -> None:
            return None

    session._client = FakeClient()
    # The real parser machinery is exercised separately; here we only need the
    # one streamed packet to flip the device so the loop's edge/emit path runs.
    monkeypatch.setattr(
        session._live_parser,
        "parse_packet",
        lambda packet, *, pg_count: session._live_parser.devices_by_id[4].__setattr__("state", "on"),
    )

    waits = {"n": 0}

    def fake_wait(timeout):
        waits["n"] += 1
        return waits["n"] > 1  # run the body once, then exit

    monkeypatch.setattr(session._stop_event, "wait", fake_wait)
    try:
        session._stream_loop()
    finally:
        session.close()

    assert captured and captured[-1].get(4) == "on"


# ---------------------------------------- cooperative diagnostics sweep (fix)


class _FakeClient:
    """Minimal client: no-op writes, no packets to read."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def send_packet(self, packet: bytes) -> None:
        self.sent.append(packet)

    def send_packets(self, packets) -> None:
        self.sent.extend(packets)

    def read_packets(self, *, timeout=None):
        return iter(())

    def close(self) -> None:
        return None


def test_diagnostics_base_scopes_to_targeted_devices(monkeypatch) -> None:
    # The fast-retry chasing an unresolved wireless temperature must re-poll
    # ONLY the named device(s), not the whole bus (which froze the reader).
    session = _make_session(monkeypatch)
    client = _FakeClient()
    devices = [
        DeviceStatusModel(id=3, name="Therm A", inferred_device_type="thermometer", state="off"),
        DeviceStatusModel(id=4, name="Therm B", inferred_device_type="thermometer", state="off"),
    ]

    full = session._query_snapshot_base_locked(
        client, panel_model="JA-107K", pg_count=0, devices=devices, central=None,
        query_device_status=True, include_diagnostics=True, diagnostics_device_ids=None, timeout=0.0,
    )
    # Full sweep: both diagnosable devices plus the panel (0).
    assert set(full.diagnostic_numbers) >= {3, 4, 0}

    targeted = session._query_snapshot_base_locked(
        client, panel_model="JA-107K", pg_count=0, devices=devices, central=None,
        query_device_status=True, include_diagnostics=True, diagnostics_device_ids=[4], timeout=0.0,
    )
    # Targeted retry: only device 4 — no whole-bus, no panel/lan/gsm.
    assert targeted.diagnostic_numbers == [4]


def test_diagnostics_sweep_releases_io_lock_between_devices(monkeypatch) -> None:
    # The core fix: the sweep must NOT hold _io_lock continuously. Between
    # devices the lock is released (and the worker sleeps off-lock) so the
    # continuous stream reader can interleave instead of being starved.
    session = _make_session(monkeypatch)
    client = _FakeClient()
    monkeypatch.setattr(session, "_ensure_client_locked", lambda auth_code=None: client)
    monkeypatch.setattr(session, "_read_into_parser_locked", lambda *a, **k: None)
    session._client = client
    devices = [
        DeviceStatusModel(id=3, name="Therm A", inferred_device_type="thermometer", state="off"),
        DeviceStatusModel(id=4, name="Therm B", inferred_device_type="thermometer", state="off"),
    ]

    owned_during_yield: list[bool] = []

    def fake_sleep(_seconds: float) -> None:
        # The inter-device yield happens off the lock: the worker thread must
        # not own _io_lock here, or the stream reader could not run.
        owned_during_yield.append(session._io_lock._is_owned())

    monkeypatch.setattr(legacy.time, "sleep", fake_sleep)

    snapshot = session.query_snapshot(
        panel_model="JA-107K", pg_count=0, devices=devices, central=None,
        query_device_status=True, include_diagnostics=True, timeout=0.0,
    )

    assert owned_during_yield, "expected at least one inter-device yield"
    assert not any(owned_during_yield), "_io_lock must be released between devices"
    assert {d.id for d in snapshot.devices} >= {3, 4}
