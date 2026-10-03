"""Adapters around the proven reverse-engineering helpers already in the repo."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterator

from jablotron_re_tools import (
    CONFIGURATION_ESCAPED_PREFIX,
    CONFIGURATION_SECTIONS_MODE,
    EXITED_SECTIONS_MODE,
    REPORT_800114,
    LoginRights,
    describe_sections_mode,
    enter_setup_mode,
    leave_configuration_mode,
    parse_login_rights,
    read_config_revision,
    send_accept_configuration,
    send_flink_export_refresh_sequence,
    send_report,
    verify_config_revision_advanced,
    wait_for_reply,
    write_config_over_hid,
)
from jablotron_usb_debug import (
    DEVICE_INFO_KNOWN_SUBPACKETS,
    DEVICE_INFO_SUBPACKET_WIRELESS,
    DEVICE_INFO_UNKNOWN_SUBPACKETS,
    DeviceConnection,
    DeviceFault,
    DeviceInfoType,
    Jablotron,
    JablotronUSBClient,
    JablotronUSBStreamError,
    SystemInfo,
    UI_CONTROL_AUTHORISATION_END,
    UI_CONTROL_MODIFY_SECTION,
    UI_CONTROL_TOGGLE_PG_OUTPUT,
    ensure_serial_port,
    perform_enable_device_states,
    perform_login,
    perform_logout,
    perform_sections_query,
    perform_system_info_query,
)

from jablotron_api.domain.models import BusStatusModel, CentralStatusModel, DeviceStatusModel, PGStatusModel, SectionStatusModel

LOGGER = logging.getLogger(__name__)


class WrongCodeError(ValueError):
    """Raised when the panel rejects a user-supplied control code."""


class PanelConfigError(RuntimeError):
    """A configuration operation inside the status session failed.

    The session's channel has been reset (graceful exit, then a reopen
    attempt) or the session was closed so the next poll logs in afresh; the
    panel is not left in setup mode by this process. ``RuntimeError`` so the
    HTTP layer reports it as 409, like every other panel or link failure.
    """


class ConfigWriteError(PanelConfigError):
    """The HID configuration write inside the status session failed."""


class ExportRefreshIncomplete(PanelConfigError):
    """The export refresh sequence inside the status session did not complete."""


@dataclass(frozen=True)
class LegacySystemInfo:
    model: str | None
    hardware_version: str | None
    firmware_version: str | None


@dataclass(frozen=True)
class LegacyPanelSnapshot:
    sections: list[SectionStatusModel]
    pgs: list[PGStatusModel]
    devices: list[DeviceStatusModel]
    central: CentralStatusModel
    service_mode: bool


@dataclass
class _SnapshotJob:
    """In-progress snapshot state carried across the cooperative diagnostics
    sweep. The sweep releases _io_lock between devices so the continuous stream
    reader interleaves; the parser/seed/device maps must persist across those
    releases, so they live here rather than as locals under one lock hold."""

    parser: _SnapshotParser
    devices_by_id: dict[int, DeviceStatusModel]
    special_devices: dict[str, int | None]
    seed_states: dict[int, str | None]
    pg_count: int
    diagnostic_numbers: list[int]


def _panel_special_devices(model: str | None) -> dict[str, int | None]:
    if model in {"JA-101K", "JA-101K-LAN", "JA-106K-3G", "JA-14K"}:
        return {"power_supply": 124, "lan": 125, "gsm": 127}
    if model in {"JA-103K", "JA-103KRY", "JA-107K"}:
        return {"power_supply": None, "lan": 233, "gsm": 234}
    return {"power_supply": None, "lan": None, "gsm": None}


def _device_supports_diagnostics(device: DeviceStatusModel) -> bool:
    inferred = device.inferred_device_type or ""
    return inferred in {
        "thermometer",
        "thermostat",
        "smoke_detector",
        "electricity_meter_with_pulse_output",
        "outdoor_siren",
        "indoor_siren",
    }


def _section_state_to_name(section_state: object) -> str | None:
    state_name = getattr(section_state, "state", None)
    state_value = getattr(state_name, "name", "")
    if getattr(section_state, "triggered", False):
        return "triggered"
    if getattr(section_state, "pending", False):
        return "pending"
    if getattr(section_state, "arming", False):
        return "arming"
    if state_value == "ARMED_FULL":
        return "armed_away"
    if state_value == "ARMED_PARTIALLY":
        return "armed_night"
    if state_value == "SERVICE":
        return "service"
    if state_value == "BLOCKED":
        return "blocked"
    if state_value == "OFF":
        return "off"
    return "disarmed"


def _parse_lan_ip(raw: bytes) -> str:
    return ".".join(str(Jablotron.bytes_to_int(raw[index:(index + 1)])) for index in range(4))


def _await_login_success(client: JablotronUSBClient, *, timeout: float = 0.8) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for packet in client.read_packets(timeout=0.1):
            if Jablotron._is_login_error_packet(packet):
                raise WrongCodeError("Wrong code.")


class _SessionTeeClient:
    """Client handed to the jablotron_re_tools step functions when they run
    inside the status session.

    Every packet read is fed to the session's live parser (per-packet latch
    sync and edge emit, as in _stream_loop) and then returned to the caller,
    so a motion edge pushed while a write or export trigger holds the bus is
    published within one read slice instead of being dropped by
    wait_for_reply. Writes pass straight through. The caller must hold
    _io_lock.
    """

    def __init__(self, session: "PersistentSnapshotSession", client: JablotronUSBClient) -> None:
        self._session = session
        self._client = client

    def read_packets(self, *, timeout: float | None = None) -> Iterator[bytes]:
        # Materialise the batch first so the post-read dwell hook runs at a
        # deterministic point (the step functions list() the iterator anyway).
        # A JablotronUSBStreamError from the underlying read propagates as is.
        packets = list(self._client.read_packets(timeout=timeout))
        for packet in packets:
            self._session._observe_packet_locked(packet)
        self._session._after_read_locked()
        return iter(packets)

    def send_packet(self, packet: bytes) -> None:
        self._client.send_packet(packet)

    def send_packets(self, packets) -> None:
        self._client.send_packets(packets)

    def _write(self, report: bytes) -> None:
        # perform_send_raw_report writes raw 64-byte reports through this.
        self._client._write(report)

    def close(self) -> None:
        # The step functions never close the client they are handed; the
        # session owns its channel.
        LOGGER.debug("Ignoring close() on the session tee client")


RAW_SESSION_KEEPALIVE = bytes.fromhex("520102")
EXIT_DIAGNOSTICS_OFF_PACKET = bytes.fromhex("94020100")
# In-session configuration operations.
SETUP_MODE_LEAVE_TIMEOUT_SECONDS = 3.0  # wait for 80 01 17 after an error-path 80 01 14
SECTIONS_MODE_QUERY_TIMEOUT_SECONDS = 0.8  # finish_export's 52 01 0E reply window
LOGIN_RIGHTS_WAIT_SECONDS = 1.5  # how long login_rights_for_code reads for an 80 1A 0C
# After a fully confirmed write (accept confirmed, 80 01 17 seen, revision
# advanced) the session keeps its channel and only re-arms the device-state
# subscription: F-Link stays connected across its writes, and the post-write
# export stalls we saw also happened on fresh logins (the catalog retry covers
# them). True restores the exit shape of the proven standalone write session
# (graceful exit + immediate re-login) after every write; failure paths and a
# missing 80 01 17 always reset the channel regardless of this flag.
BOUNCE_AFTER_SUCCESSFUL_WRITE = False
DEVICE_STATE_RENEWAL_SECONDS = 240.0
DEFAULT_DIAGNOSTICS_TIMEOUT_SECONDS = 2.0
WIRELESS_TEMPERATURE_DIAGNOSTICS_TIMEOUT_SECONDS = 5.0
CONTROL_CONFIRMATION_TIMEOUT_SECONDS = 0.7
FAST_CONTROL_CONFIRMATION_TIMEOUT_SECONDS = 0.25
AUTHORIZATION_REFRESH_SETTLE_SECONDS = 0.12
PG_CONTROL_QUERY_SETTLE_SECONDS = 0.05
CONTROL_AUTHORIZATION_IDLE_SECONDS = 60.0
# Reopen backoff after a USB stream failure: refuse to retry the (re)open+login
# until a deadline that grows linearly with the failure streak, capped, so a
# truly-absent device does not get hammered. Mirrors upstream STREAM_REOPEN_DELAY
# / STREAM_REOPEN_MAX_DELAY (cd2432d).
STREAM_REOPEN_DELAY_SECONDS = 1.0
STREAM_REOPEN_MAX_DELAY_SECONDS = 30.0

# Continuous device-state reader (the keepalive thread doubles as a live stream
# reader). After perform_enable_device_states the panel asynchronously *pushes*
# device-state packets (motion/contact on/off) whenever they change. The thread
# drains them every tick so a brief PIR pulse is observed in real time instead of
# being aliased away by the periodic snapshot poll. All reads stay under
# _io_lock; the budget/tick are kept short so a control op never waits more than
# one read burst for the lock.
STREAM_LOOP_TICK_SECONDS = 0.05
# Kept short so the lock is held only briefly per tick: an idle read blocks at
# most this long under _io_lock, bounding how long a concurrent control op waits
# for the bus. A streamed packet returns sooner (select wakes immediately), so a
# small budget costs nothing for real-time edge capture.
STREAM_READ_BUDGET_SECONDS = 0.05
STREAM_KEEPALIVE_INTERVAL_SECONDS = 1.0
# A rising motion edge is held "on" for at least this long before a following
# "off" is honoured, so a fire-and-clear pulse whose on/off packets land in the
# same read burst is still published as an "on" before it clears. The dwell only
# *defers* the off (never drops it): _expire_pending_offs_locked applies it once
# the dwell elapses. Clearing relies on the panel's own "off" edge — exactly as
# the original integration did, with no host-side auto-timeout. Should an "off"
# edge ever be lost on the wire, the periodic device-states bitmap the panel
# re-pushes on the DEVICE_STATE_RENEWAL_SECONDS re-enable corrects it (bounded
# staleness), so a device cannot stay stuck "on" indefinitely.
MOTION_ON_MIN_DWELL_SECONDS = 1.0


def _diagnostics_timeout_for_device(device: DeviceStatusModel) -> float:
    if device.wireless and (device.inferred_device_type or "") in {"thermometer", "thermostat"}:
        return WIRELESS_TEMPERATURE_DIAGNOSTICS_TIMEOUT_SECONDS
    return DEFAULT_DIAGNOSTICS_TIMEOUT_SECONDS


def _diagnostics_priority(device: DeviceStatusModel) -> tuple[int, int]:
    inferred = device.inferred_device_type or ""
    if device.wireless and inferred in {"thermometer", "thermostat"} and device.temperature is None:
        return (0, device.id)
    if device.wireless and inferred in {"thermometer", "thermostat"}:
        return (1, device.id)
    return (2, device.id)


@dataclass
class _SnapshotParser:
    devices_by_id: dict[int, DeviceStatusModel]
    special_devices: dict[str, int | None]
    sections: list[SectionStatusModel] = field(default_factory=list)
    pgs: list[PGStatusModel] = field(default_factory=list)
    central: CentralStatusModel = field(default_factory=CentralStatusModel)
    service_mode: bool = False
    login_failed: bool = False

    def parse_packet(self, packet: bytes, *, pg_count: int) -> None:
        if Jablotron._is_login_error_packet(packet):
            self.login_failed = True
            return
        if Jablotron._is_sections_states_packet(packet):
            self._parse_sections_packet(packet)
            return
        if Jablotron._is_pg_outputs_states_packet(packet):
            self._parse_pgs_packet(packet, pg_count=pg_count)
            return
        if Jablotron._is_devices_states_packet(packet):
            self._parse_devices_states_packet(packet)
            return
        if Jablotron._is_device_state_packet(packet):
            self._parse_device_state_packet(packet)
            return
        if Jablotron._is_device_status_packet(packet):
            self._parse_device_status_packet(packet)
            return
        if Jablotron._is_device_info_packet(packet):
            self._parse_device_info_packet(packet)

    def _parse_sections_packet(self, packet: bytes) -> None:
        section_states = Jablotron._convert_sections_states_packet_to_sections_states(packet)
        self.sections = [
            SectionStatusModel(
                id=section_id,
                name=f"Section {section_id}",
                state=_section_state_to_name(state),
                pending=bool(getattr(state, "pending", False)),
                arming=bool(getattr(state, "arming", False)),
                triggered=bool(getattr(state, "triggered", False)),
                problem=bool(getattr(state, "problem", False)),
                sabotage=bool(getattr(state, "sabotage", False)),
                fire=bool(getattr(state, "fire", False)),
            )
            for section_id, state in section_states.items()
        ]
        self.service_mode = any(section.state == "service" for section in self.sections)

    def _parse_pgs_packet(self, packet: bytes, *, pg_count: int) -> None:
        states_start = 2
        states_end = states_start + Jablotron.bytes_to_int(packet[1:2])
        states = Jablotron._bytes_to_reverse_binary(packet[states_start:states_end])
        self.pgs = [
            PGStatusModel(
                id=index + 1,
                name=f"PG output {index + 1}",
                state="on" if states[index:(index + 1)] == "1" else "off",
            )
            for index in range(pg_count)
        ]

    def _parse_devices_states_packet(self, packet: bytes) -> None:
        states_start = 2
        states_end = states_start + Jablotron.bytes_to_int(packet[1:2])
        states = Jablotron._bytes_to_reverse_binary(packet[(states_start + 1):states_end])
        for device_id, device in self.devices_by_id.items():
            if device_id >= len(states):
                continue
            device.state = "on" if states[device_id:(device_id + 1)] == "1" else "off"

    def _parse_device_state_packet(self, packet: bytes) -> None:
        device_id = Jablotron._parse_device_number_from_device_state_packet(packet)
        state = Jablotron._convert_jablotron_device_state_to_state(packet, device_id)
        if device_id == self.special_devices.get("lan"):
            if state is not None:
                self.central.lan_connection = state == "off"
            return
        if device_id == self.special_devices.get("gsm"):
            if state is not None:
                self.central.gsm_signal = state == "off"
            return
        device = self.devices_by_id.get(device_id)
        if device is None or state is None:
            return
        packet_state_binary = Jablotron._bytes_to_binary(packet[2:3])
        is_heartbeat = Jablotron.binary_to_int(packet_state_binary[4:]) == 15
        if not is_heartbeat:
            fault_marker = Jablotron.binary_to_int(packet_state_binary[4:6]) == 1
            if fault_marker:
                try:
                    fault = DeviceFault(Jablotron.binary_to_int(packet_state_binary[6:]))
                except ValueError:
                    fault = None
                if fault == DeviceFault.BATTERY:
                    device.battery_problem = state == "on"
                else:
                    device.problem = state == "on"
            elif device.inferred_entity_type:
                device.state = state
        if device.wireless:
            device.signal_strength = Jablotron.bytes_to_int(packet[10:11]) * 4

    def _parse_device_status_packet(self, packet: bytes) -> None:
        device_id = Jablotron._parse_device_number_from_device_status_packet(packet)
        if device_id == self.special_devices.get("power_supply"):
            self._parse_central_info_subpacket(packet[4:], packet)
            return
        if device_id == self.special_devices.get("gsm"):
            if packet[4:5] in (b"\xa4", b"\xd5"):
                self.central.gsm_signal_strength = float(Jablotron.bytes_to_int(packet[5:6]))
            return
        if device_id == self.special_devices.get("lan"):
            if len(packet) >= 10:
                self.central.lan_ip = _parse_lan_ip(packet[6:10])
            return

        device = self.devices_by_id.get(device_id)
        if device is None:
            return
        connection = Jablotron._parse_device_connection_type_from_device_status_packet(packet)
        device.connection = connection.value
        device.wireless = connection == DeviceConnection.WIRELESS
        if connection == DeviceConnection.WIRELESS:
            signal = Jablotron._parse_device_signal_strength_from_device_status_packet(packet)
            if signal is not None:
                device.signal_strength = signal
            battery = Jablotron._parse_device_battery_level_from_device_status_packet(packet)
            if battery is not None:
                device.battery_level = battery.level
                device.battery_problem = not battery.ok

    def _parse_device_info_packet(self, packet: bytes) -> None:
        device_id = Jablotron._parse_device_number_from_device_info_packet(packet)
        subpackets = Jablotron._parse_device_info_subpackets_from_device_info_packet(packet)
        for subpacket in subpackets:
            subpacket_type = subpacket[0:1]
            if subpacket_type not in DEVICE_INFO_KNOWN_SUBPACKETS:
                # Same guard as the upstream integration: only the wireless
                # (`01`), periodic (`9C`) and requested (`0A`) subpackets have
                # the battery byte and info records the code below expects. A
                # diagnostics-command response (for example the 236-byte `6B`
                # answer to `96 <dev> 6A ...`, which the USB client now hands
                # over whole) would otherwise set a bogus battery level and be
                # scanned as info records.
                if subpacket_type not in DEVICE_INFO_UNKNOWN_SUBPACKETS:
                    LOGGER.debug(
                        "Ignoring device %d info subpacket of unknown type %s (%s)",
                        device_id,
                        subpacket_type.hex(),
                        packet.hex(),
                    )
                continue
            if subpacket_type == DEVICE_INFO_SUBPACKET_WIRELESS:
                device = self.devices_by_id.get(device_id)
                if device is not None:
                    device.signal_strength = Jablotron._parse_device_signal_strength_from_device_info_subpacket(subpacket)
                    device.connection = DeviceConnection.WIRELESS.value
                    device.wireless = True
                continue

            info_subpacket = subpacket[2:]
            if device_id == 0 or device_id == self.special_devices.get("power_supply"):
                self._parse_central_info_subpacket(info_subpacket, packet)
            elif device_id == self.special_devices.get("lan"):
                self._parse_lan_info_subpacket(info_subpacket, packet)
            elif device_id == self.special_devices.get("gsm"):
                self._parse_gsm_info_subpacket(info_subpacket, packet)
            else:
                self._parse_device_info_subpacket(device_id, info_subpacket, packet)

    def _parse_device_info_subpacket(self, device_id: int, info_subpacket: bytes, packet: bytes) -> None:
        device = self.devices_by_id.get(device_id)
        if device is None:
            return

        battery = Jablotron._parse_device_battery_level_from_device_info_packet(info_subpacket, packet)
        if battery is not None:
            device.battery_level = battery.level
            device.battery_problem = not battery.ok

        info_packets = Jablotron._parse_device_info_packets_from_device_info_subpacket(info_subpacket, packet)
        inferred = device.inferred_device_type or ""
        pulse_values: list[int] = []

        for info_packet in info_packets:
            if inferred in {"thermometer", "thermostat"} and info_packet.type == DeviceInfoType.INPUT_VALUE:
                input_type = info_packet.packet[2:3]
                if input_type == b"\x00":
                    modifier = Jablotron.bytes_to_int(info_packet.packet[4:5])
                    if modifier >= 128:
                        modifier -= 256
                    device.temperature = round((Jablotron.bytes_to_int(info_packet.packet[3:4]) + (255 * modifier)) / 10, 1)
            elif inferred == "smoke_detector" and info_packet.type == DeviceInfoType.SMOKE:
                temperature = float(Jablotron.bytes_to_int(info_packet.packet[1:2]))
                if temperature > 100:
                    temperature -= 128
                device.temperature = temperature
            elif inferred in {"outdoor_siren", "indoor_siren"} and info_packet.type in {DeviceInfoType.POWER, DeviceInfoType.POWER_PRECISE}:
                channel = info_packet.packet[1:2]
                if channel == b"\x00":
                    device.battery_standby_voltage = Jablotron.bytes_to_float(info_packet.packet[2:3])
                elif channel == b"\x01":
                    device.battery_load_voltage = Jablotron.bytes_to_float(info_packet.packet[2:3])
            elif inferred == "electricity_meter_with_pulse_output" and info_packet.type == DeviceInfoType.PULSE:
                if info_packet.packet[1:2] != b"\x00" and len(pulse_values) < 2:
                    pulse_values.append(Jablotron.bytes_to_int(info_packet.packet[1:2]) + 255 * Jablotron.bytes_to_int(info_packet.packet[2:3]))

        if pulse_values:
            device.pulses = pulse_values

    def _parse_central_info_subpacket(self, info_subpacket: bytes, packet: bytes) -> None:
        if not info_subpacket:
            return
        power_supply_and_battery_binary = Jablotron._bytes_to_binary(info_subpacket[0:1])
        self.central.power_supply = power_supply_and_battery_binary[1:2] == "1"

        battery = Jablotron._parse_device_battery_level_from_device_info_packet(info_subpacket, packet)
        if battery is not None:
            self.central.battery_level = battery.level
            self.central.battery_problem = not battery.ok

        buses: dict[int, BusStatusModel] = {bus.bus_number: bus for bus in self.central.buses}
        info_packets = Jablotron._parse_device_info_packets_from_device_info_subpacket(info_subpacket, packet)
        for info_packet in info_packets:
            if info_packet.type != DeviceInfoType.POWER:
                continue
            channel = info_packet.packet[1:2]
            if channel == b"\x00":
                self.central.battery_load_voltage = Jablotron.bytes_to_float(info_packet.packet[2:3])
            elif channel == b"\x10":
                self.central.battery_standby_voltage = Jablotron.bytes_to_float(info_packet.packet[2:3])
            elif channel in {b"\x01", b"\x02", b"\x03"}:
                bus_number = Jablotron.bytes_to_int(channel)
                bus = buses.setdefault(bus_number, BusStatusModel(bus_number=bus_number))
                bus.voltage = Jablotron.bytes_to_float(info_packet.packet[2:3])
                bus.devices_loss_count = Jablotron.bytes_to_int(info_packet.packet[3:4])
        self.central.buses = sorted(buses.values(), key=lambda item: item.bus_number)

    def _parse_lan_info_subpacket(self, info_subpacket: bytes, packet: bytes) -> None:
        info_packets = Jablotron._parse_device_info_packets_from_device_info_subpacket(info_subpacket, packet)
        for info_packet in info_packets:
            if info_packet.type != DeviceInfoType.LAN:
                continue
            state_binary = Jablotron._bytes_to_binary(info_packet.packet[1:2])
            lan_ok = state_binary[0:1] == "1"
            dhcp_ok = state_binary[6:7] == "1"
            self.central.lan_connection = lan_ok and dhcp_ok
            self.central.lan_ip = _parse_lan_ip(info_packet.packet[2:6])

    def _parse_gsm_info_subpacket(self, info_subpacket: bytes, packet: bytes) -> None:
        info_packets = Jablotron._parse_device_info_packets_from_device_info_subpacket(info_subpacket, packet)
        for info_packet in info_packets:
            if info_packet.type != DeviceInfoType.GSM:
                continue
            state_binary = Jablotron._bytes_to_binary(info_packet.packet[5:6])
            self.central.gsm_signal = state_binary[7:8] == "1"
            self.central.gsm_signal_strength = float(Jablotron.bytes_to_int(info_packet.packet[1:2]))


class PersistentSnapshotSession:
    """Long-lived authenticated HID session for steady-state status polling."""

    def __init__(self, *, port: str, code: str, reset: bool = True) -> None:
        # Keep the raw configured value ("auto" or a fixed path) so the port can
        # be re-resolved after a USB re-enumeration, not just once at startup.
        self._configured_port = port
        self._code = code
        self._reset = reset
        self._client: JablotronUSBClient | None = None
        self._io_lock = threading.RLock()
        self._stop_event = threading.Event()
        self._keepalive_thread: threading.Thread | None = None
        self._last_enable_device_states_at = 0.0
        self._authorized_code: str | None = None
        self._last_control_authorized_at = 0.0
        # Reopen-backoff state, mutated only under self._io_lock.
        self._reopen_failures = 0
        self._next_reopen_allowed_at = 0.0
        # Live device-state stream state, all mutated only under self._io_lock.
        # _live_parser is a persistent _SnapshotParser seeded with the catalog
        # devices so streamed packets are interpreted exactly like a snapshot
        # read (heartbeat/fault handling included). _latched_states is the
        # authoritative on/off map the runtime overlays onto every emit.
        self._live_parser: _SnapshotParser | None = None
        self._live_pg_count = 0
        self._latched_states: dict[int, str] = {}
        self._state_on_since: dict[int, float] = {}
        self._pending_off: set[int] = set()
        self._on_device_state_change: Callable[[dict[int, str]], None] | None = None
        # Login-rights bookkeeping (80 1A 0C) and the last sections mode byte
        # seen on a 0x51 packet, captured from every read path under _io_lock.
        # _pending_auth_code names the code being authorised while a login or
        # re-authorisation is in flight, so a rights reply read during it is
        # tagged with the right code.
        self._login_rights: LoginRights | None = None
        self._login_rights_code: str | None = None
        self._pending_auth_code: str | None = None
        self._last_sections_mode: int | None = None
        # Resolve the port last, once every field exists: a failed detection
        # is handled by feeding the reopen backoff, which the fields above
        # back. ensure_serial_port raises SystemExit when no device is found
        # (OSError on a host without the hidraw sysfs tree); the runtime
        # constructs this object on the event-loop thread, where an escaping
        # SystemExit stops the server. A missing panel is an ordinary USB
        # dropout: keep the configured value and let the first
        # _ensure_client_locked redetect and fail into the normal backoff,
        # so the poll reports it and the next one retries.
        try:
            self._serial_port = ensure_serial_port(port)
        except (SystemExit, OSError) as exc:
            LOGGER.warning(
                "No usable panel device at session start (%s); the next open will redetect.",
                exc,
            )
            self._serial_port = port
            self._note_reopen_failure_locked()

    def set_on_device_state_change(self, callback: Callable[[dict[int, str]], None] | None) -> None:
        """Register a callback fired whenever a latched device on/off state
        changes. The argument is a fresh copy of the latched map.

        The callback fires on the I/O lock, from whichever thread observed the
        edge: the stream-reader thread, the poll worker (snapshot read hook) or
        the worker running a configuration operation through the tee client.
        Every emitter holds the lock while it fires so frames reach the event
        loop newest-last. The callback must therefore be cheap, thread-safe and
        must never take the lock itself; the runtime only hands the frame to
        the event loop via ``loop.call_soon_threadsafe`` and returns."""
        self._on_device_state_change = callback

    def configure_live_devices(self, devices, *, pg_count: int, panel_model: str | None) -> None:
        """Seed the persistent live-stream parser with the catalog devices so the
        continuous reader can interpret pushed device-state packets. Latched
        states are preserved across reconfigure so an in-flight motion is not
        cleared by a catalog refresh."""
        with self._io_lock:
            self._live_pg_count = pg_count
            self._live_parser = _SnapshotParser(
                devices_by_id={device.id: device.model_copy(deep=True) for device in devices},
                special_devices=_panel_special_devices(panel_model),
            )

    def snapshot_device_states(self) -> dict[int, str]:
        with self._io_lock:
            return dict(self._latched_states)

    def close(self) -> None:
        self._stop_event.set()
        thread = self._keepalive_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)
        with self._io_lock:
            client = self._client
            if client is not None:
                try:
                    self._graceful_exit_locked(client)
                except Exception:
                    pass
            self._close_client_locked()

    def query_snapshot(
        self,
        *,
        panel_model: str | None,
        pg_count: int,
        devices: list[DeviceStatusModel] | None = None,
        central: CentralStatusModel | None = None,
        query_device_status: bool = True,
        include_diagnostics: bool = False,
        diagnostics_device_ids: list[int] | None = None,
        timeout: float = 2.0,
    ) -> LegacyPanelSnapshot:
        # Base snapshot (sections/PGs/device status) under one short hold. The
        # diagnostics sweep is the only long part, and it runs cooperatively
        # below so it never freezes the real-time reader for its full duration.
        with self._io_lock:
            try:
                client = self._ensure_client_locked()
                self._maybe_refresh_device_state_stream_locked(client)
                job = self._query_snapshot_base_locked(
                    client,
                    panel_model=panel_model,
                    pg_count=pg_count,
                    devices=devices,
                    central=central,
                    query_device_status=query_device_status,
                    include_diagnostics=include_diagnostics,
                    diagnostics_device_ids=diagnostics_device_ids,
                    timeout=timeout,
                )
                if job.parser.login_failed:
                    self._close_client_locked()
                    raise WrongCodeError("Wrong code.")
                if not job.diagnostic_numbers:
                    # Fast path (no diagnostics): finalize under the same hold so
                    # a plain poll is a single, brief lock acquisition.
                    return self._finalize_snapshot_locked(job)
            except Exception:
                self._close_client_locked()
                raise

        # Cooperative diagnostics: one device per lock acquisition, yielding the
        # bus (sleep off-lock) between devices so the stream reader can run:
        # read pushed motion and age out dwell-offs. This caps real-time
        # latency during a sweep at one device's diagnostics window (~2-3s)
        # instead of the whole ~38s sweep.
        for device_id in job.diagnostic_numbers:
            time.sleep(STREAM_LOOP_TICK_SECONDS)
            with self._io_lock:
                try:
                    client = self._client
                    if client is None:
                        break  # session bounced mid-sweep; abandon the rest
                    self._run_one_device_diagnostics_locked(client, job, device_id)
                except Exception:
                    self._close_client_locked()
                    raise

        with self._io_lock:
            try:
                return self._finalize_snapshot_locked(job)
            except Exception:
                self._close_client_locked()
                raise

    def query_system_info(self, *, timeout: float = 2.0) -> LegacySystemInfo:
        with self._io_lock:
            try:
                client = self._ensure_client_locked()
                return self._query_system_info_locked(client, timeout=timeout)
            except Exception:
                self._close_client_locked()
                raise

    def control_section(self, *, section_id: int, action: str, code: str | None = None) -> None:
        if action not in {"disarm", "arm_away", "arm_home", "arm_night"}:
            raise ValueError(f"Unsupported section action: {action}")
        with self._io_lock:
            previous_code = self._authorized_code
            requested_code = code or self._code
            try:
                client = self._ensure_client_locked(auth_code=requested_code)
                self._ensure_authorized_code_locked(client, requested_code)
                if self._should_refresh_control_authorization_locked(requested_code):
                    self._force_authorization_refresh_locked(client, requested_code)
                if self._send_section_control_locked(
                    client,
                    section_id=section_id,
                    action=action,
                    confirmation_timeout=FAST_CONTROL_CONFIRMATION_TIMEOUT_SECONDS,
                ):
                    self._last_control_authorized_at = time.monotonic()
                    return
                LOGGER.warning(
                    "Section control received no panel confirmation on the existing session; refreshing authorization and retrying once."
                )
                self._force_authorization_refresh_locked(client, requested_code)
                if self._send_section_control_locked(
                    client,
                    section_id=section_id,
                    action=action,
                    confirmation_timeout=CONTROL_CONFIRMATION_TIMEOUT_SECONDS,
                ):
                    self._last_control_authorized_at = time.monotonic()
                    return
                raise RuntimeError("Section control was not acknowledged by the panel.")
            except Exception:
                self._restore_previous_authorization_locked(previous_code)
                raise

    def control_pg(self, *, pg_id: int, enabled: bool, code: str | None = None) -> None:
        with self._io_lock:
            previous_code = self._authorized_code
            requested_code = code or self._code
            try:
                client = self._ensure_client_locked(auth_code=requested_code)
                self._ensure_authorized_code_locked(client, requested_code)
                if self._should_refresh_control_authorization_locked(requested_code):
                    self._force_authorization_refresh_locked(client, requested_code)
                if self._send_pg_control_locked(
                    client,
                    pg_id=pg_id,
                    enabled=enabled,
                    confirmation_timeout=FAST_CONTROL_CONFIRMATION_TIMEOUT_SECONDS,
                ):
                    self._last_control_authorized_at = time.monotonic()
                    return
                LOGGER.warning(
                    "PG control received no panel confirmation on the existing session; refreshing authorization and retrying once."
                )
                self._force_authorization_refresh_locked(client, requested_code)
                if self._send_pg_control_locked(
                    client,
                    pg_id=pg_id,
                    enabled=enabled,
                    confirmation_timeout=CONTROL_CONFIRMATION_TIMEOUT_SECONDS,
                ):
                    self._last_control_authorized_at = time.monotonic()
                    return
                raise RuntimeError("PG control was not acknowledged by the panel.")
            except Exception:
                self._restore_previous_authorization_locked(previous_code)
                raise

    # ------------------------------------------- in-session configuration ops

    def write_configuration(self, payload: bytes, *, code: str | None = None) -> int | None:
        """F-Link's HID configuration write, inside this session, under one
        _io_lock hold.

        Setup mode (80 01 0F -> 80 02 1A 0A -> 80 01 0F -> 80 01 12), revision
        before (52 03 1A 01 00 -> 52 07 1B 01 00 <u16>), the 1D 09 00 <msgpack>
        packet (chunked as 48/49/4A when it does not fit one report), the ack
        1D 03 44 00 00, accept (52 01 0C -> 52 03 83 01 02), leave setup
        (80 01 14 -> 80 01 17), and the revision after must have advanced.
        Every packet read on the way is fed to the live device-state parser,
        so motion keeps publishing while the write holds the bus.

        After a fully confirmed write the session keeps its channel and
        re-arms the device-state subscription, as F-Link stays connected
        across its writes (BOUNCE_AFTER_SUCCESSFUL_WRITE=True instead resets
        the channel the way the proven standalone write session ended:
        graceful exit + immediate re-login). When the panel did not answer
        the 80 01 14 with 80 01 17, or on any failure once setup mode was
        entered, the channel is reset either way, so the session is never
        left in configuration mode.

        Returns the revision after the write (None when the panel reported
        none). Raises ConfigWriteError for every failure (step refused or
        timed out, wrong code, USB gone); the session is then either reopened
        or closed for the next poll.
        """
        code = code or self._code
        with self._io_lock:
            try:
                client = self._ensure_client_locked(auth_code=code)
                self._ensure_authorized_code_locked(client, code)
            except WrongCodeError as exc:
                # AUTH_END already went out: we are logged out on the panel.
                self._close_client_locked()
                raise ConfigWriteError(f"The panel refused the write code: {exc}") from exc
            except JablotronUSBStreamError as exc:
                self._close_client_locked()
                self._redetect_serial_port_locked()
                raise ConfigWriteError(f"USB link failed before the write: {exc}") from exc
            tee = self._tee_client(client)
            entered_setup = False  # True once enter_setup_mode returned (80 01 12 seen)
            # True once the panel confirmed the accept (52 03 83 01 02). From
            # then on the leave step sends its own 80 01 14; before that an
            # error path has to send it (an unconfirmed accept raises before
            # 80 01 14 goes out, with the panel still in configuration mode).
            accept_confirmed = False
            escaped = True
            revision_before: int | None = None
            revision_after: int | None = None
            try:
                try:
                    enter_setup_mode(tee, verbose=False, assume_logged_in=True)
                    entered_setup = True
                    revision_before = read_config_revision(tee, verbose=False)
                    write_config_over_hid(tee, payload, verbose=False)
                    send_accept_configuration(tee, verbose=False)
                    accept_confirmed = True
                    escaped = leave_configuration_mode(tee, verbose=False)
                    revision_after = verify_config_revision_advanced(tee, before=revision_before, verbose=False)
                except SystemExit as exc:
                    raise ConfigWriteError(str(exc)) from None
            except JablotronUSBStreamError as exc:
                self._close_client_locked()
                self._redetect_serial_port_locked()
                raise ConfigWriteError(f"USB link failed during the write: {exc}") from exc
            except BaseException:
                # 80 01 14 goes out only from inside configuration mode (80 01 12
                # seen) and only while the accept is unconfirmed: a missing ack,
                # a refused or unconfirmed accept. Once the accept was confirmed
                # the leave step has sent its own. A failed entry (no 80 01 12,
                # or another configuration session holds the panel) gets the
                # graceful exit for our channel only.
                if entered_setup and not accept_confirmed:
                    self._leave_setup_mode_locked(tee)
                self._bounce_client_locked(reopen=True, code=code)
                raise
            if not escaped:
                LOGGER.warning(
                    "The panel did not acknowledge leaving configuration mode after the write (no 80 01 17); "
                    "resetting the channel."
                )
                self._bounce_client_locked(reopen=True, code=code)
            elif BOUNCE_AFTER_SUCCESSFUL_WRITE:
                self._bounce_client_locked(reopen=True, code=code)
            else:
                try:
                    perform_enable_device_states(client)
                    self._last_enable_device_states_at = time.monotonic()
                except Exception:
                    LOGGER.warning(
                        "Could not re-arm the device-state subscription after the write; resetting the channel.",
                        exc_info=True,
                    )
                    self._bounce_client_locked(reopen=True, code=code)
            LOGGER.info(
                "In-session configuration write applied: revision 0x%04x -> %s, sections_mode=%s",
                revision_before or 0,
                None if revision_after is None else f"0x{revision_after:04x}",
                describe_sections_mode(self._last_sections_mode),
            )
            return revision_after

    def _leave_setup_mode_locked(self, tee: _SessionTeeClient) -> None:
        """Error path from inside setup mode before the accept: send 80 01 14
        and wait SETUP_MODE_LEAVE_TIMEOUT_SECONDS for 80 01 17 through the tee.
        Logs the outcome; never raises. The caller resets the channel afterwards
        either way."""
        try:
            send_report(tee, REPORT_800114, verbose=False)
            reply = wait_for_reply(
                tee,
                prefix_hex=CONFIGURATION_ESCAPED_PREFIX,
                timeout=SETUP_MODE_LEAVE_TIMEOUT_SECONDS,
                verbose=False,
                label="leave-setup",
            )
            if reply is None:
                LOGGER.warning("No 80 01 17 after the error-path 80 01 14.")
        except Exception:
            LOGGER.debug("Leaving setup mode after a failed write raised", exc_info=True)

    def _bounce_client_locked(self, *, reopen: bool = False, code: str | None = None) -> None:
        """Reset this session's channel: graceful exit (best effort; the F-Link
        exit sequence 94 02 01 00 / 80 01 01 / 52 01 0E / 52 01 02 with its
        drain through the packet hook) and close. With reopen=True, log in
        again at once via _ensure_client_locked (fresh login, 0x13 re-armed,
        80 1A 0C captured by the drain) so the stream is back before the lock
        is released; a reopen failure is logged and left to the next poll
        (backoff applies). Keeps the stream thread, which idles while _client
        is None."""
        client = self._client
        if client is not None:
            try:
                self._graceful_exit_locked(client)
            except Exception:
                LOGGER.debug("Graceful exit during channel reset raised", exc_info=True)
        self._close_client_locked()
        if reopen:
            try:
                self._ensure_client_locked(auth_code=code or self._code)
            except Exception:
                LOGGER.warning(
                    "Could not reopen the status session after a configuration op; the next poll will retry.",
                    exc_info=True,
                )

    def trigger_export(self, *, code: str | None = None) -> None:
        """Run F-Link's export refresh sequence inside this session, under one
        _io_lock hold, every reply going through the live parser.

        The sequence is jablotron_re_tools.send_flink_export_refresh_sequence
        unchanged: 52 01 02 twice, 80 01 0F, 52 01 02, 52 02 13 05 9A 00, the
        logon-info line, 52 01 25, then up to 8 s waiting for 52 07 83 01 25
        with 52 01 02 keepalives, then 52 01 02 / 80 01 02 and the drains. The
        block read of EXPORT.CFG is the caller's job (SCSI, no HID), and the
        caller must call finish_export() afterwards: the sequence leaves the
        panel in configuration-active sections mode. When the reload-complete
        reply does not come, the channel is reset first (graceful exit +
        reopen, so a retry starts from a fresh login, the shape that recovered
        live; F-Link's same-channel retry never did) and ExportRefreshIncomplete
        is raised.
        """
        code = code or self._code
        with self._io_lock:
            try:
                client = self._ensure_client_locked(auth_code=code)
                self._ensure_authorized_code_locked(client, code)
            except WrongCodeError as exc:
                self._close_client_locked()
                raise ExportRefreshIncomplete(f"The panel refused the session code: {exc}") from exc
            except JablotronUSBStreamError as exc:
                self._close_client_locked()
                self._redetect_serial_port_locked()
                raise ExportRefreshIncomplete(f"USB link failed before the export trigger: {exc}") from exc
            tee = self._tee_client(client)
            try:
                send_flink_export_refresh_sequence(tee, verbose=False)
            except SystemExit as exc:
                self._bounce_client_locked(reopen=True, code=code)
                raise ExportRefreshIncomplete(str(exc)) from None
            except JablotronUSBStreamError as exc:
                self._close_client_locked()
                self._redetect_serial_port_locked()
                raise ExportRefreshIncomplete(f"USB link failed during the export trigger: {exc}") from exc
            LOGGER.debug(
                "In-session export trigger complete; sections_mode=%s",
                describe_sections_mode(self._last_sections_mode),
            )

    def finish_export(self) -> None:
        """Called after the block read of EXPORT.CFG, the point where the
        separate cleanup session ran before (whether the file stays
        materialised without a session is untested, so this never runs
        earlier).

        Queries the sections mode through the tee (52 01 0E, read up to
        SECTIONS_MODE_QUERY_TIMEOUT_SECONDS). Exited mode: keep the channel
        and re-arm the device-state subscription. Configuration-active mode,
        or no 0x51 reply: reset the channel (graceful exit, the proven
        exit-only cleanup, then reopen). Logs the mode at INFO either way.
        Never raises.

        The lock is released during the block read, and the stream reader
        closes the client on any read error in that window. The trigger has
        still put the panel in configuration-active mode, so a missing client
        is not a reason to skip this step: log in again first (the separate
        cleanup session of the old path did exactly that) and run the same
        check, so the exit sequence is sent when the mode calls for it. When
        the reopen fails (device gone, backoff) there is nothing to exit on;
        log it and leave the retry to the next poll.
        """
        with self._io_lock:
            client = self._client
            if client is None:
                try:
                    client = self._ensure_client_locked()
                except Exception:
                    LOGGER.warning(
                        "The status session was lost during the export read and could not be "
                        "reopened; the panel may still be in configuration mode until the next poll.",
                        exc_info=True,
                    )
                    return
            mode: int | None = None
            try:
                self._last_sections_mode = None
                tee = self._tee_client(client)
                perform_sections_query(tee)
                deadline = time.monotonic() + SECTIONS_MODE_QUERY_TIMEOUT_SECONDS
                while self._last_sections_mode is None and time.monotonic() < deadline:
                    list(tee.read_packets(timeout=0.1))
                mode = self._last_sections_mode
            except Exception:
                LOGGER.debug("Sections-mode query after the export read raised", exc_info=True)
            if mode == EXITED_SECTIONS_MODE:
                LOGGER.info(
                    "Export read finished with the panel in %s; keeping the status session.",
                    describe_sections_mode(mode),
                )
                try:
                    perform_enable_device_states(client)
                    self._last_enable_device_states_at = time.monotonic()
                except Exception:
                    LOGGER.warning(
                        "Could not re-arm the device-state subscription after the export read; "
                        "closing the session for the next poll.",
                        exc_info=True,
                    )
                    self._close_client_locked()
                return
            LOGGER.info(
                "Export read finished with the panel in %s; resetting the status session channel.",
                describe_sections_mode(mode),
            )
            self._bounce_client_locked(reopen=True)

    @property
    def sections_mode(self) -> int | None:
        """The last sections-mode byte seen on a 0x51 packet (observability)."""
        return self._last_sections_mode

    def login_rights_for_code(self, code: str, *, timeout: float = LOGIN_RIGHTS_WAIT_SECONDS) -> LoginRights | None:
        """The rights the panel reported (80 1A 0C) for ``code`` on this session.

        Opens and logs in if needed (the login drain captures the reply) and
        re-authorises if a control operation left another code active. In the
        common case, the write code equal to the session code and the session
        already logged in, the rights were captured by the login drain and this
        returns without any I/O.

        If no reply for ``code`` has been captured, read for ``timeout``, then
        fall back to one channel reset with reopen: a fresh login is the proven
        point where 80 1A 0C arrives (whether an AUTH_END + code
        re-authorisation repeats it is uncaptured). Returns None when the panel
        still reported nothing; the caller then probes as before. Raises
        ConfigWriteError on a refused code or a dead link, with the session
        closed.
        """
        with self._io_lock:
            try:
                client = self._ensure_client_locked(auth_code=code)
                self._ensure_authorized_code_locked(client, code)
                if self._login_rights_code != code:
                    self._await_login_rights_locked(client, code, timeout)
                if self._login_rights_code != code:
                    LOGGER.info("No login rights reported for the write code on this channel; logging in afresh.")
                    # A fresh login; its drain captures the 80 1A 0C reply.
                    self._bounce_client_locked(reopen=True, code=code)
                    if self._client is not None and self._login_rights_code != code:
                        self._await_login_rights_locked(self._client, code, timeout)
            except WrongCodeError as exc:
                self._close_client_locked()
                raise ConfigWriteError(f"The panel refused the write code: {exc}") from exc
            except JablotronUSBStreamError as exc:
                self._close_client_locked()
                self._redetect_serial_port_locked()
                raise ConfigWriteError(f"USB link failed while reading login rights: {exc}") from exc
            return self._login_rights if self._login_rights_code == code else None

    def _await_login_rights_locked(self, client: JablotronUSBClient, code: str, timeout: float) -> None:
        """Read through the tee until a login-rights reply tagged with ``code``
        arrives or ``timeout`` runs out. Every packet read still reaches the
        live device-state parser."""
        tee = self._tee_client(client)
        deadline = time.monotonic() + timeout
        while self._login_rights_code != code and time.monotonic() < deadline:
            list(tee.read_packets(timeout=0.1))

    def _ensure_client_locked(self, auth_code: str | None = None) -> JablotronUSBClient:
        if self._client is not None:
            return self._client

        # Reopen backoff: after a (re)open failure, refuse to retry until the
        # deadline so a truly-absent device is not hammered on every poll/request.
        # Only consult the clock while actually in a failure streak, so the
        # steady-state open path issues no extra time.monotonic() call.
        if self._reopen_failures > 0:
            now = time.monotonic()
            if now < self._next_reopen_allowed_at:
                raise JablotronUSBStreamError(
                    f"USB device unavailable on {self._serial_port}; backing off "
                    f"{self._next_reopen_allowed_at - now:.1f}s before the next reopen attempt"
                )
            # A /dev/hidrawN renumbering is picked up before we try to reopen.
            self._redetect_serial_port_locked()

        try:
            client = JablotronUSBClient(self._serial_port)
        except OSError as exc:
            # Device path missing/dead: feed backoff and surface a catchable error
            # without ever reaching the expensive login sequence.
            self._note_reopen_failure_locked()
            raise JablotronUSBStreamError(
                f"Failed to open USB device {self._serial_port}: {exc}"
            ) from exc

        active_code = auth_code or self._code
        self._pending_auth_code = active_code
        try:
            perform_login(client, active_code, reset=self._reset)
            time.sleep(0.5)
            perform_enable_device_states(client)
            self._last_enable_device_states_at = time.monotonic()
            perform_sections_query(client)
            # The drain runs the packet hook, so the 80 1A 0C login reply is
            # captured (and tagged with active_code) at every login.
            self._drain_packets_locked(client, timeout=0.5)
        except Exception:
            client.close()
            self._pending_auth_code = None
            self._note_reopen_failure_locked()
            raise

        self._client = client
        self._authorized_code = active_code
        self._pending_auth_code = None
        self._last_control_authorized_at = time.monotonic()
        # Successful (re)open clears the backoff streak.
        self._reopen_failures = 0
        self._next_reopen_allowed_at = 0.0
        self._ensure_keepalive_thread_locked()
        return client

    def _note_reopen_failure_locked(self) -> None:
        """Record a failed (re)open and arm the backoff deadline."""
        self._reopen_failures += 1
        delay = min(
            STREAM_REOPEN_DELAY_SECONDS * self._reopen_failures,
            STREAM_REOPEN_MAX_DELAY_SECONDS,
        )
        self._next_reopen_allowed_at = time.monotonic() + delay
        LOGGER.debug(
            "USB (re)open attempt %d failed on %s; backing off %.1fs",
            self._reopen_failures,
            self._serial_port,
            delay,
        )

    def _redetect_serial_port_locked(self) -> None:
        """Re-resolve the serial port so a /dev/hidrawN re-enumeration is followed.

        Never raises: ``ensure_serial_port`` raises ``SystemExit`` when no device
        is found, and ``Jablotron.detect_serial_port`` may raise ``OSError`` on a
        host without the hidraw sysfs tree. In either case we keep the previously
        resolved port and let the subsequent open fail into the normal backoff
        path. Must never raise, because it is also called from the keepalive
        thread's ``except Exception`` handler where an escaping ``SystemExit``
        would silently kill the daemon thread.
        """
        try:
            new_port = ensure_serial_port(self._configured_port)
        except (SystemExit, OSError) as exc:
            LOGGER.debug("Serial-port redetection found no usable device: %s", exc)
            return
        if new_port != self._serial_port:
            LOGGER.info("Serial port changed from %s to %s", self._serial_port, new_port)
            self._serial_port = new_port

    def _ensure_keepalive_thread_locked(self) -> None:
        if self._keepalive_thread is not None and self._keepalive_thread.is_alive():
            return
        self._stop_event.clear()
        self._keepalive_thread = threading.Thread(
            target=self._stream_loop,
            name="jablotron-session-stream",
            daemon=True,
        )
        self._keepalive_thread.start()

    def _close_client_locked(self) -> None:
        client = self._client
        self._client = None
        self._last_enable_device_states_at = 0.0
        self._authorized_code = None
        self._last_control_authorized_at = 0.0
        self._login_rights = None
        self._login_rights_code = None
        self._pending_auth_code = None
        if client is None:
            return
        try:
            client.close()
        except Exception:
            pass

    def _ensure_authorized_code_locked(self, client: JablotronUSBClient, code: str) -> None:
        if self._authorized_code == code:
            return
        # AUTHORISATION_END clears the panel's authorization immediately.
        # Invalidate our cache before awaiting the result so a wrong-code
        # rejection cannot leave us thinking the previous code is still
        # authorized on the panel (it isn't).
        self._authorized_code = None
        self._last_control_authorized_at = 0.0
        # The rights on record belong to the code that was just logged out.
        self._login_rights = None
        self._login_rights_code = None
        self._pending_auth_code = code
        try:
            client.send_packets(
                [
                    Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END),
                    Jablotron.create_packet_authorisation_code(code),
                ]
            )
            _await_login_success(self._tee_client(client))
            time.sleep(0.5)
            self._authorized_code = code
        finally:
            self._pending_auth_code = None
        self._last_control_authorized_at = time.monotonic()

    def _restore_previous_authorization_locked(self, previous_code: str | None) -> None:
        client = self._client
        if client is None or previous_code is None or previous_code == self._authorized_code:
            return
        try:
            self._ensure_authorized_code_locked(client, previous_code)
        except Exception:
            self._close_client_locked()

    def _graceful_exit_locked(self, client: JablotronUSBClient) -> None:
        client.send_packet(EXIT_DIAGNOSTICS_OFF_PACKET)
        time.sleep(0.03)
        client.send_packets(
            [
                Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END),
                Jablotron.create_packet_command(b"\x0e"),
            ]
        )
        time.sleep(0.06)
        client.send_packet(Jablotron.create_packet_command(b"\x02"))
        self._drain_packets_locked(client, timeout=0.8)

    def _stream_loop(self) -> None:
        """Continuous keepalive + device-state reader.

        Each tick (off the lock, so control is never starved more than one burst)
        it takes _io_lock and: sends the ~1s keepalive when due, renews the
        device-state stream, drains pushed device-state packets into the live
        parser/latch, and ages out any dwell-deferred "off". When a latched
        state changed it notifies the runtime while still holding the lock, so
        its frame cannot be overtaken by a newer one from the poll worker or a
        configuration operation and then delivered stale (the callback only
        schedules work on the event loop). The client is only consumed here,
        never opened — (re)open + backoff stay owned by _ensure_client_locked,
        driven by the snapshot poll."""
        last_keepalive = 0.0
        while not self._stop_event.wait(STREAM_LOOP_TICK_SECONDS):
            with self._io_lock:
                client = self._client
                if client is not None:
                    try:
                        now = time.monotonic()
                        if now - last_keepalive >= STREAM_KEEPALIVE_INTERVAL_SECONDS:
                            client.send_packet(RAW_SESSION_KEEPALIVE)
                            last_keepalive = now
                        self._maybe_refresh_device_state_stream_locked(client)
                        changed = False
                        if self._live_parser is not None:
                            for packet in client.read_packets(timeout=STREAM_READ_BUDGET_SECONDS):
                                self._inspect_packet_locked(packet)
                                self._live_parser.parse_packet(packet, pg_count=self._live_pg_count)
                                # Sync after *every* packet so the rising edge of a
                                # same-burst on->off pulse is latched before the
                                # "off" is parsed.
                                if self._sync_latch_from_live_parser_locked(time.monotonic()):
                                    changed = True
                        if self._expire_pending_offs_locked(time.monotonic()):
                            changed = True
                        if changed:
                            self._notify_latched_locked()
                    except Exception:
                        self._close_client_locked()
                        # Follow a re-enumerated port so the next reopen targets it.
                        # _redetect_serial_port_locked never raises (it swallows the
                        # SystemExit ensure_serial_port raises when no device is
                        # found), so it cannot kill this daemon thread.
                        self._redetect_serial_port_locked()

    # ----------------------------------------------------- device-state latch

    def _tee_client(self, client: JablotronUSBClient) -> _SessionTeeClient:
        return _SessionTeeClient(self, client)

    def _inspect_packet_locked(self, packet: bytes) -> None:
        """Session bookkeeping for every packet read by any path: the
        login-rights reply (80 1A 0C -> LoginRights, tagged with the code being
        authorised) and the sections-mode trailer byte of a 0x51 packet (its
        last byte, as jablotron_re_tools.extract_sections_state_mode reads it)."""
        rights = parse_login_rights(packet)
        if rights is not None:
            self._login_rights = rights
            self._login_rights_code = self._authorized_code or self._pending_auth_code
        if Jablotron._is_sections_states_packet(packet) and packet:
            self._last_sections_mode = packet[-1]

    def _observe_packet_locked(self, packet: bytes) -> None:
        """Tee/drain hook: bookkeeping, then the live parser with the
        per-packet latch sync and emit. Never raises: a malformed pushed packet
        must not abort the configuration operation that happens to be reading
        (the stream loop would close the client on the same exception; here the
        operation owns the channel and decides)."""
        try:
            self._inspect_packet_locked(packet)
            if self._live_parser is None:
                return
            self._live_parser.parse_packet(packet, pg_count=self._live_pg_count)
            if self._sync_latch_from_live_parser_locked(time.monotonic()):
                self._notify_latched_locked()
        except Exception:
            LOGGER.debug(
                "Live-parser bookkeeping failed for a packet read inside a configuration op", exc_info=True
            )

    def _after_read_locked(self) -> None:
        """Post-read dwell hook for the tee: a dwell-deferred off is published
        within one read slice even when no packet arrives. Never raises."""
        try:
            if self._expire_pending_offs_locked(time.monotonic()):
                self._notify_latched_locked()
        except Exception:
            LOGGER.debug("Dwell expiry failed inside a configuration op", exc_info=True)

    def _notify_latched_locked(self) -> None:
        """Fire the device-state callback with a copy of the latch, under the
        lock. Ordering: every emitter holds _io_lock while it fires, so frames
        reach the event loop newest-last. Swallows callback errors."""
        callback = self._on_device_state_change
        if callback is None:
            return
        snapshot = dict(self._latched_states)
        try:
            callback(snapshot)
        except Exception:
            LOGGER.debug("Device-state change callback failed", exc_info=True)

    def _sync_latch_from_live_parser_locked(self, now: float) -> bool:
        if self._live_parser is None:
            return False
        changed = False
        for device_id, device in self._live_parser.devices_by_id.items():
            if self._apply_latched_state_locked(device_id, device.state, now):
                changed = True
        return changed

    def _apply_latched_state_locked(self, device_id: int, state: str | None, now: float) -> bool:
        """Fold a freshly observed on/off into the latch with rising-edge dwell.

        Returns True when the published (latched) state changed. A trailing "off"
        seen within MOTION_ON_MIN_DWELL_SECONDS of the rising edge is deferred
        (recorded in _pending_off) so a brief pulse stays observable; it is
        applied later by _expire_pending_offs_locked or by a subsequent "off"
        once the dwell has elapsed."""
        if state not in ("on", "off"):
            return False
        current = self._latched_states.get(device_id)
        if state == "on":
            self._pending_off.discard(device_id)
            if current != "on":
                self._latched_states[device_id] = "on"
                self._state_on_since[device_id] = now
                return True
            return False
        # state == "off"
        if current == "on":
            if now - self._state_on_since.get(device_id, 0.0) >= MOTION_ON_MIN_DWELL_SECONDS:
                self._latched_states[device_id] = "off"
                self._pending_off.discard(device_id)
                return True
            self._pending_off.add(device_id)
            return False
        if current != "off":
            self._latched_states[device_id] = "off"
            return True
        return False

    def _expire_pending_offs_locked(self, now: float) -> bool:
        if not self._pending_off:
            return False
        changed = False
        for device_id in list(self._pending_off):
            if now - self._state_on_since.get(device_id, 0.0) >= MOTION_ON_MIN_DWELL_SECONDS:
                self._latched_states[device_id] = "off"
                self._pending_off.discard(device_id)
                changed = True
        return changed

    def _maybe_refresh_device_state_stream_locked(self, client: JablotronUSBClient) -> None:
        now = time.monotonic()
        if now - self._last_enable_device_states_at < DEVICE_STATE_RENEWAL_SECONDS:
            return
        perform_enable_device_states(client)
        self._last_enable_device_states_at = now

    def _force_authorization_refresh_locked(self, client: JablotronUSBClient, code: str) -> None:
        client.send_packets(
            [
                Jablotron.create_packet_authorisation_code(code),
                Jablotron.create_packet_enable_device_states(),
            ]
        )
        _await_login_success(self._tee_client(client))
        self._drain_packets_locked(client, timeout=AUTHORIZATION_REFRESH_SETTLE_SECONDS)
        self._last_enable_device_states_at = time.monotonic()
        self._last_control_authorized_at = self._last_enable_device_states_at

    def _should_refresh_control_authorization_locked(self, code: str) -> bool:
        if self._authorized_code != code or self._last_control_authorized_at <= 0.0:
            return False
        return (time.monotonic() - self._last_control_authorized_at) > CONTROL_AUTHORIZATION_IDLE_SECONDS

    def _send_pg_control_locked(
        self,
        client: JablotronUSBClient,
        *,
        pg_id: int,
        enabled: bool,
        confirmation_timeout: float,
    ) -> bool:
        payload = Jablotron.int_to_bytes(pg_id - 1) + (b"\x01" if enabled else b"\x00")
        client.send_packet(Jablotron.create_packet_ui_control(UI_CONTROL_TOGGLE_PG_OUTPUT, payload))
        time.sleep(PG_CONTROL_QUERY_SETTLE_SECONDS)
        perform_sections_query(client)
        return self._await_pg_control_confirmation_locked(
            client,
            pg_id=pg_id,
            enabled=enabled,
            timeout=confirmation_timeout,
        )

    def _send_section_control_locked(
        self,
        client: JablotronUSBClient,
        *,
        section_id: int,
        action: str,
        confirmation_timeout: float,
    ) -> bool:
        int_packets = {
            "disarm": 143,
            "arm_away": 159,
            "arm_home": 175,
            "arm_night": 175,
        }
        modify_packet = Jablotron.int_to_bytes(int_packets[action] + section_id)
        self._drain_packets_locked(client, timeout=0.05)
        client.send_packet(Jablotron.create_packet_ui_control(UI_CONTROL_MODIFY_SECTION, modify_packet))
        time.sleep(PG_CONTROL_QUERY_SETTLE_SECONDS)
        perform_sections_query(client)
        return self._await_section_control_confirmation_locked(
            client,
            section_id=section_id,
            action=action,
            timeout=confirmation_timeout,
        )

    def _await_pg_control_confirmation_locked(
        self,
        client: JablotronUSBClient,
        *,
        pg_id: int,
        enabled: bool,
        timeout: float = CONTROL_CONFIRMATION_TIMEOUT_SECONDS,
    ) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            batch = list(client.read_packets(timeout=min(0.1, remaining)))
            if not batch:
                continue
            for packet in batch:
                if Jablotron._is_login_error_packet(packet):
                    raise WrongCodeError("Wrong code.")
                if Jablotron._is_pg_output_toggle_packet(packet):
                    return True
                if Jablotron._is_pg_outputs_states_packet(packet):
                    states_start = 2
                    states_end = states_start + Jablotron.bytes_to_int(packet[1:2])
                    states = Jablotron._bytes_to_reverse_binary(packet[states_start:states_end])
                    if pg_id - 1 < len(states):
                        state = states[(pg_id - 1):pg_id]
                        if (state == "1") is enabled:
                            return True
        return False

    def _await_section_control_confirmation_locked(
        self,
        client: JablotronUSBClient,
        *,
        section_id: int,
        action: str,
        timeout: float = CONTROL_CONFIRMATION_TIMEOUT_SECONDS,
    ) -> bool:
        confirmation_states = {
            "disarm": {"disarmed", "off"},
            "arm_away": {"armed_away", "arming", "pending"},
            "arm_home": {"armed_night", "arming", "pending"},
            "arm_night": {"armed_night", "arming", "pending"},
        }[action]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            batch = list(client.read_packets(timeout=min(0.1, remaining)))
            if not batch:
                continue
            for packet in batch:
                if Jablotron._is_login_error_packet(packet):
                    raise WrongCodeError("Wrong code.")
                if not Jablotron._is_sections_states_packet(packet):
                    continue
                section_states = Jablotron._convert_sections_states_packet_to_sections_states(packet)
                state = section_states.get(section_id)
                if state is None:
                    continue
                if _section_state_to_name(state) in confirmation_states:
                    return True
        return False

    def _drain_packets_locked(self, client: JablotronUSBClient, *, timeout: float) -> list[bytes]:
        """Read until a quiet slice or the timeout. Every packet goes through
        the full packet hook: a device-state bitmap pushed during a login
        drain, a control-op settle or the graceful exit is device state and
        belongs in the latch, and the login-rights reply is captured here."""
        packets: list[bytes] = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            batch = list(client.read_packets(timeout=min(0.1, remaining)))
            if not batch:
                break
            for packet in batch:
                self._observe_packet_locked(packet)
            packets.extend(batch)
        return packets

    def _read_into_parser_locked(
        self,
        client: JablotronUSBClient,
        parser: _SnapshotParser,
        *,
        pg_count: int,
        timeout: float,
        stop_on_first_gap: bool = True,
        on_packet: Callable[[], None] | None = None,
    ) -> None:
        deadline = time.monotonic() + timeout
        saw_packets = False
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            batch = list(client.read_packets(timeout=min(0.2, remaining)))
            if not batch:
                if saw_packets and stop_on_first_gap:
                    break
                continue
            saw_packets = True
            for packet in batch:
                self._inspect_packet_locked(packet)
                parser.parse_packet(packet, pg_count=pg_count)
                # Surface device-state edges as they are parsed, even mid-read.
                # A long diagnostics read holds the bus for many seconds; without
                # this hook a motion edge captured during it would not be emitted
                # until the whole snapshot finished, reintroducing the latency.
                if on_packet is not None:
                    on_packet()

    def _query_snapshot_base_locked(
        self,
        client: JablotronUSBClient,
        *,
        panel_model: str | None,
        pg_count: int,
        devices: list[DeviceStatusModel] | None,
        central: CentralStatusModel | None,
        query_device_status: bool,
        include_diagnostics: bool,
        diagnostics_device_ids: list[int] | None,
        timeout: float,
    ) -> _SnapshotJob:
        """Run the base snapshot (sections/PGs/device status) and compute the
        diagnostics work-list. Returns a _SnapshotJob the caller drives through
        the cooperative diagnostics sweep and then finalizes."""
        devices_by_id = {device.id: device.model_copy(deep=True) for device in (devices or [])}
        special_devices = _panel_special_devices(panel_model)
        parser = _SnapshotParser(
            devices_by_id=devices_by_id,
            special_devices=special_devices,
            central=central.model_copy(deep=True) if central is not None else CentralStatusModel(),
        )
        seed_states = {device_id: device.state for device_id, device in devices_by_id.items()}
        # Real-time edge emit during this read: whoever holds the bus (fast poll
        # or a long diagnostics sweep) publishes motion edges per-packet, so
        # device-state latency is decoupled from how long the read holds the lock.
        on_packet = lambda: self._emit_snapshot_device_edges_locked(parser, seed_states)

        # Parse (don't discard) any device-state packets pushed since the last
        # read so a motion edge buffered just before this poll isn't thrown away;
        # the stale sections reply mixed in is harmlessly overwritten by the
        # fresh perform_sections_query below.
        for packet in self._drain_packets_locked(client, timeout=0.05) or ():
            parser.parse_packet(packet, pg_count=pg_count)
        on_packet()
        perform_sections_query(client)

        if query_device_status:
            status_device_numbers = sorted(
                {device_id for device_id in devices_by_id}
                | {device_id for device_id in special_devices.values() if isinstance(device_id, int)}
            )
            if status_device_numbers:
                client.send_packets([Jablotron.create_packet_device_info(device_id) for device_id in status_device_numbers])

        self._read_into_parser_locked(client, parser, pg_count=pg_count, timeout=timeout, on_packet=on_packet)

        diagnostic_numbers: list[int] = []
        if include_diagnostics:
            if diagnostics_device_ids is not None:
                # Targeted retry (e.g. chasing an unresolved wireless
                # temperature): re-poll only the named devices, not the whole
                # bus, so the sweep stays short.
                wanted = set(diagnostics_device_ids)
                diagnostic_numbers = [
                    device.id
                    for device in sorted(
                        (
                            device
                            for device in devices_by_id.values()
                            if device.id in wanted and _device_supports_diagnostics(device)
                        ),
                        key=_diagnostics_priority,
                    )
                ]
            else:
                diagnostic_numbers = [
                    device.id
                    for device in sorted(
                        (device for device in devices_by_id.values() if _device_supports_diagnostics(device)),
                        key=_diagnostics_priority,
                    )
                ]
                diagnostic_numbers.extend(
                    device_id
                    for key, device_id in special_devices.items()
                    if key in {"lan", "gsm"} and isinstance(device_id, int)
                )
                diagnostic_numbers.append(0)

        return _SnapshotJob(
            parser=parser,
            devices_by_id=devices_by_id,
            special_devices=special_devices,
            seed_states=seed_states,
            pg_count=pg_count,
            diagnostic_numbers=diagnostic_numbers,
        )

    def _run_one_device_diagnostics_locked(self, client: JablotronUSBClient, job: _SnapshotJob, device_id: int) -> None:
        """Diagnose a single device into the job's parser. Called under a fresh
        lock acquisition per device so the stream reader interleaves between
        devices (see query_snapshot's cooperative sweep)."""
        parser = job.parser
        pg_count = job.pg_count
        on_packet = lambda: self._emit_snapshot_device_edges_locked(parser, job.seed_states)
        device = job.devices_by_id.get(device_id)
        packets = [
            Jablotron._create_packet_device_diagnostics_start(device_id),
            Jablotron._create_packet_device_diagnostics_force_info(device_id),
        ]
        if device is not None:
            packets.insert(0, Jablotron.create_packet_device_info(device_id))
        client.send_packets(packets)
        self._read_into_parser_locked(
            client,
            parser,
            pg_count=pg_count,
            timeout=DEFAULT_DIAGNOSTICS_TIMEOUT_SECONDS if device is None else _diagnostics_timeout_for_device(device),
            stop_on_first_gap=False,
            on_packet=on_packet,
        )
        client.send_packet(Jablotron._create_packet_device_diagnostics_end(device_id))
        self._read_into_parser_locked(client, parser, pg_count=pg_count, timeout=0.1, on_packet=on_packet)

    def _finalize_snapshot_locked(self, job: _SnapshotJob) -> LegacyPanelSnapshot:
        # The latch (fed by the continuous stream reader) is the authority for
        # device on/off. Fold in any genuine edge this snapshot itself observed,
        # then overlay the latched value so the emitted snapshot agrees with the
        # stream and a dwell-held motion is not stomped back to "off".
        self._reconcile_snapshot_devices_locked(job.devices_by_id, job.seed_states)

        return LegacyPanelSnapshot(
            sections=job.parser.sections,
            pgs=job.parser.pgs,
            devices=list(job.parser.devices_by_id.values()),
            central=job.parser.central,
            service_mode=job.parser.service_mode,
        )

    def _emit_snapshot_device_edges_locked(
        self, parser: _SnapshotParser, seed_states: dict[int, str | None]
    ) -> bool:
        """Per-packet hook for snapshot/diagnostics reads: fold any device whose
        parsed state changed since last seen into the latch and notify the
        runtime immediately, and age out dwell-deferred offs. This is what keeps
        motion real-time while a multi-second diagnostics read holds the bus
        (the stream loop is blocked on the lock during that read, so it cannot
        do this itself). ``seed_states`` is advanced as edges are applied so each
        change is fed exactly once and a stale baseline never regresses the latch."""
        now = time.monotonic()
        changed = False
        for device_id, device in parser.devices_by_id.items():
            observed = device.state
            if observed in ("on", "off") and observed != seed_states.get(device_id):
                seed_states[device_id] = observed
                if self._apply_latched_state_locked(device_id, observed, now):
                    changed = True
        if self._expire_pending_offs_locked(now):
            changed = True
        if changed:
            self._notify_latched_locked()
        return changed

    def _reconcile_snapshot_devices_locked(
        self, devices_by_id: dict[int, DeviceStatusModel], seed_states: dict[int, str | None]
    ) -> None:
        now = time.monotonic()
        for device_id, device in devices_by_id.items():
            observed = device.state
            # Only feed the latch when a real packet changed the state during
            # this read (observed != the seed it started from), never the stale
            # baseline — that would let an old snapshot value regress a newer
            # streamed edge.
            if observed in ("on", "off") and observed != seed_states.get(device_id):
                self._apply_latched_state_locked(device_id, observed, now)
            latched = self._latched_states.get(device_id)
            if latched is not None:
                device.state = latched

    def _query_system_info_locked(self, client: JablotronUSBClient, *, timeout: float) -> LegacySystemInfo:
        model = None
        hardware_version = None
        firmware_version = None
        self._drain_packets_locked(client, timeout=0.05)
        perform_system_info_query(
            client,
            [SystemInfo.MODEL, SystemInfo.HARDWARE_VERSION, SystemInfo.FIRMWARE_VERSION],
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            batch = list(client.read_packets(timeout=min(0.2, remaining)))
            if not batch:
                continue
            for packet in batch:
                if Jablotron._is_login_error_packet(packet):
                    self._close_client_locked()
                    raise WrongCodeError("Wrong code.")
                if packet[:1] != b"\x40":
                    continue
                try:
                    info_type = SystemInfo(Jablotron.bytes_to_int(packet[2:3]))
                except ValueError:
                    continue
                try:
                    value = Jablotron.decode_system_info_packet(packet)
                except UnicodeDecodeError:
                    continue
                if info_type == SystemInfo.MODEL:
                    model = value
                elif info_type == SystemInfo.HARDWARE_VERSION:
                    hardware_version = value
                elif info_type == SystemInfo.FIRMWARE_VERSION:
                    firmware_version = value
            if model is not None and hardware_version is not None and firmware_version is not None:
                break
        return LegacySystemInfo(model=model, hardware_version=hardware_version, firmware_version=firmware_version)


def query_system_info(*, port: str, code: str, reset: bool = True, timeout: float = 2.0) -> LegacySystemInfo:
    client = JablotronUSBClient(ensure_serial_port(port))
    model = None
    hardware_version = None
    firmware_version = None
    try:
        perform_login(client, code, reset=reset)
        time.sleep(0.5)
        perform_system_info_query(
            client,
            [SystemInfo.MODEL, SystemInfo.HARDWARE_VERSION, SystemInfo.FIRMWARE_VERSION],
        )
        for packet in client.read_packets(timeout=timeout):
            if packet[:1] != b"\x40":
                continue
            try:
                info_type = SystemInfo(Jablotron.bytes_to_int(packet[2:3]))
            except ValueError:
                continue
            try:
                value = Jablotron.decode_system_info_packet(packet)
            except UnicodeDecodeError:
                continue
            if info_type == SystemInfo.MODEL:
                model = value
            elif info_type == SystemInfo.HARDWARE_VERSION:
                hardware_version = value
            elif info_type == SystemInfo.FIRMWARE_VERSION:
                firmware_version = value
        try:
            perform_logout(client)
        except Exception:
            pass
    finally:
        client.close()
    return LegacySystemInfo(model=model, hardware_version=hardware_version, firmware_version=firmware_version)


def query_panel_snapshot(
    *,
    port: str,
    code: str,
    panel_model: str | None,
    pg_count: int,
    devices: list[DeviceStatusModel] | None = None,
    central: CentralStatusModel | None = None,
    include_diagnostics: bool = False,
    reset: bool = True,
    timeout: float = 2.0,
) -> LegacyPanelSnapshot:
    client = JablotronUSBClient(ensure_serial_port(port))
    devices_by_id = {device.id: device.model_copy(deep=True) for device in (devices or [])}
    special_devices = _panel_special_devices(panel_model)
    parser = _SnapshotParser(
        devices_by_id=devices_by_id,
        special_devices=special_devices,
        central=central.model_copy(deep=True) if central is not None else CentralStatusModel(),
    )
    try:
        perform_login(client, code, reset=reset)
        time.sleep(0.5)
        perform_enable_device_states(client)
        perform_sections_query(client)

        status_device_numbers = sorted(
            {
                device_id
                for device_id in devices_by_id
            }
            | {device_id for device_id in special_devices.values() if isinstance(device_id, int)}
        )
        if status_device_numbers:
            client.send_packets([Jablotron.create_packet_device_info(device_id) for device_id in status_device_numbers])

        for packet in client.read_packets(timeout=timeout):
            parser.parse_packet(packet, pg_count=pg_count)

        if include_diagnostics:
            diagnostic_numbers = sorted(
                {
                    device.id
                    for device in devices_by_id.values()
                    if _device_supports_diagnostics(device)
                }
                | {0}
                | {device_id for key, device_id in special_devices.items() if key in {"lan", "gsm"} and isinstance(device_id, int)}
            )
            for device_id in diagnostic_numbers:
                client.send_packets(
                    [
                        Jablotron._create_packet_device_diagnostics_start(device_id),
                        Jablotron._create_packet_device_diagnostics_force_info(device_id),
                    ]
                )
                for packet in client.read_packets(timeout=0.5):
                    parser.parse_packet(packet, pg_count=pg_count)
                client.send_packet(Jablotron._create_packet_device_diagnostics_end(device_id))
                for packet in client.read_packets(timeout=0.1):
                    parser.parse_packet(packet, pg_count=pg_count)

        if parser.login_failed:
            raise WrongCodeError("Wrong code.")
        try:
            perform_logout(client)
        except Exception:
            pass
    finally:
        client.close()
    return LegacyPanelSnapshot(
        sections=parser.sections,
        pgs=parser.pgs,
        devices=list(parser.devices_by_id.values()),
        central=parser.central,
        service_mode=parser.service_mode,
    )


def query_sections_and_pgs(
    *,
    port: str,
    code: str,
    pg_count: int,
    devices: list[DeviceStatusModel] | None = None,
    reset: bool = True,
    timeout: float = 2.0,
) -> tuple[list[SectionStatusModel], list[PGStatusModel], list[DeviceStatusModel], bool]:
    snapshot = query_panel_snapshot(
        port=port,
        code=code,
        panel_model=None,
        pg_count=pg_count,
        devices=devices,
        central=None,
        include_diagnostics=False,
        reset=reset,
        timeout=timeout,
    )
    return snapshot.sections, snapshot.pgs, snapshot.devices, snapshot.service_mode


def control_section(
    *,
    port: str,
    code: str,
    section_id: int,
    action: str,
    reset: bool = True,
) -> None:
    if action not in {"disarm", "arm_away", "arm_home", "arm_night"}:
        raise ValueError(f"Unsupported section action: {action}")
    int_packets = {
        "disarm": 143,
        "arm_away": 159,
        "arm_home": 175,
        "arm_night": 175,
    }
    client = JablotronUSBClient(ensure_serial_port(port))
    try:
        perform_login(client, code, reset=reset)
        _await_login_success(client)
        time.sleep(0.5)
        modify_packet = Jablotron.int_to_bytes(int_packets[action] + section_id)
        client.send_packet(Jablotron.create_packet_ui_control(b"\x0d", modify_packet))
        time.sleep(0.3)
        try:
            perform_logout(client)
        except Exception:
            pass
    finally:
        client.close()


def control_pg(
    *,
    port: str,
    code: str,
    pg_id: int,
    enabled: bool,
    reset: bool = True,
) -> None:
    client = JablotronUSBClient(ensure_serial_port(port))
    try:
        perform_login(client, code, reset=reset)
        _await_login_success(client)
        time.sleep(0.5)
        payload = Jablotron.int_to_bytes(pg_id - 1) + (b"\x01" if enabled else b"\x00")
        client.send_packet(Jablotron.create_packet_ui_control(b"\x23", payload))
        time.sleep(0.3)
        try:
            perform_logout(client)
        except Exception:
            pass
    finally:
        client.close()
