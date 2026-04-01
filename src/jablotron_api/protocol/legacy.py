"""Adapters around the proven reverse-engineering helpers already in the repo."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

from jablotron_usb_debug import (
    DeviceConnection,
    DeviceFault,
    DeviceInfoType,
    Jablotron,
    JablotronUSBClient,
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


RAW_SESSION_KEEPALIVE = bytes.fromhex("520102")
EXIT_DIAGNOSTICS_OFF_PACKET = bytes.fromhex("94020100")
DEVICE_STATE_RENEWAL_SECONDS = 240.0
DEFAULT_DIAGNOSTICS_TIMEOUT_SECONDS = 0.5
WIRELESS_TEMPERATURE_DIAGNOSTICS_TIMEOUT_SECONDS = 5.0
CONTROL_CONFIRMATION_TIMEOUT_SECONDS = 0.7
FAST_CONTROL_CONFIRMATION_TIMEOUT_SECONDS = 0.25
AUTHORIZATION_REFRESH_SETTLE_SECONDS = 0.12
PG_CONTROL_QUERY_SETTLE_SECONDS = 0.05
CONTROL_AUTHORIZATION_IDLE_SECONDS = 60.0


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
            if subpacket_type == b"\x01":
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
        self._serial_port = ensure_serial_port(port)
        self._code = code
        self._reset = reset
        self._client: JablotronUSBClient | None = None
        self._io_lock = threading.RLock()
        self._stop_event = threading.Event()
        self._keepalive_thread: threading.Thread | None = None
        self._last_enable_device_states_at = 0.0
        self._authorized_code: str | None = None
        self._last_control_authorized_at = 0.0

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
        timeout: float = 2.0,
    ) -> LegacyPanelSnapshot:
        with self._io_lock:
            try:
                client = self._ensure_client_locked()
                self._maybe_refresh_device_state_stream_locked(client)
                return self._query_snapshot_locked(
                    client,
                    panel_model=panel_model,
                    pg_count=pg_count,
                    devices=devices,
                    central=central,
                    query_device_status=query_device_status,
                    include_diagnostics=include_diagnostics,
                    timeout=timeout,
                )
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
        int_packets = {
            "disarm": 143,
            "arm_away": 159,
            "arm_home": 175,
            "arm_night": 175,
        }
        with self._io_lock:
            previous_code = self._authorized_code
            requested_code = code or self._code
            try:
                client = self._ensure_client_locked(auth_code=requested_code)
                self._ensure_authorized_code_locked(client, requested_code)
                modify_packet = Jablotron.int_to_bytes(int_packets[action] + section_id)
                client.send_packet(Jablotron.create_packet_ui_control(UI_CONTROL_MODIFY_SECTION, modify_packet))
                time.sleep(0.3)
                self._last_control_authorized_at = time.monotonic()
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

    def _ensure_client_locked(self, auth_code: str | None = None) -> JablotronUSBClient:
        if self._client is not None:
            return self._client

        client = JablotronUSBClient(self._serial_port)
        try:
            active_code = auth_code or self._code
            perform_login(client, active_code, reset=self._reset)
            time.sleep(0.5)
            perform_enable_device_states(client)
            self._last_enable_device_states_at = time.monotonic()
            perform_sections_query(client)
            self._drain_packets_locked(client, timeout=0.5)
        except Exception:
            client.close()
            raise

        self._client = client
        self._authorized_code = active_code
        self._last_control_authorized_at = time.monotonic()
        self._ensure_keepalive_thread_locked()
        return client

    def _ensure_keepalive_thread_locked(self) -> None:
        if self._keepalive_thread is not None and self._keepalive_thread.is_alive():
            return
        self._stop_event.clear()
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop,
            name="jablotron-session-keepalive",
            daemon=True,
        )
        self._keepalive_thread.start()

    def _close_client_locked(self) -> None:
        client = self._client
        self._client = None
        self._last_enable_device_states_at = 0.0
        self._authorized_code = None
        self._last_control_authorized_at = 0.0
        if client is None:
            return
        try:
            client.close()
        except Exception:
            pass

    def _ensure_authorized_code_locked(self, client: JablotronUSBClient, code: str) -> None:
        if self._authorized_code == code:
            return
        client.send_packets(
            [
                Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END),
                Jablotron.create_packet_authorisation_code(code),
            ]
        )
        _await_login_success(client)
        time.sleep(0.5)
        self._authorized_code = code
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

    def _keepalive_loop(self) -> None:
        while not self._stop_event.wait(1.0):
            with self._io_lock:
                client = self._client
                if client is None:
                    continue
                try:
                    client.send_packet(RAW_SESSION_KEEPALIVE)
                except Exception:
                    self._close_client_locked()

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
        _await_login_success(client)
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

    def _drain_packets_locked(self, client: JablotronUSBClient, *, timeout: float) -> list[bytes]:
        packets: list[bytes] = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            batch = list(client.read_packets(timeout=min(0.1, remaining)))
            if not batch:
                break
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
                parser.parse_packet(packet, pg_count=pg_count)

    def _query_snapshot_locked(
        self,
        client: JablotronUSBClient,
        *,
        panel_model: str | None,
        pg_count: int,
        devices: list[DeviceStatusModel] | None,
        central: CentralStatusModel | None,
        query_device_status: bool,
        include_diagnostics: bool,
        timeout: float,
    ) -> LegacyPanelSnapshot:
        devices_by_id = {device.id: device.model_copy(deep=True) for device in (devices or [])}
        special_devices = _panel_special_devices(panel_model)
        parser = _SnapshotParser(
            devices_by_id=devices_by_id,
            special_devices=special_devices,
            central=central.model_copy(deep=True) if central is not None else CentralStatusModel(),
        )

        self._drain_packets_locked(client, timeout=0.05)
        perform_sections_query(client)

        if query_device_status:
            status_device_numbers = sorted(
                {device_id for device_id in devices_by_id}
                | {device_id for device_id in special_devices.values() if isinstance(device_id, int)}
            )
            if status_device_numbers:
                client.send_packets([Jablotron.create_packet_device_info(device_id) for device_id in status_device_numbers])

        self._read_into_parser_locked(client, parser, pg_count=pg_count, timeout=timeout)

        if include_diagnostics:
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
            for device_id in diagnostic_numbers:
                device = devices_by_id.get(device_id)
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
                )
                client.send_packet(Jablotron._create_packet_device_diagnostics_end(device_id))
                self._read_into_parser_locked(client, parser, pg_count=pg_count, timeout=0.1)

        if parser.login_failed:
            self._close_client_locked()
            raise WrongCodeError("Wrong code.")

        return LegacyPanelSnapshot(
            sections=parser.sections,
            pgs=parser.pgs,
            devices=list(parser.devices_by_id.values()),
            central=parser.central,
            service_mode=parser.service_mode,
        )

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
