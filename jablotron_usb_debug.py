#!/usr/bin/env python3
"""Small CLI helper to inspect Jablotron USB traffic outside Home Assistant.

The script relies on the existing packet helpers from the custom integration so
we can reuse packet formatting, detection and decoding logic. Typical usage
examples:

    # Detect the hidraw device automatically and log in with code 1234
    python jablotron_usb_debug.py login --code 1234

    # Query central unit model/hardware/firmware info
    python jablotron_usb_debug.py get-system-info

    # Continuously monitor incoming packets (Ctrl+C to stop)
    python jablotron_usb_debug.py monitor --decode
"""

from __future__ import annotations

import argparse
import enum
import logging
import os
import select
import sys
import time
import types
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

# Ensure the repository root (containing custom_components) is on sys.path
REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def ensure_homeassistant_stubs() -> None:
    """Provide lightweight stubs so jablotron.py can be imported standalone."""

    try:  # pragma: no cover - best-effort shim for CLI usage
        import homeassistant  # type: ignore
        return
    except ModuleNotFoundError:
        pass

    homeassistant = types.ModuleType("homeassistant")
    homeassistant.__path__ = []  # type: ignore[attr-defined]
    sys.modules["homeassistant"] = homeassistant

    core = types.ModuleType("homeassistant.core")

    def callback(func):  # type: ignore[override]
        return func

    core.callback = callback  # type: ignore[attr-defined]
    sys.modules["homeassistant.core"] = core
    homeassistant.core = core  # type: ignore[attr-defined]

    const = types.ModuleType("homeassistant.const")
    const.ATTR_BATTERY_LEVEL = "battery_level"
    const.CONF_PASSWORD = "password"
    const.EVENT_HOMEASSISTANT_STOP = "homeassistant_stop"
    const.STATE_OFF = "off"
    const.STATE_ON = "on"

    class Platform(enum.Enum):
        ALARM_CONTROL_PANEL = "alarm_control_panel"
        BINARY_SENSOR = "binary_sensor"
        EVENT = "event"
        SENSOR = "sensor"
        SWITCH = "switch"

    const.Platform = Platform  # type: ignore[attr-defined]
    sys.modules["homeassistant.const"] = const
    homeassistant.const = const  # type: ignore[attr-defined]

    exceptions_module = types.ModuleType("homeassistant.exceptions")

    class HomeAssistantError(Exception):
        pass

    exceptions_module.HomeAssistantError = HomeAssistantError  # type: ignore[attr-defined]
    sys.modules["homeassistant.exceptions"] = exceptions_module
    homeassistant.exceptions = exceptions_module  # type: ignore[attr-defined]

    components = types.ModuleType("homeassistant.components")
    components.__path__ = []  # type: ignore[attr-defined]
    sys.modules["homeassistant.components"] = components
    homeassistant.components = components  # type: ignore[attr-defined]

    config_entries = types.ModuleType("homeassistant.config_entries")

    class ConfigEntry:
        def __init__(self, entry_id: str = "debug", data: Optional[dict] = None, options: Optional[dict] = None):
            self.entry_id = entry_id
            self.data = data or {}
            self.options = options or {}
            self.runtime_data = None

        def add_update_listener(self, _listener):
            return lambda: None

        def async_on_unload(self, _callback):
            return None

    config_entries.ConfigEntry = ConfigEntry  # type: ignore[attr-defined]
    sys.modules["homeassistant.config_entries"] = config_entries
    homeassistant.config_entries = config_entries  # type: ignore[attr-defined]

    alarm_control_panel = types.ModuleType("homeassistant.components.alarm_control_panel")

    class AlarmControlPanelState(enum.Enum):
        DISARMED = "disarmed"
        ARMED_HOME = "armed_home"
        ARMED_AWAY = "armed_away"
        ARMED_NIGHT = "armed_night"
        TRIGGERED = "triggered"
        PENDING = "pending"
        ARMING = "arming"

    alarm_control_panel.AlarmControlPanelState = AlarmControlPanelState  # type: ignore[attr-defined]
    sys.modules["homeassistant.components.alarm_control_panel"] = alarm_control_panel
    components.alarm_control_panel = alarm_control_panel  # type: ignore[attr-defined]

    helpers = types.ModuleType("homeassistant.helpers")
    helpers.__path__ = []  # type: ignore[attr-defined]
    sys.modules["homeassistant.helpers"] = helpers
    homeassistant.helpers = helpers  # type: ignore[attr-defined]

    storage_module = types.ModuleType("homeassistant.helpers.storage")

    class DummyStore:
        def __init__(self, *args, **kwargs):
            pass

        async def async_load(self):
            return None

        async def async_save(self, _data):
            return None

        def async_delay_save(self, *args, **kwargs):
            return None

    storage_module.Store = DummyStore  # type: ignore[attr-defined]
    sys.modules["homeassistant.helpers.storage"] = storage_module
    helpers.storage = storage_module  # type: ignore[attr-defined]

    dispatcher_module = types.ModuleType("homeassistant.helpers.dispatcher")

    def _noop(*args, **kwargs):
        return None

    dispatcher_module.async_dispatcher_send = _noop  # type: ignore[attr-defined]
    dispatcher_module.dispatcher_send = _noop  # type: ignore[attr-defined]
    sys.modules["homeassistant.helpers.dispatcher"] = dispatcher_module
    helpers.dispatcher = dispatcher_module  # type: ignore[attr-defined]

    device_registry = types.ModuleType("homeassistant.helpers.device_registry")
    device_registry.async_get = _noop  # type: ignore[attr-defined]
    device_registry.async_get_or_create = _noop  # type: ignore[attr-defined]
    sys.modules["homeassistant.helpers.device_registry"] = device_registry
    helpers.device_registry = device_registry  # type: ignore[attr-defined]

    entity_module = types.ModuleType("homeassistant.helpers.entity")

    class DeviceInfo(dict):
        pass

    class Entity:
        pass

    entity_module.DeviceInfo = DeviceInfo  # type: ignore[attr-defined]
    entity_module.Entity = Entity  # type: ignore[attr-defined]
    sys.modules["homeassistant.helpers.entity"] = entity_module
    helpers.entity = entity_module  # type: ignore[attr-defined]

    entity_registry_module = types.ModuleType("homeassistant.helpers.entity_registry")
    entity_registry_module.async_get = _noop  # type: ignore[attr-defined]
    entity_registry_module.async_get_or_create = _noop  # type: ignore[attr-defined]
    sys.modules["homeassistant.helpers.entity_registry"] = entity_registry_module
    helpers.entity_registry = entity_registry_module  # type: ignore[attr-defined]

    event_module = types.ModuleType("homeassistant.helpers.event")
    event_module.async_call_later = _noop  # type: ignore[attr-defined]
    sys.modules["homeassistant.helpers.event"] = event_module
    helpers.event = event_module  # type: ignore[attr-defined]

    core.HomeAssistant = type("HomeAssistant", (), {})  # type: ignore[attr-defined]

    typing_module = types.ModuleType("homeassistant.helpers.typing")
    typing_module.StateType = object  # type: ignore[attr-defined]
    sys.modules["homeassistant.helpers.typing"] = typing_module
    helpers.typing = typing_module  # type: ignore[attr-defined]


ensure_homeassistant_stubs()

from custom_components.jablotron100.const import (  # noqa: E402
    COMMAND_GET_DEVICE_STATUS,
    COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES,
    COMMAND_RESPONSE_DEVICE_STATUS,
    EMPTY_PACKET,
    PACKET_COMMAND,
    PACKET_DEVICE_INFO,
    PACKET_DEVICE_STATE,
    PACKET_DEVICES_SECTIONS,
    PACKET_DEVICES_STATES,
    PACKET_DIAGNOSTICS,
    PACKET_DIAGNOSTICS_COMMAND,
    PACKET_GET_DEVICES_SECTIONS,
    PACKET_PG_OUTPUTS_STATES,
    PACKET_SYSTEM_INFO,
    PACKET_UI_CONTROL,
    STREAM_PACKET_SIZE,
    UI_CONTROL_AUTHORISATION_CODE,
    UI_CONTROL_AUTHORISATION_END,
    UI_CONTROL_MODIFY_SECTION,
    UI_CONTROL_TOGGLE_PG_OUTPUT,
)
from custom_components.jablotron100.const import LOGGER as INTEGRATION_LOGGER  # noqa: E402
from custom_components.jablotron100.const import SystemInfo  # noqa: E402
from custom_components.jablotron100.jablotron import Jablotron  # noqa: E402

_LOGGER = logging.getLogger("jablotron_usb_debug")
DEFAULT_LOGIN_SETTLE_TIME = 0.5


def ensure_serial_port(port: str | None) -> str:
    if not port or port == "auto":
        detected = Jablotron.detect_serial_port()
        if detected is None:
            raise SystemExit("Unable to auto-detect Jablotron USB interface. Use --port with /dev/hidrawX.")
        _LOGGER.info("Detected Jablotron USB port at %s", detected)
        return detected
    return port


class JablotronUSBClient:
    """Thin wrapper that mirrors the integration's read/write helpers."""

    def __init__(self, serial_port: str, *, write_delay: float = 0.1) -> None:
        self._serial_port = serial_port
        self._write_delay = write_delay
        self._fd = os.open(self._serial_port, os.O_RDWR | os.O_NONBLOCK)

    def send_packet(self, packet: bytes) -> None:
        self._log_outgoing(packet)
        self._write(packet)

    def send_packets(self, packets: Iterable[bytes]) -> None:
        buffer = b""
        for packet in packets:
            self._log_outgoing(packet)

            if len(buffer) + len(packet) > STREAM_PACKET_SIZE:
                self._write(buffer)
                buffer = b""

            buffer += packet

        if buffer:
            self._write(buffer)

    def _write(self, payload: bytes) -> None:
        os.write(self._fd, payload)
        time.sleep(self._write_delay)

    def _log_outgoing(self, packet: bytes) -> None:
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug("TX %s", Jablotron.format_packet_to_string(packet))

    def read_packets(self, *, timeout: Optional[float] = None) -> Iterator[bytes]:
        start = time.monotonic()

        try:
            while True:
                wait_timeout = None
                if timeout is not None:
                    elapsed = time.monotonic() - start
                    remaining = timeout - elapsed
                    if remaining <= 0:
                        break
                    wait_timeout = remaining

                ready, _, _ = select.select([self._fd], [], [], wait_timeout)
                if not ready:
                    break

                try:
                    raw = os.read(self._fd, STREAM_PACKET_SIZE)
                except BlockingIOError:
                    continue

                if not raw:
                    break

                for packet in Jablotron.get_packets_from_packet(raw):
                    yield packet
        except OSError as exc:
            raise SystemExit(f"USB read failed on {self._serial_port}: {exc}") from exc

    def close(self) -> None:
        os.close(self._fd)


def describe_packet(packet: bytes, *, decode: bool = False) -> str:
    label = "unknown"
    details: List[str] = []

    def add_device_number() -> None:
        device_number = Jablotron._parse_device_number_from_packet(packet)
        if device_number is not None:
            details.append(f"device={device_number}")

    if Jablotron._is_sections_states_packet(packet):
        label = "sections_states"
    elif Jablotron._is_pg_outputs_states_packet(packet):
        label = "pg_outputs_states"
    elif Jablotron._is_devices_states_packet(packet):
        label = "devices_states"
    elif Jablotron._is_devices_sections_packet(packet):
        label = "devices_sections"
    elif Jablotron._is_device_state_packet(packet):
        label = "device_state"
        add_device_number()
    elif Jablotron._is_device_info_packet(packet):
        label = "device_info"
        add_device_number()
    elif Jablotron._is_device_status_packet(packet):
        label = "device_status"
        add_device_number()
    elif Jablotron._is_device_get_status_packet(packet):
        label = "command_get_device_status"
        add_device_number()
    elif Jablotron._is_device_get_diagnostics_packet(packet):
        label = "diagnostics"
        add_device_number()
    elif Jablotron._is_section_modify_packet(packet):
        label = "ui_modify_section"
    elif Jablotron._is_pg_output_toggle_packet(packet):
        label = "ui_toggle_pg_output"
        add_device_number()
    elif Jablotron._is_get_sections_and_pg_outputs_states_packet(packet):
        label = "command_get_sections_pg_outputs"
    elif Jablotron._is_login_error_packet(packet):
        label = "login_error"
    elif packet[:1] == PACKET_SYSTEM_INFO:
        label = "system_info"
        try:
            info_type = SystemInfo(Jablotron.bytes_to_int(packet[2:3]))
            details.append(f"type={info_type.name.lower()}")
            if decode:
                decoded = Jablotron.decode_system_info_packet(packet)
                if decoded:
                    details.append(f"value={decoded}")
        except ValueError:
            details.append("type=unknown")
    elif packet[:1] == PACKET_COMMAND:
        command_type = Jablotron.bytes_to_int(packet[2:3])
        details.append(f"command=0x{command_type:02x}")
    elif packet[:1] == PACKET_UI_CONTROL:
        control_type = Jablotron.bytes_to_int(packet[2:3])
        details.append(f"ui=0x{control_type:02x}")

    hex_repr = Jablotron.format_packet_to_string(packet)
    suffix = f" ({', '.join(details)})" if details else ""
    return f"{label}: {hex_repr}{suffix}"


def perform_login(client: JablotronUSBClient, code: str, *, reset: bool) -> None:
    if len(code) < 4:
        raise SystemExit("Authorisation code must have at least 4 digits.")

    _LOGGER.info("Attempting to perform login")
    packets: List[bytes] = []
    if reset:
        _LOGGER.info("Login: Reset is true. Sending UI_CONTROL_AUTHORISATION_END")
        packets.append(Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END))
    packets.append(Jablotron.create_packet_authorisation_code(code))
    _LOGGER.info("Login: Sending packet_authorisation_code")
    client.send_packets(packets)


def perform_keepalive(client: JablotronUSBClient, code: str) -> None:
    packets = Jablotron.create_packets_keepalive(code)
    _LOGGER.debug("<Sending keepalive>")
    client.send_packets(packets)


def perform_system_info_query(client: JablotronUSBClient, targets: Iterable[SystemInfo]) -> None:
    packets = [Jablotron.create_packet_get_system_info(target) for target in targets]
    target_list = list(targets)
    _LOGGER.debug("perform_system_info_query targets=%s", [target.name for target in target_list])
    client.send_packets(packets)


def perform_sections_query(client: JablotronUSBClient) -> None:
    client.send_packet(Jablotron.create_packet_command(COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES))


def perform_device_status_query(client: JablotronUSBClient, device: int) -> None:
    if device < 0 or device > 255:
        raise SystemExit("Device number must be between 0 and 255.")
    client.send_packet(Jablotron.create_packet_command(COMMAND_GET_DEVICE_STATUS, Jablotron.int_to_bytes(device)))


def perform_enable_device_states(client: JablotronUSBClient) -> None:
    client.send_packet(Jablotron.create_packet_enable_device_states())


def perform_logout(client: JablotronUSBClient) -> None:
    client.send_packet(Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END))


def monitor_packets(client: JablotronUSBClient, *, timeout: Optional[float], count: Optional[int], decode: bool) -> None:
    seen = 0
    try:
        for packet in client.read_packets(timeout=timeout):
            print(describe_packet(packet, decode=decode))
            seen += 1
            if count and seen >= count:
                break
    except KeyboardInterrupt:
        pass


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
    INTEGRATION_LOGGER.setLevel(level)


def read_and_print_responses(client: JablotronUSBClient, *, timeout: float, decode: bool) -> None:
    if timeout <= 0:
        return

    received = False
    for packet in client.read_packets(timeout=timeout):
        received = True
        print(describe_packet(packet, decode=decode))

    if not received:
        _LOGGER.info("No packets received within %.1fs", timeout)


def maybe_login_first(client: JablotronUSBClient, *, code: Optional[str], login_first: bool, reset: bool) -> None:
    if not login_first:
        return
    if not code:
        raise SystemExit("--code is required when using --login-first")

    perform_login(client, code, reset=reset)
    # Give the panel a brief moment to process the auth packet before the next query.
    time.sleep(DEFAULT_LOGIN_SETTLE_TIME)


def _build_common_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--port",
        dest="port",
        default=argparse.SUPPRESS,
        help="Serial port (e.g. /dev/hidraw3). Defaults to auto-detect.",
    )
    common.add_argument(
        "--code",
        dest="code",
        default=argparse.SUPPRESS,
        help="Authorisation code used for login/keepalive operations.",
    )
    common.add_argument(
        "--verbose",
        dest="verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Enable verbose logging including TX packets.",
    )
    common.add_argument(
        "--login-first",
        dest="login_first",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Authenticate in the same process before sending the selected command.",
    )
    common.add_argument(
        "--no-reset",
        dest="no_reset",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Skip the initial authorisation-end reset packet when logging in.",
    )
    common.add_argument(
        "--response-timeout",
        dest="response_timeout",
        type=float,
        default=argparse.SUPPRESS,
        help="Listen for responses for this many seconds after commands that request data (default 2).",
    )
    return common


def build_parser() -> argparse.ArgumentParser:
    common = _build_common_parser()

    parser = argparse.ArgumentParser(
        description="Debug Jablotron USB traffic using integration helpers.",
        parents=[common],
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    login_parser = subparsers.add_parser("login", help="Send login packets (UI authorisation).", parents=[common])

    subparsers.add_parser("logout", help="Send UI authorisation end packet.", parents=[common])

    subparsers.add_parser("keepalive", help="Send keepalive packets (authorisation code + enable device states).", parents=[common])

    system_info_parser = subparsers.add_parser("get-system-info", help="Request system info packets.", parents=[common])
    system_info_parser.add_argument(
        "--info",
        choices=[info.name.lower() for info in SystemInfo],
        help="Request a single system info type instead of the default trio (model, hardware, firmware).",
    )

    subparsers.add_parser("get-sections", help="Request sections and PG outputs states.", parents=[common])

    device_status_parser = subparsers.add_parser(
        "get-device-status", help="Request detailed device status for a given device number.", parents=[common]
    )
    device_status_parser.add_argument("device", type=int, help="Device number as reported by Jablotron (0-255).")

    subparsers.add_parser("enable-device-states", help="Enable streaming device state packets.", parents=[common])

    monitor_parser = subparsers.add_parser("monitor", help="Read and print packets from the USB interface.", parents=[common])
    monitor_parser.add_argument("--timeout", type=float, help="Maximum time (seconds) to wait for packets before exiting.")
    monitor_parser.add_argument("--count", type=int, help="Stop after receiving this many packets.")
    monitor_parser.add_argument("--decode", action="store_true", help="Attempt to decode known packet types.")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    port = getattr(args, "port", "auto")
    code = getattr(args, "code", None)
    verbose = getattr(args, "verbose", False)
    response_timeout = float(getattr(args, "response_timeout", 2.0))
    login_first = getattr(args, "login_first", False)
    no_reset = getattr(args, "no_reset", False)

    configure_logging(verbose)

    serial_port = ensure_serial_port(port)
    client = JablotronUSBClient(serial_port)
    try:
        if args.command == "login":
            if not code:
                raise SystemExit("--code is required for login")
            perform_login(client, code, reset=not no_reset)
        elif args.command == "logout":
            perform_logout(client)
        elif args.command == "keepalive":
            if not code:
                raise SystemExit("--code is required for keepalive")
            perform_keepalive(client, code)
        elif args.command == "get-system-info":
            maybe_login_first(client, code=code, login_first=login_first, reset=not no_reset)
            if args.info:
                target = SystemInfo[args.info.upper()]
                perform_system_info_query(client, [target])
            else:
                perform_system_info_query(client, [SystemInfo.MODEL, SystemInfo.HARDWARE_VERSION, SystemInfo.FIRMWARE_VERSION])
            read_and_print_responses(client, timeout=response_timeout, decode=True)
        elif args.command == "get-sections":
            maybe_login_first(client, code=code, login_first=login_first, reset=not no_reset)
            perform_sections_query(client)
            read_and_print_responses(client, timeout=response_timeout, decode=True)
        elif args.command == "get-device-status":
            maybe_login_first(client, code=code, login_first=login_first, reset=not no_reset)
            perform_device_status_query(client, args.device)
            read_and_print_responses(client, timeout=response_timeout, decode=True)
        elif args.command == "enable-device-states":
            maybe_login_first(client, code=code, login_first=login_first, reset=not no_reset)
            perform_enable_device_states(client)
        elif args.command == "monitor":
            maybe_login_first(client, code=code, login_first=login_first, reset=not no_reset)
            monitor_packets(client, timeout=args.timeout, count=args.count, decode=args.decode)
        else:
            parser.error(f"Unhandled command: {args.command}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
