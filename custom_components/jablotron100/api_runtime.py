from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from homeassistant import core
from homeassistant.components.alarm_control_panel import AlarmControlPanelState
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_BATTERY_LEVEL, EVENT_HOMEASSISTANT_STOP, STATE_OFF, STATE_ON
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.dispatcher import async_dispatcher_send, dispatcher_send
from homeassistant.helpers.entity import DeviceInfo, Entity
from homeassistant.helpers.typing import StateType

from .api_client import JablotronApiClient, JablotronApiError
from .const import (
    CONF_API_TOKEN,
    CONF_CONTROL_CODE,
    CONF_PARTIALLY_ARMING_MODE,
    CONF_REQUIRE_CODE_TO_ARM,
    CONF_REQUIRE_CODE_TO_DISARM,
    CONF_SERVER_URL,
    CONF_TLS_CA_CERT,
    CONF_TLS_CLIENT_CERT,
    CONF_TLS_CLIENT_KEY,
    DEFAULT_CONF_REQUIRE_CODE_TO_ARM,
    DEFAULT_CONF_REQUIRE_CODE_TO_DISARM,
    DOMAIN,
    EVENT_WRONG_CODE,
    EntityType,
    EventLoginType,
    LOGGER,
    PartiallyArmingMode,
)


LEGACY_LAN_GSM_MODELS = {"JA-101K", "JA-101K-LAN", "JA-106K-3G", "JA-14K", "JA-103K", "JA-103KRY", "JA-107K"}
TEMPERATURE_DEVICE_TYPES = {"thermometer", "thermostat", "smoke_detector"}
SIREN_DEVICE_TYPES = {"outdoor_siren", "indoor_siren"}


@dataclass
class JablotronCentralUnit:
    unique_id: str
    model: str
    hardware_version: str
    firmware_version: str


@dataclass
class JablotronHassDevice:
    id: str
    name: str
    translation_key: str | None = None
    translation_placeholders: dict[str, str] = field(default_factory=dict)
    battery_level: int | None = None


@dataclass
class JablotronControl:
    central_unit: JablotronCentralUnit
    hass_device: JablotronHassDevice | None
    id: str
    name: str | None = None


@dataclass
class JablotronAlarmControlPanel(JablotronControl):
    section: int = 0


@dataclass
class JablotronProgrammableOutput(JablotronControl):
    pg_output_number: int = 0


class Jablotron:
    def __init__(self, hass: core.HomeAssistant, config_entry_id: str, config: dict, options: dict) -> None:
        self._hass = hass
        self._config_entry_id = config_entry_id
        self._config = config
        self._options = options
        self._api = JablotronApiClient(
            hass,
            server_url=config[CONF_SERVER_URL],
            api_token=config[CONF_API_TOKEN],
            ca_cert=config.get(CONF_TLS_CA_CERT),
            client_cert=config.get(CONF_TLS_CLIENT_CERT),
            client_key=config.get(CONF_TLS_CLIENT_KEY),
        )
        self._central_unit: JablotronCentralUnit | None = None
        self._catalog: dict[str, Any] = {}
        self._last_authorized_user_or_device: str | None = None
        self._code_prefix_enabled = False
        self.entities: dict[EntityType, dict[str, JablotronControl]] = {entity_type: {} for entity_type in EntityType.__members__.values()}
        self.entities_states: dict[str, StateType | AlarmControlPanelState] = {}
        self.hass_entities: dict[str, JablotronEntity] = {}
        self.last_update_success = False
        self.in_service_mode = False
        self._ws_task: asyncio.Task | None = None

    def signal_entities_added(self) -> str:
        return f"{DOMAIN}_{self._config_entry_id}_entities_added"

    def central_unit(self) -> JablotronCentralUnit:
        assert self._central_unit is not None
        return self._central_unit

    def is_code_required_for_disarm(self) -> bool:
        return self._options.get(CONF_REQUIRE_CODE_TO_DISARM, DEFAULT_CONF_REQUIRE_CODE_TO_DISARM)

    def is_code_required_for_arm(self) -> bool:
        return self._options.get(CONF_REQUIRE_CODE_TO_ARM, DEFAULT_CONF_REQUIRE_CODE_TO_ARM)

    def partially_arming_mode(self) -> PartiallyArmingMode:
        return PartiallyArmingMode(self._options.get(CONF_PARTIALLY_ARMING_MODE, PartiallyArmingMode.NIGHT_MODE.value))

    def code_contains_asterisk(self) -> bool:
        return self._code_prefix_enabled

    def last_authorized_user_or_device(self) -> str | None:
        return self._last_authorized_user_or_device

    def default_control_code(self) -> str | None:
        code = self._options.get(CONF_CONTROL_CODE)
        if not isinstance(code, str):
            return None
        cleaned = code.strip()
        return cleaned or None

    async def initialize(self) -> None:
        self._hass.bus.async_listen(EVENT_HOMEASSISTANT_STOP, lambda _: self.shutdown())
        system = await self._api.get("/v1/system")
        status = await self._api.get("/v1/status")
        catalog = await self._api.get("/v1/export/catalog")
        unique_id = system.get("panel_unique_id") or self._config[CONF_SERVER_URL]
        self._central_unit = JablotronCentralUnit(
            unique_id=unique_id,
            model=system.get("panel_model") or "Jablotron",
            hardware_version=system.get("panel_hardware_version") or "",
            firmware_version=system.get("panel_firmware_version") or "",
        )
        self._apply_catalog_and_status(catalog, status)
        self.last_update_success = True

    def start_background_tasks(self, config_entry: ConfigEntry) -> None:
        if self._ws_task is not None:
            return
        self._ws_task = config_entry.async_create_background_task(
            self._hass,
            self._ws_loop(),
            "jablotron100_api_hass_ws",
        )

    def shutdown(self) -> None:
        if self._ws_task is not None:
            self._ws_task.cancel()

    def shutdown_and_clean(self) -> None:
        self.shutdown()

    def subscribe_hass_entity_for_updates(self, control_id: str, hass_entity: "JablotronEntity") -> None:
        self.hass_entities[control_id] = hass_entity

    def reset_problem_sensor(self, control: JablotronControl) -> None:
        self._update_entity_state(control.id, STATE_OFF)

    async def _ws_loop(self) -> None:
        while True:
            try:
                ws = await self._api.ws_connect()
                await ws.receive_json()
                await ws.send_json({"action": "subscribe", "topics": ["status", "catalog", "users"]})
                async for msg in ws:
                    if msg.type.name != "TEXT":
                        continue
                    payload = msg.json(loads=__import__("json").loads)
                    topic = payload.get("topic")
                    if topic == "status":
                        added = self._apply_status(payload.get("payload", {}))
                        if added:
                            self._send_signal_entities_added()
                    elif topic in {"catalog", "system"}:
                        data = payload.get("payload", {})
                        if "sections" in data or "users" in data or "devices" in data:
                            added = self._apply_catalog(data)
                            if added:
                                self._send_signal_entities_added()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.last_update_success = False
                LOGGER.warning("API websocket disconnected: %s", exc)
                await asyncio.sleep(5)

    def _apply_catalog_and_status(self, catalog: dict, status: dict) -> None:
        added = self._apply_catalog(catalog)
        added = self._apply_status(status) or added
        self._remove_unsupported_central_entities(status)
        if added:
            self._send_signal_entities_added()

    @staticmethod
    def _usable_last_id(catalog: dict, key: str) -> int | None:
        initial_setup = catalog.get("initial_setup") or {}
        selected_range = initial_setup.get(key) or {}
        last_id = selected_range.get("last_id")
        return int(last_id) if isinstance(last_id, int) else None

    @staticmethod
    def _usable_first_id(catalog: dict, key: str) -> int | None:
        initial_setup = catalog.get("initial_setup") or {}
        selected_range = initial_setup.get(key) or {}
        first_id = selected_range.get("first_id")
        return int(first_id) if isinstance(first_id, int) else None

    @staticmethod
    def _legacy_section_id(section_no: int) -> str:
        return f"section_{section_no}"

    @staticmethod
    def _legacy_section_problem_id(section_no: int) -> str:
        return f"section_problem_sensor_{section_no}"

    @staticmethod
    def _legacy_section_fire_id(section_no: int) -> str:
        return f"section_fire_sensor_{section_no}"

    @staticmethod
    def _legacy_device_id(device_no: int) -> str:
        return f"device_{device_no}"

    @staticmethod
    def _legacy_device_state_id(device_no: int) -> str:
        return f"device_sensor_{device_no}"

    @staticmethod
    def _legacy_device_problem_id(device_no: int) -> str:
        return f"device_problem_sensor_{device_no}"

    @staticmethod
    def _legacy_device_signal_strength_id(device_no: int) -> str:
        return f"device_signal_strength_sensor_{device_no}"

    @staticmethod
    def _legacy_device_battery_problem_id(device_no: int) -> str:
        return f"device_battery_problem_sensor_{device_no}"

    @staticmethod
    def _legacy_device_battery_level_id(device_no: int) -> str:
        return f"device_battery_level_sensor_{device_no}"

    @staticmethod
    def _legacy_device_temperature_id(device_no: int) -> str:
        return f"device_temperature_sensor_{device_no}"

    @staticmethod
    def _legacy_device_battery_standby_voltage_id(device_no: int) -> str:
        return f"battery_standby_voltage_{device_no}"

    @staticmethod
    def _legacy_device_battery_load_voltage_id(device_no: int) -> str:
        return f"battery_load_voltage_{device_no}"

    @staticmethod
    def _legacy_pulse_id(device_no: int, pulse_no: int = 0) -> str:
        return f"pulses_{device_no}" if pulse_no == 0 else f"pulses_{device_no}_{pulse_no}"

    @staticmethod
    def _legacy_pg_id(pg_no: int) -> str:
        return f"pg_output_{pg_no}"

    @staticmethod
    def _legacy_power_supply_id() -> str:
        return "device_power_supply_sensor_0"

    @staticmethod
    def _legacy_bus_voltage_id(bus_no: int) -> str:
        return "bus_voltage_0" if bus_no == 1 else f"bus_voltage_0_bus_{bus_no}"

    @staticmethod
    def _legacy_bus_devices_loss_id(bus_no: int) -> str:
        return "bus_devices_loss_0" if bus_no == 1 else f"bus_devices_loss_0_bus_{bus_no}"

    def _panel_has_lan_gsm(self) -> bool:
        return self._central_unit is not None and self._central_unit.model in LEGACY_LAN_GSM_MODELS

    def _ensure_control(
        self,
        entity_type: EntityType,
        control_id: str,
        *,
        hass_device: JablotronHassDevice | None = None,
        name: str | None = None,
    ) -> bool:
        bucket = self.entities[entity_type]
        if control_id in bucket:
            bucket[control_id].hass_device = hass_device
            bucket[control_id].name = name
            return False
        bucket[control_id] = JablotronControl(self.central_unit(), hass_device, control_id, name)
        return True

    def _ensure_alarm_panel(self, section_no: int, hass_device: JablotronHassDevice) -> bool:
        control_id = self._legacy_section_id(section_no)
        bucket = self.entities[EntityType.ALARM_CONTROL_PANEL]
        if control_id in bucket:
            control = bucket[control_id]
            control.hass_device = hass_device
            control.name = None
            return False
        bucket[control_id] = JablotronAlarmControlPanel(
            central_unit=self.central_unit(),
            hass_device=hass_device,
            id=control_id,
            name=None,
            section=section_no,
        )
        return True

    def _ensure_pg_output(self, pg_no: int, hass_device: JablotronHassDevice) -> bool:
        control_id = self._legacy_pg_id(pg_no)
        bucket = self.entities[EntityType.PROGRAMMABLE_OUTPUT]
        if control_id in bucket:
            control = bucket[control_id]
            control.hass_device = hass_device
            control.name = None
            return False
        bucket[control_id] = JablotronProgrammableOutput(
            central_unit=self.central_unit(),
            hass_device=hass_device,
            id=control_id,
            name=None,
            pg_output_number=pg_no,
        )
        return True

    def _ensure_login_event(self) -> bool:
        added = self._ensure_control(EntityType.EVENT_LOGIN, "login", hass_device=None)
        if "login" not in self.entities_states:
            self.entities_states["login"] = STATE_ON
        return added

    def _ensure_default_state(self, entity_id: str, state: StateType | AlarmControlPanelState) -> None:
        if entity_id not in self.entities_states:
            self.entities_states[entity_id] = state

    def _remove_control_by_id(self, control_id: str, *, entity_type: EntityType | None = None) -> None:
        if entity_type is None:
            for bucket in self.entities.values():
                bucket.pop(control_id, None)
        else:
            self.entities[entity_type].pop(control_id, None)
        self.entities_states.pop(control_id, None)
        self.hass_entities.pop(control_id, None)

        if self._central_unit is None or not hasattr(self._hass, "data"):
            return

        target_unique_id = f"{DOMAIN}.{self._central_unit.unique_id}.{control_id}"
        registry = er.async_get(self._hass)
        for entity_id, entry in list(registry.entities.items()):
            if entry.unique_id == target_unique_id:
                registry.async_remove(entity_id)

    def _remove_unsupported_central_entities(self, status: dict) -> None:
        central = status.get("central") or {}
        if central.get("power_supply") is None:
            self._remove_control_by_id(self._legacy_power_supply_id(), entity_type=EntityType.POWER_SUPPLY)
        if central.get("gsm_signal") is None:
            self._remove_control_by_id("gsm_signal_sensor", entity_type=EntityType.GSM_SIGNAL)
        if central.get("gsm_signal_strength") is None:
            self._remove_control_by_id("gsm_signal_strength_sensor", entity_type=EntityType.GSM_SIGNAL_STRENGTH)

    def _section_has_smoke_detector(self, section_no: int) -> bool:
        for device in self._catalog.get("devices", []):
            if int(device.get("section_id") or 0) + 1 == section_no and device.get("inferred_device_type") == "smoke_detector":
                return True
        return False

    def _apply_catalog(self, catalog: dict) -> bool:
        self._catalog = catalog
        self._code_prefix_enabled = bool((catalog.get("initial_setup") or {}).get("code_prefix"))
        added_any = self._ensure_login_event()
        if self._panel_has_lan_gsm():
            added_any = self._ensure_control(EntityType.LAN_CONNECTION, "lan", hass_device=None) or added_any

        usable_section_first_id = self._usable_first_id(catalog, "sections")
        usable_section_last_id = self._usable_last_id(catalog, "sections")
        usable_pg_last_id = self._usable_last_id(catalog, "pgs")
        usable_device_last_id = self._usable_last_id(catalog, "devices")

        for section in catalog.get("sections", []):
            section_no = int(section.get("display_id", section["id"])) + 1
            if usable_section_first_id is not None and section_no < usable_section_first_id:
                continue
            if usable_section_last_id is not None and section_no > usable_section_last_id:
                continue
            section_hass_device = JablotronHassDevice(id=f"section_{section_no}", name=section.get("name") or f"Section {section_no}")
            added_any = self._ensure_alarm_panel(section_no, section_hass_device) or added_any
            added_any = self._ensure_control(EntityType.PROBLEM, self._legacy_section_problem_id(section_no), hass_device=section_hass_device) or added_any
            self._ensure_default_state(self._legacy_section_problem_id(section_no), STATE_OFF)
            if self._section_has_smoke_detector(section_no):
                added_any = self._ensure_control(EntityType.FIRE, self._legacy_section_fire_id(section_no), hass_device=section_hass_device) or added_any
                self._ensure_default_state(self._legacy_section_fire_id(section_no), STATE_OFF)

        for pg in catalog.get("pgs", []):
            pg_no = int(pg["display_id"])
            if usable_pg_last_id is not None and pg_no > usable_pg_last_id:
                continue
            pg_name = pg.get("name") or f"PG output {pg_no}"
            pg_hass_device = JablotronHassDevice(id=f"pg_{pg_no}", name=f"PG{pg_no}: {pg_name}")
            added_any = self._ensure_pg_output(pg_no, pg_hass_device) or added_any

        for device in catalog.get("devices", []):
            device_no = int(device["id"])
            if usable_device_last_id is not None and device_no > usable_device_last_id:
                continue
            hass_device = JablotronHassDevice(
                id=self._legacy_device_id(device_no),
                name=device.get("name") or f"Device {device_no}",
            )
            added_any = self._ensure_control(EntityType.PROBLEM, self._legacy_device_problem_id(device_no), hass_device=hass_device) or added_any
            self._ensure_default_state(self._legacy_device_problem_id(device_no), STATE_OFF)

            entity_type_name = device.get("inferred_entity_type")
            if entity_type_name:
                try:
                    entity_type = EntityType(entity_type_name)
                except ValueError:
                    entity_type = None
                if entity_type is not None:
                    added_any = self._ensure_control(entity_type, self._legacy_device_state_id(device_no), hass_device=hass_device) or added_any
            else:
                self._remove_control_by_id(self._legacy_device_state_id(device_no))

            inferred_device_type = device.get("inferred_device_type")
            if inferred_device_type in TEMPERATURE_DEVICE_TYPES:
                added_any = self._ensure_control(EntityType.TEMPERATURE, self._legacy_device_temperature_id(device_no), hass_device=hass_device) or added_any
            if inferred_device_type == "electricity_meter_with_pulse_output":
                added_any = self._ensure_control(EntityType.PULSES, self._legacy_pulse_id(device_no), hass_device=hass_device) or added_any
            if inferred_device_type in SIREN_DEVICE_TYPES:
                added_any = self._ensure_control(EntityType.BATTERY_STANDBY_VOLTAGE, self._legacy_device_battery_standby_voltage_id(device_no), hass_device=hass_device) or added_any
                added_any = self._ensure_control(EntityType.BATTERY_LOAD_VOLTAGE, self._legacy_device_battery_load_voltage_id(device_no), hass_device=hass_device) or added_any

        return added_any

    def _find_catalog_device(self, device_no: int) -> dict[str, Any]:
        for device in self._catalog.get("devices", []):
            if int(device["id"]) == device_no:
                return device
        return {}

    def _ensure_device_dynamic_entities(self, device: dict) -> bool:
        device_no = int(device["id"])
        catalog_device = self._find_catalog_device(device_no)
        hass_device = JablotronHassDevice(
            id=self._legacy_device_id(device_no),
            name=catalog_device.get("name") or device.get("name") or f"Device {device_no}",
            battery_level=device.get("battery_level"),
        )
        added_any = False
        if device.get("signal_strength") is not None or device.get("wireless"):
            added_any = self._ensure_control(EntityType.SIGNAL_STRENGTH, self._legacy_device_signal_strength_id(device_no), hass_device=hass_device) or added_any
        else:
            self._remove_control_by_id(self._legacy_device_signal_strength_id(device_no), entity_type=EntityType.SIGNAL_STRENGTH)
        if device.get("battery_level") is not None or device.get("battery_problem") is not None:
            added_any = self._ensure_control(EntityType.BATTERY_LEVEL, self._legacy_device_battery_level_id(device_no), hass_device=hass_device) or added_any
            added_any = self._ensure_control(EntityType.BATTERY_PROBLEM, self._legacy_device_battery_problem_id(device_no), hass_device=hass_device) or added_any
        else:
            self._remove_control_by_id(self._legacy_device_battery_level_id(device_no), entity_type=EntityType.BATTERY_LEVEL)
            self._remove_control_by_id(self._legacy_device_battery_problem_id(device_no), entity_type=EntityType.BATTERY_PROBLEM)
        inferred_device_type = catalog_device.get("inferred_device_type")
        if inferred_device_type in SIREN_DEVICE_TYPES:
            added_any = self._ensure_control(EntityType.BATTERY_STANDBY_VOLTAGE, self._legacy_device_battery_standby_voltage_id(device_no), hass_device=hass_device) or added_any
            added_any = self._ensure_control(EntityType.BATTERY_LOAD_VOLTAGE, self._legacy_device_battery_load_voltage_id(device_no), hass_device=hass_device) or added_any
        else:
            self._remove_control_by_id(self._legacy_device_battery_standby_voltage_id(device_no), entity_type=EntityType.BATTERY_STANDBY_VOLTAGE)
            self._remove_control_by_id(self._legacy_device_battery_load_voltage_id(device_no), entity_type=EntityType.BATTERY_LOAD_VOLTAGE)
        if device.get("temperature") is not None and inferred_device_type in TEMPERATURE_DEVICE_TYPES:
            added_any = self._ensure_control(EntityType.TEMPERATURE, self._legacy_device_temperature_id(device_no), hass_device=hass_device) or added_any
        else:
            self._remove_control_by_id(self._legacy_device_temperature_id(device_no), entity_type=EntityType.TEMPERATURE)
        for pulse_no, _pulse in enumerate(device.get("pulses") or []):
            added_any = self._ensure_control(EntityType.PULSES, self._legacy_pulse_id(device_no, pulse_no), hass_device=hass_device) or added_any
        return added_any

    def _ensure_central_dynamic_entities(self, status: dict) -> bool:
        added_any = False
        central = status.get("central") or {}
        if central.get("power_supply") is not None:
            added_any = self._ensure_control(EntityType.POWER_SUPPLY, self._legacy_power_supply_id(), hass_device=None) or added_any
        if central.get("battery_level") is not None or central.get("battery_problem") is not None:
            added_any = self._ensure_control(EntityType.BATTERY_LEVEL, self._legacy_device_battery_level_id(0), hass_device=None) or added_any
            added_any = self._ensure_control(EntityType.BATTERY_PROBLEM, self._legacy_device_battery_problem_id(0), hass_device=None) or added_any
            added_any = self._ensure_control(EntityType.BATTERY_STANDBY_VOLTAGE, self._legacy_device_battery_standby_voltage_id(0), hass_device=None) or added_any
            added_any = self._ensure_control(EntityType.BATTERY_LOAD_VOLTAGE, self._legacy_device_battery_load_voltage_id(0), hass_device=None) or added_any
        if central.get("lan_ip"):
            added_any = self._ensure_control(EntityType.LAN_IP, "lan_ip", hass_device=None) or added_any
        if central.get("gsm_signal") is not None:
            added_any = self._ensure_control(EntityType.GSM_SIGNAL, "gsm_signal_sensor", hass_device=None) or added_any
        if central.get("gsm_signal_strength") is not None:
            added_any = self._ensure_control(EntityType.GSM_SIGNAL_STRENGTH, "gsm_signal_strength_sensor", hass_device=None) or added_any
        for bus in central.get("buses") or []:
            bus_no = int(bus["bus_number"])
            added_any = self._ensure_control(EntityType.BUS_VOLTAGE, self._legacy_bus_voltage_id(bus_no), hass_device=None, name=f"BUS {bus_no} voltage") or added_any
            added_any = self._ensure_control(EntityType.BUS_DEVICES_CURRENT, self._legacy_bus_devices_loss_id(bus_no), hass_device=None, name=f"BUS {bus_no} devices loss") or added_any
        return added_any

    def _apply_status(self, status: dict) -> bool:
        self.in_service_mode = bool(status.get("service_mode", False))
        self.last_update_success = True
        added_any = self._ensure_central_dynamic_entities(status)

        central = status.get("central") or {}
        self._last_authorized_user_or_device = central.get("last_authorized_user_or_device") or self._last_authorized_user_or_device
        self._update_entity_state(self._legacy_power_supply_id(), STATE_ON if central.get("power_supply") else STATE_OFF if central.get("power_supply") is not None else None)
        self._update_entity_state(self._legacy_device_battery_level_id(0), central.get("battery_level"))
        self._update_entity_state(self._legacy_device_battery_problem_id(0), STATE_ON if central.get("battery_problem") else STATE_OFF if central.get("battery_problem") is not None else None)
        self._update_entity_state(self._legacy_device_battery_standby_voltage_id(0), central.get("battery_standby_voltage"))
        self._update_entity_state(self._legacy_device_battery_load_voltage_id(0), central.get("battery_load_voltage"))
        self._update_entity_state("lan", STATE_ON if central.get("lan_connection") else STATE_OFF if central.get("lan_connection") is not None else None)
        self._update_entity_state("lan_ip", central.get("lan_ip"))
        self._update_entity_state("gsm_signal_sensor", STATE_ON if central.get("gsm_signal") else STATE_OFF if central.get("gsm_signal") is not None else None)
        self._update_entity_state("gsm_signal_strength_sensor", central.get("gsm_signal_strength"))
        for bus in central.get("buses") or []:
            bus_no = int(bus["bus_number"])
            self._update_entity_state(self._legacy_bus_voltage_id(bus_no), bus.get("voltage"))
            self._update_entity_state(self._legacy_bus_devices_loss_id(bus_no), bus.get("devices_loss_count"))

        for section in status.get("sections", []):
            section_no = int(section["id"])
            mapped = {
                "disarmed": AlarmControlPanelState.DISARMED,
                "armed_away": AlarmControlPanelState.ARMED_AWAY,
                "armed_home": AlarmControlPanelState.ARMED_HOME,
                "armed_night": AlarmControlPanelState.ARMED_NIGHT,
                "pending": AlarmControlPanelState.PENDING,
                "arming": AlarmControlPanelState.ARMING,
                "triggered": AlarmControlPanelState.TRIGGERED,
            }.get(section.get("state"))
            self._update_entity_state(self._legacy_section_id(section_no), mapped)
            self._update_entity_state(self._legacy_section_problem_id(section_no), STATE_ON if section.get("problem") or section.get("sabotage") else STATE_OFF)
            if section.get("fire") and self._ensure_control(EntityType.FIRE, self._legacy_section_fire_id(section_no), hass_device=self.entities[EntityType.ALARM_CONTROL_PANEL][self._legacy_section_id(section_no)].hass_device):
                added_any = True
            self._update_entity_state(self._legacy_section_fire_id(section_no), STATE_ON if section.get("fire") else STATE_OFF if self._legacy_section_fire_id(section_no) in self.entities_states else None)

        for pg in status.get("pgs", []):
            pg_no = int(pg["id"])
            self._update_entity_state(self._legacy_pg_id(pg_no), STATE_ON if pg.get("state") == "on" else STATE_OFF if pg.get("state") == "off" else None)

        for device in status.get("devices", []):
            added_any = self._ensure_device_dynamic_entities(device) or added_any
            device_no = int(device["id"])
            self._update_entity_state(self._legacy_device_state_id(device_no), STATE_ON if device.get("state") == "on" else STATE_OFF if device.get("state") == "off" else None)
            self._update_entity_state(self._legacy_device_problem_id(device_no), STATE_ON if device.get("problem") else STATE_OFF if device.get("problem") is not None else None)
            self._update_entity_state(self._legacy_device_signal_strength_id(device_no), device.get("signal_strength"))
            self._update_entity_state(self._legacy_device_battery_level_id(device_no), device.get("battery_level"))
            self._update_entity_state(self._legacy_device_battery_problem_id(device_no), STATE_ON if device.get("battery_problem") else STATE_OFF if device.get("battery_problem") is not None else None)
            self._update_entity_state(self._legacy_device_temperature_id(device_no), device.get("temperature"))
            self._update_entity_state(self._legacy_device_battery_standby_voltage_id(device_no), device.get("battery_standby_voltage"))
            self._update_entity_state(self._legacy_device_battery_load_voltage_id(device_no), device.get("battery_load_voltage"))
            for pulse_no, pulse_value in enumerate(device.get("pulses") or []):
                self._update_entity_state(self._legacy_pulse_id(device_no, pulse_no), pulse_value)

        return added_any

    def _send_signal_entities_added(self) -> None:
        try:
            in_event_loop = self._hass.loop == asyncio.get_running_loop()
        except RuntimeError:
            in_event_loop = False
        if in_event_loop:
            async_dispatcher_send(self._hass, self.signal_entities_added())
        else:
            self._hass.add_job(async_dispatcher_send, self._hass, self.signal_entities_added())

    def _update_entity_state(self, entity_id: str, state: StateType | AlarmControlPanelState | None) -> None:
        if state is None and entity_id not in self.entities_states:
            return
        self.entities_states[entity_id] = state
        if entity_id in self.hass_entities:
            self.hass_entities[entity_id].update_state(state)

    def _trigger_wrong_code(self) -> None:
        def _fire() -> None:
            for control in self.entities[EntityType.EVENT_LOGIN].values():
                entity = self.hass_entities.get(control.id)
                if entity is not None and hasattr(entity, "trigger_event"):
                    entity.trigger_event(EventLoginType.WRONG_CODE)
            self._hass.bus.async_fire(EVENT_WRONG_CODE)

        try:
            in_event_loop = self._hass.loop == asyncio.get_running_loop()
        except RuntimeError:
            in_event_loop = False
        if in_event_loop:
            _fire()
        else:
            self._hass.add_job(_fire)

    def modify_alarm_control_panel_section_state(self, section: int, state: AlarmControlPanelState, code: str | None) -> None:
        code = code or self.default_control_code()
        mode_map = {
            AlarmControlPanelState.ARMED_AWAY: "away",
            AlarmControlPanelState.ARMED_HOME: "home",
            AlarmControlPanelState.ARMED_NIGHT: "night",
        }

        async def _run() -> None:
            try:
                if state == AlarmControlPanelState.DISARMED:
                    params = {"code": code} if code else None
                    payload = await self._api.post(f"/v1/sections/{section}/disarm", params=params)
                else:
                    params = {"mode": mode_map[state]}
                    if code:
                        params["code"] = code
                    payload = await self._api.post(f"/v1/sections/{section}/arm", params=params)
            except JablotronApiError as exc:
                if exc.status == 400 and exc.detail == "Wrong code.":
                    self._trigger_wrong_code()
                    return
                LOGGER.warning("Section control failed: %s", exc)
                return
            added = self._apply_status(payload)
            if added:
                self._send_signal_entities_added()

        self._hass.add_job(_run)

    def toggle_pg_output(self, pg_output_number: int, state: str, code: str | None = None) -> None:
        code = code or self.default_control_code()

        async def _run() -> None:
            try:
                params = {"code": code} if code else None
                payload = await self._api.post(
                    f"/v1/pgs/{pg_output_number}/{'on' if state == STATE_ON else 'off'}",
                    params=params,
                )
            except JablotronApiError as exc:
                LOGGER.warning("PG control failed: %s", exc)
                return
            added = self._apply_status(payload)
            if added:
                self._send_signal_entities_added()

        self._hass.add_job(_run)


class JablotronEntity(Entity):
    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(self, jablotron: Jablotron, control: JablotronControl) -> None:
        self._jablotron = jablotron
        self._control = control
        self._attr_unique_id = f"{DOMAIN}.{self._control.central_unit.unique_id}.{self._control.id}"
        if self._control.name is not None:
            self._attr_name = self._control.name
        if self._control.hass_device is None:
            self._attr_device_info = DeviceInfo(
                manufacturer="Jablotron",
                identifiers={(DOMAIN, self._control.central_unit.unique_id)},
            )
        else:
            device_info_kwargs = {
                "manufacturer": "Jablotron",
                "identifiers": {(DOMAIN, self._control.hass_device.id)},
                "name": self._control.hass_device.name,
                "via_device": (DOMAIN, self._control.central_unit.unique_id),
            }
            if self._control.hass_device.translation_key is not None:
                device_info_kwargs["translation_key"] = self._control.hass_device.translation_key
                device_info_kwargs["translation_placeholders"] = self._control.hass_device.translation_placeholders
            self._attr_device_info = DeviceInfo(**device_info_kwargs)
        self._update_attributes()

    def _update_attributes(self) -> None:
        if self._control.hass_device is not None and self._control.hass_device.battery_level is not None:
            self._attr_extra_state_attributes = {ATTR_BATTERY_LEVEL: self._control.hass_device.battery_level}

    @property
    def control(self) -> JablotronControl:
        return self._control

    @property
    def available(self) -> bool:
        return self._jablotron.last_update_success and self._jablotron.entities_states.get(self._control.id) is not None and not self._jablotron.in_service_mode

    async def async_added_to_hass(self) -> None:
        self._jablotron.subscribe_hass_entity_for_updates(self._control.id, self)

    async def remove_from_hass(self) -> None:
        if self.registry_entry:
            er.async_get(self.hass).async_remove(self.entity_id)
        else:
            await self.async_remove(force_remove=True)

    def refresh_state(self) -> None:
        self._update_attributes()
        self.schedule_update_ha_state()

    def update_state(self, state: StateType | AlarmControlPanelState | None) -> None:
        self._jablotron.entities_states[self._control.id] = state
        self.refresh_state()

    def _get_state(self) -> StateType | AlarmControlPanelState | None:
        return self._jablotron.entities_states.get(self._control.id)
