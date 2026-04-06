from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from homeassistant.components.alarm_control_panel import AlarmControlPanelEntityFeature, AlarmControlPanelState, CodeFormat
import custom_components.jablotron100_api_hass.api_client as api_client_module
from custom_components.jablotron100_api_hass.api_runtime import JablotronAlarmControlPanel
from custom_components.jablotron100_api_hass.alarm_control_panel import JablotronAlarmControlPanelEntity
from homeassistant.const import ATTR_BATTERY_LEVEL
from custom_components.jablotron100_api_hass.api_runtime import Jablotron, JablotronCentralUnit, JablotronControl, JablotronEntity, JablotronHassDevice
from custom_components.jablotron100_api_hass.api_client import JablotronApiClient, JablotronApiError
from custom_components.jablotron100_api_hass.const import (
    CONF_API_TOKEN,
    CONF_CONTROL_CODE,
    CONF_DEVICE_TYPE_OVERRIDES,
    CONF_SERVER_URL,
    EVENT_WRONG_CODE,
    EntityType,
    EventLoginType,
)
from custom_components.jablotron100_api_hass.errors import ControlDenied


class _FakeBus:
    def __init__(self) -> None:
        self.events: list[str] = []

    def async_fire(self, event_type: str) -> None:
        self.events.append(event_type)

    def async_listen(self, _event_type: str, _callback) -> None:
        return None


class _FakeHass:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.bus = _FakeBus()

    def async_create_task(self, coro):
        return self.loop.create_task(coro)

    async def async_add_executor_job(self, target, *args):
        return target(*args)

    def add_job(self, target, *args):
        return target(*args)


class _FakeEventEntity:
    def __init__(self) -> None:
        self.events: list[str] = []

    def trigger_event(self, event: EventLoginType) -> None:
        self.events.append(event.value)


class _FakeRefreshEntity:
    def __init__(self) -> None:
        self.refresh_calls = 0

    def refresh_state(self) -> None:
        self.refresh_calls += 1


def _build_runtime() -> Jablotron:
    hass = _FakeHass()
    runtime = Jablotron(
        hass,
        "entry-1",
        {CONF_SERVER_URL: "https://panel.local", CONF_API_TOKEN: "token"},
        {},
    )
    runtime._central_unit = JablotronCentralUnit(
        unique_id="panel-1",
        model="JA-107K",
        hardware_version="MD6112.09.1",
        firmware_version="MD12007",
    )
    return runtime


def test_api_runtime_recreates_legacy_ids_and_dynamic_entities() -> None:
    runtime = _build_runtime()
    catalog = {
        "sections": [{"id": 0, "display_id": 0, "name": "Ground Floor"}],
        "pgs": [{"id": 0, "display_id": 1, "name": "Gate Relay"}],
        "devices": [
            {
                "id": 2,
                "name": "PIR Lobby",
                "section_id": 0,
                "inferred_device_type": "motion_detector",
                "inferred_entity_type": "device_state_motion",
            },
            {
                "id": 3,
                "name": "Thermometer 1",
                "section_id": 0,
                "inferred_device_type": "thermometer",
                "inferred_entity_type": None,
            },
            {
                "id": 4,
                "name": "Meter 1",
                "section_id": 0,
                "inferred_device_type": "electricity_meter_with_pulse_output",
                "inferred_entity_type": None,
            },
            {
                "id": 5,
                "name": "Smoke 1",
                "section_id": 0,
                "inferred_device_type": "smoke_detector",
                "inferred_entity_type": "device_state_smoke",
            },
        ],
        "users": [],
        "initial_setup": {
            "sections": {"last_id": 1},
            "devices": {"last_id": 10},
            "pgs": {"last_id": 1},
            "users": {"last_id": 100},
            "code_prefix": True,
        },
    }
    status = {
        "service_mode": False,
        "sections": [{"id": 1, "state": "disarmed", "problem": False, "sabotage": False, "fire": False}],
        "pgs": [{"id": 1, "state": "on"}],
        "devices": [
            {"id": 2, "state": "off", "problem": True, "signal_strength": 80, "battery_level": 90, "battery_problem": False, "wireless": True},
            {"id": 3, "temperature": 21.5},
            {"id": 4, "pulses": [123, 456]},
            {"id": 5, "state": "off", "temperature": 26.0},
        ],
        "central": {
            "power_supply": True,
            "battery_level": 95,
            "battery_problem": False,
            "battery_standby_voltage": 13.7,
            "battery_load_voltage": 13.2,
            "lan_connection": True,
            "lan_ip": "192.168.1.20",
            "gsm_signal": True,
            "gsm_signal_strength": 87,
            "buses": [{"bus_number": 1, "voltage": 13.8, "devices_loss_count": 0}],
        },
    }

    assert runtime._apply_catalog(catalog) is True
    assert runtime._apply_status(status) is True

    assert "section_1" in runtime.entities[EntityType.ALARM_CONTROL_PANEL]
    assert "section_alarm_control_panel_1" not in runtime.entities[EntityType.ALARM_CONTROL_PANEL]
    assert "device_sensor_2" in runtime.entities[EntityType.DEVICE_STATE_MOTION]
    assert "device_problem_sensor_2" in runtime.entities[EntityType.PROBLEM]
    assert "device_signal_strength_sensor_2" in runtime.entities[EntityType.SIGNAL_STRENGTH]
    assert "device_battery_level_sensor_2" in runtime.entities[EntityType.BATTERY_LEVEL]
    assert "device_temperature_sensor_3" in runtime.entities[EntityType.TEMPERATURE]
    assert "pulses_4" in runtime.entities[EntityType.PULSES]
    assert "pulses_4_1" in runtime.entities[EntityType.PULSES]
    assert "section_fire_sensor_1" in runtime.entities[EntityType.FIRE]
    assert "device_power_supply_sensor_0" in runtime.entities[EntityType.POWER_SUPPLY]
    assert "lan" in runtime.entities[EntityType.LAN_CONNECTION]
    assert "lan_ip" in runtime.entities[EntityType.LAN_IP]
    assert "gsm_signal_sensor" in runtime.entities[EntityType.GSM_SIGNAL]
    assert "gsm_signal_strength_sensor" in runtime.entities[EntityType.GSM_SIGNAL_STRENGTH]
    assert "bus_voltage_0" in runtime.entities[EntityType.BUS_VOLTAGE]
    assert "bus_devices_loss_0" in runtime.entities[EntityType.BUS_DEVICES_CURRENT]
    assert runtime.entities_states["pg_output_1"] == "on"
    assert runtime.entities_states["device_problem_sensor_2"] == "on"
    assert runtime.entities_states["device_temperature_sensor_3"] == 21.5
    assert runtime.entities_states["lan_ip"] == "192.168.1.20"
    assert runtime.code_contains_asterisk() is True


def test_api_runtime_triggers_wrong_code_event() -> None:
    runtime = _build_runtime()
    runtime._apply_catalog({"sections": [], "pgs": [], "devices": [], "users": []})
    event_entity = _FakeEventEntity()
    runtime.hass_entities["login"] = event_entity

    runtime._trigger_wrong_code()

    assert event_entity.events == [EventLoginType.WRONG_CODE.value]
    assert runtime._hass.bus.events == [EVENT_WRONG_CODE]


def test_api_runtime_section_control_raises_control_denied_on_wrong_code() -> None:
    runtime = _build_runtime()
    runtime._apply_catalog({"sections": [], "pgs": [], "devices": [], "users": []})
    event_entity = _FakeEventEntity()
    runtime.hass_entities["login"] = event_entity
    runtime._api = SimpleNamespace(
        post=AsyncMock(side_effect=JablotronApiError(400, "Wrong code."))
    )

    async def _run() -> None:
        try:
            await runtime.async_modify_alarm_control_panel_section_state(1, AlarmControlPanelState.DISARMED, "1812")
        except ControlDenied as exc:
            assert str(exc) == "The entered code was rejected by the panel."
        else:
            raise AssertionError("Expected ControlDenied")

    asyncio.run(_run())

    assert event_entity.events == [EventLoginType.WRONG_CODE.value]
    assert runtime._hass.bus.events == [EVENT_WRONG_CODE]


def test_api_runtime_section_control_raises_control_denied_on_forbidden() -> None:
    runtime = _build_runtime()
    runtime._apply_catalog({"sections": [], "pgs": [], "devices": [], "users": []})
    runtime._api = SimpleNamespace(
        post=AsyncMock(side_effect=JablotronApiError(403, "Token is not allowed to impersonate this panel user."))
    )

    async def _run() -> None:
        try:
            await runtime.async_modify_alarm_control_panel_section_state(1, AlarmControlPanelState.DISARMED, "1812")
        except ControlDenied as exc:
            assert str(exc) == "Token is not allowed to impersonate this panel user."
        else:
            raise AssertionError("Expected ControlDenied")

    asyncio.run(_run())


def test_api_runtime_seeds_legacy_central_fallback_states() -> None:
    runtime = _build_runtime()

    runtime._apply_catalog({"sections": [], "pgs": [], "devices": [], "users": []})
    runtime._apply_status({"service_mode": False, "sections": [], "pgs": [], "devices": [], "central": {}})
    runtime._remove_unsupported_central_entities({"central": {}})

    assert "device_power_supply_sensor_0" not in runtime.entities[EntityType.POWER_SUPPLY]
    assert "gsm_signal_sensor" not in runtime.entities[EntityType.GSM_SIGNAL]
    assert "gsm_signal_strength_sensor" not in runtime.entities[EntityType.GSM_SIGNAL_STRENGTH]
    assert "lan" in runtime.entities[EntityType.LAN_CONNECTION]


def test_api_runtime_removes_stale_device_state_entity_when_mapping_drops_state() -> None:
    runtime = _build_runtime()

    runtime._apply_catalog(
        {
            "sections": [],
            "pgs": [],
            "devices": [
                {
                    "id": 35,
                    "name": "Module channel 1",
                    "inferred_device_type": "door_opening_detector",
                    "inferred_entity_type": "device_state_door",
                }
            ],
            "users": [],
        }
    )
    assert "device_sensor_35" in runtime.entities[EntityType.DEVICE_STATE_DOOR]

    runtime._apply_catalog(
        {
            "sections": [],
            "pgs": [],
            "devices": [
                {
                    "id": 35,
                    "name": "Module channel 1",
                    "inferred_device_type": "io_module",
                    "inferred_entity_type": None,
                }
            ],
            "users": [],
        }
    )

    for bucket in runtime.entities.values():
        assert "device_sensor_35" not in bucket


def test_alarm_control_panel_clean_code_strips_frontend_placeholder_prefixes() -> None:
    assert JablotronAlarmControlPanelEntity._clean_code("") is None
    assert JablotronAlarmControlPanelEntity._clean_code("undefined") is None
    assert JablotronAlarmControlPanelEntity._clean_code("null") is None
    assert JablotronAlarmControlPanelEntity._clean_code("undefined1812") == "1812"
    assert JablotronAlarmControlPanelEntity._clean_code("null4458") == "4458"
    assert JablotronAlarmControlPanelEntity._clean_code("  1812  ") == "1812"


def test_alarm_control_panel_entity_populates_cached_alarm_attrs() -> None:
    runtime = _build_runtime()
    runtime._code_prefix_enabled = False
    runtime.entities_states["section_1"] = AlarmControlPanelState.DISARMED

    entity = JablotronAlarmControlPanelEntity(
        runtime,
        JablotronAlarmControlPanel(
            central_unit=runtime.central_unit(),
            hass_device=None,
            id="section_1",
            name="Section 1",
            section=1,
        ),
    )

    assert entity._attr_alarm_state == AlarmControlPanelState.DISARMED
    assert entity._attr_code_arm_required is False
    assert entity._attr_code_format is None
    assert entity._attr_supported_features == (
        AlarmControlPanelEntityFeature.ARM_AWAY | AlarmControlPanelEntityFeature.ARM_NIGHT
    )
    assert entity._attr_changed_by is None


def test_base_entity_populates_cached_available_and_clears_extra_attrs() -> None:
    class _TestEntity(JablotronEntity):
        pass

    runtime = _build_runtime()
    control = JablotronControl(
        central_unit=runtime.central_unit(),
        hass_device=JablotronHassDevice(id="device-1", name="Device 1", battery_level=42),
        id="device_sensor_1",
        name="Device 1",
    )

    entity = _TestEntity(runtime, control)

    assert entity._attr_available is False
    assert entity._attr_extra_state_attributes == {ATTR_BATTERY_LEVEL: 42}

    runtime.last_update_success = True
    runtime.entities_states["device_sensor_1"] = "on"
    entity._update_attributes()
    assert entity._attr_available is True

    runtime.in_service_mode = True
    entity._update_attributes()
    assert entity._attr_available is False

    runtime.in_service_mode = False
    control.hass_device.battery_level = None
    entity._update_attributes()
    assert entity._attr_extra_state_attributes is None


def test_api_runtime_keeps_dynamic_entities_when_status_data_disappears() -> None:
    runtime = _build_runtime()

    runtime._apply_catalog(
        {
            "sections": [],
            "pgs": [],
            "devices": [
                {
                    "id": 24,
                    "name": "Thermostat 24",
                    "inferred_device_type": "thermostat",
                    "inferred_entity_type": None,
                }
            ],
            "users": [],
        }
    )
    runtime._apply_status(
        {
            "service_mode": False,
            "sections": [],
            "pgs": [],
            "devices": [
                {
                    "id": 24,
                    "battery_level": 60,
                    "battery_problem": False,
                    "temperature": 23.3,
                    "wireless": True,
                    "signal_strength": 55,
                }
            ],
            "central": {},
        }
    )

    assert "device_battery_level_sensor_24" in runtime.entities[EntityType.BATTERY_LEVEL]
    assert "device_battery_problem_sensor_24" in runtime.entities[EntityType.BATTERY_PROBLEM]
    assert "device_temperature_sensor_24" in runtime.entities[EntityType.TEMPERATURE]
    assert "device_signal_strength_sensor_24" in runtime.entities[EntityType.SIGNAL_STRENGTH]

    runtime._apply_status(
        {
            "service_mode": False,
            "sections": [],
            "pgs": [],
            "devices": [
                {
                    "id": 24,
                    "battery_level": None,
                    "battery_problem": None,
                    "temperature": None,
                    "wireless": False,
                    "signal_strength": None,
                }
            ],
            "central": {},
        }
    )

    assert "device_battery_level_sensor_24" in runtime.entities[EntityType.BATTERY_LEVEL]
    assert "device_battery_problem_sensor_24" in runtime.entities[EntityType.BATTERY_PROBLEM]
    assert "device_temperature_sensor_24" in runtime.entities[EntityType.TEMPERATURE]
    assert "device_signal_strength_sensor_24" in runtime.entities[EntityType.SIGNAL_STRENGTH]


def test_api_runtime_catalog_reconciliation_removes_structurally_unsupported_dynamic_entities() -> None:
    runtime = _build_runtime()

    runtime._apply_catalog(
        {
            "sections": [],
            "pgs": [],
            "devices": [
                {
                    "id": 24,
                    "name": "Thermostat 24",
                    "inferred_device_type": "thermostat",
                    "inferred_entity_type": None,
                }
            ],
            "users": [],
        }
    )
    runtime._apply_status(
        {
            "service_mode": False,
            "sections": [],
            "pgs": [],
            "devices": [
                {
                    "id": 24,
                    "battery_level": 60,
                    "battery_problem": False,
                    "temperature": 23.3,
                    "wireless": True,
                    "signal_strength": 55,
                }
            ],
            "central": {},
        }
    )

    assert "device_temperature_sensor_24" in runtime.entities[EntityType.TEMPERATURE]
    assert "device_signal_strength_sensor_24" in runtime.entities[EntityType.SIGNAL_STRENGTH]
    assert "device_battery_level_sensor_24" in runtime.entities[EntityType.BATTERY_LEVEL]

    runtime._apply_catalog(
        {
            "sections": [],
            "pgs": [],
            "devices": [
                {
                    "id": 24,
                    "name": "Module 24",
                    "inferred_device_type": "io_module",
                    "inferred_entity_type": None,
                }
            ],
            "users": [],
        }
    )

    assert "device_temperature_sensor_24" not in runtime.entities[EntityType.TEMPERATURE]
    assert "device_signal_strength_sensor_24" in runtime.entities[EntityType.SIGNAL_STRENGTH]
    assert "device_battery_level_sensor_24" in runtime.entities[EntityType.BATTERY_LEVEL]


def test_api_runtime_device_type_override_restores_legacy_state_entity() -> None:
    runtime = Jablotron(
        _FakeHass(),
        "entry-1",
        {CONF_SERVER_URL: "https://panel.local", CONF_API_TOKEN: "token"},
        {CONF_DEVICE_TYPE_OVERRIDES: {"24": "thermostat"}},
    )
    runtime._central_unit = JablotronCentralUnit(
        unique_id="panel-1",
        model="JA-107K",
        hardware_version="MD6112.09.1",
        firmware_version="MD12007",
    )

    runtime._apply_catalog(
        {
            "sections": [],
            "pgs": [],
            "devices": [
                {
                    "id": 24,
                    "name": "Thermostat 24",
                    "inferred_device_type": "custom",
                    "inferred_entity_type": "device_state_custom",
                }
            ],
            "users": [],
        }
    )
    runtime._apply_status(
        {
            "service_mode": False,
            "sections": [],
            "pgs": [],
            "devices": [{"id": 24, "state": "on", "temperature": 23.3}],
            "central": {},
        }
    )

    assert "device_sensor_24" in runtime.entities[EntityType.DEVICE_STATE_THERMOSTAT]
    assert runtime.entities_states["device_sensor_24"] == "on"
    assert "device_temperature_sensor_24" in runtime.entities[EntityType.TEMPERATURE]


def test_api_runtime_device_type_override_can_ignore_device() -> None:
    runtime = Jablotron(
        _FakeHass(),
        "entry-1",
        {CONF_SERVER_URL: "https://panel.local", CONF_API_TOKEN: "token"},
        {CONF_DEVICE_TYPE_OVERRIDES: {"35": "other"}},
    )
    runtime._central_unit = JablotronCentralUnit(
        unique_id="panel-1",
        model="JA-107K",
        hardware_version="MD6112.09.1",
        firmware_version="MD12007",
    )

    runtime._apply_catalog(
        {
            "sections": [],
            "pgs": [],
            "devices": [
                {
                    "id": 35,
                    "name": "Module channel 1",
                    "inferred_device_type": "door_opening_detector",
                    "inferred_entity_type": "device_state_door",
                }
            ],
            "users": [],
        }
    )

    for bucket in runtime.entities.values():
        assert "device_sensor_35" not in bucket
        assert "device_problem_sensor_35" not in bucket


def test_api_client_ws_connect_uses_heartbeat_and_receive_timeout(monkeypatch) -> None:
    hass = _FakeHass()
    client = JablotronApiClient(hass, server_url="https://panel.local", api_token="token")
    captured: dict[str, object] = {}

    async def _fake_ws_connect(url: str, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return SimpleNamespace()

    fake_session = SimpleNamespace(ws_connect=_fake_ws_connect)
    monkeypatch.setattr(api_client_module, "async_get_clientsession", lambda _hass: fake_session)

    async def _exercise() -> None:
        await client.ws_connect()

    asyncio.run(_exercise())

    assert captured["url"] == "wss://panel.local/v1/ws?token=token"
    assert captured["kwargs"]["heartbeat"] == 10
    assert captured["kwargs"]["receive_timeout"] == 25


def test_api_runtime_marks_unavailable_when_websocket_ends_cleanly() -> None:
    runtime = _build_runtime()
    runtime.last_update_success = True
    refresh_entity = _FakeRefreshEntity()
    runtime.hass_entities["entity-1"] = refresh_entity

    class _FakeMessage:
        type = SimpleNamespace(name="CLOSE")

    class _FakeWebSocket:
        async def receive_json(self):
            return {"event": "hello"}

        async def send_json(self, _payload):
            return None

        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

        async def close(self):
            return None

    runtime._api.ws_connect = AsyncMock(return_value=_FakeWebSocket())

    async def _exercise() -> None:
        task = asyncio.create_task(runtime._ws_loop())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_exercise())

    assert runtime.last_update_success is False
    assert refresh_entity.refresh_calls >= 1


def test_api_runtime_pg_control_requires_default_control_code() -> None:
    runtime = _build_runtime()

    async def _exercise() -> None:
        try:
            await runtime.async_toggle_pg_output(7, "on")
        except ControlDenied as exc:
            assert str(exc) == "PG control requires a Default control code in the integration options."
        else:
            raise AssertionError("Expected ControlDenied when no PG control code is configured.")

    asyncio.run(_exercise())


def test_api_runtime_reads_default_control_code_from_entry_data() -> None:
    runtime = Jablotron(
        _FakeHass(),
        "entry-1",
        {CONF_SERVER_URL: "https://panel.local", CONF_API_TOKEN: "token", CONF_CONTROL_CODE: "2468"},
        {},
    )

    assert runtime.default_control_code() == "2468"


def test_api_runtime_reads_api_token_from_options_override() -> None:
    runtime = Jablotron(
        _FakeHass(),
        "entry-1",
        {CONF_SERVER_URL: "https://panel.local", CONF_API_TOKEN: "entry-token"},
        {CONF_API_TOKEN: "options-token"},
    )

    assert runtime._api._api_token == "options-token"


def test_api_runtime_refreshes_all_entities_on_service_mode_change() -> None:
    runtime = _build_runtime()
    refresh_entity = _FakeRefreshEntity()
    runtime.hass_entities["entity-1"] = refresh_entity

    runtime._set_service_mode(True)
    runtime._set_service_mode(False)

    assert refresh_entity.refresh_calls == 2
