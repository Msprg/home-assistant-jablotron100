from __future__ import annotations

import asyncio

from custom_components.jablotron100.api_runtime import Jablotron, JablotronCentralUnit
from custom_components.jablotron100.const import CONF_API_TOKEN, CONF_SERVER_URL, EVENT_WRONG_CODE, EntityType, EventLoginType


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

    def add_job(self, target, *args):
        return target(*args)


class _FakeEventEntity:
    def __init__(self) -> None:
        self.events: list[str] = []

    def trigger_event(self, event: EventLoginType) -> None:
        self.events.append(event.value)


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
