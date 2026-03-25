from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import custom_components.jablotron100.api_client as api_client_module
from custom_components.jablotron100.api_runtime import Jablotron, JablotronCentralUnit
from custom_components.jablotron100.api_client import JablotronApiClient
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

    async def async_add_executor_job(self, target, *args):
        return target(*args)

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


def test_api_runtime_removes_stale_dynamic_entities_when_status_data_disappears() -> None:
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

    assert "device_battery_level_sensor_24" not in runtime.entities[EntityType.BATTERY_LEVEL]
    assert "device_battery_problem_sensor_24" not in runtime.entities[EntityType.BATTERY_PROBLEM]
    assert "device_temperature_sensor_24" not in runtime.entities[EntityType.TEMPERATURE]
    assert "device_signal_strength_sensor_24" not in runtime.entities[EntityType.SIGNAL_STRENGTH]


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
