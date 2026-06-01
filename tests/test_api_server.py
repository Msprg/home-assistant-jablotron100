from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from itertools import chain, repeat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from jablotron_api.domain.models import (
    CentralStatusModel,
    DEFAULT_ADMIN_SCOPES,
    DeviceStatusModel,
    ExportCatalogModel,
    ExportPGModel,
    ExportSectionModel,
    InitialSetupModel,
    InitialSetupRangeModel,
    PanelStatusModel,
    PGStatusModel,
    RawCatalogCountsModel,
    SectionStatusModel,
    Scope,
    UserCreateModel,
    UserModel,
)
import jablotron_api.panel.runtime as runtime_module
from jablotron_api.panel.runtime import PanelRuntime, PanelRuntimeConfig
from jablotron_api.panel.runtime import _apply_catalog_names, _catalog_to_model, _infer_device_type
from jablotron_api.protocol import legacy
from jablotron_api.protocol.legacy import LegacyPanelSnapshot, PersistentSnapshotSession
from jablotron_api.server.app import create_app
from jablotron_api.server.config import ServerSettings
from jablotron_api.server.ws import ConnectionManager
from jablotron_api.server.tls import TLS_EXTENSION_KEY
from jablotron_api.services.storage import TokenStore


class FakeRuntime:
    def __init__(self) -> None:
        self.system_info = {
            "panel_model": "JA-107K",
            "panel_hardware_version": "MD6112.09.1",
            "panel_firmware_version": "MD12007",
            "panel_unique_id": "panel-1",
        }
        self._listeners = []
        self.last_arm_code = None
        self.last_disarm_code = None
        self.last_pg_code = None
        self.status = PanelStatusModel(
            refreshed_at=datetime.now(timezone.utc),
            sections=[SectionStatusModel(id=1, name="Section 1", state="disarmed")],
            pgs=[PGStatusModel(id=1, name="PG output 1", state="off")],
            devices=[
                {
                    "id": 2,
                    "name": "PIR Recepcia 1NP",
                    "inferred_device_type": "motion_detector",
                    "inferred_entity_type": "device_state_motion",
                    "state": "off",
                }
            ],
            service_mode=False,
        )
        self.catalog = ExportCatalogModel(
            sections=[ExportSectionModel(id=1, display_id=1, name="Section 1")],
            pgs=[ExportPGModel(id=1, display_id=1, name="PG output 1")],
            devices=[
                {
                    "id": 2,
                    "name": "PIR Recepcia 1NP",
                    "hardware_model": "JA-110P",
                    "inferred_device_type": "motion_detector",
                    "inferred_entity_type": "device_state_motion",
                }
            ],
            users=[UserModel(id=80, name="User 80", code="1812", rights="coUserNoSelfedit")],
            initial_setup=InitialSetupModel(
                source="inferred_catalog",
                exact=False,
                sections=InitialSetupRangeModel(first_id=1, last_id=1, count=1),
                devices=InitialSetupRangeModel(first_id=1, last_id=50, count=50),
                users=InitialSetupRangeModel(first_id=1, last_id=100, count=100),
                pgs=InitialSetupRangeModel(first_id=1, last_id=1, count=1),
            ),
            raw_counts=RawCatalogCountsModel(sections=14, devices=55, users=102, pgs=128),
            path="/tmp/export.bin",
            sha256="deadbeef",
        )

    async def start(self) -> None:
        return None

    async def close(self) -> None:
        return None

    def code_format(self):
        from jablotron_api.domain.codes import CodeFormat
        return CodeFormat(code_length=4, code_prefix=False, source="panel")

    def add_listener(self, listener) -> None:
        self._listeners.append(listener)

    async def refresh_system(self):
        return self.system_info

    async def get_status(self):
        return self.status

    async def get_catalog(self):
        return self.catalog

    async def get_users(self):
        return self.catalog.users

    async def get_export_users(self):
        return self.catalog.users

    async def get_user(self, user_id: int):
        for user in self.catalog.users:
            if user.id == user_id:
                return user
        return None

    async def get_events_recent(self, **kwargs):
        return [{"text": "armed", "kind": "EVENT"}]

    async def get_export_time_limits(self):
        return [{"group_id": 0, "group_display_id": 1, "comment": "Office", "days": []}]

    async def get_export_communications(self):
        return {"communications": {"service_enabled": True, "sms_enabled": False}}

    async def arm_section(self, section_id, mode, code=None, *, allowed_user_ids=None):
        del allowed_user_ids
        if section_id != 1:
            raise ValueError("Section 2 is outside the client-facing usable range 1-1.")
        self.last_arm_code = code
        self.status.sections[0].state = "armed_away"
        for listener in self._listeners:
            await listener("status", self.status.model_dump(mode="json"))
        return self.status

    async def disarm_section(self, section_id, code=None, *, allowed_user_ids=None):
        del allowed_user_ids
        if section_id != 1:
            raise ValueError("Section 2 is outside the client-facing usable range 1-1.")
        self.last_disarm_code = code
        self.status.sections[0].state = "disarmed"
        return self.status

    async def set_pg(self, pg_id, enabled, code=None, *, allowed_user_ids=None):
        if pg_id != 1:
            raise ValueError("PG 2 is outside the client-facing usable range 1-1.")
        self.last_pg_code = code
        self.status.pgs[0].state = "on" if enabled else "off"
        return self.status

    async def add_user(self, payload: UserCreateModel):
        if payload.id < 1 or payload.id > 100:
            raise ValueError(f"User {payload.id} is outside the client-facing usable range 1-100.")
        user = UserModel(id=payload.id, name=payload.name, rights="coUserNoSelfedit")
        self.catalog.users.append(user)
        return user

    async def edit_user(self, user_id, payload):
        if user_id < 1 or user_id > 100:
            raise ValueError(f"User {user_id} is outside the client-facing usable range 1-100.")
        user = await self.get_user(user_id)
        assert user is not None
        if payload.name is not None:
            user.name = payload.name
        return user

    async def delete_user(self, user_id):
        if user_id < 1 or user_id > 100:
            raise ValueError(f"User {user_id} is outside the client-facing usable range 1-100.")
        self.catalog.users = [user for user in self.catalog.users if user.id != user_id]


def build_client(tmp_path: Path) -> tuple[TestClient, str]:
    runtime = FakeRuntime()
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(label="test-admin", scopes=list(DEFAULT_ADMIN_SCOPES))
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    return TestClient(app), token


def build_client_with_runtime(tmp_path: Path) -> tuple[TestClient, str, FakeRuntime]:
    runtime = FakeRuntime()
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(label="test-admin", scopes=list(DEFAULT_ADMIN_SCOPES))
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    return TestClient(app), token, runtime


def test_health_and_system(tmp_path: Path) -> None:
    client, token = build_client(tmp_path)
    assert client.get("/v1/health").json() == {"status": "ok"}
    response = client.get("/v1/system", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["panel_model"] == "JA-107K"


def test_user_crud_and_scope_enforcement(tmp_path: Path) -> None:
    client, token = build_client(tmp_path)
    response = client.get("/v1/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()[0]["id"] == 80

    create_response = client.post(
        "/v1/users",
        headers={"Authorization": f"Bearer {token}"},
        json={"id": 81, "name": "User 81"},
    )
    assert create_response.status_code == 200
    assert create_response.json()["id"] == 81

    patch_response = client.patch(
        "/v1/users/81",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Edited 81"},
    )
    assert patch_response.status_code == 200
    assert patch_response.json()["name"] == "Edited 81"

    delete_response = client.delete("/v1/users/81", headers={"Authorization": f"Bearer {token}"})
    assert delete_response.status_code == 200
    assert delete_response.json()["status"] == "deleted"


def test_user_reads_redact_codes_without_users_codes_scope(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(label="users-readonly", scopes=[Scope.USERS_READ.value])
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    client = TestClient(app)

    users_response = client.get("/v1/users", headers={"Authorization": f"Bearer {token}"})
    assert users_response.status_code == 200
    assert users_response.json()[0]["code"] == ""

    export_response = client.get("/v1/export/users", headers={"Authorization": f"Bearer {token}"})
    assert export_response.status_code == 200
    assert export_response.json()[0]["code"] == ""


def test_user_reads_include_codes_with_explicit_sensitive_scope(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(
        label="users-sensitive",
        scopes=[Scope.USERS_READ.value, Scope.USERS_CODES_READ.value],
    )
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    client = TestClient(app)

    response = client.get("/v1/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()[0]["code"] == "1812"


def test_catalog_read_is_separate_and_redacts_users_by_default(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(label="catalog-only", scopes=[Scope.CATALOG_READ.value])
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    client = TestClient(app)

    response = client.get("/v1/export/catalog", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["users"] == []


def test_catalog_read_with_users_read_redacts_codes_without_sensitive_scope(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(
        label="catalog-users",
        scopes=[Scope.CATALOG_READ.value, Scope.USERS_READ.value],
    )
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    client = TestClient(app)

    response = client.get("/v1/export/catalog", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["users"][0]["code"] == ""


def test_export_catalog_now_requires_catalog_read_only(tmp_path: Path) -> None:
    # v1 lock: the historic catalog:read OR config:read alias was removed.
    # config:read alone must now be rejected for /v1/export/catalog.
    runtime = FakeRuntime()
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(label="config-only", scopes=[Scope.CONFIG_READ.value])
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    client = TestClient(app)

    response = client.get("/v1/export/catalog", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert response.json()["detail"]["missing"] == [Scope.CATALOG_READ.value]


def test_control_endpoints_forward_supplied_code(tmp_path: Path) -> None:
    client, token, runtime = build_client_with_runtime(tmp_path)
    headers = {"Authorization": f"Bearer {token}"}

    arm_response = client.post("/v1/sections/1/arm?mode=away&code=4321", headers=headers)
    assert arm_response.status_code == 200
    assert runtime.last_arm_code == "4321"

    disarm_response = client.post("/v1/sections/1/disarm?code=9876", headers=headers)
    assert disarm_response.status_code == 200
    assert runtime.last_disarm_code == "9876"

    pg_response = client.post("/v1/pgs/1/on?code=2468", headers=headers)
    assert pg_response.status_code == 200
    assert runtime.last_pg_code == "2468"


def test_control_endpoints_require_impersonation_scope_for_alternate_code(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(
        label="pg-control-only",
        scopes=[Scope.PGS_CONTROL.value],
    )
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    client = TestClient(app)

    forbidden = client.post("/v1/pgs/1/on?code=2468", headers={"Authorization": f"Bearer {token}"})
    assert forbidden.status_code == 403
    assert forbidden.json()["detail"]["missing"] == [Scope.CODES_IMPERSONATE.value]


def test_pg_control_endpoints_require_explicit_code(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(
        label="pg-control-only",
        scopes=[Scope.PGS_CONTROL.value, Scope.CODES_IMPERSONATE.value],
    )
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    client = TestClient(app)

    response = client.post("/v1/pgs/1/on", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert response.json()["detail"] == "PG control requires an explicit panel code."


def test_panel_runtime_uses_fast_lightweight_refresh_after_initial_full_poll() -> None:
    calls: list[dict[str, object]] = []

    class FakeSession:
        def query_snapshot(self, **kwargs):
            calls.append(dict(kwargs))
            return LegacyPanelSnapshot(
                sections=[SectionStatusModel(id=1, name="Section 1", state="disarmed")],
                pgs=[PGStatusModel(id=1, name="PG output 1", state="off")],
                devices=[],
                central=CentralStatusModel(),
                service_mode=False,
            )

    async def run() -> None:
        runtime = PanelRuntime(
            PanelRuntimeConfig(
                poll_interval_seconds=2.0,
                full_refresh_interval_seconds=15.0,
                fast_status_timeout_seconds=0.6,
                full_status_timeout_seconds=2.0,
            )
        )
        fake_session = FakeSession()
        runtime._create_status_session = lambda: fake_session  # type: ignore[method-assign]

        await runtime.refresh_status()
        await runtime.refresh_status()

    asyncio.run(run())

    assert len(calls) == 2
    assert calls[0]["query_device_status"] is True
    assert calls[0]["timeout"] == 2.0
    assert calls[1]["query_device_status"] is False
    assert calls[1]["timeout"] == 0.6


def test_panel_runtime_rejects_pg_control_for_known_user_without_pg_rights() -> None:
    async def run() -> None:
        runtime = PanelRuntime(PanelRuntimeConfig(port="auto", auth_code="4458"))
        runtime._catalog = ExportCatalogModel(
            sections=[],
            pgs=[ExportPGModel(id=15, display_id=15, name="PG output 15")],
            devices=[],
            users=[
                UserModel(
                    id=100,
                    name="HomeAssistant",
                    code="4458",
                    section_ids=[1],
                    pg_ids=[18],
                    rights="coUserNoSelfedit",
                )
            ],
            initial_setup=InitialSetupModel(
                source="test",
                exact=True,
                pgs=InitialSetupRangeModel(first_id=1, last_id=20, count=20),
            ),
        )
        try:
            await runtime.set_pg(15, True, code="4458")
        except PermissionError as exc:
            assert str(exc) == "The supplied code is not allowed to control PG 15."
            assert "100" not in str(exc)  # user id MUST NOT leak to clients
        else:
            raise AssertionError("Expected PermissionError for unauthorized PG control.")

    asyncio.run(run())


def test_panel_runtime_rejects_pg_control_for_token_bound_to_other_user() -> None:
    async def run() -> None:
        runtime = PanelRuntime(PanelRuntimeConfig(port="auto", auth_code="4458"))
        runtime._catalog = ExportCatalogModel(
            sections=[],
            pgs=[ExportPGModel(id=15, display_id=15, name="PG output 15")],
            devices=[],
            users=[
                UserModel(
                    id=100,
                    name="HomeAssistant",
                    code="4458",
                    section_ids=[1],
                    pg_ids=[15],
                    rights="coUserNoSelfedit",
                )
            ],
            initial_setup=InitialSetupModel(
                source="test",
                exact=True,
                pgs=InitialSetupRangeModel(first_id=1, last_id=20, count=20),
            ),
        )
        try:
            await runtime.set_pg(15, True, code="4458", allowed_user_ids=[101])
        except PermissionError as exc:
            assert str(exc) == "The supplied code is not allowed by this token."
            assert "100" not in str(exc)
        else:
            raise AssertionError("Expected PermissionError for token/user mismatch.")

    asyncio.run(run())


def test_device_problem_defaults_to_false() -> None:
    device = DeviceStatusModel(id=1, name="Device 1")
    assert device.problem is False


def test_export_endpoints_and_device_metadata(tmp_path: Path) -> None:
    client, token = build_client(tmp_path)
    devices = client.get("/v1/devices", headers={"Authorization": f"Bearer {token}"}).json()
    assert devices[0]["inferred_device_type"] == "motion_detector"

    export_catalog = client.get("/v1/export/catalog", headers={"Authorization": f"Bearer {token}"}).json()
    assert export_catalog["devices"][0]["hardware_model"] == "JA-110P"
    assert export_catalog["initial_setup"]["pgs"]["last_id"] == 1
    assert export_catalog["raw_counts"]["pgs"] == 128

    time_limits = client.get("/v1/export/time-limits", headers={"Authorization": f"Bearer {token}"}).json()
    assert time_limits["time_limits"][0]["comment"] == "Office"

    communications = client.get("/v1/export/communications", headers={"Authorization": f"Bearer {token}"}).json()
    assert communications["communications"]["service_enabled"] is True


def test_catalog_names_are_applied_to_live_status() -> None:
    sections, pgs = _apply_catalog_names(
        sections=[SectionStatusModel(id=1, name="Section 1", state="disarmed")],
        pgs=[PGStatusModel(id=1, name="PG output 1", state="off")],
        catalog=ExportCatalogModel(
            sections=[ExportSectionModel(id=1, display_id=1, name="Ground Floor")],
            pgs=[ExportPGModel(id=0, display_id=1, name="Gate Relay")],
            devices=[],
            users=[],
        ),
    )
    assert sections[0].name == "Ground Floor"
    assert pgs[0].name == "Gate Relay"


def test_infer_device_type_avoids_module_name_mismatches() -> None:
    assert _infer_device_type(name="Module channel 1", hardware_model="JA-114HN", type_raw=14, object_id=35) == ("io_module", None)
    assert _infer_device_type(name="Reader 1", hardware_model="JA-122E", type_raw=14, object_id=40) == ("rfid_reader", None)
    assert _infer_device_type(name="Bus booster", hardware_model="120Z", type_raw=14, object_id=1) == ("bus_booster", None)


def test_infer_device_type_restores_legacy_stateful_types() -> None:
    assert _infer_device_type(name="Thermostat hallway", hardware_model="JA-150TP", type_raw=None, object_id=41) == (
        "thermostat",
        "device_state_thermostat",
    )
    assert _infer_device_type(name="Glass break", hardware_model=None, type_raw=None, object_id=17) == (
        "glass_break_detector",
        "device_state_glass",
    )
    assert _infer_device_type(name="Garage gate", hardware_model=None, type_raw=None, object_id=18) == (
        "garage_door_opening_detector",
        "device_state_garage_door",
    )
    assert _infer_device_type(name="Valve boiler", hardware_model=None, type_raw=None, object_id=19) == (
        "valve",
        "device_state_valve",
    )


def test_catalog_devices_named_like_pgs_do_not_become_fake_doors() -> None:
    snapshot = SimpleNamespace(
        sections_by_id={},
        pgs_by_id={5: SimpleNamespace(pg_id=5, display_id=6, name="PG mirror channel 1", comment="", section_id=0)},
        objects_by_id={
            36: SimpleNamespace(
                object_id=36,
                name="PG mirror channel 1",
                kind_raw=4,
                section_id=0,
                type_raw=14,
                subtype_raw=-1,
                comment="",
            )
        },
        users=[],
        hardware_by_id={},
        main_config=None,
        path=None,
        sha256=None,
    )
    catalog = _catalog_to_model(snapshot)
    assert catalog.devices[0].inferred_device_type == "io_module"
    assert catalog.devices[0].inferred_entity_type is None


def test_persistent_snapshot_session_reuses_single_login(monkeypatch) -> None:
    client_creations = 0
    login_calls = 0
    enable_calls = 0
    section_query_calls = 0
    close_calls = 0

    class FakeClient:
        def __init__(self, serial_port: str) -> None:
            nonlocal client_creations
            client_creations += 1
            self.serial_port = serial_port

        def send_packet(self, packet: bytes) -> None:
            return None

        def send_packets(self, packets) -> None:
            return None

        def read_packets(self, *, timeout=None):
            return iter(())

        def close(self) -> None:
            nonlocal close_calls
            close_calls += 1

    def fake_login(client, code: str, *, reset: bool) -> None:
        nonlocal login_calls
        login_calls += 1

    def fake_enable(client) -> None:
        nonlocal enable_calls
        enable_calls += 1

    def fake_sections(client) -> None:
        nonlocal section_query_calls
        section_query_calls += 1

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy, "JablotronUSBClient", FakeClient)
    monkeypatch.setattr(legacy, "perform_login", fake_login)
    monkeypatch.setattr(legacy, "perform_enable_device_states", fake_enable)
    monkeypatch.setattr(legacy, "perform_sections_query", fake_sections)
    monkeypatch.setattr(legacy.time, "sleep", lambda _: None)

    session = PersistentSnapshotSession(port="auto", code="1812", reset=True)
    try:
        first = session.query_snapshot(panel_model=None, pg_count=0, timeout=0.01)
        second = session.query_snapshot(panel_model=None, pg_count=0, timeout=0.01)
    finally:
        session.close()

    assert first.sections == []
    assert second.sections == []
    assert client_creations == 1
    assert login_calls == 1
    assert enable_calls == 1
    assert section_query_calls == 3
    assert close_calls == 1


def test_persistent_snapshot_session_close_logs_out_before_closing(monkeypatch) -> None:
    events: list[str] = []
    sent_packets: list[bytes] = []

    class FakeClient:
        def __init__(self, serial_port: str) -> None:
            self.serial_port = serial_port

        def send_packet(self, packet: bytes) -> None:
            sent_packets.append(packet)
            return None

        def send_packets(self, packets) -> None:
            sent_packets.extend(list(packets))
            return None

        def read_packets(self, *, timeout=None):
            return iter(())

        def close(self) -> None:
            events.append("client_close")

    def fake_login(client, code: str, *, reset: bool) -> None:
        events.append("login")

    def fake_enable(client) -> None:
        events.append("enable")

    def fake_sections(client) -> None:
        events.append("sections")

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy, "JablotronUSBClient", FakeClient)
    monkeypatch.setattr(legacy, "perform_login", fake_login)
    monkeypatch.setattr(legacy, "perform_enable_device_states", fake_enable)
    monkeypatch.setattr(legacy, "perform_sections_query", fake_sections)
    monkeypatch.setattr(legacy.time, "sleep", lambda _: None)

    session = PersistentSnapshotSession(port="auto", code="1812", reset=True)
    session.query_snapshot(panel_model=None, pg_count=0, timeout=0.01)
    session.close()

    assert legacy.EXIT_DIAGNOSTICS_OFF_PACKET in sent_packets
    assert legacy.Jablotron.create_packet_ui_control(legacy.UI_CONTROL_AUTHORISATION_END) in sent_packets
    assert legacy.Jablotron.create_packet_command(b"\x0e") in sent_packets
    assert legacy.Jablotron.create_packet_command(b"\x02") in sent_packets
    assert events.index("client_close") > 0


def test_diagnostics_timeout_is_longer_for_wireless_temperature_devices() -> None:
    assert legacy._diagnostics_timeout_for_device(
        DeviceStatusModel(id=41, name="Wireless thermostat", inferred_device_type="thermostat", wireless=True)
    ) == legacy.WIRELESS_TEMPERATURE_DIAGNOSTICS_TIMEOUT_SECONDS
    assert legacy._diagnostics_timeout_for_device(
        DeviceStatusModel(id=18, name="Wired thermostat", inferred_device_type="thermostat", wireless=False)
    ) == legacy.DEFAULT_DIAGNOSTICS_TIMEOUT_SECONDS
    assert legacy._diagnostics_timeout_for_device(
        DeviceStatusModel(id=2, name="Wireless PIR", inferred_device_type="motion_detector", wireless=True)
    ) == legacy.DEFAULT_DIAGNOSTICS_TIMEOUT_SECONDS


def test_diagnostics_priority_prefers_unresolved_wireless_temperature_devices() -> None:
    unresolved = DeviceStatusModel(id=41, name="Wireless thermostat", inferred_device_type="thermostat", wireless=True, temperature=None)
    resolved = DeviceStatusModel(id=42, name="Wireless thermostat", inferred_device_type="thermostat", wireless=True, temperature=23.6)
    wired = DeviceStatusModel(id=24, name="Wired thermostat", inferred_device_type="thermostat", wireless=False, temperature=23.3)

    ordered = sorted([wired, resolved, unresolved], key=legacy._diagnostics_priority)

    assert [device.id for device in ordered] == [41, 42, 24]


def test_read_into_parser_can_wait_through_quiet_gap_for_late_packets(monkeypatch) -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.calls = 0

        def read_packets(self, *, timeout=None):
            self.calls += 1
            if self.calls == 1:
                return iter([b"first"])
            if self.calls == 2:
                return iter(())
            if self.calls == 3:
                return iter([b"late"])
            return iter(())

    parser = type("Parser", (), {"seen": [], "parse_packet": lambda self, packet, *, pg_count: self.seen.append(packet)})()
    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    session = PersistentSnapshotSession(port="auto", code="4458", reset=True)
    client = FakeClient()

    monotonic_values = chain([0.0, 0.0, 0.1, 0.1, 0.4, 0.4, 0.7, 0.7, 1.1], repeat(1.1))
    monkeypatch.setattr(legacy.time, "monotonic", lambda: next(monotonic_values))

    session._read_into_parser_locked(client, parser, pg_count=0, timeout=1.0, stop_on_first_gap=False)

    assert parser.seen == [b"first", b"late"]


def test_panel_runtime_close_runs_exit_only_cleanup_after_status_session(monkeypatch) -> None:
    events: list[tuple[str, object]] = []

    class FakeSession:
        def close(self) -> None:
            events.append(("session_close", None))

    def fake_cleanup_read_session(*, port: str, code: str, cleanup_mode: str, verbose: bool):
        events.append(("cleanup", {"port": port, "code": code, "cleanup_mode": cleanup_mode, "verbose": verbose}))
        return 0x90

    monkeypatch.setattr(runtime_module, "cleanup_read_session", fake_cleanup_read_session)

    async def run() -> None:
        runtime = PanelRuntime(PanelRuntimeConfig(port="auto", auth_code="4458"))
        runtime._status_session = FakeSession()  # type: ignore[assignment]
        await runtime.close()

    import asyncio

    asyncio.run(run())

    assert events == [
        ("session_close", None),
        ("cleanup", {"port": "auto", "code": "4458", "cleanup_mode": "exit-only", "verbose": False}),
    ]


def test_persistent_snapshot_session_control_reuses_existing_login(monkeypatch) -> None:
    client_creations = 0
    login_calls = 0
    close_calls = 0

    class FakeClient:
        def __init__(self, serial_port: str) -> None:
            nonlocal client_creations
            client_creations += 1
            self.serial_port = serial_port

        def send_packet(self, packet: bytes) -> None:
            return None

        def send_packets(self, packets) -> None:
            return None

        def read_packets(self, *, timeout=None):
            return iter(())

        def close(self) -> None:
            nonlocal close_calls
            close_calls += 1

    def fake_login(client, code: str, *, reset: bool) -> None:
        nonlocal login_calls
        login_calls += 1

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy, "JablotronUSBClient", FakeClient)
    monkeypatch.setattr(legacy, "perform_login", fake_login)
    monkeypatch.setattr(legacy, "perform_enable_device_states", lambda client: None)
    monkeypatch.setattr(legacy, "perform_sections_query", lambda client: None)
    monkeypatch.setattr(
        PersistentSnapshotSession,
        "_await_pg_control_confirmation_locked",
        lambda self, client, *, pg_id, enabled, timeout=legacy.CONTROL_CONFIRMATION_TIMEOUT_SECONDS: True,
    )
    monkeypatch.setattr(
        PersistentSnapshotSession,
        "_await_section_control_confirmation_locked",
        lambda self, client, *, section_id, action, timeout=legacy.CONTROL_CONFIRMATION_TIMEOUT_SECONDS: True,
    )
    monkeypatch.setattr(legacy.time, "sleep", lambda _: None)

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    session = PersistentSnapshotSession(port="auto", code="4458", reset=True)
    try:
        session.query_snapshot(panel_model=None, pg_count=0, timeout=0.01)
        session.control_pg(pg_id=17, enabled=True, code="4458")
        session.control_section(section_id=5, action="disarm", code="4458")
        session.query_snapshot(panel_model=None, pg_count=0, timeout=0.01)
    finally:
        session.close()

    assert client_creations == 1
    assert login_calls == 1
    assert close_calls == 1


def test_persistent_snapshot_session_retries_pg_control_with_auth_refresh_after_missing_confirmation(monkeypatch) -> None:
    sent_packets: list[bytes] = []
    confirmations = iter([False, True])
    confirmation_timeouts: list[float] = []

    class FakeClient:
        def __init__(self, serial_port: str) -> None:
            self.serial_port = serial_port

        def send_packet(self, packet: bytes) -> None:
            sent_packets.append(packet)

        def send_packets(self, packets) -> None:
            sent_packets.extend(list(packets))

        def read_packets(self, *, timeout=None):
            return iter(())

        def close(self) -> None:
            return None

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy, "JablotronUSBClient", FakeClient)
    monkeypatch.setattr(legacy, "perform_login", lambda client, code, *, reset: None)
    monkeypatch.setattr(legacy, "perform_enable_device_states", lambda client: None)
    monkeypatch.setattr(legacy, "perform_sections_query", lambda client: None)
    monkeypatch.setattr(legacy, "_await_login_success", lambda client, timeout=0.8: None)
    monkeypatch.setattr(
        PersistentSnapshotSession,
        "_await_pg_control_confirmation_locked",
        lambda self, client, *, pg_id, enabled, timeout=legacy.CONTROL_CONFIRMATION_TIMEOUT_SECONDS: (
            confirmation_timeouts.append(timeout) or next(confirmations)
        ),
    )
    monkeypatch.setattr(PersistentSnapshotSession, "_drain_packets_locked", lambda self, client, *, timeout: [])
    monkeypatch.setattr(legacy.time, "sleep", lambda _: None)

    session = PersistentSnapshotSession(port="auto", code="4458", reset=True)
    try:
        with session._io_lock:
            session._ensure_client_locked()
        session.control_pg(pg_id=17, enabled=True, code="4458")
    finally:
        session.close()

    assert legacy.Jablotron.create_packet_authorisation_code("4458") in sent_packets
    assert legacy.Jablotron.create_packet_enable_device_states() in sent_packets
    assert sent_packets.count(legacy.Jablotron.create_packet_ui_control(legacy.UI_CONTROL_TOGGLE_PG_OUTPUT, b"\x10\x01")) == 2
    assert confirmation_timeouts == [
        legacy.FAST_CONTROL_CONFIRMATION_TIMEOUT_SECONDS,
        legacy.CONTROL_CONFIRMATION_TIMEOUT_SECONDS,
    ]


def test_persistent_snapshot_session_does_not_refresh_authorization_when_pg_control_is_confirmed(monkeypatch) -> None:
    sent_packets: list[bytes] = []
    confirmation_timeouts: list[float] = []

    class FakeClient:
        def __init__(self, serial_port: str) -> None:
            self.serial_port = serial_port

        def send_packet(self, packet: bytes) -> None:
            sent_packets.append(packet)

        def send_packets(self, packets) -> None:
            sent_packets.extend(list(packets))

        def read_packets(self, *, timeout=None):
            return iter(())

        def close(self) -> None:
            return None

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy, "JablotronUSBClient", FakeClient)
    monkeypatch.setattr(legacy, "perform_login", lambda client, code, *, reset: None)
    monkeypatch.setattr(legacy, "perform_enable_device_states", lambda client: None)
    monkeypatch.setattr(legacy, "perform_sections_query", lambda client: None)
    monkeypatch.setattr(legacy, "_await_login_success", lambda client, timeout=0.8: None)
    monkeypatch.setattr(
        PersistentSnapshotSession,
        "_await_pg_control_confirmation_locked",
        lambda self, client, *, pg_id, enabled, timeout=legacy.CONTROL_CONFIRMATION_TIMEOUT_SECONDS: (
            confirmation_timeouts.append(timeout) or True
        ),
    )
    monkeypatch.setattr(PersistentSnapshotSession, "_drain_packets_locked", lambda self, client, *, timeout: [])
    monkeypatch.setattr(legacy.time, "sleep", lambda _: None)

    session = PersistentSnapshotSession(port="auto", code="4458", reset=True)
    try:
        with session._io_lock:
            session._ensure_client_locked()
        session.control_pg(pg_id=17, enabled=True, code="4458")
    finally:
        session.close()

    assert sent_packets.count(legacy.Jablotron.create_packet_authorisation_code("4458")) == 0
    assert legacy.Jablotron.create_packet_ui_control(legacy.UI_CONTROL_TOGGLE_PG_OUTPUT, b"\x10\x01") in sent_packets
    assert confirmation_timeouts == [legacy.FAST_CONTROL_CONFIRMATION_TIMEOUT_SECONDS]


def test_persistent_snapshot_session_skips_first_pg_attempt_after_control_auth_idle_timeout(monkeypatch) -> None:
    sent_packets: list[bytes] = []
    confirmation_timeouts: list[float] = []

    class FakeClient:
        def __init__(self, serial_port: str) -> None:
            self.serial_port = serial_port

        def send_packet(self, packet: bytes) -> None:
            sent_packets.append(packet)

        def send_packets(self, packets) -> None:
            sent_packets.extend(list(packets))

        def read_packets(self, *, timeout=None):
            return iter(())

        def close(self) -> None:
            return None

    monotonic_values = iter([100.0, 100.0, 161.0, 162.0, 163.0])

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy, "JablotronUSBClient", FakeClient)
    monkeypatch.setattr(legacy, "perform_login", lambda client, code, *, reset: None)
    monkeypatch.setattr(legacy, "perform_enable_device_states", lambda client: None)
    monkeypatch.setattr(legacy, "perform_sections_query", lambda client: None)
    monkeypatch.setattr(legacy, "_await_login_success", lambda client, timeout=0.8: None)
    monkeypatch.setattr(
        PersistentSnapshotSession,
        "_await_pg_control_confirmation_locked",
        lambda self, client, *, pg_id, enabled, timeout=legacy.CONTROL_CONFIRMATION_TIMEOUT_SECONDS: (
            confirmation_timeouts.append(timeout) or True
        ),
    )
    monkeypatch.setattr(PersistentSnapshotSession, "_drain_packets_locked", lambda self, client, *, timeout: [])
    monkeypatch.setattr(legacy.time, "sleep", lambda _: None)
    monkeypatch.setattr(legacy.time, "monotonic", lambda: next(monotonic_values))

    session = PersistentSnapshotSession(port="auto", code="4458", reset=True)
    try:
        with session._io_lock:
            session._ensure_client_locked()
        session.control_pg(pg_id=17, enabled=True, code="4458")
    finally:
        session.close()

    assert sent_packets.count(legacy.Jablotron.create_packet_authorisation_code("4458")) == 1
    assert sent_packets.count(legacy.Jablotron.create_packet_ui_control(legacy.UI_CONTROL_TOGGLE_PG_OUTPUT, b"\x10\x01")) == 1
    assert confirmation_timeouts == [legacy.FAST_CONTROL_CONFIRMATION_TIMEOUT_SECONDS]


def test_pg_control_confirmation_requires_target_pg_to_reach_requested_state(monkeypatch) -> None:
    class FakeClient:
        def read_packets(self, *, timeout=None):
            return iter([bytes.fromhex("820300")])

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    session = PersistentSnapshotSession(port="auto", code="4458", reset=True)
    monotonic_values = iter([0.0, 0.1, 0.2, 0.8])

    monkeypatch.setattr(legacy.time, "monotonic", lambda: next(monotonic_values))

    assert session._await_pg_control_confirmation_locked(FakeClient(), pg_id=1, enabled=True) is False


def test_persistent_snapshot_session_switches_codes_without_reopening(monkeypatch) -> None:
    client_creations = 0
    login_calls = 0
    close_calls = 0

    class FakeClient:
        def __init__(self, serial_port: str) -> None:
            nonlocal client_creations
            client_creations += 1
            self.serial_port = serial_port

        def send_packet(self, packet: bytes) -> None:
            return None

        def send_packets(self, packets) -> None:
            return None

        def read_packets(self, *, timeout=None):
            return iter(())

        def close(self) -> None:
            nonlocal close_calls
            close_calls += 1

    def fake_login(client, code: str, *, reset: bool) -> None:
        nonlocal login_calls
        login_calls += 1

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy, "JablotronUSBClient", FakeClient)
    monkeypatch.setattr(legacy, "perform_login", fake_login)
    monkeypatch.setattr(legacy, "perform_enable_device_states", lambda client: None)
    monkeypatch.setattr(legacy, "perform_sections_query", lambda client: None)
    monkeypatch.setattr(
        PersistentSnapshotSession,
        "_await_section_control_confirmation_locked",
        lambda self, client, *, section_id, action, timeout=legacy.CONTROL_CONFIRMATION_TIMEOUT_SECONDS: True,
    )
    monkeypatch.setattr(legacy.time, "sleep", lambda _: None)

    session = PersistentSnapshotSession(port="auto", code="4458", reset=True)
    try:
        session.query_snapshot(panel_model=None, pg_count=0, timeout=0.01)
        session.control_section(section_id=5, action="disarm", code="1812")
        session.query_snapshot(panel_model=None, pg_count=0, timeout=0.01)
    finally:
        session.close()

    assert client_creations == 1
    assert login_calls == 1
    assert close_calls == 1


def test_persistent_snapshot_session_retries_section_control_with_auth_refresh_after_missing_confirmation(monkeypatch) -> None:
    sent_packets: list[bytes] = []
    confirmations = iter([False, True])
    confirmation_timeouts: list[float] = []

    class FakeClient:
        def __init__(self, serial_port: str) -> None:
            self.serial_port = serial_port

        def send_packet(self, packet: bytes) -> None:
            sent_packets.append(packet)

        def send_packets(self, packets) -> None:
            sent_packets.extend(list(packets))

        def read_packets(self, *, timeout=None):
            return iter(())

        def close(self) -> None:
            return None

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy, "JablotronUSBClient", FakeClient)
    monkeypatch.setattr(legacy, "perform_login", lambda client, code, *, reset: None)
    monkeypatch.setattr(legacy, "perform_enable_device_states", lambda client: None)
    monkeypatch.setattr(legacy, "perform_sections_query", lambda client: None)
    monkeypatch.setattr(legacy, "_await_login_success", lambda client, timeout=0.8: None)
    monkeypatch.setattr(
        PersistentSnapshotSession,
        "_await_section_control_confirmation_locked",
        lambda self, client, *, section_id, action, timeout=legacy.CONTROL_CONFIRMATION_TIMEOUT_SECONDS: (
            confirmation_timeouts.append(timeout) or next(confirmations)
        ),
    )
    monkeypatch.setattr(PersistentSnapshotSession, "_drain_packets_locked", lambda self, client, *, timeout: [])
    monkeypatch.setattr(legacy.time, "sleep", lambda _: None)

    session = PersistentSnapshotSession(port="auto", code="4458", reset=True)
    try:
        with session._io_lock:
            session._ensure_client_locked()
        session.control_section(section_id=4, action="arm_away", code="4458")
    finally:
        session.close()

    assert legacy.Jablotron.create_packet_authorisation_code("4458") in sent_packets
    assert legacy.Jablotron.create_packet_enable_device_states() in sent_packets
    assert sent_packets.count(legacy.Jablotron.create_packet_ui_control(legacy.UI_CONTROL_MODIFY_SECTION, b"\xa3")) == 2
    assert confirmation_timeouts == [
        legacy.FAST_CONTROL_CONFIRMATION_TIMEOUT_SECONDS,
        legacy.CONTROL_CONFIRMATION_TIMEOUT_SECONDS,
    ]


def test_persistent_snapshot_session_does_not_refresh_authorization_when_section_control_is_confirmed(monkeypatch) -> None:
    sent_packets: list[bytes] = []
    confirmation_timeouts: list[float] = []

    class FakeClient:
        def __init__(self, serial_port: str) -> None:
            self.serial_port = serial_port

        def send_packet(self, packet: bytes) -> None:
            sent_packets.append(packet)

        def send_packets(self, packets) -> None:
            sent_packets.extend(list(packets))

        def read_packets(self, *, timeout=None):
            return iter(())

        def close(self) -> None:
            return None

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy, "JablotronUSBClient", FakeClient)
    monkeypatch.setattr(legacy, "perform_login", lambda client, code, *, reset: None)
    monkeypatch.setattr(legacy, "perform_enable_device_states", lambda client: None)
    monkeypatch.setattr(legacy, "perform_sections_query", lambda client: None)
    monkeypatch.setattr(legacy, "_await_login_success", lambda client, timeout=0.8: None)
    monkeypatch.setattr(
        PersistentSnapshotSession,
        "_await_section_control_confirmation_locked",
        lambda self, client, *, section_id, action, timeout=legacy.CONTROL_CONFIRMATION_TIMEOUT_SECONDS: (
            confirmation_timeouts.append(timeout) or True
        ),
    )
    monkeypatch.setattr(PersistentSnapshotSession, "_drain_packets_locked", lambda self, client, *, timeout: [])
    monkeypatch.setattr(legacy.time, "sleep", lambda _: None)

    session = PersistentSnapshotSession(port="auto", code="4458", reset=True)
    try:
        with session._io_lock:
            session._ensure_client_locked()
        session.control_section(section_id=4, action="arm_away", code="4458")
    finally:
        session.close()

    assert sent_packets.count(legacy.Jablotron.create_packet_authorisation_code("4458")) == 0
    assert legacy.Jablotron.create_packet_ui_control(legacy.UI_CONTROL_MODIFY_SECTION, b"\xa3") in sent_packets
    assert confirmation_timeouts == [legacy.FAST_CONTROL_CONFIRMATION_TIMEOUT_SECONDS]


def test_persistent_snapshot_session_skips_first_section_attempt_after_control_auth_idle_timeout(monkeypatch) -> None:
    sent_packets: list[bytes] = []
    confirmation_timeouts: list[float] = []

    class FakeClient:
        def __init__(self, serial_port: str) -> None:
            self.serial_port = serial_port

        def send_packet(self, packet: bytes) -> None:
            sent_packets.append(packet)

        def send_packets(self, packets) -> None:
            sent_packets.extend(list(packets))

        def read_packets(self, *, timeout=None):
            return iter(())

        def close(self) -> None:
            return None

    monotonic_values = iter([100.0, 100.0, 161.0, 162.0, 163.0])

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy, "JablotronUSBClient", FakeClient)
    monkeypatch.setattr(legacy, "perform_login", lambda client, code, *, reset: None)
    monkeypatch.setattr(legacy, "perform_enable_device_states", lambda client: None)
    monkeypatch.setattr(legacy, "perform_sections_query", lambda client: None)
    monkeypatch.setattr(legacy, "_await_login_success", lambda client, timeout=0.8: None)
    monkeypatch.setattr(
        PersistentSnapshotSession,
        "_await_section_control_confirmation_locked",
        lambda self, client, *, section_id, action, timeout=legacy.CONTROL_CONFIRMATION_TIMEOUT_SECONDS: (
            confirmation_timeouts.append(timeout) or True
        ),
    )
    monkeypatch.setattr(PersistentSnapshotSession, "_drain_packets_locked", lambda self, client, *, timeout: [])
    monkeypatch.setattr(legacy.time, "sleep", lambda _: None)
    monkeypatch.setattr(legacy.time, "monotonic", lambda: next(monotonic_values))

    session = PersistentSnapshotSession(port="auto", code="4458", reset=True)
    try:
        with session._io_lock:
            session._ensure_client_locked()
        session.control_section(section_id=4, action="arm_away", code="4458")
    finally:
        session.close()

    assert sent_packets.count(legacy.Jablotron.create_packet_authorisation_code("4458")) == 1
    assert sent_packets.count(legacy.Jablotron.create_packet_ui_control(legacy.UI_CONTROL_MODIFY_SECTION, b"\xa3")) == 1
    assert confirmation_timeouts == [legacy.FAST_CONTROL_CONFIRMATION_TIMEOUT_SECONDS]


def test_section_control_confirmation_requires_target_section_to_reach_requested_state(monkeypatch) -> None:
    class _SectionState:
        pending = False
        arming = False
        triggered = False
        state = SimpleNamespace(name="OFF")

    class FakeClient:
        def read_packets(self, *, timeout=None):
            return iter([b"\x81\x00"])

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy.Jablotron, "_is_sections_states_packet", lambda packet: True)
    monkeypatch.setattr(
        legacy.Jablotron,
        "_convert_sections_states_packet_to_sections_states",
        lambda packet: {4: _SectionState()},
    )
    session = PersistentSnapshotSession(port="auto", code="4458", reset=True)
    monotonic_values = iter([0.0, 0.1, 0.2, 0.8])

    monkeypatch.setattr(legacy.time, "monotonic", lambda: next(monotonic_values))

    assert session._await_section_control_confirmation_locked(FakeClient(), section_id=4, action="arm_away") is False


def test_persistent_snapshot_session_system_info_reuses_existing_login(monkeypatch) -> None:
    client_creations = 0
    login_calls = 0
    close_calls = 0

    class FakeClient:
        def __init__(self, serial_port: str) -> None:
            nonlocal client_creations
            client_creations += 1
            self.serial_port = serial_port

        def send_packet(self, packet: bytes) -> None:
            return None

        def send_packets(self, packets) -> None:
            return None

        def read_packets(self, *, timeout=None):
            return iter(())

        def close(self) -> None:
            nonlocal close_calls
            close_calls += 1

    def fake_login(client, code: str, *, reset: bool) -> None:
        nonlocal login_calls
        login_calls += 1

    monkeypatch.setattr(legacy, "ensure_serial_port", lambda port: "/dev/fakehid")
    monkeypatch.setattr(legacy, "JablotronUSBClient", FakeClient)
    monkeypatch.setattr(legacy, "perform_login", fake_login)
    monkeypatch.setattr(legacy, "perform_enable_device_states", lambda client: None)
    monkeypatch.setattr(legacy, "perform_sections_query", lambda client: None)
    monkeypatch.setattr(legacy.time, "sleep", lambda _: None)

    session = PersistentSnapshotSession(port="auto", code="4458", reset=True)
    try:
        session.query_system_info(timeout=0.01)
        session.query_snapshot(panel_model=None, pg_count=0, timeout=0.01)
    finally:
        session.close()

    assert client_creations == 1
    assert login_calls == 1
    assert close_calls == 1


def test_scope_denial_revocation_and_certificate_binding(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    store = TokenStore(tmp_path / "tokens.db")
    readonly_token, readonly_info = store.create_token(
        label="readonly",
        scopes=[
            Scope.SECTIONS_READ.value,
            Scope.PGS_READ.value,
            Scope.DEVICES_READ.value,
            Scope.SYSTEM_READ.value,
        ],
    )
    cert_token, _ = store.create_token(
        label="cert-bound",
        scopes=[Scope.SYSTEM_READ.value],
        certificate_fingerprint="demo-fingerprint",
    )
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    client = TestClient(app)

    denied = client.post("/v1/users", headers={"Authorization": f"Bearer {readonly_token}"}, json={"id": 81, "name": "Denied"})
    assert denied.status_code == 403
    assert denied.json()["detail"]["error"] == "missing_scopes"

    store.revoke_token(readonly_info.id)
    revoked = client.get("/v1/status", headers={"Authorization": f"Bearer {readonly_token}"})
    assert revoked.status_code == 401

    missing_fingerprint = client.get("/v1/system", headers={"Authorization": f"Bearer {cert_token}"})
    assert missing_fingerprint.status_code == 401

    from jablotron_api.server.app import certificate_fingerprint_from_request

    # Override the TLS-scope-derived dependency to simulate a verified
    # client cert in the test transport, which doesn't actually run mTLS.
    # The server never reads cert fingerprints from request headers or
    # query parameters; this override is the only sanctioned way to inject
    # one from a test.
    app.dependency_overrides[certificate_fingerprint_from_request] = lambda: "demo-fingerprint"
    try:
        matching_fingerprint = client.get(
            "/v1/system",
            headers={"Authorization": f"Bearer {cert_token}"},
        )
        assert matching_fingerprint.status_code == 200

        # Header injection MUST NOT bypass cert binding: even with a
        # matching fingerprint in the X-Client-Cert-Fingerprint header,
        # the server should ignore it when the dependency returns None.
        app.dependency_overrides[certificate_fingerprint_from_request] = lambda: None
        forged_header = client.get(
            "/v1/system",
            headers={
                "Authorization": f"Bearer {cert_token}",
                "X-Client-Cert-Fingerprint": "demo-fingerprint",
            },
        )
        assert forged_header.status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_section_control_ack_failure_returns_conflict(tmp_path: Path) -> None:
    runtime = FakeRuntime()

    async def fail_arm(section_id, mode, code=None, *, allowed_user_ids=None):
        del allowed_user_ids
        raise RuntimeError("Section control was not acknowledged by the panel.")

    runtime.arm_section = fail_arm
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(
        label="controller",
        scopes=[
            Scope.SECTIONS_ARM.value,
            Scope.SECTIONS_DISARM.value,
            Scope.CODES_IMPERSONATE.value,
        ],
    )
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    client = TestClient(app)

    response = client.post(
        "/v1/sections/1/arm?mode=away&code=1812",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Section control was not acknowledged by the panel."


def test_user_mutation_verification_failures_return_conflict(tmp_path: Path) -> None:
    runtime = FakeRuntime()

    async def fail_add(payload):
        raise RuntimeError("User 81 post-add verification failed for: name.")

    async def fail_edit(user_id, payload):
        raise RuntimeError("User 81 post-edit verification failed for: name.")

    async def fail_delete(user_id):
        raise RuntimeError("User 81 was still present after delete.")

    runtime.add_user = fail_add
    runtime.edit_user = fail_edit
    runtime.delete_user = fail_delete
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(
        label="controller",
        scopes=[Scope.USERS_WRITE.value],
    )
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    client = TestClient(app)

    add_response = client.post(
        "/v1/users",
        headers={"Authorization": f"Bearer {token}"},
        json={"id": 81, "name": "User 81"},
    )
    assert add_response.status_code == 409

    edit_response = client.patch(
        "/v1/users/81",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Edited 81"},
    )
    assert edit_response.status_code == 409

    delete_response = client.delete(
        "/v1/users/81",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert delete_response.status_code == 409


def test_panel_runtime_add_user_verification_ignores_omitted_optional_fields() -> None:
    runtime = object.__new__(PanelRuntime)
    user = UserModel(
        id=90,
        name="API REF TEST 90",
        flags_raw=0,
        access_raw=0,
        enabled=True,
        rights="coNoAccess",
        time_limited_group_raw=0,
    )

    runtime._verify_added_user(user, UserCreateModel(id=90, name="API REF TEST 90"))

    with pytest.raises(RuntimeError, match="access_raw"):
        runtime._verify_added_user(user, UserCreateModel(id=90, name="API REF TEST 90", access_raw=811))


def test_scope_tls_extension_certificate_binding(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    store = TokenStore(tmp_path / "tokens.db")
    bound_token, _ = store.create_token(
        label="tls-bound",
        scopes=[Scope.SYSTEM_READ.value],
        certificate_fingerprint="tls-fingerprint",
    )
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )

    @app.middleware("http")
    async def inject_tls_scope(request: Request, call_next):
        request.scope.setdefault("extensions", {})[TLS_EXTENSION_KEY] = {
            "client_cert_fingerprint_sha256": "tls-fingerprint",
        }
        return await call_next(request)

    client = TestClient(app)
    response = client.get("/v1/system", headers={"Authorization": f"Bearer {bound_token}"})
    assert response.status_code == 200
    assert response.json()["panel_model"] == "JA-107K"


def test_client_facing_ranges_are_enforced(tmp_path: Path) -> None:
    client, token = build_client(tmp_path)

    bad_section = client.post("/v1/sections/2/arm", headers={"Authorization": f"Bearer {token}"})
    assert bad_section.status_code == 400
    assert "usable range 1-1" in bad_section.json()["detail"]

    bad_pg = client.post("/v1/pgs/2/on?code=1812", headers={"Authorization": f"Bearer {token}"})
    assert bad_pg.status_code == 400
    assert "usable range 1-1" in bad_pg.json()["detail"]

    bad_user = client.post(
        "/v1/users",
        headers={"Authorization": f"Bearer {token}"},
        json={"id": 101, "name": "Out Of Range"},
    )
    assert bad_user.status_code == 400
    assert "usable range 1-100" in bad_user.json()["detail"]


def test_websocket_subscription(tmp_path: Path) -> None:
    client, token = build_client(tmp_path)
    with client.websocket_connect(f"/v1/ws?token={token}") as websocket:
        hello = websocket.receive_json()
        assert hello["event"] == "hello"
        websocket.send_json({"action": "subscribe", "topics": ["status"]})
        snapshot = websocket.receive_json()
        assert snapshot["event"] == "snapshot"
        assert snapshot["topic"] == "status"


def test_websocket_catalog_snapshot_redacts_users_without_sensitive_scopes(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(
        label="catalog-ws",
        scopes=[Scope.CATALOG_READ.value, Scope.USERS_READ.value],
    )
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    client = TestClient(app)

    with client.websocket_connect(f"/v1/ws?token={token}") as websocket:
        websocket.receive_json()
        websocket.send_json({"action": "subscribe", "topics": ["catalog"]})
        snapshot = websocket.receive_json()
        assert snapshot["event"] == "snapshot"
        assert snapshot["topic"] == "catalog"
        assert snapshot["payload"]["users"][0]["code"] == ""


def test_connection_manager_close_all_closes_connected_websockets() -> None:
    manager = ConnectionManager()
    websocket_a = AsyncMock()
    websocket_b = AsyncMock()

    async def _exercise() -> None:
        await manager.connect(websocket_a)
        await manager.connect(websocket_b)
        await manager.subscribe(websocket_a, ["status"])
        await manager.close_all(code=1001, reason="server shutdown")

    asyncio.run(_exercise())

    websocket_a.close.assert_awaited_once_with(code=1001, reason="server shutdown")
    websocket_b.close.assert_awaited_once_with(code=1001, reason="server shutdown")
    assert manager._connections == {}


def test_legacy_scope_migration_rewrites_old_token_names(tmp_path: Path) -> None:
    """Tokens minted with pre-v1 scope names (status:read, sections:control)
    should be transparently rewritten on next TokenStore startup."""

    import json
    import sqlite3
    import secrets

    db_path = tmp_path / "tokens.db"
    # First initialize the schema by constructing a store, then close.
    TokenStore(db_path)

    # Insert a token with legacy scopes directly, simulating a pre-v1 token.
    legacy_scopes = ["status:read", "sections:control", "codes:impersonate"]
    raw_token = secrets.token_urlsafe(16)
    from jablotron_api.services.storage import token_hash

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO tokens (
                id, label, token_hash, scopes_json, certificate_fingerprint,
                allowed_user_ids_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy01",
                "legacy",
                token_hash(raw_token),
                json.dumps(legacy_scopes),
                None,
                "[]",
                "2026-01-01T00:00:00+00:00",
            ),
        )
        conn.commit()
    finally:
        conn.close()

    # Re-open the store; migration should run during __init__.
    store = TokenStore(db_path)
    token = store.authenticate(raw_token)
    assert token is not None
    assert set(token.scopes) == {
        "sections:read",
        "pgs:read",
        "devices:read",
        "sections:arm",
        "sections:disarm",
        "codes:impersonate",
    }
