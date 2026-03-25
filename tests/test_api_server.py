from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import Request
from fastapi.testclient import TestClient

from jablotron_api.domain.models import (
    CentralStatusModel,
    DEFAULT_ADMIN_SCOPES,
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
from jablotron_api.panel.runtime import PanelRuntime, PanelRuntimeConfig
from jablotron_api.panel.runtime import _apply_catalog_names
from jablotron_api.protocol import legacy
from jablotron_api.protocol.legacy import LegacyPanelSnapshot, PersistentSnapshotSession
from jablotron_api.server.app import create_app
from jablotron_api.server.config import ServerSettings
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
            users=[UserModel(id=80, name="User 80", rights="coUserNoSelfedit")],
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

    async def arm_section(self, section_id, mode, code=None):
        if section_id != 1:
            raise ValueError("Section 2 is outside the client-facing usable range 1-1.")
        self.last_arm_code = code
        self.status.sections[0].state = "armed_away"
        for listener in self._listeners:
            await listener("status", self.status.model_dump(mode="json"))
        return self.status

    async def disarm_section(self, section_id, code=None):
        if section_id != 1:
            raise ValueError("Section 2 is outside the client-facing usable range 1-1.")
        self.last_disarm_code = code
        self.status.sections[0].state = "disarmed"
        return self.status

    async def set_pg(self, pg_id, enabled, code=None):
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

    import asyncio

    asyncio.run(run())

    assert len(calls) == 2
    assert calls[0]["query_device_status"] is True
    assert calls[0]["timeout"] == 2.0
    assert calls[1]["query_device_status"] is False
    assert calls[1]["timeout"] == 0.6


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
    monkeypatch.setattr(legacy.time, "sleep", lambda _: None)

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
    readonly_token, readonly_info = store.create_token(label="readonly", scopes=[Scope.STATUS_READ.value, Scope.SYSTEM_READ.value])
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

    matching_fingerprint = client.get(
        "/v1/system",
        headers={
            "Authorization": f"Bearer {cert_token}",
            "X-Client-Cert-Fingerprint": "demo-fingerprint",
        },
    )
    assert matching_fingerprint.status_code == 200


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

    bad_pg = client.post("/v1/pgs/2/on", headers={"Authorization": f"Bearer {token}"})
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
