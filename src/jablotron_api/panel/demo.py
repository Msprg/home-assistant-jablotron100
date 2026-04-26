"""Demo panel runtime for local validation without panel hardware."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Awaitable, Callable

from jablotron_api.domain.models import (
    ArmMode,
    BusStatusModel,
    CentralStatusModel,
    DeviceStatusModel,
    EventRecordModel,
    ExportCatalogModel,
    ExportPGModel,
    ExportSectionModel,
    InitialSetupModel,
    InitialSetupRangeModel,
    PanelStatusModel,
    PGStatusModel,
    RawCatalogCountsModel,
    SectionStatusModel,
    UserCreateModel,
    UserModel,
    UserPatchModel,
)


StatusListener = Callable[[str, dict], Awaitable[None]]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DemoPanelRuntime:
    """In-memory runtime that mirrors the live runtime surface."""

    def __init__(self) -> None:
        self._listeners: list[StatusListener] = []
        self._system_info: dict[str, str | None] = {
            "panel_model": "JA-107K Demo",
            "panel_hardware_version": "DEMO-HW-1",
            "panel_firmware_version": "DEMO-FW-1",
            "panel_unique_id": "jablotron-demo-panel",
        }
        self._catalog = ExportCatalogModel(
            sections=[
                ExportSectionModel(id=1, display_id=1, name="Ground Floor"),
                ExportSectionModel(id=2, display_id=2, name="Warehouse"),
            ],
            pgs=[
                ExportPGModel(id=1, display_id=1, name="Gate Relay", section_id=1),
                ExportPGModel(id=2, display_id=2, name="Irrigation", section_id=2),
            ],
            devices=[
                DeviceStatusModel(
                    id=2,
                    name="Reception PIR",
                    section_id=1,
                    type_raw=0,
                    hardware_model="JA-110P",
                    inferred_device_type="motion_detector",
                    inferred_entity_type="device_state_motion",
                    comment="Demo motion detector",
                ),
                DeviceStatusModel(
                    id=3,
                    name="Front Door Contact",
                    section_id=1,
                    hardware_model="JA-111M",
                    inferred_device_type="window_opening_detector",
                    inferred_entity_type="device_state_window",
                    comment="Demo magnetic contact",
                ),
                DeviceStatusModel(
                    id=4,
                    name="Boiler Room Flood",
                    section_id=2,
                    type_raw=45,
                    hardware_model="JA-110F",
                    inferred_device_type="flood_detector",
                    inferred_entity_type="device_state_moisture",
                    comment="Demo flood sensor",
                ),
            ],
            users=[
                UserModel(id=1, name="Installer", rights="admin"),
                UserModel(id=2, name="Guard", rights="setUnset"),
            ],
            initial_setup=InitialSetupModel(
                source="demo",
                exact=True,
                sections=InitialSetupRangeModel(first_id=1, last_id=2, count=2),
                devices=InitialSetupRangeModel(first_id=1, last_id=4, count=4),
                users=InitialSetupRangeModel(first_id=1, last_id=2, count=2),
                pgs=InitialSetupRangeModel(first_id=1, last_id=2, count=2),
            ),
            raw_counts=RawCatalogCountsModel(sections=2, devices=3, users=2, pgs=2),
            sha256="demo-catalog",
            path="/demo/EXPORT.CFG",
        )
        self._status = PanelStatusModel(
            sections=[
                SectionStatusModel(id=1, name="Ground Floor", state="disarmed"),
                SectionStatusModel(id=2, name="Warehouse", state="armed_night"),
            ],
            pgs=[
                PGStatusModel(id=1, name="Gate Relay", state="off"),
                PGStatusModel(id=2, name="Irrigation", state="on"),
            ],
            devices=[
                DeviceStatusModel(
                    id=2,
                    name="Reception PIR",
                    section_id=1,
                    hardware_model="JA-110P",
                    inferred_device_type="motion_detector",
                    inferred_entity_type="device_state_motion",
                    state="off",
                    signal_strength=72,
                    battery_level=88,
                    battery_problem=False,
                    wireless=True,
                ),
                DeviceStatusModel(
                    id=3,
                    name="Front Door Contact",
                    section_id=1,
                    hardware_model="JA-111M",
                    inferred_device_type="window_opening_detector",
                    inferred_entity_type="device_state_window",
                    state="off",
                    signal_strength=64,
                    battery_level=91,
                    battery_problem=False,
                    wireless=True,
                ),
                DeviceStatusModel(
                    id=4,
                    name="Boiler Room Flood",
                    section_id=2,
                    hardware_model="JA-110F",
                    inferred_device_type="flood_detector",
                    inferred_entity_type="device_state_moisture",
                    state="off",
                    signal_strength=59,
                    battery_level=84,
                    battery_problem=False,
                    wireless=True,
                ),
            ],
            central=CentralStatusModel(
                power_supply=True,
                battery_level=96,
                battery_problem=False,
                battery_standby_voltage=13.8,
                battery_load_voltage=13.4,
                lan_connection=True,
                lan_ip="192.168.1.50",
                gsm_signal=True,
                gsm_signal_strength=82,
                buses=[BusStatusModel(bus_number=1, voltage=13.9, devices_loss_count=0)],
            ),
            service_mode=False,
            source="demo",
        )
        self._events = [
            EventRecordModel(timestamp=_utc_now(), kind="EVENT", text="Demo runtime started", source="demo"),
            EventRecordModel(timestamp=_utc_now(), kind="EVENT", text="Warehouse armed in night mode", source="demo", section="2"),
        ]

    def _ensure_usable_section_id(self, section_id: int) -> None:
        section_range = self._catalog.initial_setup.sections if self._catalog.initial_setup is not None else None
        if section_range is None:
            return
        if not section_range.first_id <= section_id <= section_range.last_id:
            raise ValueError(
                f"Section {section_id} is outside the client-facing usable range "
                f"{section_range.first_id}-{section_range.last_id}."
            )

    def _ensure_usable_pg_id(self, pg_id: int) -> None:
        pg_range = self._catalog.initial_setup.pgs if self._catalog.initial_setup is not None else None
        if pg_range is None:
            return
        if not pg_range.first_id <= pg_id <= pg_range.last_id:
            raise ValueError(
                f"PG {pg_id} is outside the client-facing usable range "
                f"{pg_range.first_id}-{pg_range.last_id}."
            )

    def _ensure_usable_user_id(self, user_id: int) -> None:
        user_range = self._catalog.initial_setup.users if self._catalog.initial_setup is not None else None
        if user_range is None:
            return
        if not user_range.first_id <= user_id <= user_range.last_id:
            raise ValueError(
                f"User {user_id} is outside the client-facing usable range "
                f"{user_range.first_id}-{user_range.last_id}."
            )

    async def start(self) -> None:
        await self._emit("system", dict(self._system_info))
        await self._emit("catalog", self._catalog.model_dump(mode="json"))
        await self._emit("status", self._status.model_dump(mode="json"))

    async def close(self) -> None:
        return None

    def add_listener(self, listener: StatusListener) -> None:
        self._listeners.append(listener)

    async def _emit(self, topic: str, payload: dict) -> None:
        for listener in list(self._listeners):
            await listener(topic, payload)

    async def refresh_all(self) -> None:
        await self.refresh_system()
        await self.refresh_catalog()
        await self.refresh_status()

    async def refresh_system(self) -> dict[str, str | None]:
        await self._emit("system", dict(self._system_info))
        return dict(self._system_info)

    async def refresh_status(self) -> PanelStatusModel:
        self._status.refreshed_at = datetime.now(timezone.utc)
        await self._emit("status", self._status.model_dump(mode="json"))
        return self._status

    async def refresh_catalog(self) -> ExportCatalogModel:
        await self._emit("catalog", self._catalog.model_dump(mode="json"))
        return self._catalog

    async def get_status(self) -> PanelStatusModel:
        return self._status

    async def get_catalog(self) -> ExportCatalogModel:
        return self._catalog

    async def get_users(self) -> list[UserModel]:
        user_range = self._catalog.initial_setup.users if self._catalog.initial_setup is not None else None
        if user_range is None:
            return self._catalog.users
        return [user for user in self._catalog.users if user_range.first_id <= user.id <= user_range.last_id]

    async def get_user(self, user_id: int) -> UserModel | None:
        for user in self._catalog.users:
            if user.id == user_id:
                return user
        return None

    async def get_events_recent(
        self,
        *,
        limit: int = 20,
        include_raw: bool = False,
        kinds: str | None = None,
        exclude_kinds: str | None = None,
    ) -> list[EventRecordModel]:
        del include_raw, kinds, exclude_kinds
        return self._events[:limit]

    async def get_export_users(self) -> list[UserModel]:
        return await self.get_users()

    async def get_export_time_limits(self) -> list[dict[str, object]]:
        return [
            {
                "group_id": 0,
                "group_display_id": 1,
                "comment": "Weekday office",
                "days": [
                    {
                        "day_index": 0,
                        "day_name": "Monday",
                        "section_rules": [{"section_id": 1, "windows": [{"on": "08:00", "off": "18:00"}]}],
                    }
                ],
            }
        ]

    async def get_export_communications(self) -> dict[str, object]:
        return {
            "communications": {
                "service_enabled": True,
                "sms_enabled": True,
                "calls_enabled": False,
                "arc_enabled": False,
                "service_phone": "+421900000000",
                "service_phone_enabled": True,
                "sms_report_numbers": ["+421900000001"],
                "call_report_numbers": [],
                "sdc": None,
            }
        }

    async def arm_section(self, section_id: int, mode: ArmMode, code: str | None = None) -> PanelStatusModel:
        del code
        self._ensure_usable_section_id(section_id)
        for section in self._status.sections:
            if section.id == section_id:
                section.state = {
                    ArmMode.AWAY: "armed_away",
                    ArmMode.HOME: "armed_home",
                    ArmMode.NIGHT: "armed_night",
                }[mode]
                break
        self._events.insert(0, EventRecordModel(timestamp=_utc_now(), kind="EVENT", text=f"Section {section_id} armed {mode.value}", source="demo", section=str(section_id)))
        return await self.refresh_status()

    async def disarm_section(self, section_id: int, code: str | None = None) -> PanelStatusModel:
        del code
        self._ensure_usable_section_id(section_id)
        for section in self._status.sections:
            if section.id == section_id:
                section.state = "disarmed"
                break
        self._events.insert(0, EventRecordModel(timestamp=_utc_now(), kind="EVENT", text=f"Section {section_id} disarmed", source="demo", section=str(section_id)))
        return await self.refresh_status()

    async def set_pg(
        self,
        pg_id: int,
        enabled: bool,
        code: str | None = None,
        *,
        allowed_user_ids: list[int] | None = None,
    ) -> PanelStatusModel:
        del code, allowed_user_ids
        self._ensure_usable_pg_id(pg_id)
        for pg in self._status.pgs:
            if pg.id == pg_id:
                pg.state = "on" if enabled else "off"
                break
        self._events.insert(0, EventRecordModel(timestamp=_utc_now(), kind="EVENT", text=f"PG {pg_id} set {'on' if enabled else 'off'}", source="demo"))
        return await self.refresh_status()

    async def add_user(self, payload: UserCreateModel) -> UserModel:
        self._ensure_usable_user_id(payload.id)
        user = UserModel(
            id=payload.id,
            name=payload.name,
            phone=payload.phone,
            code=payload.code,
            cards=[payload.card1] if payload.card1 else [],
            comment=payload.comment,
            flags_raw=payload.flags_raw,
            access_raw=payload.access_raw,
            section_ids=list(payload.sections),
            pg_ids=list(payload.pgs),
            rights="coUserNoSelfedit",
            time_limited_group_raw=payload.time_limited_group_raw,
        )
        self._catalog.users.append(user)
        await self._emit("users", {"action": "added", "user": user.model_dump(mode="json")})
        return user

    async def edit_user(self, user_id: int, payload: UserPatchModel) -> UserModel:
        self._ensure_usable_user_id(user_id)
        user = await self.get_user(user_id)
        if user is None:
            raise RuntimeError(f"User {user_id} not found.")
        for field, value in payload.model_dump(exclude_unset=True).items():
            if field == "card1":
                user.cards = [value] if value else []
            elif field == "sections":
                user.section_ids = list(value or [])
            elif field == "pgs":
                user.pg_ids = list(value or [])
            else:
                setattr(user, field, value)
        await self._emit("users", {"action": "edited", "user": user.model_dump(mode="json")})
        return user

    async def delete_user(self, user_id: int) -> None:
        self._ensure_usable_user_id(user_id)
        self._catalog.users = [user for user in self._catalog.users if user.id != user_id]
        await self._emit("users", {"action": "deleted", "user_id": user_id})

    @property
    def system_info(self) -> dict[str, str | None]:
        return dict(self._system_info)
