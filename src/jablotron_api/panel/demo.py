"""Demo panel runtime for local validation without panel hardware."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Awaitable, Callable, Sequence

from jablotron_api.domain.codes import CodeFormat, resolve_code_format
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
    UserBatchCreate,
    UserBatchResponse,
    UserBatchResult,
    UserBatchWrite,
    UserCreateModel,
    UserModel,
    UserPatchModel,
)
from jablotron_api.domain.user_validation import (
    UserSlotOccupied,
    UserTableEntry,
    entry_from_record,
    validate_user_write,
)
from jablotron_api.services.catalog_io import ensure_id_in_range
from jablotron_api.services.user_batch import BatchTarget, check_batch_shape, validate_batch, write_id

LOGGER = logging.getLogger(__name__)


StatusListener = Callable[[str, dict], Awaitable[None]]


def _utc_now() -> str:
    return _utc_now_dt().isoformat()


def _utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _comparable(user: UserModel) -> dict:
    """A user as the panel would compare it: section and PG ids as sets."""

    dumped = user.model_dump()
    dumped["section_ids"] = sorted(dumped["section_ids"])
    dumped["pg_ids"] = sorted(dumped["pg_ids"])
    return dumped


class DemoPanelRuntime:
    """In-memory runtime that mirrors the live runtime surface."""

    def __init__(self, *, batch_max_records: int = 3) -> None:
        self._batch_max_records = batch_max_records
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
                # Ten user slots with two populated, so a provisioning client
                # can exercise creates without first deleting a demo user
                # now that a create onto an occupied slot is refused.
                users=InitialSetupRangeModel(first_id=1, last_id=10, count=10),
                pgs=InitialSetupRangeModel(first_id=1, last_id=2, count=2),
                # The demo panel declares a code format so that user writes
                # face the same code rules here as on a real panel.
                code_length=4,
                code_prefix=False,
            ),
            raw_counts=RawCatalogCountsModel(sections=2, devices=3, users=10, pgs=2),
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

    def code_format(self) -> CodeFormat:
        initial = self._catalog.initial_setup
        return resolve_code_format(
            catalog_code_length=initial.code_length if initial is not None else None,
            catalog_code_prefix=initial.code_prefix if initial is not None else None,
            server_auth_code=None,
        )

    def _ensure_usable_section_id(self, section_id: int) -> None:
        ensure_id_in_range(self._catalog.initial_setup, kind="Section", attr="sections", value=section_id)

    def _ensure_usable_pg_id(self, pg_id: int) -> None:
        ensure_id_in_range(self._catalog.initial_setup, kind="PG", attr="pgs", value=pg_id)

    def _ensure_usable_user_id(self, user_id: int) -> None:
        ensure_id_in_range(self._catalog.initial_setup, kind="User", attr="users", value=user_id)

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

    async def get_catalog(self, max_age_seconds: float | None = None) -> ExportCatalogModel:
        # The demo panel is in memory, so it is always current and no
        # configuration mode is ever entered: the freshness fields say so
        # honestly rather than echoing the live runtime's values.
        del max_age_seconds
        return self._catalog.model_copy(
            update={"as_of": _utc_now_dt(), "source": "panel", "trigger_used": False}
        )

    async def get_users(self, max_age_seconds: float | None = None) -> list[UserModel]:
        del max_age_seconds
        user_range = self._catalog.initial_setup.users if self._catalog.initial_setup is not None else None
        if user_range is None:
            return self._catalog.users
        return [user for user in self._catalog.users if user_range.first_id <= user.id <= user_range.last_id]

    async def get_user(
        self, user_id: int, max_age_seconds: float | None = None
    ) -> UserModel | None:
        del max_age_seconds
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

    async def get_export_users(self, max_age_seconds: float | None = None) -> list[UserModel]:
        return await self.get_users(max_age_seconds)

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

    async def arm_section(
        self,
        section_id: int,
        mode: ArmMode,
        code: str | None = None,
    ) -> PanelStatusModel:
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

    async def disarm_section(
        self,
        section_id: int,
        code: str | None = None,
    ) -> PanelStatusModel:
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
    ) -> PanelStatusModel:
        del code
        self._ensure_usable_pg_id(pg_id)
        for pg in self._status.pgs:
            if pg.id == pg_id:
                pg.state = "on" if enabled else "off"
                break
        self._events.insert(0, EventRecordModel(timestamp=_utc_now(), kind="EVENT", text=f"PG {pg_id} set {'on' if enabled else 'off'}", source="demo"))
        return await self.refresh_status()

    def _validate_user_write(
        self,
        user_id: int,
        *,
        code: str,
        cards: tuple[str, ...],
        time_limited_group_raw: int | None,
        include_current: bool,
        name: str = "",
        comment: str = "",
    ) -> None:
        """Apply the shared user-table rules to the in-memory table.

        The demo runtime is what provisioning clients develop against, so it
        refuses the same records the live runtime refuses — a client should
        not first meet these rules on a real alarm panel.
        """

        existing = [entry_from_record(user) for user in self._catalog.users]
        current = None
        if include_current:
            current = next((entry for entry in existing if entry.user_id == user_id), None)
        warnings = validate_user_write(
            existing=existing,
            user_id=user_id,
            current=current,
            target=UserTableEntry(
                user_id=user_id,
                code=code,
                cards=cards,
                time_limited_group_raw=time_limited_group_raw,
                name=name,
                comment=comment,
            ),
            code_format=self.code_format(),
        )
        for message in warnings:
            LOGGER.warning("User %s write preflight warning: %s", user_id, message)

    async def add_user(self, payload: UserCreateModel, *, replace: bool = False) -> UserModel:
        self._ensure_usable_user_id(payload.id)
        occupant = await self.get_user(payload.id)
        if occupant is not None and occupant.name.strip() and not replace:
            raise UserSlotOccupied(payload.id)
        self._validate_user_write(
            payload.id,
            code=payload.code,
            cards=(payload.card1,) if payload.card1 else (),
            time_limited_group_raw=payload.time_limited_group_raw,
            include_current=False,
            name=payload.name,
            comment=payload.comment,
        )
        if occupant is not None:
            self._catalog.users = [user for user in self._catalog.users if user.id != payload.id]
        user = self._created_user(payload)
        self._catalog.users.append(user)
        await self._emit("users", {"action": "added", "user": user.model_dump(mode="json")})
        return user

    async def edit_user(self, user_id: int, payload: UserPatchModel) -> UserModel:
        self._ensure_usable_user_id(user_id)
        user = await self.get_user(user_id)
        if user is None:
            raise RuntimeError(f"User {user_id} not found.")
        requested = payload.model_dump(exclude_unset=True)
        self._validate_user_write(
            user_id,
            code=requested.get("code", user.code) or "",
            cards=(
                ((requested["card1"],) if requested["card1"] else ())
                if "card1" in requested
                else tuple(user.cards)
            ),
            time_limited_group_raw=requested.get(
                "time_limited_group_raw", user.time_limited_group_raw
            ),
            include_current=True,
            name=requested.get("name", user.name) or "",
            comment=requested.get("comment", user.comment) or "",
        )
        before = user.model_dump()
        for field, value in requested.items():
            if field == "card1":
                user.cards = [value] if value else []
            elif field == "sections":
                user.section_ids = list(value or [])
            elif field == "pgs":
                user.pg_ids = list(value or [])
            else:
                setattr(user, field, value)
        if user.model_dump() == before:
            # As on the panel: an edit that changes nothing is no write.
            return user
        await self._emit("users", {"action": "edited", "user": user.model_dump(mode="json")})
        return user

    async def delete_user(self, user_id: int) -> None:
        self._ensure_usable_user_id(user_id)
        occupant = await self.get_user(user_id)
        if occupant is None or not occupant.name.strip():
            # As on the panel: nothing to delete is no write and no event.
            return
        self._catalog.users = [user for user in self._catalog.users if user.id != user_id]
        await self._emit("users", {"action": "deleted", "user_id": user_id})

    async def batch_users(self, writes: Sequence[UserBatchWrite]) -> UserBatchResponse:
        """The live runtime's batch on the in-memory table: the same shape
        checks, slot refusals and joint rules, then every record applied at
        once. A create is stored as add_user stores it and an update applied
        as edit_user applies it; an update that changes nothing gets no
        event. The demo encodes no records, so it never answers
        payload_too_large."""

        check_batch_shape(writes, max_records=self._batch_max_records)
        for write in writes:
            self._ensure_usable_user_id(write_id(write))
        currents: dict[int, UserModel | None] = {}
        for write in writes:
            user_id = write_id(write)
            currents[user_id] = occupant = await self.get_user(user_id)
            if isinstance(write, UserBatchCreate):
                if occupant is not None and occupant.name.strip() and not write.replace:
                    raise UserSlotOccupied(user_id, batch=True)
            elif occupant is None or not occupant.name.strip():
                raise RuntimeError(f"User {user_id} not found.")

        planned: list[tuple[str, int, UserModel, bool]] = []
        targets: list[BatchTarget] = []
        for write in writes:
            user_id = write_id(write)
            current = currents[user_id]
            if isinstance(write, UserBatchCreate):
                op, updated, current_entry = "create", self._created_user(write.user), None
            else:
                op = "update"
                updated = current.model_copy(deep=True)
                # As on the panel: a null is not sent, and the decoded section
                # and PG ids come back sorted.
                for field, value in write.patch.model_dump(exclude_unset=True).items():
                    if value is None:
                        continue
                    if field == "card1":
                        updated.cards = [value] if value else []
                    elif field == "sections":
                        updated.section_ids = sorted(value)
                    elif field == "pgs":
                        updated.pg_ids = sorted(value)
                    else:
                        setattr(updated, field, value)
                current_entry = entry_from_record(current)
                if _comparable(updated) == _comparable(current):
                    planned.append((op, user_id, current, True))
                    continue
            targets.append(BatchTarget(user_id, current_entry, entry_from_record(updated)))
            planned.append((op, user_id, updated, False))
        validate_batch(
            [entry_from_record(user) for user in self._catalog.users], targets, self.code_format()
        )

        slots = {user.id: index for index, user in enumerate(self._catalog.users)}
        for _, user_id, user, noop in planned:
            if noop:
                continue
            if user_id in slots:
                self._catalog.users[slots[user_id]] = user
            else:
                self._catalog.users.append(user)
        results = []
        for op, user_id, user, noop in planned:
            if not noop:
                action = "added" if op == "create" else "edited"
                await self._emit("users", {"action": action, "user": user.model_dump(mode="json")})
            results.append(UserBatchResult(id=user_id, op=op, verified=True, user=user))
        return UserBatchResponse(results=results, as_of=_utc_now_dt(), pull_started_after_request=None)

    @staticmethod
    def _created_user(payload: UserCreateModel) -> UserModel:
        return UserModel(
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

    @property
    def system_info(self) -> dict[str, str | None]:
        return dict(self._system_info)
