"""Single-owner panel runtime built on top of the existing reverse-engineering helpers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
import time
from types import SimpleNamespace
from typing import Awaitable, Callable
import unicodedata

from export_cfg_tool import render_readable_export_report
from jablotron_event_tool import (
    build_decoded_records,
    parse_kind_filter,
    pull_live_archive,
    resolve_decoder_catalog,
    select_display_records,
    split_crlf_records,
)
from jablotron_re_tools import (
    DEFAULT_IMPORT_PATH,
    ExportCatalogSnapshot,
    ExportSnapshot,
    UserRecord,
    apply_import_sector,
    default_export_output,
    extract_export_catalog,
    extract_users,
    pull_live_export_snapshot,
)
from jablotron_user_tool import build_delete_sector, build_upsert_sector

from jablotron_api.domain.models import (
    ArmMode,
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
from jablotron_api.protocol.legacy import (
    PersistentSnapshotSession,
)


StatusListener = Callable[[str, dict], Awaitable[None]]

SYSTEM_OBJECT_IDS = {0, 233, 234, 235, 237}


@dataclass
class PanelRuntimeConfig:
    port: str = "auto"
    auth_code: str = "1812"
    flexi_cfg_device: str = "auto"
    flexi_log_device: str = "auto"
    import_path: Path = DEFAULT_IMPORT_PATH
    mount_tool: str = "sudo"
    stage_mode: str = "filesystem"
    read_cleanup_mode: str = "auto"
    write_cleanup_mode: str = "auto"
    poll_interval_seconds: float = 15.0
    reset: bool = True


def _user_to_model(record: UserRecord) -> UserModel:
    return UserModel(
        id=record.user_id or 0,
        name=record.name,
        phone=record.phone,
        code=record.code,
        cards=[card for card in record.cards if card],
        comment=record.comment,
        flags_raw=record.flags_raw,
        access_raw=record.access_raw,
        section_ids=list(record.section_ids),
        pg_ids=list(record.pg_ids),
        enabled=record.enabled,
        rights=record.rights,
        time_limited_group_raw=record.time_limited_group_raw,
    )


def _infer_device_type(*, name: str, hardware_model: str | None, type_raw: int | None, object_id: int) -> tuple[str | None, str | None]:
    hardware = (hardware_model or "").upper()
    lowered_name = name.lower()

    if object_id in {0, 233, 234, 235, 237}:
        return None, None
    if hardware.startswith("JA-110P"):
        return "motion_detector", "device_state_motion"
    if hardware.startswith("JA-111M"):
        return "window_opening_detector", "device_state_window"
    if hardware.startswith("JA-110ST"):
        return "smoke_detector", "device_state_smoke"
    if hardware.startswith("JA-110F"):
        return "flood_detector", "device_state_moisture"
    if hardware.startswith("JA-110A") or hardware.startswith("JA-111A"):
        return "indoor_siren", "device_state_indoor_siren_button"
    if hardware.startswith("JA-111TH"):
        return "thermometer", None
    if hardware.startswith("JA-110TP") or hardware.startswith("JA-150TP"):
        return "thermostat", None
    if hardware.startswith("JA-154J"):
        return "key_fob", "device_state_button"
    if hardware.startswith("JA-111R"):
        return "radio_module", None
    if hardware.startswith("JA-11") and hardware.endswith("E"):
        return "keypad", None
    if "sirena" in lowered_name or "siren" in lowered_name:
        return "indoor_siren", "device_state_indoor_siren_button"
    if "elektrom" in lowered_name or "meter" in lowered_name:
        return "electricity_meter_with_pulse_output", None
    if "dym" in lowered_name:
        return "smoke_detector", "device_state_smoke"
    if "plyn" in lowered_name:
        return "gas_detector", "device_state_gas"
    if "zapl" in lowered_name:
        return "flood_detector", "device_state_moisture"
    if "teplomer" in lowered_name:
        return "thermometer", None
    if "termostat" in lowered_name:
        return "thermostat", None
    if "magnet" in lowered_name or "okno" in lowered_name:
        return "window_opening_detector", "device_state_window"
    if "vstup" in lowered_name or "branka" in lowered_name:
        return "door_opening_detector", "device_state_door"
    if type_raw == 45:
        return "flood_detector", "device_state_moisture"
    if type_raw == 3:
        return "smoke_detector", "device_state_smoke"
    if type_raw in {0, 1}:
        return "motion_detector", "device_state_motion"
    return "custom", "device_state_custom"


def _normalized_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value or "")
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    return " ".join(ascii_only.lower().split())


def _is_default_section_name(name: str, display_id: int) -> bool:
    normalized = _normalized_name(name)
    return normalized in {f"section {display_id}", f"sekcia {display_id + 1}"}


def _is_default_pg_name(name: str, display_id: int) -> bool:
    normalized = _normalized_name(name)
    return normalized in {f"pg output {display_id}", f"pg vystup {display_id}"}


def _tail_default_cutoff(names: list[tuple[int, str]], *, is_default: Callable[[str, int], bool], minimum_suffix: int = 8) -> int | None:
    if len(names) < minimum_suffix:
        return None
    for index, (display_id, name) in enumerate(names):
        suffix = names[index:]
        if len(suffix) < minimum_suffix:
            break
        if is_default(name, display_id) and all(is_default(item_name, item_display_id) for item_display_id, item_name in suffix):
            return index
    return None


def _make_range(*, first_id: int, last_id: int) -> InitialSetupRangeModel | None:
    if last_id < first_id:
        return None
    return InitialSetupRangeModel(first_id=first_id, last_id=last_id, count=(last_id - first_id) + 1)


def _build_initial_setup(snapshot: ExportCatalogSnapshot) -> InitialSetupModel | None:
    if snapshot.main_config is not None:
        main = snapshot.main_config
        notes: list[str] = []
        if main.rfid_restrict is not None:
            notes.append("EM Unique card support is not mapped exactly yet; raw rfid_restrict is kept in the reverse-engineering parser.")
        return InitialSetupModel(
            source="export_main_config",
            exact=True,
            sections=_make_range(first_id=1, last_id=main.sections_raw or 0),
            devices=_make_range(first_id=1, last_id=main.peripheries_raw or 0),
            users=_make_range(first_id=1, last_id=main.users_raw or 0),
            pgs=_make_range(first_id=1, last_id=main.pgs_raw or 0),
            system_name=main.name or None,
            language=main.language_id or None,
            code_length=main.code_len_raw,
            code_prefix=main.code_prefix,
            em_unique_enabled=None,
            notes=notes,
        )

    non_system_objects = [device for device in snapshot.objects_by_id.values() if device.object_id not in SYSTEM_OBJECT_IDS and device.object_id < 233]
    section_count = 0
    if non_system_objects:
        section_count = max((device.section_id or 0) for device in non_system_objects) + 1
    if section_count <= 0:
        section_cutoff = _tail_default_cutoff(
            [(section.display_id, section.name) for section in sorted(snapshot.sections_by_id.values(), key=lambda item: item.display_id)],
            is_default=_is_default_section_name,
            minimum_suffix=4,
        )
        section_count = len(snapshot.sections_by_id) if section_cutoff is None else section_cutoff + 1

    device_ids = sorted(device.object_id for device in non_system_objects if device.object_id > 0)
    device_last_id = 0
    for expected_id, object_id in enumerate(device_ids, start=1):
        if object_id != expected_id:
            break
        device_last_id = object_id
    if device_last_id == 0 and device_ids:
        device_last_id = max(device_ids)

    regular_user_ids = sorted(user.user_id for user in snapshot.users if user.user_id is not None and 1 <= user.user_id < 0x200)
    user_last_id = max(regular_user_ids, default=0)

    pg_cutoff = _tail_default_cutoff(
        [(pg.display_id, pg.name) for pg in sorted(snapshot.pgs_by_id.values(), key=lambda item: item.display_id)],
        is_default=_is_default_pg_name,
        minimum_suffix=8,
    )
    pg_last_id = len(snapshot.pgs_by_id) if pg_cutoff is None else pg_cutoff

    notes = [
        "Initial setup was inferred from catalog structure because this export variant does not currently populate main_config.",
        "Raw export endpoints remain unrestricted; client-facing status/control surfaces use these inferred usable ranges.",
    ]
    return InitialSetupModel(
        source="inferred_catalog",
        exact=False,
        sections=_make_range(first_id=1, last_id=section_count),
        devices=_make_range(first_id=1, last_id=device_last_id),
        users=_make_range(first_id=1, last_id=user_last_id),
        pgs=_make_range(first_id=1, last_id=pg_last_id),
        notes=notes,
    )


def _filter_sections_for_clients(sections: list[SectionStatusModel], initial_setup: InitialSetupModel | None) -> list[SectionStatusModel]:
    section_range = None if initial_setup is None else initial_setup.sections
    if section_range is None:
        return sections
    return [section for section in sections if section_range.first_id <= section.id <= section_range.last_id]


def _filter_pgs_for_clients(pgs: list[PGStatusModel], initial_setup: InitialSetupModel | None) -> list[PGStatusModel]:
    pg_range = None if initial_setup is None else initial_setup.pgs
    if pg_range is None:
        return pgs
    return [pg for pg in pgs if pg_range.first_id <= pg.id <= pg_range.last_id]


def _filter_devices_for_clients(devices: list[DeviceStatusModel], initial_setup: InitialSetupModel | None) -> list[DeviceStatusModel]:
    device_range = None if initial_setup is None else initial_setup.devices
    if device_range is None:
        return devices
    return [device for device in devices if device_range.first_id <= device.id <= device_range.last_id]


def _filter_users_for_clients(users: list[UserModel], initial_setup: InitialSetupModel | None) -> list[UserModel]:
    user_range = None if initial_setup is None else initial_setup.users
    if user_range is None:
        return users
    return [user for user in users if user_range.first_id <= user.id <= user_range.last_id]


def _catalog_to_model(snapshot: ExportCatalogSnapshot) -> ExportCatalogModel:
    initial_setup = _build_initial_setup(snapshot)
    return ExportCatalogModel(
        sections=[
            ExportSectionModel(
                id=section.section_id,
                display_id=section.display_id,
                name=section.name or f"Section {section.display_id}",
                comment=section.comment,
            )
            for section in snapshot.sections_by_id.values()
        ],
        pgs=[
            ExportPGModel(
                id=pg.pg_id,
                display_id=pg.display_id,
                name=pg.name or f"PG output {pg.display_id}",
                comment=pg.comment,
                section_id=pg.section_id,
            )
            for pg in snapshot.pgs_by_id.values()
        ],
        devices=[
            DeviceStatusModel(
                id=device.object_id,
                name=device.name or f"Object {device.object_id}",
                kind=str(device.kind_raw) if device.kind_raw is not None else None,
                section_id=device.section_id,
                type_raw=device.type_raw,
                subtype_raw=device.subtype_raw,
                hardware_model=snapshot.hardware_by_id.get(device.object_id).model if device.object_id in snapshot.hardware_by_id else None,
                inferred_device_type=_infer_device_type(
                    name=device.name or f"Object {device.object_id}",
                    hardware_model=snapshot.hardware_by_id.get(device.object_id).model if device.object_id in snapshot.hardware_by_id else None,
                    type_raw=device.type_raw,
                    object_id=device.object_id,
                )[0],
                inferred_entity_type=_infer_device_type(
                    name=device.name or f"Object {device.object_id}",
                    hardware_model=snapshot.hardware_by_id.get(device.object_id).model if device.object_id in snapshot.hardware_by_id else None,
                    type_raw=device.type_raw,
                    object_id=device.object_id,
                )[1],
                comment=device.comment,
            )
            for device in snapshot.objects_by_id.values()
        ],
        users=[_user_to_model(user) for user in snapshot.users],
        initial_setup=initial_setup,
        raw_counts=RawCatalogCountsModel(
            sections=len(snapshot.sections_by_id),
            devices=len(snapshot.objects_by_id),
            users=len(snapshot.users),
            pgs=len(snapshot.pgs_by_id),
        ),
        sha256=getattr(snapshot, "sha256", None),
        path=str(getattr(snapshot, "path", "")) or None,
    )


def _apply_catalog_names(
    *,
    sections: list[SectionStatusModel],
    pgs: list[PGStatusModel],
    catalog: ExportCatalogModel | None,
) -> tuple[list[SectionStatusModel], list[PGStatusModel]]:
    if catalog is None:
        return sections, pgs

    section_names = {section.id: section.name for section in catalog.sections}
    section_names_by_display = {section.display_id: section.name for section in catalog.sections}
    section_names_by_human_number = {section.display_id + 1: section.name for section in catalog.sections}
    pg_names = {pg.id: pg.name for pg in catalog.pgs}
    pg_names_by_display = {pg.display_id: pg.name for pg in catalog.pgs}

    renamed_sections = [
        section.model_copy(
            update={
                "name": (
                    section_names_by_human_number.get(section.id)
                    or section_names.get(section.id)
                    or section_names_by_display.get(section.id)
                    or section.name
                )
            }
        )
        for section in sections
    ]
    renamed_pgs = [
        pg.model_copy(
            update={"name": pg_names_by_display.get(pg.id) or pg_names.get(pg.id) or pg.name}
        )
        for pg in pgs
    ]
    return renamed_sections, renamed_pgs


class PanelRuntime:
    """Caches panel reads and serializes all panel access through one lock."""

    def __init__(self, config: PanelRuntimeConfig) -> None:
        self._config = config
        self._lock = asyncio.Lock()
        self._listeners: list[StatusListener] = []
        self._status: PanelStatusModel | None = None
        self._catalog: ExportCatalogModel | None = None
        self._system_info: dict[str, str | None] = {
            "panel_model": None,
            "panel_hardware_version": None,
            "panel_firmware_version": None,
            "panel_unique_id": None,
        }
        self._poller_task: asyncio.Task[None] | None = None
        self._closed = False
        self._next_diagnostics_refresh_monotonic = 0.0
        self._status_session: PersistentSnapshotSession | None = None

    def _initial_setup(self) -> InitialSetupModel | None:
        return None if self._catalog is None else self._catalog.initial_setup

    def _ensure_usable_section_id(self, section_id: int) -> None:
        section_range = None if self._catalog is None or self._catalog.initial_setup is None else self._catalog.initial_setup.sections
        if section_range is None:
            return
        if not section_range.first_id <= section_id <= section_range.last_id:
            raise ValueError(
                f"Section {section_id} is outside the client-facing usable range "
                f"{section_range.first_id}-{section_range.last_id}."
            )

    def _ensure_usable_pg_id(self, pg_id: int) -> None:
        pg_range = None if self._catalog is None or self._catalog.initial_setup is None else self._catalog.initial_setup.pgs
        if pg_range is None:
            return
        if not pg_range.first_id <= pg_id <= pg_range.last_id:
            raise ValueError(
                f"PG {pg_id} is outside the client-facing usable range "
                f"{pg_range.first_id}-{pg_range.last_id}."
            )

    def _ensure_usable_user_id(self, user_id: int) -> None:
        user_range = None if self._catalog is None or self._catalog.initial_setup is None else self._catalog.initial_setup.users
        if user_range is None:
            return
        if not user_range.first_id <= user_id <= user_range.last_id:
            raise ValueError(
                f"User {user_id} is outside the client-facing usable range "
                f"{user_range.first_id}-{user_range.last_id}."
            )

    async def start(self) -> None:
        await self.refresh_all()
        self._poller_task = asyncio.create_task(self._poll_loop(), name="jablotron-panel-poller")

    async def close(self) -> None:
        self._closed = True
        if self._poller_task is not None:
            self._poller_task.cancel()
            try:
                await self._poller_task
            except asyncio.CancelledError:
                pass
        async with self._lock:
            await self._close_status_session_locked()

    def add_listener(self, listener: StatusListener) -> None:
        self._listeners.append(listener)

    async def _emit(self, topic: str, payload: dict) -> None:
        for listener in list(self._listeners):
            await listener(topic, payload)

    async def _poll_loop(self) -> None:
        while not self._closed:
            try:
                await self.refresh_status()
            except Exception:
                pass
            await asyncio.sleep(self._config.poll_interval_seconds)

    async def refresh_all(self) -> None:
        await self.refresh_catalog()
        await self.refresh_system()
        await self.refresh_status()

    async def refresh_system(self) -> dict[str, str | None]:
        async with self._lock:
            if self._status_session is None:
                self._status_session = self._create_status_session()
            info = await asyncio.to_thread(self._status_session.query_system_info)
            self._system_info.update(
                {
                    "panel_model": info.model,
                    "panel_hardware_version": info.hardware_version,
                    "panel_firmware_version": info.firmware_version,
                }
            )
            return dict(self._system_info)

    async def refresh_status(self) -> PanelStatusModel:
        async with self._lock:
            pg_count = len(self._catalog.pgs) if self._catalog is not None else 0
            devices = self._status.devices if self._status is not None else (self._catalog.devices if self._catalog is not None else [])
            include_diagnostics = time.monotonic() >= self._next_diagnostics_refresh_monotonic
            if self._status_session is None:
                self._status_session = self._create_status_session()
            snapshot = await asyncio.to_thread(
                self._status_session.query_snapshot,
                panel_model=self._system_info.get("panel_model"),
                pg_count=pg_count,
                devices=devices,
                central=None if self._status is None else self._status.central,
                include_diagnostics=include_diagnostics,
            )
            sections, pgs = _apply_catalog_names(sections=snapshot.sections, pgs=snapshot.pgs, catalog=self._catalog)
            status = PanelStatusModel(
                sections=_filter_sections_for_clients(sections, self._initial_setup()),
                pgs=_filter_pgs_for_clients(pgs, self._initial_setup()),
                devices=_filter_devices_for_clients(snapshot.devices, self._initial_setup()),
                central=snapshot.central,
                service_mode=snapshot.service_mode,
            )
            self._status = status
            if include_diagnostics:
                self._next_diagnostics_refresh_monotonic = time.monotonic() + 3600.0
        await self._emit("status", status.model_dump(mode="json"))
        return status

    async def refresh_catalog(self) -> ExportCatalogModel:
        async with self._lock:
            catalog = await self._pull_catalog_snapshot("api-server-catalog")
            self._catalog = _catalog_to_model(catalog)
        await self._emit("catalog", self._catalog.model_dump(mode="json"))
        return self._catalog

    async def get_status(self) -> PanelStatusModel:
        if self._status is None:
            return await self.refresh_status()
        return self._status

    async def get_catalog(self) -> ExportCatalogModel:
        if self._catalog is None:
            return await self.refresh_catalog()
        return self._catalog

    async def get_users(self) -> list[UserModel]:
        catalog = await self.get_catalog()
        return _filter_users_for_clients(catalog.users, catalog.initial_setup)

    async def get_user(self, user_id: int) -> UserModel | None:
        for user in await self.get_users():
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
        async with self._lock:
            await self._close_status_session_locked()
            args = SimpleNamespace(
                output=None,
                metadata_output=None,
                records_output=None,
                output_prefix="api_server_events",
                records_format="jsonl",
                save_records=False,
                log_device=self._config.flexi_log_device,
                mountpoint="/mnt/flexi_log",
                source_fdb=None,
                source_export_cfg=None,
                port=self._config.port,
                auth_code=self._config.auth_code,
                no_reset=not self._config.reset,
                verbose=False,
                mount_tool=self._config.mount_tool,
                end_mode="logical",
                copy_files_dir=None,
                transport="archive",
                window_bytes=65536,
                decode_records=False,
                record_preview_count=5,
                index_preview_count=8,
                crlf_preview_count=8,
                preview_limit=10,
                cleanup_mode="login-exit",
            )
            snapshot = await asyncio.to_thread(pull_live_archive, args)
            archive = snapshot.output.read_bytes()
            records = split_crlf_records(archive, base_offset=snapshot.window_start)
            catalog = resolve_decoder_catalog(fdb_path=None, export_cfg_path=None)
            decoded = build_decoded_records(records, archive, catalog=catalog)
            display_records = select_display_records(
                decoded,
                limit=limit,
                include_raw=include_raw,
                include_kinds=parse_kind_filter(kinds) or None,
                exclude_kinds=parse_kind_filter(exclude_kinds) or None,
            )
        return [
            EventRecordModel(
                timestamp=record.timestamp_prefix,
                kind=record.kind,
                text=record.text,
                event_code=record.event_code,
                source=record.source_name,
                channel=record.channel,
                section=record.section,
                raw=None,
            )
            for record in display_records
        ]

    async def get_export_users(self) -> list[UserModel]:
        return (await self.get_catalog()).users

    async def get_export_time_limits(self) -> list[dict[str, object]]:
        catalog = await self._refresh_export_snapshot()
        groups: list[dict[str, object]] = []
        for group in catalog.time_limit_groups_by_id.values():
            groups.append(
                {
                    "group_id": group.group_id,
                    "group_display_id": group.group_display_id,
                    "comment": group.comment,
                    "days": [
                        {
                            "day_index": day.day_index,
                            "day_name": day.day_name,
                            "section_rules": [
                                {
                                    "section_id": rule.section_id,
                                    "windows": [{"on": window.on, "off": window.off} for window in rule.windows],
                                }
                                for rule in day.section_rules
                            ],
                        }
                        for day in group.days
                    ],
                }
            )
        return groups

    async def get_export_communications(self) -> dict[str, object]:
        catalog = await self._refresh_export_snapshot()
        communications = catalog.communications
        if communications is None:
            return {"communications": None}
        sdc = None
        if communications.sdc is not None:
            sdc = {
                "enabled": communications.sdc.enabled,
                "position_raw": communications.sdc.position_raw,
                "position_name": communications.sdc.sdc_position_name,
                "service_access_mode_raw": communications.sdc.service_access_mode_raw,
                "service_access_mode_name": communications.sdc.service_access_mode_name,
            }
        return {
            "communications": {
                "service_enabled": communications.service_enabled,
                "sms_enabled": communications.sms_enabled,
                "calls_enabled": communications.calls_enabled,
                "arc_enabled": communications.arc_enabled,
                "service_phone": communications.service_phone,
                "service_phone_enabled": communications.service_phone_enabled,
                "sms_report_numbers": communications.sms_report_numbers,
                "call_report_numbers": communications.call_report_numbers,
                "sdc": sdc,
            }
        }

    async def _refresh_export_snapshot(self) -> ExportCatalogSnapshot:
        return await self._pull_catalog_snapshot("api-server-export")

    async def _pull_catalog_snapshot(self, output_prefix: str) -> ExportCatalogSnapshot:
        await self._close_status_session_locked()
        output = default_export_output(output_prefix)
        export_snapshot = await asyncio.to_thread(
            pull_live_export_snapshot,
            output=output,
            device=self._config.flexi_cfg_device,
            port=self._config.port,
            code=self._config.auth_code,
            reset=self._config.reset,
            cleanup_mode=self._config.read_cleanup_mode,
        )
        catalog = await asyncio.to_thread(extract_export_catalog, export_snapshot.path)
        if (
            self._config.reset
            and not catalog.sections_by_id
            and not catalog.pgs_by_id
            and not catalog.objects_by_id
            and not catalog.users
        ):
            await asyncio.sleep(0.8)
            retry_output = default_export_output(f"{output_prefix}-retry")
            export_snapshot = await asyncio.to_thread(
                pull_live_export_snapshot,
                output=retry_output,
                device=self._config.flexi_cfg_device,
                port=self._config.port,
                code=self._config.auth_code,
                reset=False,
                cleanup_mode=self._config.read_cleanup_mode,
            )
            catalog = await asyncio.to_thread(extract_export_catalog, export_snapshot.path)
        return catalog

    async def arm_section(self, section_id: int, mode: ArmMode, code: str | None = None) -> PanelStatusModel:
        self._ensure_usable_section_id(section_id)
        action = {
            ArmMode.AWAY: "arm_away",
            ArmMode.HOME: "arm_home",
            ArmMode.NIGHT: "arm_night",
        }[mode]
        async with self._lock:
            session = self._status_session
            if session is None:
                session = self._create_status_session()
                self._status_session = session
            await asyncio.to_thread(
                session.control_section,
                section_id=section_id,
                action=action,
                code=code,
            )
        return await self.refresh_status()

    async def disarm_section(self, section_id: int, code: str | None = None) -> PanelStatusModel:
        self._ensure_usable_section_id(section_id)
        async with self._lock:
            session = self._status_session
            if session is None:
                session = self._create_status_session()
                self._status_session = session
            await asyncio.to_thread(
                session.control_section,
                section_id=section_id,
                action="disarm",
                code=code,
            )
        return await self.refresh_status()

    async def set_pg(self, pg_id: int, enabled: bool, code: str | None = None) -> PanelStatusModel:
        self._ensure_usable_pg_id(pg_id)
        async with self._lock:
            session = self._status_session
            if session is None:
                session = self._create_status_session()
                self._status_session = session
            await asyncio.to_thread(
                session.control_pg,
                pg_id=pg_id,
                enabled=enabled,
                code=code,
            )
        return await self.refresh_status()

    def _user_args(self, *, command: str, user_id: int, payload: UserCreateModel | UserPatchModel | None = None) -> SimpleNamespace:
        fields = {}
        if payload is not None:
            fields = payload.model_dump(exclude_unset=True)
        return SimpleNamespace(
            command=command,
            user_id=user_id,
            name=fields.get("name"),
            phone=fields.get("phone"),
            pin=fields.get("code"),
            card1=fields.get("card1"),
            card2=None,
            comment=fields.get("comment"),
            flags_raw=fields.get("flags_raw"),
            field0_raw=None,
            access_raw=fields.get("access_raw"),
            permissions_raw=None,
            sections_mask=None,
            sections=",".join(str(item) for item in fields.get("sections", [])) or None,
            pg_masks=None,
            pgs=",".join(str(item) for item in fields.get("pgs", [])) or None,
            pg_num_if_ring_raw=None,
            field8_raw=None,
            time_limited_group_raw=fields.get("time_limited_group_raw"),
            field9_raw=None,
            parent_user_no_raw=None,
            field11_raw=None,
            template_file=None,
            template_pcap=None,
            template_frame=None,
            sector_output=None,
            keep_sector=False,
            import_path=str(self._config.import_path),
            device=self._config.flexi_cfg_device,
            port=self._config.port,
            auth_code=self._config.auth_code,
            no_reset=not self._config.reset,
            mount_tool=self._config.mount_tool,
            stage_mode=self._config.stage_mode,
            write_cleanup_mode=self._config.write_cleanup_mode,
            verify_output=None,
            no_apply=False,
            verbose=False,
            export_cfg=None,
            output=None,
            no_trigger=False,
            read_cleanup_mode=self._config.read_cleanup_mode,
            show_access_names=False,
            no_preflight_validation=False,
            format="json",
        )

    async def add_user(self, payload: UserCreateModel) -> UserModel:
        self._ensure_usable_user_id(payload.id)
        args = self._user_args(command="add", user_id=payload.id, payload=payload)
        async with self._lock:
            await self._close_status_session_locked()
            sector_path, _, cleanup_sector = await asyncio.to_thread(build_upsert_sector, args, current=None)
            try:
                verify_output = default_export_output(f"api-add-user{payload.id}")
                await asyncio.to_thread(
                    apply_import_sector,
                    sector_path=sector_path,
                    import_path=self._config.import_path,
                    device=self._config.flexi_cfg_device,
                    port=self._config.port,
                    code=self._config.auth_code,
                    reset=self._config.reset,
                    mount_tool=self._config.mount_tool,
                    stage_mode=self._config.stage_mode,
                    write_cleanup_mode=self._config.write_cleanup_mode,
                    verbose=False,
                    verify_output=verify_output,
                )
            finally:
                if cleanup_sector and sector_path.exists():
                    sector_path.unlink()
        await self.refresh_catalog()
        user = await self.get_user(payload.id)
        if user is None:
            raise RuntimeError(f"User {payload.id} was not present after add.")
        await self._emit("users", {"action": "added", "user": user.model_dump(mode="json")})
        return user

    async def edit_user(self, user_id: int, payload: UserPatchModel) -> UserModel:
        self._ensure_usable_user_id(user_id)
        args = self._user_args(command="edit", user_id=user_id, payload=payload)
        current = await self.get_user(user_id)
        if current is None:
            raise RuntimeError(f"User {user_id} not found.")
        current_record = UserRecord(
            offset=0,
            user_id=current.id,
            raw_id_bytes="",
            flags_raw=current.flags_raw,
            flags=[],
            access_raw=current.access_raw,
            rights=current.rights,
            enabled=current.enabled,
            section_access_mask_raw=None,
            section_ids=current.section_ids,
            pg_access_masks_raw=[],
            pg_ids=current.pg_ids,
            name=current.name,
            phone=current.phone,
            code=current.code,
            cards=current.cards,
            comment=current.comment,
            pg_num_if_ring_raw=None,
            time_limited_group_raw=current.time_limited_group_raw,
            parent_user_no_raw=None,
        )
        async with self._lock:
            await self._close_status_session_locked()
            sector_path, _, cleanup_sector = await asyncio.to_thread(build_upsert_sector, args, current=current_record)
            try:
                verify_output = default_export_output(f"api-edit-user{user_id}")
                await asyncio.to_thread(
                    apply_import_sector,
                    sector_path=sector_path,
                    import_path=self._config.import_path,
                    device=self._config.flexi_cfg_device,
                    port=self._config.port,
                    code=self._config.auth_code,
                    reset=self._config.reset,
                    mount_tool=self._config.mount_tool,
                    stage_mode=self._config.stage_mode,
                    write_cleanup_mode=self._config.write_cleanup_mode,
                    verbose=False,
                    verify_output=verify_output,
                )
            finally:
                if cleanup_sector and sector_path.exists():
                    sector_path.unlink()
        await self.refresh_catalog()
        user = await self.get_user(user_id)
        if user is None:
            raise RuntimeError(f"User {user_id} disappeared after edit.")
        await self._emit("users", {"action": "edited", "user": user.model_dump(mode="json")})
        return user

    async def delete_user(self, user_id: int) -> None:
        self._ensure_usable_user_id(user_id)
        args = self._user_args(command="delete", user_id=user_id)
        async with self._lock:
            await self._close_status_session_locked()
            sector_path, _, cleanup_sector = await asyncio.to_thread(build_delete_sector, args)
            try:
                verify_output = default_export_output(f"api-delete-user{user_id}")
                await asyncio.to_thread(
                    apply_import_sector,
                    sector_path=sector_path,
                    import_path=self._config.import_path,
                    device=self._config.flexi_cfg_device,
                    port=self._config.port,
                    code=self._config.auth_code,
                    reset=self._config.reset,
                    mount_tool=self._config.mount_tool,
                    stage_mode=self._config.stage_mode,
                    write_cleanup_mode=self._config.write_cleanup_mode,
                    verbose=False,
                    verify_output=verify_output,
                )
            finally:
                if cleanup_sector and sector_path.exists():
                    sector_path.unlink()
        await self.refresh_catalog()
        await self._emit("users", {"action": "deleted", "user_id": user_id})

    @property
    def system_info(self) -> dict[str, str | None]:
        return dict(self._system_info)

    def _create_status_session(self) -> PersistentSnapshotSession:
        return PersistentSnapshotSession(
            port=self._config.port,
            code=self._config.auth_code,
            reset=self._config.reset,
        )

    async def _close_status_session_locked(self) -> None:
        session = self._status_session
        self._status_session = None
        if session is not None:
            await asyncio.to_thread(session.close)
