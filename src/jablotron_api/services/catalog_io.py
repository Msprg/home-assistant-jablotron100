"""Catalog snapshot conversion and client-facing range helpers.

Wraps the export-snapshot dataclasses produced by `jablotron_re_tools` and
converts them into the stable API `ExportCatalogModel` plus the inferred
`InitialSetupModel` that bounds client-facing endpoints.

All logic here was previously inlined in `panel/runtime.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from jablotron_re_tools import (
    ExportCatalogSnapshot,
    ExportSnapshot,
    UserRecord,
    default_export_output,
    extract_export_catalog,
    pull_live_export_snapshot,
)

from jablotron_api.domain.models import (
    DeviceStatusModel,
    ExportCatalogModel,
    ExportPGModel,
    ExportSectionModel,
    InitialSetupModel,
    InitialSetupRangeModel,
    PGStatusModel,
    RawCatalogCountsModel,
    SectionStatusModel,
    UserModel,
)
from jablotron_api.services.device_inference import (
    SYSTEM_OBJECT_IDS,
    infer_device_type,
    is_default_pg_name,
    is_default_section_name,
    tail_default_cutoff,
)


def user_to_model(record: UserRecord) -> UserModel:
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


def _make_range(*, first_id: int, last_id: int) -> InitialSetupRangeModel | None:
    if last_id < first_id:
        return None
    return InitialSetupRangeModel(first_id=first_id, last_id=last_id, count=(last_id - first_id) + 1)


def build_initial_setup(snapshot: ExportCatalogSnapshot) -> InitialSetupModel | None:
    if snapshot.main_config is not None:
        main = snapshot.main_config
        notes: list[str] = []
        if main.rfid_restrict is not None:
            notes.append(
                "EM Unique card support is not mapped exactly yet; raw rfid_restrict is kept in the reverse-engineering parser."
            )
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

    non_system_objects = [
        device for device in snapshot.objects_by_id.values()
        if device.object_id not in SYSTEM_OBJECT_IDS and device.object_id < 233
    ]
    section_count = 0
    if non_system_objects:
        section_count = max((device.section_id or 0) for device in non_system_objects) + 1
    if section_count <= 0:
        section_cutoff = tail_default_cutoff(
            [
                (section.display_id, section.name)
                for section in sorted(snapshot.sections_by_id.values(), key=lambda item: item.display_id)
            ],
            is_default=is_default_section_name,
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

    regular_user_ids = sorted(
        user.user_id for user in snapshot.users if user.user_id is not None and 1 <= user.user_id < 0x200
    )
    user_last_id = max(regular_user_ids, default=0)

    pg_cutoff = tail_default_cutoff(
        [
            (pg.display_id, pg.name)
            for pg in sorted(snapshot.pgs_by_id.values(), key=lambda item: item.display_id)
        ],
        is_default=is_default_pg_name,
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


def _filter_by_range(items, getter, initial_setup, attr):
    selection = None if initial_setup is None else getattr(initial_setup, attr)
    if selection is None:
        return items
    return [item for item in items if selection.first_id <= getter(item) <= selection.last_id]


def filter_sections_for_clients(
    sections: list[SectionStatusModel], initial_setup: InitialSetupModel | None
) -> list[SectionStatusModel]:
    return _filter_by_range(sections, lambda item: item.id, initial_setup, "sections")


def filter_pgs_for_clients(
    pgs: list[PGStatusModel], initial_setup: InitialSetupModel | None
) -> list[PGStatusModel]:
    return _filter_by_range(pgs, lambda item: item.id, initial_setup, "pgs")


def filter_devices_for_clients(
    devices: list[DeviceStatusModel], initial_setup: InitialSetupModel | None
) -> list[DeviceStatusModel]:
    return _filter_by_range(devices, lambda item: item.id, initial_setup, "devices")


def filter_users_for_clients(
    users: list[UserModel], initial_setup: InitialSetupModel | None
) -> list[UserModel]:
    return _filter_by_range(users, lambda item: item.id, initial_setup, "users")


def ensure_id_in_range(
    initial_setup: InitialSetupModel | None,
    *,
    kind: str,
    attr: str,
    value: int,
) -> None:
    selection = None if initial_setup is None else getattr(initial_setup, attr)
    if selection is None:
        return
    if not selection.first_id <= value <= selection.last_id:
        raise ValueError(
            f"{kind} {value} is outside the client-facing usable range "
            f"{selection.first_id}-{selection.last_id}."
        )


def catalog_to_model(snapshot: ExportCatalogSnapshot) -> ExportCatalogModel:
    initial_setup = build_initial_setup(snapshot)
    pg_names = {pg.name for pg in snapshot.pgs_by_id.values() if pg.name}

    def _device_inference(device) -> tuple[str | None, str | None]:
        if (
            (device.name or "") in pg_names
            and snapshot.hardware_by_id.get(device.object_id) is None
            and device.type_raw == 14
        ):
            return "io_module", None
        return infer_device_type(
            name=device.name or f"Object {device.object_id}",
            hardware_model=(
                snapshot.hardware_by_id.get(device.object_id).model
                if device.object_id in snapshot.hardware_by_id
                else None
            ),
            type_raw=device.type_raw,
            object_id=device.object_id,
        )

    devices: list[DeviceStatusModel] = []
    for device in snapshot.objects_by_id.values():
        inferred_type, inferred_entity = _device_inference(device)
        devices.append(
            DeviceStatusModel(
                id=device.object_id,
                name=device.name or f"Object {device.object_id}",
                kind=str(device.kind_raw) if device.kind_raw is not None else None,
                section_id=device.section_id,
                type_raw=device.type_raw,
                subtype_raw=device.subtype_raw,
                hardware_model=(
                    snapshot.hardware_by_id.get(device.object_id).model
                    if device.object_id in snapshot.hardware_by_id
                    else None
                ),
                inferred_device_type=inferred_type,
                inferred_entity_type=inferred_entity,
                comment=device.comment,
            )
        )

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
        devices=devices,
        users=[user_to_model(user) for user in snapshot.users],
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


def apply_catalog_names(
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


@dataclass
class CatalogPullConfig:
    flexi_cfg_device: str
    port: str
    auth_code: str
    reset: bool
    read_cleanup_mode: str


def pull_catalog_snapshot(
    config: CatalogPullConfig,
    output_prefix: str,
    *,
    sleep: Callable[[float], None] | None = None,
) -> ExportCatalogSnapshot:
    """Pull a fresh export-catalog snapshot from the live panel.

    Retries the pull once without reset if the first read came back fully empty,
    which has historically indicated a transient FAT16 read race.
    """

    output = default_export_output(output_prefix)
    export_snapshot: ExportSnapshot = pull_live_export_snapshot(
        output=output,
        device=config.flexi_cfg_device,
        port=config.port,
        code=config.auth_code,
        reset=config.reset,
        cleanup_mode=config.read_cleanup_mode,
    )
    catalog = extract_export_catalog(export_snapshot.path)
    if (
        config.reset
        and not catalog.sections_by_id
        and not catalog.pgs_by_id
        and not catalog.objects_by_id
        and not catalog.users
    ):
        if sleep is not None:
            sleep(0.8)
        retry_output = default_export_output(f"{output_prefix}-retry")
        export_snapshot = pull_live_export_snapshot(
            output=retry_output,
            device=config.flexi_cfg_device,
            port=config.port,
            code=config.auth_code,
            reset=False,
            cleanup_mode=config.read_cleanup_mode,
        )
        catalog = extract_export_catalog(export_snapshot.path)
    return catalog


def export_time_limits_payload(catalog: ExportCatalogSnapshot) -> list[dict[str, object]]:
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


def export_communications_payload(catalog: ExportCatalogSnapshot) -> dict[str, object]:
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
