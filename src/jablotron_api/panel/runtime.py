"""Single-owner panel runtime.

Holds the persistent HID session, serializes panel access through one lock,
and delegates the actual transformation / CRUD / event work to the service
modules under ``jablotron_api/services/``.

Symbols re-exported here for backward compatibility with existing tests:
- ``_infer_device_type`` — was the pure inference helper
- ``_catalog_to_model`` — was the snapshot → API model converter
- ``_apply_catalog_names`` — was the live-status renaming pass

These now live in the service modules; the names are preserved as private
aliases until the test suite is updated.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
from pathlib import Path
import time
from typing import Awaitable, Callable

from jablotron_re_tools import (
    DEFAULT_IMPORT_PATH,
    ExportCatalogSnapshot,
    cleanup_read_session,
)

from jablotron_api.domain.codes import CodeFormat, resolve_code_format
from jablotron_api.domain.models import (
    ArmMode,
    EventRecordModel,
    ExportCatalogModel,
    InitialSetupModel,
    PanelStatusModel,
    UserCreateModel,
    UserModel,
    UserPatchModel,
)
from jablotron_api.protocol.legacy import PersistentSnapshotSession
from jablotron_api.services.catalog_io import (
    CatalogPullConfig,
    apply_catalog_names as _apply_catalog_names,
    catalog_to_model as _catalog_to_model,
    ensure_id_in_range,
    export_communications_payload,
    export_time_limits_payload,
    filter_devices_for_clients,
    filter_pgs_for_clients,
    filter_sections_for_clients,
    filter_users_for_clients,
    pull_catalog_snapshot,
    user_to_model as _user_to_model,
)
from jablotron_api.services.device_inference import infer_device_type as _infer_device_type
from jablotron_api.services.event_reader import EventReaderConfig, read_recent_events
from jablotron_api.services.user_manager import (
    UserManagerConfig,
    apply_delete as _apply_delete_user,
    apply_upsert as _apply_upsert_user,
    user_to_record,
    verify_added_user as _verify_added_user_fn,
    verify_edited_user as _verify_edited_user_fn,
)

LOGGER = logging.getLogger(__name__)


StatusListener = Callable[[str, dict], Awaitable[None]]


__all__ = [
    "PanelRuntime",
    "PanelRuntimeConfig",
    "StatusListener",
    "_apply_catalog_names",
    "_catalog_to_model",
    "_infer_device_type",
    "_user_to_model",
]


@dataclass
class PanelRuntimeConfig:
    port: str = "auto"
    # No default: the panel service code is installation-specific and must
    # be provided explicitly. ServerSettings reads it from
    # JABLOTRON_PANEL_AUTH_CODE; tests pass it directly.
    auth_code: str = ""
    flexi_cfg_device: str = "auto"
    flexi_log_device: str = "auto"
    import_path: Path = DEFAULT_IMPORT_PATH
    mount_tool: str = "sudo"
    stage_mode: str = "filesystem"
    read_cleanup_mode: str = "auto"
    write_cleanup_mode: str = "auto"
    poll_interval_seconds: float = 2.0
    full_refresh_interval_seconds: float = 15.0
    fast_status_timeout_seconds: float = 0.6
    full_status_timeout_seconds: float = 2.0
    reset: bool = True


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
        self._next_full_refresh_monotonic = 0.0
        self._status_session: PersistentSnapshotSession | None = None

    # ------------------------------------------------------------------ config

    def _catalog_pull_config(self) -> CatalogPullConfig:
        return CatalogPullConfig(
            flexi_cfg_device=self._config.flexi_cfg_device,
            port=self._config.port,
            auth_code=self._config.auth_code,
            reset=self._config.reset,
            read_cleanup_mode=self._config.read_cleanup_mode,
        )

    def _user_manager_config(self) -> UserManagerConfig:
        return UserManagerConfig(
            import_path=self._config.import_path,
            flexi_cfg_device=self._config.flexi_cfg_device,
            port=self._config.port,
            auth_code=self._config.auth_code,
            reset=self._config.reset,
            mount_tool=self._config.mount_tool,
            stage_mode=self._config.stage_mode,
            write_cleanup_mode=self._config.write_cleanup_mode,
            read_cleanup_mode=self._config.read_cleanup_mode,
        )

    def _event_reader_config(self) -> EventReaderConfig:
        return EventReaderConfig(
            flexi_log_device=self._config.flexi_log_device,
            port=self._config.port,
            auth_code=self._config.auth_code,
            reset=self._config.reset,
            mount_tool=self._config.mount_tool,
        )

    # --------------------------------------------------------- range validation

    def _initial_setup(self) -> InitialSetupModel | None:
        return None if self._catalog is None else self._catalog.initial_setup

    def code_format(self) -> CodeFormat:
        initial = self._initial_setup()
        return resolve_code_format(
            catalog_code_length=initial.code_length if initial is not None else None,
            catalog_code_prefix=initial.code_prefix if initial is not None else None,
            server_auth_code=self._config.auth_code or None,
        )

    def _ensure_usable_section_id(self, section_id: int) -> None:
        ensure_id_in_range(self._initial_setup(), kind="Section", attr="sections", value=section_id)

    def _ensure_usable_pg_id(self, pg_id: int) -> None:
        ensure_id_in_range(self._initial_setup(), kind="PG", attr="pgs", value=pg_id)

    def _ensure_usable_user_id(self, user_id: int) -> None:
        ensure_id_in_range(self._initial_setup(), kind="User", attr="users", value=user_id)

    # ------------------------------------------------------- start / stop / emit

    async def start(self) -> None:
        LOGGER.info(
            "Starting panel runtime: port=%s flexi_cfg=%s flexi_log=%s poll_interval=%.1fs full_refresh_interval=%.1fs",
            self._config.port,
            self._config.flexi_cfg_device,
            self._config.flexi_log_device,
            self._config.poll_interval_seconds,
            self._config.full_refresh_interval_seconds,
        )
        await self.refresh_all()
        self._poller_task = asyncio.create_task(self._poll_loop(), name="jablotron-panel-poller")
        LOGGER.info("Panel runtime started")

    async def close(self) -> None:
        LOGGER.info("Stopping panel runtime")
        self._closed = True
        if self._poller_task is not None:
            self._poller_task.cancel()
            try:
                await self._poller_task
            except asyncio.CancelledError:
                pass
        async with self._lock:
            had_status_session = self._status_session is not None
            await self._close_status_session_locked()
            if had_status_session:
                await self._cleanup_shutdown_session_locked()
        LOGGER.info("Panel runtime stopped")

    def add_listener(self, listener: StatusListener) -> None:
        self._listeners.append(listener)

    async def _emit(self, topic: str, payload: dict) -> None:
        for listener in list(self._listeners):
            await listener(topic, payload)

    async def _poll_loop(self) -> None:
        while not self._closed:
            try:
                await self.refresh_status()
            except Exception as exc:
                LOGGER.warning("Background panel status refresh failed: %s", exc, exc_info=True)
            await asyncio.sleep(self._config.poll_interval_seconds)

    async def refresh_all(self) -> None:
        await self.refresh_catalog()
        await self.refresh_system()
        await self.refresh_status()

    # ----------------------------------------------------------- system / status

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
            LOGGER.info(
                "Panel system info refreshed: model=%s hardware=%s firmware=%s",
                info.model,
                info.hardware_version,
                info.firmware_version,
            )
            return dict(self._system_info)

    async def refresh_status(self) -> PanelStatusModel:
        async with self._lock:
            now = time.monotonic()
            pg_count = len(self._catalog.pgs) if self._catalog is not None else 0
            devices = (
                self._status.devices
                if self._status is not None
                else (self._catalog.devices if self._catalog is not None else [])
            )
            include_diagnostics = now >= self._next_diagnostics_refresh_monotonic
            include_full_refresh = self._status is None or now >= self._next_full_refresh_monotonic
            timeout = (
                self._config.full_status_timeout_seconds
                if include_full_refresh or include_diagnostics
                else self._config.fast_status_timeout_seconds
            )
            if self._status_session is None:
                self._status_session = self._create_status_session()
            snapshot = await asyncio.to_thread(
                self._status_session.query_snapshot,
                panel_model=self._system_info.get("panel_model"),
                pg_count=pg_count,
                devices=devices,
                central=None if self._status is None else self._status.central,
                query_device_status=include_full_refresh or include_diagnostics,
                include_diagnostics=include_diagnostics,
                timeout=timeout,
            )
            sections, pgs = _apply_catalog_names(
                sections=snapshot.sections, pgs=snapshot.pgs, catalog=self._catalog
            )
            initial = self._initial_setup()
            status = PanelStatusModel(
                sections=filter_sections_for_clients(sections, initial),
                pgs=filter_pgs_for_clients(pgs, initial),
                devices=filter_devices_for_clients(snapshot.devices, initial),
                central=snapshot.central,
                service_mode=snapshot.service_mode,
            )
            self._status = status
            LOGGER.debug(
                "Panel status refreshed: sections=%s pgs=%s devices=%s service_mode=%s include_full=%s include_diagnostics=%s",
                len(status.sections),
                len(status.pgs),
                len(status.devices),
                status.service_mode,
                include_full_refresh,
                include_diagnostics,
            )
            if include_diagnostics:
                unresolved_wireless_temperatures = any(
                    device.wireless
                    and (device.inferred_device_type or "") in {"thermometer", "thermostat"}
                    and device.temperature is None
                    for device in status.devices
                )
                self._next_diagnostics_refresh_monotonic = time.monotonic() + (
                    60.0 if unresolved_wireless_temperatures else 3600.0
                )
            if include_full_refresh or include_diagnostics:
                self._next_full_refresh_monotonic = time.monotonic() + self._config.full_refresh_interval_seconds
        await self._emit("status", status.model_dump(mode="json"))
        return status

    async def refresh_catalog(self) -> ExportCatalogModel:
        async with self._lock:
            catalog = await self._pull_catalog_snapshot_locked("api-server-catalog")
            self._catalog = _catalog_to_model(catalog)
            LOGGER.info(
                "Panel catalog refreshed: sections=%s pgs=%s devices=%s users=%s initial_setup_exact=%s",
                len(self._catalog.sections),
                len(self._catalog.pgs),
                len(self._catalog.devices),
                len(self._catalog.users),
                None if self._catalog.initial_setup is None else self._catalog.initial_setup.exact,
            )
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
        return filter_users_for_clients(catalog.users, catalog.initial_setup)

    async def get_user(self, user_id: int) -> UserModel | None:
        for user in await self.get_users():
            if user.id == user_id:
                return user
        return None

    # -------------------------------------------------------------------- events

    async def get_events_recent(
        self,
        *,
        limit: int = 20,
        include_raw: bool = False,
        kinds: str | None = None,
        exclude_kinds: str | None = None,
    ) -> list[EventRecordModel]:
        LOGGER.info(
            "Reading recent events: limit=%s include_raw=%s include_kinds=%s exclude_kinds=%s",
            limit,
            include_raw,
            kinds,
            exclude_kinds,
        )
        async with self._lock:
            await self._close_status_session_locked()
            return await asyncio.to_thread(
                read_recent_events,
                self._event_reader_config(),
                limit=limit,
                include_raw=include_raw,
                kinds=kinds,
                exclude_kinds=exclude_kinds,
            )

    # ---------------------------------------------------------------- exports

    async def get_export_users(self) -> list[UserModel]:
        return (await self.get_catalog()).users

    async def get_export_time_limits(self) -> list[dict[str, object]]:
        catalog = await self._refresh_export_snapshot()
        return export_time_limits_payload(catalog)

    async def get_export_communications(self) -> dict[str, object]:
        catalog = await self._refresh_export_snapshot()
        return export_communications_payload(catalog)

    async def _refresh_export_snapshot(self) -> ExportCatalogSnapshot:
        async with self._lock:
            return await self._pull_catalog_snapshot_locked("api-server-export")

    async def _pull_catalog_snapshot_locked(self, output_prefix: str) -> ExportCatalogSnapshot:
        LOGGER.info(
            "Pulling export catalog snapshot: prefix=%s reset=%s cleanup_mode=%s",
            output_prefix,
            self._config.reset,
            self._config.read_cleanup_mode,
        )
        await self._close_status_session_locked()
        catalog = await asyncio.to_thread(
            pull_catalog_snapshot,
            self._catalog_pull_config(),
            output_prefix,
            sleep=time.sleep,
        )
        LOGGER.debug(
            "Export catalog snapshot ready: sections=%s pgs=%s devices=%s users=%s",
            len(catalog.sections_by_id),
            len(catalog.pgs_by_id),
            len(catalog.objects_by_id),
            len(catalog.users),
        )
        return catalog

    # ---------------------------------------------------------------- control

    _ARM_ACTIONS = {
        ArmMode.AWAY: "arm_away",
        ArmMode.HOME: "arm_home",
        ArmMode.NIGHT: "arm_night",
    }

    async def arm_section(
        self,
        section_id: int,
        mode: ArmMode,
        code: str | None = None,
    ) -> PanelStatusModel:
        return await self._invoke_section_control(
            section_id=section_id,
            action=self._ARM_ACTIONS[mode],
            code=code,
            op="arm_section",
            log_detail=f"mode={mode.value}",
        )

    async def disarm_section(
        self,
        section_id: int,
        code: str | None = None,
    ) -> PanelStatusModel:
        return await self._invoke_section_control(
            section_id=section_id,
            action="disarm",
            code=code,
            op="disarm_section",
            log_detail="",
        )

    async def _invoke_section_control(
        self,
        *,
        section_id: int,
        action: str,
        code: str | None,
        op: str,
        log_detail: str,
    ) -> PanelStatusModel:
        self._ensure_usable_section_id(section_id)
        effective_code = await self._effective_control_code(code)
        # The supplied code is forwarded to the panel as-is; the panel is the
        # sole authority on whether the code is valid and what it may control.
        # The API server only gates on token scope (sections:arm/disarm plus
        # codes:impersonate when a code is supplied) at the route layer.
        LOGGER.info(
            "Panel %s requested: section=%s %scode_source=%s",
            op,
            section_id,
            f"{log_detail} " if log_detail else "",
            "explicit" if code and code.strip() else "service_default",
        )
        async with self._lock:
            session = self._status_session
            if session is None:
                session = self._create_status_session()
                self._status_session = session
            await asyncio.to_thread(
                session.control_section,
                section_id=section_id,
                action=action,
                code=effective_code,
            )
        LOGGER.info("Panel %s completed: section=%s %s", op, section_id, log_detail)
        return await self.refresh_status()

    async def set_pg(
        self,
        pg_id: int,
        enabled: bool,
        code: str | None = None,
    ) -> PanelStatusModel:
        self._ensure_usable_pg_id(pg_id)
        effective_code = (code or "").strip()
        if not effective_code:
            raise PermissionError("PG control requires an explicit panel code.")
        # As with section control, the code is forwarded verbatim and the panel
        # decides validity and authorization; the route layer has already
        # required pgs:control plus codes:impersonate.
        LOGGER.info(
            "Panel set_pg requested: pg=%s enabled=%s code_source=explicit",
            pg_id,
            enabled,
        )
        async with self._lock:
            session = self._status_session
            if session is None:
                session = self._create_status_session()
                self._status_session = session
            await asyncio.to_thread(
                session.control_pg,
                pg_id=pg_id,
                enabled=enabled,
                code=effective_code,
            )
        LOGGER.info("Panel set_pg completed: pg=%s enabled=%s", pg_id, enabled)
        return await self.refresh_status()

    async def _effective_control_code(self, code: str | None) -> str:
        normalized = (code or "").strip()
        return normalized or self._config.auth_code

    # ---------------------------------------------------------------- user CRUD

    def _verify_added_user(self, user: UserModel, payload: UserCreateModel) -> None:
        _verify_added_user_fn(user, payload)

    def _verify_edited_user(self, user: UserModel, payload: UserPatchModel) -> None:
        _verify_edited_user_fn(user, payload)

    async def add_user(self, payload: UserCreateModel) -> UserModel:
        self._ensure_usable_user_id(payload.id)
        async with self._lock:
            await self._close_status_session_locked()
            await asyncio.to_thread(
                _apply_upsert_user,
                self._user_manager_config(),
                user_id=payload.id,
                payload=payload,
                current=None,
                verify_prefix=f"api-add-user{payload.id}",
            )
        await self.refresh_catalog()
        user = await self.get_user(payload.id)
        if user is None:
            raise RuntimeError(f"User {payload.id} was not present after add.")
        self._verify_added_user(user, payload)
        await self._emit("users", {"action": "added", "user": user.model_dump(mode="json")})
        return user

    async def edit_user(self, user_id: int, payload: UserPatchModel) -> UserModel:
        self._ensure_usable_user_id(user_id)
        current = await self.get_user(user_id)
        if current is None:
            raise RuntimeError(f"User {user_id} not found.")
        current_record = user_to_record(current)
        async with self._lock:
            await self._close_status_session_locked()
            await asyncio.to_thread(
                _apply_upsert_user,
                self._user_manager_config(),
                user_id=user_id,
                payload=payload,
                current=current_record,
                verify_prefix=f"api-edit-user{user_id}",
            )
        await self.refresh_catalog()
        user = await self.get_user(user_id)
        if user is None:
            raise RuntimeError(f"User {user_id} disappeared after edit.")
        self._verify_edited_user(user, payload)
        await self._emit("users", {"action": "edited", "user": user.model_dump(mode="json")})
        return user

    async def delete_user(self, user_id: int) -> None:
        self._ensure_usable_user_id(user_id)
        async with self._lock:
            await self._close_status_session_locked()
            await asyncio.to_thread(
                _apply_delete_user,
                self._user_manager_config(),
                user_id=user_id,
                verify_prefix=f"api-delete-user{user_id}",
            )
        await self.refresh_catalog()
        if await self.get_user(user_id) is not None:
            raise RuntimeError(f"User {user_id} was still present after delete.")
        await self._emit("users", {"action": "deleted", "user_id": user_id})

    # ---------------------------------------------------------------- system

    @property
    def system_info(self) -> dict[str, str | None]:
        return dict(self._system_info)

    def _create_status_session(self) -> PersistentSnapshotSession:
        LOGGER.debug("Creating persistent panel status session")
        return PersistentSnapshotSession(
            port=self._config.port,
            code=self._config.auth_code,
            reset=self._config.reset,
        )

    async def _close_status_session_locked(self) -> None:
        session = self._status_session
        self._status_session = None
        if session is not None:
            LOGGER.debug("Closing persistent panel status session")
            await asyncio.to_thread(session.close)

    async def _cleanup_shutdown_session_locked(self) -> None:
        try:
            LOGGER.debug("Running shutdown panel cleanup session")
            await asyncio.to_thread(
                cleanup_read_session,
                port=self._config.port,
                code=self._config.auth_code,
                cleanup_mode="exit-only",
                verbose=False,
            )
        except Exception as exc:
            LOGGER.warning("Shutdown panel cleanup session failed: %s", exc)
            return
