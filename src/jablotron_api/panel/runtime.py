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
from collections import deque
from dataclasses import dataclass, field
import logging
import math
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
    utc_now,
)
from jablotron_api.protocol.legacy import PanelConfigError, PersistentSnapshotSession
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
from jablotron_api.domain.user_validation import UserSlotOccupied
from jablotron_api.services.user_manager import (
    UserManagerConfig,
    UserWritePreflight,
    apply_delete as _apply_delete_user,
    apply_upsert as _apply_upsert_user,
    resolve_write_transport,
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


_WRITE_CODE_HINT = (
    " The panel takes IMPORT.CFG writes only from a service- or ARC-rights login; set"
    " JABLOTRON_PANEL_WRITE_AUTH_CODE to such a code, or let a master-rights code write"
    " over HID with JABLOTRON_PANEL_WRITE_TRANSPORT=hid."
)


async def _run_panel_io(func, /, *args, label: str, failure_hint: str | None = None, **kwargs):
    """Run a blocking panel operation in a worker thread and report its
    failure as a ``RuntimeError`` (409) prefixed with ``label``.

    Two failure shapes are converted: ``SystemExit`` from the standalone
    tooling (``jablotron_re_tools``) and ``PanelConfigError`` from the
    operations that run inside the status session.
    """

    try:
        return await asyncio.to_thread(func, *args, **kwargs)
    except (SystemExit, PanelConfigError) as exc:
        message = f"{label}: {exc}"
        if failure_hint and "IMPORT.CFG staging failed" in message:
            message += failure_hint
        raise RuntimeError(message) from None


async def _run_panel_write(func, /, *args, failure_hint: str | None = None, **kwargs):
    """Run a blocking user write in a worker thread, SystemExit-safe.

    The write tooling (``jablotron_re_tools``) reports failures with
    ``SystemExit``: a refused IMPORT.CFG write, a failed read-back, setup
    mode not reached. ``SystemExit`` is a ``BaseException``, so it passes
    every ``except Exception`` and, raised out of ``asyncio.to_thread``,
    stops uvicorn; on 2026-09-25 a panel refusal restarted the container
    that way. Re-raised as ``RuntimeError`` it becomes the 409 the HTTP
    layer already uses for "the panel or the link failed, stop". The
    in-session write reports its failures as ``ConfigWriteError``, which
    takes the same route.
    """

    return await _run_panel_io(func, *args, label="Panel write failed", failure_hint=failure_hint, **kwargs)


@dataclass
class PanelRuntimeConfig:
    port: str = "auto"
    # No default: the panel code is installation-specific and must be
    # provided explicitly. ServerSettings reads it from
    # JABLOTRON_PANEL_AUTH_CODE; tests pass it directly.
    auth_code: str = field(default="", repr=False)
    # Optional: a second code for user writes only
    # (JABLOTRON_PANEL_WRITE_AUTH_CODE). IMPORT.CFG writes need a service- or
    # ARC-rights login; a master-rights login writes over HID instead. Empty
    # means writes use auth_code.
    write_auth_code: str = field(default="", repr=False)
    # "auto" | "hid" | "storage" (JABLOTRON_PANEL_WRITE_TRANSPORT); see
    # services.user_manager.UserManagerConfig.write_transport.
    write_transport: str = "auto"
    flexi_cfg_device: str = "auto"
    flexi_log_device: str = "auto"
    import_path: Path = DEFAULT_IMPORT_PATH
    mount_tool: str = "sudo"
    stage_mode: str = "filesystem"
    read_cleanup_mode: str = "auto"
    write_cleanup_mode: str = "auto"
    poll_interval_seconds: float = 2.0
    full_refresh_interval_seconds: float = 3600.0
    fast_status_timeout_seconds: float = 0.6
    full_status_timeout_seconds: float = 2.0
    reset: bool = True
    # Mirrors ServerSettings.panel.catalog_max_age_seconds; production passes
    # a PanelSettings here, so the two dataclasses must stay in step.
    catalog_max_age_seconds: float = 3600.0
    # Mirrors ServerSettings.panel.in_session_config_ops: user writes run
    # inside the persistent status session; False closes the session and
    # uses a separate client, as before.
    in_session_config_ops: bool = True


class PanelRuntime:
    """Caches panel reads and serializes all panel access through one lock."""

    def __init__(self, config: PanelRuntimeConfig) -> None:
        self._config = config
        self._lock = asyncio.Lock()
        self._listeners: list[StatusListener] = []
        self._status: PanelStatusModel | None = None
        self._catalog: ExportCatalogModel | None = None
        # Raw snapshot behind `_catalog`, kept for the export endpoints that
        # need fields the API model does not carry. Never handed to the
        # user-write preflight: that must validate against its own fresh read.
        self._catalog_snapshot: ExportCatalogSnapshot | None = None
        # Freshness bookkeeping for the demand-driven cache, in monotonic time
        # so a wall-clock jump cannot make a stale catalog look current.
        self._catalog_completed_monotonic: float | None = None
        self._catalog_started_monotonic_for_cache: float = float("-inf")
        self._catalog_pull_task: asyncio.Task[None] | None = None
        self._catalog_pull_started_monotonic: float = float("-inf")
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
        # When the previous diagnostics run left a wireless temperature
        # unresolved, the next (fast-retry) run re-polls only those devices
        # instead of the whole bus. None => a full diagnostics sweep.
        self._diagnostics_targeted_device_ids: list[int] | None = None
        self._status_session: PersistentSnapshotSession | None = None
        # Event loop captured at start() so the session's stream-reader thread
        # can hand device-state edges back via call_soon_threadsafe.
        self._loop: asyncio.AbstractEventLoop | None = None
        self._pending_stream_states: deque[dict[int, str]] = deque()
        self._stream_emit_scheduled = False
        self._stream_emit_tasks: set[asyncio.Task[None]] = set()

    # ------------------------------------------------------------------ config

    def _catalog_pull_config(self, session: PersistentSnapshotSession | None = None) -> CatalogPullConfig:
        return CatalogPullConfig(
            flexi_cfg_device=self._config.flexi_cfg_device,
            port=self._config.port,
            auth_code=self._config.auth_code,
            reset=self._config.reset,
            read_cleanup_mode=self._config.read_cleanup_mode,
            trigger_session=session,
        )

    def _write_failure_hint(self) -> str | None:
        """Hint appended to a refused storage write when no write code is set."""

        if self._config.write_auth_code or self._write_transport() == "hid":
            return None
        return _WRITE_CODE_HINT

    def _write_transport(self) -> str:
        return resolve_write_transport(self._user_manager_config())

    def _user_manager_config(self) -> UserManagerConfig:
        return UserManagerConfig(
            import_path=self._config.import_path,
            flexi_cfg_device=self._config.flexi_cfg_device,
            port=self._config.port,
            auth_code=self._config.auth_code,
            write_auth_code=self._config.write_auth_code,
            reset=self._config.reset,
            mount_tool=self._config.mount_tool,
            stage_mode=self._config.stage_mode,
            write_cleanup_mode=self._config.write_cleanup_mode,
            read_cleanup_mode=self._config.read_cleanup_mode,
            write_transport=getattr(self._config, "write_transport", "auto"),
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
        self._loop = asyncio.get_running_loop()
        await self.refresh_all()
        self._poller_task = asyncio.create_task(self._poll_loop(), name="jablotron-panel-poller")
        LOGGER.info(
            "Panel runtime started: user writes use the %s transport and log in with %s; in_session=%s",
            self._write_transport(),
            "the separate write code" if self._config.write_auth_code else "the session code",
            self._config.in_session_config_ops,
        )

    async def close(self) -> None:
        LOGGER.info("Stopping panel runtime")
        self._closed = True
        # Stop accepting stream-reader callbacks before tearing the session down.
        self._loop = None
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

    # ----------------------------------------------- live device-state stream

    def _on_device_states_changed(self, states: dict[int, str]) -> None:
        """Called from the session's stream-reader thread on any latched device
        on/off change. Hands the work to the event loop and returns immediately;
        never touches the asyncio lock or self._status from the worker thread."""
        loop = self._loop
        if loop is None:
            return
        try:
            loop.call_soon_threadsafe(self._handle_stream_device_states, states)
        except RuntimeError:
            # Loop already closed during shutdown; nothing to deliver.
            pass

    def _handle_stream_device_states(self, states: dict[int, str]) -> None:
        # Runs on the event loop. Preserve every latched edge in callback order:
        # HA motion automations need to observe the rising "on" transition even
        # if a following "off" is already queued before the emit task gets CPU.
        self._pending_stream_states.append(dict(states))
        if len(self._pending_stream_states) > 2:
            self._compact_pending_stream_states()
        if not self._stream_emit_scheduled:
            self._stream_emit_scheduled = True
            task = asyncio.create_task(self._emit_stream_status())
            # Keep a strong reference so the task is not GC'd mid-flight.
            self._stream_emit_tasks.add(task)
            task.add_done_callback(self._stream_emit_tasks.discard)

    async def _emit_stream_status(self) -> None:
        try:
            while self._pending_stream_states:
                states = self._pending_stream_states.popleft()
                base = self._status
                if base is None:
                    continue
                devices = [
                    device.model_copy(update={"state": states[device.id]}) if device.id in states else device
                    for device in base.devices
                ]
                status = base.model_copy(update={"devices": devices, "source": "stream", "refreshed_at": utc_now()})
                self._status = status
                await self._emit("status", status.model_dump(mode="json"))
        finally:
            self._stream_emit_scheduled = False
            if self._pending_stream_states:
                if len(self._pending_stream_states) > 2:
                    self._compact_pending_stream_states()
                self._stream_emit_scheduled = True
                task = asyncio.create_task(self._emit_stream_status())
                self._stream_emit_tasks.add(task)
                task.add_done_callback(self._stream_emit_tasks.discard)

    def _compact_pending_stream_states(self) -> None:
        """Bound sustained-motion backlog without losing rising motion edges.

        Stream callbacks carry full latched state maps. When websocket delivery is
        slower than incoming PIR changes, replaying every old full snapshot makes
        HA display stale motion tens of seconds late. Compact pending frames to at
        most a synthetic rising-edge frame plus the latest frame: listeners still
        observe any not-yet-published ``off -> on`` transition, then catch up to
        the current panel state immediately.
        """
        if len(self._pending_stream_states) <= 2:
            return
        frames = list(self._pending_stream_states)
        latest = frames[-1]
        base_states = {
            device.id: device.state
            for device in self._status.devices
        } if self._status is not None else {}

        rising_frame = dict(latest)
        has_rising = False
        for frame in frames:
            for device_id, state in frame.items():
                if state == "on" and base_states.get(device_id) != "on":
                    rising_frame[device_id] = "on"
                    has_rising = True

        self._pending_stream_states.clear()
        if has_rising and rising_frame != latest:
            self._pending_stream_states.append(rising_frame)
        self._pending_stream_states.append(latest)

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
                diagnostics_device_ids=self._diagnostics_targeted_device_ids if include_diagnostics else None,
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
                unresolved_temp_device_ids = [
                    device.id
                    for device in status.devices
                    if device.wireless
                    and (device.inferred_device_type or "") in {"thermometer", "thermostat"}
                    and device.temperature is None
                ]
                if unresolved_temp_device_ids:
                    # Chase the missing temperature(s) on a 5-minute cadence, and
                    # target only those devices next time so the retry is a short
                    # sweep rather than the whole bus (which froze the real-time
                    # reader). A permanently-None sensor stays harmless: the
                    # cooperative sweep never blocks motion.
                    self._next_diagnostics_refresh_monotonic = time.monotonic() + 300.0
                    self._diagnostics_targeted_device_ids = unresolved_temp_device_ids
                else:
                    self._next_diagnostics_refresh_monotonic = time.monotonic() + 3600.0
                    self._diagnostics_targeted_device_ids = None
            if include_full_refresh or include_diagnostics:
                self._next_full_refresh_monotonic = time.monotonic() + self._config.full_refresh_interval_seconds
        await self._emit("status", status.model_dump(mode="json"))
        return status

    # ------------------------------------------------------------ catalog cache
    #
    # Demand-driven, never scheduled. There is no timer, no poll-loop hook and
    # no background task that refreshes the catalog: a pull happens only when a
    # request arrives whose freshness requirement the cache cannot meet at that
    # moment, so an idle server does no panel work at all. This is deliberate —
    # every catalog read enters the panel's configuration mode (the panel only
    # materialises EXPORT.CFG inside a session; see docs/panel-export-freshness.md),
    # and that is not something to do on a timer.
    #
    # `max_age_seconds` conventions, shared by every read below:
    #   None  -> use the configured default (`catalog_max_age_seconds`, finite)
    #   0     -> require a pull that STARTED at or after this call arrived
    #   inf   -> any cached catalog will do, however old
    #   n > 0 -> cache is acceptable if it completed within n seconds

    def _resolved_max_age(self, max_age_seconds: float | None) -> float:
        if max_age_seconds is None:
            return self._config.catalog_max_age_seconds
        return float(max_age_seconds)

    def _catalog_meets(self, max_age_seconds: float, requested_at: float) -> bool:
        if self._catalog is None or self._catalog_completed_monotonic is None:
            return False
        if max_age_seconds == math.inf:
            return True
        if max_age_seconds <= 0:
            # A pull that began before this request arrived answers a question
            # about a panel state that predates the request. `board` reads with
            # max_age=0 immediately before deleting panel entries, so "started
            # earlier" is not good enough — chain another pull instead.
            return self._catalog_started_monotonic_for_cache >= requested_at
        return (time.monotonic() - self._catalog_completed_monotonic) <= max_age_seconds

    def _inflight_meets(self, max_age_seconds: float, requested_at: float) -> bool:
        if self._catalog_pull_task is None:
            return False
        if max_age_seconds <= 0:
            return self._catalog_pull_started_monotonic >= requested_at
        return True

    async def _ensure_catalog(self, *, max_age_seconds: float, prefix: str) -> bool:
        """Make the cache satisfy ``max_age_seconds``. Returns True if untouched.

        Single-flight: concurrent requests that need a pull join the one
        in-flight pull instead of queueing several behind the panel lock. With
        a ~16 s pull and three clients that is the difference between one
        interruption of the panel and three.
        """

        requested_at = time.monotonic()
        served_from_cache = True
        while not self._catalog_meets(max_age_seconds, requested_at):
            task = self._catalog_pull_task
            if task is None:
                served_from_cache = False
                started_at = time.monotonic()
                self._catalog_pull_started_monotonic = started_at
                task = asyncio.create_task(
                    self._pull_catalog_into_cache(started_at=started_at, prefix=prefix)
                )
                self._catalog_pull_task = task
            elif self._inflight_meets(max_age_seconds, requested_at):
                served_from_cache = False
            # Shielded: a client that disconnects mid-wait must not cancel a
            # panel read the other waiters are relying on.
            await asyncio.shield(task)
        return served_from_cache

    async def _pull_catalog_into_cache(self, *, started_at: float, prefix: str) -> None:
        try:
            async with self._lock:
                snapshot = await self._pull_catalog_snapshot_locked(prefix)
                self._catalog_snapshot = snapshot
                self._catalog = _catalog_to_model(
                    snapshot,
                    as_of=utc_now(),
                    source="panel",
                    # Every catalog read triggers the F-Link export refresh
                    # sequence, which is the only thing that materialises
                    # EXPORT.CFG on the FlexiCFG volume.
                    trigger_used=True,
                )
                self._catalog_started_monotonic_for_cache = started_at
                self._catalog_completed_monotonic = time.monotonic()
                LOGGER.info(
                    "Panel catalog refreshed: sections=%s pgs=%s devices=%s users=%s "
                    "initial_setup_exact=%s took=%.1fs",
                    len(self._catalog.sections),
                    len(self._catalog.pgs),
                    len(self._catalog.devices),
                    len(self._catalog.users),
                    None if self._catalog.initial_setup is None else self._catalog.initial_setup.exact,
                    self._catalog_completed_monotonic - started_at,
                )
                if self._status_session is not None:
                    # configure_live_devices takes the session's I/O lock, which
                    # a worker may hold for tens of seconds now that the session
                    # stays alive through pulls; the event-loop thread never
                    # blocks on it (a cancelled to_thread leaves its worker
                    # running, the asyncio lock already released).
                    await asyncio.to_thread(self._configure_session_live_devices, self._status_session)
            await self._emit("catalog", self._catalog.model_dump(mode="json"))
        finally:
            self._catalog_pull_task = None

    async def _catalog_model(
        self, *, max_age_seconds: float | None, prefix: str
    ) -> ExportCatalogModel:
        requested_at = time.monotonic()
        served_from_cache = await self._ensure_catalog(
            max_age_seconds=self._resolved_max_age(max_age_seconds), prefix=prefix
        )
        catalog = self._catalog
        if catalog is None:  # pragma: no cover - _ensure_catalog guarantees one
            raise RuntimeError("Panel catalog unavailable after a read.")
        # The causal fact, in this process's monotonic clock: did the pull behind
        # what we are about to return begin at or after this call arrived? A client
        # cannot derive it — it has no access to this clock, and wall clocks across
        # two hosts are exactly what this backstops.
        started = self._catalog_started_monotonic_for_cache
        began_after = None if started is None else started >= requested_at
        if served_from_cache:
            return catalog.model_copy(
                update={"source": "cache", "pull_started_after_request": began_after}
            )
        return catalog.model_copy(update={"pull_started_after_request": began_after})

    async def refresh_catalog(self) -> ExportCatalogModel:
        """Force a panel read and replace the cache. Never serves the cache."""

        return await self._catalog_model(max_age_seconds=0.0, prefix="api-server-catalog")

    async def get_status(self) -> PanelStatusModel:
        if self._status is None:
            return await self.refresh_status()
        return self._status

    async def get_catalog(self, max_age_seconds: float | None = None) -> ExportCatalogModel:
        return await self._catalog_model(
            max_age_seconds=max_age_seconds, prefix="api-server-catalog"
        )

    async def get_users(self, max_age_seconds: float | None = None) -> list[UserModel]:
        catalog = await self.get_catalog(max_age_seconds)
        return filter_users_for_clients(catalog.users, catalog.initial_setup)

    async def get_user(
        self, user_id: int, max_age_seconds: float | None = None
    ) -> UserModel | None:
        for user in await self.get_users(max_age_seconds):
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

    async def get_export_users(self, max_age_seconds: float | None = None) -> list[UserModel]:
        return (await self.get_catalog(max_age_seconds)).users

    async def get_export_time_limits(self) -> list[dict[str, object]]:
        catalog = await self._refresh_export_snapshot()
        return export_time_limits_payload(catalog)

    async def get_export_communications(self) -> dict[str, object]:
        catalog = await self._refresh_export_snapshot()
        return export_communications_payload(catalog)

    async def _refresh_export_snapshot(self) -> ExportCatalogSnapshot:
        """Always-fresh snapshot for the raw config-inspection endpoints.

        These two endpoints keep the always-pull semantics they have always
        had (`max_age_seconds=0`): they exist to inspect the panel's actual
        configuration, where a cached answer is a footgun, and they are called
        rarely. What changes is only their behaviour under concurrency —
        routing them through the shared machinery means they join an in-flight
        pull that started after they arrived instead of stacking pulls behind
        the panel lock. They deliberately take no `max_age_seconds` parameter.
        """

        await self._ensure_catalog(max_age_seconds=0.0, prefix="api-server-export")
        snapshot = self._catalog_snapshot
        if snapshot is None:  # pragma: no cover - a completed pull always stores one
            raise RuntimeError("Export catalog snapshot unavailable after a panel read.")
        return snapshot

    async def _pull_catalog_snapshot_locked(self, output_prefix: str) -> ExportCatalogSnapshot:
        """Caller holds self._lock. In-session mode the export refresh runs
        inside the status session (which stays open, so motion keeps
        streaming); legacy mode closes it and uses a separate login + cleanup
        session as before. A SystemExit from the pull tooling or an
        ExportRefreshIncomplete from the session reaches the HTTP layer as a
        RuntimeError (409) instead of stopping the server."""
        session = await self._prepare_panel_config_op_locked()
        LOGGER.info(
            "Pulling export catalog snapshot: prefix=%s reset=%s cleanup_mode=%s in_session=%s",
            output_prefix,
            self._config.reset,
            self._config.read_cleanup_mode,
            session is not None,
        )
        catalog = await _run_panel_io(
            pull_catalog_snapshot,
            self._catalog_pull_config(session),
            output_prefix,
            sleep=time.sleep,
            label="Panel catalog read failed",
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

    def _snapshot_code_format(self, snapshot: ExportCatalogSnapshot) -> CodeFormat:
        main_config = snapshot.main_config
        return resolve_code_format(
            catalog_code_length=main_config.code_len_raw if main_config is not None else None,
            catalog_code_prefix=main_config.code_prefix if main_config is not None else None,
            server_auth_code=self._config.auth_code or None,
        )

    def _user_write_preflight(
        self,
        snapshot: ExportCatalogSnapshot,
        user_id: int,
        *,
        include_current: bool,
    ) -> UserWritePreflight:
        """Bind a freshly read user table to the write about to happen.

        Read-then-decide: the rules are applied to the table as it is now,
        read under the same lock that then performs the write, so the
        decision cannot be made against a cached table that no longer
        exists. The code format comes from the same read rather than from
        the cached catalog.
        """

        if snapshot is self._catalog_snapshot:
            # Structural guard, not a style rule. The duplicate, code-format
            # and duress-adjacency rules only mean anything against the table
            # the panel holds right now: a preflight that passes against a
            # cached table can assign a code that is another user's silent-panic
            # twin. If the catalog cache is ever wired in here, fail loudly.
            raise RuntimeError(
                "User-write preflight must validate against a fresh panel read, "
                "not the cached catalog snapshot."
            )
        return UserWritePreflight.from_records(
            snapshot.users,
            user_id=user_id,
            code_format=self._snapshot_code_format(snapshot),
            include_current=include_current,
        )

    async def _prepare_panel_config_op_locked(self) -> PersistentSnapshotSession | None:
        """Caller holds self._lock. In-session mode: make sure a status session
        object exists (it logs in lazily on first use) and return it. Legacy
        mode: close the status session so a separate client can log in, as
        before, and return None. Call it immediately before the panel
        operation, after any step that may close the session (in legacy mode
        the preflight pull still does): a session fetched earlier would have
        been closed and detached, and would live on as an orphan second login
        on the device."""
        if self._config.in_session_config_ops:
            if self._status_session is None:
                self._status_session = self._create_status_session()
            return self._status_session
        await self._close_status_session_locked()
        return None

    async def add_user(self, payload: UserCreateModel, *, replace: bool = False) -> UserModel:
        self._ensure_usable_user_id(payload.id)
        async with self._lock:
            snapshot = await self._pull_catalog_snapshot_locked(
                f"api-preflight-add-user{payload.id}"
            )
            # The panel's import is an upsert, so a create aimed at an
            # occupied slot would silently overwrite its user. Decided on the
            # table just read, never on the cache: a stale "occupied" would
            # refuse a slot F-Link has since freed, and a stale "free" is the
            # overwrite this check exists to prevent.
            occupant = next(
                (record for record in snapshot.users if record.user_id == payload.id), None
            )
            if occupant is not None and (occupant.name or "").strip() and not replace:
                raise UserSlotOccupied(payload.id)
            preflight = self._user_write_preflight(
                snapshot, payload.id, include_current=False
            )
            session = await self._prepare_panel_config_op_locked()
            await _run_panel_write(
                _apply_upsert_user,
                self._user_manager_config(),
                failure_hint=self._write_failure_hint(),
                user_id=payload.id,
                payload=payload,
                current=None,
                preflight=preflight,
                verify_prefix=f"api-add-user{payload.id}",
                session=session,
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
        # Any cached view will do for the existence check: the fresh read
        # taken under the lock below is the authority for both the preflight
        # and the carried-over field values, so making this lookup pull too
        # would just spend a second ~16 s panel session on the same answer.
        current = await self.get_user(user_id, max_age_seconds=math.inf)
        if current is None:
            raise RuntimeError(f"User {user_id} not found.")
        current_record = user_to_record(current)
        async with self._lock:
            snapshot = await self._pull_catalog_snapshot_locked(
                f"api-preflight-edit-user{user_id}"
            )
            preflight = self._user_write_preflight(snapshot, user_id, include_current=True)
            fresh_record = next(
                (record for record in snapshot.users if record.user_id == user_id), None
            )
            if fresh_record is not None:
                # Carry unsupplied fields over from the table we just read,
                # not from the poller's cache, so an edit cannot silently
                # rewrite a field with a value the panel has since changed.
                current_record = user_to_record(_user_to_model(fresh_record))
            session = await self._prepare_panel_config_op_locked()
            await _run_panel_write(
                _apply_upsert_user,
                self._user_manager_config(),
                failure_hint=self._write_failure_hint(),
                user_id=user_id,
                payload=payload,
                current=current_record,
                preflight=preflight,
                verify_prefix=f"api-edit-user{user_id}",
                session=session,
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
            session = await self._prepare_panel_config_op_locked()
            await _run_panel_write(
                _apply_delete_user,
                self._user_manager_config(),
                failure_hint=self._write_failure_hint(),
                user_id=user_id,
                verify_prefix=f"api-delete-user{user_id}",
                session=session,
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
        session = PersistentSnapshotSession(
            port=self._config.port,
            code=self._config.auth_code,
            reset=self._config.reset,
        )
        session.set_on_device_state_change(self._on_device_states_changed)
        self._configure_session_live_devices(session)
        return session

    def _configure_session_live_devices(self, session: PersistentSnapshotSession) -> None:
        if self._catalog is None:
            return
        session.configure_live_devices(
            self._catalog.devices,
            pg_count=len(self._catalog.pgs),
            panel_model=self._system_info.get("panel_model"),
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
