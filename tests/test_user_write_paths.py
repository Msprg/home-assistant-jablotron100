"""The HTTP write path must run the same user-table rules as the CLI.

Every test here stays offline: the panel-touching calls are replaced, and the
assertions are about *what would have been written* and whether the refusal
arrives before anything reaches the panel.
"""

from __future__ import annotations

import asyncio
import math
from pathlib import Path
from types import SimpleNamespace
import time

import pytest
from fastapi.testclient import TestClient

import jablotron_re_tools as re_tools
import jablotron_user_tool
from jablotron_api.domain.codes import CodeFormat
from jablotron_api.domain.models import (
    DEFAULT_ADMIN_SCOPES,
    ExportCatalogModel,
    InitialSetupModel,
    InitialSetupRangeModel,
    UserCreateModel,
    UserModel,
    UserPatchModel,
)
from jablotron_api.domain.user_validation import (
    REASON_CODE_LENGTH_UNKNOWN,
    REASON_COMMENT_TOO_LONG,
    REASON_NAME_TOO_LONG,
    REASON_PANIC_CODE_COLLISION,
    UserSlotOccupied,
    UserTableEntry,
    UserWriteRejected,
    UserWriteViolation,
)
from jablotron_api.panel.demo import DemoPanelRuntime
import jablotron_api.panel.runtime as runtime_module
from jablotron_api.panel.runtime import PanelRuntime, PanelRuntimeConfig
from jablotron_api.protocol import legacy
from jablotron_api.server.app import create_app
from jablotron_api.server.config import ServerSettings
import jablotron_api.services.user_manager as user_manager
from jablotron_api.services.user_manager import (
    UserManagerConfig,
    UserWritePreflight,
    apply_upsert,
)
from jablotron_api.services.storage import TokenStore


class _Record:
    """Stand-in for the RE tools' UserRecord as read from a panel export."""

    def __init__(self, user_id, code="", cards=(), time_limited_group_raw=None, name=""):
        self.user_id = user_id
        self.code = code
        self.cards = list(cards)
        self.time_limited_group_raw = time_limited_group_raw
        self.name = name


def _manager_config(tmp_path: Path) -> UserManagerConfig:
    return UserManagerConfig(
        import_path=tmp_path / "IMPORT.CFG",
        flexi_cfg_device="/dev/null",
        port="auto",
        auth_code="1812",
        write_auth_code="",
        reset=True,
        mount_tool="sudo",
        stage_mode="filesystem",
        write_cleanup_mode="auto",
        read_cleanup_mode="auto",
    )


def _stub_sector(monkeypatch, tmp_path: Path, summary: dict) -> list:
    """Replace the sector builder and the panel write; record any write."""

    sector_path = tmp_path / "sector.bin"
    sector_path.write_bytes(b"")
    writes: list = []

    monkeypatch.setattr(
        user_manager,
        "build_upsert_sector",
        lambda args, *, current: (sector_path, summary, False),
    )
    monkeypatch.setattr(
        user_manager,
        "apply_import_sector",
        lambda **kwargs: writes.append(kwargs),
    )
    # The "auto" transport asks the panel which rights the write code has;
    # answer "ARC" so these tests keep exercising the storage path.
    monkeypatch.setattr(
        user_manager,
        "probe_login_rights",
        lambda **kwargs: re_tools.LoginRights(rights_raw=re_tools.LOGIN_RIGHTS_ARC, position=7),
    )
    return writes


# ------------------------------------------------------ services/user_manager


def test_apply_upsert_refuses_a_panic_collision_before_touching_the_panel(
    monkeypatch, tmp_path: Path
) -> None:
    writes = _stub_sector(monkeypatch, tmp_path, {"code": "1484", "cards": [], "time_limited_group_raw": 0})
    preflight = UserWritePreflight.from_records(
        [_Record(7, "1483")],
        user_id=4,
        code_format=CodeFormat(4, False, "panel"),
        include_current=False,
    )

    with pytest.raises(UserWriteRejected) as excinfo:
        apply_upsert(
            _manager_config(tmp_path),
            user_id=4,
            payload=UserCreateModel(id=4, name="New", code="1484"),
            current=None,
            preflight=preflight,
            verify_prefix="test",
        )

    assert excinfo.value.reason == REASON_PANIC_CODE_COLLISION
    assert excinfo.value.conflicting_user_ids == (7,)
    assert writes == [], "the panel must not be written when validation refuses"


def test_apply_upsert_writes_when_the_record_is_legal(monkeypatch, tmp_path: Path) -> None:
    writes = _stub_sector(monkeypatch, tmp_path, {"code": "1486", "cards": [], "time_limited_group_raw": 0})
    preflight = UserWritePreflight.from_records(
        [_Record(7, "1483")],
        user_id=4,
        code_format=CodeFormat(4, False, "panel"),
        include_current=False,
    )

    apply_upsert(
        _manager_config(tmp_path),
        user_id=4,
        payload=UserCreateModel(id=4, name="New", code="1486"),
        current=None,
        preflight=preflight,
        verify_prefix="test",
    )

    assert len(writes) == 1


def test_apply_upsert_can_use_a_write_only_auth_code(monkeypatch, tmp_path: Path) -> None:
    writes = _stub_sector(monkeypatch, tmp_path, {"code": "1486", "cards": [], "time_limited_group_raw": 0})
    config = _manager_config(tmp_path)
    config.write_auth_code = "9999"

    apply_upsert(
        config,
        user_id=4,
        payload=UserCreateModel(id=4, name="New", code="1486"),
        current=None,
        preflight=UserWritePreflight(code_format=CodeFormat(4, False, "panel")),
        verify_prefix="test",
    )

    assert writes[0]["code"] == "9999"


def test_apply_upsert_validates_the_encoded_record_not_the_request(
    monkeypatch, tmp_path: Path
) -> None:
    """A patch that omits `code` still writes the carried-over code."""

    # The request only renames the user; the sector builder carries the panel's
    # existing code into the record, and that code is what gets validated.
    writes = _stub_sector(monkeypatch, tmp_path, {"code": "1484", "cards": [], "time_limited_group_raw": 0})
    preflight = UserWritePreflight.from_records(
        [_Record(7, "1483"), _Record(4, "9999")],
        user_id=4,
        code_format=CodeFormat(4, False, "panel"),
        include_current=True,
    )

    with pytest.raises(UserWriteRejected):
        apply_upsert(
            _manager_config(tmp_path),
            user_id=4,
            payload=UserPatchModel(name="Renamed"),
            current=SimpleNamespace(),
            preflight=preflight,
            verify_prefix="test",
        )
    assert writes == []


def test_apply_upsert_allows_an_edit_that_keeps_a_preexisting_collision(
    monkeypatch, tmp_path: Path
) -> None:
    writes = _stub_sector(monkeypatch, tmp_path, {"code": "1484", "cards": [], "time_limited_group_raw": 0})
    preflight = UserWritePreflight.from_records(
        [_Record(7, "1483"), _Record(4, "1484")],
        user_id=4,
        code_format=CodeFormat(4, False, "panel"),
        include_current=True,
    )

    apply_upsert(
        _manager_config(tmp_path),
        user_id=4,
        payload=UserPatchModel(name="Renamed"),
        current=SimpleNamespace(),
        preflight=preflight,
        verify_prefix="test",
    )

    assert len(writes) == 1


def test_apply_upsert_refuses_when_the_panels_code_length_is_unknown(
    monkeypatch, tmp_path: Path
) -> None:
    writes = _stub_sector(monkeypatch, tmp_path, {"code": "1483", "cards": [], "time_limited_group_raw": 0})
    preflight = UserWritePreflight.from_records(
        [],
        user_id=4,
        code_format=CodeFormat(None, None, "unknown"),
        include_current=False,
    )

    with pytest.raises(UserWriteRejected) as excinfo:
        apply_upsert(
            _manager_config(tmp_path),
            user_id=4,
            payload=UserCreateModel(id=4, name="New", code="1483"),
            current=None,
            preflight=preflight,
            verify_prefix="test",
        )
    assert excinfo.value.reason == REASON_CODE_LENGTH_UNKNOWN
    assert writes == []


def test_preflight_from_records_picks_up_the_users_own_row():
    preflight = UserWritePreflight.from_records(
        [_Record(7, "1483"), _Record(4, "1484", cards=["00123456", ""])],
        user_id=4,
        code_format=CodeFormat(4, False, "panel"),
        include_current=True,
    )
    assert preflight.current == UserTableEntry(4, "1484", ("00123456",), None)
    assert len(preflight.existing) == 2


def test_preflight_from_records_omits_current_for_a_create():
    preflight = UserWritePreflight.from_records(
        [_Record(4, "1484")],
        user_id=4,
        code_format=CodeFormat(4, False, "panel"),
        include_current=False,
    )
    assert preflight.current is None


# ---------------------------------------------------------------- panel runtime


class _FakeConfigSession:
    """Stand-in for the persistent status session as the runtime and the
    user manager see it. Shared with other test files. A write through it
    is a test failure: these tests exercise the separate-client stubs."""

    def __init__(self) -> None:
        self.closes = 0

    def login_rights_for_code(self, code):
        return None

    def write_configuration(self, payload, *, code=None):
        pytest.fail("the fake status session must not be written through")

    def close(self) -> None:
        self.closes += 1

    def trigger_export(self) -> None:
        return None

    def finish_export(self) -> None:
        return None

    def configure_live_devices(self, devices, *, pg_count, panel_model) -> None:
        return None

    def set_on_device_state_change(self, callback) -> None:
        return None


def _runtime() -> PanelRuntime:
    # A zero write window: every preflight reads the panel, so the tests
    # below can tell the fresh read and the cache apart.
    runtime = PanelRuntime(
        PanelRuntimeConfig(port="auto", auth_code="1812", write_preflight_max_age_seconds=0.0)
    )
    # A status session object so _prepare_panel_config_op_locked never
    # constructs a real one (that would look for the USB device).
    runtime._status_session = _FakeConfigSession()
    # A cached catalog that knows the user range but holds NO users: anything
    # the rules find has to have come from the fresh read.
    runtime._catalog = ExportCatalogModel(
        sections=[],
        pgs=[],
        devices=[],
        users=[],
        initial_setup=InitialSetupModel(
            source="test",
            exact=True,
            users=InitialSetupRangeModel(first_id=1, last_id=100, count=100),
        ),
    )
    return runtime


def _snapshot(users, *, code_len=4, code_prefix=False):
    return SimpleNamespace(
        users=users,
        main_config=SimpleNamespace(code_len_raw=code_len, code_prefix=code_prefix),
    )


def _route_refresh(monkeypatch, runtime: PanelRuntime) -> list[tuple[str, bool]]:
    """Replace the cache refresh with one that takes its snapshot from the
    runtime's (patched) ``_pull_catalog_snapshot_locked`` and keeps the
    freshness bookkeeping, but skips the API-model conversion these minimal
    snapshots cannot go through. Returns the recorded (prefix, after_write)
    pairs: the preflight pull and the one post-write refresh."""

    refreshes: list[tuple[str, bool]] = []

    async def fake_refresh(*, prefix, started_at=None, after_write=False):
        refreshes.append((prefix, after_write))
        started = time.monotonic() if started_at is None else started_at
        snapshot = await runtime._pull_catalog_snapshot_locked(prefix, after_write=after_write)
        runtime._catalog_snapshot = snapshot
        runtime._catalog_started_monotonic_for_cache = started
        runtime._catalog_completed_monotonic = time.monotonic()
        runtime._catalog_dirty = False
        return snapshot

    monkeypatch.setattr(runtime, "_refresh_catalog_locked", fake_refresh)
    return refreshes


def test_runtime_takes_the_code_format_from_the_snapshot_it_just_read() -> None:
    runtime = _runtime()
    fmt = runtime._snapshot_code_format(_snapshot([], code_len=6, code_prefix=True))
    assert fmt == CodeFormat(6, True, "panel")


def test_runtime_passes_write_auth_code_only_to_user_writes() -> None:
    runtime = PanelRuntime(PanelRuntimeConfig(port="auto", auth_code="1812", write_auth_code="9999"))

    assert runtime._catalog_pull_config().auth_code == "1812"
    assert runtime._event_reader_config().auth_code == "1812"
    manager_config = runtime._user_manager_config()
    assert manager_config.auth_code == "1812"
    assert manager_config.write_auth_code == "9999"


def test_runtime_falls_back_to_the_session_code_when_main_config_is_absent() -> None:
    runtime = _runtime()
    snapshot = SimpleNamespace(users=[], main_config=None)
    fmt = runtime._snapshot_code_format(snapshot)
    # The panel accepted this auth code, so its length is evidence rather than
    # a guess — but the source is reported as inferred, not panel.
    assert fmt == CodeFormat(4, False, "inferred")


def test_runtime_validates_against_a_fresh_read_not_the_cached_catalog(monkeypatch) -> None:
    """The cached catalog is empty; the fresh read is what must decide."""

    runtime = _runtime()
    captured: dict = {}

    async def fake_pull(prefix: str, *, after_write: bool = False):
        return _snapshot([_Record(7, "1483")])

    def fake_apply(config, **kwargs):
        captured["preflight"] = kwargs["preflight"]

    async def fake_close() -> None:
        return None

    monkeypatch.setattr(runtime, "_pull_catalog_snapshot_locked", fake_pull)
    monkeypatch.setattr(runtime, "_close_status_session_locked", fake_close)
    monkeypatch.setattr(runtime_module, "_apply_upsert_user", fake_apply)
    refreshes = _route_refresh(monkeypatch, runtime)
    monkeypatch.setattr(
        runtime,
        "get_user",
        lambda user_id, max_age_seconds=None: _async_value(None),
    )

    async def run() -> None:
        with pytest.raises(RuntimeError):
            # The post-write lookup fails (get_user returns None); by then the
            # preflight has already been built and handed to the write.
            await runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))

    asyncio.run(run())

    assert refreshes[0] == ("api-preflight-add-user4", False)
    assert captured["preflight"].existing == (UserTableEntry(7, "1483", (), None),)
    assert captured["preflight"].code_format == CodeFormat(4, False, "panel")


def test_a_refused_panel_write_is_a_runtime_error_not_a_process_exit(monkeypatch) -> None:
    """The write tooling signals a refused IMPORT.CFG write with SystemExit.
    Out of asyncio.to_thread that stopped uvicorn (the container restarted on
    2026-09-25); it must reach the HTTP layer as RuntimeError, i.e. 409."""

    runtime = _runtime()

    async def fake_pull(prefix: str, *, after_write: bool = False):
        return _snapshot([])

    def refused(config, **kwargs):
        raise SystemExit("IMPORT.CFG staging failed: [Errno 5] Input/output error")

    async def fake_close() -> None:
        return None

    monkeypatch.setattr(runtime, "_pull_catalog_snapshot_locked", fake_pull)
    monkeypatch.setattr(runtime, "_close_status_session_locked", fake_close)
    monkeypatch.setattr(runtime_module, "_apply_upsert_user", refused)
    monkeypatch.setattr(runtime_module, "_apply_delete_user", refused)
    refreshes = _route_refresh(monkeypatch, runtime)

    async def run() -> None:
        with pytest.raises(RuntimeError, match="Panel write failed: IMPORT.CFG staging failed"):
            await runtime.add_user(UserCreateModel(id=4, name="New"))
        with pytest.raises(RuntimeError, match="Panel write failed"):
            await runtime.delete_user(4)

    asyncio.run(run())
    # A refused write gets no post-write refresh; it marks the cache dirty.
    assert refreshes == [("api-preflight-add-user4", False)]
    assert runtime._catalog_dirty is True


def test_runtime_hands_the_status_session_to_the_write(monkeypatch) -> None:
    runtime = _runtime()
    captured: dict = {}
    closes: list[bool] = []

    def fake_apply(config, **kwargs):
        captured["session"] = kwargs["session"]

    async def fake_close() -> None:
        closes.append(True)

    async def fake_pull(prefix: str, *, after_write: bool = False):
        return _snapshot([])

    monkeypatch.setattr(runtime, "_close_status_session_locked", fake_close)
    monkeypatch.setattr(runtime, "_pull_catalog_snapshot_locked", fake_pull)
    monkeypatch.setattr(runtime_module, "_apply_delete_user", fake_apply)
    _route_refresh(monkeypatch, runtime)
    monkeypatch.setattr(runtime, "get_user", lambda user_id, max_age_seconds=None: _async_value(None))

    asyncio.run(runtime.delete_user(4))
    assert captured["session"] is runtime._status_session
    assert captured["session"] is not None
    assert closes == [], "in-session mode keeps the status session open across the write"

    # The rollback switch: the session is closed and the write gets no session.
    runtime._config.in_session_config_ops = False
    asyncio.run(runtime.delete_user(4))
    assert captured["session"] is None
    assert closes == [True]


def test_the_post_write_refresh_is_flagged_after_write(monkeypatch) -> None:
    """Each write ends with exactly one catalog refresh, flagged after_write
    so the pull settles first and retries a stalled reload; the preflight
    pull is an ordinary one. No trailing refresh_catalog() follows."""

    runtime = _runtime()
    pulls: list[tuple[str, bool]] = []

    async def fake_pull(prefix: str, *, after_write: bool = False):
        pulls.append((prefix, after_write))
        return _snapshot([_full_record(4, "1486", name="Old")])

    async def no_trailing_refresh():
        pytest.fail("the write must not run a second, trailing catalog refresh")

    async def get_user(user_id, max_age_seconds=None):
        assert max_age_seconds == math.inf, "the lookup after a write is served by its own refresh"
        return None

    monkeypatch.setattr(runtime, "_pull_catalog_snapshot_locked", fake_pull)
    monkeypatch.setattr(runtime_module, "_apply_upsert_user", lambda config, **kw: None)
    monkeypatch.setattr(runtime_module, "_apply_delete_user", lambda config, **kw: None)
    monkeypatch.setattr(runtime, "refresh_catalog", no_trailing_refresh)
    refreshes = _route_refresh(monkeypatch, runtime)

    with pytest.raises(RuntimeError, match="not present after add"):
        asyncio.run(runtime.add_user(UserCreateModel(id=5, name="New", code="1484"), replace=True))
    assert refreshes == [("api-preflight-add-user5", False), ("api-after-add-user5", True)]
    assert pulls == refreshes

    refreshes.clear()
    asyncio.run(runtime.delete_user(4))
    assert refreshes == [("api-after-delete-user4", True)]


def _full_record(user_id: int, code: str, *, name: str):
    """A fresh-read row with every field user_to_model reads: the edit path
    re-derives the carried-over fields from the row it has just pulled."""

    return SimpleNamespace(
        user_id=user_id,
        code=code,
        cards=[],
        time_limited_group_raw=None,
        name=name,
        phone="",
        comment="",
        flags_raw=None,
        access_raw=None,
        section_ids=[],
        pg_ids=[],
        enabled=None,
        rights="",
    )


@pytest.mark.parametrize("operation", ["add", "edit"])
def test_the_write_gets_the_session_that_survives_the_preflight_pull(monkeypatch, operation) -> None:
    """The preflight pull still closes and detaches the status session. The
    write must receive the session object the runtime owns *after* that, not
    one fetched earlier that would log in again as an orphan second session.
    Both write paths that pull first are covered; delete has no preflight."""

    runtime = _runtime()
    first = runtime._status_session
    recorded: dict = {}
    existing = UserModel(id=4, name="Old", code="1486")
    lookups: list[int] = []

    async def fake_pull(prefix: str, *, after_write: bool = False):
        if not after_write:
            # The real close, as the legacy preflight pull does. The
            # post-write refresh is left alone so the assertions below see
            # the session the write was handed.
            await runtime._close_status_session_locked()
        return _snapshot([_full_record(4, "1486", name="Old")] if operation == "edit" else [])

    def fake_apply(config, **kwargs):
        recorded["session"] = kwargs["session"]

    async def get_user(user_id, max_age_seconds=None):
        # The edit's existence check before the write finds the user; the
        # verification lookup after the write (either path) finds nothing.
        lookups.append(user_id)
        return existing if operation == "edit" and len(lookups) == 1 else None

    monkeypatch.setattr(runtime_module, "PersistentSnapshotSession", lambda **kwargs: _FakeConfigSession())
    monkeypatch.setattr(runtime, "_pull_catalog_snapshot_locked", fake_pull)
    monkeypatch.setattr(runtime_module, "_apply_upsert_user", fake_apply)
    _route_refresh(monkeypatch, runtime)
    monkeypatch.setattr(runtime, "get_user", get_user)

    if operation == "add":
        with pytest.raises(RuntimeError, match="not present after add"):
            asyncio.run(runtime.add_user(UserCreateModel(id=4, name="New", code="1484")))
    else:
        with pytest.raises(RuntimeError, match="disappeared after edit"):
            asyncio.run(runtime.edit_user(4, UserPatchModel(code="1484")))

    assert first.closes == 1
    assert recorded["session"] is not None
    assert recorded["session"] is runtime._status_session
    assert recorded["session"] is not first


def _refusing_runtime(monkeypatch, **config):
    runtime = _runtime()
    for key, value in config.items():
        setattr(runtime._config, key, value)

    async def fake_pull(prefix: str, *, after_write: bool = False):
        return _snapshot([])

    async def fake_close() -> None:
        return None

    def refused(config, **kwargs):
        raise SystemExit("IMPORT.CFG staging failed: the write raised [Errno 5] Input/output error")

    monkeypatch.setattr(runtime, "_pull_catalog_snapshot_locked", fake_pull)
    monkeypatch.setattr(runtime, "_close_status_session_locked", fake_close)
    monkeypatch.setattr(runtime_module, "_apply_upsert_user", refused)
    _route_refresh(monkeypatch, runtime)
    return runtime


def test_a_system_exit_from_the_catalog_pull_is_a_runtime_error(monkeypatch) -> None:
    """The pull tooling reports a stalled export refresh with SystemExit. Out
    of asyncio.to_thread that would stop uvicorn; it must reach the HTTP layer
    as RuntimeError (409), like a refused write does."""

    runtime = _runtime()

    def stalled(config, prefix, *, sleep=None):
        raise SystemExit("Export refresh did not reach the reload-complete state.")

    monkeypatch.setattr(runtime_module, "pull_catalog_snapshot", stalled)

    with pytest.raises(RuntimeError, match="Panel catalog read failed: Export refresh did not reach"):
        asyncio.run(runtime.refresh_catalog())

    assert runtime._status_session is not None, "an in-session pull failure leaves the session to the runtime"
    assert runtime._catalog_pull_task is None


def test_the_post_write_pull_settles_and_retries_and_reports_a_stall_as_a_catalog_failure(monkeypatch) -> None:
    runtime = _runtime()
    seen: list[dict] = []

    def stalled(config, prefix, *, sleep=None, **kwargs):
        seen.append(kwargs)
        raise runtime_module.ExportReloadStalled("Export refresh did not reach the reload-complete state.")

    monkeypatch.setattr(runtime_module, "pull_catalog_snapshot", stalled)

    async def run(after_write: bool) -> None:
        async with runtime._lock:
            await runtime._pull_catalog_snapshot_locked("test-prefix", after_write=after_write)

    with pytest.raises(RuntimeError, match="Panel catalog read failed: Export refresh did not reach"):
        asyncio.run(run(True))
    with pytest.raises(RuntimeError, match="Panel catalog read failed"):
        asyncio.run(run(False))

    assert seen == [
        {"settle_seconds": re_tools.POST_WRITE_EXPORT_SETTLE_SECONDS, "reload_retries": 3},
        {},
    ]


def test_a_missing_panel_at_session_creation_is_a_runtime_error_not_a_process_exit(monkeypatch) -> None:
    """Without a status session (startup, or right after the events read
    closed it) the in-session pull creates one on the event-loop thread.
    The port lookup reports a missing device with SystemExit; that must
    become the session's reopen backoff and a 409 from the pull, never a
    SystemExit out of the event loop (a USB dropout is a known event on
    this install)."""
    runtime = _runtime()
    runtime._status_session = None
    opens: list[str] = []

    def no_device(port):
        raise SystemExit("Unable to auto-detect Jablotron USB interface.")

    def refuse_open(port):
        opens.append(port)
        raise OSError("no such device")

    monkeypatch.setattr(legacy, "ensure_serial_port", no_device)
    monkeypatch.setattr(legacy, "JablotronUSBClient", refuse_open)

    def pull(config, prefix, *, sleep=None):
        # What the real pull does first: the export trigger on the session.
        config.trigger_session.trigger_export()
        pytest.fail("the trigger cannot succeed without a device")

    monkeypatch.setattr(runtime_module, "pull_catalog_snapshot", pull)

    with pytest.raises(RuntimeError, match="Panel catalog read failed: USB link failed before the export trigger"):
        asyncio.run(runtime.refresh_catalog())

    session = runtime._status_session
    assert isinstance(session, legacy.PersistentSnapshotSession), "the session object exists for the next poll"
    assert session._serial_port == "auto", "the configured value is kept for redetection"
    assert session._reopen_failures >= 1, "the failed detection armed the reopen backoff"
    assert opens == [], "nothing was opened under the placeholder port"
    assert runtime._catalog_pull_task is None


def test_a_refused_write_without_a_write_code_points_at_the_setting(monkeypatch) -> None:
    runtime = _refusing_runtime(monkeypatch)

    async def run() -> None:
        with pytest.raises(RuntimeError, match="JABLOTRON_PANEL_WRITE_AUTH_CODE"):
            await runtime.add_user(UserCreateModel(id=4, name="New"))

    asyncio.run(run())


def test_a_refused_write_with_a_write_code_does_not_repeat_the_hint(monkeypatch) -> None:
    runtime = _refusing_runtime(monkeypatch, write_auth_code="9999")

    async def run() -> None:
        with pytest.raises(RuntimeError) as excinfo:
            await runtime.add_user(UserCreateModel(id=4, name="New"))
        assert "JABLOTRON_PANEL_WRITE_AUTH_CODE" not in str(excinfo.value)

    asyncio.run(run())


def test_panel_codes_stay_out_of_config_reprs(tmp_path: Path) -> None:
    from jablotron_api.server.config import PanelSettings

    configs = [
        PanelSettings(auth_code="1812", write_auth_code="9999"),
        PanelRuntimeConfig(port="auto", auth_code="1812", write_auth_code="9999"),
        PanelRuntime(PanelRuntimeConfig(port="auto", auth_code="1812", write_auth_code="9999"))._user_manager_config(),
    ]
    for config in configs:
        assert "1812" not in repr(config) and "9999" not in repr(config), type(config).__name__


async def _async_value(value):
    return value


# ----------------------------------------------------------------- HTTP surface


def _client(tmp_path: Path, runtime) -> tuple[TestClient, str]:
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(label="admin", scopes=list(DEFAULT_ADMIN_SCOPES))
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    return TestClient(app), token


def _demo_client(tmp_path: Path) -> tuple[TestClient, dict, DemoPanelRuntime]:
    runtime = DemoPanelRuntime()
    client, token = _client(tmp_path, runtime)
    return client, {"Authorization": f"Bearer {token}"}, runtime


def test_http_add_user_returns_400_with_a_machine_readable_reason(tmp_path: Path) -> None:
    client, headers, _ = _demo_client(tmp_path)
    assert client.patch("/v1/users/1", json={"code": "1483"}, headers=headers).status_code == 200

    clash = client.post(
        "/v1/users", json={"id": 3, "name": "Guard 3", "code": "1484"}, headers=headers
    )
    assert clash.status_code == 400
    detail = clash.json()["detail"]
    assert detail["error"] == "user_write_rejected"
    assert detail["reason"] == REASON_PANIC_CODE_COLLISION
    assert detail["conflicting_user_ids"] == [1]
    assert "silent panic" in detail["message"]


def test_http_refusal_is_distinguishable_from_a_broken_panel(tmp_path: Path) -> None:
    """400 means "try another value"; 409 means the panel failed. Not the same."""

    client, headers, runtime = _demo_client(tmp_path)
    client.patch("/v1/users/1", json={"code": "1483"}, headers=headers)
    rejected = client.patch("/v1/users/2", json={"code": "1484"}, headers=headers)

    async def broken_write(*args, **kwargs):
        raise RuntimeError("Panel did not acknowledge the import sector.")

    runtime.edit_user = broken_write  # type: ignore[method-assign]
    broken = client.patch("/v1/users/2", json={"code": "1486"}, headers=headers)

    assert rejected.status_code == 400
    assert rejected.json()["detail"]["reason"] == REASON_PANIC_CODE_COLLISION
    assert broken.status_code == 409


def test_http_refusal_does_not_leak_another_users_code(tmp_path: Path) -> None:
    client, headers, _ = _demo_client(tmp_path)
    client.patch("/v1/users/1", json={"code": "1483"}, headers=headers)
    clash = client.patch("/v1/users/2", json={"code": "1484"}, headers=headers)
    assert clash.status_code == 400
    assert "1483" not in clash.text


def test_http_edit_user_is_validated_too(tmp_path: Path) -> None:
    client, headers, _ = _demo_client(tmp_path)
    client.patch("/v1/users/1", json={"code": "1483"}, headers=headers)

    clash = client.patch("/v1/users/2", json={"code": "1484"}, headers=headers)
    assert clash.status_code == 400
    assert clash.json()["detail"]["reason"] == REASON_PANIC_CODE_COLLISION

    # A non-adjacent code is fine, and renaming afterwards stays legal.
    assert client.patch("/v1/users/2", json={"code": "1486"}, headers=headers).status_code == 200
    assert client.patch("/v1/users/2", json={"name": "Guard 2"}, headers=headers).status_code == 200


def test_http_add_user_rejects_a_wrong_length_code(tmp_path: Path) -> None:
    client, headers, _ = _demo_client(tmp_path)
    response = client.post(
        "/v1/users", json={"id": 3, "name": "Guard 3", "code": "148300"}, headers=headers
    )
    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "invalid_user_code"


# ------------------------------------------------------------------ CLI boundary


def test_cli_preflight_raises_the_typed_refusal_not_system_exit() -> None:
    snapshot = SimpleNamespace(path=Path("/dev/null"), records=[_Record(7, "1483")])
    with pytest.raises(UserWriteRejected):
        jablotron_user_tool.validate_preflight(
            snapshot=snapshot,
            user_id=4,
            current=None,
            target={"code": "1484", "cards": [], "time_limited_group_raw": 0},
            code_format=CodeFormat(4, False, "panel"),
        )


def test_cli_main_turns_the_refusal_into_an_exit_code(monkeypatch) -> None:
    def explode(_args):
        raise UserWriteRejected(
            [UserWriteViolation(REASON_PANIC_CODE_COLLISION, "collision", (7,))]
        )

    monkeypatch.setattr(
        jablotron_user_tool,
        "build_parser",
        lambda: SimpleNamespace(parse_args=lambda: SimpleNamespace(func=explode)),
    )

    with pytest.raises(SystemExit) as excinfo:
        jablotron_user_tool.main()
    assert "Preflight validation failed" in str(excinfo.value)
    assert REASON_PANIC_CODE_COLLISION in str(excinfo.value)


# ------------------------------------------------------------------- demo panel


def test_demo_runtime_enforces_the_same_rules() -> None:
    async def run() -> None:
        runtime = DemoPanelRuntime()
        await runtime.add_user(UserCreateModel(id=3, name="Guard 3", code="1483"))
        with pytest.raises(UserWriteRejected):
            await runtime.add_user(UserCreateModel(id=4, name="Guard 4", code="1484"))
        # The mirrored direction, against a table built in the other order.
        await runtime.add_user(UserCreateModel(id=4, name="Guard 4", code="1486"))
        with pytest.raises(UserWriteRejected):
            await runtime.edit_user(4, UserPatchModel(code="1482"))

    asyncio.run(run())


# ------------------------------------------------------------- field widths


def test_apply_upsert_refuses_an_over_long_encoded_name_before_the_write(
    monkeypatch, tmp_path: Path
) -> None:
    """The summary describes the record as it would be written; that is what
    is measured, so a carried-over or defaulted value is checked too."""

    writes = _stub_sector(
        monkeypatch,
        tmp_path,
        {"name": "n" * 61, "code": "1486", "cards": [], "comment": "", "time_limited_group_raw": None},
    )
    with pytest.raises(UserWriteRejected) as excinfo:
        apply_upsert(
            _manager_config(tmp_path),
            user_id=4,
            payload=UserCreateModel(id=4, name="n" * 61, code="1486"),
            current=None,
            preflight=UserWritePreflight(code_format=CodeFormat(4, False, "panel")),
            verify_prefix="test",
        )
    assert [v.reason for v in excinfo.value.violations] == [REASON_NAME_TOO_LONG]
    assert writes == []


def test_http_add_user_rejects_over_long_fields_with_a_typed_reason(tmp_path: Path) -> None:
    client, headers, _ = _demo_client(tmp_path)

    fits = client.post(
        "/v1/users", json={"id": 3, "name": "Guard", "comment": "c" * 60}, headers=headers
    )
    assert fits.status_code == 200
    assert fits.json()["comment"] == "c" * 60

    too_long = client.post(
        "/v1/users", json={"id": 4, "name": "Guard", "comment": "c" * 61}, headers=headers
    )
    assert too_long.status_code == 400
    assert too_long.json()["detail"]["error"] == "user_write_rejected"
    assert too_long.json()["detail"]["reason"] == REASON_COMMENT_TOO_LONG

    # UTF-8 bytes, not characters: 31 two-byte characters are 62 bytes.
    multibyte = client.patch("/v1/users/3", json={"comment": "é" * 31}, headers=headers)
    assert multibyte.status_code == 400
    assert multibyte.json()["detail"]["reason"] == REASON_COMMENT_TOO_LONG

    name = client.patch("/v1/users/3", json={"name": "n" * 61}, headers=headers)
    assert name.status_code == 400
    assert name.json()["detail"]["reason"] == REASON_NAME_TOO_LONG


# ------------------------------------------------------------ occupied slots


def test_http_add_user_onto_an_occupied_slot_is_409_unless_replace(tmp_path: Path) -> None:
    client, headers, runtime = _demo_client(tmp_path)
    before = client.get("/v1/users/1", headers=headers).json()
    assert before["name"]

    refused = client.post("/v1/users", json={"id": 1, "name": "Guard"}, headers=headers)
    assert refused.status_code == 409
    detail = refused.json()["detail"]
    assert detail["error"] == "user_slot_occupied"
    assert detail["user_id"] == 1
    assert "replace=1" in detail["message"]
    assert client.get("/v1/users/1", headers=headers).json()["name"] == before["name"]

    replaced = client.post(
        "/v1/users?replace=1", json={"id": 1, "name": "Guard"}, headers=headers
    )
    assert replaced.status_code == 200
    assert replaced.json()["name"] == "Guard"
    assert [user.id for user in runtime._catalog.users].count(1) == 1


def test_runtime_refuses_a_create_onto_an_occupied_slot_from_the_fresh_read(monkeypatch) -> None:
    """The cached catalog holds no users; only the fresh read can show the slot
    is taken, and the refusal must arrive before anything is written."""

    runtime = _runtime()
    captured: dict = {}

    async def fake_pull(prefix: str, *, after_write: bool = False):
        return _snapshot([_Record(7, "1483", name="Existing user")])

    def fake_apply(config, **kwargs):
        captured["written"] = kwargs["user_id"]

    async def fake_close() -> None:
        return None

    monkeypatch.setattr(runtime, "_pull_catalog_snapshot_locked", fake_pull)
    monkeypatch.setattr(runtime, "_close_status_session_locked", fake_close)
    monkeypatch.setattr(runtime_module, "_apply_upsert_user", fake_apply)
    _route_refresh(monkeypatch, runtime)
    monkeypatch.setattr(runtime, "get_user", lambda user_id, max_age_seconds=None: _async_value(None))

    with pytest.raises(UserSlotOccupied):
        asyncio.run(runtime.add_user(UserCreateModel(id=7, name="New", code="1486")))
    assert "written" not in captured

    # A slot whose record has no name is free: the panel keeps empty records.
    async def fake_pull_unnamed(prefix: str, *, after_write: bool = False):
        return _snapshot([_Record(7, "", name="")])

    monkeypatch.setattr(runtime, "_pull_catalog_snapshot_locked", fake_pull_unnamed)
    with pytest.raises(RuntimeError, match="not present after add"):
        asyncio.run(runtime.add_user(UserCreateModel(id=7, name="New", code="1486")))
    assert captured["written"] == 7

    # replace=True overwrites a named occupant.
    captured.clear()
    monkeypatch.setattr(runtime, "_pull_catalog_snapshot_locked", fake_pull)
    with pytest.raises(RuntimeError, match="not present after add"):
        asyncio.run(
            runtime.add_user(UserCreateModel(id=7, name="New", code="1486"), replace=True)
        )
    assert captured["written"] == 7
