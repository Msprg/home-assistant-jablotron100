"""Demand-driven catalog freshness: age policy, single-flight, and the
guarantee that a user write is never validated against the cache.

Everything here is offline. The panel read is replaced by a controllable
fake, and age is simulated by moving the runtime's own monotonic bookkeeping
rather than by patching the clock.
"""

from __future__ import annotations

import asyncio
import math
import time
from types import SimpleNamespace

import pytest

import jablotron_re_tools as re_tools
from jablotron_api.domain.models import (
    ExportCatalogModel,
    InitialSetupModel,
    InitialSetupRangeModel,
    UserCreateModel,
    UserModel,
    UserPatchModel,
    utc_now,
)
from jablotron_api.domain.user_validation import UserSlotOccupied, UserWriteRejected
import jablotron_api.panel.runtime as runtime_module
import jablotron_api.services.user_manager as user_manager
from jablotron_api.panel.runtime import PanelRuntime, PanelRuntimeConfig
from jablotron_api.server.config import PanelSettings, ServerSettings
from test_user_write_paths import _FakeConfigSession, _full_record


class _Record:
    """Stand-in for a UserRecord in a pulled snapshot."""

    def __init__(self, user_id, code="", cards=(), time_limited_group_raw=None):
        self.user_id = user_id
        self.code = code
        self.cards = list(cards)
        self.time_limited_group_raw = time_limited_group_raw


def _snapshot(users=(), *, code_len=4):
    return SimpleNamespace(
        users=list(users),
        main_config=SimpleNamespace(code_len_raw=code_len, code_prefix=False),
    )


def _model(users=()):
    return ExportCatalogModel(
        sections=[],
        pgs=[],
        devices=[],
        users=[UserModel(id=r.user_id, name=f"User {r.user_id}", code=r.code) for r in users],
        initial_setup=InitialSetupModel(
            source="test",
            exact=True,
            users=InitialSetupRangeModel(first_id=1, last_id=100, count=100),
        ),
        as_of=utc_now(),
        source="panel",
        trigger_used=True,
    )


class _Harness:
    """A PanelRuntime whose only panel interaction is a controllable fake pull."""

    def __init__(self, monkeypatch, *, max_age=3600.0, users=(), delay=0.0, preflight_max_age=60.0):
        self.runtime = PanelRuntime(
            PanelRuntimeConfig(
                port="auto",
                auth_code="1812",
                catalog_max_age_seconds=max_age,
                write_preflight_max_age_seconds=preflight_max_age,
            )
        )
        self.pulls: list[str] = []
        self.pull_started = asyncio.Event()
        self.release = asyncio.Event()
        self.delay = delay
        self.users = list(users)
        self.emitted: list[str] = []
        # When set, a post-write pull (after_write=True) raises this.
        self.after_write_error: BaseException | None = None

        async def fake_pull(prefix: str, *, after_write: bool = False):
            self.pulls.append(prefix)
            self.pull_started.set()
            if after_write and self.after_write_error is not None:
                raise self.after_write_error
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.gated:
                await self.release.wait()
            return _snapshot(self.users)

        async def noop() -> None:
            return None

        async def fake_emit(topic, payload):
            self.emitted.append(topic)

        self.gated = False
        monkeypatch.setattr(self.runtime, "_pull_catalog_snapshot_locked", fake_pull)
        monkeypatch.setattr(self.runtime, "_close_status_session_locked", noop)
        monkeypatch.setattr(self.runtime, "_emit", fake_emit)
        monkeypatch.setattr(
            runtime_module,
            "_catalog_to_model",
            lambda snapshot, **kwargs: _model(snapshot.users).model_copy(update=kwargs),
        )

    def age_cache(self, seconds: float) -> None:
        """Pretend the cached catalog completed `seconds` ago, from a pull
        that started a second before that."""
        self.runtime._catalog_completed_monotonic = time.monotonic() - seconds
        self.runtime._catalog_started_monotonic_for_cache = time.monotonic() - seconds - 1


# ----------------------------------------------------------------- age policy


def test_first_read_pulls_the_panel_and_reports_it(monkeypatch):
    h = _Harness(monkeypatch)

    async def run():
        catalog = await h.runtime.get_catalog()
        assert catalog.source == "panel"
        assert catalog.trigger_used is True
        assert catalog.as_of is not None

    asyncio.run(run())
    assert h.pulls == ["api-server-catalog"]


def test_second_read_inside_the_window_serves_the_cache(monkeypatch):
    h = _Harness(monkeypatch)

    async def run():
        await h.runtime.get_catalog()
        catalog = await h.runtime.get_catalog()
        assert catalog.source == "cache"
        # The provenance of the underlying read is preserved.
        assert catalog.trigger_used is True
        assert catalog.as_of is not None

    asyncio.run(run())
    assert len(h.pulls) == 1


def test_read_past_the_window_pulls_again(monkeypatch):
    h = _Harness(monkeypatch, max_age=3600.0)

    async def run():
        await h.runtime.get_catalog()
        h.age_cache(3601)
        catalog = await h.runtime.get_catalog()
        assert catalog.source == "panel"

    asyncio.run(run())
    assert len(h.pulls) == 2


def test_cache_just_inside_the_window_is_still_served(monkeypatch):
    h = _Harness(monkeypatch, max_age=3600.0)

    async def run():
        await h.runtime.get_catalog()
        h.age_cache(3599)
        assert (await h.runtime.get_catalog()).source == "cache"

    asyncio.run(run())
    assert len(h.pulls) == 1


def test_explicit_max_age_overrides_the_default(monkeypatch):
    h = _Harness(monkeypatch, max_age=3600.0)

    async def run():
        await h.runtime.get_catalog()
        h.age_cache(120)
        assert (await h.runtime.get_catalog(max_age_seconds=60)).source == "panel"

    asyncio.run(run())
    assert len(h.pulls) == 2


def test_infinite_max_age_accepts_any_cache(monkeypatch):
    h = _Harness(monkeypatch)

    async def run():
        await h.runtime.get_catalog()
        h.age_cache(10 * 24 * 3600)
        assert (await h.runtime.get_catalog(max_age_seconds=math.inf)).source == "cache"

    asyncio.run(run())
    assert len(h.pulls) == 1


def test_the_shipped_default_is_finite():
    # An unbounded default is the original defect; adding an opt-in parameter
    # while leaving the default infinite would fix nothing.
    assert PanelSettings().catalog_max_age_seconds == 3600.0
    assert math.isfinite(ServerSettings().panel.catalog_max_age_seconds)


def test_refresh_catalog_never_serves_the_cache(monkeypatch):
    h = _Harness(monkeypatch)

    async def run():
        await h.runtime.get_catalog()
        catalog = await h.runtime.refresh_catalog()
        assert catalog.source == "panel"

    asyncio.run(run())
    assert len(h.pulls) == 2


def test_users_and_export_users_follow_the_same_policy(monkeypatch):
    h = _Harness(monkeypatch, users=[_Record(5, "1483")])

    async def run():
        assert [user.id for user in await h.runtime.get_users()] == [5]
        await h.runtime.get_users()
        await h.runtime.get_export_users()
        assert (await h.runtime.get_user(5)) is not None
        h.age_cache(4000)
        await h.runtime.get_users()

    asyncio.run(run())
    assert len(h.pulls) == 2


# --------------------------------------------------------------- single-flight


def test_concurrent_reads_join_one_pull(monkeypatch):
    h = _Harness(monkeypatch)
    h.gated = True

    async def run():
        tasks = [asyncio.create_task(h.runtime.get_catalog()) for _ in range(3)]
        await h.pull_started.wait()
        await asyncio.sleep(0)
        h.release.set()
        results = await asyncio.gather(*tasks)
        assert all(r is not None for r in results)

    asyncio.run(run())
    assert len(h.pulls) == 1, "three clients must interrupt the panel once, not three times"


def test_a_disconnecting_client_does_not_cancel_the_shared_pull(monkeypatch):
    h = _Harness(monkeypatch)
    h.gated = True

    async def run():
        first = asyncio.create_task(h.runtime.get_catalog())
        second = asyncio.create_task(h.runtime.get_catalog())
        await h.pull_started.wait()
        await asyncio.sleep(0)
        first.cancel()  # the client hung up
        h.release.set()
        assert (await second) is not None

    asyncio.run(run())
    assert len(h.pulls) == 1


def test_a_failed_pull_is_reported_and_the_next_read_retries(monkeypatch):
    h = _Harness(monkeypatch)
    failures = {"count": 0}

    async def failing_pull(prefix: str, *, after_write: bool = False):
        h.pulls.append(prefix)
        failures["count"] += 1
        if failures["count"] == 1:
            raise RuntimeError("panel did not answer")
        return _snapshot([])

    monkeypatch.setattr(h.runtime, "_pull_catalog_snapshot_locked", failing_pull)

    async def run():
        with pytest.raises(RuntimeError):
            await h.runtime.get_catalog()
        assert (await h.runtime.get_catalog()).source == "panel"

    asyncio.run(run())
    assert len(h.pulls) == 2


def test_a_catalog_pull_no_longer_closes_the_status_session(monkeypatch):
    """The export refresh runs inside the status session now, so a catalog
    pull keeps it (and its motion stream) alive; legacy mode still closes it
    so the separate login + cleanup session can have the bus."""

    def pull(in_session: bool) -> tuple[int, object]:
        h = _Harness(monkeypatch)
        h.runtime._config.in_session_config_ops = in_session
        closes = {"count": 0}

        async def counting_close() -> None:
            closes["count"] += 1
            h.runtime._status_session = None

        # The real pull path decides whether the session is closed; only the
        # blocking tool call underneath it is replaced.
        monkeypatch.setattr(h.runtime, "_close_status_session_locked", counting_close)
        monkeypatch.setattr(
            h.runtime,
            "_pull_catalog_snapshot_locked",
            PanelRuntime._pull_catalog_snapshot_locked.__get__(h.runtime),
        )
        session = _FakeConfigSession()
        h.runtime._status_session = session
        configs: list = []

        def fake_pull_catalog_snapshot(config, prefix, *, sleep=None):
            configs.append(config)
            # The real pull path logs the catalog's counts.
            return SimpleNamespace(**vars(_snapshot([])), sections_by_id={}, pgs_by_id={}, objects_by_id={})

        monkeypatch.setattr(runtime_module, "pull_catalog_snapshot", fake_pull_catalog_snapshot)
        asyncio.run(h.runtime.refresh_catalog())
        assert len(configs) == 1
        assert configs[0].trigger_session is (session if in_session else None)
        return closes["count"], h.runtime._status_session

    closes, remaining = pull(True)
    assert closes == 0
    assert remaining is not None

    closes, remaining = pull(False)
    assert closes == 1
    assert remaining is None


# ------------------------------------------------------------- max_age_seconds=0


def test_max_age_zero_pulls_even_with_a_warm_cache(monkeypatch):
    h = _Harness(monkeypatch)

    async def run():
        await h.runtime.get_catalog()
        assert (await h.runtime.get_catalog(max_age_seconds=0)).source == "panel"

    asyncio.run(run())
    assert len(h.pulls) == 2


def test_max_age_zero_chains_a_second_pull_when_the_inflight_one_began_earlier(monkeypatch):
    """Joining a pull that started before the request is a quiet lie."""

    h = _Harness(monkeypatch)
    h.gated = True

    async def run():
        first = asyncio.create_task(h.runtime.get_catalog())
        await h.pull_started.wait()
        await asyncio.sleep(0)
        # This request arrives strictly after the in-flight pull began.
        strict = asyncio.create_task(h.runtime.get_catalog(max_age_seconds=0))
        await asyncio.sleep(0)
        h.release.set()
        h.gated = False
        assert (await first).source == "panel"
        assert (await strict).source == "panel"

    asyncio.run(run())
    assert len(h.pulls) == 2, "the strict read must chain its own pull, not reuse the earlier one"


def test_max_age_zero_is_satisfied_by_the_pull_it_starts_itself(monkeypatch):
    h = _Harness(monkeypatch)

    async def run():
        assert (await h.runtime.get_catalog(max_age_seconds=0)).source == "panel"

    asyncio.run(run())
    assert len(h.pulls) == 1


def test_export_snapshot_endpoints_always_pull(monkeypatch):
    h = _Harness(monkeypatch)

    async def run():
        await h.runtime.get_catalog()
        snapshot = await h.runtime._refresh_export_snapshot()
        assert snapshot is not None

    asyncio.run(run())
    assert h.pulls == ["api-server-catalog", "api-server-export"]


# ------------------------------------------------------- no background refresh


def test_the_poll_loop_never_refreshes_the_catalog(monkeypatch):
    """No timer, no scheduled task: an idle server does no catalog work."""

    h = _Harness(monkeypatch)
    h.runtime._config.poll_interval_seconds = 0.001
    ticks = {"count": 0}

    async def fake_status():
        ticks["count"] += 1
        if ticks["count"] >= 5:
            h.runtime._closed = True

    monkeypatch.setattr(h.runtime, "refresh_status", fake_status)

    async def run():
        await h.runtime._poll_loop()

    asyncio.run(run())
    assert ticks["count"] >= 5
    assert h.pulls == [], "the poll loop must never pull the catalog"


# --------------------------------------------- the write preflight and the cache


def _write_harness(monkeypatch, tmp_path, *, cached_users, fresh_users, preflight_max_age=0.0):
    """Runtime whose cache and panel deliberately disagree.

    The real `apply_upsert` runs — that is where the rules are enforced — with
    only the sector builder and the panel write replaced, so `applied` counts
    exactly the writes that would have reached the panel. The cache is warm
    (its pull started just now); `preflight_max_age` is the write window.
    """

    h = _Harness(monkeypatch, users=fresh_users, preflight_max_age=preflight_max_age)
    applied: list = []
    sector = tmp_path / "sector.bin"
    sector.write_bytes(b"")

    def fake_build(args, *, current):
        summary = {
            "code": args.pin or "",
            "cards": [args.card1] if args.card1 else [],
            "time_limited_group_raw": args.time_limited_group_raw,
        }
        return sector, summary, False

    monkeypatch.setattr(user_manager, "build_upsert_sector", fake_build)
    monkeypatch.setattr(user_manager, "apply_import_sector", lambda **kw: applied.append(kw))
    monkeypatch.setattr(user_manager, "probe_login_rights", lambda **kw: re_tools.LoginRights(0x2A, 7))
    # The write asks the status session for rights (none yet), the probe then
    # reports ARC rights, so the storage stub above records the write.
    h.runtime._status_session = _FakeConfigSession()
    h.runtime._catalog = _model(cached_users)
    h.runtime._catalog_snapshot = _snapshot(cached_users)
    h.runtime._catalog_completed_monotonic = time.monotonic()
    h.runtime._catalog_started_monotonic_for_cache = time.monotonic()
    return h, applied


def test_preflight_refuses_a_collision_the_cache_cannot_see(monkeypatch, tmp_path):
    """The dangerous direction: cache says the code is free, the panel does not."""

    h, applied = _write_harness(
        monkeypatch,
        tmp_path,
        cached_users=[],
        fresh_users=[_Record(7, "1483")],
        preflight_max_age=0.0,
    )

    async def run():
        with pytest.raises(UserWriteRejected) as excinfo:
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))
        assert excinfo.value.conflicting_user_ids == (7,)

    asyncio.run(run())
    assert applied == [], "the write must not reach the panel"
    assert h.pulls, "the preflight must have pulled the panel"


def test_preflight_allows_a_write_the_stale_cache_would_have_refused(monkeypatch, tmp_path):
    """The other direction: a stale collision must not block a legal write."""

    h, applied = _write_harness(
        monkeypatch,
        tmp_path,
        cached_users=[_Record(7, "1483")],
        fresh_users=[],
        preflight_max_age=0.0,
    )

    async def run():
        # The write goes through; the post-write verification then fails
        # because this fake panel never grows the user. What matters is that
        # the stale cached collision did not refuse it.
        with pytest.raises(RuntimeError, match="not present after add"):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))

    asyncio.run(run())
    assert len(applied) == 1, "a legal write must reach the panel"


def test_preflight_pulls_fresh_when_the_window_is_zero(monkeypatch, tmp_path):
    h, applied = _write_harness(
        monkeypatch, tmp_path, cached_users=[], fresh_users=[], preflight_max_age=0.0
    )

    async def run():
        with pytest.raises(RuntimeError):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1486"))

    asyncio.run(run())
    assert h.pulls[0] == "api-preflight-add-user4", "with a zero window a warm cache must not satisfy the preflight"


def test_edit_preflight_also_pulls_fresh(monkeypatch, tmp_path):
    h, applied = _write_harness(
        monkeypatch,
        tmp_path,
        cached_users=[_Record(4, "1486")],
        fresh_users=[_full_record(4, "1486", name="User 4"), _Record(7, "1483")],
        preflight_max_age=0.0,
    )

    async def run():
        with pytest.raises(UserWriteRejected) as excinfo:
            await h.runtime.edit_user(4, UserPatchModel(code="1484"))
        assert excinfo.value.conflicting_user_ids == (7,)

    asyncio.run(run())
    assert applied == []
    assert h.pulls == ["api-preflight-edit-user4"]


@pytest.mark.parametrize("fresh_users", [[], [_full_record(4, "1486", name="")]], ids=["absent", "nameless"])
def test_edit_refuses_a_user_the_fresh_table_no_longer_has(monkeypatch, tmp_path, fresh_users):
    """A delete whose reply was lost leaves the user in the (dirty) cache. The
    existence check on that cache passes, but the preflight pull is the
    authority: writing the edit would bring the deleted user back with the
    old code and sections."""

    h, applied = _write_harness(
        monkeypatch,
        tmp_path,
        cached_users=[_full_record(4, "1486", name="User 4")],
        fresh_users=fresh_users,
        preflight_max_age=60.0,
    )
    h.runtime._catalog_dirty = True

    async def run():
        with pytest.raises(RuntimeError, match="User 4 not found"):
            await h.runtime.edit_user(4, UserPatchModel(name="Renamed"))

    asyncio.run(run())
    assert applied == [], "the edit must not recreate the user on the panel"
    assert h.pulls == ["api-preflight-edit-user4"]


def test_handing_the_cached_snapshot_to_the_preflight_fails_loudly(monkeypatch, tmp_path):
    """The structural guard: a cached table past the window never validates a write."""

    h, _ = _write_harness(
        monkeypatch,
        tmp_path,
        cached_users=[_Record(7, "1483")],
        fresh_users=[],
        preflight_max_age=60.0,
    )
    h.age_cache(61)
    with pytest.raises(RuntimeError, match="fresh panel read"):
        h.runtime._user_write_preflight(
            h.runtime._catalog_snapshot, 4, include_current=False, served_from_cache=True
        )


def test_a_cached_snapshot_inside_the_window_is_accepted_by_the_guard(monkeypatch, tmp_path):
    h, _ = _write_harness(
        monkeypatch,
        tmp_path,
        cached_users=[_Record(7, "1483")],
        fresh_users=[],
        preflight_max_age=60.0,
    )
    h.age_cache(10)
    preflight = h.runtime._user_write_preflight(
        h.runtime._catalog_snapshot, 4, include_current=False, served_from_cache=True
    )
    assert [entry.user_id for entry in preflight.existing] == [7]


def test_a_dirty_cache_is_rejected_by_the_guard_inside_the_window(monkeypatch, tmp_path):
    h, _ = _write_harness(
        monkeypatch,
        tmp_path,
        cached_users=[_Record(7, "1483")],
        fresh_users=[],
        preflight_max_age=60.0,
    )
    h.age_cache(10)
    h.runtime._catalog_dirty = True
    with pytest.raises(RuntimeError, match="dirtied by a write"):
        h.runtime._user_write_preflight(
            h.runtime._catalog_snapshot, 4, include_current=False, served_from_cache=True
        )


def test_a_snapshot_that_is_not_the_cache_cannot_claim_to_be_served_from_it(monkeypatch, tmp_path):
    h, _ = _write_harness(
        monkeypatch, tmp_path, cached_users=[], fresh_users=[], preflight_max_age=60.0
    )
    with pytest.raises(RuntimeError, match="fresh panel read"):
        h.runtime._user_write_preflight(
            _snapshot([_Record(9, "1483")]), 4, include_current=False, served_from_cache=True
        )


def test_a_fresh_snapshot_is_accepted_by_the_guard(monkeypatch, tmp_path):
    h, _ = _write_harness(
        monkeypatch,
        tmp_path,
        cached_users=[_Record(7, "1483")],
        fresh_users=[],
        preflight_max_age=0.0,
    )
    preflight = h.runtime._user_write_preflight(
        _snapshot([_Record(9, "1483")]), 4, include_current=False
    )
    assert [entry.user_id for entry in preflight.existing] == [9]


# ------------------------------------------------- one export pull per write


def test_preflight_uses_the_cache_inside_the_write_window(monkeypatch, tmp_path):
    """Inside the window the cached table decides, and it decides with the
    same rules: the collision it holds refuses the write without a pull."""

    h, applied = _write_harness(
        monkeypatch,
        tmp_path,
        cached_users=[_Record(7, "1483")],
        fresh_users=[],
        preflight_max_age=60.0,
    )

    async def run():
        with pytest.raises(UserWriteRejected) as excinfo:
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))
        assert excinfo.value.conflicting_user_ids == (7,)

    asyncio.run(run())
    assert applied == []
    assert h.pulls == []


def test_preflight_age_counts_from_pull_start(monkeypatch, tmp_path):
    """EXPORT.CFG shows the table as it was when the pull began: a pull that
    started 70 s ago is 70 s old even if it completed 5 s ago."""

    h, applied = _write_harness(
        monkeypatch, tmp_path, cached_users=[], fresh_users=[], preflight_max_age=60.0
    )
    now = time.monotonic()
    h.runtime._catalog_started_monotonic_for_cache = now - 70
    h.runtime._catalog_completed_monotonic = now - 5

    async def run():
        with pytest.raises(RuntimeError, match="not present after add"):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))

    asyncio.run(run())
    assert h.pulls[0] == "api-preflight-add-user4"


def test_a_write_costs_one_pull_with_a_warm_cache(monkeypatch, tmp_path):
    h, applied = _write_harness(
        monkeypatch, tmp_path, cached_users=[], fresh_users=[], preflight_max_age=60.0
    )

    async def run():
        # The fake panel never grows the user, so the lookup after the write
        # fails; the point is how many times the panel was read.
        with pytest.raises(RuntimeError, match="not present after add"):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))

    asyncio.run(run())
    assert len(applied) == 1
    assert h.pulls == ["api-after-add-user4"]


def test_a_write_costs_two_pulls_with_a_cold_cache(monkeypatch, tmp_path):
    h, applied = _write_harness(
        monkeypatch, tmp_path, cached_users=[], fresh_users=[], preflight_max_age=60.0
    )
    h.age_cache(61)

    async def run():
        with pytest.raises(RuntimeError, match="not present after add"):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))

    asyncio.run(run())
    assert len(applied) == 1
    assert h.pulls == ["api-preflight-add-user4", "api-after-add-user4"]


def test_edit_and_delete_also_refresh_once_after_the_write(monkeypatch, tmp_path):
    h, applied = _write_harness(
        monkeypatch,
        tmp_path,
        cached_users=[_full_record(4, "1486", name="User 4")],
        fresh_users=[_full_record(4, "1486", name="User 4")],
        preflight_max_age=60.0,
    )
    deletes: list = []
    monkeypatch.setattr(runtime_module, "_apply_delete_user", lambda config, **kw: deletes.append(kw))

    async def run():
        edited = await h.runtime.edit_user(4, UserPatchModel(name="User 4"))
        assert edited.id == 4
        # The warm cache served the existence check and the preflight.
        assert h.pulls == ["api-after-edit-user4"]
        h.pulls.clear()
        with pytest.raises(RuntimeError, match="still present after delete"):
            await h.runtime.delete_user(4)

    asyncio.run(run())
    assert len(applied) == 1
    assert len(deletes) == 1
    assert h.pulls == ["api-after-delete-user4"]


@pytest.mark.parametrize("op", ["add", "edit"])
def test_the_write_paths_hand_the_cache_flag_to_the_guard(monkeypatch, tmp_path, op):
    """add_user and edit_user pass from_cache on to the guard: a snapshot
    that claims to be the cache but is not must be refused before any write."""

    cached = [_full_record(4, "1486", name="User 4")] if op == "edit" else []
    h, applied = _write_harness(
        monkeypatch, tmp_path, cached_users=cached, fresh_users=cached, preflight_max_age=60.0
    )
    # Not the cached snapshot object, so the guard must refuse it.
    impostor = _snapshot([*cached, _Record(9, "1483")])

    async def fake_preflight(prefix):
        return impostor, True

    monkeypatch.setattr(h.runtime, "_preflight_snapshot_locked", fake_preflight)

    async def run():
        with pytest.raises(RuntimeError, match="fresh panel read"):
            if op == "add":
                await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))
            else:
                await h.runtime.edit_user(4, UserPatchModel(code="1484"))

    asyncio.run(run())
    assert applied == []
    assert h.pulls == []


@pytest.mark.parametrize("dirty", [False, True], ids=["cold", "dirty"])
def test_a_refused_write_still_announces_the_catalog_its_preflight_pulled(monkeypatch, tmp_path, dirty):
    h, applied = _write_harness(
        monkeypatch,
        tmp_path,
        cached_users=[],
        fresh_users=[_full_record(4, "1486", name="User 4")],
        preflight_max_age=60.0,
    )
    if dirty:
        h.runtime._catalog_dirty = True
    else:
        h.age_cache(61)

    async def run():
        with pytest.raises(UserSlotOccupied):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))

    asyncio.run(run())
    assert applied == []
    assert h.pulls == ["api-preflight-add-user4"]
    assert h.emitted == ["catalog"], "the cache changed, so listeners must hear about it"
    assert [user.id for user in h.runtime._catalog.users] == [4]


def test_a_refused_write_from_the_cache_announces_nothing(monkeypatch, tmp_path):
    h, applied = _write_harness(
        monkeypatch,
        tmp_path,
        cached_users=[_Record(7, "1483")],
        fresh_users=[],
        preflight_max_age=60.0,
    )

    async def run():
        with pytest.raises(UserWriteRejected):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))

    asyncio.run(run())
    assert h.pulls == []
    assert h.emitted == []


def test_a_listener_error_does_not_hide_the_write_error(monkeypatch, tmp_path):
    h, applied = _write_harness(
        monkeypatch,
        tmp_path,
        cached_users=[],
        fresh_users=[_full_record(4, "1486", name="User 4")],
        preflight_max_age=0.0,
    )

    async def broken_emit(topic, payload):
        raise RuntimeError("listener broke")

    monkeypatch.setattr(h.runtime, "_emit", broken_emit)

    async def run():
        with pytest.raises(UserSlotOccupied):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))

    asyncio.run(run())
    assert applied == []


def test_a_failed_write_dirties_the_cache_so_the_next_preflight_pulls(monkeypatch, tmp_path):
    h, applied = _write_harness(
        monkeypatch, tmp_path, cached_users=[], fresh_users=[], preflight_max_age=60.0
    )
    dirty_at_write: list[bool] = []

    def refused(**kwargs):
        raise SystemExit("refused")

    monkeypatch.setattr(user_manager, "apply_import_sector", refused)

    async def first():
        with pytest.raises(RuntimeError, match="Panel write failed: refused"):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))

    asyncio.run(first())
    assert h.runtime._catalog_dirty is True
    assert h.pulls == [], "the warm cache served the first preflight"

    def accepted(**kwargs):
        dirty_at_write.append(h.runtime._catalog_dirty)
        applied.append(kwargs)

    monkeypatch.setattr(user_manager, "apply_import_sector", accepted)

    async def second():
        with pytest.raises(RuntimeError, match="not present after add"):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))

    asyncio.run(second())
    assert h.pulls == ["api-preflight-add-user4", "api-after-add-user4"]
    assert dirty_at_write == [False], "the preflight pull cleared the dirty mark before the write"
    assert h.runtime._catalog_dirty is False


def test_a_failed_post_write_refresh_reports_the_write_landed_and_dirties_the_cache(monkeypatch, tmp_path):
    h, applied = _write_harness(
        monkeypatch, tmp_path, cached_users=[], fresh_users=[], preflight_max_age=60.0
    )
    h.after_write_error = RuntimeError("stalled")

    async def run():
        with pytest.raises(RuntimeError, match="User 4 was written but the catalog refresh failed: stalled"):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))
        assert h.runtime._catalog_dirty is True
        assert h.pulls == ["api-after-add-user4"]
        # A read with the finite default age does not trust the dirty cache.
        await h.runtime.get_users()
        assert h.pulls == ["api-after-add-user4", "api-server-catalog"]
        assert h.runtime._catalog_dirty is False

    asyncio.run(run())
    assert len(applied) == 1


def test_a_dirty_cache_still_serves_a_read_that_accepts_any_age(monkeypatch, tmp_path):
    h, _ = _write_harness(
        monkeypatch, tmp_path, cached_users=[], fresh_users=[], preflight_max_age=60.0
    )
    h.runtime._catalog_dirty = True

    async def run():
        assert (await h.runtime.get_catalog(max_age_seconds=math.inf)).source == "cache"
        assert (await h.runtime.get_catalog(max_age_seconds=3600)).source == "panel"

    asyncio.run(run())
    assert h.pulls == ["api-server-catalog"]


def test_the_post_write_refresh_serves_the_following_get(monkeypatch, tmp_path):
    h, applied = _write_harness(
        monkeypatch, tmp_path, cached_users=[], fresh_users=[], preflight_max_age=60.0
    )
    h.age_cache(5)
    before = h.runtime._catalog_completed_monotonic

    async def run():
        with pytest.raises(RuntimeError, match="not present after add"):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))
        assert h.runtime._catalog_completed_monotonic > before
        pulls = list(h.pulls)
        await h.runtime.get_users(max_age_seconds=math.inf)
        assert h.pulls == pulls

    asyncio.run(run())
    assert h.emitted.count("catalog") == 1, "the post-write refresh is announced once"


def test_the_shipped_preflight_window_is_sixty_seconds(monkeypatch):
    assert PanelSettings(auth_code="x").write_preflight_max_age_seconds == 60.0
    assert PanelRuntimeConfig().write_preflight_max_age_seconds == 60.0
    monkeypatch.delenv("JABLOTRON_PANEL_WRITE_PREFLIGHT_MAX_AGE_SECONDS", raising=False)
    assert ServerSettings().panel.write_preflight_max_age_seconds == 60.0
    monkeypatch.setenv("JABLOTRON_PANEL_WRITE_PREFLIGHT_MAX_AGE_SECONDS", "0")
    assert ServerSettings().panel.write_preflight_max_age_seconds == 0.0


def test_a_negative_preflight_window_is_refused_at_startup(tmp_path):
    from jablotron_api.server.app import create_app
    from jablotron_api.services.storage import TokenStore

    settings = ServerSettings(
        db_path=tmp_path / "tokens.db",
        runtime_mode="live",
        panel=PanelSettings(auth_code="1812", write_preflight_max_age_seconds=-1.0),
    )
    with pytest.raises(RuntimeError, match="JABLOTRON_PANEL_WRITE_PREFLIGHT_MAX_AGE_SECONDS must be >= 0"):
        create_app(settings=settings, token_store=TokenStore(tmp_path / "tokens.db"))


# ------------------------------------------------------------------ HTTP surface


def _client(tmp_path, runtime):
    from fastapi.testclient import TestClient

    from jablotron_api.domain.models import DEFAULT_ADMIN_SCOPES
    from jablotron_api.server.app import create_app
    from jablotron_api.server.config import ServerSettings as _Settings
    from jablotron_api.services.storage import TokenStore

    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(label="admin", scopes=list(DEFAULT_ADMIN_SCOPES))
    app = create_app(
        settings=_Settings(db_path=tmp_path / "tokens.db"), runtime=runtime, token_store=store
    )
    return TestClient(app), {"Authorization": f"Bearer {token}"}


class _RecordingDemo:
    """Demo runtime that records the max_age each read was given."""

    def __init__(self):
        from jablotron_api.panel.demo import DemoPanelRuntime

        self._inner = DemoPanelRuntime()
        self.seen: list[tuple[str, float | None]] = []

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def get_catalog(self, max_age_seconds=None):
        self.seen.append(("get_catalog", max_age_seconds))
        return await self._inner.get_catalog(max_age_seconds)

    async def get_users(self, max_age_seconds=None):
        self.seen.append(("get_users", max_age_seconds))
        return await self._inner.get_users(max_age_seconds)

    async def get_export_users(self, max_age_seconds=None):
        self.seen.append(("get_export_users", max_age_seconds))
        return await self._inner.get_export_users(max_age_seconds)

    async def get_user(self, user_id, max_age_seconds=None):
        self.seen.append(("get_user", max_age_seconds))
        return await self._inner.get_user(user_id, max_age_seconds)


def test_catalog_response_carries_its_provenance(tmp_path):
    client, headers = _client(tmp_path, _RecordingDemo())
    body = client.get("/v1/export/catalog", headers=headers).json()
    assert body["as_of"] is not None
    assert body["source"] in {"panel", "cache"}
    assert body["trigger_used"] is False  # the demo panel enters no config mode


def test_max_age_query_parameter_reaches_the_runtime(tmp_path):
    runtime = _RecordingDemo()
    client, headers = _client(tmp_path, runtime)
    client.get("/v1/export/catalog?max_age_seconds=0", headers=headers)
    client.get("/v1/users?max_age_seconds=30", headers=headers)
    client.get("/v1/export/users?max_age_seconds=45", headers=headers)
    client.get("/v1/users/1?max_age_seconds=60", headers=headers)
    client.get("/v1/export/catalog", headers=headers)
    assert runtime.seen == [
        ("get_catalog", 0.0),
        ("get_users", 30.0),
        ("get_export_users", 45.0),
        ("get_user", 60.0),
        ("get_catalog", None),  # omitted -> the server's configured default
    ]


def test_negative_max_age_is_rejected(tmp_path):
    client, headers = _client(tmp_path, _RecordingDemo())
    assert client.get("/v1/export/catalog?max_age_seconds=-1", headers=headers).status_code == 422
