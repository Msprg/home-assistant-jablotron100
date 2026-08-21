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

from jablotron_api.domain.models import (
    ExportCatalogModel,
    InitialSetupModel,
    InitialSetupRangeModel,
    UserCreateModel,
    UserModel,
    UserPatchModel,
    utc_now,
)
from jablotron_api.domain.user_validation import UserWriteRejected
import jablotron_api.panel.runtime as runtime_module
import jablotron_api.services.user_manager as user_manager
from jablotron_api.panel.runtime import PanelRuntime, PanelRuntimeConfig
from jablotron_api.server.config import PanelSettings, ServerSettings


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

    def __init__(self, monkeypatch, *, max_age=3600.0, users=(), delay=0.0):
        self.runtime = PanelRuntime(
            PanelRuntimeConfig(port="auto", auth_code="1812", catalog_max_age_seconds=max_age)
        )
        self.pulls: list[str] = []
        self.pull_started = asyncio.Event()
        self.release = asyncio.Event()
        self.delay = delay
        self.users = list(users)
        self.emitted: list[str] = []

        async def fake_pull(prefix: str):
            self.pulls.append(prefix)
            self.pull_started.set()
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
        """Pretend the cached catalog completed `seconds` ago."""
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

    async def failing_pull(prefix: str):
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


def _write_harness(monkeypatch, tmp_path, *, cached_users, fresh_users):
    """Runtime whose cache and panel deliberately disagree.

    The real `apply_upsert` runs — that is where the rules are enforced — with
    only the sector builder and the panel write replaced, so `applied` counts
    exactly the writes that would have reached the panel.
    """

    h = _Harness(monkeypatch, users=fresh_users)
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
    h.runtime._catalog = _model(cached_users)
    h.runtime._catalog_snapshot = _snapshot(cached_users)
    h.runtime._catalog_completed_monotonic = time.monotonic()
    h.runtime._catalog_started_monotonic_for_cache = time.monotonic()
    return h, applied


def test_preflight_refuses_a_collision_the_cache_cannot_see(monkeypatch, tmp_path):
    """The dangerous direction: cache says the code is free, the panel does not."""

    h, applied = _write_harness(
        monkeypatch, tmp_path, cached_users=[], fresh_users=[_Record(7, "1483")]
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
        monkeypatch, tmp_path, cached_users=[_Record(7, "1483")], fresh_users=[]
    )

    async def run():
        # The write goes through; the post-write verification then fails
        # because this fake panel never grows the user. What matters is that
        # the stale cached collision did not refuse it.
        with pytest.raises(RuntimeError, match="not present after add"):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))

    asyncio.run(run())
    assert len(applied) == 1, "a legal write must reach the panel"


def test_preflight_pulls_fresh_even_when_the_cache_is_seconds_old(monkeypatch, tmp_path):
    h, applied = _write_harness(monkeypatch, tmp_path, cached_users=[], fresh_users=[])
    before = len(h.pulls)

    async def run():
        with pytest.raises(RuntimeError):
            await h.runtime.add_user(UserCreateModel(id=4, name="New", code="1486"))

    asyncio.run(run())
    assert len(h.pulls) > before, "a warm cache must not satisfy the write preflight"


def test_edit_preflight_also_pulls_fresh(monkeypatch, tmp_path):
    h, applied = _write_harness(
        monkeypatch, tmp_path, cached_users=[_Record(4, "1486")], fresh_users=[_Record(7, "1483")]
    )

    async def run():
        with pytest.raises(UserWriteRejected) as excinfo:
            await h.runtime.edit_user(4, UserPatchModel(code="1484"))
        assert excinfo.value.conflicting_user_ids == (7,)

    asyncio.run(run())
    assert applied == []


def test_handing_the_cached_snapshot_to_the_preflight_fails_loudly(monkeypatch, tmp_path):
    """The structural guard: if the cache is ever wired in, this fires."""

    h, _ = _write_harness(
        monkeypatch, tmp_path, cached_users=[_Record(7, "1483")], fresh_users=[]
    )
    with pytest.raises(RuntimeError, match="fresh panel read"):
        h.runtime._user_write_preflight(
            h.runtime._catalog_snapshot, 4, include_current=False
        )


def test_a_fresh_snapshot_is_accepted_by_the_guard(monkeypatch, tmp_path):
    h, _ = _write_harness(
        monkeypatch, tmp_path, cached_users=[_Record(7, "1483")], fresh_users=[]
    )
    preflight = h.runtime._user_write_preflight(
        _snapshot([_Record(9, "1483")]), 4, include_current=False
    )
    assert [entry.user_id for entry in preflight.existing] == [9]


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
