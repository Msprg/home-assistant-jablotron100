"""DELETE of a slot that holds no named user writes nothing to the panel."""

from __future__ import annotations

import asyncio
import copy

import pytest

from test_user_patch_carry_over import _Harness, _panel_record


@pytest.mark.parametrize(
    "records", [[], [_panel_record(name="")]], ids=["absent", "nameless"]
)
def test_deleting_a_user_the_table_does_not_hold_writes_nothing(monkeypatch, tmp_path, records):
    h = _Harness(monkeypatch, tmp_path, records)

    assert asyncio.run(h.runtime.delete_user(4)) is None
    assert h.session.writes == []
    assert h.refreshes == [], "no write, so no post-write refresh"
    assert h.emitted == []
    assert h.runtime._catalog_dirty is False


def test_deleting_a_missing_user_reads_the_panel_when_the_cache_is_too_old(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, [], window=0.0)

    asyncio.run(h.runtime.delete_user(4))
    assert h.session.writes == []
    assert h.refreshes == [("api-preflight-delete-user4", False)]
    assert h.emitted == ["catalog"], "the preflight pull replaced the cache"


def test_deleting_a_present_user_still_writes_and_refreshes(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, [_panel_record()])

    async def run():
        h.records[:] = []
        h.lookup.clear()
        await h.runtime.delete_user(4)

    # The cached table (still holding user 4) decides; the pull after the
    # write sees the slot empty.
    asyncio.run(run())
    assert h.written_records() == [{4: None}]
    assert h.refreshes == [("api-after-delete-user4", True)]
    assert h.emitted == ["catalog", "users"]


def test_a_delete_runs_the_same_cached_table_guard_as_add_and_edit(monkeypatch, tmp_path):
    """A table claiming to come from the cache that is not the current cache
    never decides a delete, as it never decides an add or an edit."""

    h = _Harness(monkeypatch, tmp_path, [])
    stale = copy.copy(h.runtime._catalog_snapshot)

    async def stale_preflight(prefix):
        return stale, True

    monkeypatch.setattr(h.runtime, "_preflight_snapshot_locked", stale_preflight)
    with pytest.raises(RuntimeError, match="fresh panel read"):
        asyncio.run(h.runtime.delete_user(4))
    assert h.session.writes == []
    assert h.emitted == []
