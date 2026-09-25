"""The causal flag must be true exactly when the pull began after the request."""
import asyncio

from test_catalog_freshness import _Harness


def test_a_forced_pull_reports_the_flag_true(monkeypatch):
    h = _Harness(monkeypatch)
    cat = asyncio.run(h.runtime.get_catalog(max_age_seconds=0))
    assert cat.pull_started_after_request is True
    assert cat.source == "panel"


def test_a_cache_hit_reports_the_flag_false(monkeypatch):
    h = _Harness(monkeypatch)
    asyncio.run(h.runtime.get_catalog(max_age_seconds=0))
    cat = asyncio.run(h.runtime.get_catalog(max_age_seconds=3600))
    assert cat.source == "cache"
    assert cat.pull_started_after_request is False


def test_the_flag_never_claims_a_pull_that_started_earlier(monkeypatch):
    """The whole point: a max_age=0 request that joins an older in-flight pull must not
    come back claiming the panel was read for it."""
    h = _Harness(monkeypatch)
    h.gated = True

    async def go():
        first = asyncio.create_task(h.runtime.get_catalog(max_age_seconds=3600))
        await h.pull_started.wait()
        await asyncio.sleep(0)
        late = asyncio.create_task(h.runtime.get_catalog(max_age_seconds=0))
        await asyncio.sleep(0.05)
        h.release.set()
        return (await first, await late)

    _, late = asyncio.run(go())
    assert late.pull_started_after_request is True, "chained pull must be causally after"
