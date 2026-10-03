"""The export pull with the status session as the trigger.

With a session, ``pull_live_export_snapshot`` runs the export refresh on the
session's own channel, reads EXPORT.CFG over the block device as before, and
hands the channel back to the session (``finish_export``) even when the block
read fails. Without a session the separate login + cleanup path is unchanged.
No test opens hardware: the device lookup, the block reader and the
standalone trigger/cleanup helpers are replaced.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import jablotron_re_tools as tools
import jablotron_api.services.catalog_io as catalog_io
from jablotron_api.services.catalog_io import CatalogPullConfig, pull_catalog_snapshot
from jablotron_re_tools import ExportSnapshot


class FakeTrigger:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def trigger_export(self) -> None:
        self.calls.append("trigger")

    def finish_export(self) -> None:
        self.calls.append("finish")


def _empty_catalog():
    return SimpleNamespace(users=[], sections_by_id={}, pgs_by_id={}, time_limit_groups_by_id={})


def _stub_block_path(monkeypatch, calls: list[str], *, read_error: BaseException | None = None):
    """Replace everything under pull_live_export_snapshot that touches a device."""

    monkeypatch.setattr(tools, "resolve_flexi_cfg_device", lambda device=None: "/dev/fake-flexicfg")
    monkeypatch.setattr(tools, "get_device_mountpoint", lambda device: None)

    def read_export_direct(*, device, output, start_lba, sectors):
        calls.append("read")
        if read_error is not None:
            raise read_error
        output.write_bytes(b"\x00" * 512)

    monkeypatch.setattr(tools, "read_export_direct", read_export_direct)
    monkeypatch.setattr(tools, "extract_users", lambda path, *, dedupe="raw": [])
    monkeypatch.setattr(tools, "extract_export_catalog", lambda path: _empty_catalog())


def _pull(tmp_path: Path, **kwargs) -> ExportSnapshot:
    return tools.pull_live_export_snapshot(
        output=tmp_path / "EXPORT.CFG.bin",
        device="auto",
        port="auto",
        code="1812",
        reset=True,
        **kwargs,
    )


def test_pull_live_export_snapshot_uses_the_session_trigger_and_finishes_after_the_read(monkeypatch, tmp_path) -> None:
    calls: list[str] = []
    _stub_block_path(monkeypatch, calls)
    monkeypatch.setattr(tools, "trigger_live_export", lambda **kw: pytest.fail("no separate trigger session"))
    monkeypatch.setattr(tools, "cleanup_read_session", lambda **kw: pytest.fail("no separate cleanup session"))

    snapshot = _pull(tmp_path, trigger_session=FakeTrigger(calls))

    assert calls == ["trigger", "read", "finish"]
    assert isinstance(snapshot, ExportSnapshot)
    assert snapshot.path == tmp_path / "EXPORT.CFG.bin"
    assert snapshot.records == []


def test_finish_export_runs_even_when_the_block_read_fails(monkeypatch, tmp_path) -> None:
    calls: list[str] = []
    _stub_block_path(monkeypatch, calls, read_error=OSError("[Errno 5] Input/output error"))
    monkeypatch.setattr(tools, "trigger_live_export", lambda **kw: pytest.fail("no separate trigger session"))
    monkeypatch.setattr(tools, "cleanup_read_session", lambda **kw: pytest.fail("no separate cleanup session"))

    with pytest.raises(OSError, match="Errno 5"):
        _pull(tmp_path, trigger_session=FakeTrigger(calls))

    assert calls == ["trigger", "read", "finish"]


def test_pull_live_export_snapshot_without_a_session_keeps_the_old_path(monkeypatch, tmp_path) -> None:
    calls: list[str] = []
    _stub_block_path(monkeypatch, calls)
    triggers: list[dict] = []
    cleanups: list[dict] = []
    monkeypatch.setattr(tools, "trigger_live_export", lambda **kw: triggers.append(kw))

    def cleanup(**kw):
        cleanups.append(kw)
        return tools.EXITED_SECTIONS_MODE

    monkeypatch.setattr(tools, "cleanup_read_session", cleanup)

    snapshot = _pull(tmp_path)

    assert isinstance(snapshot, ExportSnapshot)
    assert calls == ["read"]
    assert triggers == [{"port": "auto", "code": "1812", "reset": True}]
    assert len(cleanups) == 1
    assert cleanups[0]["cleanup_mode"] == "auto"


def test_pull_catalog_snapshot_passes_the_session_through(monkeypatch, tmp_path) -> None:
    sentinel = object()
    captured: list[dict] = []

    def fake_pull_live_export_snapshot(**kwargs):
        captured.append(kwargs)
        return SimpleNamespace(path=tmp_path / "EXPORT.CFG.bin")

    monkeypatch.setattr(catalog_io, "pull_live_export_snapshot", fake_pull_live_export_snapshot)
    monkeypatch.setattr(
        catalog_io,
        "extract_export_catalog",
        lambda path: SimpleNamespace(sections_by_id={1: object()}, pgs_by_id={}, objects_by_id={}, users=[]),
    )
    config = CatalogPullConfig(
        flexi_cfg_device="auto",
        port="auto",
        auth_code="1812",
        reset=True,
        read_cleanup_mode="auto",
        trigger_session=sentinel,
    )

    pull_catalog_snapshot(config, "test-prefix")

    assert len(captured) == 1
    assert captured[0]["trigger_session"] is sentinel
    assert captured[0]["cleanup_mode"] == "auto"
    assert CatalogPullConfig("auto", "auto", "1812", True, "auto").trigger_session is None


def test_the_empty_catalog_retry_pulls_on_the_same_session(monkeypatch, tmp_path) -> None:
    """A fully empty first read is retried once without reset. That second
    pull must run on the session too: falling back to the separate trigger
    would be a second login on the device while the status session holds
    it, which is the hazard the in-session pull removes."""
    sentinel = object()
    captured: list[dict] = []
    catalogs = [
        SimpleNamespace(sections_by_id={}, pgs_by_id={}, objects_by_id={}, users=[]),
        SimpleNamespace(sections_by_id={1: object()}, pgs_by_id={}, objects_by_id={}, users=[]),
    ]

    def fake_pull_live_export_snapshot(**kwargs):
        captured.append(kwargs)
        return SimpleNamespace(path=tmp_path / f"EXPORT-{len(captured)}.CFG.bin")

    monkeypatch.setattr(catalog_io, "pull_live_export_snapshot", fake_pull_live_export_snapshot)
    monkeypatch.setattr(catalog_io, "extract_export_catalog", lambda path: catalogs.pop(0))
    config = CatalogPullConfig(
        flexi_cfg_device="auto",
        port="auto",
        auth_code="1812",
        reset=True,
        read_cleanup_mode="auto",
        trigger_session=sentinel,
    )

    catalog = pull_catalog_snapshot(config, "test-prefix")

    assert len(captured) == 2
    assert all(call["trigger_session"] is sentinel for call in captured)
    assert captured[0]["reset"] is True
    assert captured[1]["reset"] is False
    assert captured[1]["output"] != captured[0]["output"]
    assert catalog.sections_by_id


def _retry_config() -> CatalogPullConfig:
    return CatalogPullConfig(
        flexi_cfg_device="auto",
        port="auto",
        auth_code="1812",
        reset=True,
        read_cleanup_mode="auto",
        trigger_session=object(),
    )


def _stalling_pull(monkeypatch, tmp_path, failures: list[BaseException]) -> list[dict]:
    """pull_live_export_snapshot raises each of `failures` in turn, then
    returns a snapshot whose catalog is not empty (no empty-catalog retry)."""

    calls: list[dict] = []

    def fake_pull_live_export_snapshot(**kwargs):
        calls.append(kwargs)
        if failures:
            raise failures.pop(0)
        return SimpleNamespace(path=tmp_path / "EXPORT.CFG.bin")

    monkeypatch.setattr(catalog_io, "pull_live_export_snapshot", fake_pull_live_export_snapshot)
    monkeypatch.setattr(
        catalog_io,
        "extract_export_catalog",
        lambda path: SimpleNamespace(sections_by_id={1: object()}, pgs_by_id={}, objects_by_id={}, users=[]),
    )
    return calls


STALL = "Export refresh did not reach the reload-complete state."


def test_pull_catalog_snapshot_retries_a_stalled_post_write_export(monkeypatch, tmp_path) -> None:
    sleeps: list[float] = []
    calls = _stalling_pull(monkeypatch, tmp_path, [RuntimeError(STALL), RuntimeError(STALL)])

    catalog = pull_catalog_snapshot(
        _retry_config(), "test-prefix", sleep=sleeps.append, settle_seconds=1.5, reload_retries=3
    )

    assert catalog.sections_by_id
    assert len(calls) == 3
    assert sleeps == [1.5, 2.0, 2.0]


def test_a_stalled_export_without_retries_is_a_runtime_error(monkeypatch, tmp_path) -> None:
    sleeps: list[float] = []
    calls = _stalling_pull(monkeypatch, tmp_path, [RuntimeError(STALL)])

    with pytest.raises(RuntimeError, match="reload-complete state"):
        pull_catalog_snapshot(
            _retry_config(), "test-prefix", sleep=sleeps.append, settle_seconds=1.5, reload_retries=1
        )

    assert len(calls) == 1
    assert sleeps == [1.5]


def test_a_stalled_export_from_the_separate_client_never_escapes_as_system_exit(monkeypatch, tmp_path) -> None:
    """The separate-client trigger reports the stall with SystemExit; out of
    a worker thread that would stop the server, so the retry loop always
    ends in a RuntimeError."""

    sleeps: list[float] = []
    calls = _stalling_pull(monkeypatch, tmp_path, [SystemExit(STALL) for _ in range(3)])

    with pytest.raises(RuntimeError, match="reload-complete state") as excinfo:
        pull_catalog_snapshot(
            _retry_config(), "test-prefix", sleep=sleeps.append, settle_seconds=1.5, reload_retries=3
        )

    assert isinstance(excinfo.value, catalog_io.ExportReloadStalled)
    assert len(calls) == 3
    assert sleeps == [1.5, 2.0, 2.0]


def test_other_pull_failures_are_not_retried(monkeypatch, tmp_path) -> None:
    sleeps: list[float] = []
    calls = _stalling_pull(monkeypatch, tmp_path, [RuntimeError("USB link failed before the export trigger")])

    with pytest.raises(RuntimeError, match="USB link failed") as excinfo:
        pull_catalog_snapshot(
            _retry_config(), "test-prefix", sleep=sleeps.append, settle_seconds=1.5, reload_retries=3
        )

    assert not isinstance(excinfo.value, catalog_io.ExportReloadStalled)
    assert len(calls) == 1
    assert sleeps == [1.5]


def test_an_ordinary_pull_neither_settles_nor_retries(monkeypatch, tmp_path) -> None:
    sleeps: list[float] = []
    calls = _stalling_pull(monkeypatch, tmp_path, [RuntimeError(STALL)])

    with pytest.raises(RuntimeError, match="reload-complete state"):
        pull_catalog_snapshot(_retry_config(), "test-prefix", sleep=sleeps.append)

    assert len(calls) == 1
    assert sleeps == []
