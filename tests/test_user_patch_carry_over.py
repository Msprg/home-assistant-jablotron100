"""PATCH carries over the fields it does not send from the panel's row.

Each test runs offline. The panel write is captured at the status session's
``write_configuration`` (the in-session HID path), so the bytes asserted on
are the ones the real record builder produced; every separate-client path is
replaced with a test failure. The harness here is shared with the delete and
no-op PATCH tests.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import msgpack
import pytest

import jablotron_re_tools as re_tools
import jablotron_user_tool
from jablotron_api.domain.models import UserModel, UserPatchModel
from jablotron_api.services.catalog_io import user_to_model
import jablotron_api.services.user_manager as user_manager
from test_user_write_paths import _route_refresh, _runtime, _snapshot


CARD2 = "00000A0001"


def _panel_record(
    user_id: int = 4,
    *,
    name: str = "Guard 4",
    code: str = "1486",
    cards: tuple[str, ...] = ("", ""),
    section_mask: int = 0b101,
    pg_masks: tuple[int, ...] = (0b1001, 0, 0, 1),
    pg_num: int = 3,
    parent: int = 2,
) -> re_tools.UserRecord:
    """A user row as the export parser yields it, with every raw field set."""

    return re_tools.UserRecord(
        offset=0,
        user_id=user_id,
        raw_id_bytes="",
        flags_raw=0,
        flags=[],
        access_raw=827,
        rights="coUser",
        enabled=True,
        section_access_mask_raw=section_mask,
        section_ids=[1, 3],
        pg_access_masks_raw=list(pg_masks),
        pg_ids=[1, 4, 97],
        name=name,
        phone="",
        code=code,
        cards=list(cards),
        comment="",
        pg_num_if_ring_raw=pg_num,
        time_limited_group_raw=0,
        parent_user_no_raw=parent,
    )


class _MasterSession:
    """The status session, logged in with master rights: the write goes over
    HID inside it, and its payload is recorded instead of sent."""

    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.closes = 0

    def login_rights_for_code(self, code):
        return re_tools.LoginRights(rights_raw=re_tools.LOGIN_RIGHTS_MASTER, position=1)

    def write_configuration(self, payload, *, code=None):
        self.writes.append(bytes(payload))
        return None

    def close(self) -> None:
        self.closes += 1


class _Harness:
    """A PanelRuntime with a warm, clean cached table holding ``records``.

    The pull returns ``records`` too. Lookups through ``get_user`` answer from
    ``self.lookup``; the post-write verification is left to each test.
    """

    def __init__(self, monkeypatch, tmp_path: Path, records, *, window: float = 60.0) -> None:
        self.runtime = runtime = _runtime()
        runtime._config.write_preflight_max_age_seconds = window
        self.records = list(records)
        self.session = _MasterSession()
        runtime._status_session = self.session
        runtime._catalog_snapshot = _snapshot(list(self.records))
        runtime._catalog_started_monotonic_for_cache = time.monotonic()
        runtime._catalog_completed_monotonic = time.monotonic()
        self.emitted: list[str] = []
        self.lookup: dict[int, UserModel | None] = {
            record.user_id: user_to_model(record) for record in self.records if record.name
        }

        async def fake_pull(prefix: str, *, after_write: bool = False):
            return _snapshot(list(self.records))

        async def fake_emit(topic, payload):
            self.emitted.append(topic)

        async def get_user(user_id, max_age_seconds=None):
            return self.lookup.get(user_id)

        def refuse(**kwargs):
            pytest.fail("the write must stay inside the status session")

        monkeypatch.setattr(runtime, "_pull_catalog_snapshot_locked", fake_pull)
        monkeypatch.setattr(runtime, "_emit", fake_emit)
        monkeypatch.setattr(runtime, "get_user", get_user)
        monkeypatch.setattr(user_manager, "probe_login_rights", refuse)
        monkeypatch.setattr(user_manager, "apply_import_sector", refuse)
        monkeypatch.setattr(user_manager, "apply_config_payload_over_hid", refuse)
        monkeypatch.setattr(
            jablotron_user_tool, "default_sector_output", lambda prefix: tmp_path / f"{prefix}.bin"
        )
        self.refreshes = _route_refresh(monkeypatch, runtime)

    def written_records(self) -> list[dict]:
        return [msgpack.unpackb(payload, strict_map_key=False)[7] for payload in self.session.writes]


def _verify_error(func, user, payload) -> str | None:
    try:
        func(user, payload)
    except RuntimeError as exc:
        return str(exc)
    return None


def _edit(h: _Harness, patch: dict, *, verify: bool = False) -> UserModel:
    if not verify:
        h.runtime._verify_edited_user = lambda user, payload: None
    return asyncio.run(h.runtime.edit_user(4, UserPatchModel.model_validate(patch)))


def test_a_patch_naming_only_the_name_keeps_the_masks_pg_num_and_parent(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, [_panel_record()])
    _edit(h, {"name": "Renamed"})

    [written] = h.written_records()
    record = written[4]
    assert record[4] == "Renamed"
    assert record[2] == 0b101, "the section mask was wiped"
    assert record[3] == [0b1001, 0, 0, 1], "the PG masks were wiped"
    assert record[8] == 3, "pg_num_if_ring was reset"
    assert record[11] == 2, "the parent user was reset"


def test_a_patch_keeps_a_lone_second_card_in_its_slot(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, [_panel_record(cards=("", CARD2))])
    _edit(h, {"name": "Renamed"})

    [written] = h.written_records()
    assert written[4][7] == [{0: ""}, {0: CARD2}]


def test_sent_sections_and_pgs_still_replace_the_masks(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, [_panel_record()])
    _edit(h, {"sections": [2], "pgs": [5]})

    [written] = h.written_records()
    assert written[4][2] == 0b10
    assert written[4][3] == [0b10000, 0, 0, 0]
    assert (written[4][8], written[4][11]) == (3, 2)


def test_an_explicit_empty_list_clears_the_sections_and_pgs(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, [_panel_record()])
    _edit(h, {"sections": [], "pgs": []})

    [written] = h.written_records()
    assert written[4][2] == 0
    assert written[4][3] == [0, 0, 0, 0]
    assert (written[4][8], written[4][11]) == (3, 2)


def test_an_explicit_null_keeps_the_sections_and_pgs(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, [_panel_record()])
    _edit(h, {"name": "Renamed", "sections": None, "pgs": None})

    [written] = h.written_records()
    assert written[4][2] == 0b101
    assert written[4][3] == [0b1001, 0, 0, 1]


def test_an_explicit_null_is_not_checked_after_the_write():
    user = UserModel(id=4, name="Guard 4", section_ids=[1, 3], pg_ids=[1])
    payload = UserPatchModel.model_validate({"name": None, "sections": None, "pgs": None})
    assert _verify_error(user_manager.verify_edited_user, user, payload) is None
