"""A PATCH whose encoded record equals the panel's record writes nothing."""

from __future__ import annotations

import pytest

from jablotron_api.services.catalog_io import user_to_model
from test_user_patch_carry_over import _edit, _Harness, _panel_record


@pytest.mark.parametrize(
    "patch",
    [
        {"name": "Guard 4"},
        {"code": "1486", "comment": ""},
        {"sections": [3, 1], "pgs": [97, 4, 1]},
    ],
    ids=["same-name", "same-code", "same-masks"],
)
def test_a_patch_that_changes_nothing_writes_nothing(monkeypatch, tmp_path, patch):
    record = _panel_record()
    h = _Harness(monkeypatch, tmp_path, [record])
    cached = h.runtime._catalog_snapshot

    user = _edit(h, patch, verify=True)
    assert h.session.writes == [], "no configuration event for a no-op"
    assert h.refreshes == []
    assert h.runtime._catalog_snapshot is cached
    assert h.runtime._catalog_dirty is False
    assert h.emitted == []
    assert user == user_to_model(record)


def test_a_no_op_patch_after_a_preflight_pull_announces_only_the_catalog(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, [_panel_record()], window=0.0)

    _edit(h, {"name": "Guard 4"}, verify=True)
    assert h.session.writes == []
    assert h.refreshes == [("api-preflight-edit-user4", False)]
    assert h.emitted == ["catalog"]


def test_a_patch_that_changes_one_field_still_writes(monkeypatch, tmp_path):
    h = _Harness(monkeypatch, tmp_path, [_panel_record()])

    _edit(h, {"name": "Guard 4", "comment": "night shift"})
    assert len(h.session.writes) == 1
    assert h.refreshes == [("api-after-edit-user4", True)]
