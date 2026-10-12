"""POST /v1/users/batch in the live runtime: one configuration event for
several users.

Every test runs offline on the harness of the PATCH carry-over tests: the
status session is logged in with master rights and records the payload of
its one HID write instead of sending it, every separate-client path is a
test failure, and the catalog pulls are fakes. The fake panel here applies
the written collection-7 map to its rows, so the post-write pull returns
what the panel would hold and the per-user verification runs against it.
"""

from __future__ import annotations

import asyncio
import dataclasses

import msgpack
import pytest

import jablotron_re_tools as re_tools
from import_cfg_tool import decode_bitmask_ids, decode_pg_ids
from jablotron_api.domain.models import (
    UserBatchCreate,
    UserBatchUpdate,
    UserCreateModel,
    UserPatchModel,
)
from jablotron_api.domain.user_validation import (
    REASON_DUPLICATE_CARD,
    REASON_DUPLICATE_CODE,
    REASON_PANIC_CODE_COLLISION,
    UserBatchRecordRejected,
    UserBatchRejected,
    UserSlotOccupied,
)
from jablotron_api.protocol import legacy
from jablotron_api.services.catalog_io import user_to_model
from test_user_patch_carry_over import _Harness, _panel_record


CARD_A = "00000A0001"


def _row(user_id: int, record: dict) -> re_tools.UserRecord:
    """A written collection-7 record as the export parser would read it back."""

    return re_tools.UserRecord(
        offset=0,
        user_id=user_id,
        raw_id_bytes="",
        flags_raw=record[0],
        flags=[],
        access_raw=record[1],
        rights="",
        enabled=None,
        section_access_mask_raw=record[2],
        section_ids=decode_bitmask_ids(record[2], bits=15),
        pg_access_masks_raw=list(record[3]),
        pg_ids=decode_pg_ids(record[3]),
        name=record[4],
        phone=record[5],
        code=record[6],
        cards=[card[0] for card in record[7]],
        comment=record[10],
        pg_num_if_ring_raw=record[8],
        time_limited_group_raw=record[9],
        parent_user_no_raw=record[11],
    )


class _BatchHarness(_Harness):
    """The PATCH harness, with a panel that takes the written map in.

    ``tamper`` may rewrite a row as the post-write pull returns it, to stand
    for a panel that stored something other than what was sent.
    """

    def __init__(self, monkeypatch, tmp_path, records, *, window: float = 60.0, max_records: int = 3):
        super().__init__(monkeypatch, tmp_path, records, window=window)
        runtime = self.runtime
        runtime._config.batch_max_records = max_records
        self.tamper = None

        async def fake_pull(prefix: str, *, after_write: bool = False):
            if after_write and self.session.writes:
                written = msgpack.unpackb(self.session.writes[-1], strict_map_key=False)[7]
                rows = {record.user_id: record for record in self.records}
                for user_id, record in written.items():
                    rows[user_id] = _row(user_id, record)
                if self.tamper is not None:
                    rows = {user_id: self.tamper(row) for user_id, row in rows.items()}
                self.records = list(rows.values())
            from test_user_write_paths import _snapshot

            return _snapshot(list(self.records))

        async def get_user(user_id, max_age_seconds=None):
            snapshot = runtime._catalog_snapshot
            for record in snapshot.users:
                if record.user_id == user_id and record.name:
                    return user_to_model(record)
            return None

        monkeypatch.setattr(runtime, "_pull_catalog_snapshot_locked", fake_pull)
        monkeypatch.setattr(runtime, "get_user", get_user)

    def batch(self, writes):
        return asyncio.run(self.runtime.batch_users(writes))

    def written_maps(self) -> list[dict]:
        return [msgpack.unpackb(payload, strict_map_key=False)[7] for payload in self.session.writes]


def _create(user_id: int, *, replace: bool = False, **fields) -> UserBatchCreate:
    return UserBatchCreate(
        op="create", replace=replace, user=UserCreateModel(id=user_id, name=fields.pop("name", f"User {user_id}"), **fields)
    )


def _update(user_id: int, **fields) -> UserBatchUpdate:
    return UserBatchUpdate(op="update", id=user_id, patch=UserPatchModel(**fields))


# ------------------------------------------------------------- one event


def test_a_batch_writes_one_map_with_every_record_and_refreshes_once(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])

    response = h.batch([_create(5, code="1490"), _create(6, code="1492"), _update(4, name="Renamed")])

    [written] = h.written_maps()
    assert list(written) == [5, 6, 4], "one map, records in request order"
    assert written[5][6] == "1490" and written[6][6] == "1492"
    assert written[4][4] == "Renamed"
    # The update keeps what it did not send, as a single PATCH does.
    assert written[4][2] == 0b101 and written[4][3] == [0b1001, 0, 0, 1]
    assert (written[4][8], written[4][11]) == (3, 2)
    assert h.refreshes == [("api-after-batch-users", True)]
    assert [(item.id, item.op, item.verified, item.detail) for item in response.results] == [
        (5, "create", True, None),
        (6, "create", True, None),
        (4, "update", True, None),
    ]
    assert [item.user.name for item in response.results] == ["User 5", "User 6", "Renamed"]
    assert h.emitted == ["catalog", "users", "users", "users"]


def test_a_cold_cache_costs_one_preflight_pull_and_one_refresh(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)], window=0.0)

    response = h.batch([_create(5), _create(6)])

    assert len(h.session.writes) == 1
    assert h.refreshes == [("api-preflight-batch-users", False), ("api-after-batch-users", True)]
    assert response.pull_started_after_request is True


# ------------------------------------------------------- joint validation


def test_two_creates_with_the_same_code_are_refused_before_the_panel(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])

    with pytest.raises(UserBatchRecordRejected) as excinfo:
        h.batch([_create(5, code="1490"), _create(6, code="1490")])

    assert excinfo.value.reason == REASON_DUPLICATE_CODE
    assert excinfo.value.user_id == 5
    assert excinfo.value.conflicting_user_ids == (6,)
    payload = excinfo.value.to_payload()
    assert payload["error"] == "user_write_rejected"
    assert payload["user_id"] == 5
    assert h.session.writes == [] and h.refreshes == []
    assert h.runtime._catalog_dirty is False


def test_two_records_with_the_same_card_are_refused(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])

    with pytest.raises(UserBatchRecordRejected) as excinfo:
        h.batch([_create(5, card1=CARD_A), _update(4, card1=CARD_A)])

    assert excinfo.value.reason == REASON_DUPLICATE_CARD
    assert excinfo.value.user_id == 5
    assert excinfo.value.conflicting_user_ids == (4,)
    assert h.session.writes == []


def test_a_peer_panic_twin_is_refused(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])

    with pytest.raises(UserBatchRecordRejected) as excinfo:
        h.batch([_create(5, code="1490"), _create(6, code="1491")])

    assert excinfo.value.reason == REASON_PANIC_CODE_COLLISION
    assert excinfo.value.conflicting_user_ids == (6,)
    assert h.session.writes == []


def test_a_peer_is_judged_at_its_new_value_so_a_code_swap_is_legal(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4, code="1486"), _panel_record(7, name="Guard 7", code="1480")])

    response = h.batch([_update(4, code="1480"), _update(7, code="1486")])

    [written] = h.written_maps()
    assert (written[4][6], written[7][6]) == ("1480", "1486")
    assert all(item.verified for item in response.results)


def test_a_code_freed_by_a_peer_is_judged_against_the_rest_of_the_table(monkeypatch, tmp_path):
    # User 7 keeps 1480; a create may not take it even when the batch also
    # edits user 7's name.
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4), _panel_record(7, name="Guard 7", code="1480")])

    with pytest.raises(UserBatchRecordRejected) as excinfo:
        h.batch([_update(7, name="Guard Seven"), _create(5, code="1480")])

    assert excinfo.value.reason == REASON_DUPLICATE_CODE
    assert excinfo.value.user_id == 5
    assert h.session.writes == []


def test_a_section_outside_the_panels_range_is_refused_before_the_write(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])

    with pytest.raises(RuntimeError, match=r"^Panel write failed: "):
        h.batch([_create(5), _update(4, sections=[99])])

    assert h.session.writes == [] and h.refreshes == []
    assert h.runtime._catalog_dirty is False, "nothing was sent, so the cache stays clean"


# ----------------------------------------------------- slot refusals


def test_a_create_on_an_occupied_slot_writes_nothing(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])

    with pytest.raises(UserSlotOccupied) as excinfo:
        h.batch([_create(5), _create(4)])

    assert excinfo.value.user_id == 4
    assert h.session.writes == [] and h.refreshes == []


def test_replace_lets_a_create_overwrite_its_slot(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])

    response = h.batch([_create(4, replace=True, name="Fresh 4")])

    [written] = h.written_maps()
    assert written[4][4] == "Fresh 4"
    assert written[4][2] == 0, "a create starts from the default record"
    assert response.results[0].verified is True


def test_an_update_of_a_missing_user_writes_nothing(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])

    with pytest.raises(RuntimeError, match=r"^User 9 not found\.$"):
        h.batch([_create(5), _update(9, name="Nobody")])

    assert h.session.writes == [] and h.refreshes == []


# -------------------------------------------------------- request shape


@pytest.mark.parametrize(
    ("writes", "reason"),
    [
        ([], "empty"),
        ([_create(5), _create(6), _create(7), _create(8)], "too_many"),
        ([_create(5), _update(5, name="Again")], "duplicate_id"),
    ],
    ids=["empty", "too_many", "duplicate_id"],
)
def test_a_malformed_batch_is_refused_before_any_panel_traffic(monkeypatch, tmp_path, writes, reason):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)], window=0.0)

    with pytest.raises(UserBatchRejected) as excinfo:
        h.batch(writes)

    assert excinfo.value.reason == reason
    assert excinfo.value.to_payload() == {
        "error": "batch_rejected",
        "reason": reason,
        "message": str(excinfo.value),
    }
    assert h.refreshes == [], "not even the preflight pull"
    assert h.session.writes == []


def _long_create(user_id: int) -> UserBatchCreate:
    # About 150 bytes of msgpack: a 60-byte name and a 60-byte comment.
    return _create(user_id, name=f"{user_id:02d}" + "n" * 58, comment="c" * 60)


def test_a_batch_that_does_not_fit_one_sector_is_refused_under_auto(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)], max_records=5)

    with pytest.raises(UserBatchRejected) as excinfo:
        h.batch([_long_create(user_id) for user_id in (5, 6, 7, 8)])

    assert excinfo.value.reason == "payload_too_large"
    assert h.session.writes == [] and h.refreshes == []


def test_the_default_three_does_not_always_fit_the_sector(monkeypatch, tmp_path):
    """README and the status entry tell a client to expect payload_too_large
    at the default limit: three long records do not fit, two do."""

    def longest(user_id: int) -> UserBatchCreate:
        return _create(user_id, name=f"{user_id:02d}" + "n" * 58, comment="c" * 60, phone="+" + "4" * 19)

    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])
    with pytest.raises(UserBatchRejected) as excinfo:
        h.batch([longest(user_id) for user_id in (5, 6, 7)])
    assert excinfo.value.reason == "payload_too_large"
    assert h.session.writes == []

    h.batch([longest(user_id) for user_id in (5, 6)])
    assert list(h.written_maps()[0]) == [5, 6]


def test_the_hid_transport_takes_the_same_batch_up_to_its_own_bound(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)], max_records=5)
    h.runtime._config.write_transport = "hid"

    h.batch([_long_create(user_id) for user_id in (5, 6, 7, 8)])

    [payload] = h.session.writes
    assert 512 < len(payload) <= re_tools.HID_CONFIG_WRITE_MAX_PAYLOAD
    assert list(msgpack.unpackb(payload, strict_map_key=False)[7]) == [5, 6, 7, 8]


def test_the_hid_transport_refuses_a_batch_over_its_bound(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)], max_records=10)
    h.runtime._config.write_transport = "hid"

    with pytest.raises(UserBatchRejected) as excinfo:
        h.batch([_long_create(user_id) for user_id in range(5, 13)])

    assert excinfo.value.reason == "payload_too_large"
    assert h.session.writes == []


# ----------------------------------------------------- after the write


def test_a_record_the_panel_stored_differently_is_unverified_not_a_409(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])

    def drop_comment(row):
        return dataclasses.replace(row, comment="") if row.user_id == 6 else row

    h.tamper = drop_comment
    response = h.batch([_create(5, comment="day"), _create(6, comment="night")])

    first, second = response.results
    assert (first.verified, first.detail) == (True, None)
    assert second.verified is False
    assert second.detail == "User 6 post-add verification failed for: comment."
    assert second.user is not None and second.user.comment == ""
    assert h.runtime._catalog_dirty is False


def test_a_record_missing_after_the_write_is_unverified_without_a_user(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])

    def lose_six(row):
        return dataclasses.replace(row, name="") if row.user_id == 6 else row

    h.tamper = lose_six
    response = h.batch([_create(5), _create(6)])

    assert response.results[1].verified is False
    assert response.results[1].user is None
    assert response.results[1].detail == "User 6 was not present after the batch write."
    assert h.emitted == ["catalog", "users"], "no users event for a user that is not there"


def test_a_no_op_update_is_left_out_of_the_map(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])

    response = h.batch([_update(4, name="Guard 4"), _create(5)])

    [written] = h.written_maps()
    assert list(written) == [5]
    assert [(item.id, item.verified, item.detail) for item in response.results] == [(4, True, None), (5, True, None)]
    assert response.results[0].user.name == "Guard 4"
    assert h.emitted == ["catalog", "users"]


def test_a_batch_of_no_ops_has_no_configuration_event(monkeypatch, tmp_path):
    record = _panel_record(4)
    h = _BatchHarness(monkeypatch, tmp_path, [record, _panel_record(7, name="Guard 7", code="1480")])
    cached = h.runtime._catalog_snapshot

    response = h.batch([_update(4, name="Guard 4"), _update(7, sections=[3, 1])])

    assert h.session.writes == []
    assert h.refreshes == []
    assert h.runtime._catalog_snapshot is cached
    assert h.emitted == []
    assert [item.verified for item in response.results] == [True, True]
    assert response.results[0].user == user_to_model(record)
    assert response.pull_started_after_request is False


def test_a_refused_panel_write_is_the_single_routes_409_and_dirties_the_cache(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])

    def refuse(payload, *, code=None):
        raise legacy.PanelConfigError("setup mode refused")

    h.session.write_configuration = refuse
    with pytest.raises(RuntimeError, match=r"^Panel write failed: setup mode refused$"):
        h.batch([_create(5), _create(6)])

    assert h.refreshes == []
    assert h.runtime._catalog_dirty is True


def test_a_failed_refresh_after_the_write_says_the_batch_landed(monkeypatch, tmp_path):
    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])
    pull = h.runtime._pull_catalog_snapshot_locked

    async def stalled(prefix, *, after_write=False):
        if after_write:
            raise RuntimeError("Panel catalog read failed: export stalled")
        return await pull(prefix, after_write=after_write)

    monkeypatch.setattr(h.runtime, "_pull_catalog_snapshot_locked", stalled)
    with pytest.raises(RuntimeError) as excinfo:
        h.batch([_create(5), _create(6)])

    assert str(excinfo.value).startswith(
        "The batch for users 5, 6 was written but the catalog refresh failed: "
    )
    assert len(h.session.writes) == 1
    assert h.runtime._catalog_dirty is True


# ------------------------------------------------- the other transports


def test_the_storage_transport_stages_the_batch_in_one_sector(monkeypatch, tmp_path):
    from import_cfg_tool import decode_sector
    import jablotron_api.services.user_manager as user_manager

    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])
    h.runtime._config.write_transport = "storage"
    staged: list[tuple[str, bytes]] = []

    def stage(*, sector_path, **kwargs):
        sector = sector_path.read_bytes()
        staged.append((str(sector_path), sector))
        # The fake panel takes the staged command in, as it does over HID.
        h.session.writes.append(re_tools.sector_payload_bytes(sector))

    monkeypatch.setattr(user_manager, "apply_import_sector", stage)
    response = h.batch([_create(5), _create(6)])

    [(path, sector)] = staged
    assert len(sector) == 512
    assert list(decode_sector(sector)["payload"][7]) == [5, 6]
    assert path.startswith(str(tmp_path)), "the sector goes where the tests point the builder"
    assert not (tmp_path / "api-batch-users.bin").exists(), "the staged sector is removed"
    assert h.session.closes == 1, "the storage write runs outside the status session"
    assert [item.verified for item in response.results] == [True, True]


def test_a_separate_write_code_sends_the_batch_over_its_own_hid_client(monkeypatch, tmp_path):
    import jablotron_api.services.user_manager as user_manager

    h = _BatchHarness(monkeypatch, tmp_path, [_panel_record(4)])
    h.runtime._config.write_transport = "hid"
    h.runtime._config.write_auth_code = "2913"
    sent: list[dict] = []

    def over_hid(**kwargs):
        sent.append(kwargs)
        h.session.writes.append(kwargs["payload"])

    monkeypatch.setattr(user_manager, "apply_config_payload_over_hid", over_hid)
    h.batch([_create(5), _create(6)])

    [call] = sent
    assert call["code"] == "2913"
    assert list(msgpack.unpackb(call["payload"], strict_map_key=False)[7]) == [5, 6]
    assert h.session.closes == 1
