"""The HTTP write path must run the same user-table rules as the CLI.

Every test here stays offline: the panel-touching calls are replaced, and the
assertions are about *what would have been written* and whether the refusal
arrives before anything reaches the panel.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import jablotron_user_tool
from jablotron_api.domain.codes import CodeFormat
from jablotron_api.domain.models import (
    DEFAULT_ADMIN_SCOPES,
    ExportCatalogModel,
    InitialSetupModel,
    InitialSetupRangeModel,
    UserCreateModel,
    UserPatchModel,
)
from jablotron_api.domain.user_validation import (
    REASON_CODE_LENGTH_UNKNOWN,
    REASON_COMMENT_TOO_LONG,
    REASON_NAME_TOO_LONG,
    REASON_PANIC_CODE_COLLISION,
    UserTableEntry,
    UserWriteRejected,
    UserWriteViolation,
)
from jablotron_api.panel.demo import DemoPanelRuntime
import jablotron_api.panel.runtime as runtime_module
from jablotron_api.panel.runtime import PanelRuntime, PanelRuntimeConfig
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

    def __init__(self, user_id, code="", cards=(), time_limited_group_raw=None):
        self.user_id = user_id
        self.code = code
        self.cards = list(cards)
        self.time_limited_group_raw = time_limited_group_raw


def _manager_config(tmp_path: Path) -> UserManagerConfig:
    return UserManagerConfig(
        import_path=tmp_path / "IMPORT.CFG",
        flexi_cfg_device="/dev/null",
        port="auto",
        auth_code="1812",
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


def _runtime() -> PanelRuntime:
    runtime = PanelRuntime(PanelRuntimeConfig(port="auto", auth_code="1812"))
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


def test_runtime_takes_the_code_format_from_the_snapshot_it_just_read() -> None:
    runtime = _runtime()
    fmt = runtime._snapshot_code_format(_snapshot([], code_len=6, code_prefix=True))
    assert fmt == CodeFormat(6, True, "panel")


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

    async def fake_pull(prefix: str):
        captured["prefix"] = prefix
        return _snapshot([_Record(7, "1483")])

    def fake_apply(config, **kwargs):
        captured["preflight"] = kwargs["preflight"]

    async def fake_close() -> None:
        return None

    monkeypatch.setattr(runtime, "_pull_catalog_snapshot_locked", fake_pull)
    monkeypatch.setattr(runtime, "_close_status_session_locked", fake_close)
    monkeypatch.setattr(runtime_module, "_apply_upsert_user", fake_apply)
    monkeypatch.setattr(runtime, "refresh_catalog", fake_close)
    monkeypatch.setattr(
        runtime,
        "get_user",
        lambda user_id: _async_value(None),
    )

    async def run() -> None:
        with pytest.raises(RuntimeError):
            # The post-write lookup fails (get_user returns None); by then the
            # preflight has already been built and handed to the write.
            await runtime.add_user(UserCreateModel(id=4, name="New", code="1484"))

    asyncio.run(run())

    assert captured["prefix"].startswith("api-preflight-add-user")
    assert captured["preflight"].existing == (UserTableEntry(7, "1483", (), None),)
    assert captured["preflight"].code_format == CodeFormat(4, False, "panel")


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
