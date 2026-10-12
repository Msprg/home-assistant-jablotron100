"""The demo runtime answers a delete of an empty slot, a no-op PATCH and a
batch as the panel runtime does: no write, so no users event, where the
panel would get none."""

from __future__ import annotations

import asyncio

from fastapi.testclient import TestClient

import pytest

from jablotron_api.domain.models import DEFAULT_ADMIN_SCOPES, UserBatchUpdate, UserModel, UserPatchModel
from jablotron_api.panel.demo import DemoPanelRuntime
from jablotron_api.server.app import create_app
from jablotron_api.server.config import ServerSettings
from jablotron_api.services.storage import TokenStore


def _demo() -> tuple[DemoPanelRuntime, list[tuple[str, dict]]]:
    runtime = DemoPanelRuntime()
    events: list[tuple[str, dict]] = []

    async def listener(topic, payload):
        events.append((topic, payload))

    runtime.add_listener(listener)
    return runtime, events


def test_demo_delete_of_an_empty_slot_announces_no_deletion():
    runtime, events = _demo()

    asyncio.run(runtime.delete_user(5))
    assert events == []
    assert [user.id for user in runtime._catalog.users] == [1, 2]


def test_demo_delete_of_a_present_user_still_announces_it():
    runtime, events = _demo()

    asyncio.run(runtime.delete_user(2))
    assert events == [("users", {"action": "deleted", "user_id": 2})]


def test_demo_patch_that_changes_nothing_announces_no_edit():
    runtime, events = _demo()

    user = asyncio.run(runtime.edit_user(2, UserPatchModel(name="Guard")))
    assert user.name == "Guard"
    assert events == []

    asyncio.run(runtime.edit_user(2, UserPatchModel(name="Guard 2")))
    assert [topic for topic, _ in events] == ["users"]


def test_demo_http_delete_of_an_empty_slot_answers_deleted(tmp_path):
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(label="admin", scopes=list(DEFAULT_ADMIN_SCOPES))
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=DemoPanelRuntime(),
        token_store=store,
    )
    response = TestClient(app).delete("/v1/users/5", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"status": "deleted", "user_id": 5}


def _update(user_id: int, **patch) -> UserBatchUpdate:
    return UserBatchUpdate(op="update", id=user_id, patch=UserPatchModel(**patch))


def test_demo_batch_treats_an_explicit_null_as_not_sent():
    runtime, events = _demo()
    before = asyncio.run(runtime.get_user(2))

    answer = asyncio.run(runtime.batch_users([_update(2, name=None, phone=None, sections=None, pgs=None)]))

    assert events == []
    assert answer.results[0].verified is True
    assert asyncio.run(runtime.get_user(2)) == before


def test_demo_batch_refuses_an_update_of_a_nameless_slot():
    runtime, events = _demo()
    runtime._catalog.users.append(UserModel(id=4, name=""))

    with pytest.raises(RuntimeError, match="User 4 not found."):
        asyncio.run(runtime.batch_users([_update(4, name="Someone")]))
    assert events == []
    assert asyncio.run(runtime.get_user(4)).name == ""


def test_demo_batch_compares_sections_and_pgs_without_order():
    runtime, events = _demo()
    runtime._catalog.users[1].section_ids = [1, 2]
    runtime._catalog.users[1].pg_ids = [1, 2]

    asyncio.run(runtime.batch_users([_update(2, sections=[2, 1], pgs=[2, 1])]))
    assert events == []

    asyncio.run(runtime.batch_users([_update(2, sections=[2], pgs=[2, 1], name="Guard 2")]))
    stored = asyncio.run(runtime.get_user(2))
    assert (stored.section_ids, stored.pg_ids) == ([2], [1, 2])
    assert [payload["action"] for _, payload in events] == ["edited"]
