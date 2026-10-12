"""POST /v1/users/batch over HTTP, against the demo runtime and a fake one.

The live runtime's behaviour (one map, one refresh, verification) is covered
in test_user_batch_runtime.py; this file holds the route's contract: request
and answer shapes, status codes, redaction, the audit row, the WebSocket
events, the setting and the reference client.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sqlite3

import httpx
import pytest
from fastapi.testclient import TestClient

from jablotron_api.client.api import JablotronApiClient
from jablotron_api.domain.models import (
    DEFAULT_ADMIN_SCOPES,
    Scope,
    UserBatchResponse,
    UserBatchResult,
    UserModel,
)
from jablotron_api.domain.user_validation import UserBatchRejected
from jablotron_api.panel.demo import DemoPanelRuntime
from jablotron_api.panel.runtime import PanelRuntimeConfig
from jablotron_api.server.app import create_app
from jablotron_api.server.config import PanelSettings, ServerSettings
from jablotron_api.services.storage import TokenStore


def _client(tmp_path: Path, runtime, *, scopes=None) -> tuple[TestClient, dict]:
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(label="admin", scopes=list(scopes or DEFAULT_ADMIN_SCOPES))
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db"),
        runtime=runtime,
        token_store=store,
    )
    return TestClient(app), {"Authorization": f"Bearer {token}"}


def _demo(tmp_path: Path, *, scopes=None):
    runtime = DemoPanelRuntime()
    events: list[tuple[str, dict]] = []

    async def listen(topic, payload):
        events.append((topic, payload))

    runtime.add_listener(listen)
    client, headers = _client(tmp_path, runtime, scopes=scopes)
    return client, headers, runtime, events


def _audit_rows(tmp_path: Path) -> list[tuple[str, str, dict]]:
    with sqlite3.connect(tmp_path / "tokens.db") as conn:
        rows = conn.execute("SELECT action, resource, details_json FROM audit_log ORDER BY id").fetchall()
    return [(action, resource, json.loads(details)) for action, resource, details in rows]


def _create(user_id: int, **fields) -> dict:
    return {"op": "create", "replace": fields.pop("replace", False), "user": {"id": user_id, "name": f"User {user_id}", **fields}}


def _update(user_id: int, **patch) -> dict:
    return {"op": "update", "id": user_id, "patch": patch}


# ------------------------------------------------------------------ demo


def test_a_batch_answers_per_user_results_in_request_order(tmp_path):
    client, headers, runtime, events = _demo(tmp_path)

    response = client.post(
        "/v1/users/batch",
        json={"writes": [_create(5, code="1490"), _update(2, name="Guard Two"), _create(3, code="1492")]},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert [(item["id"], item["op"], item["verified"], item["detail"]) for item in body["results"]] == [
        (5, "create", True, None),
        (2, "update", True, None),
        (3, "create", True, None),
    ]
    assert [item["user"]["name"] for item in body["results"]] == ["User 5", "Guard Two", "User 3"]
    assert isinstance(body["as_of"], str) and body["as_of"]
    assert "pull_started_after_request" in body
    assert [topic for topic, _ in events] == ["users", "users", "users"]
    assert [payload["action"] for _, payload in events] == ["added", "edited", "added"]
    assert {user.id for user in asyncio.run(runtime.get_users())} == {1, 2, 3, 5}


def test_a_batch_redacts_codes_like_post_users(tmp_path):
    scopes = [scope for scope in DEFAULT_ADMIN_SCOPES if scope != Scope.USERS_CODES_READ.value]
    client, headers, _, _ = _demo(tmp_path, scopes=scopes)

    response = client.post("/v1/users/batch", json={"writes": [_create(5, code="1490")]}, headers=headers)

    assert response.status_code == 200
    assert response.json()["results"][0]["user"]["code"] == ""
    assert "1490" not in response.text


def test_a_batch_writes_one_audit_row(tmp_path):
    client, headers, _, _ = _demo(tmp_path)

    client.post(
        "/v1/users/batch",
        json={"writes": [_create(5, replace=True), _update(2, name="Guard Two")]},
        headers=headers,
    )

    [(action, resource, details)] = _audit_rows(tmp_path)
    assert action == "batch_users"
    assert resource == "users:5,2"
    first, second = details["writes"]
    assert first["op"] == "create" and first["id"] == 5 and first["replace"] is True
    assert first["name"] == "User 5"
    assert second == {"op": "update", "id": 2, "name": "Guard Two"}


def test_a_batch_needs_users_write(tmp_path):
    scopes = [scope for scope in DEFAULT_ADMIN_SCOPES if scope != Scope.USERS_WRITE.value]
    client, headers, runtime, _ = _demo(tmp_path, scopes=scopes)

    response = client.post("/v1/users/batch", json={"writes": [_create(5)]}, headers=headers)

    assert response.status_code == 403
    assert asyncio.run(runtime.get_user(5)) is None


@pytest.mark.parametrize(
    ("writes", "reason"),
    [
        ([], "empty"),
        ([_create(3), _create(4), _create(5), _create(6)], "too_many"),
        ([_create(5), _update(5, name="Again")], "duplicate_id"),
    ],
    ids=["empty", "too_many", "duplicate_id"],
)
def test_a_malformed_batch_is_a_400_batch_rejected(tmp_path, writes, reason):
    client, headers, runtime, events = _demo(tmp_path)

    response = client.post("/v1/users/batch", json={"writes": writes}, headers=headers)

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "batch_rejected"
    assert detail["reason"] == reason
    assert isinstance(detail["message"], str) and detail["message"]
    assert events == []
    assert _audit_rows(tmp_path) == []


def test_a_cross_record_conflict_is_a_400_naming_the_record_and_its_peer(tmp_path):
    client, headers, runtime, events = _demo(tmp_path)

    response = client.post(
        "/v1/users/batch",
        json={"writes": [_create(5, code="1490"), _create(6, code="1490")]},
        headers=headers,
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["error"] == "user_write_rejected"
    assert detail["reason"] == "duplicate_code"
    assert detail["user_id"] == 5
    assert detail["conflicting_user_ids"] == [6]
    assert "1490" not in response.text
    assert events == []
    assert asyncio.run(runtime.get_user(5)) is None


def test_a_create_on_an_occupied_slot_is_a_409_and_writes_nothing(tmp_path):
    client, headers, runtime, events = _demo(tmp_path)

    response = client.post(
        "/v1/users/batch", json={"writes": [_create(5), _create(1)]}, headers=headers
    )

    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["error"] == "user_slot_occupied"
    assert detail["user_id"] == 1
    assert events == []
    assert asyncio.run(runtime.get_user(5)) is None


def test_an_update_of_a_missing_user_is_a_409_and_writes_nothing(tmp_path):
    client, headers, runtime, events = _demo(tmp_path)

    response = client.post(
        "/v1/users/batch", json={"writes": [_create(5), _update(9, name="Nobody")]}, headers=headers
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "User 9 not found."}
    assert events == []
    assert asyncio.run(runtime.get_user(5)) is None


def test_the_demo_leaves_a_no_op_update_without_an_event(tmp_path):
    client, headers, _, events = _demo(tmp_path)

    response = client.post(
        "/v1/users/batch", json={"writes": [_update(2, name="Guard"), _create(5)]}, headers=headers
    )

    assert response.status_code == 200
    assert [item["verified"] for item in response.json()["results"]] == [True, True]
    assert [payload["action"] for _, payload in events] == ["added"]


def test_an_unknown_op_is_a_422(tmp_path):
    client, headers, _, _ = _demo(tmp_path)

    response = client.post(
        "/v1/users/batch", json={"writes": [{"op": "delete", "id": 2}]}, headers=headers
    )

    assert response.status_code == 422


# ------------------------------------------------------------ fake runtime


class _FakeBatchRuntime:
    def __init__(self, outcome) -> None:
        self.outcome = outcome
        self.calls: list = []

    def add_listener(self, listener) -> None:
        return None

    async def start(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def batch_users(self, writes):
        self.calls.append(writes)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def test_a_payload_too_large_refusal_is_a_400_batch_rejected(tmp_path):
    runtime = _FakeBatchRuntime(UserBatchRejected("payload_too_large", "The batch is 600 bytes."))
    client, headers = _client(tmp_path, runtime)

    response = client.post("/v1/users/batch", json={"writes": [_create(5)]}, headers=headers)

    assert response.status_code == 400
    assert response.json()["detail"] == {
        "error": "batch_rejected",
        "reason": "payload_too_large",
        "message": "The batch is 600 bytes.",
    }


def test_a_panel_failure_is_the_single_routes_409_string(tmp_path):
    runtime = _FakeBatchRuntime(RuntimeError("Panel write failed: setup mode refused"))
    client, headers = _client(tmp_path, runtime)

    response = client.post("/v1/users/batch", json={"writes": [_create(5)]}, headers=headers)

    assert response.status_code == 409
    assert response.json() == {"detail": "Panel write failed: setup mode refused"}
    assert _audit_rows(tmp_path) == []


def test_an_unverified_result_is_still_a_200(tmp_path):
    outcome = UserBatchResponse(
        results=[
            UserBatchResult(id=5, op="create", verified=False, user=UserModel(id=5, name="User 5", code="1490"), detail="User 5 post-add verification failed for: comment."),
            UserBatchResult(id=6, op="create", verified=False, user=None, detail="User 6 was not present after the batch write."),
        ],
        as_of=None,
        pull_started_after_request=True,
    )
    scopes = [scope for scope in DEFAULT_ADMIN_SCOPES if scope != Scope.USERS_CODES_READ.value]
    client, headers = _client(tmp_path, _FakeBatchRuntime(outcome), scopes=scopes)

    response = client.post("/v1/users/batch", json={"writes": [_create(5), _create(6)]}, headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["results"][0]["user"]["code"] == ""
    assert body["results"][0]["detail"] == "User 5 post-add verification failed for: comment."
    assert body["results"][1]["user"] is None
    assert body["pull_started_after_request"] is True


def test_the_route_refuses_a_malformed_batch_without_calling_the_runtime(tmp_path):
    runtime = _FakeBatchRuntime(AssertionError("must not be called"))
    client, headers = _client(tmp_path, runtime)

    response = client.post("/v1/users/batch", json={"writes": []}, headers=headers)

    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "empty"
    assert runtime.calls == []


# ---------------------------------------------------------------- setting


def test_the_shipped_batch_limit_is_three(monkeypatch):
    assert PanelSettings(auth_code="x").batch_max_records == 3
    assert PanelRuntimeConfig().batch_max_records == 3
    monkeypatch.delenv("JABLOTRON_PANEL_BATCH_MAX_RECORDS", raising=False)
    assert ServerSettings().panel.batch_max_records == 3
    monkeypatch.setenv("JABLOTRON_PANEL_BATCH_MAX_RECORDS", "5")
    assert ServerSettings().panel.batch_max_records == 5


@pytest.mark.parametrize("mode", ["live", "demo"])
def test_a_batch_limit_below_one_is_refused_at_startup(tmp_path, mode):
    settings = ServerSettings(
        db_path=tmp_path / "tokens.db",
        runtime_mode=mode,
        panel=PanelSettings(auth_code="1812", batch_max_records=0),
    )
    with pytest.raises(RuntimeError, match="JABLOTRON_PANEL_BATCH_MAX_RECORDS must be >= 1"):
        create_app(settings=settings, token_store=TokenStore(tmp_path / "tokens.db"))


def test_the_demo_takes_the_limit_from_the_settings(tmp_path):
    from jablotron_api.domain.models import UserBatchRequest

    settings = ServerSettings(
        db_path=tmp_path / "tokens.db",
        runtime_mode="demo",
        panel=PanelSettings(batch_max_records=1),
    )
    app = create_app(settings=settings, token_store=TokenStore(tmp_path / "tokens.db"))
    writes = UserBatchRequest.model_validate({"writes": [_create(5), _create(6)]}).writes

    # The runtime itself, not the route's check, refuses the second write.
    with pytest.raises(UserBatchRejected) as excinfo:
        asyncio.run(app.state.runtime.batch_users(writes))
    assert excinfo.value.reason == "too_many"


# ----------------------------------------------------------- schema, client


def test_the_openapi_document_describes_the_batch_route_and_catalog_freshness(tmp_path):
    client, _ = _client(tmp_path, DemoPanelRuntime())
    spec = client.app.openapi()

    assert "post" in spec["paths"]["/v1/users/batch"]
    schemas = spec["components"]["schemas"]
    assert "UserBatchRequest" in schemas and "UserBatchResponse" in schemas
    assert "pull_started_after_request" in schemas["ExportCatalogModel"]["properties"]


def test_the_reference_client_posts_a_batch():
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert (request.method, request.url.path) == ("POST", "/v1/users/batch")
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"results": [], "as_of": "2026-10-12T00:00:00Z", "pull_started_after_request": True})

    async def run():
        async with JablotronApiClient(
            base_url="http://api.test", token="token", transport=httpx.MockTransport(handler)
        ) as client:
            return await client.batch_users([_create(5)])

    result = asyncio.run(run())
    assert seen == [{"writes": [_create(5)]}]
    assert result["pull_started_after_request"] is True
