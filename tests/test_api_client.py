from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from jablotron_api.client.api import JablotronApiClient, JablotronApiError
from jablotron_api.cli.client import _token_payload, _user_payload, build_parser
from jablotron_api.domain.models import Scope
from jablotron_api.panel.demo import DemoPanelRuntime
from jablotron_api.server.app import create_app
from jablotron_api.server.config import ServerSettings
from jablotron_api.services.storage import TokenStore


def test_reference_client_covers_representative_methods_and_errors() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        assert request.headers["authorization"] == "Bearer token"
        if request.url.path == "/v1/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/v1/users" and request.method == "GET":
            return httpx.Response(200, json=[{"id": 90, "name": "Test User"}])
        if request.url.path == "/v1/users/90" and request.method == "GET":
            return httpx.Response(200, json={"id": 90, "name": "Test User"})
        if request.url.path == "/v1/users" and request.method == "POST":
            assert json.loads(request.content) == {"id": 91, "name": "Created"}
            return httpx.Response(200, json={"id": 91, "name": "Created"})
        if request.url.path == "/v1/users/91" and request.method == "PATCH":
            assert json.loads(request.content) == {"name": "Patched"}
            return httpx.Response(200, json={"id": 91, "name": "Patched"})
        if request.url.path == "/v1/users/91" and request.method == "DELETE":
            return httpx.Response(200, json={"status": "deleted", "user_id": 91})
        if request.url.path == "/v1/events/recent":
            assert request.url.params["limit"] == "5"
            assert request.url.params["include_raw"] == "true"
            return httpx.Response(200, json=[{"text": "armed"}])
        if request.url.path == "/v1/tokens":
            return httpx.Response(200, json=[])
        if request.url.path == "/v1/pgs/1/on":
            assert request.url.params["code"] == "1234"
            return httpx.Response(200, json={"pgs": [{"id": 1, "state": "on"}]})
        if request.url.path == "/v1/users/404":
            return httpx.Response(404, json={"detail": "User not found."})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    async def _run() -> None:
        async with JablotronApiClient(
            base_url="http://api.test",
            token="token",
            transport=httpx.MockTransport(handler),
        ) as client:
            assert await client.get_health() == {"status": "ok"}
            assert (await client.list_users())[0]["id"] == 90
            assert (await client.get_user(90))["name"] == "Test User"
            assert (await client.create_user({"id": 91, "name": "Created"}))["id"] == 91
            assert (await client.patch_user(91, {"name": "Patched"}))["name"] == "Patched"
            assert (await client.delete_user(91))["status"] == "deleted"
            assert (await client.list_events(limit=5, include_raw=True))[0]["text"] == "armed"
            assert await client.list_tokens() == []
            assert (await client.set_pg(1, True, code="1234"))["pgs"][0]["state"] == "on"
            try:
                await client.get_user(404)
            except JablotronApiError as exc:
                assert exc.status_code == 404
                assert exc.detail == "User not found."
            else:
                raise AssertionError("Expected JablotronApiError")

    asyncio.run(_run())
    assert ("POST", "/v1/users") in seen
    assert ("PATCH", "/v1/users/91") in seen
    assert ("DELETE", "/v1/users/91") in seen


def test_client_cli_user_payload_direct_flags_and_json_file(tmp_path: Path) -> None:
    json_path = tmp_path / "user.json"
    json_path.write_text('{"phone":"+421900000000","comment":"from-json"}', encoding="utf-8")

    args = build_parser().parse_args(
        [
            "users",
            "create",
            "90",
            "--base-url",
            "http://api.test",
            "--token",
            "token",
            "--timeout",
            "180",
            "--json",
            f"@{json_path}",
            "--name",
            "API REF TEST 90",
            "--code",
            "9090",
            "--sections",
            "1,2",
            "--pgs",
            "3",
        ]
    )

    payload = _user_payload(args, include_id=True)
    assert args.timeout == 180
    assert payload == {
        "id": 90,
        "name": "API REF TEST 90",
        "phone": "+421900000000",
        "code": "9090",
        "comment": "from-json",
        "sections": [1, 2],
        "pgs": [3],
    }


def test_client_cli_token_payload() -> None:
    args = build_parser().parse_args(
        [
            "tokens",
            "--base-url",
            "http://api.test",
            "--token",
            "token",
            "create",
            "--label",
            "ops",
            "--scope",
            "users:read",
            "--scope",
            "events:read",
            "--allowed-user-id",
            "90",
        ]
    )

    assert _token_payload(args) == {
        "label": "ops",
        "scopes": ["users:read", "events:read"],
        "allowed_user_ids": [90],
    }


def test_demo_runtime_pg_control_accepts_server_call_shape(tmp_path: Path) -> None:
    runtime = DemoPanelRuntime()
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(
        label="demo-pg",
        scopes=[Scope.PGS_CONTROL.value, Scope.CODES_IMPERSONATE.value, Scope.STATUS_READ.value],
    )
    app = create_app(
        settings=ServerSettings(db_path=tmp_path / "tokens.db", runtime_mode="demo"),
        runtime=runtime,
        token_store=store,
    )
    client = TestClient(app)

    response = client.post("/v1/pgs/1/off?code=1234", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert next(pg for pg in response.json()["pgs"] if pg["id"] == 1)["state"] == "off"
