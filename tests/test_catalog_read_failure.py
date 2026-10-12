"""A failed catalog pull behind a GET route is a 503, not an unmapped 500."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from jablotron_api.domain.models import DEFAULT_ADMIN_SCOPES
from jablotron_api.server.app import create_app
from jablotron_api.server.config import PanelSettings, ServerSettings
from jablotron_api.services.storage import TokenStore


class _FailingCatalogRuntime:
    def __init__(self, message: str, error: type[Exception] = RuntimeError) -> None:
        self.message = message
        self.error = error

    def add_listener(self, listener) -> None:
        return None

    async def start(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def _fail(self, *args, **kwargs):
        raise self.error(self.message)

    get_users = get_user = get_export_users = get_catalog = _fail
    get_export_time_limits = get_export_communications = _fail


def _failing_client(
    tmp_path: Path, message: str, error: type[Exception] = RuntimeError
) -> tuple[TestClient, dict]:
    store = TokenStore(tmp_path / "tokens.db")
    token, _ = store.create_token(label="admin", scopes=list(DEFAULT_ADMIN_SCOPES))
    app = create_app(
        settings=ServerSettings(
            db_path=tmp_path / "tokens.db",
            panel=PanelSettings(auth_code="1812", write_auth_code="2913"),
        ),
        runtime=_FailingCatalogRuntime(message, error),
        token_store=store,
    )
    return TestClient(app, raise_server_exceptions=False), {"Authorization": f"Bearer {token}"}


GET_ROUTES = [
    "/v1/users",
    "/v1/users/4",
    "/v1/export/users",
    "/v1/export/catalog",
    "/v1/export/time-limits",
    "/v1/export/communications",
]


@pytest.mark.parametrize("path", GET_ROUTES)
def test_a_failed_catalog_read_on_a_get_route_is_a_503(tmp_path, path):
    message = "Panel catalog read failed: Export refresh did not reach the reload-complete state."
    client, headers = _failing_client(tmp_path, message)

    response = client.get(path, headers=headers)
    assert response.status_code == 503
    assert response.json() == {"detail": message}


@pytest.mark.parametrize("path", GET_ROUTES)
def test_the_503_detail_names_the_catalog_read_and_carries_no_panel_code(tmp_path, path):
    client, headers = _failing_client(tmp_path, "login with 1812 then 2913 was refused")

    response = client.get(path, headers=headers)
    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail.startswith("Panel catalog read failed: ")
    assert "1812" not in detail and "2913" not in detail


@pytest.mark.parametrize("error", [OSError, ValueError])
@pytest.mark.parametrize("path", GET_ROUTES)
def test_a_device_or_parse_failure_outside_the_panel_wrapper_is_a_503_too(tmp_path, path, error):
    client, headers = _failing_client(tmp_path, "unreadable export with 1812", error)

    response = client.get(path, headers=headers)
    assert response.status_code == 503
    assert response.json() == {"detail": "Panel catalog read failed: unreadable export with <redacted>"}


def test_a_programming_error_in_a_catalog_read_stays_a_500(tmp_path):
    client, headers = _failing_client(tmp_path, "bug", TypeError)

    assert client.get("/v1/users", headers=headers).status_code == 500
