"""Reference Python client for the Jablotron API server."""

from __future__ import annotations

import json
import ssl
from typing import Any, AsyncIterator

import httpx
import websockets


class JablotronApiError(Exception):
    """Raised when the API server returns a non-success response."""

    def __init__(self, status_code: int, detail: str, *, payload: Any = None) -> None:
        self.status_code = status_code
        self.detail = detail
        self.payload = payload
        super().__init__(f"Jablotron API request failed with status {status_code}: {detail}")


class JablotronApiClient:
    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        verify: str | bool = True,
        cert: tuple[str, str] | None = None,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._verify = verify
        self._cert = cert
        verify_config: str | bool | ssl.SSLContext = self._verify
        if self._base_url.startswith("https://"):
            verify_config = self._ssl_context()
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {self._token}"},
            verify=verify_config,
            timeout=timeout,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "JablotronApiClient":
        return self

    async def __aexit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        await self.aclose()

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = await self._client.request(method, path, **kwargs)
        if response.status_code >= 400:
            payload: Any = None
            detail = response.reason_phrase or "Request failed"
            try:
                payload = response.json()
            except ValueError:
                text = response.text.strip()
                if text:
                    detail = text
            else:
                if isinstance(payload, dict):
                    raw_detail = payload.get("detail")
                    if isinstance(raw_detail, str):
                        detail = raw_detail
                    elif raw_detail is not None:
                        detail = json.dumps(raw_detail, sort_keys=True)
                elif payload is not None:
                    detail = json.dumps(payload, sort_keys=True)
            raise JablotronApiError(response.status_code, detail, payload=payload)
        if not response.content:
            return None
        return response.json()

    async def get_health(self) -> dict:
        return await self.request("GET", "/v1/health")

    async def get_system(self) -> dict:
        return await self.request("GET", "/v1/system")

    async def get_status(self) -> dict:
        return await self.request("GET", "/v1/status")

    async def list_sections(self) -> list[dict]:
        return await self.request("GET", "/v1/sections")

    async def list_pgs(self) -> list[dict]:
        return await self.request("GET", "/v1/pgs")

    async def list_devices(self) -> list[dict]:
        return await self.request("GET", "/v1/devices")

    async def list_users(self) -> list[dict]:
        return await self.request("GET", "/v1/users")

    async def get_user(self, user_id: int) -> dict:
        return await self.request("GET", f"/v1/users/{user_id}")

    async def create_user(self, payload: dict[str, Any]) -> dict:
        return await self.request("POST", "/v1/users", json=payload)

    async def patch_user(self, user_id: int, payload: dict[str, Any]) -> dict:
        return await self.request("PATCH", f"/v1/users/{user_id}", json=payload)

    async def delete_user(self, user_id: int) -> dict:
        return await self.request("DELETE", f"/v1/users/{user_id}")

    async def list_events(
        self,
        *,
        limit: int = 20,
        include_raw: bool = False,
        kinds: str | None = None,
        exclude_kinds: str | None = None,
    ) -> list[dict]:
        params: dict[str, Any] = {"limit": limit, "include_raw": include_raw}
        if kinds:
            params["kinds"] = kinds
        if exclude_kinds:
            params["exclude_kinds"] = exclude_kinds
        return await self.request("GET", "/v1/events/recent", params=params)

    async def recent_events(self, *, limit: int = 20) -> list[dict]:
        return await self.list_events(limit=limit)

    async def export_users(self) -> list[dict]:
        return await self.request("GET", "/v1/export/users")

    async def get_catalog(self) -> dict:
        return await self.request("GET", "/v1/export/catalog")

    async def get_time_limits(self) -> dict:
        return await self.request("GET", "/v1/export/time-limits")

    async def get_communications(self) -> dict:
        return await self.request("GET", "/v1/export/communications")

    async def create_token(self, payload: dict[str, Any]) -> dict:
        return await self.request("POST", "/v1/tokens", json=payload)

    async def list_tokens(self) -> list[dict]:
        return await self.request("GET", "/v1/tokens")

    async def revoke_token(self, token_id: str) -> dict:
        return await self.request("DELETE", f"/v1/tokens/{token_id}")

    async def arm_section(self, section_id: int, *, mode: str = "away", code: str | None = None) -> dict:
        params = {"mode": mode}
        if code:
            params["code"] = code
        return await self.request("POST", f"/v1/sections/{section_id}/arm", params=params)

    async def disarm_section(self, section_id: int, *, code: str | None = None) -> dict:
        params = {"code": code} if code else None
        return await self.request("POST", f"/v1/sections/{section_id}/disarm", params=params)

    async def set_pg(self, pg_id: int, enabled: bool, *, code: str | None = None) -> dict:
        action = "on" if enabled else "off"
        params = {"code": code} if code else None
        return await self.request("POST", f"/v1/pgs/{pg_id}/{action}", params=params)

    def _ssl_context(self) -> ssl.SSLContext | None:
        if self._base_url.startswith("ws://") or self._base_url.startswith("http://"):
            return None
        if self._verify is False:
            context = ssl._create_unverified_context()
        elif isinstance(self._verify, str):
            context = ssl.create_default_context(cafile=self._verify)
        else:
            context = ssl.create_default_context()
        if self._cert is not None:
            context.load_cert_chain(*self._cert)
        return context

    def _websocket_ssl_context(self) -> ssl.SSLContext | None:
        return self._ssl_context()

    async def websocket(self, *, topics: list[str] | None = None) -> AsyncIterator[dict]:
        ws_url = self._base_url.replace("https://", "wss://").replace("http://", "ws://") + f"/v1/ws?token={self._token}"
        async with websockets.connect(ws_url, ssl=self._websocket_ssl_context()) as websocket:
            await websocket.send(json.dumps({"action": "subscribe", "topics": topics or ["status", "events", "users", "catalog", "system"]}))
            async for message in websocket:
                yield json.loads(message)
