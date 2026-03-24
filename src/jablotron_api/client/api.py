"""Reference Python client."""

from __future__ import annotations

import json
import ssl
from typing import AsyncIterator

import httpx
import websockets


class JablotronApiClient:
    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        verify: str | bool = True,
        cert: tuple[str, str] | None = None,
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
            timeout=30.0,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get_system(self) -> dict:
        return (await self._client.get("/v1/system")).json()

    async def get_status(self) -> dict:
        return (await self._client.get("/v1/status")).json()

    async def list_sections(self) -> list[dict]:
        return (await self._client.get("/v1/sections")).json()

    async def list_pgs(self) -> list[dict]:
        return (await self._client.get("/v1/pgs")).json()

    async def list_devices(self) -> list[dict]:
        return (await self._client.get("/v1/devices")).json()

    async def list_users(self) -> list[dict]:
        return (await self._client.get("/v1/users")).json()

    async def recent_events(self, *, limit: int = 20) -> list[dict]:
        return (await self._client.get("/v1/events/recent", params={"limit": limit})).json()

    async def arm_section(self, section_id: int, *, mode: str = "away", code: str | None = None) -> dict:
        params = {"mode": mode}
        if code:
            params["code"] = code
        return (await self._client.post(f"/v1/sections/{section_id}/arm", params=params)).json()

    async def disarm_section(self, section_id: int, *, code: str | None = None) -> dict:
        params = {"code": code} if code else None
        return (await self._client.post(f"/v1/sections/{section_id}/disarm", params=params)).json()

    async def set_pg(self, pg_id: int, enabled: bool, *, code: str | None = None) -> dict:
        action = "on" if enabled else "off"
        params = {"code": code} if code else None
        return (await self._client.post(f"/v1/pgs/{pg_id}/{action}", params=params)).json()

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
