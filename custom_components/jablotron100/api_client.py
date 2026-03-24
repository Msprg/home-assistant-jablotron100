from __future__ import annotations

import asyncio
import ssl
from typing import Any

from aiohttp import ClientWebSocketResponse
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.core import HomeAssistant


class JablotronApiError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        self.status = status
        self.detail = detail
        super().__init__(f"API request failed with status {status}: {detail}")


class JablotronApiClient:
    def __init__(
        self,
        hass: HomeAssistant,
        *,
        server_url: str,
        api_token: str,
        ca_cert: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
    ) -> None:
        self._hass = hass
        self._server_url = server_url.rstrip("/")
        self._api_token = api_token
        self._ca_cert = ca_cert
        self._client_cert = client_cert
        self._client_key = client_key
        self._ssl_context_cache: ssl.SSLContext | bool | None = None
        self._ssl_context_lock = asyncio.Lock()

    def _build_ssl_context(self) -> ssl.SSLContext | bool:
        if self._server_url.startswith("http://"):
            return False
        context = ssl.create_default_context(cafile=self._ca_cert or None)
        if self._client_cert and self._client_key:
            context.load_cert_chain(self._client_cert, self._client_key)
        return context

    async def _ssl_context(self) -> ssl.SSLContext | bool:
        if self._ssl_context_cache is not None:
            return self._ssl_context_cache
        async with self._ssl_context_lock:
            if self._ssl_context_cache is None:
                self._ssl_context_cache = await self._hass.async_add_executor_job(self._build_ssl_context)
        return self._ssl_context_cache

    @property
    def base_url(self) -> str:
        return self._server_url

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        session = async_get_clientsession(self._hass)
        headers = dict(kwargs.pop("headers", {}))
        headers["Authorization"] = f"Bearer {self._api_token}"
        async with session.request(
            method,
            f"{self._server_url}{path}",
            headers=headers,
            ssl=await self._ssl_context(),
            **kwargs,
        ) as response:
            if response.status >= 400:
                detail = response.reason or "Request failed"
                try:
                    payload = await response.json()
                except Exception:
                    payload = None
                if isinstance(payload, dict) and isinstance(payload.get("detail"), str):
                    detail = payload["detail"]
                elif payload is None:
                    try:
                        detail = await response.text()
                    except Exception:
                        pass
                raise JablotronApiError(response.status, detail)
            return await response.json()

    async def get(self, path: str, **kwargs: Any) -> Any:
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> Any:
        return await self.request("POST", path, **kwargs)

    async def patch(self, path: str, **kwargs: Any) -> Any:
        return await self.request("PATCH", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> Any:
        return await self.request("DELETE", path, **kwargs)

    async def ws_connect(self) -> ClientWebSocketResponse:
        session = async_get_clientsession(self._hass)
        ws_url = self._server_url.replace("https://", "wss://").replace("http://", "ws://")
        return await session.ws_connect(
            f"{ws_url}/v1/ws?token={self._api_token}",
            ssl=await self._ssl_context(),
        )
