"""WebSocket connection manager."""

from __future__ import annotations

import asyncio
from collections import defaultdict

from fastapi import WebSocket

from jablotron_api.domain.models import WebSocketEnvelope


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[WebSocket, set[str]] = defaultdict(set)
        self._sequence = 0
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections[websocket] = set()

    async def disconnect(self, websocket: WebSocket) -> None:
        self._connections.pop(websocket, None)

    async def close_all(self, *, code: int = 1001, reason: str = "server shutdown") -> None:
        async with self._lock:
            connections = list(self._connections)
            self._connections.clear()
        for websocket in connections:
            try:
                await websocket.close(code=code, reason=reason)
            except Exception:
                continue

    async def subscribe(self, websocket: WebSocket, topics: list[str]) -> None:
        self._connections.setdefault(websocket, set()).update(topics)

    async def broadcast(self, topic: str, event: str, payload: dict) -> None:
        async with self._lock:
            self._sequence += 1
            envelope = WebSocketEnvelope(sequence=self._sequence, topic=topic, event=event, payload=payload)
            dead: list[WebSocket] = []
            for websocket, topics in self._connections.items():
                if topic not in topics:
                    continue
                try:
                    await websocket.send_json(envelope.model_dump(mode="json"))
                except Exception:
                    dead.append(websocket)
            for websocket in dead:
                self._connections.pop(websocket, None)
