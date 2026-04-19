"""WebSocket connection manager."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
import logging
from typing import Any, Callable

from fastapi import WebSocket

from jablotron_api.domain.models import WebSocketEnvelope

LOGGER = logging.getLogger(__name__)


@dataclass
class ConnectionState:
    topics: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[WebSocket, ConnectionState] = defaultdict(ConnectionState)
        self._sequence = 0
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, *, metadata: dict[str, Any] | None = None) -> None:
        await websocket.accept()
        self._connections[websocket] = ConnectionState(metadata=dict(metadata or {}))
        LOGGER.debug("WebSocket accepted: active_connections=%s", len(self._connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        self._connections.pop(websocket, None)
        LOGGER.debug("WebSocket removed: active_connections=%s", len(self._connections))

    async def close_all(self, *, code: int = 1001, reason: str = "server shutdown") -> None:
        async with self._lock:
            connections = list(self._connections)
            self._connections.clear()
        LOGGER.info("Closing all websocket clients: count=%s code=%s reason=%s", len(connections), code, reason)
        for websocket in connections:
            try:
                await websocket.close(code=code, reason=reason)
            except Exception:
                continue

    async def subscribe(self, websocket: WebSocket, topics: list[str]) -> None:
        state = self._connections.setdefault(websocket, ConnectionState())
        state.topics.update(topics)
        LOGGER.debug("WebSocket topic update: topics=%s", sorted(state.topics))

    async def broadcast(
        self,
        topic: str,
        event: str,
        payload: dict,
        *,
        transform: Callable[[dict[str, Any], str, dict], dict] | None = None,
    ) -> None:
        async with self._lock:
            dead: list[WebSocket] = []
            delivered = 0
            for websocket, state in self._connections.items():
                if topic not in state.topics:
                    continue
                try:
                    effective_payload = transform(state.metadata, topic, payload) if transform is not None else payload
                    self._sequence += 1
                    envelope = WebSocketEnvelope(sequence=self._sequence, topic=topic, event=event, payload=effective_payload)
                    await websocket.send_json(envelope.model_dump(mode="json"))
                    delivered += 1
                except Exception:
                    dead.append(websocket)
            for websocket in dead:
                self._connections.pop(websocket, None)
            LOGGER.debug(
                "WebSocket broadcast: topic=%s event=%s sequence=%s delivered=%s removed_dead=%s",
                topic,
                event,
                self._sequence,
                delivered,
                len(dead),
            )
