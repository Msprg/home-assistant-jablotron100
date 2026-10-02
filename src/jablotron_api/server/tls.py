"""TLS helpers for direct ASGI transport metadata."""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any

from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol


TLS_EXTENSION_KEY = "jablotron_api.tls"


def tls_extension_from_transport(transport: asyncio.Transport | None) -> dict[str, str] | None:
    if transport is None:
        return None
    ssl_object = transport.get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    try:
        peer_cert = ssl_object.getpeercert(binary_form=True)
    except Exception:
        return None
    if not peer_cert:
        return None
    return {"client_cert_fingerprint_sha256": hashlib.sha256(peer_cert).hexdigest()}


def apply_tls_extension(scope: dict[str, Any], transport: asyncio.Transport | None) -> None:
    extension = tls_extension_from_transport(transport)
    if extension is None:
        return
    extensions = scope.setdefault("extensions", {})
    if not isinstance(extensions, dict):
        extensions = {}
        scope["extensions"] = extensions
    extensions[TLS_EXTENSION_KEY] = extension


class TLSAwareH11Protocol(H11Protocol):
    """Inject client-cert fingerprint metadata into HTTP ASGI scopes."""

    def handle_events(self) -> None:
        previous_scope = self.scope
        super().handle_events()
        if self.scope is not None and self.scope is not previous_scope:
            apply_tls_extension(self.scope, self.transport)


class TLSAwareWebSocketProtocol(WebSocketsSansIOProtocol):
    """Inject client-cert fingerprint metadata into WebSocket ASGI scopes.

    Built on uvicorn's ``websockets-sansio`` protocol: the legacy
    ``websockets`` protocol is deprecated and warns on import. The sansio
    protocol builds the ASGI scope inside ``handle_connect`` and only when
    the handshake is accepted, so the extension is applied right after it.
    """

    def handle_connect(self, event) -> None:  # type: ignore[override]
        super().handle_connect(event)
        scope = getattr(self, "scope", None)
        if scope is not None:
            apply_tls_extension(scope, self.transport)
