"""Application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status

from jablotron_api import __version__
from jablotron_api.domain.models import (
    ArmMode,
    AuthenticatedToken,
    Scope,
    ServerSystemModel,
    TokenCreateRequest,
    TokenCreateResponse,
    UserCreateModel,
    UserPatchModel,
)
from jablotron_api.panel.demo import DemoPanelRuntime
from jablotron_api.server.config import ServerSettings
from jablotron_api.server.tls import TLS_EXTENSION_KEY
from jablotron_api.server.ws import ConnectionManager
from jablotron_api.services.auth import require_scopes
from jablotron_api.services.storage import TokenStore


def create_app(
    *,
    settings: ServerSettings | None = None,
    runtime: object | None = None,
    token_store: TokenStore | None = None,
) -> FastAPI:
    settings = settings or ServerSettings()
    if runtime is None:
        if settings.runtime_mode == "demo":
            runtime = DemoPanelRuntime()
        else:
            from jablotron_api.panel.runtime import PanelRuntime

            runtime = PanelRuntime(settings.panel)
    token_store = token_store or TokenStore(settings.db_path)
    ws_manager = ConnectionManager()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        runtime.add_listener(lambda topic, payload: ws_manager.broadcast(topic, "update", payload))
        await runtime.start()
        yield
        await ws_manager.close_all(code=1001, reason="server shutdown")
        await runtime.close()

    app = FastAPI(title="Jablotron API Server", version=__version__, lifespan=lifespan)
    app.state.runtime = runtime
    app.state.token_store = token_store
    app.state.ws_manager = ws_manager
    app.state.settings = settings

    topic_scopes = {
        "status": Scope.STATUS_READ.value,
        "events": Scope.EVENTS_READ.value,
        "users": Scope.USERS_READ.value,
        "catalog": Scope.CONFIG_READ.value,
        "system": Scope.SYSTEM_READ.value,
    }

    def _tls_fingerprint_from_scope(scope: dict) -> str | None:
        extensions = scope.get("extensions")
        if not isinstance(extensions, dict):
            return None
        tls_extension = extensions.get(TLS_EXTENSION_KEY)
        if not isinstance(tls_extension, dict):
            return None
        fingerprint = tls_extension.get("client_cert_fingerprint_sha256")
        return fingerprint if isinstance(fingerprint, str) and fingerprint else None

    def certificate_fingerprint_from_request(
        request: Request,
        x_client_cert_fingerprint: str | None = Header(default=None),
    ) -> str | None:
        return _tls_fingerprint_from_scope(request.scope) or x_client_cert_fingerprint

    def require_token(
        authorization: str | None = Header(default=None),
        fingerprint: str | None = Depends(certificate_fingerprint_from_request),
    ) -> AuthenticatedToken:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token.")
        token_value = authorization.split(" ", 1)[1].strip()
        token = token_store.authenticate(token_value, certificate_fingerprint=fingerprint)
        if token is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token or certificate binding.")
        return token

    async def build_system_payload(token: AuthenticatedToken) -> ServerSystemModel:
        require_scopes(token, Scope.SYSTEM_READ.value)
        if not runtime.system_info.get("panel_model"):
            await runtime.refresh_system()
        return ServerSystemModel(
            server_version=__version__,
            panel_model=runtime.system_info.get("panel_model"),
            panel_hardware_version=runtime.system_info.get("panel_hardware_version"),
            panel_firmware_version=runtime.system_info.get("panel_firmware_version"),
            panel_unique_id=runtime.system_info.get("panel_unique_id"),
            mtls_required=settings.mtls_required,
            token_scopes=token.scopes,
            poll_interval_seconds=settings.panel.poll_interval_seconds,
        )

    @app.get("/v1/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/system")
    async def system(token: AuthenticatedToken = Depends(require_token)) -> ServerSystemModel:
        return await build_system_payload(token)

    @app.get("/v1/status")
    async def status_snapshot(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.STATUS_READ.value)
        return await runtime.get_status()

    @app.get("/v1/sections")
    async def sections(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.STATUS_READ.value)
        return (await runtime.get_status()).sections

    @app.get("/v1/pgs")
    async def pgs(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.STATUS_READ.value)
        return (await runtime.get_status()).pgs

    @app.get("/v1/devices")
    async def devices(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.STATUS_READ.value)
        return (await runtime.get_status()).devices

    @app.post("/v1/sections/{section_id}/arm")
    async def arm_section(
        section_id: int,
        mode: ArmMode = Query(default=ArmMode.AWAY),
        code: str | None = Query(default=None),
        token: AuthenticatedToken = Depends(require_token),
    ):
        require_scopes(token, Scope.SECTIONS_CONTROL.value)
        if code is not None and code.strip() and code.strip() != settings.panel.auth_code:
            require_scopes(token, Scope.CODES_IMPERSONATE.value)
        try:
            updated = await runtime.arm_section(section_id, mode, code=code)
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="arm_section", resource=f"section:{section_id}", details={"mode": mode.value, "code_supplied": bool(code)})
        return updated

    @app.post("/v1/sections/{section_id}/disarm")
    async def disarm_section(section_id: int, code: str | None = Query(default=None), token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.SECTIONS_CONTROL.value)
        if code is not None and code.strip() and code.strip() != settings.panel.auth_code:
            require_scopes(token, Scope.CODES_IMPERSONATE.value)
        try:
            updated = await runtime.disarm_section(section_id, code=code)
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="disarm_section", resource=f"section:{section_id}", details={"code_supplied": bool(code)})
        return updated

    @app.post("/v1/pgs/{pg_id}/on")
    async def pg_on(pg_id: int, code: str | None = Query(default=None), token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.PGS_CONTROL.value)
        if code is not None and code.strip() and code.strip() != settings.panel.auth_code:
            require_scopes(token, Scope.CODES_IMPERSONATE.value)
        try:
            updated = await runtime.set_pg(pg_id, True, code=code)
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="pg_on", resource=f"pg:{pg_id}", details={"code_supplied": bool(code)})
        return updated

    @app.post("/v1/pgs/{pg_id}/off")
    async def pg_off(pg_id: int, code: str | None = Query(default=None), token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.PGS_CONTROL.value)
        if code is not None and code.strip() and code.strip() != settings.panel.auth_code:
            require_scopes(token, Scope.CODES_IMPERSONATE.value)
        try:
            updated = await runtime.set_pg(pg_id, False, code=code)
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="pg_off", resource=f"pg:{pg_id}", details={"code_supplied": bool(code)})
        return updated

    @app.get("/v1/users")
    async def users(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.USERS_READ.value)
        return await runtime.get_users()

    @app.get("/v1/users/{user_id}")
    async def user(user_id: int, token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.USERS_READ.value)
        result = await runtime.get_user(user_id)
        if result is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        return result

    @app.post("/v1/users")
    async def add_user(payload: UserCreateModel, token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.USERS_WRITE.value)
        try:
            result = await runtime.add_user(payload)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="add_user", resource=f"user:{payload.id}", details=payload.model_dump(mode="json"))
        return result

    @app.patch("/v1/users/{user_id}")
    async def edit_user(user_id: int, payload: UserPatchModel, token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.USERS_WRITE.value)
        try:
            result = await runtime.edit_user(user_id, payload)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="edit_user", resource=f"user:{user_id}", details=payload.model_dump(exclude_unset=True, mode="json"))
        return result

    @app.delete("/v1/users/{user_id}")
    async def delete_user(user_id: int, token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.USERS_WRITE.value)
        try:
            await runtime.delete_user(user_id)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="delete_user", resource=f"user:{user_id}", details={})
        return {"status": "deleted", "user_id": user_id}

    @app.get("/v1/events")
    @app.get("/v1/events/recent")
    async def events_recent(
        limit: int = Query(default=20, ge=1, le=200),
        include_raw: bool = Query(default=False),
        kinds: str | None = Query(default=None),
        exclude_kinds: str | None = Query(default=None),
        token: AuthenticatedToken = Depends(require_token),
    ):
        require_scopes(token, Scope.EVENTS_READ.value)
        return await runtime.get_events_recent(limit=limit, include_raw=include_raw, kinds=kinds, exclude_kinds=exclude_kinds)

    @app.get("/v1/export/users")
    async def export_users(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.CONFIG_READ.value)
        return await runtime.get_export_users()

    @app.get("/v1/export/catalog")
    async def export_catalog(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.CONFIG_READ.value)
        return await runtime.get_catalog()

    @app.get("/v1/export/time-limits")
    async def export_time_limits(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.CONFIG_READ.value)
        return {"time_limits": await runtime.get_export_time_limits()}

    @app.get("/v1/export/communications")
    async def export_communications(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.CONFIG_READ.value)
        return await runtime.get_export_communications()

    @app.post("/v1/tokens")
    async def create_token(payload: TokenCreateRequest, token: AuthenticatedToken = Depends(require_token)) -> TokenCreateResponse:
        require_scopes(token, Scope.TOKENS_ADMIN.value)
        token_value, token_info = token_store.create_token(
            label=payload.label,
            scopes=payload.scopes,
            certificate_fingerprint=payload.certificate_fingerprint,
        )
        token_store.write_audit(token_id=token.id, action="create_token", resource=f"token:{token_info.id}", details=payload.model_dump(mode="json"))
        return TokenCreateResponse(token=token_value, token_info=token_info)

    @app.get("/v1/tokens")
    async def list_tokens(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.TOKENS_ADMIN.value)
        return token_store.list_tokens()

    @app.delete("/v1/tokens/{token_id}")
    async def delete_token(token_id: str, token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.TOKENS_ADMIN.value)
        token_store.revoke_token(token_id)
        token_store.write_audit(token_id=token.id, action="revoke_token", resource=f"token:{token_id}", details={})
        return {"status": "revoked", "token_id": token_id}

    @app.websocket("/v1/ws")
    async def websocket_endpoint(websocket: WebSocket, token: str = Query(...), fingerprint: str | None = Query(default=None)):
        authenticated = token_store.authenticate(
            token,
            certificate_fingerprint=_tls_fingerprint_from_scope(websocket.scope) or fingerprint,
        )
        if authenticated is None:
            await websocket.close(code=4401)
            return
        await ws_manager.connect(websocket)
        try:
            await websocket.send_json({"event": "hello", "topics": list(topic_scopes)})
            while True:
                message = await websocket.receive_json()
                action = message.get("action")
                if action == "subscribe":
                    topics = [str(topic) for topic in message.get("topics", [])]
                    allowed_topics: list[str] = []
                    denied_topics: list[str] = []
                    for topic in topics:
                        required_scope = topic_scopes.get(topic)
                        if required_scope is None or required_scope in authenticated.scopes:
                            allowed_topics.append(topic)
                        else:
                            denied_topics.append(topic)
                    if denied_topics:
                        await websocket.send_json({"event": "error", "error": "missing_scopes", "topics": denied_topics})
                    if not allowed_topics:
                        continue
                    topics = allowed_topics
                    await ws_manager.subscribe(websocket, topics)
                    for topic in topics:
                        if topic == "status":
                            await websocket.send_json({"event": "snapshot", "topic": "status", "payload": (await runtime.get_status()).model_dump(mode="json")})
                        elif topic == "catalog":
                            await websocket.send_json({"event": "snapshot", "topic": "catalog", "payload": (await runtime.get_catalog()).model_dump(mode="json")})
                        elif topic == "system":
                            await websocket.send_json({"event": "snapshot", "topic": "system", "payload": (await build_system_payload(authenticated)).model_dump(mode="json")})
                        elif topic == "users":
                            await websocket.send_json({"event": "snapshot", "topic": "users", "payload": [user.model_dump(mode="json") for user in await runtime.get_users()]})
                        elif topic == "events":
                            await websocket.send_json({"event": "snapshot", "topic": "events", "payload": [event.model_dump(mode="json") for event in await runtime.get_events_recent(limit=20)]})
                elif action == "ping":
                    await websocket.send_json({"event": "pong"})
        except WebSocketDisconnect:
            pass
        finally:
            await ws_manager.disconnect(websocket)

    return app
