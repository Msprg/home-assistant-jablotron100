"""Application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging

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

LOGGER = logging.getLogger(__name__)


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
        LOGGER.info(
            "Starting Jablotron API server: runtime_mode=%s host=%s port=%s mtls_required=%s poll_interval=%.1fs full_refresh_interval=%.1fs panel_port=%s",
            settings.runtime_mode,
            settings.host,
            settings.port,
            settings.mtls_required,
            settings.panel.poll_interval_seconds,
            settings.panel.full_refresh_interval_seconds,
            settings.panel.port,
        )
        runtime.add_listener(lambda topic, payload: ws_manager.broadcast(topic, "update", payload))
        await runtime.start()
        LOGGER.info(
            "Jablotron API server started: panel_model=%s panel_hw=%s panel_fw=%s panel_id=%s",
            runtime.system_info.get("panel_model"),
            runtime.system_info.get("panel_hardware_version"),
            runtime.system_info.get("panel_firmware_version"),
            runtime.system_info.get("panel_unique_id"),
        )
        yield
        LOGGER.info("Stopping Jablotron API server")
        await ws_manager.close_all(code=1001, reason="server shutdown")
        await runtime.close()
        LOGGER.info("Jablotron API server stopped")

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

    def _short_fingerprint(fingerprint: str | None) -> str | None:
        if not fingerprint:
            return None
        return f"{fingerprint[:12]}..."

    def _token_log_label(token: AuthenticatedToken) -> str:
        return f"{token.label} ({token.id})"

    def certificate_fingerprint_from_request(
        request: Request,
        x_client_cert_fingerprint: str | None = Header(default=None),
    ) -> str | None:
        return _tls_fingerprint_from_scope(request.scope) or x_client_cert_fingerprint

    def require_token(
        request: Request,
        authorization: str | None = Header(default=None),
        fingerprint: str | None = Depends(certificate_fingerprint_from_request),
    ) -> AuthenticatedToken:
        if not authorization or not authorization.lower().startswith("bearer "):
            LOGGER.warning(
                "HTTP authentication failed: missing bearer token method=%s path=%s fingerprint=%s",
                request.method,
                request.url.path,
                _short_fingerprint(fingerprint),
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token.")
        token_value = authorization.split(" ", 1)[1].strip()
        token = token_store.authenticate(token_value, certificate_fingerprint=fingerprint)
        if token is None:
            LOGGER.warning(
                "HTTP authentication failed: invalid token or certificate binding method=%s path=%s fingerprint=%s",
                request.method,
                request.url.path,
                _short_fingerprint(fingerprint),
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token or certificate binding.")
        LOGGER.debug(
            "HTTP authentication ok: method=%s path=%s token=%s scopes=%s fingerprint=%s",
            request.method,
            request.url.path,
            _token_log_label(token),
            ",".join(token.scopes),
            _short_fingerprint(fingerprint),
        )
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
        LOGGER.info(
            "Section arm requested: token=%s section=%s mode=%s explicit_code=%s",
            _token_log_label(token),
            section_id,
            mode.value,
            bool(code and code.strip()),
        )
        try:
            updated = await runtime.arm_section(section_id, mode, code=code)
        except PermissionError as exc:
            LOGGER.warning(
                "Section arm denied: token=%s section=%s mode=%s reason=%s",
                _token_log_label(token),
                section_id,
                mode.value,
                exc,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ValueError as exc:
            LOGGER.warning(
                "Section arm rejected: token=%s section=%s mode=%s reason=%s",
                _token_log_label(token),
                section_id,
                mode.value,
                exc,
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except RuntimeError as exc:
            LOGGER.warning(
                "Section arm failed: token=%s section=%s mode=%s reason=%s",
                _token_log_label(token),
                section_id,
                mode.value,
                exc,
            )
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="arm_section", resource=f"section:{section_id}", details={"mode": mode.value, "code_supplied": bool(code)})
        LOGGER.info(
            "Section arm completed: token=%s section=%s mode=%s resulting_state=%s",
            _token_log_label(token),
            section_id,
            mode.value,
            next((section.state for section in updated.sections if section.id == section_id), None),
        )
        return updated

    @app.post("/v1/sections/{section_id}/disarm")
    async def disarm_section(section_id: int, code: str | None = Query(default=None), token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.SECTIONS_CONTROL.value)
        if code is not None and code.strip() and code.strip() != settings.panel.auth_code:
            require_scopes(token, Scope.CODES_IMPERSONATE.value)
        LOGGER.info(
            "Section disarm requested: token=%s section=%s explicit_code=%s",
            _token_log_label(token),
            section_id,
            bool(code and code.strip()),
        )
        try:
            updated = await runtime.disarm_section(section_id, code=code)
        except PermissionError as exc:
            LOGGER.warning(
                "Section disarm denied: token=%s section=%s reason=%s",
                _token_log_label(token),
                section_id,
                exc,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ValueError as exc:
            LOGGER.warning(
                "Section disarm rejected: token=%s section=%s reason=%s",
                _token_log_label(token),
                section_id,
                exc,
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except RuntimeError as exc:
            LOGGER.warning(
                "Section disarm failed: token=%s section=%s reason=%s",
                _token_log_label(token),
                section_id,
                exc,
            )
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="disarm_section", resource=f"section:{section_id}", details={"code_supplied": bool(code)})
        LOGGER.info(
            "Section disarm completed: token=%s section=%s resulting_state=%s",
            _token_log_label(token),
            section_id,
            next((section.state for section in updated.sections if section.id == section_id), None),
        )
        return updated

    @app.post("/v1/pgs/{pg_id}/on")
    async def pg_on(pg_id: int, code: str | None = Query(default=None), token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.PGS_CONTROL.value)
        if code is None or not code.strip():
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="PG control requires an explicit panel code.")
        require_scopes(token, Scope.CODES_IMPERSONATE.value)
        LOGGER.info(
            "PG on requested: token=%s pg=%s explicit_code=%s allowed_user_ids=%s",
            _token_log_label(token),
            pg_id,
            True,
            token.allowed_user_ids,
        )
        try:
            updated = await runtime.set_pg(pg_id, True, code=code, allowed_user_ids=token.allowed_user_ids)
        except PermissionError as exc:
            LOGGER.warning("PG on denied: token=%s pg=%s reason=%s", _token_log_label(token), pg_id, exc)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ValueError as exc:
            LOGGER.warning("PG on rejected: token=%s pg=%s reason=%s", _token_log_label(token), pg_id, exc)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except RuntimeError as exc:
            LOGGER.warning("PG on failed: token=%s pg=%s reason=%s", _token_log_label(token), pg_id, exc)
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="pg_on", resource=f"pg:{pg_id}", details={"code_supplied": bool(code)})
        LOGGER.info(
            "PG on completed: token=%s pg=%s resulting_state=%s",
            _token_log_label(token),
            pg_id,
            next((pg.state for pg in updated.pgs if pg.id == pg_id), None),
        )
        return updated

    @app.post("/v1/pgs/{pg_id}/off")
    async def pg_off(pg_id: int, code: str | None = Query(default=None), token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.PGS_CONTROL.value)
        if code is None or not code.strip():
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="PG control requires an explicit panel code.")
        require_scopes(token, Scope.CODES_IMPERSONATE.value)
        LOGGER.info(
            "PG off requested: token=%s pg=%s explicit_code=%s allowed_user_ids=%s",
            _token_log_label(token),
            pg_id,
            True,
            token.allowed_user_ids,
        )
        try:
            updated = await runtime.set_pg(pg_id, False, code=code, allowed_user_ids=token.allowed_user_ids)
        except PermissionError as exc:
            LOGGER.warning("PG off denied: token=%s pg=%s reason=%s", _token_log_label(token), pg_id, exc)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ValueError as exc:
            LOGGER.warning("PG off rejected: token=%s pg=%s reason=%s", _token_log_label(token), pg_id, exc)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except RuntimeError as exc:
            LOGGER.warning("PG off failed: token=%s pg=%s reason=%s", _token_log_label(token), pg_id, exc)
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="pg_off", resource=f"pg:{pg_id}", details={"code_supplied": bool(code)})
        LOGGER.info(
            "PG off completed: token=%s pg=%s resulting_state=%s",
            _token_log_label(token),
            pg_id,
            next((pg.state for pg in updated.pgs if pg.id == pg_id), None),
        )
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
        LOGGER.info("User add requested: token=%s user=%s", _token_log_label(token), payload.id)
        try:
            result = await runtime.add_user(payload)
        except ValueError as exc:
            LOGGER.warning("User add rejected: token=%s user=%s reason=%s", _token_log_label(token), payload.id, exc)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except RuntimeError as exc:
            LOGGER.warning("User add failed: token=%s user=%s reason=%s", _token_log_label(token), payload.id, exc)
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="add_user", resource=f"user:{payload.id}", details=payload.model_dump(mode="json"))
        LOGGER.info("User add completed: token=%s user=%s", _token_log_label(token), payload.id)
        return result

    @app.patch("/v1/users/{user_id}")
    async def edit_user(user_id: int, payload: UserPatchModel, token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.USERS_WRITE.value)
        LOGGER.info("User edit requested: token=%s user=%s", _token_log_label(token), user_id)
        try:
            result = await runtime.edit_user(user_id, payload)
        except ValueError as exc:
            LOGGER.warning("User edit rejected: token=%s user=%s reason=%s", _token_log_label(token), user_id, exc)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except RuntimeError as exc:
            LOGGER.warning("User edit failed: token=%s user=%s reason=%s", _token_log_label(token), user_id, exc)
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="edit_user", resource=f"user:{user_id}", details=payload.model_dump(exclude_unset=True, mode="json"))
        LOGGER.info("User edit completed: token=%s user=%s", _token_log_label(token), user_id)
        return result

    @app.delete("/v1/users/{user_id}")
    async def delete_user(user_id: int, token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.USERS_WRITE.value)
        LOGGER.info("User delete requested: token=%s user=%s", _token_log_label(token), user_id)
        try:
            await runtime.delete_user(user_id)
        except ValueError as exc:
            LOGGER.warning("User delete rejected: token=%s user=%s reason=%s", _token_log_label(token), user_id, exc)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except RuntimeError as exc:
            LOGGER.warning("User delete failed: token=%s user=%s reason=%s", _token_log_label(token), user_id, exc)
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        token_store.write_audit(token_id=token.id, action="delete_user", resource=f"user:{user_id}", details={})
        LOGGER.info("User delete completed: token=%s user=%s", _token_log_label(token), user_id)
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
            allowed_user_ids=payload.allowed_user_ids,
        )
        token_store.write_audit(token_id=token.id, action="create_token", resource=f"token:{token_info.id}", details=payload.model_dump(mode="json"))
        LOGGER.info(
            "Token created via API: actor=%s token=%s scopes=%s allowed_user_ids=%s fingerprint_bound=%s",
            _token_log_label(token),
            f"{token_info.label} ({token_info.id})",
            ",".join(token_info.scopes),
            token_info.allowed_user_ids,
            bool(token_info.certificate_fingerprint),
        )
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
        LOGGER.info("Token revoked via API: actor=%s token_id=%s", _token_log_label(token), token_id)
        return {"status": "revoked", "token_id": token_id}

    @app.websocket("/v1/ws")
    async def websocket_endpoint(websocket: WebSocket, token: str = Query(...), fingerprint: str | None = Query(default=None)):
        fingerprint = _tls_fingerprint_from_scope(websocket.scope) or fingerprint
        authenticated = token_store.authenticate(
            token,
            certificate_fingerprint=fingerprint,
        )
        if authenticated is None:
            LOGGER.warning(
                "WebSocket authentication failed: path=%s fingerprint=%s",
                websocket.url.path,
                _short_fingerprint(fingerprint),
            )
            await websocket.close(code=4401)
            return
        await ws_manager.connect(websocket)
        LOGGER.info(
            "WebSocket connected: token=%s fingerprint=%s",
            _token_log_label(authenticated),
            _short_fingerprint(fingerprint),
        )
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
                        LOGGER.warning(
                            "WebSocket subscribe denied topics: token=%s denied=%s",
                            _token_log_label(authenticated),
                            denied_topics,
                        )
                        await websocket.send_json({"event": "error", "error": "missing_scopes", "topics": denied_topics})
                    if not allowed_topics:
                        continue
                    topics = allowed_topics
                    await ws_manager.subscribe(websocket, topics)
                    LOGGER.info(
                        "WebSocket subscribed: token=%s topics=%s",
                        _token_log_label(authenticated),
                        topics,
                    )
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
            LOGGER.info("WebSocket disconnected: token=%s", _token_log_label(authenticated))
        finally:
            await ws_manager.disconnect(websocket)

    return app
