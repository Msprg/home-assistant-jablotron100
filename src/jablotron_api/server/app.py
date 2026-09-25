"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
import json
import logging
import re
from typing import Any, Awaitable, Callable, Mapping

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)

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
from jablotron_api.domain.serialization import (
    serialize_catalog,
    serialize_users,
    serialize_ws_payload,
)
from jablotron_api.domain.user_validation import UserSlotOccupied, UserWriteRejected
from jablotron_api.panel.demo import DemoPanelRuntime
from jablotron_api.server.config import ServerSettings
from jablotron_api.server.tls import TLS_EXTENSION_KEY
from jablotron_api.server.ws import ConnectionManager
from jablotron_api.services.auth import require_scopes
from jablotron_api.services.storage import TokenStore

LOGGER = logging.getLogger(__name__)


# WebSocket message size cap. 64 KiB is more than enough for any
# legitimate subscribe / ping payload; anything larger is treated as a
# DoS attempt and the connection is closed with code 1009.
_WS_MAX_MESSAGE_BYTES: int = 64 * 1024

# HTTP request body size cap. Token CRUD / user CRUD payloads are small;
# anything larger is rejected with 413 before any handler runs.
_MAX_HTTP_BODY_BYTES: int = 1 * 1024 * 1024


def _json_response(status_code: int, body: dict[str, Any]):
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=status_code, content=body)


TOPIC_SCOPES: dict[str, tuple[str, ...]] = {
    # status topic carries sections+pgs+devices; consumers need all three read scopes
    "status": (Scope.SECTIONS_READ.value, Scope.PGS_READ.value, Scope.DEVICES_READ.value),
    "events": (Scope.EVENTS_READ.value,),
    "users": (Scope.USERS_READ.value,),
    "catalog": (Scope.CATALOG_READ.value,),
    "system": (Scope.SYSTEM_READ.value,),
}


class SensitiveQueryAccessLogFilter(logging.Filter):
    """Redact ?token=... and ?fingerprint=... from uvicorn access log lines.

    uvicorn formats access lines as ``"{request_line} {status_code}"`` where
    ``request_line`` is e.g. ``GET /v1/ws?token=abc HTTP/1.1``. The token
    would otherwise land in any access-log sink (stdout, container logs,
    log shippers, ELK). This filter rewrites the request_line argument
    before formatting.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if not args:
            return True
        if isinstance(args, dict):
            redacted = {key: _redact_url(value) if isinstance(value, str) else value for key, value in args.items()}
            record.args = redacted
            return True
        if isinstance(args, tuple):
            record.args = tuple(_redact_url(item) if isinstance(item, str) else item for item in args)
        return True


_SENSITIVE_QUERY_PARAMS: tuple[str, ...] = ("token", "fingerprint")
_QUERY_REDACTION_PATTERN: re.Pattern[str] = re.compile(
    r"([?&](?:" + "|".join(_SENSITIVE_QUERY_PARAMS) + r")=)[^& \"]+",
    re.IGNORECASE,
)
_LOG_INJECTION_PATTERN: re.Pattern[str] = re.compile(r"[\r\n\t\x00-\x1f\x7f]")


def _redact_url(url: str) -> str:
    return _QUERY_REDACTION_PATTERN.sub(r"\1<redacted>", url)


def sanitize_for_log(value: str | None) -> str:
    """Strip control characters that would let an attacker forge log lines."""

    if value is None:
        return ""
    return _LOG_INJECTION_PATTERN.sub("?", value)


def _bearer_token_from_headers(headers: Mapping[str, str]) -> str | None:
    auth = headers.get("authorization") if hasattr(headers, "get") else None
    if not auth or not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip() or None


def certificate_fingerprint_from_request(request: Request) -> str | None:
    """Module-level dependency so tests can override it via FastAPI's
    ``app.dependency_overrides`` mapping. We never accept a fingerprint
    from a client-supplied header or query parameter — only from the
    mTLS-aware uvicorn protocol's TLS scope extension.
    """

    return _tls_fingerprint_from_scope(request.scope)


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
    # Sanitize the user-controlled label so a token created with a newline
    # in its label cannot forge or split log entries.
    return f"{sanitize_for_log(token.label)} ({token.id})"


def _authorize_topic(token: AuthenticatedToken, topic: str) -> bool:
    required_scopes = TOPIC_SCOPES.get(topic)
    if required_scopes is None:
        return True
    return all(scope in token.scopes for scope in required_scopes)


# A refused user record and a broken panel must not look alike to a
# provisioning client: `UserWriteRejected` (400, with a machine-readable
# reason in the body) means "that value is illegal, try another one", while
# a RuntimeError from the write path (409) means the panel or the link
# failed and the client should stop rather than retry.
_RUNTIME_ERROR_MAP: tuple[tuple[type[Exception], int], ...] = (
    (PermissionError, status.HTTP_403_FORBIDDEN),
    (UserWriteRejected, status.HTTP_400_BAD_REQUEST),
    (ValueError, status.HTTP_400_BAD_REQUEST),
    (RuntimeError, status.HTTP_409_CONFLICT),
)


def _http_status_for(exc: Exception) -> int | None:
    for exception_type, http_status in _RUNTIME_ERROR_MAP:
        if isinstance(exc, exception_type):
            return http_status
    return None


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
            if not settings.panel.auth_code:
                raise RuntimeError(
                    "JABLOTRON_PANEL_AUTH_CODE is required in live runtime mode. "
                    "Set the env var to the installation's panel service code, "
                    "or run with JABLOTRON_API_RUNTIME_MODE=demo for a smoke test."
                )
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
        runtime.add_listener(
            lambda topic, payload: ws_manager.broadcast(
                topic,
                "update",
                payload,
                transform=lambda metadata, broadcast_topic, broadcast_payload: serialize_ws_payload(
                    metadata["token"],
                    broadcast_topic,
                    broadcast_payload,
                ),
            )
        )
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

    @app.middleware("http")
    async def _limit_request_body(request: Request, call_next):
        # Refuse requests that advertise a body larger than the cap so a
        # malicious or malfunctioning client cannot exhaust memory before
        # any handler runs. None of our endpoints accept payloads larger
        # than a few KiB; 1 MiB is generous.
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > _MAX_HTTP_BODY_BYTES:
                    return _json_response(
                        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        {"detail": "Request body too large."},
                    )
            except ValueError:
                return _json_response(
                    status.HTTP_400_BAD_REQUEST,
                    {"detail": "Malformed Content-Length header."},
                )
        try:
            return await call_next(request)
        except RecursionError:
            # Deeply-nested JSON exceeds Python's recursion limit during
            # parsing — return a clean 400 instead of crashing the worker.
            LOGGER.warning(
                "RecursionError while handling request method=%s path=%s",
                request.method,
                request.url.path,
            )
            return _json_response(
                status.HTTP_400_BAD_REQUEST,
                {"detail": "Request payload nesting too deep."},
            )

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
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token or certificate binding.",
            )
        LOGGER.debug(
            "HTTP authentication ok: method=%s path=%s token=%s scopes=%s fingerprint=%s",
            request.method,
            request.url.path,
            _token_log_label(token),
            ",".join(token.scopes),
            _short_fingerprint(fingerprint),
        )
        return token

    async def _execute_runtime_call(
        *,
        token: AuthenticatedToken,
        op: str,
        resource: str,
        audit_details: dict[str, Any],
        runtime_callable: Callable[[], Awaitable[Any]],
        log_summary: Callable[[Any], str] | None = None,
    ) -> Any:
        """Execute a panel-mutating runtime call with uniform logging,
        runtime-error→HTTP mapping, and audit-trail emission."""

        token_label = _token_log_label(token)
        LOGGER.info("%s requested: token=%s resource=%s", op, token_label, resource)
        try:
            result = await runtime_callable()
        except UserWriteRejected as exc:
            LOGGER.warning(
                "%s rejected: token=%s resource=%s reason=%s conflicts=%s detail=%s",
                op,
                token_label,
                resource,
                exc.reason,
                ",".join(str(item) for item in exc.conflicting_user_ids) or "-",
                exc.summary(),
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=exc.to_payload()
            ) from exc
        except UserSlotOccupied as exc:
            LOGGER.warning(
                "%s refused: token=%s resource=%s reason=user_slot_occupied",
                op,
                token_label,
                resource,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=exc.to_payload()
            ) from exc
        except Exception as exc:
            http_status = _http_status_for(exc)
            if http_status is None:
                raise
            level = "denied" if http_status == status.HTTP_403_FORBIDDEN else (
                "rejected" if http_status == status.HTTP_400_BAD_REQUEST else "failed"
            )
            LOGGER.warning(
                "%s %s: token=%s resource=%s reason=%s",
                op,
                level,
                token_label,
                resource,
                exc,
            )
            raise HTTPException(status_code=http_status, detail=str(exc)) from exc
        token_store.write_audit(
            token_id=token.id, action=op, resource=resource, details=audit_details
        )
        summary = log_summary(result) if log_summary is not None else "ok"
        LOGGER.info("%s completed: token=%s resource=%s %s", op, token_label, resource, summary)
        return result

    def _validate_user_code(code: str | None) -> None:
        from jablotron_api.domain.codes import validate_user_code

        try:
            validate_user_code(code, runtime.code_format())
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    def _require_section_arm(token: AuthenticatedToken, code: str | None) -> None:
        require_scopes(token, Scope.SECTIONS_ARM.value)
        _validate_user_code(code)
        _maybe_require_impersonate(token, code)

    def _require_section_disarm(token: AuthenticatedToken, code: str | None) -> None:
        require_scopes(token, Scope.SECTIONS_DISARM.value)
        _validate_user_code(code)
        _maybe_require_impersonate(token, code)

    def _require_pg_control(token: AuthenticatedToken, code: str | None) -> None:
        require_scopes(token, Scope.PGS_CONTROL.value)
        if code is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="PG control requires an explicit panel code.",
            )
        _validate_user_code(code)
        _maybe_require_impersonate(token, code)

    def _maybe_require_impersonate(token: AuthenticatedToken, code: str | None) -> None:
        if code is not None and code.strip() and code.strip() != settings.panel.auth_code:
            require_scopes(token, Scope.CODES_IMPERSONATE.value)

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
        # Status is a composite view; require at least one of the three
        # per-resource read scopes and return only the slices the token can
        # actually see. central/refreshed_at/service_mode/source are always
        # included (they are not gated by any per-resource read scope).
        granted = {
            Scope.SECTIONS_READ.value: Scope.SECTIONS_READ.value in token.scopes,
            Scope.PGS_READ.value: Scope.PGS_READ.value in token.scopes,
            Scope.DEVICES_READ.value: Scope.DEVICES_READ.value in token.scopes,
        }
        if not any(granted.values()):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "missing_scopes",
                    "missing": [
                        Scope.SECTIONS_READ.value,
                        Scope.PGS_READ.value,
                        Scope.DEVICES_READ.value,
                    ],
                    "note": "Need at least one of these read scopes.",
                },
            )
        snapshot = await runtime.get_status()
        return snapshot.model_copy(
            update={
                "sections": snapshot.sections if granted[Scope.SECTIONS_READ.value] else [],
                "pgs": snapshot.pgs if granted[Scope.PGS_READ.value] else [],
                "devices": snapshot.devices if granted[Scope.DEVICES_READ.value] else [],
            }
        )

    @app.get("/v1/sections")
    async def sections(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.SECTIONS_READ.value)
        return (await runtime.get_status()).sections

    @app.get("/v1/pgs")
    async def pgs(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.PGS_READ.value)
        return (await runtime.get_status()).pgs

    @app.get("/v1/devices")
    async def devices(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.DEVICES_READ.value)
        return (await runtime.get_status()).devices

    @app.post("/v1/sections/{section_id}/arm")
    async def arm_section(
        section_id: int,
        mode: ArmMode = Query(default=ArmMode.AWAY),
        code: str | None = Query(default=None),
        token: AuthenticatedToken = Depends(require_token),
    ):
        _require_section_arm(token, code)
        return await _execute_runtime_call(
            token=token,
            op="arm_section",
            resource=f"section:{section_id}",
            audit_details={"mode": mode.value, "code_supplied": bool(code)},
            runtime_callable=lambda: runtime.arm_section(section_id, mode, code=code),
            log_summary=lambda updated: (
                f"mode={mode.value} resulting_state="
                + str(next((section.state for section in updated.sections if section.id == section_id), None))
            ),
        )

    @app.post("/v1/sections/{section_id}/disarm")
    async def disarm_section(
        section_id: int,
        code: str | None = Query(default=None),
        token: AuthenticatedToken = Depends(require_token),
    ):
        _require_section_disarm(token, code)
        return await _execute_runtime_call(
            token=token,
            op="disarm_section",
            resource=f"section:{section_id}",
            audit_details={"code_supplied": bool(code)},
            runtime_callable=lambda: runtime.disarm_section(section_id, code=code),
            log_summary=lambda updated: "resulting_state=" + str(
                next((section.state for section in updated.sections if section.id == section_id), None)
            ),
        )

    @app.post("/v1/pgs/{pg_id}/on")
    async def pg_on(
        pg_id: int,
        code: str | None = Query(default=None),
        token: AuthenticatedToken = Depends(require_token),
    ):
        _require_pg_control(token, code)
        return await _execute_runtime_call(
            token=token,
            op="pg_on",
            resource=f"pg:{pg_id}",
            audit_details={"code_supplied": bool(code)},
            runtime_callable=lambda: runtime.set_pg(pg_id, True, code=code),
            log_summary=lambda updated: "resulting_state=" + str(
                next((pg.state for pg in updated.pgs if pg.id == pg_id), None)
            ),
        )

    @app.post("/v1/pgs/{pg_id}/off")
    async def pg_off(
        pg_id: int,
        code: str | None = Query(default=None),
        token: AuthenticatedToken = Depends(require_token),
    ):
        _require_pg_control(token, code)
        return await _execute_runtime_call(
            token=token,
            op="pg_off",
            resource=f"pg:{pg_id}",
            audit_details={"code_supplied": bool(code)},
            runtime_callable=lambda: runtime.set_pg(pg_id, False, code=code),
            log_summary=lambda updated: "resulting_state=" + str(
                next((pg.state for pg in updated.pgs if pg.id == pg_id), None)
            ),
        )

    @app.get("/v1/users")
    async def users(
        max_age_seconds: float | None = Query(
            default=None,
            ge=0,
            description=(
                "Serve the cached catalog only if it is at most this many seconds old; "
                "otherwise read the panel. 0 forces a read that starts after this "
                "request arrives. Omitted: the server's configured default."
            ),
        ),
        token: AuthenticatedToken = Depends(require_token),
    ):
        require_scopes(token, Scope.USERS_READ.value)
        return serialize_users(await runtime.get_users(max_age_seconds), token)

    @app.get("/v1/users/{user_id}")
    async def user(
        user_id: int,
        max_age_seconds: float | None = Query(
            default=None,
            ge=0,
            description=(
                "Serve the cached catalog only if it is at most this many seconds old; "
                "otherwise read the panel. 0 forces a read that starts after this "
                "request arrives. Omitted: the server's configured default."
            ),
        ),
        token: AuthenticatedToken = Depends(require_token),
    ):
        require_scopes(token, Scope.USERS_READ.value)
        result = await runtime.get_user(user_id, max_age_seconds)
        if result is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        return serialize_users([result], token)[0]

    @app.post("/v1/users")
    async def add_user(
        payload: UserCreateModel,
        replace: bool = Query(
            default=False,
            description=(
                "The panel's import is an upsert. Without this flag a create aimed "
                "at a slot that already holds a named user is refused with 409 "
                "user_slot_occupied; with replace=1 the slot is overwritten."
            ),
        ),
        token: AuthenticatedToken = Depends(require_token),
    ):
        require_scopes(token, Scope.USERS_WRITE.value)
        return await _execute_runtime_call(
            token=token,
            op="add_user",
            resource=f"user:{payload.id}",
            audit_details={**payload.model_dump(mode="json"), "replace": replace},
            runtime_callable=lambda: runtime.add_user(payload, replace=replace),
        )

    @app.patch("/v1/users/{user_id}")
    async def edit_user(
        user_id: int,
        payload: UserPatchModel,
        token: AuthenticatedToken = Depends(require_token),
    ):
        require_scopes(token, Scope.USERS_WRITE.value)
        return await _execute_runtime_call(
            token=token,
            op="edit_user",
            resource=f"user:{user_id}",
            audit_details=payload.model_dump(exclude_unset=True, mode="json"),
            runtime_callable=lambda: runtime.edit_user(user_id, payload),
        )

    @app.delete("/v1/users/{user_id}")
    async def delete_user(user_id: int, token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.USERS_WRITE.value)
        await _execute_runtime_call(
            token=token,
            op="delete_user",
            resource=f"user:{user_id}",
            audit_details={},
            runtime_callable=lambda: runtime.delete_user(user_id),
        )
        return {"status": "deleted", "user_id": user_id}

    @app.get("/v1/events")
    async def events(
        limit: int = Query(default=20, ge=1, le=200),
        include_raw: bool = Query(default=False),
        kinds: str | None = Query(default=None),
        exclude_kinds: str | None = Query(default=None),
        token: AuthenticatedToken = Depends(require_token),
    ):
        require_scopes(token, Scope.EVENTS_READ.value)
        return await runtime.get_events_recent(
            limit=limit, include_raw=include_raw, kinds=kinds, exclude_kinds=exclude_kinds
        )

    # Deprecated alias retained for v1 backward compatibility with the
    # earlier /v1/events/recent path. Clients should migrate to /v1/events
    # with the same query parameters; this alias will be removed after the
    # v1 alpha window.
    @app.get("/v1/events/recent", deprecated=True)
    async def events_recent_deprecated(
        limit: int = Query(default=20, ge=1, le=200),
        include_raw: bool = Query(default=False),
        kinds: str | None = Query(default=None),
        exclude_kinds: str | None = Query(default=None),
        token: AuthenticatedToken = Depends(require_token),
    ):
        return await events(limit, include_raw, kinds, exclude_kinds, token)

    @app.get("/v1/export/users")
    async def export_users(
        max_age_seconds: float | None = Query(
            default=None,
            ge=0,
            description=(
                "Serve the cached catalog only if it is at most this many seconds old; "
                "otherwise read the panel. 0 forces a read that starts after this "
                "request arrives. Omitted: the server's configured default."
            ),
        ),
        token: AuthenticatedToken = Depends(require_token),
    ):
        require_scopes(token, Scope.USERS_READ.value)
        return serialize_users(await runtime.get_export_users(max_age_seconds), token)

    @app.get("/v1/export/catalog")
    async def export_catalog(
        max_age_seconds: float | None = Query(
            default=None,
            ge=0,
            description=(
                "Serve the cached catalog only if it is at most this many seconds old; "
                "otherwise read the panel. 0 forces a read that starts after this "
                "request arrives. Omitted: the server's configured default."
            ),
        ),
        token: AuthenticatedToken = Depends(require_token),
    ):
        require_scopes(token, Scope.CATALOG_READ.value)
        return serialize_catalog(await runtime.get_catalog(max_age_seconds), token)

    @app.get("/v1/export/time-limits")
    async def export_time_limits(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.CONFIG_READ.value)
        return {"time_limits": await runtime.get_export_time_limits()}

    @app.get("/v1/export/communications")
    async def export_communications(token: AuthenticatedToken = Depends(require_token)):
        require_scopes(token, Scope.CONFIG_READ.value)
        return await runtime.get_export_communications()

    @app.post("/v1/tokens")
    async def create_token(
        payload: TokenCreateRequest, token: AuthenticatedToken = Depends(require_token)
    ) -> TokenCreateResponse:
        require_scopes(token, Scope.TOKENS_ADMIN.value)
        try:
            token_value, token_info = token_store.create_token(
                label=payload.label,
                scopes=payload.scopes,
                certificate_fingerprint=payload.certificate_fingerprint,
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        token_store.write_audit(
            token_id=token.id,
            action="create_token",
            resource=f"token:{token_info.id}",
            details=payload.model_dump(mode="json"),
        )
        LOGGER.info(
            "Token created via API: actor=%s token=%s scopes=%s fingerprint_bound=%s",
            _token_log_label(token),
            f"{sanitize_for_log(token_info.label)} ({token_info.id})",
            ",".join(token_info.scopes),
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
        token_store.write_audit(
            token_id=token.id, action="revoke_token", resource=f"token:{token_id}", details={}
        )
        LOGGER.info("Token revoked via API: actor=%s token_id=%s", _token_log_label(token), token_id)
        return {"status": "revoked", "token_id": token_id}

    @app.websocket("/v1/ws")
    async def websocket_endpoint(
        websocket: WebSocket,
        token: str | None = Query(default=None),
    ):
        # Auth precedence:
        #   1. Authorization: Bearer <token> header on the WS upgrade request.
        #   2. ?token=<token> query parameter (kept for HA-integration
        #      compatibility — deprecated for v1.1; tokens in URLs land in
        #      access logs and proxy logs).
        # The TLS fingerprint is read only from the verified TLS scope;
        # never from a client-supplied query parameter or header.
        header_token = _bearer_token_from_headers(websocket.headers)
        token_value = header_token or token
        if not token_value:
            LOGGER.warning(
                "WebSocket authentication failed: missing bearer token path=%s",
                websocket.url.path,
            )
            await websocket.close(code=4401)
            return
        if header_token is None and token is not None:
            LOGGER.warning(
                "WebSocket authentication used deprecated ?token= query parameter; "
                "move to the Authorization header to keep the token out of access logs.",
            )
        fingerprint = _tls_fingerprint_from_scope(websocket.scope)
        authenticated = token_store.authenticate(token_value, certificate_fingerprint=fingerprint)
        if authenticated is None:
            LOGGER.warning(
                "WebSocket authentication failed: path=%s fingerprint=%s",
                websocket.url.path,
                _short_fingerprint(fingerprint),
            )
            await websocket.close(code=4401)
            return
        await ws_manager.connect(websocket, metadata={"token": authenticated})
        LOGGER.info(
            "WebSocket connected: token=%s fingerprint=%s",
            _token_log_label(authenticated),
            _short_fingerprint(fingerprint),
        )
        try:
            await websocket.send_json({"event": "hello", "topics": list(TOPIC_SCOPES)})
            while True:
                # receive_text + json.loads instead of receive_json so we can
                # cap message size and route JSONDecodeError to a 1003 close
                # instead of crashing the receive loop with an uncaught
                # exception.
                raw = await websocket.receive_text()
                if len(raw) > _WS_MAX_MESSAGE_BYTES:
                    LOGGER.warning(
                        "WebSocket message exceeded size cap: token=%s size=%d",
                        _token_log_label(authenticated),
                        len(raw),
                    )
                    await websocket.close(code=1009, reason="message too large")
                    return
                try:
                    message = json.loads(raw)
                except json.JSONDecodeError:
                    await websocket.send_json({"event": "error", "error": "invalid_json"})
                    continue
                if not isinstance(message, dict):
                    await websocket.send_json({"event": "error", "error": "invalid_message"})
                    continue
                action = message.get("action")
                if action == "subscribe":
                    await _handle_ws_subscribe(websocket, authenticated, message)
                elif action == "ping":
                    await websocket.send_json({"event": "pong"})
                else:
                    await websocket.send_json({"event": "error", "error": "unknown_action"})
        except WebSocketDisconnect:
            LOGGER.info("WebSocket disconnected: token=%s", _token_log_label(authenticated))
        finally:
            await ws_manager.disconnect(websocket)

    async def _handle_ws_subscribe(
        websocket: WebSocket, authenticated: AuthenticatedToken, message: dict
    ) -> None:
        topics = [str(topic) for topic in message.get("topics", [])]
        allowed_topics: list[str] = []
        denied_topics: list[str] = []
        for topic in topics:
            if _authorize_topic(authenticated, topic):
                allowed_topics.append(topic)
            else:
                denied_topics.append(topic)
        if denied_topics:
            LOGGER.warning(
                "WebSocket subscribe denied topics: token=%s denied=%s",
                _token_log_label(authenticated),
                denied_topics,
            )
            await websocket.send_json(
                {"event": "error", "error": "missing_scopes", "topics": denied_topics}
            )
        if not allowed_topics:
            return
        await ws_manager.subscribe(websocket, allowed_topics)
        LOGGER.info(
            "WebSocket subscribed: token=%s topics=%s",
            _token_log_label(authenticated),
            allowed_topics,
        )
        for topic in allowed_topics:
            await _send_ws_snapshot(websocket, authenticated, topic)

    async def _send_ws_snapshot(
        websocket: WebSocket, authenticated: AuthenticatedToken, topic: str
    ) -> None:
        if topic == "status":
            payload = (await runtime.get_status()).model_dump(mode="json")
        elif topic == "catalog":
            payload = serialize_catalog(await runtime.get_catalog(), authenticated)
        elif topic == "system":
            payload = (await build_system_payload(authenticated)).model_dump(mode="json")
        elif topic == "users":
            payload = serialize_users(await runtime.get_users(), authenticated)
        elif topic == "events":
            payload = [
                event.model_dump(mode="json")
                for event in await runtime.get_events_recent(limit=20)
            ]
        else:
            return
        await websocket.send_json({"event": "snapshot", "topic": topic, "payload": payload})

    return app
