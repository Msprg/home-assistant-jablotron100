"""Authentication helpers."""

from __future__ import annotations

from fastapi import HTTPException, status

from jablotron_api.domain.models import AuthenticatedToken


def require_scopes(token: AuthenticatedToken, *required: str) -> None:
    missing = [scope for scope in required if scope not in token.scopes]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "missing_scopes",
                "missing": missing,
            },
        )


def require_any_scope(token: AuthenticatedToken, *allowed: str) -> None:
    if any(scope in token.scopes for scope in allowed):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": "missing_scopes",
            "missing_any_of": list(allowed),
        },
    )
