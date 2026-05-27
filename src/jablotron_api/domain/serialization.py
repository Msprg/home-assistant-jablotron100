"""Token-aware serializers for users and catalogs.

The serializers honor scope-gated visibility: panel `code` values are only
included when the token carries `users:codes:read`.
"""

from __future__ import annotations

from jablotron_api.domain.models import AuthenticatedToken, Scope


def _has_scope(token: AuthenticatedToken, scope: Scope) -> bool:
    return scope.value in token.scopes


def can_read_users(token: AuthenticatedToken) -> bool:
    return _has_scope(token, Scope.USERS_READ)


def can_read_user_codes(token: AuthenticatedToken) -> bool:
    return _has_scope(token, Scope.USERS_CODES_READ)


def can_read_catalog(token: AuthenticatedToken) -> bool:
    return _has_scope(token, Scope.CATALOG_READ)


def serialize_users(users: list, token: AuthenticatedToken) -> list[dict]:
    include_codes = can_read_user_codes(token)
    return [
        user.model_dump(mode="json")
        if include_codes
        else user.model_copy(update={"code": ""}).model_dump(mode="json")
        for user in users
    ]


def serialize_catalog(catalog, token: AuthenticatedToken) -> dict:
    users_payload: list[dict] = []
    if can_read_users(token):
        users_payload = serialize_users(catalog.users, token)
    return catalog.model_dump(mode="json", exclude={"users"}) | {"users": users_payload}


def serialize_ws_payload(token: AuthenticatedToken, topic: str, payload):
    if topic == "catalog":
        users_payload: list[dict] = []
        if can_read_users(token):
            users_payload = [
                user_payload if can_read_user_codes(token) else {**user_payload, "code": ""}
                for user_payload in payload.get("users", [])
            ]
        return {**payload, "users": users_payload}
    if topic == "users":
        if can_read_user_codes(token):
            return payload
        return [{**user_payload, "code": ""} for user_payload in payload]
    return payload
