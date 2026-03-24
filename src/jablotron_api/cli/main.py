"""Command-line entrypoints for the API server and reference client."""

from __future__ import annotations

import argparse
import asyncio
import ssl
from pathlib import Path

import uvicorn

from jablotron_api.client.api import JablotronApiClient
from jablotron_api.domain.models import DEFAULT_ADMIN_SCOPES
from jablotron_api.server.tls import TLSAwareH11Protocol, TLSAwareWebSocketProtocol
from jablotron_api.services.storage import TokenStore


def _parse_verify(value: str | bool) -> str | bool:
    if isinstance(value, bool):
        return value
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return value


def _parse_cert_args(args: argparse.Namespace) -> tuple[str, str] | None:
    if bool(getattr(args, "client_cert", None)) != bool(getattr(args, "client_key", None)):
        raise SystemExit("Both --client-cert and --client-key must be provided together.")
    if args.client_cert and args.client_key:
        return (args.client_cert, args.client_key)
    return None


def _build_client(args: argparse.Namespace) -> JablotronApiClient:
    return JablotronApiClient(
        base_url=args.base_url,
        token=args.token,
        verify=_parse_verify(args.verify),
        cert=_parse_cert_args(args),
    )


def cmd_bootstrap_token(args: argparse.Namespace) -> None:
    store = TokenStore(Path(args.db_path))
    token_value, token_info = store.create_token(
        label=args.label,
        scopes=args.scopes or list(DEFAULT_ADMIN_SCOPES),
        certificate_fingerprint=args.certificate_fingerprint,
    )
    print(f"token {token_value}")
    print(f"id {token_info.id}")
    print(f"scopes {','.join(token_info.scopes)}")


def cmd_server(_args: argparse.Namespace) -> None:
    from jablotron_api.server.app import create_app
    from jablotron_api.server.config import ServerSettings

    settings = ServerSettings()
    app = create_app(settings=settings)
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        http=TLSAwareH11Protocol,
        ws=TLSAwareWebSocketProtocol,
        ssl_certfile=settings.tls_certfile,
        ssl_keyfile=settings.tls_keyfile,
        ssl_ca_certs=settings.tls_ca_certs,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )


async def _cmd_client_status(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        print(await client.get_status())
    finally:
        await client.aclose()


async def _cmd_client_users(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        print(await client.list_users())
    finally:
        await client.aclose()


def _add_client_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--verify", default=True)
    parser.add_argument("--client-cert")
    parser.add_argument("--client-key")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    server = subparsers.add_parser("server", help="Run the Jablotron API server.")
    server.set_defaults(func=cmd_server)

    bootstrap = subparsers.add_parser("bootstrap-token", help="Create a local bootstrap/admin token.")
    bootstrap.add_argument("--db-path", default="/data/jablotron-api.db")
    bootstrap.add_argument("--label", default="bootstrap-admin")
    bootstrap.add_argument("--scope", dest="scopes", action="append", default=[])
    bootstrap.add_argument("--certificate-fingerprint")
    bootstrap.set_defaults(func=cmd_bootstrap_token)

    client_status = subparsers.add_parser("client-status", help="Fetch the current server status.")
    _add_client_args(client_status)
    client_status.set_defaults(async_func=_cmd_client_status)

    client_users = subparsers.add_parser("client-users", help="Fetch users from the server.")
    _add_client_args(client_users)
    client_users.set_defaults(async_func=_cmd_client_users)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
        return
    if hasattr(args, "async_func"):
        asyncio.run(args.async_func(args))
        return
    parser.error("No command selected.")
