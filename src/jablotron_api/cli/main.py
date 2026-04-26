"""Command-line entrypoints for the API server and reference client."""

from __future__ import annotations

import argparse
import copy
import logging.config
import ssl
from pathlib import Path

import uvicorn
from uvicorn.config import LOGGING_CONFIG

from jablotron_api.cli import client as client_cli
from jablotron_api.domain.models import DEFAULT_ADMIN_SCOPES
from jablotron_api.server.tls import TLSAwareH11Protocol, TLSAwareWebSocketProtocol
from jablotron_api.services.storage import TokenStore


def cmd_bootstrap_token(args: argparse.Namespace) -> None:
    store = TokenStore(Path(args.db_path))
    token_value, token_info = store.create_token(
        label=args.label,
        scopes=args.scopes or list(DEFAULT_ADMIN_SCOPES),
        certificate_fingerprint=args.certificate_fingerprint,
        allowed_user_ids=args.allowed_user_ids,
    )
    print(f"token {token_value}")
    print(f"id {token_info.id}")
    print(f"scopes {','.join(token_info.scopes)}")
    if token_info.allowed_user_ids:
        print(f"allowed_user_ids {','.join(str(item) for item in token_info.allowed_user_ids)}")


def cmd_server(_args: argparse.Namespace) -> None:
    from jablotron_api.server.app import create_app
    from jablotron_api.server.config import ServerSettings

    settings = ServerSettings()
    app = create_app(settings=settings)
    log_config = copy.deepcopy(LOGGING_CONFIG)
    log_config["formatters"]["default"]["fmt"] = "%(asctime)s %(levelprefix)s %(message)s"
    log_config["formatters"]["access"]["fmt"] = '%(asctime)s %(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s'
    log_config["formatters"]["default"]["datefmt"] = "%Y-%m-%d %H:%M:%S"
    log_config["formatters"]["access"]["datefmt"] = "%Y-%m-%d %H:%M:%S"
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
        timeout_graceful_shutdown=15,
        log_config=log_config,
    )


def cmd_client(args: argparse.Namespace) -> None:
    client_cli.main(args.client_args)


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
    bootstrap.add_argument("--allowed-user-id", dest="allowed_user_ids", type=int, action="append", default=[])
    bootstrap.set_defaults(func=cmd_bootstrap_token)

    client = subparsers.add_parser("client", help="Run the packaged reference client CLI.")
    client.add_argument("client_args", nargs=argparse.REMAINDER)
    client.set_defaults(func=cmd_client)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
        return
    parser.error("No command selected.")


if __name__ == "__main__":
    main()
