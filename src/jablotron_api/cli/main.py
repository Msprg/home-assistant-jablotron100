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
    )
    print(f"token {token_value}")
    print(f"id {token_info.id}")
    print(f"scopes {','.join(token_info.scopes)}")


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
    # Redact sensitive query parameters (token=, fingerprint=) from
    # uvicorn's access log before they hit any file or stdout sink.
    log_config.setdefault("filters", {})["redact_sensitive_query"] = {
        "()": "jablotron_api.server.app.SensitiveQueryAccessLogFilter",
    }
    log_config["loggers"]["uvicorn.access"].setdefault("filters", []).append(
        "redact_sensitive_query"
    )
    uvicorn_kwargs: dict = dict(
        host=settings.host,
        port=settings.port,
        http=TLSAwareH11Protocol,
        ws=TLSAwareWebSocketProtocol,
        timeout_graceful_shutdown=15,
        log_config=log_config,
    )
    # Always serve over TLS; the difference is whether we demand and
    # validate the client certificate. mTLS off path is for HA Add-on
    # localhost / Supervisor deployments where mTLS is friction without
    # security benefit.
    if settings.tls_certfile and settings.tls_keyfile:
        uvicorn_kwargs["ssl_certfile"] = settings.tls_certfile
        uvicorn_kwargs["ssl_keyfile"] = settings.tls_keyfile
    if settings.mtls_required:
        if settings.tls_ca_certs:
            uvicorn_kwargs["ssl_ca_certs"] = settings.tls_ca_certs
        uvicorn_kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED
    uvicorn.run(app, **uvicorn_kwargs)


def cmd_client(args: argparse.Namespace) -> None:
    client_cli.main(args.client_args)


def cmd_openapi_export(args: argparse.Namespace) -> None:
    """Write the FastAPI-generated OpenAPI document to disk for the v1 lock."""

    import json
    import tempfile

    from jablotron_api.panel.demo import DemoPanelRuntime
    from jablotron_api.server.app import create_app
    from jablotron_api.server.config import ServerSettings

    output = Path(args.output)
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "tokens.db"
        settings = ServerSettings(db_path=db, runtime_mode="demo")
        app = create_app(settings=settings, runtime=DemoPanelRuntime(), token_store=TokenStore(db))
        spec = app.openapi()
    output.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n")
    print(f"wrote {output}")


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

    client = subparsers.add_parser("client", help="Run the packaged reference client CLI.")
    client.add_argument("client_args", nargs=argparse.REMAINDER)
    client.set_defaults(func=cmd_client)

    openapi = subparsers.add_parser(
        "openapi-export",
        help="Generate the FastAPI OpenAPI document for the v1 schema lock.",
    )
    openapi.add_argument("output", help="Output JSON path (e.g. docs/openapi.v1.json)")
    openapi.set_defaults(func=cmd_openapi_export)

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
