"""Command-line reference client for the Jablotron API server."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Awaitable, Callable, Sequence

from jablotron_api.client.api import JablotronApiClient, JablotronApiError


Handler = Callable[[argparse.Namespace, JablotronApiClient], Awaitable[Any]]


def parse_verify(value: str | bool) -> str | bool:
    if isinstance(value, bool):
        return value
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return value


def parse_cert(args: argparse.Namespace) -> tuple[str, str] | None:
    if bool(args.client_cert) != bool(args.client_key):
        raise SystemExit("Both --client-cert and --client-key must be provided together.")
    if args.client_cert and args.client_key:
        return (args.client_cert, args.client_key)
    return None


def build_client(args: argparse.Namespace) -> JablotronApiClient:
    missing = [name for name in ("base_url", "token") if not getattr(args, name, None)]
    if missing:
        raise SystemExit(f"Missing required connection argument(s): {', '.join('--' + name.replace('_', '-') for name in missing)}")
    return JablotronApiClient(
        base_url=args.base_url,
        token=args.token,
        verify=parse_verify(args.verify),
        cert=parse_cert(args),
        timeout=args.timeout,
    )


def _load_json_value(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    raw = Path(value[1:]).read_text(encoding="utf-8") if value.startswith("@") else value
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise SystemExit("JSON payload must be an object.")
    return payload


def _parse_csv_ints(value: str | None) -> list[int] | None:
    if value is None:
        return None
    if not value.strip():
        return []
    try:
        return [int(item.strip()) for item in value.split(",") if item.strip()]
    except ValueError as exc:
        raise SystemExit(f"Expected comma-separated integers, got: {value}") from exc


def _merge_if_set(payload: dict[str, Any], key: str, value: Any) -> None:
    if value is not None:
        payload[key] = value


def _user_payload(args: argparse.Namespace, *, include_id: bool) -> dict[str, Any]:
    payload = _load_json_value(args.json_payload)
    if include_id:
        payload["id"] = args.user_id
    for key in ("name", "phone", "code", "card1", "comment"):
        _merge_if_set(payload, key, getattr(args, key))
    _merge_if_set(payload, "flags_raw", args.flags_raw)
    _merge_if_set(payload, "access_raw", args.access_raw)
    _merge_if_set(payload, "time_limited_group_raw", args.time_limited_group_raw)
    sections = _parse_csv_ints(args.sections)
    pgs = _parse_csv_ints(args.pgs)
    if sections is not None:
        payload["sections"] = sections
    if pgs is not None:
        payload["pgs"] = pgs
    return payload


def _token_payload(args: argparse.Namespace) -> dict[str, Any]:
    payload = _load_json_value(args.json_payload)
    _merge_if_set(payload, "label", args.label)
    if args.scope:
        payload["scopes"] = args.scope
    _merge_if_set(payload, "certificate_fingerprint", args.certificate_fingerprint)
    if not payload.get("label"):
        raise SystemExit("Token creation requires --label or a label field in --json.")
    return payload


def _print_payload(payload: Any, output_format: str) -> None:
    if output_format == "pretty":
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))


async def _run_health(_args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.get_health()


async def _run_system(_args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.get_system()


async def _run_status(_args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.get_status()


async def _run_sections(_args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.list_sections()


async def _run_pgs(_args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.list_pgs()


async def _run_devices(_args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.list_devices()


async def _run_export_users(_args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.export_users()


async def _run_export_catalog(_args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.get_catalog()


async def _run_export_time_limits(_args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.get_time_limits()


async def _run_export_communications(_args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.get_communications()


async def _run_users_list(_args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.list_users()


async def _run_users_get(args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.get_user(args.user_id)


async def _run_users_create(args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.create_user(_user_payload(args, include_id=True))


async def _run_users_patch(args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.patch_user(args.user_id, _user_payload(args, include_id=False))


async def _run_users_delete(args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.delete_user(args.user_id)


async def _run_events_recent(args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.list_events(
        limit=args.limit,
        include_raw=args.include_raw,
        kinds=args.kinds,
        exclude_kinds=args.exclude_kinds,
    )


async def _run_tokens_list(_args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.list_tokens()


async def _run_tokens_create(args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.create_token(_token_payload(args))


async def _run_tokens_revoke(args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.revoke_token(args.token_id)


async def _run_arm(args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.arm_section(args.section_id, mode=args.mode, code=args.code)


async def _run_disarm(args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.disarm_section(args.section_id, code=args.code)


async def _run_pg(args: argparse.Namespace, client: JablotronApiClient) -> Any:
    return await client.set_pg(args.pg_id, args.enabled, code=args.code)


async def _run_ws(args: argparse.Namespace, client: JablotronApiClient) -> None:
    count = 0
    async for message in client.websocket(topics=args.topic):
        _print_payload(message, args.output_format)
        count += 1
        if args.count and count >= args.count:
            break


def _connection_parent() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--base-url", default=argparse.SUPPRESS)
    parent.add_argument("--token", default=argparse.SUPPRESS)
    parent.add_argument("--verify", default=argparse.SUPPRESS)
    parent.add_argument("--client-cert", default=argparse.SUPPRESS)
    parent.add_argument("--client-key", default=argparse.SUPPRESS)
    parent.add_argument("--timeout", type=float, default=argparse.SUPPRESS)
    parent.add_argument("--format", dest="output_format", choices=["json", "pretty"], default=argparse.SUPPRESS)
    return parent


def _set_handler(parser: argparse.ArgumentParser, handler: Handler) -> None:
    parser.set_defaults(handler=handler)


def _add_user_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", dest="json_payload", help="JSON object payload, or @path to a JSON file.")
    parser.add_argument("--name")
    parser.add_argument("--phone")
    parser.add_argument("--code")
    parser.add_argument("--card1")
    parser.add_argument("--comment")
    parser.add_argument("--flags-raw", type=int)
    parser.add_argument("--access-raw", type=int)
    parser.add_argument("--sections", help="Comma-separated section IDs.")
    parser.add_argument("--pgs", help="Comma-separated PG IDs.")
    parser.add_argument("--time-limited-group-raw", type=int)


def build_parser() -> argparse.ArgumentParser:
    connection = _connection_parent()
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command, handler in (
        ("health", _run_health),
        ("system", _run_system),
        ("status", _run_status),
        ("sections", _run_sections),
        ("pgs", _run_pgs),
        ("devices", _run_devices),
        ("export-users", _run_export_users),
        ("export-catalog", _run_export_catalog),
        ("export-time-limits", _run_export_time_limits),
        ("export-communications", _run_export_communications),
    ):
        subparser = subparsers.add_parser(command, parents=[connection])
        _set_handler(subparser, handler)

    users = subparsers.add_parser("users", parents=[connection])
    users_subparsers = users.add_subparsers(dest="users_command", required=True)
    _set_handler(users_subparsers.add_parser("list", parents=[connection]), _run_users_list)
    users_get = users_subparsers.add_parser("get", parents=[connection])
    users_get.add_argument("user_id", type=int)
    _set_handler(users_get, _run_users_get)
    users_create = users_subparsers.add_parser("create", parents=[connection])
    users_create.add_argument("user_id", type=int)
    _add_user_payload_args(users_create)
    _set_handler(users_create, _run_users_create)
    users_patch = users_subparsers.add_parser("patch", parents=[connection])
    users_patch.add_argument("user_id", type=int)
    _add_user_payload_args(users_patch)
    _set_handler(users_patch, _run_users_patch)
    users_delete = users_subparsers.add_parser("delete", parents=[connection])
    users_delete.add_argument("user_id", type=int)
    _set_handler(users_delete, _run_users_delete)

    events = subparsers.add_parser("events", parents=[connection])
    events_subparsers = events.add_subparsers(dest="events_command", required=True)
    events_recent = events_subparsers.add_parser("recent", parents=[connection])
    events_recent.add_argument("--limit", type=int, default=20)
    events_recent.add_argument("--include-raw", action="store_true")
    events_recent.add_argument("--kinds")
    events_recent.add_argument("--exclude-kinds")
    _set_handler(events_recent, _run_events_recent)

    tokens = subparsers.add_parser("tokens", parents=[connection])
    tokens_subparsers = tokens.add_subparsers(dest="tokens_command", required=True)
    _set_handler(tokens_subparsers.add_parser("list", parents=[connection]), _run_tokens_list)
    tokens_create = tokens_subparsers.add_parser("create", parents=[connection])
    tokens_create.add_argument("--json", dest="json_payload", help="JSON object payload, or @path to a JSON file.")
    tokens_create.add_argument("--label")
    tokens_create.add_argument("--scope", action="append", default=[])
    tokens_create.add_argument("--certificate-fingerprint")
    _set_handler(tokens_create, _run_tokens_create)
    tokens_revoke = tokens_subparsers.add_parser("revoke", parents=[connection])
    tokens_revoke.add_argument("token_id")
    _set_handler(tokens_revoke, _run_tokens_revoke)

    arm = subparsers.add_parser("arm", parents=[connection])
    arm.add_argument("section_id", type=int)
    arm.add_argument("--mode", choices=["away", "home", "night"], default="away")
    arm.add_argument("--code")
    _set_handler(arm, _run_arm)

    disarm = subparsers.add_parser("disarm", parents=[connection])
    disarm.add_argument("section_id", type=int)
    disarm.add_argument("--code")
    _set_handler(disarm, _run_disarm)

    pg_on = subparsers.add_parser("pg-on", parents=[connection])
    pg_on.add_argument("pg_id", type=int)
    pg_on.add_argument("--code")
    pg_on.set_defaults(handler=_run_pg, enabled=True)

    pg_off = subparsers.add_parser("pg-off", parents=[connection])
    pg_off.add_argument("pg_id", type=int)
    pg_off.add_argument("--code")
    pg_off.set_defaults(handler=_run_pg, enabled=False)

    ws = subparsers.add_parser("ws", parents=[connection])
    ws.add_argument("--topic", action="append", default=[])
    ws.add_argument("--count", type=int, default=5)
    _set_handler(ws, _run_ws)

    return parser


async def async_main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.verify = getattr(args, "verify", True)
    args.client_cert = getattr(args, "client_cert", None)
    args.client_key = getattr(args, "client_key", None)
    args.timeout = getattr(args, "timeout", 30.0)
    args.output_format = getattr(args, "output_format", "pretty")
    client = build_client(args)
    try:
        payload = await args.handler(args, client)
        if payload is not None:
            _print_payload(payload, args.output_format)
    except JablotronApiError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        await client.aclose()
    return 0


def main(argv: Sequence[str] | None = None) -> None:
    raise SystemExit(asyncio.run(async_main(argv)))


if __name__ == "__main__":
    main()
