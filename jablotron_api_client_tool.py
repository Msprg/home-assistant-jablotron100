#!/usr/bin/env python3
"""Thin wrapper for basic Jablotron API client checks."""

from __future__ import annotations

import argparse
import asyncio
import sys

from jablotron_api.client.api import JablotronApiClient


def _parse_verify(value: str | bool) -> str | bool:
    if isinstance(value, bool):
        return value
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return value


def _parse_cert(args: argparse.Namespace) -> tuple[str, str] | None:
    if bool(args.client_cert) != bool(args.client_key):
        raise SystemExit("Both --client-cert and --client-key must be provided together.")
    if args.client_cert and args.client_key:
        return (args.client_cert, args.client_key)
    return None


def _build_client(args: argparse.Namespace) -> JablotronApiClient:
    return JablotronApiClient(
        base_url=args.base_url,
        token=args.token,
        verify=_parse_verify(args.verify),
        cert=_parse_cert(args),
    )


async def _run_status(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        print(await client.get_status())
    finally:
        await client.aclose()


async def _run_system(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        print(await client.get_system())
    finally:
        await client.aclose()


async def _run_devices(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        print(await client.list_devices())
    finally:
        await client.aclose()


async def _run_users(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        print(await client.list_users())
    finally:
        await client.aclose()


async def _run_events(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        print(await client.recent_events(limit=args.limit))
    finally:
        await client.aclose()


async def _run_arm(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        print(await client.arm_section(args.section_id, mode=args.mode, code=args.code))
    finally:
        await client.aclose()


async def _run_disarm(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        print(await client.disarm_section(args.section_id, code=args.code))
    finally:
        await client.aclose()


async def _run_pg(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        print(await client.set_pg(args.pg_id, args.enabled, code=args.code))
    finally:
        await client.aclose()


async def _run_ws(args: argparse.Namespace) -> None:
    client = _build_client(args)
    try:
        count = 0
        async for message in client.websocket(topics=args.topic):
            print(message)
            count += 1
            if count >= args.count:
                break
    finally:
        await client.aclose()


def _add_connection_args(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument("--base-url", required=True)
    subparser.add_argument("--token", required=True)
    subparser.add_argument("--verify", default=True)
    subparser.add_argument("--client-cert")
    subparser.add_argument("--client-key")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command, func in (("system", _run_system), ("status", _run_status), ("devices", _run_devices), ("users", _run_users)):
        subparser = subparsers.add_parser(command)
        _add_connection_args(subparser)
        subparser.set_defaults(func=func)

    events = subparsers.add_parser("events")
    _add_connection_args(events)
    events.add_argument("--limit", type=int, default=20)
    events.set_defaults(func=_run_events)

    arm = subparsers.add_parser("arm")
    _add_connection_args(arm)
    arm.add_argument("section_id", type=int)
    arm.add_argument("--mode", choices=["away", "home", "night"], default="away")
    arm.add_argument("--code")
    arm.set_defaults(func=_run_arm)

    disarm = subparsers.add_parser("disarm")
    _add_connection_args(disarm)
    disarm.add_argument("section_id", type=int)
    disarm.add_argument("--code")
    disarm.set_defaults(func=_run_disarm)

    pg_on = subparsers.add_parser("pg-on")
    _add_connection_args(pg_on)
    pg_on.add_argument("pg_id", type=int)
    pg_on.add_argument("--code")
    pg_on.set_defaults(func=_run_pg, enabled=True)

    pg_off = subparsers.add_parser("pg-off")
    _add_connection_args(pg_off)
    pg_off.add_argument("pg_id", type=int)
    pg_off.add_argument("--code")
    pg_off.set_defaults(func=_run_pg, enabled=False)

    ws = subparsers.add_parser("ws")
    _add_connection_args(ws)
    ws.add_argument("--topic", action="append", default=[])
    ws.add_argument("--count", type=int, default=5)
    ws.set_defaults(func=_run_ws)

    return parser


if __name__ == "__main__":
    parsed = build_parser().parse_args()
    asyncio.run(parsed.func(parsed))
