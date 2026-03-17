#!/usr/bin/env python3
"""Live smoke tests for the current reverse-engineering workflow."""

from __future__ import annotations

import argparse

from jablotron_re_tools import (
    DEFAULT_IMPORT_PATH,
    JablotronUSBClient,
    add_flexi_cfg_device_argument,
    default_export_output,
    drain_packets,
    enter_setup_mode,
    ensure_serial_port,
    graceful_exit_session,
    print_export_snapshot_summary,
    perform_login,
    pull_live_export_snapshot,
    resolve_flexi_cfg_device,
)


def cmd_read_users(args: argparse.Namespace) -> None:
    output = default_export_output("dev-smoke")
    snapshot = pull_live_export_snapshot(
        output=output,
        device=args.device,
        port=args.port,
        code=args.auth_code,
        reset=not args.no_reset,
        cleanup_mode=args.read_cleanup_mode,
        verbose=args.verbose,
    )
    print_export_snapshot_summary(snapshot, device=args.device, resolver=resolve_flexi_cfg_device)
    for record in snapshot.records[: args.limit]:
        print(
            "\t".join(
                [
                    "" if record.user_id is None else str(record.user_id),
                    record.rights,
                    "" if record.enabled is None else ("yes" if record.enabled else "no"),
                    record.name,
                    record.code,
                    record.comment,
                ]
            )
        )


def cmd_setup_session(args: argparse.Namespace) -> None:
    port = ensure_serial_port(args.port)
    client = JablotronUSBClient(port)
    try:
        perform_login(client, args.auth_code, reset=not args.no_reset)
        pre_packets = drain_packets(client, timeout=1.0, prefix="pre", verbose=args.verbose)
        enter_setup_mode(client, verbose=args.verbose, initial_packets=pre_packets)
        graceful_exit_session(client, verbose=args.verbose)
    finally:
        client.close()
    print(f"setup mode entered on {port}")
    print(f"device {resolve_flexi_cfg_device(args.device)}")
    print(f"import_path {DEFAULT_IMPORT_PATH}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    read_users = subparsers.add_parser("read-users", help="Pull a live export and print a short user summary.")
    add_flexi_cfg_device_argument(read_users)
    read_users.add_argument("--port", default="auto", help="HID port (default: auto).")
    read_users.add_argument("--auth-code", default="1812", help="Authorisation code for the smoke test.")
    read_users.add_argument("--no-reset", action="store_true", help="Skip the initial auth-end reset packet.")
    read_users.add_argument(
        "--read-cleanup-mode",
        choices=("auto", "none", "exit-only", "login-exit"),
        default="auto",
        help="How to close the post-read HID session after a live trigger (default: auto).",
    )
    read_users.add_argument("--limit", type=int, default=5, help="Number of users to print from the deduped table.")
    read_users.add_argument("--verbose", action="store_true", help="Print observed HID packets for debugging.")
    read_users.set_defaults(func=cmd_read_users)

    setup_session = subparsers.add_parser("setup-session", help="Log in and confirm setup-mode entry only.")
    add_flexi_cfg_device_argument(setup_session)
    setup_session.add_argument("--port", default="auto", help="HID port (default: auto).")
    setup_session.add_argument("--auth-code", default="1812", help="Authorisation code for the smoke test.")
    setup_session.add_argument("--no-reset", action="store_true", help="Skip the initial auth-end reset packet.")
    setup_session.add_argument("--verbose", action="store_true", help="Print the observed HID packets.")
    setup_session.set_defaults(func=cmd_setup_session)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
