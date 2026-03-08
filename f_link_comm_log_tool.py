#!/usr/bin/env python3
"""Decode F-Link comm.log*.htm files.

Recovered from F-Link 2.9.2.1509:

- class: TObfuscatedLogStream
- constructor: 0x00702314
- read: 0x00702350
- write: 0x00702388
- XOR table VA: 0x011DBE31

The stream applies a bytewise XOR with a 256-byte repeating table and an
internal key position that starts at zero for each file. The resulting payload
is plain UTF-8 HTML.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path

COMM_LOG_KEY = bytes.fromhex(
    "e95dd5b085c506818406a344aedc0c4d"
    "5d88f809e1919b8164605142aa15f174"
    "91d7eff36db810b5280e71254c31964c"
    "ba984e78ce95e65a30d048aeef26528c"
    "3ae3081b2f2a2c438d6e99774229ee26"
    "e542cf240d1444c1389d88d20d418301"
    "83bfa8e8b1894d849dc4c5594311ed9b"
    "a6899871ec0ec9682d6dec18b18ac0f5"
    "958bdbc87afc69e2eb0294c84f04dd95"
    "6521f3424324af15575bd4a2f1356ea0"
    "998b144f504dac49b5e5a0eb49a383e3"
    "349be98b5ae542b64c66da5970d14f7d"
    "cbe11d3c80b92adf6a05bd1c1afc57e4"
    "ee3e31badf743e9e475905ebb516b603"
    "793b556350e0bedb95a1134a17d9c346"
    "0ec32ba647cd26470d8fed22d14ca83c"
)

TAG_RE = re.compile(r"<[^>]+>")
LINEBREAK_RE = re.compile(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</li>|</h[1-6]>")


def decode_comm_log(data: bytes, key: bytes = COMM_LOG_KEY) -> bytes:
    return bytes(byte ^ key[index & 0xFF] for index, byte in enumerate(data))


def html_to_text(decoded_html: bytes) -> str:
    text = decoded_html.decode("utf-8", "replace")
    text = LINEBREAK_RE.sub("\n", text)
    text = TAG_RE.sub("", text)
    text = html.unescape(text)
    lines = [line.rstrip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line.strip())


def write_output(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
        return
    path.write_bytes(data)


def cmd_decode(args: argparse.Namespace) -> None:
    decoded = decode_comm_log(Path(args.input).read_bytes())
    if args.stdout:
        sys.stdout.buffer.write(decoded)
        return
    if not args.output:
        raise SystemExit("decode requires OUTPUT unless --stdout is used")
    write_output(Path(args.output), decoded)


def cmd_decode_tree(args: argparse.Namespace) -> None:
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    files = sorted(input_dir.glob(args.glob))
    if not files:
        raise SystemExit(f"no files matched {args.glob!r} in {input_dir}")
    for source in files:
        output_name = source.name if args.keep_name else f"{source.name}{args.suffix}"
        target = output_dir / output_name
        write_output(target, decode_comm_log(source.read_bytes()))
        print(target)


def cmd_dump_text(args: argparse.Namespace) -> None:
    text = html_to_text(decode_comm_log(Path(args.input).read_bytes()))
    if args.output:
        write_output(Path(args.output), text)
        return
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")


def cmd_dump_text_tree(args: argparse.Namespace) -> None:
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    files = sorted(input_dir.glob(args.glob))
    if not files:
        raise SystemExit(f"no files matched {args.glob!r} in {input_dir}")
    for source in files:
        target = output_dir / f"{source.stem}.txt"
        write_output(target, html_to_text(decode_comm_log(source.read_bytes())))
        print(target)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    decode_parser = subparsers.add_parser("decode", help="decode one comm.log file to HTML")
    decode_parser.add_argument("input", help="input comm.log*.htm file")
    decode_parser.add_argument("output", nargs="?", help="decoded HTML output path")
    decode_parser.add_argument("--stdout", action="store_true", help="write decoded HTML to stdout")
    decode_parser.set_defaults(func=cmd_decode)

    decode_tree_parser = subparsers.add_parser(
        "decode-tree",
        help="decode a directory of comm.log files",
    )
    decode_tree_parser.add_argument("input_dir", help="directory containing comm.log files")
    decode_tree_parser.add_argument("output_dir", help="directory for decoded HTML files")
    decode_tree_parser.add_argument(
        "--glob",
        default="comm.log*.htm",
        help="glob used to select input files",
    )
    decode_tree_parser.add_argument(
        "--suffix",
        default=".decoded.html",
        help="suffix appended to decoded filenames when --keep-name is not used",
    )
    decode_tree_parser.add_argument(
        "--keep-name",
        action="store_true",
        help="preserve the original filename in the output directory",
    )
    decode_tree_parser.set_defaults(func=cmd_decode_tree)

    dump_text_parser = subparsers.add_parser(
        "dump-text",
        help="decode one comm.log file and strip the HTML tags",
    )
    dump_text_parser.add_argument("input", help="input comm.log*.htm file")
    dump_text_parser.add_argument("output", nargs="?", help="plaintext output path")
    dump_text_parser.set_defaults(func=cmd_dump_text)

    dump_text_tree_parser = subparsers.add_parser(
        "dump-text-tree",
        help="decode a directory of comm.log files and write plaintext .txt outputs",
    )
    dump_text_tree_parser.add_argument("input_dir", help="directory containing comm.log files")
    dump_text_tree_parser.add_argument("output_dir", help="directory for plaintext outputs")
    dump_text_tree_parser.add_argument(
        "--glob",
        default="comm.log*.htm",
        help="glob used to select input files",
    )
    dump_text_tree_parser.set_defaults(func=cmd_dump_text_tree)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
