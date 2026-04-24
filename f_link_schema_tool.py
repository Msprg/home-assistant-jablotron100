#!/usr/bin/env python3
"""Extract and inspect embedded F-Link schema blobs from process dumps."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


SCHEMA_MARKER = b'{\r\n    "README": ['
SCHEMA_MARKER_ALT = b'{\n    "README": ['


@dataclass(frozen=True)
class ExtractedSchema:
    source: Path
    start_offset: int
    end_offset: int
    obj: Dict[str, Any]

    @property
    def size(self) -> int:
        return self.end_offset - self.start_offset


def load_schema(path: Path) -> ExtractedSchema:
    if path.suffix.lower() == ".json":
        obj = json.loads(path.read_text(encoding="utf-8"))
        return ExtractedSchema(source=path, start_offset=0, end_offset=path.stat().st_size, obj=obj)

    data = path.read_bytes()
    start = data.find(SCHEMA_MARKER)
    if start == -1:
        start = data.find(SCHEMA_MARKER_ALT)
    if start == -1:
        raise SystemExit(f"No embedded schema JSON marker found in {path}.")

    end = find_matching_brace(data, start)
    blob = data[start:end]
    obj = json.loads(blob)
    return ExtractedSchema(source=path, start_offset=start, end_offset=end, obj=obj)


def find_matching_brace(data: bytes, start: int) -> int:
    depth = 0
    in_string = False
    escape = False

    for index in range(start, len(data)):
        ch = data[index]
        if in_string:
            if escape:
                escape = False
            elif ch == 0x5C:
                escape = True
            elif ch == 0x22:
                in_string = False
            continue

        if ch == 0x22:
            in_string = True
        elif ch == 0x7B:
            depth += 1
        elif ch == 0x7D:
            depth -= 1
            if depth == 0:
                return index + 1

    raise SystemExit("Embedded schema JSON appears truncated; matching '}' not found.")


def write_json(output: Path, obj: Dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def get_path(obj: Any, path_expr: str) -> Any:
    current = obj
    for part in path_expr.split("."):
        if isinstance(current, dict):
            if part not in current:
                raise SystemExit(f"Path component {part!r} not found.")
            current = current[part]
            continue
        if isinstance(current, list):
            try:
                index = int(part)
            except ValueError as exc:
                raise SystemExit(f"List path component must be an integer, got {part!r}.") from exc
            try:
                current = current[index]
            except IndexError as exc:
                raise SystemExit(f"List index {index} out of range.") from exc
            continue
        raise SystemExit(f"Cannot descend into {type(current).__name__} with path component {part!r}.")
    return current


def format_access_entry(item: Any, index: int) -> str:
    if isinstance(item, str):
        return f"{index:>2}: {item}"
    if isinstance(item, dict):
        parts = [f"{index:>2}: {item.get('name', '<unnamed>')}"]
        if "def" in item:
            parts.append(f"def={item['def']}")
        if item.get("info"):
            parts.append(f"info={item['info']}")
        return " | ".join(parts)
    return f"{index:>2}: {item!r}"


def build_access_report(schema: Dict[str, Any]) -> str:
    common = schema["MODULE(cfg_types_common)"]
    storage = schema["MODULE(cfg_storage_types)"]

    lines: List[str] = []
    lines.append("F-Link Embedded Schema Access Report")
    lines.append("")

    lines.append("access_e")
    for index, item in enumerate(common["access_e"]["enum"]):
        lines.append(f"  {format_access_entry(item, index)}")
    lines.append("")

    lines.append("competence_e")
    for index, item in enumerate(common["competence_e"]["enum"]):
        lines.append(f"  {format_access_entry(item, index)}")
    lines.append("")

    lines.append("cfg_data_t access gates")
    for field, node in storage["cfg_data_t"]["class"].items():
        read_access = node.get("r_access")
        write_access = node.get("w_access")
        if read_access or write_access:
            lines.append(
                f"  {field}: class={node.get('class')} r_access={read_access or '-'} w_access={write_access or '-'}"
            )
    lines.append("")

    lines.append("cfg_user_t fields")
    for field, node in storage["cfg_user_t"]["class"].items():
        if not isinstance(node, dict):
            continue
        details = [
            f"class={node.get('class')}",
            f"flrecname={node.get('flrecname', '-')}",
        ]
        if node.get("w_access"):
            details.append(f"w_access={node['w_access']}")
        if node.get("r_access"):
            details.append(f"r_access={node['r_access']}")
        if node.get("info"):
            details.append(f"info={node['info']}")
        lines.append(f"  {field}: " + " | ".join(details))
    lines.append("")

    if "cfg_comm_service_access_e" in storage:
        lines.append("cfg_comm_service_access_e")
        for index, item in enumerate(storage["cfg_comm_service_access_e"]["enum"]):
            lines.append(f"  {format_access_entry(item, index)}")
        lines.append("")

    lines.append("Notable findings")
    lines.append("  ACCESS_SYSTEM exists with def=15 and is described as unrestricted software-only access.")
    lines.append("  COMP_SYSTEM exists and is described as direct software-only access with no external access.")
    lines.append("  User/config read/write gates in cfg_data_t are expressed in terms of ACCESS_* comparisons.")
    lines.append("  cfg_user_t.access maps to access_t, while F-Link UI competence labels appear to be a separate layer.")
    return "\n".join(lines) + "\n"


def cmd_extract(args: argparse.Namespace) -> None:
    schema = load_schema(Path(args.input))
    output = Path(args.output)
    write_json(output, schema.obj)
    print(f"wrote {output}")
    print(f"source {schema.source}")
    print(f"offsets {schema.start_offset}..{schema.end_offset}")
    print(f"size {schema.size}")


def cmd_show(args: argparse.Namespace) -> None:
    schema = load_schema(Path(args.input))
    node = get_path(schema.obj, args.path)
    print(json.dumps(node, indent=2, ensure_ascii=False))


DEV_COMMENT_FIELDS: Tuple[str, ...] = ("info", "text", "comment")


@dataclass(frozen=True)
class DevCommentEntry:
    path: Tuple[str, ...]
    node_class: Optional[str]
    flrecname: Optional[str]
    node_id: Optional[str]
    default: Any
    info: List[str]
    text: Optional[str]
    comment: Optional[str]
    from_enum: Optional[str]
    access_read: Optional[str]
    access_write: Optional[str]

    @property
    def path_display(self) -> str:
        return " > ".join(self.path)

    @property
    def has_any_comment(self) -> bool:
        return bool(self.info or self.text or self.comment)


def _normalise_info(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if isinstance(value, list):
        out: List[str] = []
        for element in value:
            if isinstance(element, str):
                stripped = element.strip()
                if stripped:
                    out.append(stripped)
        return out
    return [json.dumps(value, ensure_ascii=False)]


def _stringify(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return json.dumps(value, ensure_ascii=False)


def iter_dev_comments(schema: Dict[str, Any]) -> Iterable[DevCommentEntry]:
    def walk(node: Any, path: Tuple[str, ...]) -> Iterable[DevCommentEntry]:
        if isinstance(node, dict):
            info = _normalise_info(node.get("info"))
            text = _stringify(node.get("text"))
            comment_value = node.get("comment")
            comment_str = _stringify(comment_value) if isinstance(comment_value, str) else None
            if info or text or comment_str:
                yield DevCommentEntry(
                    path=path,
                    node_class=_stringify(node.get("class")),
                    flrecname=_stringify(node.get("flrecname")),
                    node_id=_stringify(node.get("id")),
                    default=node.get("def"),
                    info=info,
                    text=text,
                    comment=comment_str,
                    from_enum=_stringify(node.get("from")),
                    access_read=_stringify(node.get("r_access")),
                    access_write=_stringify(node.get("w_access")),
                )
            for key, value in node.items():
                if key in DEV_COMMENT_FIELDS:
                    continue
                yield from walk(value, path + (str(key),))
        elif isinstance(node, list):
            for index, element in enumerate(node):
                yield from walk(element, path + (f"[{index}]",))

    yield from walk(schema, tuple())


def _format_default(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return json.dumps(value, ensure_ascii=False)


def format_dev_comments_text(entries: Iterable[DevCommentEntry]) -> str:
    lines: List[str] = []
    lines.append("F-Link Embedded Schema Dev-Comment Index")
    lines.append("")
    count = 0
    for entry in entries:
        count += 1
        lines.append(entry.path_display)
        meta_bits: List[str] = []
        if entry.node_class:
            meta_bits.append(f"class={entry.node_class}")
        if entry.flrecname:
            meta_bits.append(f"flrecname={entry.flrecname}")
        if entry.node_id:
            meta_bits.append(f"id={entry.node_id}")
        default_str = _format_default(entry.default)
        if default_str is not None:
            meta_bits.append(f"def={default_str}")
        if entry.from_enum:
            meta_bits.append(f"from={entry.from_enum}")
        if entry.access_read:
            meta_bits.append(f"r_access={entry.access_read}")
        if entry.access_write:
            meta_bits.append(f"w_access={entry.access_write}")
        if meta_bits:
            lines.append("  " + " | ".join(meta_bits))
        if entry.text:
            lines.append(f"  text: {entry.text}")
        for paragraph in entry.info:
            lines.append(f"  info: {paragraph}")
        if entry.comment:
            lines.append(f"  comment: {entry.comment}")
        lines.append("")
    lines.insert(1, f"entries: {count}")
    lines.insert(2, "")
    return "\n".join(lines).rstrip() + "\n"


def dev_comments_to_json_records(entries: Iterable[DevCommentEntry]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for entry in entries:
        record: Dict[str, Any] = {"path": list(entry.path)}
        if entry.node_class:
            record["class"] = entry.node_class
        if entry.flrecname:
            record["flrecname"] = entry.flrecname
        if entry.node_id:
            record["id"] = entry.node_id
        if entry.default is not None:
            record["def"] = entry.default
        if entry.from_enum:
            record["from"] = entry.from_enum
        if entry.access_read:
            record["r_access"] = entry.access_read
        if entry.access_write:
            record["w_access"] = entry.access_write
        if entry.text:
            record["text"] = entry.text
        if entry.info:
            record["info"] = list(entry.info)
        if entry.comment:
            record["comment"] = entry.comment
        records.append(record)
    return records


def _filter_entries(
    entries: Iterable[DevCommentEntry],
    *,
    path_filter: Optional[str],
    search: Optional[str],
) -> Iterable[DevCommentEntry]:
    needle_path = path_filter.lower() if path_filter else None
    needle_search = search.lower() if search else None
    for entry in entries:
        if needle_path and needle_path not in entry.path_display.lower():
            continue
        if needle_search:
            haystack_parts: List[str] = [entry.path_display]
            if entry.flrecname:
                haystack_parts.append(entry.flrecname)
            if entry.node_id:
                haystack_parts.append(entry.node_id)
            if entry.text:
                haystack_parts.append(entry.text)
            haystack_parts.extend(entry.info)
            if entry.comment:
                haystack_parts.append(entry.comment)
            haystack = "\n".join(haystack_parts).lower()
            if needle_search not in haystack:
                continue
        yield entry


def cmd_dev_comments(args: argparse.Namespace) -> None:
    schema = load_schema(Path(args.input))
    entries = list(
        _filter_entries(
            iter_dev_comments(schema.obj),
            path_filter=args.path,
            search=args.search,
        )
    )

    if args.format == "json":
        payload = {
            "source": str(schema.source),
            "entry_count": len(entries),
            "entries": dev_comments_to_json_records(entries),
        }
        body = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    else:
        body = format_dev_comments_text(entries)

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(body, encoding="utf-8")
        print(f"wrote {output}")
        print(f"entries {len(entries)}")
        return
    print(body, end="")


def cmd_access_report(args: argparse.Namespace) -> None:
    schema = load_schema(Path(args.input))
    report = build_access_report(schema.obj)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8")
        print(f"wrote {output}")
        return
    print(report, end="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract_parser = subparsers.add_parser("extract", help="Extract the embedded schema JSON from a dump.")
    extract_parser.add_argument("input", help="Path to a dump or an existing schema JSON file.")
    extract_parser.add_argument("output", help="Output JSON path.")
    extract_parser.set_defaults(func=cmd_extract)

    show_parser = subparsers.add_parser("show", help="Print one path from the extracted schema.")
    show_parser.add_argument("input", help="Path to a dump or schema JSON file.")
    show_parser.add_argument("path", help="Dot-separated path into the schema object.")
    show_parser.set_defaults(func=cmd_show)

    report_parser = subparsers.add_parser(
        "access-report",
        help="Generate a focused report covering access/competence enums and cfg_data_t gates.",
    )
    report_parser.add_argument("input", help="Path to a dump or schema JSON file.")
    report_parser.add_argument("--output", help="Optional output path for the generated report.")
    report_parser.set_defaults(func=cmd_access_report)

    dev_parser = subparsers.add_parser(
        "dev-comments",
        help="Flatten every developer comment (info/text/comment) into a browsable index.",
    )
    dev_parser.add_argument("input", help="Path to a dump or schema JSON file.")
    dev_parser.add_argument("--output", help="Optional output path; writes to stdout when omitted.")
    dev_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    dev_parser.add_argument(
        "--path",
        help="Only include entries whose dotted path contains this substring (case-insensitive).",
    )
    dev_parser.add_argument(
        "--search",
        help="Only include entries whose metadata or comment text contains this substring (case-insensitive).",
    )
    dev_parser.set_defaults(func=cmd_dev_comments)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
