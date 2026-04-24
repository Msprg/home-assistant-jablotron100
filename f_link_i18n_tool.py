#!/usr/bin/env python3
"""Extract, index, and query F-Link localization catalogs.

Two input shapes are supported:

- Jablotron's shipped ``.lng`` resource files, located under F-Link's
  ``Languages/`` directory (one catalogue per locale, UTF-8 with BOM,
  ``;`` comments, ``key = Label|Long description`` lines).
- Raw process-memory dumps of a running F-Link where the same key/value
  lines remain in the heap or resource section.

The tool collapses everything to a common in-memory schema and writes
consolidated JSON catalogues under ``research/exports/`` so schema
fields can be cross-referenced against Jablotron's own F-Link help text.

Typical usage:

    # Index every .lng under a directory into one consolidated JSON.
    python3 f_link_i18n_tool.py extract \
        "research/data ingest/F-Link 2.9.2.1509/Languages" \
        research/exports/2026-04-23_f-link-i18n-catalog.json

    # Pull strings from a process-memory dump instead of a .lng file.
    python3 f_link_i18n_tool.py extract \
        "research/data ingest/external reference resources/Peskova F-Link.DMP" \
        research/exports/2026-04-23_f-link-i18n-from-dump.json \
        --from-dump

    # Quick one-off lookups from an indexed catalogue.
    python3 f_link_i18n_tool.py show <catalog.json> cfg.ja100.systemparams.warndefaultcodes
    python3 f_link_i18n_tool.py search <catalog.json> --locale EN --query service
    python3 f_link_i18n_tool.py list <catalog.json> --prefix cfg.ja100.systemparams. --locale EN
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple


KEY_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*)$")
KEY_PREFIX_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")
META_KEYS: Tuple[str, ...] = ("aaa.codepage", "aaa.locale", "aaa.name")
DEFAULT_MIN_DUMP_STRING_LEN = 6


@dataclass
class CatalogEntry:
    """One ``key = value`` pair extracted from a catalogue source."""

    label: str
    description: Optional[str] = None
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"label": self.label}
        if self.description is not None:
            payload["description"] = self.description
        return payload


@dataclass
class LocaleCatalog:
    """All key/value pairs for a single locale."""

    locale_id: str
    source_kind: str
    source_path: str
    meta: Dict[str, str] = field(default_factory=dict)
    entries: Dict[str, CatalogEntry] = field(default_factory=dict)
    duplicate_count: int = 0

    def add(self, key: str, entry: CatalogEntry) -> None:
        if key in self.entries:
            self.duplicate_count += 1
        self.entries[key] = entry

    def to_dict(self) -> Dict[str, Any]:
        return {
            "locale_id": self.locale_id,
            "source_kind": self.source_kind,
            "source_path": self.source_path,
            "meta": dict(self.meta),
            "entry_count": len(self.entries),
            "duplicate_count": self.duplicate_count,
            "entries": {key: entry.to_dict() for key, entry in self.entries.items()},
        }


@dataclass
class CatalogBundle:
    """Top-level structure persisted as JSON on disk."""

    extracted_at: str
    tool_version: str
    locales: Dict[str, LocaleCatalog] = field(default_factory=dict)

    def add_locale(self, catalog: LocaleCatalog) -> None:
        self.locales[catalog.locale_id] = catalog

    def to_dict(self) -> Dict[str, Any]:
        return {
            "extracted_at": self.extracted_at,
            "tool_version": self.tool_version,
            "locale_count": len(self.locales),
            "total_entry_count": sum(len(catalog.entries) for catalog in self.locales.values()),
            "locales": {locale_id: catalog.to_dict() for locale_id, catalog in self.locales.items()},
        }


TOOL_VERSION = "0.1.0"


def _split_label_description(value: str) -> Tuple[str, Optional[str]]:
    """Split Jablotron's ``Label|Long description`` convention."""

    if "|" not in value:
        return value, None
    label, _, description = value.partition("|")
    return label.strip(), description.strip() or None


def parse_lng_text(
    text: str,
    *,
    source_kind: str,
    source_path: str,
    locale_id: str,
) -> LocaleCatalog:
    """Parse the textual body of one ``.lng`` file."""

    catalog = LocaleCatalog(locale_id=locale_id, source_kind=source_kind, source_path=source_path)
    for raw_line in text.splitlines():
        line = raw_line.lstrip("\ufeff")
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        match = KEY_LINE_RE.match(stripped)
        if not match:
            continue
        key, raw_value = match.group(1), match.group(2)
        label, description = _split_label_description(raw_value.strip())
        entry = CatalogEntry(label=label, description=description, raw=raw_value.strip())
        catalog.add(key, entry)
        if key in META_KEYS:
            catalog.meta[key.split(".", 1)[1]] = label
    return catalog


def load_lng_file(path: Path, *, locale_override: Optional[str] = None) -> LocaleCatalog:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    locale_id = locale_override or path.stem.upper()
    catalog = parse_lng_text(
        text,
        source_kind="lng",
        source_path=str(path),
        locale_id=locale_id,
    )
    if "locale" not in catalog.meta and locale_id:
        catalog.meta.setdefault("locale", locale_id)
    return catalog


def iter_lng_files(target: Path) -> Iterator[Path]:
    if target.is_dir():
        for child in sorted(target.iterdir()):
            if child.is_file() and child.suffix.lower() == ".lng":
                yield child
        return
    if target.is_file():
        yield target
        return
    raise SystemExit(f"{target} is neither a file nor a directory.")


def _iter_ascii_runs(data: bytes, min_length: int) -> Iterator[Tuple[int, str]]:
    start: Optional[int] = None
    for index, byte in enumerate(data):
        if 0x20 <= byte < 0x7F or byte in (0x09,):
            if start is None:
                start = index
        else:
            if start is not None and index - start >= min_length:
                yield start, data[start:index].decode("ascii", "replace")
            start = None
    if start is not None and len(data) - start >= min_length:
        yield start, data[start:].decode("ascii", "replace")


def _iter_utf16le_runs(data: bytes, min_length: int) -> Iterator[Tuple[int, str]]:
    start: Optional[int] = None
    index = 0
    end = len(data) - 1
    while index < end:
        low = data[index]
        high = data[index + 1]
        if high == 0 and (0x20 <= low < 0x7F or low == 0x09):
            if start is None:
                start = index
        else:
            if start is not None and (index - start) // 2 >= min_length:
                yield start, data[start:index].decode("utf-16-le", "replace")
            start = None
        index += 2
    if start is not None and (len(data) - start) // 2 >= min_length:
        yield start, data[start:].decode("utf-16-le", "replace")


def iter_catalog_lines(
    data: bytes,
    *,
    min_length: int = DEFAULT_MIN_DUMP_STRING_LEN,
    include_utf16: bool = True,
) -> Iterator[Tuple[int, str, str]]:
    """Yield ``(offset, encoding, text)`` for every run containing ``key = ...``."""

    for offset, text in _iter_ascii_runs(data, min_length):
        if "=" in text:
            yield offset, "ascii", text
    if include_utf16:
        for offset, text in _iter_utf16le_runs(data, min_length):
            if "=" in text:
                yield offset, "utf-16-le", text


def extract_from_dump_bytes(
    data: bytes,
    *,
    source_path: str,
    locale_id: str = "DUMP",
    min_length: int = DEFAULT_MIN_DUMP_STRING_LEN,
    include_utf16: bool = True,
) -> LocaleCatalog:
    catalog = LocaleCatalog(locale_id=locale_id, source_kind="dump", source_path=source_path)
    for _offset, _encoding, text in iter_catalog_lines(
        data, min_length=min_length, include_utf16=include_utf16
    ):
        stripped = text.strip()
        if not stripped or stripped.startswith(";"):
            continue
        match = KEY_LINE_RE.match(stripped)
        if not match:
            continue
        key, raw_value = match.group(1), match.group(2)
        if "." not in key:
            continue
        label, description = _split_label_description(raw_value.strip())
        if not label:
            continue
        entry = CatalogEntry(label=label, description=description, raw=raw_value.strip())
        catalog.add(key, entry)
        if key in META_KEYS:
            catalog.meta[key.split(".", 1)[1]] = label
    return catalog


def load_dump_file(
    path: Path,
    *,
    locale_override: Optional[str] = None,
    min_length: int = DEFAULT_MIN_DUMP_STRING_LEN,
    include_utf16: bool = True,
) -> LocaleCatalog:
    data = path.read_bytes()
    return extract_from_dump_bytes(
        data,
        source_path=str(path),
        locale_id=locale_override or path.stem.upper(),
        min_length=min_length,
        include_utf16=include_utf16,
    )


def build_bundle(catalogs: Sequence[LocaleCatalog]) -> CatalogBundle:
    bundle = CatalogBundle(
        extracted_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        tool_version=TOOL_VERSION,
    )
    for catalog in catalogs:
        bundle.add_locale(catalog)
    return bundle


def write_bundle(path: Path, bundle: CatalogBundle) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_bundle(path: Path) -> CatalogBundle:
    payload = json.loads(path.read_text(encoding="utf-8"))
    bundle = CatalogBundle(
        extracted_at=payload.get("extracted_at", ""),
        tool_version=payload.get("tool_version", ""),
    )
    for locale_id, catalog_payload in payload.get("locales", {}).items():
        catalog = LocaleCatalog(
            locale_id=locale_id,
            source_kind=catalog_payload.get("source_kind", "lng"),
            source_path=catalog_payload.get("source_path", ""),
            meta=dict(catalog_payload.get("meta", {})),
            duplicate_count=int(catalog_payload.get("duplicate_count", 0)),
        )
        for key, entry_payload in catalog_payload.get("entries", {}).items():
            catalog.entries[key] = CatalogEntry(
                label=entry_payload.get("label", ""),
                description=entry_payload.get("description"),
                raw=entry_payload.get("raw", ""),
            )
        bundle.locales[locale_id] = catalog
    return bundle


def _pick_locales(bundle: CatalogBundle, preferred: Optional[Sequence[str]]) -> List[str]:
    if preferred:
        return [p.upper() for p in preferred if p.upper() in bundle.locales]
    return list(bundle.locales)


def cmd_extract(args: argparse.Namespace) -> None:
    target = Path(args.input)
    catalogs: List[LocaleCatalog] = []

    if args.from_dump or target.is_file() and target.suffix.lower() in (".dmp", ".bin"):
        catalog = load_dump_file(
            target,
            locale_override=args.locale,
            min_length=args.min_dump_string_len,
            include_utf16=not args.no_utf16,
        )
        catalogs.append(catalog)
    else:
        for lng_path in iter_lng_files(target):
            catalog = load_lng_file(lng_path, locale_override=args.locale if target.is_file() else None)
            catalogs.append(catalog)

    if not catalogs:
        raise SystemExit("No catalogues produced; check --from-dump or the directory path.")

    bundle = build_bundle(catalogs)
    output = Path(args.output)
    write_bundle(output, bundle)
    print(f"wrote {output}")
    print(f"locales {len(bundle.locales)} entries {sum(len(c.entries) for c in bundle.locales.values())}")
    for catalog in catalogs:
        print(
            "  "
            + f"{catalog.locale_id}: entries={len(catalog.entries)} duplicates={catalog.duplicate_count} source={catalog.source_path}"
        )


def cmd_show(args: argparse.Namespace) -> None:
    bundle = load_bundle(Path(args.input))
    locales = _pick_locales(bundle, args.locales)
    if not locales:
        raise SystemExit("No matching locales in bundle.")
    printed = False
    for locale_id in locales:
        catalog = bundle.locales[locale_id]
        entry = catalog.entries.get(args.key)
        if entry is None:
            continue
        printed = True
        print(f"[{locale_id}] {args.key}")
        print(f"  label: {entry.label}")
        if entry.description:
            print(f"  description: {entry.description}")
    if not printed:
        raise SystemExit(f"Key {args.key!r} not found in requested locales.")


def cmd_search(args: argparse.Namespace) -> None:
    bundle = load_bundle(Path(args.input))
    locales = _pick_locales(bundle, args.locales)
    needle = args.query.lower() if args.query else None
    needle_prefix = args.prefix or None
    total = 0
    for locale_id in locales:
        catalog = bundle.locales[locale_id]
        locale_hits: List[Tuple[str, CatalogEntry]] = []
        for key, entry in catalog.entries.items():
            if needle_prefix and not key.startswith(needle_prefix):
                continue
            if needle:
                hay = "\n".join(
                    [
                        key,
                        entry.label,
                        entry.description or "",
                    ]
                ).lower()
                if needle not in hay:
                    continue
            locale_hits.append((key, entry))
            if args.limit and len(locale_hits) >= args.limit:
                break
        if not locale_hits:
            continue
        print(f"[{locale_id}] matches={len(locale_hits)}")
        for key, entry in locale_hits:
            print(f"  {key}")
            print(f"    label: {entry.label}")
            if entry.description:
                description = entry.description
                if args.max_description_chars and len(description) > args.max_description_chars:
                    description = description[: args.max_description_chars] + "..."
                print(f"    description: {description}")
        total += len(locale_hits)
    if total == 0:
        print("(no matches)")


def cmd_list(args: argparse.Namespace) -> None:
    bundle = load_bundle(Path(args.input))
    locales = _pick_locales(bundle, args.locales)
    if not locales:
        raise SystemExit("No matching locales in bundle.")
    locale_id = locales[0]
    catalog = bundle.locales[locale_id]
    prefix = args.prefix or ""
    keys = sorted(k for k in catalog.entries if k.startswith(prefix))
    if args.limit:
        keys = keys[: args.limit]
    for key in keys:
        entry = catalog.entries[key]
        print(f"{key}\t{entry.label}")
    print(f"# {locale_id}: {len(keys)} keys under {prefix!r}")


def cmd_info(args: argparse.Namespace) -> None:
    bundle = load_bundle(Path(args.input))
    print(f"bundle: {args.input}")
    print(f"extracted_at: {bundle.extracted_at}")
    print(f"tool_version: {bundle.tool_version}")
    print(f"locales: {len(bundle.locales)}")
    for locale_id in sorted(bundle.locales):
        catalog = bundle.locales[locale_id]
        meta_bits = " ".join(f"{k}={v!r}" for k, v in sorted(catalog.meta.items()))
        print(
            f"  {locale_id}: entries={len(catalog.entries)} dupes={catalog.duplicate_count} source_kind={catalog.source_kind} {meta_bits}"
        )


def cmd_diff(args: argparse.Namespace) -> None:
    bundle = load_bundle(Path(args.input))
    left_id = args.left.upper()
    right_id = args.right.upper()
    if left_id not in bundle.locales or right_id not in bundle.locales:
        raise SystemExit(f"Both locales must exist in the bundle; have {sorted(bundle.locales)}.")
    left = bundle.locales[left_id].entries
    right = bundle.locales[right_id].entries
    only_left = sorted(set(left) - set(right))
    only_right = sorted(set(right) - set(left))
    print(f"keys only in {left_id}: {len(only_left)}")
    for key in only_left[: args.limit]:
        print(f"  {key}\t{left[key].label}")
    print(f"keys only in {right_id}: {len(only_right)}")
    for key in only_right[: args.limit]:
        print(f"  {key}\t{right[key].label}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract_parser = subparsers.add_parser(
        "extract",
        help="Index one or more .lng files or an F-Link process-memory dump into a consolidated JSON catalogue.",
    )
    extract_parser.add_argument(
        "input",
        help="Path to a .lng file, a directory of .lng files, or an F-Link dump.",
    )
    extract_parser.add_argument("output", help="Output JSON catalogue path.")
    extract_parser.add_argument(
        "--from-dump",
        action="store_true",
        help="Force treating the input as a process-memory dump instead of a .lng resource.",
    )
    extract_parser.add_argument(
        "--locale",
        help="Locale identifier to stamp on the catalogue (default: derived from the file name).",
    )
    extract_parser.add_argument(
        "--min-dump-string-len",
        type=int,
        default=DEFAULT_MIN_DUMP_STRING_LEN,
        help=f"Minimum string length to consider when scanning dumps (default: {DEFAULT_MIN_DUMP_STRING_LEN}).",
    )
    extract_parser.add_argument(
        "--no-utf16",
        action="store_true",
        help="Disable UTF-16LE scanning when reading a dump (ASCII only).",
    )
    extract_parser.set_defaults(func=cmd_extract)

    show_parser = subparsers.add_parser("show", help="Print the entry for a single key.")
    show_parser.add_argument("input", help="Path to an extracted JSON catalogue.")
    show_parser.add_argument("key", help="Full i18n key to look up.")
    show_parser.add_argument(
        "--locale",
        dest="locales",
        action="append",
        help="Restrict lookup to one or more locales (may be repeated).",
    )
    show_parser.set_defaults(func=cmd_show)

    search_parser = subparsers.add_parser("search", help="Filter entries by key prefix and/or substring.")
    search_parser.add_argument("input", help="Path to an extracted JSON catalogue.")
    search_parser.add_argument("--query", help="Case-insensitive substring to match in key/label/description.")
    search_parser.add_argument("--prefix", help="Only keys starting with this prefix.")
    search_parser.add_argument(
        "--locale",
        dest="locales",
        action="append",
        help="Restrict search to one or more locales (may be repeated).",
    )
    search_parser.add_argument("--limit", type=int, default=0, help="Max hits per locale (0 = no limit).")
    search_parser.add_argument(
        "--max-description-chars",
        type=int,
        default=240,
        help="Truncate long descriptions in the output (0 = no truncation).",
    )
    search_parser.set_defaults(func=cmd_search)

    list_parser = subparsers.add_parser("list", help="List keys under a prefix (label only).")
    list_parser.add_argument("input", help="Path to an extracted JSON catalogue.")
    list_parser.add_argument("--prefix", default="", help="Only keys starting with this prefix.")
    list_parser.add_argument(
        "--locale",
        dest="locales",
        action="append",
        help="Locale to list from (defaults to the first locale in the bundle).",
    )
    list_parser.add_argument("--limit", type=int, default=0, help="Max keys to list (0 = no limit).")
    list_parser.set_defaults(func=cmd_list)

    info_parser = subparsers.add_parser("info", help="Summarise a catalogue bundle.")
    info_parser.add_argument("input", help="Path to an extracted JSON catalogue.")
    info_parser.set_defaults(func=cmd_info)

    diff_parser = subparsers.add_parser("diff", help="Show keys present in one locale but missing in another.")
    diff_parser.add_argument("input", help="Path to an extracted JSON catalogue.")
    diff_parser.add_argument("left", help="Left locale id, e.g. EN.")
    diff_parser.add_argument("right", help="Right locale id, e.g. CS.")
    diff_parser.add_argument("--limit", type=int, default=30, help="Max keys to print per side.")
    diff_parser.set_defaults(func=cmd_diff)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
