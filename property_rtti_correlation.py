#!/usr/bin/env python3
"""Correlate .fdb property names and values with RTTI enum definitions."""

from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from enum_rtti_scan import EnumRecord, dedupe_records, scan_dump
from fdb_tool import read_fdb

PROPERTY_TYPES = {"tkEnumeration", "tkSet"}
BOOL_MEMBERS = ("False", "True")
NAME_TOKEN_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+")


@dataclass
class ObservedProperty:
    name: str
    kind: str
    contexts: Counter[str] = field(default_factory=Counter)
    values: Counter[str] = field(default_factory=Counter)
    tokens: Counter[str] = field(default_factory=Counter)
    sources: List[str] = field(default_factory=list)

    def register(self, *, value: str, context: str, source: str) -> None:
        self.contexts[context] += 1
        self.values[value] += 1
        if source not in self.sources:
            self.sources.append(source)
        if self.kind == "tkSet":
            for token in split_set_value(value):
                self.tokens[token] += 1
        elif value:
            self.tokens[value] += 1

    @property
    def observed_items(self) -> Tuple[str, ...]:
        return tuple(sorted(self.tokens))

    @property
    def primary_context(self) -> str:
        if not self.contexts:
            return ""
        return self.contexts.most_common(1)[0][0]


@dataclass(frozen=True)
class CandidateMatch:
    type_name: str
    module: str
    member_count: int
    observed_count: int
    missing_count: int
    name_score: int
    exact_observed_match: bool
    members: Tuple[str, ...]


def split_set_value(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def tokenize_name(text: str) -> List[str]:
    return [token.lower() for token in NAME_TOKEN_RE.findall(text)]


def normalize_property_name(text: str) -> str:
    return "".join(tokenize_name(text))


def normalize_type_name(text: str) -> str:
    tokens = tokenize_name(text)
    if tokens and tokens[0] in {"t", "tt", "e", "i"}:
        tokens = tokens[1:]
    if tokens and re.fullmatch(r"(?:t|e|i)?ja\d+", tokens[0]):
        tokens = tokens[1:]
    while tokens and tokens[-1] in {"enum", "set"}:
        tokens = tokens[:-1]
    return "".join(tokens)


def derive_context(elem: ET.Element, class_stack: Sequence[str]) -> str:
    if class_stack:
        return " > ".join(class_stack[-3:])
    return elem.attrib.get("name", "")


def iter_property_entries(root: ET.Element, class_stack: Sequence[str] = ()) -> Iterable[Tuple[str, str, str, str]]:
    stack = list(class_stack)
    if root.tag == "class":
        class_name = root.attrib.get("class") or root.attrib.get("name") or "class"
        stack.append(class_name)
    if root.tag == "property":
        kind = root.attrib.get("type", "")
        if kind in PROPERTY_TYPES:
            yield (
                root.attrib.get("name", ""),
                kind,
                (root.text or "").strip(),
                derive_context(root, stack),
            )
    for child in root:
        yield from iter_property_entries(child, tuple(stack))


def load_properties_from_source(path: Path) -> Dict[Tuple[str, str], ObservedProperty]:
    if path.suffix.lower() == ".fdb":
        xml_bytes = read_fdb(path).xml_bytes
    else:
        xml_bytes = path.read_bytes()
    root = ET.fromstring(xml_bytes)

    properties: Dict[Tuple[str, str], ObservedProperty] = {}
    for name, kind, value, context in iter_property_entries(root):
        key = (name, kind)
        entry = properties.get(key)
        if entry is None:
            entry = ObservedProperty(name=name, kind=kind)
            properties[key] = entry
        entry.register(value=value, context=context, source=str(path))
    return properties


def merge_properties(groups: Iterable[Dict[Tuple[str, str], ObservedProperty]]) -> Dict[Tuple[str, str], ObservedProperty]:
    merged: Dict[Tuple[str, str], ObservedProperty] = {}
    for group in groups:
        for key, prop in group.items():
            target = merged.get(key)
            if target is None:
                target = ObservedProperty(name=prop.name, kind=prop.kind)
                merged[key] = target
            for context, count in prop.contexts.items():
                target.contexts[context] += count
            for value, count in prop.values.items():
                target.values[value] += count
            for token, count in prop.tokens.items():
                target.tokens[token] += count
            for source in prop.sources:
                if source not in target.sources:
                    target.sources.append(source)
    return merged


def score_candidate(property_name: str, record: EnumRecord, observed: Sequence[str]) -> CandidateMatch | None:
    observed_set = set(observed)
    record_set = set(record.members)
    if not observed_set.issubset(record_set):
        return None

    property_norm = normalize_property_name(property_name)
    type_norm = normalize_type_name(record.type_name)
    property_tokens = set(tokenize_name(property_name))
    type_tokens = set(tokenize_name(record.type_name))
    type_tokens -= {"t", "tt", "e", "i", "enum", "set"}
    type_tokens = {token for token in type_tokens if not re.fullmatch(r"(?:t|e|i)?ja\d+", token)}
    if property_norm == type_norm:
        name_score = 0
    elif property_tokens and property_tokens.issubset(type_tokens):
        name_score = 1
    elif property_norm and property_norm in type_norm:
        name_score = 2
    elif type_norm and type_norm in property_norm:
        name_score = 2
    elif property_tokens & type_tokens:
        name_score = 2
    else:
        name_score = 3

    return CandidateMatch(
        type_name=record.type_name,
        module=record.module,
        member_count=len(record.members),
        observed_count=len(observed_set),
        missing_count=len(record.members) - len(observed_set),
        name_score=name_score,
        exact_observed_match=record_set == observed_set,
        members=record.members,
    )


def correlate_property(prop: ObservedProperty, enums: Sequence[EnumRecord]) -> List[CandidateMatch]:
    observed = prop.observed_items
    if prop.kind == "tkEnumeration" and set(observed).issubset(set(BOOL_MEMBERS)):
        builtin = CandidateMatch(
            type_name="Boolean",
            module="System",
            member_count=2,
            observed_count=len(set(observed)),
            missing_count=2 - len(set(observed)),
            name_score=0 if normalize_property_name(prop.name) in {"isnull", "readonly", "updated"} else 3,
            exact_observed_match=set(observed) == set(BOOL_MEMBERS),
            members=BOOL_MEMBERS,
        )
        candidates = [builtin]
    else:
        candidates = []

    for enum_record in enums:
        candidate = score_candidate(prop.name, enum_record, observed)
        if candidate is not None:
            candidates.append(candidate)

    candidates.sort(
        key=lambda candidate: (
            candidate.name_score,
            0 if candidate.exact_observed_match else 1,
            candidate.missing_count,
            candidate.member_count,
            candidate.module,
            candidate.type_name,
        )
    )
    return candidates


def build_payload(properties: Dict[Tuple[str, str], ObservedProperty], enums: Sequence[EnumRecord], *, limit: int) -> List[dict]:
    payload = []
    for (_name, _kind), prop in sorted(properties.items()):
        candidates = correlate_property(prop, enums)
        entry = {
            "property": prop.name,
            "kind": prop.kind,
            "primary_context": prop.primary_context,
            "context_count": len(prop.contexts),
            "contexts": [context for context, _count in prop.contexts.most_common(5)],
            "sources": prop.sources,
            "observed_values": [value for value, _count in prop.values.most_common()],
            "observed_items": list(prop.observed_items),
            "candidates": [asdict(candidate) for candidate in candidates[:limit]],
        }
        payload.append(entry)
    return payload


def print_text(payload: Sequence[dict]) -> None:
    for entry in payload:
        print(f"{entry['property']} ({entry['kind']})")
        if entry["primary_context"]:
            print(f"  context: {entry['primary_context']}")
        print(f"  observed: {', '.join(entry['observed_items']) or '<none>'}")
        if entry["candidates"]:
            for candidate in entry["candidates"]:
                match_type = "exact" if candidate["exact_observed_match"] else "subset"
                print(
                    "  candidate: "
                    f"{candidate['module']}.{candidate['type_name']} "
                    f"[{match_type}, name_score={candidate['name_score']}, "
                    f"missing={candidate['missing_count']}]"
                )
        else:
            print("  candidate: <none>")
        print()


def cmd_correlate(args: argparse.Namespace) -> None:
    property_groups = [load_properties_from_source(Path(source)) for source in args.sources]
    properties = merge_properties(property_groups)

    enum_records: List[EnumRecord] = []
    for dump_path in args.dumps:
        enum_records.extend(scan_dump(Path(dump_path)))
    enum_records = dedupe_records(enum_records)

    payload = build_payload(properties, enum_records, limit=args.limit)
    if args.only_matched:
        payload = [entry for entry in payload if entry["candidates"]]

    if args.keyword:
        lowered = [keyword.lower() for keyword in args.keyword]
        payload = [
            entry
            for entry in payload
            if any(keyword in " ".join([entry["property"], entry["primary_context"], *entry["observed_items"]]).lower() for keyword in lowered)
        ]

    if args.format == "json":
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    print_text(payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    correlate_parser = subparsers.add_parser("correlate", help="Correlate .fdb properties with RTTI enum definitions")
    correlate_parser.add_argument("sources", nargs="+", help=".fdb or XML sources to inspect")
    correlate_parser.add_argument("--dumps", nargs="+", required=True, help="process memory dumps to scan for RTTI enums")
    correlate_parser.add_argument("--format", choices=("text", "json"), default="text")
    correlate_parser.add_argument("--limit", type=int, default=3, help="number of candidate enums to keep per property")
    correlate_parser.add_argument("--only-matched", action="store_true", help="suppress properties with no candidates")
    correlate_parser.add_argument(
        "--keyword",
        action="append",
        default=[],
        help="case-insensitive filter over property name, context, and observed items",
    )
    correlate_parser.set_defaults(func=cmd_correlate)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
