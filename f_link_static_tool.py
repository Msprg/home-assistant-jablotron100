#!/usr/bin/env python3
"""Correlate F-Link Delphi RTTI anchors, VMTs, and IDC function ranges.

The tool is intentionally dependency-free so it can be used on the preserved
F-Link artifacts without IDA, Ghidra, or a PE parsing package.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclass(frozen=True)
class PublishedMethod:
    name: str
    code: int
    metadata: int
    raw_flags: int


@dataclass(frozen=True)
class PublishedField:
    name: str
    offset: int
    type_info: int
    visibility: int
    raw_flags: int


@dataclass(frozen=True)
class DelphiClass:
    name: str
    rtti_anchor: int
    type_info: int
    vmt: int
    instance_size: int
    parent_rtti: int
    parent_vmt_cell: int
    parent_vmt: int
    field_table: int
    vmt_end: int | None
    vmt_slot_count: int | None
    method_table: int
    fields: tuple[PublishedField, ...]
    methods: tuple[PublishedMethod, ...]


class PEImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        pe_offset = self._unpack_file("<I", 0x3C)
        if self.data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ValueError(f"{path} is not a PE image")
        file_header = pe_offset + 4
        section_count = self._unpack_file("<H", file_header + 2)
        optional_size = self._unpack_file("<H", file_header + 16)
        optional = file_header + 20
        if self._unpack_file("<H", optional) != 0x10B:
            raise ValueError("only PE32 images are supported")
        self.image_base = self._unpack_file("<I", optional + 28)
        table = optional + optional_size
        sections = []
        for index in range(section_count):
            offset = table + index * 40
            name = self.data[offset : offset + 8].split(b"\0", 1)[0].decode("ascii")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", self.data, offset + 8
            )
            sections.append(
                Section(name, virtual_address, virtual_size, raw_offset, raw_size)
            )
        self.sections = tuple(sections)

    def _unpack_file(self, fmt: str, offset: int) -> int:
        return struct.unpack_from(fmt, self.data, offset)[0]

    def va_to_offset(self, va: int) -> int:
        relative = va - self.image_base
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= relative < section.virtual_address + span:
                delta = relative - section.virtual_address
                if delta >= section.raw_size:
                    raise ValueError(f"VA 0x{va:08X} has no file-backed bytes")
                return section.raw_offset + delta
        raise ValueError(f"VA 0x{va:08X} is outside mapped sections")

    def unpack(self, fmt: str, va: int) -> int:
        return struct.unpack_from(fmt, self.data, self.va_to_offset(va))[0]

    def pascal_string(self, va: int) -> str:
        offset = self.va_to_offset(va)
        size = self.data[offset]
        return self.data[offset + 1 : offset + 1 + size].decode("latin-1")


def parse_delphi_class(image: PEImage, rtti_anchor: int) -> DelphiClass:
    """Parse a class from either an RTTI pointer cell or direct TypeInfo VA.

    The component map generally records the four-byte cell that points at TypeInfo,
    while Delphi's parent-class field points directly at TypeInfo. Accepting both is
    important when walking an inheritance chain from preserved metadata.
    """
    type_info = rtti_anchor
    try:
        indirect_type_info = image.unpack("<I", rtti_anchor)
        indirect_kind = image.unpack("<B", indirect_type_info)
    except ValueError:
        indirect_kind = None
    if indirect_kind == 7:
        type_info = indirect_type_info
    else:
        try:
            direct_kind = image.unpack("<B", rtti_anchor)
        except ValueError as error:
            raise ValueError(
                f"RTTI address 0x{rtti_anchor:08X} is not mapped"
            ) from error
        if direct_kind != 7:
            raise ValueError(
                f"RTTI address 0x{rtti_anchor:08X} is neither a class TypeInfo "
                "record nor a pointer to one"
            )
    name = image.pascal_string(type_info + 1)
    type_data = type_info + 2 + len(name.encode("latin-1"))
    vmt = image.unpack("<I", type_data)
    parent_rtti = image.unpack("<I", type_data + 4)
    method_table = image.unpack("<I", vmt - 64)
    methods: list[PublishedMethod] = []
    if method_table:
        extended_count = image.unpack("<H", method_table + 2)
        for index in range(extended_count):
            entry = method_table + 4 + index * 8
            metadata = image.unpack("<I", entry)
            raw_flags = image.unpack("<I", entry + 4)
            code = image.unpack("<I", metadata + 2)
            method_name = image.pascal_string(metadata + 6)
            methods.append(PublishedMethod(method_name, code, metadata, raw_flags))
    parent_vmt_cell = image.unpack("<I", vmt - 48)
    field_table = image.unpack("<I", vmt - 68)
    instance_size = image.unpack("<I", vmt - 52)
    table_pointers = tuple(image.unpack("<I", vmt + offset) for offset in range(-84, -55, 4))
    following_tables = tuple(pointer for pointer in table_pointers if pointer > vmt)
    vmt_end = min(following_tables) if following_tables else None
    vmt_distance = vmt_end - vmt if vmt_end is not None else -1
    vmt_slot_count = (
        vmt_distance // 4
        if vmt_distance >= 0 and vmt_distance % 4 == 0
        else None
    )
    fields: list[PublishedField] = []
    if field_table:
        regular_count = image.unpack("<H", field_table + 4)
        if regular_count != 0:
            raise ValueError(
                f"unsupported regular-field table for {name}: {regular_count} entries"
            )
        extended_count = image.unpack("<H", field_table + 6)
        cursor = field_table + 8
        for field_index in range(extended_count):
            visibility = image.unpack("<B", cursor)
            field_type_info = image.unpack("<I", cursor + 1)
            field_offset = image.unpack("<I", cursor + 5)
            field_name = image.pascal_string(cursor + 9)
            raw_flags_address = cursor + 10 + len(field_name.encode("latin-1"))
            raw_flags = image.unpack("<H", raw_flags_address)
            fields.append(
                PublishedField(
                    field_name,
                    field_offset,
                    field_type_info,
                    visibility,
                    raw_flags,
                )
            )
            cursor = raw_flags_address + 2
            if field_index + 1 < extended_count:
                # Interface-typed fields can carry extra metadata after the common
                # entry. Locate the next structurally valid entry instead of
                # hard-coding that type-specific suffix.
                for candidate in range(cursor, cursor + 65):
                    try:
                        candidate_visibility = image.unpack("<B", candidate)
                        candidate_type = image.unpack("<I", candidate + 1)
                        candidate_offset = image.unpack("<I", candidate + 5)
                        candidate_name = image.pascal_string(candidate + 9)
                        if candidate_type:
                            image.va_to_offset(candidate_type)
                    except (UnicodeDecodeError, ValueError):
                        continue
                    if (
                        candidate_visibility <= 3
                        and candidate_offset < instance_size
                        and candidate_name
                        and candidate_name.isprintable()
                    ):
                        cursor = candidate
                        break
                else:
                    raise ValueError(f"cannot locate next extended field for {name}")
    return DelphiClass(
        name=name,
        rtti_anchor=rtti_anchor,
        type_info=type_info,
        vmt=vmt,
        instance_size=instance_size,
        parent_rtti=parent_rtti,
        parent_vmt_cell=parent_vmt_cell,
        parent_vmt=image.unpack("<I", parent_vmt_cell) if parent_vmt_cell else 0,
        field_table=field_table,
        vmt_end=vmt_end,
        vmt_slot_count=vmt_slot_count,
        method_table=method_table,
        fields=tuple(fields),
        methods=tuple(methods),
    )


def parse_vmt_slots(image: PEImage, vmt: int, count: int) -> tuple[int, ...]:
    """Read a caller-selected number of 32-bit Delphi VMT entries."""
    return tuple(image.unpack("<I", vmt + index * 4) for index in range(count))


def describe_vmt_slots(
    image: PEImage, parsed_class: DelphiClass, count: int | None = None
) -> tuple[dict[str, int | bool | None], ...]:
    """Describe VMT entries and whether each overrides its direct parent."""
    if count is None:
        if parsed_class.vmt_slot_count is None:
            raise ValueError(
                f"cannot infer VMT size for {parsed_class.name}; provide an explicit count"
            )
        count = parsed_class.vmt_slot_count
    slots = parse_vmt_slots(image, parsed_class.vmt, count)
    parent_count = count
    if parsed_class.parent_rtti:
        try:
            parent_count = parse_delphi_class(image, parsed_class.parent_rtti).vmt_slot_count or 0
        except ValueError:
            pass
    parent_slots = (
        parse_vmt_slots(image, parsed_class.parent_vmt, min(count, parent_count))
        if parsed_class.parent_vmt and parent_count
        else ()
    )
    parent_slots += (None,) * (count - len(parent_slots))
    return tuple(
        {
            "offset": index * 4,
            "code": code,
            "parent_code": parent_code,
            "added": parent_code is None,
            "overridden": parent_code is not None and code != parent_code,
        }
        for index, (code, parent_code) in enumerate(zip(slots, parent_slots))
    )


FUNCTION_RE = re.compile(
    r"MakeFunction\(\s*(0x[0-9A-Fa-f]+)\s*,\s*(?:(0x[0-9A-Fa-f]+)|-1)\s*\)"
)


def parse_idc_functions(text: str) -> tuple[tuple[int, int | None], ...]:
    return tuple(
        (int(match.group(1), 16), int(match.group(2), 16) if match.group(2) else None)
        for match in FUNCTION_RE.finditer(text)
    )


def containing_idc_function(
    functions: tuple[tuple[int, int | None], ...], address: int
) -> tuple[int, int | None] | None:
    for start, end in functions:
        if end is not None and start <= address < end:
            return start, end
    return None


def parse_address(value: str) -> int:
    return int(value, 0)


def cmd_classes(args: argparse.Namespace) -> None:
    image = PEImage(Path(args.exe))
    result = [asdict(parse_delphi_class(image, address)) for address in args.rtti]
    print(json.dumps(result, indent=2))


def cmd_idc_range(args: argparse.Namespace) -> None:
    text = Path(args.idc).read_text(encoding="latin-1")
    functions = parse_idc_functions(text)
    result = []
    for address in args.address:
        bounds = containing_idc_function(functions, address)
        result.append(
            {
                "address": address,
                "start": bounds[0] if bounds else None,
                "end": bounds[1] if bounds else None,
            }
        )
    print(json.dumps(result, indent=2))


def cmd_vmt_slots(args: argparse.Namespace) -> None:
    image = PEImage(Path(args.exe))
    result = []
    for address in args.rtti:
        parsed_class = parse_delphi_class(image, address)
        result.append(
            {
                "name": parsed_class.name,
                "rtti_anchor": parsed_class.rtti_anchor,
                "vmt": parsed_class.vmt,
                "parent_vmt": parsed_class.parent_vmt,
                "slots": describe_vmt_slots(image, parsed_class, args.slots),
            }
        )
    print(json.dumps(result, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    classes = subparsers.add_parser("classes", help="decode Delphi class RTTI anchors")
    classes.add_argument("exe", help="PE32 executable")
    classes.add_argument("rtti", nargs="+", type=parse_address, help="RTTI anchor VA")
    classes.set_defaults(func=cmd_classes)
    ranges = subparsers.add_parser("idc-range", help="find containing IDC function ranges")
    ranges.add_argument("idc", help="IDC file containing MakeFunction calls")
    ranges.add_argument("address", nargs="+", type=parse_address, help="landmark VA")
    ranges.set_defaults(func=cmd_idc_range)
    vmt_slots = subparsers.add_parser(
        "vmt-slots", help="compare class VMT entries with the direct parent"
    )
    vmt_slots.add_argument("exe", help="PE32 executable")
    vmt_slots.add_argument("rtti", nargs="+", type=parse_address, help="RTTI anchor VA")
    vmt_slots.add_argument(
        "--slots",
        type=int,
        help="number of VMT dwords to read (default: infer from the field-table VA)",
    )
    vmt_slots.set_defaults(func=cmd_vmt_slots)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
