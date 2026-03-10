#!/usr/bin/env python3
"""Decode and build Jablotron IMPORT.CFG user-mutation sectors.

The first sector of IMPORT.CFG is written as:
- a MessagePack object
- followed by four 0xc1 bytes
- padded with 0xff to 512 bytes
- XORed bytewise with 0xff on the medium

Observed user-management commands use top-level collection key 7:
- {7: {<user_id>: <user_record_map>}} for add/edit
- {7: {<user_id>: nil}} for delete
"""

from __future__ import annotations

import argparse
import json
from collections import OrderedDict
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping, Optional, Sequence

from flexi_pcap_tool import USBPCAP_HEADER_LEN, get_frame_bytes

SECTOR_SIZE = 512
IMPORT_COLLECTION_KEY = 7
ENCODING_XOR = 0xFF
PADDING_MARKER = b"\xC1" * 4
PADDING_FILL = 0xFF


class MessagePackError(ValueError):
    """Raised when a byte stream cannot be decoded with the supported subset."""


def invert_blob(data: bytes) -> bytes:
    return bytes(byte ^ ENCODING_XOR for byte in data)


def load_encoded_sector(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) < SECTOR_SIZE:
        raise SystemExit(f"{path} is shorter than one 512-byte sector.")
    return data[:SECTOR_SIZE]


def load_encoded_frame_sector(pcap: Path, frame: int) -> bytes:
    raw = get_frame_bytes(pcap, frame)[USBPCAP_HEADER_LEN:]
    if len(raw) < SECTOR_SIZE:
        raise SystemExit(f"Frame {frame} only contains {len(raw)} bytes after the USBPcap header.")
    return raw[:SECTOR_SIZE]


def unpack_msgpack(data: bytes, offset: int = 0) -> tuple[Any, int]:
    if offset >= len(data):
        raise MessagePackError("Unexpected end of buffer.")

    marker = data[offset]
    offset += 1

    if marker <= 0x7F:
        return marker, offset
    if marker >= 0xE0:
        return marker - 0x100, offset
    if 0x80 <= marker <= 0x8F:
        size = marker & 0x0F
        value: MutableMapping[Any, Any] = OrderedDict()
        for _ in range(size):
            key, offset = unpack_msgpack(data, offset)
            item, offset = unpack_msgpack(data, offset)
            value[key] = item
        return value, offset
    if 0x90 <= marker <= 0x9F:
        size = marker & 0x0F
        value = []
        for _ in range(size):
            item, offset = unpack_msgpack(data, offset)
            value.append(item)
        return value, offset
    if 0xA0 <= marker <= 0xBF:
        size = marker & 0x1F
        end = offset + size
        return data[offset:end].decode("utf-8", "replace"), end
    if marker == 0xC0:
        return None, offset
    if marker == 0xC2:
        return False, offset
    if marker == 0xC3:
        return True, offset
    if marker == 0xCC:
        return data[offset], offset + 1
    if marker == 0xCD:
        end = offset + 2
        return int.from_bytes(data[offset:end], "big"), end
    if marker == 0xCE:
        end = offset + 4
        return int.from_bytes(data[offset:end], "big"), end
    if marker == 0xD0:
        return int.from_bytes(data[offset : offset + 1], "big", signed=True), offset + 1
    if marker == 0xD1:
        return int.from_bytes(data[offset : offset + 2], "big", signed=True), offset + 2
    if marker == 0xD2:
        return int.from_bytes(data[offset : offset + 4], "big", signed=True), offset + 4
    if marker == 0xD9:
        size = data[offset]
        start = offset + 1
        end = start + size
        return data[start:end].decode("utf-8", "replace"), end

    raise MessagePackError(f"Unsupported MessagePack marker 0x{marker:02x} at offset 0x{offset - 1:04x}.")


def pack_msgpack(value: Any) -> bytes:
    if value is None:
        return b"\xC0"
    if value is False:
        return b"\xC2"
    if value is True:
        return b"\xC3"
    if isinstance(value, int):
        if -32 <= value < 0:
            return bytes([(value + 0x100) & 0xFF])
        if 0 <= value <= 0x7F:
            return bytes([value])
        if 0 <= value <= 0xFF:
            return b"\xCC" + bytes([value])
        if 0 <= value <= 0xFFFF:
            return b"\xCD" + value.to_bytes(2, "big")
        if 0 <= value <= 0xFFFFFFFF:
            return b"\xCE" + value.to_bytes(4, "big")
        if -0x80 <= value < 0:
            return b"\xD0" + value.to_bytes(1, "big", signed=True)
        if -0x8000 <= value < 0:
            return b"\xD1" + value.to_bytes(2, "big", signed=True)
        if -0x80000000 <= value < 0:
            return b"\xD2" + value.to_bytes(4, "big", signed=True)
        raise MessagePackError(f"Integer out of supported range: {value}")
    if isinstance(value, str):
        data = value.encode("utf-8")
        if len(data) <= 31:
            return bytes([0xA0 | len(data)]) + data
        if len(data) <= 0xFF:
            return b"\xD9" + bytes([len(data)]) + data
        raise MessagePackError("Only fixstr and str8 are supported.")
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        if len(value) > 15:
            raise MessagePackError("Only fixarray values up to length 15 are supported.")
        return bytes([0x90 | len(value)]) + b"".join(pack_msgpack(item) for item in value)
    if isinstance(value, Mapping):
        if len(value) > 15:
            raise MessagePackError("Only fixmap values up to length 15 are supported.")
        payload = bytearray([0x80 | len(value)])
        for key, item in value.items():
            payload.extend(pack_msgpack(key))
            payload.extend(pack_msgpack(item))
        return bytes(payload)
    raise MessagePackError(f"Unsupported value type: {type(value).__name__}")


def decode_sector(encoded_sector: bytes) -> dict[str, Any]:
    decoded = invert_blob(encoded_sector[:SECTOR_SIZE])
    payload, parsed_len = unpack_msgpack(decoded, 0)
    trailer = decoded[parsed_len : parsed_len + len(PADDING_MARKER)]
    fill = decoded[parsed_len + len(PADDING_MARKER) :]
    return {
        "encoded_sector": encoded_sector[:SECTOR_SIZE],
        "decoded_sector": decoded,
        "payload": payload,
        "parsed_length": parsed_len,
        "trailer": trailer,
        "fill": fill,
    }


def encode_sector(payload: Any, *, trailer: bytes = PADDING_MARKER) -> bytes:
    decoded_payload = pack_msgpack(payload)
    if len(decoded_payload) + len(trailer) > SECTOR_SIZE:
        raise SystemExit("Payload is too large for a single 512-byte sector.")
    decoded_sector = decoded_payload + trailer
    decoded_sector += bytes([PADDING_FILL]) * (SECTOR_SIZE - len(decoded_sector))
    return invert_blob(decoded_sector)


def describe_payload(payload: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "collection": None,
        "user_id": None,
        "operation": "unknown",
    }

    if not isinstance(payload, Mapping) or len(payload) != 1:
        return summary

    collection_key, collection_value = next(iter(payload.items()))
    summary["collection"] = collection_key
    if not isinstance(collection_value, Mapping) or len(collection_value) != 1:
        return summary

    user_id, user_value = next(iter(collection_value.items()))
    summary["user_id"] = user_id

    if user_value is None:
        summary["operation"] = "delete"
        return summary

    if not isinstance(user_value, Mapping):
        return summary

    pg_masks = []
    if isinstance(user_value.get(3), list):
        pg_masks = list(user_value[3])

    cards = []
    if isinstance(user_value.get(7), list):
        for item in user_value[7]:
            if isinstance(item, Mapping):
                cards.append(item.get(0, ""))
            else:
                cards.append("")

    summary.update(
        {
            "operation": "upsert",
            "field0_raw": user_value.get(0),
            "permissions_raw": user_value.get(1),
            "sections_mask": user_value.get(2),
            "pg_masks": pg_masks,
            "name": user_value.get(4, ""),
            "phone": user_value.get(5, ""),
            "code": user_value.get(6, ""),
            "cards": cards,
            "field8_raw": user_value.get(8),
            "field9_raw": user_value.get(9),
            "comment": user_value.get(10, ""),
            "field11_raw": user_value.get(11),
        }
    )
    return summary


def sections_to_mask(section_numbers: Iterable[int]) -> int:
    mask = 0
    for section in section_numbers:
        if section <= 0:
            raise SystemExit("Section numbers must be 1-based positive integers.")
        mask |= 1 << (section - 1)
    return mask


def pgs_to_masks(pg_numbers: Iterable[int]) -> list[int]:
    masks = [0, 0, 0, 0]
    for pg in pg_numbers:
        if pg <= 0 or pg > 64:
            raise SystemExit("PG numbers must be between 1 and 64.")
        index = (pg - 1) // 16
        bit = (pg - 1) % 16
        masks[index] |= 1 << bit
    return masks


def parse_number_list(spec: str) -> list[int]:
    values: list[int] = []
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        values.append(int(token, 0))
    return values


def load_template_payload(
    *,
    template_file: Optional[str],
    template_pcap: Optional[str],
    template_frame: Optional[int],
) -> OrderedDict[Any, Any]:
    if template_file:
        encoded_sector = load_encoded_sector(Path(template_file))
    elif template_pcap and template_frame is not None:
        encoded_sector = load_encoded_frame_sector(Path(template_pcap), template_frame)
    else:
        return OrderedDict(
            {
                IMPORT_COLLECTION_KEY: OrderedDict(
                    {
                        0: OrderedDict(
                            {
                                0: 0,
                                1: 0,
                                2: 0,
                                3: [0, 0, 0, 0],
                                4: "",
                                5: "",
                                6: "",
                                7: [OrderedDict({0: ""}), OrderedDict({0: ""})],
                                8: 0,
                                9: 0,
                                10: "",
                                11: -1,
                            }
                        )
                    }
                )
            }
        )

    payload = decode_sector(encoded_sector)["payload"]
    if not isinstance(payload, Mapping):
        raise SystemExit("Template payload is not a top-level map.")
    collection_value = payload.get(IMPORT_COLLECTION_KEY)
    if not isinstance(collection_value, Mapping) or len(collection_value) != 1:
        raise SystemExit("Template payload is not a single-user collection-7 command.")
    _, user_value = next(iter(collection_value.items()))
    if not isinstance(user_value, Mapping):
        raise SystemExit("Template payload is not an upsert command.")

    return OrderedDict(
        {
            IMPORT_COLLECTION_KEY: OrderedDict(
                {
                    0: OrderedDict((int(key), user_value[key]) for key in user_value.keys())
                }
            )
        }
    )


def build_user_upsert_payload(args: argparse.Namespace) -> OrderedDict[Any, Any]:
    payload = load_template_payload(
        template_file=args.template_file,
        template_pcap=args.template_pcap,
        template_frame=args.template_frame,
    )
    collection = payload[IMPORT_COLLECTION_KEY]
    _, user_record = next(iter(collection.items()))
    if not isinstance(user_record, MutableMapping):
        raise SystemExit("Template user record is not mutable.")

    collection.clear()
    collection[int(args.user_id)] = user_record

    if args.name is not None:
        user_record[4] = args.name
    if args.phone is not None:
        user_record[5] = args.phone
    if args.code is not None:
        user_record[6] = args.code
    if args.card1 is not None or args.card2 is not None:
        current_cards = user_record.get(7, [OrderedDict({0: ""}), OrderedDict({0: ""})])
        if not isinstance(current_cards, list) or len(current_cards) < 2:
            current_cards = [OrderedDict({0: ""}), OrderedDict({0: ""})]
        card1 = args.card1 if args.card1 is not None else current_cards[0].get(0, "")
        card2 = args.card2 if args.card2 is not None else current_cards[1].get(0, "")
        user_record[7] = [OrderedDict({0: card1}), OrderedDict({0: card2})]
    if args.comment is not None:
        user_record[10] = args.comment

    if args.field0_raw is not None:
        user_record[0] = args.field0_raw
    if args.permissions_raw is not None:
        user_record[1] = args.permissions_raw
    if args.sections_mask is not None:
        user_record[2] = args.sections_mask
    elif args.sections:
        user_record[2] = sections_to_mask(parse_number_list(args.sections))
    if args.pg_masks is not None:
        masks = parse_number_list(args.pg_masks)
        if len(masks) != 4:
            raise SystemExit("--pg-masks requires exactly four comma-separated integers.")
        user_record[3] = masks
    elif args.pgs:
        user_record[3] = pgs_to_masks(parse_number_list(args.pgs))
    if args.field8_raw is not None:
        user_record[8] = args.field8_raw
    if args.field9_raw is not None:
        user_record[9] = args.field9_raw
    if args.field11_raw is not None:
        user_record[11] = args.field11_raw

    return payload


def build_user_delete_payload(user_id: int) -> OrderedDict[Any, Any]:
    return OrderedDict({IMPORT_COLLECTION_KEY: OrderedDict({int(user_id): None})})


def print_summary(summary: Mapping[str, Any]) -> None:
    for key, value in summary.items():
        print(f"{key}: {value}")


def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def normalize_json_value(value: Any) -> Any:
    if isinstance(value, list):
        return [normalize_json_value(item) for item in value]
    if isinstance(value, dict):
        normalized: OrderedDict[Any, Any] = OrderedDict()
        for key, item in value.items():
            normalized_key: Any = key
            if isinstance(key, str) and key.lstrip("-").isdigit():
                normalized_key = int(key)
            normalized[normalized_key] = normalize_json_value(item)
        return normalized
    return value


def write_output(path: Path, encoded_sector: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded_sector)


def cmd_decode_file(args: argparse.Namespace) -> None:
    result = decode_sector(load_encoded_sector(Path(args.input)))
    if args.format == "json":
        print_json({"summary": describe_payload(result["payload"]), "payload": result["payload"]})
        return
    print_summary(describe_payload(result["payload"]))
    print("payload:")
    print_json(result["payload"])


def cmd_decode_frame(args: argparse.Namespace) -> None:
    result = decode_sector(load_encoded_frame_sector(Path(args.pcap), args.frame))
    if args.format == "json":
        print_json({"summary": describe_payload(result["payload"]), "payload": result["payload"]})
        return
    print_summary(describe_payload(result["payload"]))
    print("payload:")
    print_json(result["payload"])


def cmd_pack_json(args: argparse.Namespace) -> None:
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"), object_pairs_hook=OrderedDict)
    payload = normalize_json_value(payload)
    encoded_sector = encode_sector(payload)
    write_output(Path(args.output), encoded_sector)
    print(f"wrote {args.output}")


def cmd_build_user_upsert(args: argparse.Namespace) -> None:
    payload = build_user_upsert_payload(args)
    encoded_sector = encode_sector(payload)
    write_output(Path(args.output), encoded_sector)
    print(f"wrote {args.output}")
    print_json({"summary": describe_payload(payload), "payload": payload})


def cmd_build_user_delete(args: argparse.Namespace) -> None:
    payload = build_user_delete_payload(args.user_id)
    encoded_sector = encode_sector(payload)
    write_output(Path(args.output), encoded_sector)
    print(f"wrote {args.output}")
    print_json({"summary": describe_payload(payload), "payload": payload})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    decode_file = subparsers.add_parser("decode-file", help="Decode an encoded 512-byte IMPORT.CFG sector.")
    decode_file.add_argument("input", help="Path to an encoded IMPORT.CFG sector file.")
    decode_file.add_argument("--format", choices=["summary", "json"], default="summary")
    decode_file.set_defaults(func=cmd_decode_file)

    decode_frame = subparsers.add_parser("decode-frame", help="Decode an IMPORT.CFG write frame directly from a pcap.")
    decode_frame.add_argument("pcap", help="Path to the capture.")
    decode_frame.add_argument("frame", type=int, help="Frame number containing the bulk payload.")
    decode_frame.add_argument("--format", choices=["summary", "json"], default="summary")
    decode_frame.set_defaults(func=cmd_decode_frame)

    pack_json = subparsers.add_parser("pack-json", help="Pack a JSON payload into an encoded IMPORT.CFG sector.")
    pack_json.add_argument("input", help="JSON file containing the decoded payload object.")
    pack_json.add_argument("output", help="Output file for the encoded 512-byte sector.")
    pack_json.set_defaults(func=cmd_pack_json)

    upsert = subparsers.add_parser("build-user-upsert", help="Build an encoded add/edit user sector.")
    upsert.add_argument("output", help="Output file for the encoded 512-byte sector.")
    upsert.add_argument("--user-id", required=True, type=int, help="Target user ID.")
    upsert.add_argument("--name", required=True, help="User name.")
    upsert.add_argument("--phone", default="", help="Phone number field.")
    upsert.add_argument("--code", default="", help="PIN/code field without the user prefix.")
    upsert.add_argument("--card1", default="", help="Primary access-card decimal string.")
    upsert.add_argument("--card2", default="", help="Secondary access-card decimal string.")
    upsert.add_argument("--comment", default="", help="Comment field.")
    upsert.add_argument("--field0-raw", type=int, help="Raw field 0 value.")
    upsert.add_argument("--permissions-raw", type=int, help="Raw field 1 value.")
    upsert.add_argument("--sections-mask", type=int, help="Raw field 2 bitmask.")
    upsert.add_argument("--sections", help="Comma-separated 1-based section numbers to encode into field 2.")
    upsert.add_argument("--pg-masks", help="Comma-separated raw PG masks for field 3 (exactly four integers).")
    upsert.add_argument("--pgs", help="Comma-separated 1-based PG numbers to encode into the four 16-bit masks.")
    upsert.add_argument("--field8-raw", type=int, help="Raw field 8 value.")
    upsert.add_argument("--field9-raw", type=int, help="Raw field 9 value.")
    upsert.add_argument("--field11-raw", type=int, help="Raw field 11 value.")
    upsert.add_argument("--template-file", help="Use an existing encoded sector as the template for unknown fields.")
    upsert.add_argument("--template-pcap", help="Use a pcap frame as the template source.")
    upsert.add_argument("--template-frame", type=int, help="Frame number used with --template-pcap.")
    upsert.set_defaults(func=cmd_build_user_upsert)

    delete = subparsers.add_parser("build-user-delete", help="Build an encoded delete-user sector.")
    delete.add_argument("output", help="Output file for the encoded 512-byte sector.")
    delete.add_argument("--user-id", required=True, type=int, help="Target user ID.")
    delete.set_defaults(func=cmd_build_user_delete)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if getattr(args, "template_pcap", None) and args.template_frame is None:
        raise SystemExit("--template-frame is required when using --template-pcap.")
    args.func(args)


if __name__ == "__main__":
    main()
